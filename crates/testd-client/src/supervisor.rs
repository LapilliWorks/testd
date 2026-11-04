//! Supervised launch: one child process, one registration lifetime.
//!
//! The supervisor owns the child, the host connection, and the per-name state.
//! A name is registered only after the target accepts TCP, and is removed when
//! the child stops. Rebinding changes the target without restarting the child.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command as ProcessCommand};
use tokio::sync::{mpsc, oneshot};

use serde::Serialize;
use testd_core::config::ClientConfig;
use testd_core::protocol::{self, Request, Response};
use testd_core::validate;

use crate::listeners;
use crate::{Entry, Reader, Writer, connect};

const RECONNECT_DELAY: Duration = Duration::from_secs(3);
#[cfg(unix)]
const STOP_GRACE: Duration = Duration::from_secs(5);
const PROBE_INTERVAL: Duration = Duration::from_millis(200);

/// State of one `name:port` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryState {
	/// Defined, but neither registered nor reachable.
	Configured,
	/// Starting or rebinding; the target is being probed.
	Probing,
	/// Probe passed and the claim is registered.
	Confirmed,
}

/// Which stream a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
	Stdout,
	Stderr,
}

/// Progress reported by a supervised launch.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LaunchEvent {
	State { domain: String, target: String, state: EntryState, error: Option<String> },
	Output { stream: OutputStream, line: String },
	Started { pid: u32 },
	Exited { code: Option<i32> },
	Failed { message: String },
}

/// What to run and what to name it.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
	pub program: PathBuf,
	pub args: Vec<String>,
	pub cwd: Option<PathBuf>,
	pub env: Vec<(String, String)>,
	pub entries: Vec<Entry>,
	pub force: bool,
	pub probe_timeout: Duration,
	/// Detect the child's listening port when the entry target is empty, `auto`,
	/// or a bare port. An explicit `host:port` always wins.
	pub detect: bool,
	/// When a wildcard bind is detected, prefer a non-loopback address.
	pub share: bool,
}

impl LaunchSpec {
	pub fn new(program: impl Into<PathBuf>, entries: Vec<Entry>) -> Self {
		Self {
			program: program.into(),
			args: Vec::new(),
			cwd: None,
			env: Vec::new(),
			entries,
			force: false,
			probe_timeout: Duration::from_secs(30),
			detect: true,
			share: false,
		}
	}
}

/// Handle to a running supervised launch.
pub struct Launch {
	commands: mpsc::Sender<Command>,
	events: Option<mpsc::Receiver<LaunchEvent>>,
}

impl Launch {
	pub fn events(&mut self) -> &mut mpsc::Receiver<LaunchEvent> {
		self.events.as_mut().expect("launch events were already taken")
	}

	/// Take the event stream so the handle can still be used for stop/rebind.
	pub fn take_events(&mut self) -> Option<mpsc::Receiver<LaunchEvent>> {
		self.events.take()
	}

	/// Probe a new target and re-register the name without restarting the child.
	pub async fn rebind(&self, domain: &str, target: &str) -> Result<(), String> {
		validate_launch_target(target)?;
		let (respond, response) = oneshot::channel();
		self.commands
			.send(Command::Rebind { domain: domain.to_owned(), target: target.to_owned(), respond })
			.await
			.map_err(|_| "launch already stopped".to_owned())?;
		response.await.map_err(|_| "launch task exited".to_owned())?
	}

	/// Stop the child, deregister every name, and wait for cleanup.
	pub async fn stop(&self) -> Result<(), String> {
		let (respond, response) = oneshot::channel();
		if self.commands.send(Command::Stop { respond }).await.is_err() {
			return Ok(());
		}
		response.await.map_err(|_| "launch task exited".to_owned())
	}
}

/// Start a supervised launch. The host must be reachable and authenticate
/// before the child starts.
pub async fn launch(spec: LaunchSpec, mut config: ClientConfig) -> Result<Launch> {
	validate_spec(&spec)?;

	let names = crate::entry_names(&spec.entries);
	let (reader, writer) = connect(&mut config, &names).await.context("host is not reachable")?;
	let (events_tx, events_rx) = mpsc::channel(128);
	let (notices_tx, notices_rx) = mpsc::unbounded_channel();
	let live = Live::start(reader, writer, notices_tx.clone());
	let session = SessionHandle::spawn(config, live, events_tx.clone(), notices_tx);
	let (commands_tx, commands_rx) = mpsc::channel(8);

	let task_events = events_tx.clone();
	tokio::spawn(async move {
		if let Err(e) = run_launch(spec, session, commands_rx, task_events.clone(), notices_rx).await {
			let _ = task_events.send(LaunchEvent::Failed { message: format!("{e:#}") }).await;
		}
	});

	Ok(Launch { commands: commands_tx, events: Some(events_rx) })
}

/// Something the host session reports outside a request and its reply.
enum SessionNotice {
	/// An operator stopped this launch from the dashboard.
	StoppedByHost(String),
	/// An operator deleted the grant for one name. The launch keeps its other
	/// names and stops only when none are left.
	NameRevoked(String),
	/// The session cannot continue; the message explains why.
	Closed(String),
}

enum Command {
	Rebind { domain: String, target: String, respond: oneshot::Sender<Result<(), String>> },
	Stop { respond: oneshot::Sender<()> },
}

fn validate_spec(spec: &LaunchSpec) -> Result<()> {
	if spec.program.as_os_str().is_empty() {
		bail!("launch program is empty");
	}
	if spec.entries.is_empty() {
		bail!("launch needs at least one name");
	}
	let mut seen = std::collections::HashSet::new();
	for entry in &spec.entries {
		validate::validate_domain_labels(&entry.domain).map_err(|e| anyhow::anyhow!(e))?;
		if let (true, Some(hint)) = (spec.detect, auto_hint(&entry.target)) {
			if hint == Some(0) {
				bail!("port 0 is not a target");
			}
		} else {
			validate_launch_target(&entry.target).map_err(|e| anyhow::anyhow!(e))?;
		}
		if !seen.insert(entry.domain.as_str()) {
			bail!("duplicate name in launch: {}", entry.domain);
		}
	}
	Ok(())
}

/// A supervised target must include the host, because the supervisor probes it.
fn validate_launch_target(target: &str) -> Result<(), String> {
	validate::validate_target(target)?;
	if target.parse::<u16>().is_ok() {
		return Err(format!("supervised targets must include a host: {target:?}"));
	}
	Ok(())
}

async fn run_launch(
	spec: LaunchSpec,
	session: SessionHandle,
	mut commands: mpsc::Receiver<Command>,
	events: mpsc::Sender<LaunchEvent>,
	mut notices: mpsc::UnboundedReceiver<SessionNotice>,
) -> Result<()> {
	for entry in &spec.entries {
		send_state(&events, &entry.domain, &entry.target, EntryState::Configured, None).await;
	}

	let mut child = spawn_child(&spec, &events)?;
	let pid = child.id().unwrap_or_default();
	let _ = events.send(LaunchEvent::Started { pid }).await;

	// Probe and register in the background so stop remains responsive.
	let (startup_tx, mut startup_rx) = mpsc::channel(1);
	let startup = {
		let spec = spec.clone();
		let session = session.clone();
		let events = events.clone();
		tokio::spawn(async move {
			let confirmed = confirm_all(&spec, pid, &session, &events).await;
			let _ = startup_tx.send(confirmed).await;
		})
	};
	let startup_abort = startup.abort_handle();

	let mut confirmed: HashMap<String, String> = HashMap::new();
	let mut revoked: HashSet<String> = HashSet::new();
	let mut started = false;
	let mut notices_open = true;
	let mut stop_responder: Option<oneshot::Sender<()>> = None;
	let exit_code;

	loop {
		tokio::select! {
			status = child.wait() => {
				exit_code = status.ok().and_then(|s| s.code());
				break;
			},
			result = startup_rx.recv(), if !started => {
				started = true;
				match result {
					Some(mut map) => {
						// A withdrawal can arrive while the launch is still
						// probing; do not let the startup result restore it.
						map.retain(|name, _| !revoked.contains(name));
						confirmed = map;
						if confirmed.is_empty() {
							stop_child(&mut child).await;
							exit_code = None;
							break;
						}
					},
					None => {
						stop_child(&mut child).await;
						exit_code = None;
						break;
					},
				}
			},
			notice = notices.recv(), if notices_open => match notice {
				Some(SessionNotice::StoppedByHost(domain)) => {
					// The operator stopped this leaf. The saved launch and its
					// grants stay, so Start publishes the names again.
					let line = format!("testd: {domain} was stopped by the host operator (grants kept)");
					let _ = events.send(LaunchEvent::Output { stream: OutputStream::Stderr, line }).await;
					startup_abort.abort();
					stop_child(&mut child).await;
					exit_code = None;
					break;
				},
				Some(SessionNotice::NameRevoked(host_name)) => {
					// The host names the fqdn; the launch knows the entry as
					// the client spells it.
					let Some(entry) = spec
						.entries
						.iter()
						.find(|entry| crate::is_published_name(&entry.domain, &host_name))
					else {
						continue;
					};
					let domain = entry.domain.clone();
					let target = confirmed.get(&domain).cloned().unwrap_or_else(|| entry.target.clone());
					confirmed.remove(&domain);
					revoked.insert(domain.clone());
					let note = "the grant for this name was deleted; the leaf must ask again";
					send_state(&events, &domain, &target, EntryState::Configured, Some(note.to_owned())).await;
					if started && confirmed.is_empty() {
						// Nothing is left to publish for this run.
						startup_abort.abort();
						stop_child(&mut child).await;
						exit_code = None;
						break;
					}
				},
				Some(SessionNotice::Closed(reason)) => {
					let _ = events.send(LaunchEvent::Failed { message: reason }).await;
					startup_abort.abort();
					stop_child(&mut child).await;
					exit_code = None;
					break;
				},
				None => notices_open = false,
			},
			command = commands.recv() => match command {
				None => {
					startup_abort.abort();
					stop_child(&mut child).await;
					exit_code = None;
					break;
				},
				Some(Command::Stop { respond }) => {
					startup_abort.abort();
					stop_responder = Some(respond);
					stop_child(&mut child).await;
					exit_code = None;
					break;
				},
				Some(Command::Rebind { domain, target, respond }) => {
					if !started {
						let _ = respond.send(Err("launch is still starting".into()));
						continue;
					}
					let result = rebind(&spec, &session, &mut confirmed, &events, &domain, &target).await;
					let _ = respond.send(result);
				},
			},
		}
	}

	startup_abort.abort();
	session.stop().await;
	for entry in &spec.entries {
		send_state(&events, &entry.domain, &entry.target, EntryState::Configured, None).await;
	}
	let _ = events.send(LaunchEvent::Exited { code: exit_code }).await;
	if let Some(respond) = stop_responder {
		let _ = respond.send(());
	}
	Ok(())
}

async fn confirm_all(
	spec: &LaunchSpec,
	pid: u32,
	session: &SessionHandle,
	events: &mpsc::Sender<LaunchEvent>,
) -> HashMap<String, String> {
	let mut confirmed = HashMap::new();
	for entry in &spec.entries {
		send_state(events, &entry.domain, &entry.target, EntryState::Probing, None).await;

		let target = if spec.detect
			&& let Some(port) = auto_hint(&entry.target)
		{
			match detect_target(pid, port, spec.share, spec.probe_timeout).await {
				Ok(target) => {
					send_state(events, &entry.domain, &target, EntryState::Probing, None).await;
					target
				},
				Err(e) => {
					send_state(events, &entry.domain, &entry.target, EntryState::Configured, Some(e)).await;
					continue;
				},
			}
		} else {
			entry.target.clone()
		};

		if let Err(e) = wait_for_target(&target, spec.probe_timeout).await {
			send_state(events, &entry.domain, &target, EntryState::Configured, Some(e)).await;
			continue;
		}
		match session.set_target(&entry.domain, &target, spec.force).await {
			Ok(()) => {
				send_state(events, &entry.domain, &target, EntryState::Confirmed, None).await;
				confirmed.insert(entry.domain.clone(), target);
			},
			Err(e) => {
				send_state(events, &entry.domain, &target, EntryState::Configured, Some(e)).await;
			},
		}
	}
	confirmed
}

/// `Some(port)` when the target asks for detection; the port may be absent.
fn auto_hint(target: &str) -> Option<Option<u16>> {
	if target.is_empty() || target.eq_ignore_ascii_case("auto") {
		return Some(None);
	}
	target.parse::<u16>().ok().map(Some)
}

async fn detect_target(pid: u32, port: Option<u16>, share: bool, timeout: Duration) -> Result<String, String> {
	let deadline = Instant::now() + timeout;
	loop {
		let listeners = tokio::task::spawn_blocking(move || listeners::discover(pid))
			.await
			.map_err(|e| format!("listener discovery task failed: {e}"))??;
		match listeners::select(&listeners, port, share) {
			Ok(target) => return Ok(target),
			Err(e @ listeners::SelectError::Ambiguous(_)) => return Err(e.to_string()),
			Err(e) => {
				if Instant::now() >= deadline {
					return Err(e.to_string());
				}
				tokio::time::sleep(PROBE_INTERVAL).await;
			},
		}
	}
}

async fn rebind(
	spec: &LaunchSpec,
	session: &SessionHandle,
	confirmed: &mut HashMap<String, String>,
	events: &mpsc::Sender<LaunchEvent>,
	domain: &str,
	target: &str,
) -> Result<(), String> {
	let Some(entry) = spec.entries.iter().find(|entry| entry.domain == domain) else {
		return Err(format!("{domain} is not part of this launch"));
	};
	let old_target = confirmed.get(domain).cloned().unwrap_or_else(|| entry.target.clone());
	let was_confirmed = confirmed.contains_key(domain);

	send_state(events, domain, target, EntryState::Probing, None).await;
	if let Err(e) = wait_for_target(target, spec.probe_timeout).await {
		let fallback = if was_confirmed { EntryState::Confirmed } else { EntryState::Configured };
		send_state(events, domain, &old_target, fallback, Some(e.clone())).await;
		return Err(e);
	}
	match session.set_target(domain, target, spec.force).await {
		Ok(()) => {
			confirmed.insert(domain.to_owned(), target.to_owned());
			send_state(events, domain, target, EntryState::Confirmed, None).await;
			Ok(())
		},
		Err(e) => {
			let fallback = if was_confirmed { EntryState::Confirmed } else { EntryState::Configured };
			send_state(events, domain, &old_target, fallback, Some(e.clone())).await;
			Err(e)
		},
	}
}

async fn wait_for_target(target: &str, timeout: Duration) -> Result<(), String> {
	if !target.contains(':') {
		return Err(format!("target must include a port: {target:?}"));
	}
	let deadline = Instant::now() + timeout;
	loop {
		match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(target)).await {
			Ok(Ok(_)) => return Ok(()),
			Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {
				return Err(format!("invalid target {target:?}: {e}"));
			},
			_ if Instant::now() >= deadline => {
				return Err(format!("no listener on {target} within {}s", timeout.as_secs()));
			},
			_ => tokio::time::sleep(PROBE_INTERVAL).await,
		}
	}
}

async fn send_state(
	events: &mpsc::Sender<LaunchEvent>,
	domain: &str,
	target: &str,
	state: EntryState,
	error: Option<String>,
) {
	let _ = events
		.send(LaunchEvent::State { domain: domain.to_owned(), target: target.to_owned(), state, error })
		.await;
}

fn spawn_child(spec: &LaunchSpec, events: &mpsc::Sender<LaunchEvent>) -> Result<Child> {
	let mut command = ProcessCommand::new(&spec.program);
	command
		.args(&spec.args)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	if let Some(cwd) = &spec.cwd {
		command.current_dir(cwd);
	}
	for (key, value) in &spec.env {
		command.env(key, value);
	}
	#[cfg(unix)]
	command.process_group(0);
	#[cfg(windows)]
	command.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP

	let mut child = command
		.spawn()
		.with_context(|| format!("failed to spawn {}", spec.program.display()))?;
	if let Some(stdout) = child.stdout.take() {
		spawn_output_reader(stdout, OutputStream::Stdout, events.clone());
	}
	if let Some(stderr) = child.stderr.take() {
		spawn_output_reader(stderr, OutputStream::Stderr, events.clone());
	}
	Ok(child)
}

fn spawn_output_reader<R>(reader: R, stream: OutputStream, events: mpsc::Sender<LaunchEvent>)
where
	R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
	tokio::spawn(async move {
		let mut lines = BufReader::new(reader).lines();
		while let Ok(Some(line)) = lines.next_line().await {
			if events.send(LaunchEvent::Output { stream, line }).await.is_err() {
				break;
			}
		}
	});
}

async fn stop_child(child: &mut Child) {
	let Some(pid) = child.id() else {
		return;
	};

	#[cfg(unix)]
	{
		unsafe {
			libc::kill(-(pid as i32), libc::SIGTERM);
		}
		let _ = tokio::time::timeout(STOP_GRACE, child.wait()).await;
		// Also clear descendants that outlived the direct child.
		unsafe {
			libc::kill(-(pid as i32), libc::SIGKILL);
		}
		let _ = child.wait().await;
	}

	#[cfg(windows)]
	{
		let _ = ProcessCommand::new("taskkill")
			.args(["/PID", &pid.to_string(), "/T", "/F"])
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.await;
		let _ = child.wait().await;
	}

	#[cfg(not(any(unix, windows)))]
	{
		let _ = child.kill().await;
		let _ = child.wait().await;
	}
}

// --- host session ---

struct Live {
	writer: Writer,
	responses: mpsc::Receiver<Response>,
	/// Names whose grants were deleted, kept apart from replies so they can
	/// never be mistaken for one.
	revoked: mpsc::UnboundedReceiver<String>,
	closed: oneshot::Receiver<()>,
}

impl Live {
	fn start(mut reader: Reader, writer: Writer, notices: mpsc::UnboundedSender<SessionNotice>) -> Self {
		let (responses_tx, responses) = mpsc::channel(8);
		let (revoked_tx, revoked) = mpsc::unbounded_channel();
		let (closed_tx, closed) = oneshot::channel();
		tokio::spawn(async move {
			while let Ok(Some(response)) = protocol::recv::<_, Response>(&mut reader).await {
				// Host-initiated frames are never replies to a request.
				let forwarded = match response {
					Response::Stopped { domain } => notices.send(SessionNotice::StoppedByHost(domain)).is_ok(),
					Response::NameRevoked { domain } => revoked_tx.send(domain).is_ok(),
					Response::GrantRevoked => notices
						.send(SessionNotice::Closed("the host operator deleted this leaf's grant".into()))
						.is_ok(),
					response => responses_tx.send(response).await.is_ok(),
				};
				if !forwarded {
					break;
				}
			}
			let _ = closed_tx.send(());
		});
		Self { writer, responses, revoked, closed }
	}

	/// Send one request and wait for its outcome. A registration can wait on a
	/// pending name grant, so the reply is not always the first frame back.
	async fn request(&mut self, request: &Request) -> Result<Response> {
		protocol::send(&mut self.writer, request).await?;
		loop {
			match self.responses.recv().await.context("host closed the connection")? {
				Response::PendingGrant { id, domain } => {
					eprintln!("[testd] [grant] the host is waiting for approval to grant {domain} (request {id})");
				},
				response => return Ok(response),
			}
		}
	}
}

#[derive(Clone)]
struct SessionHandle {
	commands: mpsc::Sender<SessionCommand>,
}

impl SessionHandle {
	fn spawn(
		config: ClientConfig,
		live: Live,
		events: mpsc::Sender<LaunchEvent>,
		notices: mpsc::UnboundedSender<SessionNotice>,
	) -> Self {
		let (commands, receiver) = mpsc::channel(16);
		tokio::spawn(async move { session_loop(config, Some(live), receiver, events, notices).await });
		Self { commands }
	}

	async fn set_target(&self, domain: &str, target: &str, force: bool) -> Result<(), String> {
		let (respond, response) = oneshot::channel();
		self.commands
			.send(SessionCommand::SetTarget { domain: domain.to_owned(), target: target.to_owned(), force, respond })
			.await
			.map_err(|_| "session stopped".to_owned())?;
		response.await.map_err(|_| "session stopped".to_owned())?
	}

	async fn stop(&self) {
		let (respond, response) = oneshot::channel();
		if self.commands.send(SessionCommand::Stop { respond }).await.is_ok() {
			let _ = response.await;
		}
	}
}

enum SessionCommand {
	SetTarget { domain: String, target: String, force: bool, respond: oneshot::Sender<Result<(), String>> },
	Stop { respond: oneshot::Sender<()> },
}

async fn session_loop(
	mut config: ClientConfig,
	mut live: Option<Live>,
	mut commands: mpsc::Receiver<SessionCommand>,
	events: mpsc::Sender<LaunchEvent>,
	notices: mpsc::UnboundedSender<SessionNotice>,
) {
	let mut desired: HashMap<String, String> = HashMap::new();
	let mut revoked: HashSet<String> = HashSet::new();

	loop {
		let Some(connection) = live.as_mut() else {
			tokio::select! {
				command = commands.recv() => match command {
					None => return,
					Some(SessionCommand::Stop { respond }) => {
						let _ = respond.send(());
						return;
					},
					Some(SessionCommand::SetTarget { respond, .. }) => {
						let _ = respond.send(Err("host is not reachable".into()));
					},
				},
				_ = tokio::time::sleep(RECONNECT_DELAY) => match connect(&mut config, &names(&desired)).await {
					Ok((reader, writer)) => {
						let mut connection = Live::start(reader, writer, notices.clone());
						reregister(&mut connection, &mut desired, &events).await;
						live = Some(connection);
					},
					Err(e) => {
						// A refused credential will not become acceptable by asking again.
						if e.downcast_ref::<crate::ConnectFailure>().is_some_and(|failure| !failure.is_retryable()) {
							let _ = notices.send(SessionNotice::Closed(format!("{e:#}")));
							return;
						}
						eprintln!("[testd] [warn]  reconnect failed: {e:#}");
					},
				},
			}
			continue;
		};

		let Live { writer, responses, revoked: revoked_names, closed } = connection;
		let mut disconnected = false;
		tokio::select! {
			_ = &mut *closed => {
				eprintln!("[testd] [warn]  host connection lost");
				disconnected = true;
			},
			revoked_name = revoked_names.recv() => match revoked_name {
				Some(host_name) => {
					// The host names the fqdn; `desired` keys are the client's
					// spellings of the same names.
					let dropped: Vec<String> = desired
						.keys()
						.filter(|name| crate::is_published_name(name, &host_name))
						.cloned()
						.collect();
					for name in &dropped {
						desired.remove(name);
					}
					revoked.insert(host_name.clone());
					if notices.send(SessionNotice::NameRevoked(host_name)).is_err() {
						return;
					}
				},
				None => disconnected = true,
			},
			command = commands.recv() => {
				let Some(command) = command else { return };
				match command {
					SessionCommand::Stop { respond } => {
						deregister_all(writer, responses, &mut desired).await;
						let _ = respond.send(());
						return;
					},
					SessionCommand::SetTarget { domain, target, force, respond } => {
						if revoked.iter().any(|host_name| crate::is_published_name(&domain, host_name)) {
							let _ = respond.send(Err("the grant for this name was deleted; it must be approved again".into()));
							continue;
						}
						let request = Request::Register { domain: domain.clone(), target: target.clone(), force };
						let result = send_request(writer, responses, &request).await;
						match result {
							Ok(Response::Ok) => {
								desired.insert(domain, target);
								let _ = respond.send(Ok(()));
							},
							Ok(Response::Error { message, .. }) => {
								let _ = respond.send(Err(message));
							},
							Ok(_) => {
								let _ = respond.send(Err("host returned an unexpected response".into()));
							},
							Err(e) => {
								disconnected = true;
								let _ = respond.send(Err(e.to_string()));
							},
						}
					},
				}
			},
		}
		if disconnected {
			live = None;
		}
	}
}

async fn send_request(
	writer: &mut Writer,
	responses: &mut mpsc::Receiver<Response>,
	request: &Request,
) -> Result<Response> {
	protocol::send(writer, request).await?;
	loop {
		match responses.recv().await.context("host closed the connection")? {
			Response::PendingGrant { id, domain } => {
				eprintln!("[testd] [grant] the host is waiting for approval to grant {domain} (request {id})");
			},
			response => return Ok(response),
		}
	}
}

/// The names the session is publishing, for a re-authentication request.
fn names(desired: &HashMap<String, String>) -> Vec<String> {
	let mut names: Vec<String> = desired.keys().cloned().collect();
	names.sort();
	names
}

async fn reregister(live: &mut Live, desired: &mut HashMap<String, String>, events: &mpsc::Sender<LaunchEvent>) {
	let entries: Vec<(String, String)> = desired.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
	for (domain, target) in entries {
		let request = Request::Register { domain: domain.clone(), target: target.clone(), force: false };
		match live.request(&request).await {
			Ok(Response::Ok) => {},
			Ok(Response::Error { message, .. }) => {
				desired.remove(&domain);
				send_state(events, &domain, &target, EntryState::Configured, Some(message)).await;
			},
			Ok(_) => return,
			Err(_) => return,
		}
	}
}

async fn deregister_all(
	writer: &mut Writer,
	responses: &mut mpsc::Receiver<Response>,
	desired: &mut HashMap<String, String>,
) {
	for domain in desired.keys() {
		let request = Request::Deregister { domain: domain.clone() };
		let _ = send_request(writer, responses, &request).await;
	}
	desired.clear();
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::{Arc, Mutex};
	use testd_core::protocol::Auth;
	use tokio::net::TcpListener;
	use tokio::sync::mpsc::Receiver;

	struct FakeHost {
		addr: String,
		seen: Arc<Mutex<Vec<Request>>>,
	}

	impl FakeHost {
		fn requests(&self) -> Vec<String> {
			self.seen
				.lock()
				.unwrap()
				.iter()
				.map(|request| match request {
					Request::Register { domain, target, .. } => format!("register {domain} {target}"),
					Request::Deregister { domain } => format!("deregister {domain}"),
				})
				.collect()
		}
	}

	/// What the fake host does after acknowledging `domain`'s registration.
	#[derive(Clone, Copy)]
	enum After {
		Nothing,
		Stop,
		/// Delete the grant for one name, as the dashboard's Delete does.
		Revoke,
		/// Ask the operator for a grant before acknowledging.
		PendingGrant,
	}

	async fn fake_host() -> FakeHost {
		fake_host_after(After::Nothing, "app").await
	}

	async fn fake_host_after(after: After, domain: &'static str) -> FakeHost {
		let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
		let addr = listener.local_addr().unwrap().to_string();
		let seen = Arc::new(Mutex::new(Vec::new()));
		let task_seen = Arc::clone(&seen);
		tokio::spawn(async move {
			loop {
				let Ok((stream, _)) = listener.accept().await else { return };
				let seen = Arc::clone(&task_seen);
				tokio::spawn(async move {
					let (reader, mut writer) = stream.into_split();
					let mut reader = BufReader::new(reader);
					if protocol::recv::<_, Auth>(&mut reader).await.ok().flatten().is_none() {
						return;
					}
					if protocol::send(&mut writer, &Response::Ok).await.is_err() {
						return;
					}
					while let Ok(Some(request)) = protocol::recv::<_, Request>(&mut reader).await {
						let matched = matches!(&request, Request::Register { domain: name, .. } if name == domain);
						seen.lock().unwrap().push(request);
						let sent = if matched {
							match after {
								After::Nothing => protocol::send(&mut writer, &Response::Ok).await.is_ok(),
								After::Stop => {
									protocol::send(&mut writer, &Response::Ok).await.is_ok()
										&& protocol::send(&mut writer, &Response::Stopped { domain: domain.to_owned() })
											.await
											.is_ok()
								},
								After::Revoke => {
									// The host sends the fqdn, not the client's spelling.
									protocol::send(&mut writer, &Response::Ok).await.is_ok()
										&& protocol::send(
											&mut writer,
											&Response::NameRevoked { domain: format!("{domain}.test") },
										)
										.await
										.is_ok()
								},
								After::PendingGrant => {
									protocol::send(
										&mut writer,
										&Response::PendingGrant { id: "pending".into(), domain: domain.to_owned() },
									)
									.await
									.is_ok() && protocol::send(&mut writer, &Response::Ok).await.is_ok()
								},
							}
						} else {
							protocol::send(&mut writer, &Response::Ok).await.is_ok()
						};
						if !sent {
							return;
						}
					}
				});
			}
		});
		FakeHost { addr, seen }
	}

	fn config(host: &str) -> ClientConfig {
		ClientConfig {
			token: "test-token".into(),
			token_profile: "default".into(),
			hosts: vec![host.to_owned()],
			node_profile: "default".into(),
		}
	}

	async fn target() -> (TcpListener, String) {
		let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
		let addr = listener.local_addr().unwrap().to_string();
		(listener, addr)
	}

	fn spec(target: &str) -> LaunchSpec {
		let mut spec = LaunchSpec::new(sleep_program(), vec![Entry::new("app", target)]);
		spec.probe_timeout = Duration::from_secs(5);
		spec
	}

	fn sleep_program() -> String {
		#[cfg(unix)]
		{
			"sleep".into()
		}
		#[cfg(windows)]
		{
			"powershell".into()
		}
	}

	fn sleep_args() -> Vec<String> {
		#[cfg(unix)]
		{
			vec!["60".into()]
		}
		#[cfg(windows)]
		{
			// Windows timeout exits when stdin is redirected by the supervisor.
			vec!["-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), "Start-Sleep -Seconds 60".into()]
		}
	}

	fn spec_with_args(target: &str) -> LaunchSpec {
		let mut spec = spec(target);
		spec.args = sleep_args();
		spec
	}

	async fn next_state(events: &mut Receiver<LaunchEvent>, state: EntryState) -> LaunchEvent {
		tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				match events.recv().await.expect("launch events closed") {
					event @ LaunchEvent::State { state: seen, .. } if seen == state => return event,
					_ => {},
				}
			}
		})
		.await
		.expect("timed out waiting for state")
	}

	#[tokio::test]
	async fn sleep_fixture_stays_alive_with_redirected_stdin() {
		let spec = spec_with_args("127.0.0.1:1");
		let (events, _receiver) = mpsc::channel(16);
		let mut child = spawn_child(&spec, &events).expect("failed to spawn sleep fixture");

		// Stay alive through a full connection attempt, including slow refusal on Windows.
		tokio::time::sleep(Duration::from_secs(2)).await;
		let status = child.try_wait();
		stop_child(&mut child).await;
		let status = status.expect("failed to inspect sleep fixture");
		assert!(status.is_none(), "sleep fixture exited with redirected stdin: {status:?}");
	}

	#[tokio::test]
	async fn registers_after_probe_and_stops() {
		let host = fake_host().await;
		let (_listener, target) = target().await;
		let spec = spec_with_args(&target);
		let mut launch = launch(spec, config(&host.addr)).await.unwrap();

		next_state(launch.events(), EntryState::Probing).await;
		match next_state(launch.events(), EntryState::Confirmed).await {
			LaunchEvent::State { target: seen, error, .. } => {
				assert_eq!(seen, target);
				assert!(error.is_none());
			},
			_ => unreachable!(),
		}
		assert_eq!(host.requests(), vec![format!("register app {target}")]);

		launch.stop().await.unwrap();
		tokio::time::timeout(Duration::from_secs(5), async {
			loop {
				if let Some(LaunchEvent::Exited { .. }) = launch.events().recv().await {
					return;
				}
			}
		})
		.await
		.expect("timed out waiting for exit");
		assert!(host.requests().contains(&"deregister app".to_owned()));
	}

	#[tokio::test]
	async fn rebinds_to_a_new_target_without_restarting() {
		let host = fake_host().await;
		let (_first, first) = target().await;
		let (_second, second) = target().await;
		let spec = spec_with_args(&first);
		let mut launch = launch(spec, config(&host.addr)).await.unwrap();
		next_state(launch.events(), EntryState::Confirmed).await;

		launch.rebind("app", &second).await.unwrap();
		next_state(launch.events(), EntryState::Probing).await;
		match next_state(launch.events(), EntryState::Confirmed).await {
			LaunchEvent::State { target: seen, .. } => assert_eq!(seen, second),
			_ => unreachable!(),
		}
		assert_eq!(host.requests(), vec![format!("register app {first}"), format!("register app {second}")]);
		launch.stop().await.unwrap();
	}

	#[tokio::test]
	async fn an_operator_stop_ends_the_launch() {
		let host = fake_host_after(After::Stop, "app").await;
		let (_listener, target) = target().await;
		let mut launch = launch(spec_with_args(&target), config(&host.addr)).await.unwrap();

		let logged = tokio::time::timeout(Duration::from_secs(10), async {
			let mut logged = false;
			loop {
				match launch.events().recv().await.expect("launch events closed") {
					LaunchEvent::Output { line, .. } if line.contains("stopped by the host operator") => logged = true,
					LaunchEvent::Exited { .. } => return logged,
					_ => {},
				}
			}
		})
		.await
		.expect("a stopped launch exits");
		assert!(logged, "the launch says why it stopped");

		// It does not reconnect and register again.
		let requests = host.requests();
		assert_eq!(requests.iter().filter(|request| request.starts_with("register ")).count(), 1, "{requests:?}");
	}

	#[tokio::test]
	async fn deleting_one_grant_keeps_the_other_name() {
		let host = fake_host_after(After::Revoke, "api").await;
		let (_listener, target) = target().await;
		let mut spec = spec_with_args(&target);
		spec.entries.push(Entry::new("api", target.clone()));
		let mut launch = launch(spec, config(&host.addr)).await.unwrap();

		let note = tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				match launch.events().recv().await.expect("launch events closed") {
					LaunchEvent::State { domain, error: Some(error), .. } if domain == "api" => return error,
					_ => {},
				}
			}
		})
		.await
		.expect("the deleted grant is reported");
		assert!(note.contains("deleted"), "{note}");

		// The launch keeps running with the name that still has a grant.
		launch.rebind("app", &target).await.expect("the launch is still running");
		// The deleted name cannot be bound again without a new grant.
		assert!(launch.rebind("api", &target).await.is_err(), "a deleted grant stays deleted");
		launch.stop().await.unwrap();
	}

	#[tokio::test]
	async fn deleting_the_last_grant_ends_the_launch() {
		let host = fake_host_after(After::Revoke, "app").await;
		let (_listener, target) = target().await;
		let mut launch = launch(spec_with_args(&target), config(&host.addr)).await.unwrap();

		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				if let Some(LaunchEvent::Exited { .. }) = launch.events().recv().await {
					return;
				}
			}
		})
		.await
		.expect("a launch without granted names exits");
	}

	#[tokio::test]
	async fn a_pending_grant_is_waited_out() {
		let host = fake_host_after(After::PendingGrant, "app").await;
		let (_listener, target) = target().await;
		let mut launch = launch(spec_with_args(&target), config(&host.addr)).await.unwrap();

		next_state(launch.events(), EntryState::Confirmed).await;
		assert_eq!(host.requests(), vec![format!("register app {target}")]);
		launch.stop().await.unwrap();
	}

	#[cfg(target_os = "linux")]
	#[tokio::test]
	async fn auto_detects_the_child_listener() {
		if std::process::Command::new("python3").arg("--version").output().is_err() {
			return;
		}
		let host = fake_host().await;
		let script = "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); time.sleep(30)";
		let mut spec = LaunchSpec::new("python3", vec![Entry::new("app", "auto")]);
		spec.args = vec!["-c".into(), script.into()];
		spec.probe_timeout = Duration::from_secs(5);
		let mut launch = launch(spec, config(&host.addr)).await.unwrap();

		next_state(launch.events(), EntryState::Probing).await;
		match next_state(launch.events(), EntryState::Confirmed).await {
			LaunchEvent::State { target, error, .. } => {
				assert!(error.is_none());
				assert!(target.starts_with("127.0.0.1:"), "target: {target}");
				assert!(
					host.requests()
						.iter()
						.any(|request| request == &format!("register app {target}"))
				);
			},
			_ => unreachable!(),
		}
		launch.stop().await.unwrap();
	}

	#[tokio::test]
	async fn failed_rebind_keeps_the_old_target() {
		let host = fake_host().await;
		let (_listener, first) = target().await;
		let dead = {
			let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
			let addr = listener.local_addr().unwrap().to_string();
			drop(listener);
			addr
		};
		let mut spec = spec_with_args(&first);
		spec.probe_timeout = Duration::from_millis(600);
		let mut launch = launch(spec, config(&host.addr)).await.unwrap();
		next_state(launch.events(), EntryState::Confirmed).await;

		assert!(launch.rebind("app", &dead).await.is_err());
		match next_state(launch.events(), EntryState::Confirmed).await {
			LaunchEvent::State { target: seen, error, .. } => {
				assert_eq!(seen, first);
				assert!(error.is_some());
			},
			_ => unreachable!(),
		}
		assert_eq!(host.requests(), vec![format!("register app {first}")]);
		launch.stop().await.unwrap();
	}

	#[tokio::test]
	async fn probe_failure_does_not_register_or_leave_the_child_running() {
		let host = fake_host().await;
		let dead = {
			let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
			let addr = listener.local_addr().unwrap().to_string();
			drop(listener);
			addr
		};
		let mut spec = spec_with_args(&dead);
		spec.probe_timeout = Duration::from_millis(500);
		let mut launch = launch(spec, config(&host.addr)).await.unwrap();

		next_state(launch.events(), EntryState::Probing).await;
		match next_state(launch.events(), EntryState::Configured).await {
			LaunchEvent::State { error, .. } => assert!(error.is_some()),
			_ => unreachable!(),
		}
		tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				if let Some(LaunchEvent::Exited { .. }) = launch.events().recv().await {
					return;
				}
			}
		})
		.await
		.expect("timed out waiting for exit");
		assert!(host.requests().is_empty());
	}
}
