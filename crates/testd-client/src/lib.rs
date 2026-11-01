//! Dev-side client: connects to the host daemon, sends requests.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};

use testd_core::config::ClientConfig;
use testd_core::protocol::{self, Auth, Request, Response, TokenRequest};

pub mod listeners;
pub mod supervisor;

const RECONNECT_DELAY: Duration = Duration::from_secs(3);
/// A host that does not answer must not stall a run or a failover attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

type Reader = BufReader<tokio::net::tcp::OwnedReadHalf>;
type Writer = tokio::net::tcp::OwnedWriteHalf;

/// The ordered reconnect list.
fn hosts(config: &ClientConfig) -> Vec<String> {
	config.hosts.clone()
}

/// Connect to one host daemon and authenticate.
///
/// With no credential for the profile, the host is asked for one instead. The
/// approved token is saved before the connection is used, so the next run does
/// not ask again.
async fn connect_host(config: &mut ClientConfig, host: &str, names: &[String]) -> Result<(Reader, Writer)> {
	let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(host))
		.await
		.map_err(|_| anyhow::anyhow!("timed out connecting to host at {host}"))?
		.with_context(|| format!("failed to connect to host at {host}"))?;

	let (reader, mut writer) = stream.into_split();
	let mut reader = BufReader::new(reader);
	match authenticate(config, host, &mut reader, &mut writer, names).await {
		Ok(()) => Ok((reader, writer)),
		Err(e) => Err(anyhow::Error::new(ConnectFailure::rejected(e))),
	}
}

/// Present a token, or wait for the host's operator to approve a request.
async fn authenticate(
	config: &mut ClientConfig,
	host: &str,
	reader: &mut Reader,
	writer: &mut Writer,
	names: &[String],
) -> Result<()> {
	let asking = config.token.is_empty();
	let request_token = asking.then(|| TokenRequest { label: client_label(), names: names.to_vec() });
	let auth = Auth { token: config.token.clone(), request_token };
	protocol::send(writer, &auth).await?;

	let response: Response = protocol::recv(reader).await?.context("host closed connection during auth")?;

	match response {
		Response::Ok => {},
		Response::Pending { id } => {
			eprintln!(
				"[testd] [auth]  no credential for profile {:?}; requested access from {host} (request {id})",
				config.token_profile
			);
			eprintln!("[testd] [auth]  approve it on the node with `testd requests` and `testd approve {id}`");
			let response: Response = protocol::recv(reader)
				.await?
				.context("host closed connection while waiting for approval")?;
			match response {
				Response::Token { token } => {
					testd_core::config::write_credential(&config.token_profile, &token).with_context(|| {
						format!("failed to save the credential for profile {:?}", config.token_profile)
					})?;
					eprintln!(
						"[testd] [auth]  token issued; saved to {}",
						testd_core::config::credential_path(&config.token_profile).display()
					);
					config.token = token;
				},
				Response::Error { message } => bail!("access request failed: {message}"),
				_ => bail!("unexpected response to the access request"),
			}
		},
		Response::Error { message } => bail!(
			"auth failed: {message}\nif the credential is stale, remove {} (or unset TESTD_TOKEN) and run again",
			testd_core::config::credential_path(&config.token_profile).display()
		),
		Response::Token { .. } => bail!("unexpected token response during auth"),
		Response::Stopped { .. }
		| Response::NameRevoked { .. }
		| Response::GrantRevoked
		| Response::PendingGrant { .. } => bail!("the host stopped this connection during auth"),
	}

	Ok(())
}

/// The client's identity as shown to the operator deciding a request.
fn client_label() -> String {
	let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default();
	let host = std::env::var("HOSTNAME")
		.or_else(|_| std::env::var("COMPUTERNAME"))
		.unwrap_or_default();
	match (user.trim(), host.trim()) {
		("", "") => "unknown client".into(),
		("", host) => host.into(),
		(user, "") => user.into(),
		(user, host) => format!("{user}@{host}"),
	}
}

/// Why one host could not be used. A host that answered but refused us is not
/// worth asking again on another host, which would queue a second request.
#[derive(Debug)]
struct ConnectFailure {
	error: anyhow::Error,
	retry: bool,
}

impl ConnectFailure {
	fn unreachable(error: anyhow::Error) -> Self {
		Self { error, retry: true }
	}

	fn rejected(error: anyhow::Error) -> Self {
		Self { error, retry: false }
	}

	/// Whether asking again could succeed. A host that refused us said no.
	pub(crate) fn is_retryable(&self) -> bool {
		self.retry
	}
}

impl std::fmt::Display for ConnectFailure {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.error)
	}
}

impl std::error::Error for ConnectFailure {}

/// Try every host once, starting at `start`.
async fn connect_from(config: &mut ClientConfig, start: usize, names: &[String]) -> Result<(Reader, Writer, usize)> {
	let hosts = hosts(config);
	let mut last_error = None;
	for offset in 0..hosts.len() {
		let index = (start + offset) % hosts.len();
		match connect_host(config, &hosts[index], names).await {
			Ok((reader, writer)) => {
				eprintln!("[testd] [host]  {}", hosts[index]);
				return Ok((reader, writer, index));
			},
			Err(e) => {
				let failure = match e.downcast::<ConnectFailure>() {
					Ok(failure) => failure,
					Err(error) => ConnectFailure::unreachable(error),
				};
				if !failure.retry {
					return Err(anyhow::Error::new(failure));
				}
				last_error = Some(failure.error);
			},
		}
	}
	Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no hosts configured")))
}

/// Connect to the first reachable host and authenticate.
pub(crate) async fn connect(config: &mut ClientConfig, names: &[String]) -> Result<(Reader, Writer)> {
	let (reader, writer, _) = connect_from(config, 0, names).await?;
	Ok((reader, writer))
}

/// The names a leaf will ask the host to grant, as the client spells them.
pub(crate) fn entry_names(entries: &[Entry]) -> Vec<String> {
	entries.iter().map(|entry| entry.domain.clone()).collect()
}

/// Send a request and wait for its outcome. A registration can wait on a
/// pending name grant, so the reply is not always the first frame back.
async fn request(reader: &mut Reader, writer: &mut Writer, req: &Request) -> Result<()> {
	protocol::send(writer, req).await?;
	loop {
		let response: Response = protocol::recv(reader).await?.context("host closed connection")?;
		match response {
			Response::Ok => return Ok(()),
			Response::PendingGrant { id, domain } => {
				eprintln!("[testd] [grant] the host is waiting for approval to grant {domain} (request {id})");
			},
			Response::Error { message } => bail!("host error: {message}"),
			other => bail!("host returned an unexpected response: {other:?}"),
		}
	}
}

/// Connect, register all entries, and return the connection for monitoring.
async fn connect_and_register(
	entries: &[Entry],
	config: &mut ClientConfig,
	force: bool,
	start: usize,
) -> Result<(Reader, Writer, usize)> {
	let (mut reader, mut writer, index) = connect_from(config, start, &entry_names(entries)).await?;
	for entry in entries {
		request(
			&mut reader,
			&mut writer,
			&Request::Register { domain: entry.domain.clone(), target: entry.target.clone(), force },
		)
		.await?;
		eprintln!("[testd] [reg]   {}", entry.domain);
	}
	Ok((reader, writer, index))
}

/// Whether the host name `app.example.test` is `published` as `app.example`.
/// Clients do not know the host's TLD, so one extra label is accepted.
pub(crate) fn is_published_name(published: &str, host_name: &str) -> bool {
	if published == host_name {
		return true;
	}
	match host_name.strip_prefix(published).and_then(|rest| rest.strip_prefix('.')) {
		Some(tld) => !tld.is_empty() && !tld.contains('.'),
		None => false,
	}
}

/// How the registration loop ended.
enum LoopEnd {
	/// The caller asked it to stop. The writer is handed back when the
	/// connection was up, for a graceful deregistration, together with the
	/// names that are still published.
	Stopped { writer: Option<Writer>, entries: Vec<Entry> },
	/// An operator stopped this leaf. The grant is still valid, so a later run
	/// publishes the names again without asking.
	StoppedByHost,
	/// An operator deleted this leaf's grant. The stored credential is gone.
	GrantRevoked,
	/// Every granted name was deleted one by one; nothing is left to publish.
	Revoked,
}

/// Maintain registration with automatic reconnect. Runs until `stop` fires or
/// an operator stops the leaf or deletes its grant.
async fn maintain_registration(
	mut entries: Vec<Entry>,
	mut config: ClientConfig,
	stop: Arc<Notify>,
	force: bool,
) -> LoopEnd {
	let mut retrying = false;
	let mut next_host = 0usize;
	let count = hosts(&config).len();

	loop {
		// Stop must also cancel a connection that is waiting for token approval.
		let connection = tokio::select! {
			result = connect_and_register(&entries, &mut config, force, next_host) => result,
			() = stop.notified() => return LoopEnd::Stopped { writer: None, entries },
		};
		let (reader, writer, index) = match connection {
			Ok(conn) => {
				retrying = false;
				conn
			},
			Err(e) => {
				// Authentication failures include a denied or expired token request.
				// Retrying would queue another request as soon as the operator answers.
				if e.downcast_ref::<ConnectFailure>().is_some_and(|failure| !failure.retry) {
					eprintln!("[testd] [error] {e:#}");
					return LoopEnd::Stopped { writer: None, entries };
				}
				if !retrying {
					// `{e:#}` prints the full context chain instead of only the outermost context.
					eprintln!("[testd] [error] {e:#}, retrying...");
					retrying = true;
				}
				next_host = (next_host + 1) % count;
				tokio::select! {
					() = tokio::time::sleep(RECONNECT_DELAY) => {}
					() = stop.notified() => return LoopEnd::Stopped { writer: None, entries },
				}
				continue;
			},
		};
		next_host = (index + 1) % count;

		match watch(reader, &stop, &mut entries).await {
			Watch::Stopped => return LoopEnd::Stopped { writer: Some(writer), entries },
			Watch::StoppedByHost => return LoopEnd::StoppedByHost,
			Watch::Revoked => return LoopEnd::Revoked,
			Watch::GrantRevoked => {
				// The stored copy is dead; drop it so the next run asks again.
				let path = testd_core::config::credential_path(&config.token_profile);
				if let Err(e) = testd_core::config::clear_credential(&config.token_profile) {
					eprintln!("[testd] [warn]  could not forget the deleted credential {}: {e}", path.display());
				}
				eprintln!(
					"[testd] [grant] the host operator deleted this leaf's grant; run again to request a new one \
					 (unset TESTD_TOKEN if it holds the old grant)"
				);
				return LoopEnd::GrantRevoked;
			},
			Watch::Disconnected => {
				eprintln!("[testd] [warn]  connection to {} lost, reconnecting...", hosts(&config)[index]);
			},
		}
	}
}

enum Watch {
	Disconnected,
	Stopped,
	StoppedByHost,
	GrantRevoked,
	Revoked,
}

/// Read host frames until the connection drops, the caller stops the loop, or
/// an operator stops the leaf or deletes its grant.
async fn watch(mut reader: Reader, stop: &Notify, entries: &mut Vec<Entry>) -> Watch {
	let (frames_tx, mut frames) = mpsc::channel(8);
	// Reading happens in its own task: `protocol::recv` is not cancellation
	// safe, so it must not race the stop signal directly.
	let reader_task = tokio::spawn(async move {
		while let Ok(Some(response)) = protocol::recv::<_, Response>(&mut reader).await {
			if frames_tx.send(response).await.is_err() {
				break;
			}
		}
	});

	let outcome = loop {
		tokio::select! {
			frame = frames.recv() => match frame {
				Some(Response::Stopped { domain }) => {
					eprintln!("[testd] [stop]  {domain} was stopped by the host operator (grant kept)");
					break Watch::StoppedByHost;
				},
				Some(Response::GrantRevoked) => break Watch::GrantRevoked,
				Some(Response::NameRevoked { domain }) => {
					eprintln!("[testd] [grant] the host operator deleted the grant for {domain}");
					entries.retain(|entry| !is_published_name(&entry.domain, &domain));
					if entries.is_empty() {
						eprintln!("[testd] [grant] no granted names remain; stopping");
						break Watch::Revoked;
					}
				},
				Some(_) => {},
				None => break Watch::Disconnected,
			},
			() = stop.notified() => break Watch::Stopped,
		}
	};
	reader_task.abort();
	outcome
}

/// Best-effort deregister on a writer (reader may be dead).
async fn deregister_best_effort(writer: &mut Writer, entries: &[Entry]) {
	for entry in entries {
		let _ = protocol::send(writer, &Request::Deregister { domain: entry.domain.clone() }).await;
		eprintln!("[testd] [dereg] {}", entry.domain);
	}
}

/// Register entries, run a command, deregister on exit.
pub async fn run(entries: &[Entry], command: &[String], force: bool, config: ClientConfig) -> Result<()> {
	let stop = Arc::new(Notify::new());

	// Maintain registration in the background.
	let bg_entries: Vec<Entry> = entries.to_vec();
	let bg_stop = stop.clone();
	let mut registration = tokio::spawn(async move { maintain_registration(bg_entries, config, bg_stop, force).await });

	// Spawn child process.
	let mut child = tokio::process::Command::new(&command[0])
		.args(&command[1..])
		.stdin(Stdio::inherit())
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.spawn()
		.with_context(|| format!("failed to spawn: {}", command[0]))?;

	// Wait for child, signal, or a registration loop that stopped on its own.
	let status = tokio::select! {
		status = child.wait() => status?,
		_ = tokio::signal::ctrl_c() => {
			child.kill().await.ok();
			child.wait().await?
		},
		result = &mut registration => {
			child.kill().await.ok();
			child.wait().await?;
			match result {
				// The operator's action already printed why; the child is ours
				// to stop, and exiting cleanly matches the operator's intent.
				Ok(LoopEnd::StoppedByHost | LoopEnd::GrantRevoked | LoopEnd::Revoked) => std::process::exit(0),
				Ok(LoopEnd::Stopped { writer: None, .. }) => bail!("registration stopped; see the error above"),
				Ok(LoopEnd::Stopped { writer: Some(_), .. }) => bail!("registration stopped unexpectedly"),
				Err(e) => bail!("registration task failed: {e}"),
			}
		}
	};

	// Stop the registration loop and deregister the names still published.
	stop.notify_one();
	if let Ok(LoopEnd::Stopped { writer: Some(mut writer), entries }) = registration.await {
		deregister_best_effort(&mut writer, &entries).await;
	}

	std::process::exit(status.code().unwrap_or(1));
}

/// Register entries and hold the connection until interrupted.
pub async fn register(entries: &[Entry], force: bool, config: ClientConfig) -> Result<()> {
	let stop = Arc::new(Notify::new());

	let bg_entries: Vec<Entry> = entries.to_vec();
	let bg_stop = stop.clone();
	let mut registration = tokio::spawn(async move { maintain_registration(bg_entries, config, bg_stop, force).await });

	eprintln!("[testd] Press Ctrl+C to deregister.");
	tokio::select! {
		_ = tokio::signal::ctrl_c() => {
			stop.notify_one();
		},
		result = &mut registration => match result {
			// The operator's action already printed why.
			Ok(LoopEnd::StoppedByHost | LoopEnd::GrantRevoked | LoopEnd::Revoked) => return Ok(()),
			Ok(LoopEnd::Stopped { writer: None, .. }) => bail!("registration stopped; see the error above"),
			Ok(LoopEnd::Stopped { writer: Some(_), .. }) => bail!("registration stopped unexpectedly"),
			Err(e) => bail!("registration task failed: {e}"),
		},
	}

	if let Ok(LoopEnd::Stopped { writer: Some(mut writer), entries }) = registration.await {
		deregister_best_effort(&mut writer, &entries).await;
	}

	Ok(())
}

/// Deregister domains by name (one-shot, no reconnect).
pub async fn deregister(domains: &[String], mut config: ClientConfig) -> Result<()> {
	let (mut reader, mut writer) = connect(&mut config, &[]).await?;

	for domain in domains {
		request(&mut reader, &mut writer, &Request::Deregister { domain: domain.clone() }).await?;
		eprintln!("[testd] [dereg] {domain}");
	}
	Ok(())
}

/// A name to register and the target it should proxy to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
	pub domain: String,
	/// The port (or host:port) sent to the host engine.
	pub target: String,
}

impl Entry {
	pub fn new(domain: impl Into<String>, target: impl Into<String>) -> Self {
		Self { domain: domain.into(), target: target.into() }
	}
}

#[cfg(test)]
mod tests {
	use super::is_published_name;

	#[test]
	fn node_credentials_are_used_for_loopback_actions() {
		assert!(is_published_name("app", "app.test"));
	}

	#[test]
	fn published_names_match_under_the_hosts_tld() {
		assert!(is_published_name("app", "app.test"));
		assert!(is_published_name("app.example", "app.example.test"));
		assert!(is_published_name("app.example", "app.example"));
		assert!(!is_published_name("app", "app.example.test"), "a shorter name is not the same name");
		assert!(!is_published_name("app.example", "api.app.example.test"));
	}
}
