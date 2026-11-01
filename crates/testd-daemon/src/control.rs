//! Loopback control channel for URL-scheme actions.
//!
//! An OS URL-scheme handler is a separate process. It forwards the URL to the
//! running daemon over a loopback TCP connection authenticated by a per-run
//! token written to a user-private file. The daemon remains the only place that
//! repairs anything, so the handler has no system privileges of its own.
//!
//! The channel accepts typed local commands: repair actions, and share start,
//! stop, and list. Each one is authenticated by the per-run token and only
//! reachable over loopback. There is no general command channel.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream as TokioTcpStream};

use testd_core::config::{ClientConfig, config_dir};

use crate::access::{Access, Approved, PendingView, TokenView};
use crate::engine::Registrations;
use crate::health::{Action, HealthMonitor};
use crate::share::{Provider, ShareView, Shares};

/// Name of the control file inside the testd config directory.
const CONTROL_FILE: &str = "control.json";
/// Largest request line the daemon accepts.
const MAX_REQUEST: u64 = 4096;

/// What a URL handler received from the daemon.
#[derive(Debug, PartialEq, Eq)]
pub enum Dispatch {
	/// The daemon ran the action and reported the result.
	Handled(Result<(), String>),
	/// No daemon is listening; the caller may run the action itself.
	NotRunning,
}

#[derive(Debug, Serialize, Deserialize)]
struct ControlFile {
	addr: String,
	token: String,
	#[serde(default)]
	client_addr: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Request {
	Url {
		token: String,
		url: String,
	},
	Share {
		token: String,
		name: String,
		#[serde(default)]
		provider: Option<Provider>,
	},
	Unshare {
		token: String,
		name: String,
	},
	Shares {
		token: String,
	},
	Requests {
		token: String,
	},
	Approve {
		token: String,
		id: String,
	},
	Deny {
		token: String,
		id: String,
	},
	Tokens {
		token: String,
	},
	RevokeToken {
		token: String,
		id: String,
	},
}

impl Request {
	fn token(&self) -> &str {
		match self {
			Request::Url { token, .. }
			| Request::Share { token, .. }
			| Request::Unshare { token, .. }
			| Request::Shares { token }
			| Request::Requests { token }
			| Request::Approve { token, .. }
			| Request::Deny { token, .. }
			| Request::Tokens { token }
			| Request::RevokeToken { token, .. } => token,
		}
	}
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
	ok: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	error: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	url: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	shares: Option<Vec<ShareView>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	requests: Option<Vec<PendingView>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	tokens: Option<Vec<TokenView>>,
}

impl Response {
	fn ok() -> Self {
		Self { ok: true, error: None, url: None, shares: None, requests: None, tokens: None }
	}

	fn err(message: impl Into<String>) -> Self {
		Self { ok: false, error: Some(message.into()), ..Self::ok() }
	}

	fn started(url: String) -> Self {
		Self { url: Some(url), ..Self::ok() }
	}

	fn listing(shares: Vec<ShareView>) -> Self {
		Self { shares: Some(shares), ..Self::ok() }
	}

	fn requests(requests: Vec<PendingView>) -> Self {
		Self { requests: Some(requests), ..Self::ok() }
	}

	fn tokens(tokens: Vec<TokenView>) -> Self {
		Self { tokens: Some(tokens), ..Self::ok() }
	}

	fn into_error(self) -> String {
		self.error.unwrap_or_else(|| "the daemon rejected the request".into())
	}
}

/// What the CLI learned from asking the daemon to share a name.
#[derive(Debug)]
pub enum ShareStarted {
	Started(String),
	Failed(String),
	/// No daemon is listening, so no tunnel can outlive this process.
	NotRunning,
}

/// Location of the control file for this user.
pub fn control_path() -> PathBuf {
	config_dir().join(CONTROL_FILE)
}

/// Local client credentials for GUI-supervised launches.
///
/// This token is accepted only from loopback and only by the daemon that wrote
/// the control file. It is not the operator secret and cannot be used
/// from another machine.
pub fn client_config() -> Result<ClientConfig, String> {
	client_config_at(&control_path())
}

fn client_config_at(path: &Path) -> Result<ClientConfig, String> {
	let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
	let control: ControlFile = serde_json::from_slice(&data).map_err(|e| format!("parse {}: {e}", path.display()))?;
	let host = control
		.client_addr
		.ok_or_else(|| "control file has no client address".to_owned())?;
	Ok(ClientConfig {
		token: control.token,
		token_profile: "local".into(),
		hosts: vec![host],
		node_profile: "local".into(),
	})
}

/// Forward an action URL to the daemon.
///
/// Returns [`Dispatch::NotRunning`] when the control file is absent or the
/// daemon is not accepting connections, so the caller can fall back to a
/// standalone repair. A daemon that answered but rejected the action is
/// returned as [`Dispatch::Handled`].
pub fn send_action(url: &str) -> io::Result<Dispatch> {
	Ok(match with_control(&control_path(), |token| Request::Url { token, url: url.to_owned() })? {
		None => Dispatch::NotRunning,
		Some(response) => Dispatch::Handled(if response.ok { Ok(()) } else { Err(response.into_error()) }),
	})
}

/// Ask the daemon to share a registered name.
pub fn start_share(name: &str, provider: Option<Provider>) -> io::Result<ShareStarted> {
	start_share_at(&control_path(), name, provider)
}

fn start_share_at(path: &Path, name: &str, provider: Option<Provider>) -> io::Result<ShareStarted> {
	let request = |token: String| Request::Share { token, name: name.to_owned(), provider };
	match with_control(path, request)? {
		None => Ok(ShareStarted::NotRunning),
		Some(response) if response.ok => {
			Ok(ShareStarted::Started(response.url.unwrap_or_else(|| "(no URL reported)".into())))
		},
		Some(response) => Ok(ShareStarted::Failed(response.into_error())),
	}
}

/// Ask the daemon to stop sharing a name.
pub fn stop_share(name: &str) -> io::Result<Dispatch> {
	stop_share_at(&control_path(), name)
}

fn stop_share_at(path: &Path, name: &str) -> io::Result<Dispatch> {
	let request = |token: String| Request::Unshare { token, name: name.to_owned() };
	Ok(match with_control(path, request)? {
		None => Dispatch::NotRunning,
		Some(response) => Dispatch::Handled(if response.ok { Ok(()) } else { Err(response.into_error()) }),
	})
}

/// Active shares, or `None` when no daemon is listening.
pub fn list_shares() -> io::Result<Option<Vec<ShareView>>> {
	list_shares_at(&control_path())
}

fn list_shares_at(path: &Path) -> io::Result<Option<Vec<ShareView>>> {
	let request = |token: String| Request::Shares { token };
	Ok(with_control(path, request)?.map(|response| response.shares.unwrap_or_default()))
}

/// Access requests waiting for an operator, or `None` when no daemon is listening.
pub fn list_requests() -> io::Result<Option<Vec<PendingView>>> {
	list_requests_at(&control_path())
}

fn list_requests_at(path: &Path) -> io::Result<Option<Vec<PendingView>>> {
	let request = |token: String| Request::Requests { token };
	Ok(with_control(path, request)?.map(|response| response.requests.unwrap_or_default()))
}

/// Approve a waiting access request.
pub fn approve_request(id: &str) -> io::Result<Dispatch> {
	approve_request_at(&control_path(), id)
}

fn approve_request_at(path: &Path, id: &str) -> io::Result<Dispatch> {
	let request = |token: String| Request::Approve { token, id: id.to_owned() };
	Ok(match with_control(path, request)? {
		None => Dispatch::NotRunning,
		Some(response) => Dispatch::Handled(if response.ok { Ok(()) } else { Err(response.into_error()) }),
	})
}

/// Deny a waiting access request.
pub fn deny_request(id: &str) -> io::Result<Dispatch> {
	deny_request_at(&control_path(), id)
}

fn deny_request_at(path: &Path, id: &str) -> io::Result<Dispatch> {
	let request = |token: String| Request::Deny { token, id: id.to_owned() };
	Ok(match with_control(path, request)? {
		None => Dispatch::NotRunning,
		Some(response) => Dispatch::Handled(if response.ok { Ok(()) } else { Err(response.into_error()) }),
	})
}

/// Tokens issued to leaves, or `None` when no daemon is listening.
pub fn list_tokens() -> io::Result<Option<Vec<TokenView>>> {
	list_tokens_at(&control_path())
}

fn list_tokens_at(path: &Path) -> io::Result<Option<Vec<TokenView>>> {
	let request = |token: String| Request::Tokens { token };
	Ok(with_control(path, request)?.map(|response| response.tokens.unwrap_or_default()))
}

/// Revoke an issued token.
pub fn revoke_token(id: &str) -> io::Result<Dispatch> {
	revoke_token_at(&control_path(), id)
}

fn revoke_token_at(path: &Path, id: &str) -> io::Result<Dispatch> {
	let request = |token: String| Request::RevokeToken { token, id: id.to_owned() };
	Ok(match with_control(path, request)? {
		None => Dispatch::NotRunning,
		Some(response) => Dispatch::Handled(if response.ok { Ok(()) } else { Err(response.into_error()) }),
	})
}

/// One request and one response over loopback. `None` means no daemon answered.
fn with_control(path: &Path, build: impl FnOnce(String) -> Request) -> io::Result<Option<Response>> {
	let data = match std::fs::read(path) {
		Ok(data) => data,
		Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
		Err(e) => return Err(e),
	};
	let control: ControlFile = serde_json::from_slice(&data).map_err(invalid_data)?;
	let addr: SocketAddr = control.addr.parse().map_err(invalid_data)?;

	let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
		Ok(stream) => stream,
		Err(e)
			if matches!(
				e.kind(),
				io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut | io::ErrorKind::NotFound
			) =>
		{
			return Ok(None);
		},
		Err(e) => return Err(e),
	};
	stream.set_write_timeout(Some(Duration::from_secs(5)))?;
	// A share start waits for a provider to print its URL. The daemon bounds that
	// wait, so there is deliberately no read timeout here.

	let request = serde_json::to_vec(&build(control.token)).map_err(invalid_data)?;
	stream.write_all(&request)?;
	stream.write_all(b"\n")?;

	let mut reader = BufReader::new(stream);
	let mut line = String::new();
	reader.read_line(&mut line)?;
	if line.is_empty() {
		return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the daemon closed the control channel"));
	}
	Ok(Some(serde_json::from_str(&line).map_err(invalid_data)?))
}

/// `app.example.test` and `app.example` name the same registration.
fn strip_tld<'a>(name: &'a str, tld: &str) -> &'a str {
	name.strip_suffix(&format!(".{tld}")).unwrap_or(name)
}

fn invalid_data(e: impl std::fmt::Display) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// The daemon's URL-action listener.
///
/// Kept alive by [`crate::daemon::Daemon`]; dropping it removes the control file.
pub struct ControlServer {
	path: PathBuf,
	token: String,
}

impl ControlServer {
	pub(crate) async fn start(
		health: Arc<HealthMonitor>,
		client_addr: SocketAddr,
		shares: Arc<Shares>,
		registrations: Registrations,
		access: Arc<Access>,
		tld: String,
	) -> io::Result<Self> {
		Self::start_at(control_path(), health, client_addr, shares, registrations, access, tld).await
	}

	async fn start_at(
		path: PathBuf,
		health: Arc<HealthMonitor>,
		client_addr: SocketAddr,
		shares: Arc<Shares>,
		registrations: Registrations,
		access: Arc<Access>,
		tld: String,
	) -> io::Result<Self> {
		let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
		let addr = listener.local_addr()?;
		let token = random_token();
		write_control_file(&path, addr, client_addr, &token)?;
		tokio::spawn(accept_loop(listener, token.clone(), health, shares, registrations, access, tld));
		Ok(Self { path, token })
	}

	/// The local token accepted by the daemon's client listener.
	pub(crate) fn token(&self) -> &str {
		&self.token
	}
}

impl Drop for ControlServer {
	fn drop(&mut self) {
		let _ = std::fs::remove_file(&self.path);
	}
}

fn random_token() -> String {
	let mut bytes = [0u8; 32];
	getrandom::fill(&mut bytes).expect("failed to obtain random bytes");
	URL_SAFE_NO_PAD.encode(bytes)
}

fn write_control_file(path: &Path, addr: SocketAddr, client_addr: SocketAddr, token: &str) -> io::Result<()> {
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	let control =
		ControlFile { addr: addr.to_string(), token: token.to_owned(), client_addr: Some(client_addr.to_string()) };
	let data = serde_json::to_vec(&control).map_err(invalid_data)?;

	// Write then rename so a handler never reads a partial file.
	let tmp = path.with_extension("tmp");
	std::fs::write(&tmp, data)?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
	}
	std::fs::rename(&tmp, path)
}

async fn accept_loop(
	listener: TcpListener,
	token: String,
	health: Arc<HealthMonitor>,
	shares: Arc<Shares>,
	registrations: Registrations,
	access: Arc<Access>,
	tld: String,
) {
	loop {
		match listener.accept().await {
			Ok((stream, _)) => {
				tokio::spawn(handle(
					stream,
					token.clone(),
					Arc::clone(&health),
					Arc::clone(&shares),
					registrations.clone(),
					Arc::clone(&access),
					tld.clone(),
				));
			},
			Err(e) => {
				eprintln!("[warn]   control accept failed: {e}");
				tokio::time::sleep(Duration::from_millis(100)).await;
			},
		}
	}
}

async fn handle(
	stream: TokioTcpStream,
	token: String,
	health: Arc<HealthMonitor>,
	shares: Arc<Shares>,
	registrations: Registrations,
	access: Arc<Access>,
	tld: String,
) {
	let (reader, mut writer) = stream.into_split();
	let mut reader = TokioBufReader::new(reader).take(MAX_REQUEST);
	let mut line = String::new();
	let response = match tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await {
		Ok(Ok(0)) => Response::err("empty request"),
		Ok(Ok(_)) => match serde_json::from_str::<Request>(&line) {
			Ok(request) if request.token() == token => match request {
				Request::Url { url, .. } => match Action::parse(&url) {
					Some(action) => match tokio::task::spawn_blocking(move || health.repair(action)).await {
						Ok(Ok(())) => Response::ok(),
						Ok(Err(e)) => Response::err(e.to_string()),
						Err(e) => Response::err(format!("repair task failed: {e}")),
					},
					None => Response::err(format!("unknown testd action: {url}")),
				},
				Request::Share { name, provider, .. } => {
					// Registrations carry the TLD; shares are keyed by the name the
					// caller used, without it.
					let bare = strip_tld(&name, &tld).to_owned();
					let fqdn = format!("{bare}.{tld}");
					let target = registrations
						.lock()
						.await
						.snapshot()
						.into_iter()
						.find(|registration| registration.domain == fqdn || registration.domain == bare)
						.map(|registration| registration.target);
					match target {
						None => Response::err(format!("{bare} is not registered on this host")),
						Some(target) => match shares.start(&bare, &target, provider).await {
							Ok(url) => Response::started(url),
							Err(e) => Response::err(format!("{e:#}")),
						},
					}
				},
				Request::Unshare { name, .. } => {
					let bare = strip_tld(&name, &tld);
					if shares.stop(bare).await {
						Response::ok()
					} else {
						Response::err(format!("{bare} is not shared"))
					}
				},
				Request::Shares { .. } => Response::listing(shares.list().await),
				Request::Requests { .. } => Response::requests(access.pending()),
				Request::Approve { id, .. } => match access.approve(&id) {
					Ok(Approved::Token(token)) => {
						eprintln!("[access] approved {} ({})", token.label, token.id);
						Response::ok()
					},
					Ok(Approved::Name) => {
						eprintln!("[access] approved a name grant ({id})");
						Response::ok()
					},
					Err(e) => Response::err(e),
				},
				Request::Deny { id, .. } => match access.deny(&id) {
					Ok(()) => {
						eprintln!("[access] denied {id}");
						Response::ok()
					},
					Err(e) => Response::err(e),
				},
				Request::Tokens { .. } => Response::tokens(access.tokens()),
				Request::RevokeToken { id, .. } => match access.revoke(&id) {
					Ok(()) => {
						eprintln!("[access] revoked token {id}");
						Response::ok()
					},
					Err(e) => Response::err(e),
				},
			},
			Ok(_) => Response::err("unauthorized"),
			Err(e) => Response::err(format!("invalid request: {e}")),
		},
		Ok(Err(e)) => Response::err(format!("read failed: {e}")),
		Err(_) => Response::err("request timed out"),
	};

	let mut data = serde_json::to_vec(&response).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
	data.push(b'\n');
	let _ = tokio::time::timeout(Duration::from_secs(5), writer.write_all(&data)).await;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::health::RootAuthority;
	use crate::registry::Registry;
	#[cfg(unix)]
	use crate::share::Exposure;
	use tokio::sync::Mutex as AsyncMutex;
	use crate::resolver::{ResolvedName, Resolver};
	use std::sync::atomic::{AtomicBool, Ordering};
	use testd_setup::Elevation;

	struct FakeResolver {
		configured: AtomicBool,
	}

	impl Resolver for FakeResolver {
		fn apply(&self, _names: &[ResolvedName]) -> io::Result<()> {
			Ok(())
		}

		fn ensure_os(&self) -> io::Result<()> {
			self.configured.store(true, Ordering::SeqCst);
			Ok(())
		}

		fn is_os_configured(&self) -> bool {
			self.configured.load(Ordering::SeqCst)
		}

		fn cleanup(&self) -> io::Result<()> {
			Ok(())
		}
	}

	struct FakeRoot;

	impl RootAuthority for FakeRoot {
		fn is_trusted(&self) -> bool {
			false
		}

		fn install(&self, _elevation: Elevation) -> io::Result<()> {
			Ok(())
		}
	}

	fn monitor() -> (Arc<HealthMonitor>, Arc<FakeResolver>) {
		let resolver = Arc::new(FakeResolver { configured: AtomicBool::new(false) });
		let health =
			Arc::new(HealthMonitor::new("test".into(), resolver.clone(), Some(Arc::new(FakeRoot)), Elevation::Gui));
		(health, resolver)
	}

	fn dispatch(path: &Path, url: &str) -> io::Result<Dispatch> {
		Ok(match with_control(path, |token| Request::Url { token, url: url.to_owned() })? {
			None => Dispatch::NotRunning,
			Some(response) => Dispatch::Handled(if response.ok { Ok(()) } else { Err(response.into_error()) }),
		})
	}

	async fn run(path: PathBuf, url: &str) -> io::Result<Dispatch> {
		let url = url.to_owned();
		tokio::task::spawn_blocking(move || dispatch(&path, &url)).await.unwrap()
	}

	fn shares() -> (Arc<Shares>, Registrations) {
		let shares = Arc::new(Shares::new(Provider::Cloudflared, None, None));
		let registrations: Registrations = Arc::new(AsyncMutex::new(Registry::default()));
		(shares, registrations)
	}

	fn access() -> Arc<Access> {
		use std::sync::atomic::{AtomicU64, Ordering};
		static NEXT: AtomicU64 = AtomicU64::new(0);
		let path = std::env::temp_dir().join(format!(
			"testd-access-{}-{}.json",
			std::process::id(),
			NEXT.fetch_add(1, Ordering::SeqCst)
		));
		Arc::new(Access::load(path).unwrap())
	}

	#[tokio::test]
	async fn runs_an_action_in_the_daemon() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join(CONTROL_FILE);
		let (health, resolver) = monitor();
		let (shares, registrations) = shares();
		let server = ControlServer::start_at(
			path.clone(),
			health.clone(),
			"127.0.0.1:1".parse().unwrap(),
			shares,
			registrations,
			access(),
			"test".to_owned(),
		)
		.await
		.unwrap();

		let result = run(path.clone(), Action::SetupResolver.url()).await.unwrap();
		assert_eq!(result, Dispatch::Handled(Ok(())));
		assert!(resolver.configured.load(Ordering::SeqCst));
		assert!(health.health().resolver);

		drop(server);
		assert!(!path.exists());
	}

	#[tokio::test]
	async fn reports_an_unknown_action() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join(CONTROL_FILE);
		let (health, _) = monitor();
		let (shares, registrations) = shares();
		let _server = ControlServer::start_at(
			path.clone(),
			health,
			"127.0.0.1:1".parse().unwrap(),
			shares,
			registrations,
			access(),
			"test".to_owned(),
		)
		.await
		.unwrap();

		match run(path, "testd://fix/unknown").await.unwrap() {
			Dispatch::Handled(Err(message)) => assert!(message.contains("unknown testd action")),
			other => panic!("unexpected dispatch: {other:?}"),
		}
	}

	#[tokio::test]
	async fn rejects_a_wrong_token() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join(CONTROL_FILE);
		let (health, _) = monitor();
		let (shares, registrations) = shares();
		let _server = ControlServer::start_at(
			path.clone(),
			health,
			"127.0.0.1:1".parse().unwrap(),
			shares,
			registrations,
			access(),
			"test".to_owned(),
		)
		.await
		.unwrap();

		let response = tokio::task::spawn_blocking(move || {
			let control: ControlFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
			let addr: SocketAddr = control.addr.parse().unwrap();
			let mut stream = TcpStream::connect(addr).unwrap();
			let request =
				serde_json::to_vec(&Request::Url { token: "wrong".into(), url: Action::TrustRoot.url().into() })
					.unwrap();
			stream.write_all(&request).unwrap();
			stream.write_all(b"\n").unwrap();
			let mut line = String::new();
			BufReader::new(stream).read_line(&mut line).unwrap();
			serde_json::from_str::<Response>(&line).unwrap()
		})
		.await
		.unwrap();
		assert!(!response.ok);
		assert_eq!(response.error.as_deref(), Some("unauthorized"));
	}

	#[tokio::test]
	async fn missing_or_stale_control_file_means_not_running() {
		let dir = tempfile::tempdir().unwrap();
		let missing = dir.path().join("missing.json");
		assert_eq!(dispatch(&missing, Action::SetupResolver.url()).unwrap(), Dispatch::NotRunning);

		let stale = dir.path().join("stale.json");
		std::fs::write(&stale, br#"{"addr":"127.0.0.1:1","token":"x"}"#).unwrap();
		assert_eq!(dispatch(&stale, Action::SetupResolver.url()).unwrap(), Dispatch::NotRunning);
	}

	#[tokio::test]
	async fn writes_local_client_credentials() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join(CONTROL_FILE);
		let (health, _) = monitor();
		let (shares, registrations) = shares();
		let server = ControlServer::start_at(
			path.clone(),
			health,
			"127.0.0.1:17737".parse().unwrap(),
			shares,
			registrations,
			access(),
			"test".to_owned(),
		)
		.await
		.unwrap();
		let config = client_config_at(&path).unwrap();
		assert_eq!(config.hosts, vec!["127.0.0.1:17737"]);
		assert_eq!(config.token, server.token());
	}

	#[tokio::test]
	async fn lists_and_approves_an_access_request() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join(CONTROL_FILE);
		let (health, _) = monitor();
		let (shares, registrations) = shares();
		let access = access();
		let names = vec!["app.example.test".to_owned()];
		let (id, decision) = access.request("alex@laptop", "192.168.1.9:5000", names).unwrap();
		let _server = ControlServer::start_at(
			path.clone(),
			health,
			"127.0.0.1:1".parse().unwrap(),
			shares,
			registrations,
			Arc::clone(&access),
			"test".to_owned(),
		)
		.await
		.unwrap();

		let listed = {
			let path = path.clone();
			tokio::task::spawn_blocking(move || list_requests_at(&path))
				.await
				.unwrap()
				.unwrap()
				.unwrap()
		};
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].label, "alex@laptop");
		assert_eq!(listed[0].id, id);

		let approved = {
			let path = path.clone();
			let id = id.clone();
			tokio::task::spawn_blocking(move || approve_request_at(&path, &id))
				.await
				.unwrap()
				.unwrap()
		};
		assert_eq!(approved, Dispatch::Handled(Ok(())));
		assert!(matches!(decision.await.unwrap(), crate::access::Decision::Approve(_)));
		assert_eq!(access.tokens().len(), 1);
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn starts_lists_and_stops_a_share() {
		use std::os::unix::fs::PermissionsExt;

		let dir = tempfile::tempdir().unwrap();
		let provider = dir.path().join("fake-tunnel.sh");
		std::fs::write(&provider, "#!/bin/sh\necho 'INF |  https://fake-name.trycloudflare.com  |' >&2\nsleep 30\n")
			.unwrap();
		std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();

		let path = dir.path().join(CONTROL_FILE);
		let (health, _) = monitor();
		let shares = Arc::new(Shares::new(Provider::Cloudflared, Some(provider), None));
		let registrations: Registrations = Arc::new(AsyncMutex::new(Registry::default()));
		{
			let mut registry = registrations.lock().await;
			let connection = registry.connection_id();
			registry
				.register(
					connection,
					testd_core::Registration { domain: "app.example.test".into(), target: "127.0.0.1:3000".into() },
					false,
					&[],
				)
				.unwrap();
		}

		let _server = ControlServer::start_at(
			path.clone(),
			health,
			"127.0.0.1:1".parse().unwrap(),
			Arc::clone(&shares),
			registrations.clone(),
			access(),
			"test".to_owned(),
		)
		.await
		.unwrap();

		let started = {
			let path = path.clone();
			tokio::task::spawn_blocking(move || start_share_at(&path, "app.example", None))
				.await
				.unwrap()
				.unwrap()
		};
		match started {
			ShareStarted::Started(url) => assert!(url.contains("fake-name.trycloudflare.com"), "{url}"),
			other => panic!("unexpected result: {other:?}"),
		}

		let listed = {
			let path = path.clone();
			tokio::task::spawn_blocking(move || list_shares_at(&path))
				.await
				.unwrap()
				.unwrap()
				.unwrap()
		};
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].name, "app.example");
		assert_eq!(listed[0].provider, "cloudflared");
		assert_eq!(listed[0].exposure, Exposure::Public);

		// A second start for the same name is refused rather than replacing it.
		let again = {
			let path = path.clone();
			tokio::task::spawn_blocking(move || start_share_at(&path, "app.example", None))
				.await
				.unwrap()
				.unwrap()
		};
		match again {
			ShareStarted::Failed(message) => assert!(message.contains("already shared"), "{message}"),
			other => panic!("unexpected result: {other:?}"),
		}

		let stopped = {
			let path = path.clone();
			tokio::task::spawn_blocking(move || stop_share_at(&path, "app.example"))
				.await
				.unwrap()
				.unwrap()
		};
		assert_eq!(stopped, Dispatch::Handled(Ok(())));
		assert!(shares.list().await.is_empty());
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn sharing_an_unregistered_name_is_refused() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join(CONTROL_FILE);
		let (health, _) = monitor();
		let (shares, registrations) = shares();
		let _server = ControlServer::start_at(
			path.clone(),
			health,
			"127.0.0.1:1".parse().unwrap(),
			shares,
			registrations,
			access(),
			"test".to_owned(),
		)
		.await
		.unwrap();

		let result = {
			let path = path.clone();
			tokio::task::spawn_blocking(move || start_share_at(&path, "app.example", None))
				.await
				.unwrap()
				.unwrap()
		};
		match result {
			ShareStarted::Failed(message) => assert!(message.contains("not registered"), "{message}"),
			other => panic!("unexpected result: {other:?}"),
		}
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn control_file_is_private() {
		use std::os::unix::fs::PermissionsExt;

		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join(CONTROL_FILE);
		let (health, _) = monitor();
		let (shares, registrations) = shares();
		let _server = ControlServer::start_at(
			path.clone(),
			health,
			"127.0.0.1:1".parse().unwrap(),
			shares,
			registrations,
			access(),
			"test".to_owned(),
		)
		.await
		.unwrap();
		let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o600);
	}
}
