//! Host engine: TCP server, connection handling, registration management.
//!
//! A client authenticates with the host's operator secret, or with the
//! daemon's loopback control token for local supervised launches.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot, watch};
use std::time::Duration;

use testd_core::Registration;
use testd_core::config::HostConfig;
use testd_core::protocol::{Auth, Request, Response, TokenRequest, recv, send};
use testd_core::validate;

use crate::access::{Access, Decision, IssuedToken};
use crate::http::{self, HttpContext, PeekedStream};
use crate::launch::LaunchBook;
use crate::registry::{DeregisterError, RegisterError, Registry};
use crate::resolver::Resolver;

/// Replies buffered for one connection before its writer task stalls the caller.
const OUTBOX_DEPTH: usize = 16;
/// Idle authenticated connections remain valid; setup and writes are bounded.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_INTAKE_CONNECTIONS: usize = 256;

/// Event emitted when the registration set changes.
#[derive(Debug, Clone)]
pub enum EngineEvent {
	/// The registration set changed. Contains the current snapshot.
	Changed(Vec<Registration>),
}

/// Shared registration state.
pub type Registrations = Arc<Mutex<Registry>>;

/// The host engine. Manages a TCP server and domain registrations.
pub struct HostEngine {
	config: HostConfig,
	registrations: Registrations,
	resolver: Arc<dyn Resolver>,
	access: Arc<Access>,
	shares: Option<Arc<crate::share::Shares>>,
	event_tx: broadcast::Sender<EngineEvent>,
	/// Accepted from loopback only; lets the local dashboard register supervised
	/// launches without carrying the operator secret.
	local_token: Option<String>,
	/// Local-only quick launches, shared with the loopback dashboard.
	launches: Option<Arc<LaunchBook>>,
	/// Re-probe health after a local certificate change.
	health_refresh: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl HostEngine {
	pub fn new(config: HostConfig, resolver: Arc<dyn Resolver>, access: Arc<Access>) -> Self {
		let (event_tx, _) = broadcast::channel(16);
		Self {
			config,
			registrations: Arc::new(Mutex::new(Registry::default())),
			resolver,
			access,
			shares: None,
			event_tx,
			local_token: None,
			launches: None,
			health_refresh: None,
		}
	}

	/// Set the per-run token accepted from loopback, used by the local GUI.
	pub fn set_local_token(&mut self, token: String) {
		self.local_token = Some(token);
	}

	/// Attach the share manager. Only the dashboard and the status API use it.
	pub fn set_shares(&mut self, shares: Arc<crate::share::Shares>) {
		self.shares = Some(shares);
	}

	pub fn set_launches(&mut self, launches: Arc<LaunchBook>) {
		self.launches = Some(launches);
	}

	/// Attach the health re-probe used after local certificate changes.
	pub fn set_health_refresh(&mut self, refresh: impl Fn() + Send + Sync + 'static) {
		self.health_refresh = Some(Arc::new(refresh));
	}

	/// The loopback dashboard URL: this listener serves HTTP on the same port.
	pub fn local_dashboard_url(&self) -> String {
		self.config.local_dashboard_url()
	}

	/// The live registration set, shared with the edge.
	pub fn registrations(&self) -> Registrations {
		self.registrations.clone()
	}

	/// Subscribe to engine events (registration changes).
	pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
		self.event_tx.subscribe()
	}

	/// Run the TCP server. Blocks until the listener fails.
	pub async fn run(&self) -> io::Result<()> {
		let listener = TcpListener::bind(self.config.listen_addr).await?;
		eprintln!("[listen] {}", self.config.listen_addr);
		self.serve(listener).await
	}

	/// Run the TCP server on an already-bound listener.
	pub async fn serve(&self, listener: TcpListener) -> io::Result<()> {
		let (operator_tx, mut operator_rx) = mpsc::channel::<OperatorRequest>(16);
		let mut revocations = self.access.revocations();
		let connections = Arc::new(Connections::default());
		let capacity = Arc::new(tokio::sync::Semaphore::new(MAX_INTAKE_CONNECTIONS));

		let http_ctx = Arc::new(HttpContext {
			tld: self.config.tld.clone(),
			pki_dir: self.config.pki_dir.clone(),
			registrations: self.registrations.clone(),
			connections: Arc::clone(&connections),
			operator_tx,
			launches: self.launches.clone(),
			health_refresh: self.health_refresh.clone(),
			shares: self.shares.clone(),
			access: Arc::clone(&self.access),
		});

		let shared = Arc::new(Shared {
			tld: self.config.tld.clone(),
			registrations: self.registrations.clone(),
			resolver: self.resolver.clone(),
			access: Arc::clone(&self.access),
			event_tx: self.event_tx.clone(),
			resolver_checked: AtomicBool::new(false),
			answer_addr: self.config.answer_addr,
			secret: self.config.secret.clone(),
			local_token: self.local_token.clone(),
			connections,
		});

		loop {
			tokio::select! {
				result = listener.accept() => {
					let (stream, addr) = result?;
					let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
						eprintln!("[warn]   intake connection limit reached: {}", addr.ip());
						continue;
					};
					let shared = shared.clone();
					let http_ctx = http_ctx.clone();

					tokio::spawn(async move {
						let _permit = permit;
						if let Err(e) = dispatch(stream, addr, shared, http_ctx).await {
							eprintln!("[error]  {}: {e}", addr.ip());
						}
					});
				}
				Some(request) = operator_rx.recv() => {
					let result = match request.action {
						OperatorAction::Stop { domain } => stop_leaf(&shared, &domain).await,
						OperatorAction::DeleteGrant { domain } => delete_grant(&shared, &domain).await,
					};
					let _ = request.respond.send(result);
				}
				changed = revocations.changed() => {
					changed.map_err(io::Error::other)?;
					for grant in shared.connections.grants() {
						if !shared.access.has_token(&grant) {
							close_grant(&shared, &grant).await;
						}
					}
				}
			}
		}
	}
}

/// A dashboard request that must run in the serve loop, which owns the
/// registration lock and the live connections.
pub struct OperatorRequest {
	pub action: OperatorAction,
	/// Resolves once the action is carried out or refused.
	pub respond: oneshot::Sender<Result<(), String>>,
}

/// The operator's actions on a granted name.
pub enum OperatorAction {
	/// Stop the leaf that publishes `domain`. Its grant is kept, so a later
	/// run publishes the name again without asking.
	Stop { domain: String },
	/// Delete the grant for one name. The leaf keeps its other names and must
	/// request access for this one again.
	DeleteGrant { domain: String },
}

/// Stop the leaf that publishes `fqdn` and unpublish the names it holds.
async fn stop_leaf(shared: &Shared, fqdn: &str) -> Result<(), String> {
	let (connection, evicted) = {
		let mut registrations = shared.registrations.lock().await;
		let connection = registrations
			.claim(fqdn)
			.map(|claim| claim.connection)
			.ok_or_else(|| format!("{fqdn} is not registered"))?;
		(connection, registrations.release(connection))
	};
	for registration in &evicted {
		eprintln!("[evict]  {} (leaf stopped)", registration.domain);
	}
	// Tell the owner so it stops instead of reconnecting. The credential is
	// untouched, so a later run publishes the names again.
	if let Some(connection) = shared.connections.take(connection) {
		connection.close(Some(Response::Stopped { domain: fqdn.to_owned() }));
	}
	apply(shared)
		.await
		.map_err(|e| format!("{fqdn} was stopped, but the edge could not be updated: {e}"))?;
	eprintln!("[stop]   {fqdn} (dashboard)");
	Ok(())
}

/// Delete the grant for one name. The leaf keeps its credential and every
/// other granted name, and has to ask for this one again.
async fn delete_grant(shared: &Shared, fqdn: &str) -> Result<(), String> {
	let claim = {
		let registrations = shared.registrations.lock().await;
		registrations
			.claim(fqdn)
			.cloned()
			.ok_or_else(|| format!("{fqdn} is not registered"))?
	};
	let Some(grant) = shared.connections.grant(claim.connection) else {
		return Err(format!("{fqdn} has no issued grant to delete"));
	};
	// A token from before per-name grants has no list. Pin it to the names it
	// publishes now, so deleting one name actually denies it.
	let live = {
		let registrations = shared.registrations.lock().await;
		let owners: HashSet<u64> = shared.connections.with_token(&grant).into_iter().collect();
		let mut names: Vec<String> = registrations
			.claims()
			.into_iter()
			.filter(|claim| owners.contains(&claim.connection))
			.map(|claim| claim.registration.domain)
			.collect();
		names.sort();
		names.dedup();
		names
	};
	shared
		.access
		.remove_name(&grant, fqdn, &live)
		.map_err(|e| format!("could not delete the grant: {e}"))?;
	// Unpublish only this name; the connection and its other names stay.
	let removed = shared.registrations.lock().await.deregister_any(fqdn);
	if removed.is_some()
		&& let Some(out) = shared.connections.outbox(claim.connection)
	{
		let notice = Response::NameRevoked { domain: fqdn.to_owned() };
		if out.try_send(notice).is_err() {
			/* A stalled leaf cannot hold up deletion; its other grants remain valid on reconnect. */
			if let Some(connection) = shared.connections.take(claim.connection) {
				connection.close(None);
			}
		}
	}
	apply(shared)
		.await
		.map_err(|e| format!("{fqdn} was deleted, but the edge could not be updated: {e}"))?;
	eprintln!("[grant]  {fqdn} deleted (dashboard)");
	Ok(())
}

/// Close every connection admitted with `grant` and release its names.
///
/// A dashboard deletion and the access store's own revocation both lead here;
/// the second pass finds nothing left to do.
async fn close_grant(shared: &Shared, grant: &str) {
	let mut closing = Vec::new();
	{
		let mut registrations = shared.registrations.lock().await;
		for connection in shared.connections.with_token(grant) {
			if let Some(closing_connection) = shared.connections.take(connection) {
				closing.push(closing_connection);
			}
			for registration in registrations.release(connection) {
				eprintln!("[evict]  {} (grant deleted)", registration.domain);
			}
		}
	}
	for connection in closing {
		connection.close(Some(Response::GrantRevoked));
	}
	if let Err(e) = apply(shared).await {
		eprintln!("[error]  grant deletion could not update the edge: {e}");
	}
}

/// State shared by every connection handler, independent of the connection itself.
struct Shared {
	tld: String,
	registrations: Registrations,
	resolver: Arc<dyn Resolver>,
	access: Arc<Access>,
	event_tx: broadcast::Sender<EngineEvent>,
	resolver_checked: AtomicBool,
	answer_addr: std::net::Ipv4Addr,
	/// The operator secret from `[host] secret`.
	secret: String,
	local_token: Option<String>,
	/// Authenticated connections the operator can act on.
	connections: Arc<Connections>,
}

/// Closure is independent of the bounded reply queue and preempts stalled I/O.
#[derive(Clone)]
enum ConnectionState {
	Open,
	Closing { notice: Option<Response> },
}

struct Connection {
	/// The issued token that authorizes this connection, if it has one.
	grant: Option<String>,
	out: mpsc::Sender<Response>,
	closing: watch::Sender<ConnectionState>,
}

impl Connection {
	fn close(self, notice: Option<Response>) {
		self.closing.send_replace(ConnectionState::Closing { notice });
	}
}

/// Connections reachable from the dashboard, keyed by connection id.
///
/// A plain mutex keeps every lookup independent of the registration lock, so a
/// dropped connection can clean itself up from a destructor.
#[derive(Default)]
pub struct Connections {
	inner: std::sync::Mutex<HashMap<u64, Connection>>,
}

impl Connections {
	fn add(
		&self,
		id: u64,
		grant: Option<String>,
		out: mpsc::Sender<Response>,
		closing: watch::Sender<ConnectionState>,
	) {
		self.inner
			.lock()
			.expect("connection map poisoned")
			.insert(id, Connection { grant, out, closing });
	}

	fn remove(&self, id: u64) {
		self.inner.lock().expect("connection map poisoned").remove(&id);
	}

	fn take(&self, id: u64) -> Option<Connection> {
		self.inner.lock().expect("connection map poisoned").remove(&id)
	}

	fn grants(&self) -> HashSet<String> {
		self.inner
			.lock()
			.expect("connection map poisoned")
			.values()
			.filter_map(|entry| entry.grant.clone())
			.collect()
	}

	/// Ids of the connections admitted with a given issued token.
	fn with_token(&self, grant: &str) -> Vec<u64> {
		self.inner
			.lock()
			.expect("connection map poisoned")
			.iter()
			.filter(|(_, connection)| connection.grant.as_deref() == Some(grant))
			.map(|(id, _)| *id)
			.collect()
	}

	fn outbox(&self, id: u64) -> Option<mpsc::Sender<Response>> {
		let inner = self.inner.lock().expect("connection map poisoned");
		inner.get(&id).map(|connection| connection.out.clone())
	}

	/// The issued grant behind a connection, if it has one.
	pub(crate) fn grant(&self, id: u64) -> Option<String> {
		let inner = self.inner.lock().expect("connection map poisoned");
		inner.get(&id).and_then(|connection| connection.grant.clone())
	}
}

/// Removes a connection from the operator's map when its handler exits.
struct ConnectionGuard {
	connections: Arc<Connections>,
	connection: u64,
}

impl Drop for ConnectionGuard {
	fn drop(&mut self) {
		self.connections.remove(self.connection);
	}
}

/// How a connection was admitted.
enum Credential {
	/// The daemon's per-run token, used by local supervised launches.
	Local,
	/// An issued leaf token, by id.
	Token(String),
	/// The operator secret.
	Secret,
}

impl Credential {
	/// The issued token to track for revocation, if there is one.
	fn issued(self) -> Option<String> {
		match self {
			Self::Token(id) => Some(id),
			Self::Local | Self::Secret => None,
		}
	}
}

/// Peek the first byte to distinguish NDJSON (`{`) from HTTP, then dispatch.
async fn dispatch(
	mut stream: TcpStream,
	addr: SocketAddr,
	shared: Arc<Shared>,
	http_ctx: Arc<HttpContext>,
) -> io::Result<()> {
	// Enable TCP keepalive to detect half-open connections.
	let sock_ref = socket2::SockRef::from(&stream);
	let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(10));
	sock_ref.set_tcp_keepalive(&keepalive).ok();

	let mut first = [0u8; 1];
	tokio::time::timeout(AUTH_TIMEOUT, stream.read_exact(&mut first))
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "intake greeting timed out"))??;
	let peeked = PeekedStream::new(first[0], stream);

	if first[0] == b'{' {
		handle_connection(peeked, addr, shared).await
	} else {
		http::handle(peeked, &http_ctx, addr).await
	}
}

/// Handle a single NDJSON client connection.
async fn handle_connection(stream: PeekedStream, addr: SocketAddr, shared: Arc<Shared>) -> io::Result<()> {
	let (reader, writer) = tokio::io::split(stream);
	let mut reader = BufReader::new(reader);

	// The writer lives in its own task so the operator can reach the client at
	// any time, not only in reply to a request.
	let (out, outbox) = mpsc::channel::<Response>(OUTBOX_DEPTH);
	let (closing, mut closing_rx) = watch::channel(ConnectionState::Open);
	let writer = tokio::spawn(write_outbox(writer, outbox, closing_rx.clone(), closing.clone()));

	let auth_msg: Auth = match tokio::time::timeout(AUTH_TIMEOUT, recv(&mut reader))
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "authentication frame timed out"))??
	{
		Some(a) => a,
		None => return Ok(()),
	};
	let credential = match auth_msg.request_token {
		Some(request) => {
			if !auth_msg.token.is_empty() {
				let message = "present a token or request one, not both".to_owned();
				reply(&out, Response::Error { message }).await?;
				return Ok(());
			}
			match request_access(&shared, request, addr, &mut reader, &out).await? {
				Some(issued) => {
					reply(&out, Response::Token { token: issued.token.clone() }).await?;
					Credential::Token(issued.id)
				},
				None => return Ok(()),
			}
		},
		None => {
			let Some(credential) = authenticate(&shared, &auth_msg.token, addr) else {
				reply(&out, Response::Error { message: "Authentication failed".into() }).await?;
				eprintln!("[auth]   {} rejected", addr.ip());
				return Ok(());
			};
			reply(&out, Response::Ok).await?;
			credential
		},
	};

	let connection = shared.registrations.lock().await.connection_id();
	let grant = credential.issued();
	shared.connections.add(connection, grant.clone(), out.clone(), closing.clone());
	let guard = ConnectionGuard { connections: Arc::clone(&shared.connections), connection };
	/* Authentication can race revocation before this connection enters the map. */
	if grant.as_ref().is_some_and(|id| !shared.access.has_token(id)) {
		closing.send_replace(ConnectionState::Closing { notice: Some(Response::GrantRevoked) });
	}

	let mut reader = RequestReader { reader, frame: Vec::new(), deferred: VecDeque::new() };
	let processing = async {
		loop {
			let request: Request = match reader.next().await {
				Ok(Some(r)) => r,
				Ok(None) => break,
				Err(error) => return Err(error),
			};

			match request {
				Request::Register { domain, target, force } => {
					let domain = validate::normalize_bare_domain(&domain, &shared.tld);
					if let Err(message) = validate::validate_domain(&domain, &shared.tld) {
						if reply(&out, Response::Error { message }).await.is_err() {
							break;
						}
						continue;
					}
					if let Err(message) = validate::validate_target(&target) {
						if reply(&out, Response::Error { message }).await.is_err() {
							break;
						}
						continue;
					}

					let fqdn = format!("{domain}.{}", shared.tld);
					// The dashboard's own name is never registrable, so refuse it
					// before asking the operator for a grant.
					let reserved = [format!("testd.{}", shared.tld)];
					if reserved.iter().any(|name| name == &fqdn) {
						let message = format!("{fqdn} is a reserved name.");
						if reply(&out, Response::Error { message }).await.is_err() {
							break;
						}
						continue;
					}
					// A leaf on the operator secret is trusted; an issued token only
					// covers the names the operator granted it.
					if let Some(grant) = &grant
						&& !shared.access.allows(grant, &fqdn)
						&& !request_name_grant(&shared, grant, &fqdn, addr, &mut reader, &out).await?
					{
						continue;
					}
					// Bare port → prepend client IP. Full host:port → use as-is.
					let target = if target.contains(':') { target } else { format!("{}:{target}", addr.ip()) };
					let registration = Registration { domain: fqdn.clone(), target: target.clone() };

					let reserved: Vec<&str> = reserved.iter().map(String::as_str).collect();
					let result =
						shared
							.registrations
							.lock()
							.await
							.register(connection, registration.clone(), force, &reserved);

					match result {
						Err(RegisterError::Duplicate { owner }) => {
							let message = format!(
								"{fqdn} is already registered by connection {owner}. Use --force to take it over."
							);
							eprintln!("[warn]   {message}");
							if reply(&out, Response::Error { message }).await.is_err() {
								break;
							}
						},
						Err(RegisterError::Reserved) => {
							let message = format!("{fqdn} is a reserved name.");
							if reply(&out, Response::Error { message }).await.is_err() {
								break;
							}
						},
						Ok(registered) => {
							ensure_resolver_for(&shared, addr).await;
							if let Err(e) = apply(&shared).await {
								let mut regs = shared.registrations.lock().await;
								regs.restore(connection, &fqdn, registered.displaced);
								drop(regs);
								let _ = apply(&shared).await;
								eprintln!("[error]  {fqdn} apply failed: {e}");
								if reply(&out, Response::Error { message: format!("{e}") }).await.is_err() {
									break;
								}
							} else {
								if validate::is_single_label(&domain) {
									eprintln!("[warn]   {fqdn}: {}", validate::SINGLE_LABEL_HINT);
								}
								eprintln!("[reg]    {fqdn} -> {target}");
								if reply(&out, Response::Ok).await.is_err() {
									break;
								}
							}
						},
					}
				},
				Request::Deregister { domain } => {
					let domain = validate::normalize_bare_domain(&domain, &shared.tld);
					if let Err(message) = validate::validate_domain(&domain, &shared.tld) {
						if reply(&out, Response::Error { message }).await.is_err() {
							break;
						}
						continue;
					}

					let fqdn = format!("{domain}.{}", shared.tld);
					let removed = shared.registrations.lock().await.deregister(connection, &fqdn);

					let error = match removed {
						Ok(registration) => match apply(&shared).await {
							Ok(()) => {
								eprintln!("[dereg]  {fqdn}");
								if reply(&out, Response::Ok).await.is_err() {
									break;
								}
								continue;
							},
							Err(e) => {
								// Restore the entry if it could not be unpublished.
								let mut regs = shared.registrations.lock().await;
								regs.register(connection, registration.clone(), true, &[]).ok();
								drop(regs);
								let _ = apply(&shared).await;
								eprintln!("[error]  {fqdn} apply failed: {e}");
								format!("{e}")
							},
						},
						Err(DeregisterError::NotFound) => format!("{fqdn} is not registered."),
						Err(DeregisterError::NotOwner { owner }) => format!("{fqdn} is owned by connection {owner}."),
					};

					if reply(&out, Response::Error { message: error }).await.is_err() {
						break;
					}
				},
			}
		}
		Ok::<_, io::Error>(())
	};
	let result = tokio::select! {
		biased;
		_ = wait_for_close(&mut closing_rx) => Ok(()),
		result = processing => result,
	};

	// Connection closed: evict only the claims this connection owns.
	let evicted = shared.registrations.lock().await.release(connection);
	if !evicted.is_empty() {
		for registration in &evicted {
			eprintln!("[evict]  {}", registration.domain);
		}
		if let Err(e) = apply(&shared).await {
			eprintln!("[error]  apply failed during eviction: {e}");
		}
	}

	drop(guard);
	drop(out);
	let _ = writer.await;
	result
}

async fn wait_for_close(closing: &mut watch::Receiver<ConnectionState>) -> Option<Response> {
	loop {
		if let ConnectionState::Closing { notice } = closing.borrow_and_update().clone() {
			return notice;
		}
		if closing.changed().await.is_err() {
			/* Ordinary disconnects drain queued replies when the sender is dropped. */
			std::future::pending::<()>().await;
		}
	}
}

async fn write_outbox<W: AsyncWrite + Unpin>(
	mut writer: W,
	mut outbox: mpsc::Receiver<Response>,
	mut closing: watch::Receiver<ConnectionState>,
	closing_signal: watch::Sender<ConnectionState>,
) {
	let notice = tokio::select! {
		biased;
		notice = wait_for_close(&mut closing) => notice,
		_ = async {
			while let Some(response) = outbox.recv().await {
				if !matches!(tokio::time::timeout(WRITE_TIMEOUT, send(&mut writer, &response)).await, Ok(Ok(()))) {
					break;
				}
			}
		} => {
			closing_signal.send_replace(ConnectionState::Closing { notice: None });
			None
		},
	};
	/* Closure delivery is best effort; dropping both halves is unconditional. */
	let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
		if let Some(notice) = notice {
			let _ = send(&mut writer, &notice).await;
		}
		let _ = writer.shutdown().await;
	})
	.await;
}

/// Queue one reply without letting a stalled peer trap its reader task.
async fn reply(out: &mpsc::Sender<Response>, response: Response) -> io::Result<()> {
	tokio::time::timeout(WRITE_TIMEOUT, out.send(response))
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "reply queue stalled"))?
		.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
}

/// The resolver is only needed when a client registers from another machine.
/// Configure it once, lazily, and fail open: the claim is still accepted even
/// if the privileged step is refused.
async fn ensure_resolver_for(shared: &Shared, addr: SocketAddr) {
	if addr.ip().is_loopback() || shared.resolver_checked.swap(true, Ordering::SeqCst) {
		return;
	}
	let resolver = Arc::clone(&shared.resolver);
	match tokio::task::spawn_blocking(move || resolver.ensure_os()).await {
		Ok(Ok(())) => {},
		Ok(Err(e)) => eprintln!("[warn]   resolver setup failed: {e}; run `testd doctor --fix` on the host"),
		Err(e) => eprintln!("[warn]   resolver setup task failed: {e}"),
	}
}

/// A connection is admitted with the operator secret, an issued token, or the
/// dashboard's per-run token when it comes from loopback.
fn authenticate(shared: &Shared, token: &str, addr: SocketAddr) -> Option<Credential> {
	if token.is_empty() {
		return None;
	}
	if addr.ip().is_loopback() && shared.local_token.as_deref() == Some(token) {
		eprintln!("[auth]   {} (local)", addr.ip());
		return Some(Credential::Local);
	}
	if let Some(issued) = shared.access.authenticate(token) {
		eprintln!("[auth]   {} (token {}: {})", addr.ip(), issued.id, issued.label);
		return Some(Credential::Token(issued.id));
	}
	if shared.secret.is_empty() {
		eprintln!("[warn]   no operator secret configured; run `testd init` on the host");
		return None;
	}
	if token == shared.secret {
		eprintln!("[auth]   {}", addr.ip());
		return Some(Credential::Secret);
	}
	None
}

/// Wait for an operator to decide a token request on this connection. Returns
/// the approved token, or `None` after telling the client why it got nothing.
async fn request_access<R>(
	shared: &Shared,
	request: TokenRequest,
	addr: SocketAddr,
	reader: &mut R,
	out: &mpsc::Sender<Response>,
) -> io::Result<Option<IssuedToken>>
where
	R: AsyncBufRead + Unpin,
{
	// The operator approves names, so they are normalized the same way the
	// registration path normalizes them.
	let names: Vec<String> = request
		.names
		.iter()
		.map(|domain| validate::normalize_bare_domain(domain, &shared.tld))
		.filter(|domain| validate::validate_domain(domain, &shared.tld).is_ok())
		.map(|domain| format!("{domain}.{}", shared.tld))
		.collect();
	let (id, mut decision) = match shared.access.request(&request.label, &addr.to_string(), names) {
		Ok(waiting) => waiting,
		Err(message) => {
			reply(out, Response::Error { message }).await?;
			return Ok(None);
		},
	};
	// Any exit from this function, including a dropped connection, clears the
	// request from the operator's queue.
	let _cancel = PendingGuard { access: Arc::clone(&shared.access), id: id.clone() };
	eprintln!("[auth]   {} requested access ({id}): {}", addr.ip(), request.label);
	reply(out, Response::Pending { id: id.clone() }).await?;

	let mut byte = [0u8; 1];
	let outcome = tokio::select! {
		decision = &mut decision => Waited::Decided(decision.ok()),
		read = reader.read(&mut byte) => {
			let _ = read;
			Waited::Closed
		},
		_ = tokio::time::sleep(crate::access::REQUEST_TTL) => Waited::Expired,
	};

	match outcome {
		Waited::Decided(Some(Decision::Approve(issued))) => {
			eprintln!("[auth]   {} approved ({id})", addr.ip());
			Ok(Some(issued))
		},
		Waited::Decided(Some(Decision::ApproveName)) => {
			let message = "the operator approved a name grant, not a token".to_owned();
			reply(out, Response::Error { message }).await?;
			Ok(None)
		},
		Waited::Decided(Some(Decision::Deny)) => {
			let message = "the operator denied this access request".to_owned();
			reply(out, Response::Error { message }).await?;
			eprintln!("[auth]   {} denied ({id})", addr.ip());
			Ok(None)
		},
		Waited::Decided(None) => {
			let message = "the access request is no longer pending".to_owned();
			let _ = reply(out, Response::Error { message }).await;
			Ok(None)
		},
		Waited::Closed => Ok(None),
		Waited::Expired => {
			let message = "the access request expired without approval".to_owned();
			let _ = reply(out, Response::Error { message }).await;
			eprintln!("[auth]   {} request expired ({id})", addr.ip());
			Ok(None)
		},
	}
}

/// Ask the operator for a grant on one name and wait for the answer. The
/// register request that triggered it stays open until the operator decides or
/// the request expires.
async fn request_name_grant<R: AsyncBufRead + Unpin>(
	shared: &Shared,
	grant: &str,
	fqdn: &str,
	addr: SocketAddr,
	reader: &mut RequestReader<R>,
	out: &mpsc::Sender<Response>,
) -> io::Result<bool> {
	let (id, mut decision) = match shared.access.request_name(grant, fqdn, &addr.to_string()) {
		Ok(waiting) => waiting,
		Err(message) => {
			reply(out, Response::Error { message }).await?;
			return Ok(false);
		},
	};
	let _cancel = PendingGuard { access: Arc::clone(&shared.access), id: id.clone() };
	eprintln!("[auth]   {} wants {fqdn} ({id})", addr.ip());
	reply(out, Response::PendingGrant { id: id.clone(), domain: fqdn.to_owned() }).await?;

	let outcome = tokio::select! {
		decision = &mut decision => decision.ok(),
		closed = reader.buffer_until_disconnect() => {
			closed?;
			return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "leaf disconnected during grant approval"));
		},
		_ = tokio::time::sleep(crate::access::REQUEST_TTL) => None,
	};
	match outcome {
		Some(Decision::ApproveName) => {
			eprintln!("[auth]   {} approved {fqdn} ({id})", addr.ip());
			Ok(true)
		},
		Some(Decision::Deny) => {
			let message = "the operator denied the grant for this name".to_owned();
			reply(out, Response::Error { message }).await?;
			eprintln!("[auth]   {} denied {fqdn} ({id})", addr.ip());
			Ok(false)
		},
		Some(Decision::Approve(_)) => {
			let message = "the operator approved a token, not a name grant".to_owned();
			reply(out, Response::Error { message }).await?;
			Ok(false)
		},
		None => {
			let message = "the grant request expired without approval".to_owned();
			reply(out, Response::Error { message }).await?;
			eprintln!("[auth]   {} grant request for {fqdn} expired ({id})", addr.ip());
			Ok(false)
		},
	}
}

/// Partial frames survive cancellation when a grant decision interrupts reads.
struct RequestReader<R> {
	reader: R,
	frame: Vec<u8>,
	deferred: VecDeque<Request>,
}

impl<R: AsyncBufRead + Unpin> RequestReader<R> {
	async fn next(&mut self) -> io::Result<Option<Request>> {
		match self.deferred.pop_front() {
			Some(request) => Ok(Some(request)),
			None => self.read().await,
		}
	}

	async fn read(&mut self) -> io::Result<Option<Request>> {
		/* Idle leaves keep their claims; started frames have a deadline. */
		if self.frame.is_empty() && self.reader.fill_buf().await?.is_empty() {
			return Ok(None);
		}
		let complete = tokio::time::timeout(
			AUTH_TIMEOUT,
			testd_core::protocol::read_line_into(
				&mut self.reader,
				&mut self.frame,
				testd_core::protocol::MAX_FRAME_BYTES,
			),
		)
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request frame timed out"))??;
		if !complete {
			return Ok(None);
		}
		let request = serde_json::from_slice(&self.frame).map_err(io::Error::other)?;
		self.frame.clear();
		Ok(Some(request))
	}

	/// Detect EOF during approval while preserving a bounded pipeline.
	async fn buffer_until_disconnect(&mut self) -> io::Result<()> {
		while let Some(request) = self.read().await? {
			if self.deferred.len() >= OUTBOX_DEPTH {
				return Err(io::Error::new(io::ErrorKind::InvalidData, "too many pipelined requests"));
			}
			self.deferred.push_back(request);
		}
		Ok(())
	}
}

enum Waited {
	Decided(Option<Decision>),
	Closed,
	Expired,
}

struct PendingGuard {
	access: Arc<Access>,
	id: String,
}

impl Drop for PendingGuard {
	fn drop(&mut self) {
		self.access.cancel(&self.id);
	}
}

/// Apply the current registration set to the resolver and tell subscribers.
async fn apply(shared: &Shared) -> io::Result<()> {
	let regs = shared.registrations.lock().await.snapshot();
	let names: Vec<crate::resolver::ResolvedName> = regs
		.iter()
		.map(|reg| crate::resolver::ResolvedName::new(reg.domain.clone(), shared.answer_addr))
		.collect();
	shared.resolver.apply(&names)?;
	let _ = shared.event_tx.send(EngineEvent::Changed(regs));
	let _ = shared.answer_addr;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn closure_preempts_a_full_reply_queue_and_a_blocked_writer() {
		let (writer, _unread_peer) = tokio::io::duplex(1);
		let (out, outbox) = mpsc::channel(OUTBOX_DEPTH);
		let (closing, receiver) = watch::channel(ConnectionState::Open);
		for _ in 0..OUTBOX_DEPTH {
			out.try_send(Response::Ok).unwrap();
		}
		let task = tokio::spawn(write_outbox(writer, outbox, receiver, closing.clone()));
		tokio::task::yield_now().await;
		closing.send_replace(ConnectionState::Closing { notice: Some(Response::GrantRevoked) });
		tokio::time::timeout(CLOSE_TIMEOUT + Duration::from_secs(1), task)
			.await
			.expect("closure bypasses the reply queue")
			.unwrap();
		assert!(out.is_closed());
	}
}
