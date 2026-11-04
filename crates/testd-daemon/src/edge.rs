//! In-process HTTPS edge: rustls termination with on-demand leaf minting and a
//! hyper reverse proxy driven by the live registration set.
//!
//! One listener terminates TLS; an optional plain listener exists so an
//! external front (Caddy, nginx) can route to the same table. Both speak
//! HTTP/1.1 only: it keeps WebSocket upgrades simple and is what dev servers
//! speak upstream.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONNECTION, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue, UPGRADE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use testd_pki::Ca;

use crate::engine::Registrations;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;

/// Bounds for the edge. The intake listener has its own connection cap.
const MAX_EDGE_CONNECTIONS: usize = 512;
const MAX_EDGE_CONNECTIONS_PER_IP: usize = 64;
const MAX_CERT_CACHE: usize = 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Renew a cached leaf when 25% of its validity remains, i.e. after 75% of the
/// leaf lifetime. For the default 24-hour leaf that is 18 hours.
pub fn leaf_renewal_after() -> Duration {
	Duration::from_secs((testd_pki::LEAF_LIFETIME_HOURS as u64) * 3600 * 3 / 4)
}

/// Shared state for the edge and the plain router.
pub struct EdgeContext {
	pub tld: String,
	pub registrations: Registrations,
	/// Loopback dashboard listener. The dashboard name is proxied here for
	/// loopback clients only; `None` leaves the name unrouted.
	pub dashboard_addr: Option<SocketAddr>,
	/// Connection and response-header timeout for an upstream.
	pub upstream_timeout: Duration,
	/// Trust an inbound X-Forwarded-For from a configured front proxy.
	pub trust_forwarded_for: bool,
}

impl EdgeContext {
	pub fn new(tld: impl Into<String>, registrations: Registrations) -> Self {
		Self {
			tld: tld.into(),
			registrations,
			dashboard_addr: None,
			upstream_timeout: Duration::from_secs(30),
			trust_forwarded_for: false,
		}
	}
}

/// A running edge.
pub struct Edge {
	pub tls_addr: SocketAddr,
	pub http_addr: SocketAddr,
	tasks: Vec<JoinHandle<()>>,
}

/// Limits both the total number of edge connections and the number from one
/// source, so a LAN client cannot exhaust the daemon by opening handshakes.
struct ConnectionLimiter {
	inner: Mutex<LimiterState>,
	max_total: usize,
	max_per_ip: usize,
}

#[derive(Default)]
struct LimiterState {
	total: usize,
	per_ip: HashMap<IpAddr, usize>,
}

struct ConnectionPermit {
	limiter: Arc<ConnectionLimiter>,
	ip: IpAddr,
}

impl ConnectionLimiter {
	fn new(max_total: usize, max_per_ip: usize) -> Self {
		Self { inner: Mutex::new(LimiterState::default()), max_total, max_per_ip }
	}

	fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionPermit> {
		let mut state = self.inner.lock().expect("edge connection limiter poisoned");
		if state.total >= self.max_total || state.per_ip.get(&ip).copied().unwrap_or(0) >= self.max_per_ip {
			return None;
		}
		state.total += 1;
		*state.per_ip.entry(ip).or_default() += 1;
		Some(ConnectionPermit { limiter: Arc::clone(self), ip })
	}
}

impl Drop for ConnectionPermit {
	fn drop(&mut self) {
		let mut state = self.limiter.inner.lock().expect("edge connection limiter poisoned");
		state.total = state.total.saturating_sub(1);
		if let Some(count) = state.per_ip.get_mut(&self.ip) {
			*count = count.saturating_sub(1);
			if *count == 0 {
				state.per_ip.remove(&self.ip);
			}
		}
	}
}

impl Drop for Edge {
	fn drop(&mut self) {
		for task in &self.tasks {
			task.abort();
		}
	}
}

/// Start the TLS listener (if `tls_addr` is set) and the plain router.
pub fn start(
	ctx: Arc<EdgeContext>,
	tls_addr: Option<SocketAddr>,
	http_addr: SocketAddr,
	pki_dir: &std::path::Path,
) -> Result<Edge> {
	let mut tasks = Vec::new();
	let limiter = Arc::new(ConnectionLimiter::new(MAX_EDGE_CONNECTIONS, MAX_EDGE_CONNECTIONS_PER_IP));

	let plain = std::net::TcpListener::bind(http_addr).context("bind the plain edge listener")?;
	plain.set_nonblocking(true)?;
	let plain = TcpListener::from_std(plain)?;
	let http_addr = plain.local_addr()?;
	let plain_ctx = ctx.clone();
	let plain_limiter = Arc::clone(&limiter);
	tasks.push(tokio::spawn(async move {
		if let Err(e) = accept_loop(plain, PlainHandler { ctx: plain_ctx }, plain_limiter).await {
			eprintln!("[error] plain edge: {e}");
		}
	}));

	let tls_addr = match tls_addr {
		Some(addr) => {
			let listener = std::net::TcpListener::bind(addr).with_context(|| {
				format!(
					"bind the HTTPS edge on {addr}; grant the binary CAP_NET_BIND_SERVICE or set [host] edge_addr to a high port"
				)
			})?;
			listener.set_nonblocking(true)?;
			let listener = TcpListener::from_std(listener)?;
			let actual = listener.local_addr()?;

			let ca = Arc::new(Ca::load_or_init(pki_dir).context("initialize the local CA")?);
			let resolver = Arc::new(CertStore::new(ca, ctx.tld.clone(), ctx.registrations.clone()));
			let mut config = rustls::ServerConfig::builder()
				.with_no_client_auth()
				.with_cert_resolver(resolver);
			config.alpn_protocols = vec![b"http/1.1".to_vec()];
			let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

			let tls_ctx = ctx.clone();
			let tls_limiter = Arc::clone(&limiter);
			tasks.push(tokio::spawn(async move {
				if let Err(e) = tls_accept_loop(listener, acceptor, tls_ctx, tls_limiter).await {
					eprintln!("[error] HTTPS edge: {e}");
				}
			}));
			Some(actual)
		},
		None => None,
	};

	Ok(Edge { tls_addr: tls_addr.unwrap_or(http_addr), http_addr, tasks })
}

/// On-demand certificate resolver. Leaves never outlive the process cache by
/// much: the cache entry expires well before the certificate does.
struct CertStore {
	ca: Arc<Ca>,
	tld: String,
	registrations: Registrations,
	dashboard_name: String,
	cache_for: Duration,
	cache: Mutex<HashMap<String, (Arc<rustls::sign::CertifiedKey>, Instant)>>,
}

impl std::fmt::Debug for CertStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("CertStore").field("tld", &self.tld).finish_non_exhaustive()
	}
}

impl CertStore {
	fn new(ca: Arc<Ca>, tld: String, registrations: Registrations) -> Self {
		Self::with_cache_duration(ca, tld, leaf_renewal_after(), registrations)
	}

	fn with_cache_duration(ca: Arc<Ca>, tld: String, cache_for: Duration, registrations: Registrations) -> Self {
		let dashboard_name = format!("testd.{tld}");
		Self { ca, tld, dashboard_name, registrations, cache_for, cache: Mutex::new(HashMap::new()) }
	}

	fn mint(&self, name: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
		if !name.ends_with(&format!(".{}", self.tld)) {
			return None;
		}
		let registered =
			name == self.dashboard_name || self.registrations.try_lock().is_ok_and(|registry| registry.contains(name));
		if !registered {
			return None;
		}
		let mut cache = self.cache.lock().unwrap();
		if let Some((key, minted)) = cache.get(name)
			&& minted.elapsed() < self.cache_for
		{
			return Some(key.clone());
		}
		if cache.len() >= MAX_CERT_CACHE {
			cache.retain(|_, (_, minted)| minted.elapsed() < self.cache_for);
		}
		if cache.len() >= MAX_CERT_CACHE
			&& let Some(key) = cache.keys().next().cloned()
		{
			cache.remove(&key);
		}
		match self.ca.certified_key(name) {
			Ok(key) => {
				cache.insert(name.to_owned(), (key.clone(), Instant::now()));
				Some(key)
			},
			Err(e) => {
				eprintln!("[error]  cannot mint a certificate for {name}: {e}");
				None
			},
		}
	}
}

impl rustls::server::ResolvesServerCert for CertStore {
	fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
		let name = hello.server_name()?;
		self.mint(name)
	}
}

async fn tls_accept_loop(
	listener: TcpListener,
	acceptor: tokio_rustls::TlsAcceptor,
	ctx: Arc<EdgeContext>,
	limiter: Arc<ConnectionLimiter>,
) -> Result<()> {
	loop {
		let (stream, peer) = listener.accept().await?;
		let Some(permit) = limiter.acquire(peer.ip()) else {
			eprintln!("[warn]   edge connection limit reached: {}", peer.ip());
			continue;
		};
		let acceptor = acceptor.clone();
		let ctx = ctx.clone();
		tokio::spawn(async move {
			let _permit = permit;
			match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
				Ok(Ok(tls)) => {
					if let Err(e) = serve_connection(tls, Handler { ctx, scheme: "https", plain: false, peer }).await {
						eprintln!("[warn]   tls {}: {e}", peer.ip());
					}
				},
				Ok(Err(e)) => eprintln!("[warn]   tls handshake from {}: {e}", peer.ip()),
				Err(_) => eprintln!("[warn]   tls handshake from {} timed out", peer.ip()),
			}
		});
	}
}

async fn accept_loop(listener: TcpListener, handler: PlainHandler, limiter: Arc<ConnectionLimiter>) -> Result<()> {
	loop {
		let (stream, peer) = listener.accept().await?;
		let Some(permit) = limiter.acquire(peer.ip()) else {
			eprintln!("[warn]   edge connection limit reached: {}", peer.ip());
			continue;
		};
		let handler = handler.clone();
		tokio::spawn(async move {
			let _permit = permit;
			if let Err(e) = serve_connection(stream, handler.into_handler(peer)).await {
				eprintln!("[warn]   http {}: {e}", peer.ip());
			}
		});
	}
}

#[derive(Clone)]
struct PlainHandler {
	ctx: Arc<EdgeContext>,
}

impl PlainHandler {
	fn into_handler(self, peer: SocketAddr) -> Handler {
		Handler { ctx: self.ctx, scheme: "http", plain: true, peer }
	}
}

#[derive(Clone)]
struct Handler {
	ctx: Arc<EdgeContext>,
	scheme: &'static str,
	plain: bool,
	peer: SocketAddr,
}

async fn serve_connection<I>(io: I, handler: Handler) -> Result<()>
where
	I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let service = service_fn(move |request| {
		let handler = handler.clone();
		async move { Ok::<_, Infallible>(handle(handler, request).await) }
	});
	let mut builder = hyper::server::conn::http1::Builder::new();
	builder
		.keep_alive(true)
		.timer(TokioTimer::new())
		.header_read_timeout(HEADER_READ_TIMEOUT);
	builder.serve_connection(TokioIo::new(io), service).with_upgrades().await?;
	Ok(())
}

async fn handle(handler: Handler, request: Request<Incoming>) -> Response<Body> {
	if handler.plain && request.uri().path() == "/ask" {
		let domain = request.uri().query().and_then(|query| {
			query
				.split('&')
				.find_map(|pair| pair.strip_prefix("domain=").map(str::to_owned))
		});
		return match domain {
			Some(domain) => ask(&handler.ctx, &domain.to_ascii_lowercase()),
			None => text(StatusCode::BAD_REQUEST, "missing ?domain="),
		};
	}

	let host = match host_of(&request) {
		Some(host) => host,
		None => return text(StatusCode::BAD_REQUEST, "missing Host header"),
	};

	// The dashboard name is a fixed local surface, not a registration. It is
	// forwarded only when the request really came from this machine: the peer
	// must be loopback, and a front proxy must say the original client was too.
	if host == format!("testd.{}", handler.ctx.tld)
		&& let Some(addr) = handler.ctx.dashboard_addr
	{
		if !dashboard_client_is_local(&handler, request.headers()) {
			return text(StatusCode::NOT_FOUND, "The dashboard is loopback-only.");
		}
		let target = addr.to_string();
		return proxy(handler, request, &target).await;
	}

	let target = match handler.ctx.registrations.lock().await.get(&host) {
		Some(registration) => registration.target,
		None => return text(StatusCode::NOT_FOUND, &format!("No live registration for {host}.")),
	};

	proxy(handler, request, &target).await
}

/// On-demand TLS permission endpoint for an external front such as Caddy.
fn ask(ctx: &EdgeContext, host: &str) -> Response<Body> {
	let known = host == format!("testd.{}", ctx.tld) || {
		let registry = ctx.registrations.try_lock();
		registry.as_ref().is_ok_and(|registry| registry.contains(host))
	};
	if known { text(StatusCode::OK, "ok") } else { text(StatusCode::NOT_FOUND, "unknown name") }
}

/// Whether a dashboard request came from this machine.
///
/// The immediate peer must be loopback. With a front proxy in front, the first
/// `X-Forwarded-For` hop must also be loopback, so a LAN client routed through a
/// local front is refused and a remote front fails the peer check entirely.
fn dashboard_client_is_local(handler: &Handler, headers: &HeaderMap) -> bool {
	if !handler.peer.ip().is_loopback() {
		return false;
	}
	if !handler.ctx.trust_forwarded_for {
		// The TLS listener terminates the connection itself, so the peer is the
		// client. The plain listener is only fed by a front, where the peer is
		// always loopback and proves nothing.
		return !handler.plain;
	}
	match headers.get("x-forwarded-for").and_then(|value| value.to_str().ok()) {
		Some(value) => value
			.split(',')
			.next()
			.and_then(|first| first.trim().parse::<IpAddr>().ok())
			.is_some_and(|ip| ip.is_loopback()),
		None => true,
	}
}

async fn proxy(handler: Handler, request: Request<Incoming>, target: &str) -> Response<Body> {
	let mut request = request;
	let client_upgrade = if is_upgrade(&request) { Some(hyper::upgrade::on(&mut request)) } else { None };

	let (parts, body) = request.into_parts();
	let path = parts
		.uri
		.path_and_query()
		.map(|p| p.as_str().to_owned())
		.unwrap_or_else(|| "/".to_owned());

	let mut headers = filter_request_headers(&parts.headers, client_upgrade.is_some());
	if !handler.ctx.trust_forwarded_for {
		headers.remove("forwarded");
		headers.remove("x-forwarded-for");
	}
	let forwarded = match headers.get("x-forwarded-for").and_then(|value| value.to_str().ok()) {
		// Only a configured front proxy may supply the client address.
		Some(existing) if handler.ctx.trust_forwarded_for => format!("{existing}, {}", handler.peer.ip()),
		_ => handler.peer.ip().to_string(),
	};
	if let Ok(value) = HeaderValue::from_str(&forwarded) {
		headers.insert("x-forwarded-for", value);
	}
	if let Ok(value) = HeaderValue::from_str(handler.scheme) {
		headers.insert("x-forwarded-proto", value);
	}
	// Routing uses a normalized name, but applications need the original authority.
	if let Some(value) = parts.headers.get(HOST) {
		headers.insert(HOST, value.clone());
	}

	let mut upstream = Request::new(body);
	*upstream.method_mut() = parts.method;
	*upstream.uri_mut() = path.parse().unwrap_or_else(|_| "/".parse().unwrap());
	*upstream.version_mut() = Version::HTTP_11;
	*upstream.headers_mut() = headers;

	let (mut sender, connection) = match connect_upstream(target, handler.ctx.upstream_timeout).await {
		Ok(pair) => pair,
		Err(response) => return response,
	};
	tokio::spawn(async move {
		if let Err(e) = connection.await {
			eprintln!("[warn]   upstream connection: {e}");
		}
	});

	let response = match tokio::time::timeout(handler.ctx.upstream_timeout, sender.send_request(upstream)).await {
		Ok(Ok(response)) => response,
		Ok(Err(e)) => return bad_gateway(target, &e.to_string()),
		Err(_) => return text(StatusCode::GATEWAY_TIMEOUT, &format!("Upstream {target} timed out.")),
	};

	if response.status() == StatusCode::SWITCHING_PROTOCOLS {
		return upgrade_response(response, client_upgrade);
	}

	let (parts, body) = response.into_parts();
	let mut builder = Response::builder().status(parts.status).version(parts.version);
	let headers = filter_response_headers(&parts.headers);
	for (name, value) in headers.iter() {
		builder = builder.header(name, value);
	}
	builder
		.body(body.map_err(box_error).boxed())
		.unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "Invalid response."))
}

type ConnectionFuture = Pin<Box<dyn Future<Output = Result<(), hyper::Error>> + Send>>;

// The error variant is a ready-to-send response; boxing it would add an
// allocation to every failed upstream without improving the call sites.
#[allow(clippy::result_large_err)]
async fn connect_upstream(
	target: &str,
	timeout: Duration,
) -> Result<(hyper::client::conn::http1::SendRequest<Incoming>, ConnectionFuture), Response<Body>> {
	let connect = tokio::time::timeout(timeout, TcpStream::connect(target)).await;
	let stream = match connect {
		Ok(Ok(stream)) => stream,
		Ok(Err(e)) => return Err(bad_gateway(target, &e.to_string())),
		Err(_) => return Err(text(StatusCode::GATEWAY_TIMEOUT, &format!("upstream {target} timed out"))),
	};
	stream.set_nodelay(true).ok();

	match hyper::client::conn::http1::Builder::new().handshake(TokioIo::new(stream)).await {
		Ok((sender, connection)) => Ok((sender, Box::pin(connection.with_upgrades()))),
		Err(e) => Err(bad_gateway(target, &e.to_string())),
	}
}

fn upgrade_response(
	mut response: Response<Incoming>,
	client_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Response<Body> {
	let upstream_upgrade = hyper::upgrade::on(&mut response);
	let status = response.status();
	let headers = upgrade_headers(response.headers());

	let mut builder = Response::builder().status(status);
	for (name, value) in headers.iter() {
		builder = builder.header(name, value);
	}
	let response = builder.body(empty()).unwrap();

	if let Some(client_upgrade) = client_upgrade {
		tokio::spawn(async move {
			match tokio::try_join!(client_upgrade, upstream_upgrade) {
				Ok((client, upstream)) => {
					let mut client = TokioIo::new(client);
					let mut upstream = TokioIo::new(upstream);
					if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
						eprintln!("[warn]   upgraded stream: {e}");
					}
				},
				Err(e) => eprintln!("[warn]   upgrade failed: {e}"),
			}
		});
	}
	response
}

/// End-to-end headers from a 101 response, including the WebSocket accept and
/// subprotocol negotiation. Only the hop-by-hop connection fields are rebuilt.
fn upgrade_headers(headers: &hyper::HeaderMap) -> hyper::HeaderMap {
	let mut filtered = filter_response_headers(headers);
	if let Some(value) = headers.get(UPGRADE) {
		filtered.insert(UPGRADE, value.clone());
	}
	filtered.insert(CONNECTION, HeaderValue::from_static("upgrade"));
	filtered
}

fn host_of<B>(request: &Request<B>) -> Option<String> {
	let raw = request.headers().get(HOST)?.to_str().ok()?;
	let host = raw
		.rsplit_once(':')
		.filter(|(_, port)| port.parse::<u16>().is_ok())
		.map(|(host, _)| host)
		.unwrap_or(raw);
	Some(host.trim_end_matches('.').to_ascii_lowercase())
}

fn is_upgrade<B>(request: &Request<B>) -> bool {
	let connection = request.headers().get(CONNECTION).and_then(|v| v.to_str().ok()).unwrap_or("");
	let upgrade = request.headers().get(UPGRADE).and_then(|v| v.to_str().ok()).unwrap_or("");
	connection.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade")) && !upgrade.is_empty()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
	matches!(
		name.as_str(),
		"connection"
			| "keep-alive"
			| "proxy-authenticate"
			| "proxy-authorization"
			| "proxy-connection"
			| "te" | "trailer"
			| "transfer-encoding"
	)
}

fn filter_request_headers(headers: &HeaderMap, upgrade: bool) -> HeaderMap {
	let mut filtered = HeaderMap::new();
	for (name, value) in headers {
		if is_hop_by_hop(name) {
			continue;
		}
		if !upgrade && name == UPGRADE {
			continue;
		}
		filtered.append(name.clone(), value.clone());
	}
	if upgrade {
		if let Some(value) = headers.get(UPGRADE) {
			filtered.insert(UPGRADE, value.clone());
		}
		filtered.insert(CONNECTION, HeaderValue::from_static("upgrade"));
	}
	filtered
}

fn filter_response_headers(headers: &HeaderMap) -> HeaderMap {
	let mut filtered = HeaderMap::new();
	for (name, value) in headers {
		if is_hop_by_hop(name) || name == UPGRADE || name == CONNECTION {
			continue;
		}
		filtered.append(name.clone(), value.clone());
	}
	filtered
}

fn empty() -> Body {
	Full::new(Bytes::new()).map_err(box_error).boxed()
}

fn text(status: StatusCode, message: &str) -> Response<Body> {
	Response::builder()
		.status(status)
		.header(CONTENT_TYPE, "text/plain; charset=utf-8")
		.body(Full::new(Bytes::from(message.to_owned())).map_err(box_error).boxed())
		.unwrap()
}

fn bad_gateway(target: &str, error: &str) -> Response<Body> {
	text(StatusCode::BAD_GATEWAY, &format!("Cannot reach upstream {target}: {error}."))
}

fn box_error<E: std::error::Error + Send + Sync + 'static>(error: E) -> BoxError {
	Box::new(error)
}

/// Build the Caddyfile equivalent for users who want their own front.
pub fn caddyfile(tld: &str, http_addr: SocketAddr) -> String {
	format!(
		"# testd: route all *.{tld} names to the built-in router.\n\
		 # The edge terminates TLS on its own; this file is for an external front.\n\
		 {{\n\ton_demand_tls {{\n\t\task http://{http_addr}/ask\n\t}}\n}}\n\n\
		 :443 {{\n\ttls internal {{\n\t\ton_demand\n\t}}\n\treverse_proxy {http_addr}\n}}\n"
	)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;
	use tokio::sync::Mutex as AsyncMutex;

	fn temp_dir() -> PathBuf {
		static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
		let dir = std::env::temp_dir().join(format!(
			"testd-edge-certs-{}-{}",
			std::process::id(),
			NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
		));
		std::fs::create_dir_all(&dir).unwrap();
		dir
	}

	fn registrations_with(name: &str) -> Registrations {
		let mut registry = crate::registry::Registry::default();
		let connection = registry.connection_id();
		registry
			.register(
				connection,
				testd_core::Registration { domain: name.into(), target: "127.0.0.1:3000".into() },
				false,
				&[],
			)
			.unwrap();
		Arc::new(AsyncMutex::new(registry))
	}

	#[test]
	fn renewal_happens_when_a_quarter_of_the_leaf_lifetime_remains() {
		assert_eq!(leaf_renewal_after(), Duration::from_secs(18 * 3600));
	}

	#[test]
	fn a_cached_leaf_is_reused_until_its_renewal_threshold() {
		let dir = temp_dir();
		let ca = Arc::new(Ca::load_or_init(&dir).unwrap());
		let store = CertStore::with_cache_duration(
			ca.clone(),
			"test".into(),
			Duration::from_secs(3600),
			registrations_with("app.test"),
		);
		let first = store.mint("app.test").unwrap();
		let second = store.mint("app.test").unwrap();
		assert_eq!(first.cert[0].as_ref(), second.cert[0].as_ref());
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn upgrade_responses_keep_the_websocket_handshake_headers() {
		let mut headers = hyper::HeaderMap::new();
		headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
		headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
		headers.insert("sec-websocket-accept", HeaderValue::from_static("accept-value"));
		headers.insert("sec-websocket-protocol", HeaderValue::from_static("chat"));
		headers.insert("x-other", HeaderValue::from_static("kept"));

		let filtered = upgrade_headers(&headers);
		assert_eq!(filtered.get("sec-websocket-accept").unwrap(), "accept-value");
		assert_eq!(filtered.get("sec-websocket-protocol").unwrap(), "chat");
		assert_eq!(filtered.get("x-other").unwrap(), "kept");
		assert_eq!(filtered.get(UPGRADE).unwrap(), "websocket");
		assert_eq!(filtered.get(CONNECTION).unwrap(), "upgrade");
	}

	#[test]
	fn an_expired_cache_entry_is_minted_again() {
		let dir = temp_dir();
		let ca = Arc::new(Ca::load_or_init(&dir).unwrap());
		let store = CertStore::with_cache_duration(ca, "test".into(), Duration::ZERO, registrations_with("app.test"));
		let first = store.mint("app.test").unwrap();
		let second = store.mint("app.test").unwrap();
		assert_ne!(first.cert[0].as_ref(), second.cert[0].as_ref());
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn dashboard_requests_are_local_only() {
		let context = Arc::new(EdgeContext::new("test", Registrations::default()));
		let handler = |peer: &str| Handler {
			ctx: Arc::clone(&context),
			scheme: "https",
			plain: false,
			peer: peer.parse().unwrap(),
		};

		assert!(dashboard_client_is_local(&handler("127.0.0.1:5000"), &HeaderMap::new()));
		assert!(!dashboard_client_is_local(&handler("192.168.1.5:5000"), &HeaderMap::new()));

		// A plain listener is behind a front; without forwarded-header trust
		// there is no way to tell who the real client is, so fail closed.
		let mut plain = handler("127.0.0.1:5000");
		plain.plain = true;
		assert!(!dashboard_client_is_local(&plain, &HeaderMap::new()));

		let mut fronted = EdgeContext::new("test", Registrations::default());
		fronted.trust_forwarded_for = true;
		let fronted = Arc::new(fronted);
		let mut headers = HeaderMap::new();
		headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.5"));
		let backend = Handler {
			ctx: Arc::clone(&fronted),
			scheme: "https",
			plain: false,
			peer: "127.0.0.1:5000".parse().unwrap(),
		};
		assert!(!dashboard_client_is_local(&backend, &headers));

		headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
		assert!(dashboard_client_is_local(&backend, &headers));
	}

	#[tokio::test]
	async fn the_dashboard_name_routes_to_the_loopback_dashboard() {
		let dashboard = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let dashboard_addr = dashboard.local_addr().unwrap();
		tokio::spawn(async move {
			while let Ok((mut stream, _)) = dashboard.accept().await {
				tokio::spawn(async move {
					use tokio::io::{AsyncReadExt, AsyncWriteExt};
					let mut buffer = [0u8; 1024];
					let _ = stream.read(&mut buffer).await;
					let _ = stream
						.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\ndashboard")
						.await;
				});
			}
		});

		let mut context = EdgeContext::new("test", Registrations::default());
		context.dashboard_addr = Some(dashboard_addr);
		// The plain listener stands in for an external front here.
		context.trust_forwarded_for = true;
		let dir = temp_dir();
		let edge = start(Arc::new(context), None, "127.0.0.1:0".parse().unwrap(), &dir).unwrap();

		let named = plain_request(edge.http_addr, "testd.test", "127.0.0.1").await;
		assert!(named.starts_with("HTTP/1.1 200"), "{named}");
		assert!(named.ends_with("dashboard"), "{named}");

		// A LAN client behind the same front is not local, even though the
		// front's connection arrives from loopback.
		let remote = plain_request(edge.http_addr, "testd.test", "192.168.1.5").await;
		assert!(remote.starts_with("HTTP/1.1 404"), "{remote}");

		let unknown = plain_request(edge.http_addr, "nope.test", "127.0.0.1").await;
		assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");
		std::fs::remove_dir_all(&dir).ok();
	}

	async fn plain_request(addr: SocketAddr, host: &str, client: &str) -> String {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};
		let mut stream = TcpStream::connect(addr).await.unwrap();
		let request =
			format!("GET / HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: {client}\r\nConnection: close\r\n\r\n");
		stream.write_all(request.as_bytes()).await.unwrap();
		let mut out = Vec::new();
		stream.read_to_end(&mut out).await.unwrap();
		String::from_utf8_lossy(&out).into_owned()
	}

	#[test]
	fn only_registered_names_and_the_dashboard_get_certificates() {
		let dir = temp_dir();
		let ca = Arc::new(Ca::load_or_init(&dir).unwrap());
		let store = CertStore::with_cache_duration(
			ca,
			"test".into(),
			Duration::from_secs(3600),
			registrations_with("app.test"),
		);
		assert!(store.mint("app.test").is_some());
		assert!(store.mint("testd.test").is_some());
		assert!(store.mint("unknown.test").is_none());
		assert!(store.mint("app.example").is_none());
		std::fs::remove_dir_all(&dir).ok();
	}
}
