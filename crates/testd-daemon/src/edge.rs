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
use std::net::SocketAddr;
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
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use testd_pki::Ca;

use crate::registry::Registry;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;

/// Renew a cached leaf when 25% of its validity remains, i.e. after 75% of the
/// leaf lifetime. For the default 24-hour leaf that is 18 hours.
pub fn leaf_renewal_after() -> Duration {
	Duration::from_secs((testd_pki::LEAF_LIFETIME_HOURS as u64) * 3600 * 3 / 4)
}

/// Shared state for the edge and the plain router.
pub struct EdgeContext {
	pub tld: String,
	pub registrations: Arc<AsyncMutex<Registry>>,
	/// Connection and response-header timeout for an upstream.
	pub upstream_timeout: Duration,
}

impl EdgeContext {
	pub fn new(tld: impl Into<String>, registrations: Arc<AsyncMutex<Registry>>) -> Self {
		Self { tld: tld.into(), registrations, upstream_timeout: Duration::from_secs(30) }
	}
}

/// A running edge.
pub struct Edge {
	pub tls_addr: SocketAddr,
	pub http_addr: SocketAddr,
	tasks: Vec<JoinHandle<()>>,
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

	let plain = std::net::TcpListener::bind(http_addr).context("bind the plain edge listener")?;
	plain.set_nonblocking(true)?;
	let plain = TcpListener::from_std(plain)?;
	let http_addr = plain.local_addr()?;
	let plain_ctx = ctx.clone();
	tasks.push(tokio::spawn(async move {
		if let Err(e) = accept_loop(plain, PlainHandler { ctx: plain_ctx }).await {
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
			let resolver = Arc::new(CertStore::new(ca, ctx.tld.clone()));
			let mut config = rustls::ServerConfig::builder()
				.with_no_client_auth()
				.with_cert_resolver(resolver);
			config.alpn_protocols = vec![b"http/1.1".to_vec()];
			let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

			let tls_ctx = ctx.clone();
			tasks.push(tokio::spawn(async move {
				if let Err(e) = tls_accept_loop(listener, acceptor, tls_ctx).await {
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
	cache_for: Duration,
	cache: Mutex<HashMap<String, (Arc<rustls::sign::CertifiedKey>, Instant)>>,
}

impl std::fmt::Debug for CertStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("CertStore").field("tld", &self.tld).finish_non_exhaustive()
	}
}

impl CertStore {
	fn new(ca: Arc<Ca>, tld: String) -> Self {
		Self::with_cache_duration(ca, tld, leaf_renewal_after())
	}

	fn with_cache_duration(ca: Arc<Ca>, tld: String, cache_for: Duration) -> Self {
		Self { ca, tld, cache_for, cache: Mutex::new(HashMap::new()) }
	}

	fn mint(&self, name: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
		if !name.ends_with(&format!(".{}", self.tld)) {
			return None;
		}
		let mut cache = self.cache.lock().unwrap();
		if let Some((key, minted)) = cache.get(name)
			&& minted.elapsed() < self.cache_for
		{
			return Some(key.clone());
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
) -> Result<()> {
	loop {
		let (stream, peer) = listener.accept().await?;
		let acceptor = acceptor.clone();
		let ctx = ctx.clone();
		tokio::spawn(async move {
			match acceptor.accept(stream).await {
				Ok(tls) => {
					if let Err(e) = serve_connection(tls, Handler { ctx, scheme: "https", plain: false, peer }).await {
						eprintln!("[warn]   tls {}: {e}", peer.ip());
					}
				},
				Err(e) => eprintln!("[warn]   tls handshake from {}: {e}", peer.ip()),
			}
		});
	}
}

async fn accept_loop(listener: TcpListener, handler: PlainHandler) -> Result<()> {
	loop {
		let (stream, peer) = listener.accept().await?;
		let handler = handler.clone();
		tokio::spawn(async move {
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
	hyper::server::conn::http1::Builder::new()
		.keep_alive(true)
		.serve_connection(TokioIo::new(io), service)
		.with_upgrades()
		.await?;
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

	let target = match handler.ctx.registrations.lock().await.get(&host) {
		Some(registration) => registration.target,
		None => return text(StatusCode::NOT_FOUND, &format!("No live registration for {host}.")),
	};

	proxy(handler, request, &host, &target).await
}

/// On-demand TLS permission endpoint for an external front such as Caddy.
fn ask(ctx: &EdgeContext, host: &str) -> Response<Body> {
	let known = {
		let registry = ctx.registrations.try_lock();
		registry.as_ref().is_ok_and(|registry| registry.contains(host))
	};
	if known { text(StatusCode::OK, "ok") } else { text(StatusCode::NOT_FOUND, "unknown name") }
}

async fn proxy(handler: Handler, request: Request<Incoming>, host: &str, target: &str) -> Response<Body> {
	let mut request = request;
	let client_upgrade = if is_upgrade(&request) { Some(hyper::upgrade::on(&mut request)) } else { None };

	let (parts, body) = request.into_parts();
	let path = parts
		.uri
		.path_and_query()
		.map(|p| p.as_str().to_owned())
		.unwrap_or_else(|| "/".to_owned());

	let mut headers = filter_request_headers(&parts.headers, client_upgrade.is_some());
	let forwarded = match headers.get("x-forwarded-for").and_then(|value| value.to_str().ok()) {
		Some(existing) => format!("{existing}, {}", handler.peer.ip()),
		None => handler.peer.ip().to_string(),
	};
	if let Ok(value) = HeaderValue::from_str(&forwarded) {
		headers.insert("x-forwarded-for", value);
	}
	if let Ok(value) = HeaderValue::from_str(handler.scheme) {
		headers.insert("x-forwarded-proto", value);
	}
	if let Ok(value) = HeaderValue::from_str(host) {
		headers.insert(HOST, value);
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

	#[test]
	fn renewal_happens_when_a_quarter_of_the_leaf_lifetime_remains() {
		assert_eq!(leaf_renewal_after(), Duration::from_secs(18 * 3600));
	}

	#[test]
	fn a_cached_leaf_is_reused_until_its_renewal_threshold() {
		let dir = temp_dir();
		let ca = Arc::new(Ca::load_or_init(&dir).unwrap());
		let store = CertStore::with_cache_duration(ca.clone(), "test".into(), Duration::from_secs(3600));
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
		let store = CertStore::with_cache_duration(ca, "test".into(), Duration::ZERO);
		let first = store.mint("app.test").unwrap();
		let second = store.mint("app.test").unwrap();
		assert_ne!(first.cert[0].as_ref(), second.cert[0].as_ref());
		std::fs::remove_dir_all(&dir).ok();
	}
}
