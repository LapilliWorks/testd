//! Conformance suite for the in-process edge: routing, streaming, upgrades, TLS.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::{Stream, stream};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::header::{CONNECTION, UPGRADE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio_rustls::TlsConnector;

use testd_core::Registration;
use testd_daemon::edge::{self, Edge, EdgeContext};
use testd_daemon::registry::Registry;
use testd_pki::Ca;

type Body = BoxBody<Bytes, Infallible>;

struct Harness {
	edge: Edge,
	registry: Arc<AsyncMutex<Registry>>,
	dir: std::path::PathBuf,
	upstream_dropped: Arc<Notify>,
}

async fn start() -> Harness {
	let (upstream, upstream_dropped) = start_upstream().await;
	let dir = std::env::temp_dir().join(format!("testd-edge-{}-{}", std::process::id(), upstream.port()));
	std::fs::create_dir_all(&dir).unwrap();

	let registry = Arc::new(AsyncMutex::new(Registry::default()));
	let connection = registry.lock().await.connection_id();
	registry
		.lock()
		.await
		.register(connection, Registration { domain: "app.test".into(), target: upstream.to_string() }, false, &[])
		.unwrap();

	let mut ctx = EdgeContext::new("test", registry.clone());
	ctx.upstream_timeout = Duration::from_millis(300);

	let pki_dir = dir.join("pki");
	let edge =
		edge::start(Arc::new(ctx), Some("127.0.0.1:0".parse().unwrap()), "127.0.0.1:0".parse().unwrap(), &pki_dir)
			.unwrap();

	Harness { edge, registry, dir, upstream_dropped }
}

/// Streams one byte and then never finishes. Dropped when the upstream
/// connection closes; the test uses it to observe a client abort.
struct HangStream {
	dropped: Arc<Notify>,
	started: bool,
}

impl Stream for HangStream {
	type Item = Result<Frame<Bytes>, Infallible>;

	fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		if self.started {
			return Poll::Pending;
		}
		self.started = true;
		Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"x")))))
	}
}

impl Drop for HangStream {
	fn drop(&mut self) {
		self.dropped.notify_one();
	}
}

async fn start_upstream() -> (SocketAddr, Arc<Notify>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let dropped = Arc::new(Notify::new());
	let task_dropped = Arc::clone(&dropped);
	tokio::spawn(async move {
		loop {
			let Ok((stream, _)) = listener.accept().await else { return };
			let dropped = Arc::clone(&task_dropped);
			tokio::spawn(async move {
				let service = service_fn(move |request| upstream_service(request, Arc::clone(&dropped)));
				let _ = hyper::server::conn::http1::Builder::new()
					.serve_connection(TokioIo::new(stream), service)
					.with_upgrades()
					.await;
			});
		}
	});
	(addr, dropped)
}

async fn upstream_service(request: Request<Incoming>, dropped: Arc<Notify>) -> Result<Response<Body>, Infallible> {
	let path = request.uri().path().to_owned();
	match path.as_str() {
		"/slow" => {
			tokio::time::sleep(Duration::from_secs(2)).await;
			Ok(text(StatusCode::OK, "late"))
		},
		"/sse" => {
			let frames = stream::unfold(0u8, |state| async move {
				match state {
					0 => Some((Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"event: one\ndata: 1\n\n"))), 1)),
					1 => {
						tokio::time::sleep(Duration::from_millis(300)).await;
						Some((Ok(Frame::data(Bytes::from_static(b"event: two\ndata: 2\n\n"))), 2))
					},
					_ => None,
				}
			});
			Ok(Response::new(StreamBody::new(frames).boxed()))
		},
		"/hang" => Ok(Response::new(StreamBody::new(HangStream { dropped, started: false }).boxed())),
		"/chunked" => {
			let frames = stream::iter(vec![
				Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"abc"))),
				Ok(Frame::data(Bytes::from_static(b"def"))),
			]);
			Ok(Response::new(StreamBody::new(frames).boxed()))
		},
		"/ws" => {
			let mut request = request;
			let upgrade = hyper::upgrade::on(&mut request);
			tokio::spawn(async move {
				if let Ok(upgraded) = upgrade.await {
					let mut io = TokioIo::new(upgraded);
					let mut buffer = [0u8; 1024];
					loop {
						match io.read(&mut buffer).await {
							Ok(0) | Err(_) => break,
							Ok(n) => {
								if io.write_all(&buffer[..n]).await.is_err() {
									break;
								}
							},
						}
					}
				}
			});
			Ok(Response::builder()
				.status(StatusCode::SWITCHING_PROTOCOLS)
				.header(CONNECTION, "upgrade")
				.header(UPGRADE, "websocket")
				.body(empty())
				.unwrap())
		},
		_ => {
			let host = request
				.headers()
				.get("host")
				.and_then(|v| v.to_str().ok())
				.unwrap_or("")
				.to_owned();
			let method = request.method().to_string();
			let path = request
				.uri()
				.path_and_query()
				.map(|p| p.as_str().to_owned())
				.unwrap_or_default();
			let forwarded = request
				.headers()
				.get("x-forwarded-proto")
				.and_then(|v| v.to_str().ok())
				.unwrap_or("")
				.to_owned();
			let body = request.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();
			let summary = format!(
				"method={method} host={host} path={path} proto={forwarded} body={}",
				String::from_utf8_lossy(&body)
			);
			Ok(text(StatusCode::OK, &summary))
		},
	}
}

fn empty() -> Body {
	Full::new(Bytes::new()).boxed()
}

fn text(status: StatusCode, body: &str) -> Response<Body> {
	Response::builder()
		.status(status)
		.body(Full::new(Bytes::from(body.to_owned())).boxed())
		.unwrap()
}

async fn raw_request(addr: SocketAddr, request: &str) -> String {
	let mut stream = TcpStream::connect(addr).await.unwrap();
	stream.write_all(request.as_bytes()).await.unwrap();
	let mut response = Vec::new();
	stream.read_to_end(&mut response).await.unwrap();
	String::from_utf8_lossy(&response).into_owned()
}

fn get(host: &str, path: &str) -> String {
	format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

#[tokio::test]
async fn routes_by_host_and_preserves_the_original_host() {
	let harness = start().await;
	let response = raw_request(harness.edge.http_addr, &get("app.test", "/echo")).await;
	assert!(response.starts_with("HTTP/1.1 200"), "{response}");
	assert!(response.contains("host=app.test"), "{response}");
	assert!(response.contains("proto=http"), "{response}");
	assert!(response.contains("path=/echo"), "{response}");
}

#[tokio::test]
async fn streams_request_bodies_both_ways() {
	let harness = start().await;
	let request = "POST /echo HTTP/1.1\r\nHost: app.test\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world";
	let response = raw_request(harness.edge.http_addr, request).await;
	assert!(response.contains("method=POST"), "{response}");
	assert!(response.contains("body=hello world"), "{response}");
}

#[tokio::test]
async fn unknown_host_is_404() {
	let harness = start().await;
	let response = raw_request(harness.edge.http_addr, &get("nope.test", "/")).await;
	assert!(response.starts_with("HTTP/1.1 404"), "{response}");
	assert!(response.contains("No live registration"), "{response}");
}

#[tokio::test]
async fn client_abort_drops_the_upstream_connection() {
	let harness = start().await;
	let mut stream = TcpStream::connect(harness.edge.http_addr).await.unwrap();
	stream.write_all(get("app.test", "/hang").as_bytes()).await.unwrap();

	// Wait until the edge has connected upstream and forwarded the first byte.
	let mut first = [0u8; 1];
	tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut first))
		.await
		.expect("first byte")
		.expect("read first byte");

	let dropped = harness.upstream_dropped.notified();
	drop(stream);
	tokio::time::timeout(Duration::from_secs(2), dropped)
		.await
		.expect("the edge should drop the upstream connection after the client aborts");
}

#[tokio::test]
async fn dead_upstream_is_502() {
	let harness = start().await;
	let port = {
		let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
		probe.local_addr().unwrap().port()
	};
	let connection = harness.registry.lock().await.connection_id();
	harness
		.registry
		.lock()
		.await
		.register(
			connection,
			Registration { domain: "dead.test".into(), target: format!("127.0.0.1:{port}") },
			false,
			&[],
		)
		.unwrap();

	let response = raw_request(harness.edge.http_addr, &get("dead.test", "/")).await;
	assert!(response.starts_with("HTTP/1.1 502"), "{response}");
	assert!(response.contains(&format!("127.0.0.1:{port}")), "{response}");
}

#[tokio::test]
async fn slow_upstream_is_504() {
	let harness = start().await;
	let response = raw_request(harness.edge.http_addr, &get("app.test", "/slow")).await;
	assert!(response.starts_with("HTTP/1.1 504"), "{response}");
}

#[tokio::test]
async fn chunked_upstream_is_streamed() {
	let harness = start().await;
	let response = raw_request(harness.edge.http_addr, &get("app.test", "/chunked")).await;
	assert!(response.starts_with("HTTP/1.1 200"), "{response}");
	assert!(response.contains("transfer-encoding: chunked"), "{response}");
	assert!(response.contains("abc"), "{response}");
	assert!(response.contains("def"), "{response}");
}

#[tokio::test]
async fn absolute_form_targets_are_rewritten_to_origin_form() {
	let harness = start().await;
	let request = "GET http://app.test/echo HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n";
	let response = raw_request(harness.edge.http_addr, request).await;
	assert!(response.starts_with("HTTP/1.1 200"), "{response}");
	assert!(response.contains("path=/echo"), "{response}");
}

#[tokio::test]
async fn websocket_upgrade_is_spliced() {
	let harness = start().await;
	let mut stream = TcpStream::connect(harness.edge.http_addr).await.unwrap();
	let request = "GET /ws HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
	stream.write_all(request.as_bytes()).await.unwrap();

	let mut head = Vec::new();
	let mut byte = [0u8; 1];
	while !head.ends_with(b"\r\n\r\n") {
		stream.read_exact(&mut byte).await.unwrap();
		head.push(byte[0]);
	}
	let head = String::from_utf8_lossy(&head);
	assert!(head.starts_with("HTTP/1.1 101"), "{head}");

	stream.write_all(b"ping").await.unwrap();
	let mut echo = [0u8; 4];
	stream.read_exact(&mut echo).await.unwrap();
	assert_eq!(&echo, b"ping");
}

#[tokio::test]
async fn tls_serves_a_minted_leaf_from_the_local_root() {
	let harness = start().await;
	let ca = Ca::load_or_init(&harness.dir.join("pki")).unwrap();
	let mut roots = rustls::RootCertStore::empty();
	roots.add(ca.root_cert_der().unwrap()).unwrap();
	let config = rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));

	let tcp = TcpStream::connect(harness.edge.tls_addr).await.unwrap();
	let name = ServerName::try_from("app.test".to_string()).unwrap();
	let mut tls = connector.connect(name, tcp).await.expect("TLS handshake with the minted leaf");

	tls.write_all(get("app.test", "/echo").as_bytes()).await.unwrap();
	let mut response = Vec::new();
	tls.read_to_end(&mut response).await.unwrap();
	let response = String::from_utf8_lossy(&response);
	assert!(response.starts_with("HTTP/1.1 200"), "{response}");
	assert!(response.contains("proto=https"), "{response}");
}

#[tokio::test]
async fn tls_refuses_out_of_zone_server_names() {
	let harness = start().await;
	let ca = Ca::load_or_init(&harness.dir.join("pki")).unwrap();
	let mut roots = rustls::RootCertStore::empty();
	roots.add(ca.root_cert_der().unwrap()).unwrap();
	let config = rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));

	let tcp = TcpStream::connect(harness.edge.tls_addr).await.unwrap();
	let name = ServerName::try_from("evil.example.com".to_string()).unwrap();
	assert!(connector.connect(name, tcp).await.is_err());
}

#[tokio::test]
async fn expect_100_continue_does_not_deadlock() {
	let harness = start().await;
	let mut stream = TcpStream::connect(harness.edge.http_addr).await.unwrap();
	let headers = "POST /echo HTTP/1.1\r\nHost: app.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n";
	stream.write_all(headers.as_bytes()).await.unwrap();

	// A well-behaved client waits for the interim response before sending the body.
	let mut interim = Vec::new();
	let _ = tokio::time::timeout(Duration::from_millis(500), async {
		let mut byte = [0u8; 1];
		while !interim.ends_with(b"\r\n\r\n") {
			stream.read_exact(&mut byte).await.unwrap();
			interim.push(byte[0]);
		}
	})
	.await;

	stream.write_all(b"hello").await.unwrap();
	let mut rest = Vec::new();
	tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
		.await
		.expect("response after 100-continue")
		.unwrap();
	let response = format!("{}{}", String::from_utf8_lossy(&interim), String::from_utf8_lossy(&rest));
	assert!(response.contains("200 OK"), "{response}");
	assert!(response.contains("body=hello"), "{response}");
}

#[tokio::test]
async fn large_uploads_stream_through() {
	let harness = start().await;
	let payload = "x".repeat(4 * 1024 * 1024);
	let request = format!(
		"POST /echo HTTP/1.1\r\nHost: app.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
		payload.len()
	);
	let response = raw_request(harness.edge.http_addr, &request).await;
	assert!(response.starts_with("HTTP/1.1 200"), "{}", &response[..response.len().min(200)]);
	assert!(response.contains(&format!("body={payload}")));
}

#[tokio::test]
async fn sse_first_event_arrives_before_the_stream_ends() {
	let harness = start().await;
	let mut stream = TcpStream::connect(harness.edge.http_addr).await.unwrap();
	stream.write_all(get("app.test", "/sse").as_bytes()).await.unwrap();

	let mut buffer = Vec::new();
	let mut byte = [0u8; 1];
	let needle = b"event: one\n";
	tokio::time::timeout(Duration::from_millis(200), async {
		while !buffer.windows(needle.len()).any(|window| window == needle) {
			stream.read_exact(&mut byte).await.unwrap();
			buffer.push(byte[0]);
		}
	})
	.await
	.expect("first SSE event should stream before the upstream finishes");
}
