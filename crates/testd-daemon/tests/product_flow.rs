//! Product-flow contracts over real loopback TCP, UDP, and TLS sockets.
//!
//! The local root is trusted only by the test client. No system resolver,
//! system trust store, browser, or privileged port is used.

use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, RCODE, TYPE, rdata::RData};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsConnector, client::TlsStream};

use testd_core::config::HostConfig;
use testd_core::protocol::{Auth, ErrorDisposition, Request, Response, recv, send};
use testd_daemon::access::Access;
use testd_daemon::edge::{self, Edge, EdgeContext};
use testd_daemon::engine::HostEngine;
use testd_daemon::resolver::{Resolver, dns::DnsResolver};
use testd_pki::Ca;
use testd_setup::Elevation;

const SECRET: &str = "fixture-operator-secret";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

// Exercise the real DNS server without ever delegating to OS integration.
struct LocalDns(Arc<DnsResolver>);

impl Resolver for LocalDns {
	fn apply(&self, names: &[testd_daemon::resolver::ResolvedName]) -> io::Result<()> {
		self.0.apply(names)
	}

	fn ensure_os(&self) -> io::Result<()> {
		Err(io::Error::other("system resolver operations are forbidden in this fixture"))
	}

	fn is_os_configured(&self) -> bool {
		false
	}

	fn cleanup(&self) -> io::Result<()> {
		self.0.cleanup()
	}
}

struct Host {
	intake: SocketAddr,
	dns: SocketAddr,
	edge: Edge,
	root: CertificateDer<'static>,
	tld: String,
	tasks: Vec<JoinHandle<()>>,
	_dir: tempfile::TempDir,
}

impl Host {
	async fn start() -> Self {
		let dir = tempfile::tempdir().unwrap();
		let tld = testd_core::config::host_tld().to_owned();
		let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let dns = Arc::new(DnsResolver::start_with_socket(&tld, Ipv4Addr::LOCALHOST, Elevation::Sudo, socket).unwrap());
		dns.apply(&[]).unwrap();
		let dns_addr = dns.listen_addr();
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let intake = listener.local_addr().unwrap();
		let config = host_config(dir.path(), intake);
		let access = Arc::new(Access::load(dir.path().join("tokens.json")).unwrap());
		let resolver = Arc::new(LocalDns(dns));
		let engine = Arc::new(HostEngine::new(config.clone(), resolver, access));
		let context = EdgeContext::new(&tld, engine.registrations());
		let edge = edge::start(Arc::new(context), Some(config.edge_addr), config.http_addr, &config.pki_dir).unwrap();
		let root = Ca::load_or_init(&config.pki_dir).unwrap().root_cert_der().unwrap();
		let task = tokio::spawn(async move { engine.serve(listener).await.expect("intake server failed") });
		Self { intake, dns: dns_addr, edge, root, tld, tasks: vec![task], _dir: dir }
	}

	fn name(&self) -> String {
		format!("app.example.{}", self.tld)
	}

	async fn add_upstream(&mut self, label: &'static str) -> SocketAddr {
		let (address, task) = upstream(label).await;
		self.tasks.push(task);
		address
	}
}

impl Drop for Host {
	fn drop(&mut self) {
		for task in &self.tasks {
			task.abort();
		}
	}
}

fn host_config(dir: &std::path::Path, intake: SocketAddr) -> HostConfig {
	HostConfig {
		listen_addr: intake,
		caddyfile_path: dir.join("Caddyfile"),
		caddy_config_path: dir.join("global-Caddyfile"),
		pki_dir: dir.join("pki"),
		edge_addr: "127.0.0.1:0".parse().unwrap(),
		edge_enabled: true,
		http_addr: "127.0.0.1:0".parse().unwrap(),
		answer_addr: Ipv4Addr::LOCALHOST,
		secret: SECRET.into(),
		allow_remote_targets: false,
		trust_forwarded_for: false,
	}
}

async fn upstream(label: &'static str) -> (SocketAddr, JoinHandle<()>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let task = tokio::spawn(async move {
		loop {
			let (stream, _) = listener.accept().await.expect("upstream accept failed");
			tokio::spawn(async move {
				let service = service_fn(move |request: hyper::Request<Incoming>| async move {
					let host = request.headers().get("host").unwrap().to_str().unwrap();
					let body = format!("{label} {} {} {host}", request.method(), request.uri());
					Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from(body))))
				});
				hyper::server::conn::http1::Builder::new()
					.serve_connection(TokioIo::new(stream), service)
					.await
					.expect("upstream HTTP connection failed");
			});
		}
	});
	(address, task)
}

struct Client {
	reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
	writer: tokio::net::tcp::OwnedWriteHalf,
}

impl Client {
	async fn connect(address: SocketAddr, token: &str) -> (Self, Response) {
		let (reader, mut writer) = TcpStream::connect(address).await.unwrap().into_split();
		send(&mut writer, &Auth { token: token.into(), request_token: None })
			.await
			.unwrap();
		let mut reader = BufReader::new(reader);
		let response = recv(&mut reader).await.unwrap().expect("missing authentication response");
		(Self { reader, writer }, response)
	}

	async fn register(&mut self, target: SocketAddr) -> Response {
		send(
			&mut self.writer,
			&Request::Register { domain: "app.example".into(), target: target.to_string(), force: false },
		)
		.await
		.unwrap();
		recv(&mut self.reader).await.unwrap().expect("missing registration response")
	}
}

async fn dns_query(server: SocketAddr, name: &str) -> (RCODE, Vec<Ipv4Addr>) {
	let mut query = Packet::new_query(0x1234);
	query.questions.push(Question::new(
		Name::new(name).unwrap(),
		QTYPE::TYPE(TYPE::A),
		QCLASS::CLASS(CLASS::IN),
		false,
	));
	let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	client.connect(server).await.unwrap();
	client.send(&query.build_bytes_vec().unwrap()).await.unwrap();
	let mut bytes = [0u8; 512];
	let count = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut bytes))
		.await
		.expect("DNS response timed out")
		.unwrap();
	let reply = Packet::parse(&bytes[..count]).unwrap();
	assert_eq!(reply.id(), 0x1234);
	let addresses = reply
		.answers
		.iter()
		.filter_map(|answer| match &answer.rdata {
			RData::A(record) => Some(Ipv4Addr::from(record.address)),
			_ => None,
		})
		.collect();
	(reply.rcode(), addresses)
}

async fn wait_for_name_removal(host: &Host) {
	tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			if dns_query(host.dns, &host.name()).await == (RCODE::NameError, Vec::new()) {
				break;
			}
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("registration did not leave DNS after its connection closed");
}

enum Trust {
	LocalRoot,
	NoRoots,
}

async fn tls_connect(host: &Host, name: &str, trust: Trust) -> io::Result<TlsStream<TcpStream>> {
	let mut roots = rustls::RootCertStore::empty();
	if matches!(trust, Trust::LocalRoot) {
		roots.add(host.root.clone()).unwrap();
	}
	let config = rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(config));
	let tcp = TcpStream::connect(host.edge.tls_addr).await?;
	connector.connect(ServerName::try_from(name.to_owned()).unwrap(), tcp).await
}

async fn https_request(host: &Host, name: &str) -> String {
	let mut tls = tls_connect(host, name, Trust::LocalRoot)
		.await
		.expect("trusted HTTPS connection failed");
	let authority = format!("{name}:{}", host.edge.tls_addr.port());
	let request = format!("GET /health?source=contract HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
	tls.write_all(request.as_bytes()).await.unwrap();
	let mut response = Vec::new();
	tls.read_to_end(&mut response).await.unwrap();
	String::from_utf8(response).unwrap()
}

async fn exercise_lifecycle() {
	let mut host = Host::start().await;
	let upstream = host.add_upstream("first").await;
	let name = host.name();
	let dashboard = format!("testd.{}", host.tld);
	assert_eq!(dns_query(host.dns, &dashboard).await, (RCODE::NoError, vec![Ipv4Addr::LOCALHOST]));
	assert_eq!(dns_query(host.dns, &name).await, (RCODE::NameError, vec![]));

	let (mut owner, authentication) = Client::connect(host.intake, SECRET).await;
	assert!(matches!(authentication, Response::Ok));
	assert!(matches!(owner.register(upstream).await, Response::Ok));
	assert_eq!(dns_query(host.dns, &name).await, (RCODE::NoError, vec![Ipv4Addr::LOCALHOST]));
	let response = https_request(&host, &name).await;
	assert!(response.starts_with("HTTP/1.1 200"), "{response}");
	assert!(response.contains(&format!("first GET /health?source=contract {name}:{}", host.edge.tls_addr.port())));
	assert!(tls_connect(&host, &name, Trust::NoRoots).await.is_err(), "an untrusted root must not validate");
	assert!(
		tls_connect(&host, &format!("unknown.{}", host.tld), Trust::LocalRoot)
			.await
			.is_err()
	);

	drop(owner);
	wait_for_name_removal(&host).await;
	assert!(tls_connect(&host, &name, Trust::LocalRoot).await.is_err(), "an unregistered name must not receive a leaf");
	assert_eq!(dns_query(host.dns, &dashboard).await, (RCODE::NoError, vec![Ipv4Addr::LOCALHOST]));
}

async fn exercise_authentication_and_ownership() {
	let mut host = Host::start().await;
	let first = host.add_upstream("first").await;
	let second = host.add_upstream("second").await;
	let name = host.name();
	let (_rejected, response) = Client::connect(host.intake, "wrong-token").await;
	assert!(matches!(response, Response::Error { .. }));
	assert_eq!(dns_query(host.dns, &name).await, (RCODE::NameError, vec![]));

	let (mut owner, response) = Client::connect(host.intake, SECRET).await;
	assert!(matches!(response, Response::Ok));
	assert!(matches!(owner.register(first).await, Response::Ok));
	let (mut rival, response) = Client::connect(host.intake, SECRET).await;
	assert!(matches!(response, Response::Ok));
	assert!(matches!(
		rival.register(second).await,
		Response::Error { disposition: Some(ErrorDisposition::Terminal), .. }
	));
	assert!(https_request(&host, &name).await.contains("first GET"));

	drop(owner);
	wait_for_name_removal(&host).await;
	assert!(matches!(rival.register(second).await, Response::Ok));
	assert_eq!(dns_query(host.dns, &name).await, (RCODE::NoError, vec![Ipv4Addr::LOCALHOST]));
	assert!(https_request(&host, &name).await.contains("second GET"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registered_names_accept_case_insensitive_tls_server_names() {
	tokio::time::timeout(TEST_TIMEOUT, async {
		let mut host = Host::start().await;
		let upstream = host.add_upstream("first").await;
		let (mut owner, authentication) = Client::connect(host.intake, SECRET).await;
		assert!(matches!(authentication, Response::Ok));
		assert!(matches!(owner.register(upstream).await, Response::Ok));
		let uppercase_name = host.name().to_ascii_uppercase();
		let response = https_request(&host, &uppercase_name).await;
		assert!(response.starts_with("HTTP/1.1 200"), "{response}");
		assert!(response.contains(&format!("first GET /health?source=contract {uppercase_name}:")));
	})
	.await
	.expect("case-insensitive TLS contract timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_drives_dns_trusted_https_and_disconnect_cleanup() {
	tokio::time::timeout(TEST_TIMEOUT, exercise_lifecycle())
		.await
		.expect("product flow timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_and_ownership_preserve_the_live_route() {
	tokio::time::timeout(TEST_TIMEOUT, exercise_authentication_and_ownership())
		.await
		.expect("ownership flow timed out");
}
