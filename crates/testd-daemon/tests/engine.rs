//! End-to-end engine tests over real TCP connections.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use testd_core::config::{HostConfig, ResolverBackend};
use testd_core::protocol::{Auth, Request, Response, TokenRequest, recv, send};
use testd_daemon::access::{Access, Approved};
use testd_daemon::engine::HostEngine;
use testd_daemon::resolver::{ResolvedName, Resolver};

/// Records the last applied registration set so tests can observe eviction.
struct RecordingResolver {
	applied: Mutex<Vec<ResolvedName>>,
}

impl Resolver for RecordingResolver {
	fn apply(&self, names: &[ResolvedName]) -> io::Result<()> {
		*self.applied.lock().unwrap() = names.to_vec();
		Ok(())
	}

	fn cleanup(&self) -> io::Result<()> {
		Ok(())
	}
}

struct Harness {
	addr: SocketAddr,
	resolver: Arc<RecordingResolver>,
	registrations: testd_daemon::engine::Registrations,
	access: Arc<Access>,
	token: String,
	stop: Option<oneshot::Sender<()>>,
}

const SECRET: &str = "test-secret";

async fn start() -> Harness {
	start_with_dashboard(None).await
}

/// Reserve a loopback port by binding and releasing it. The engine binds it again.
async fn free_addr() -> SocketAddr {
	let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = probe.local_addr().unwrap();
	drop(probe);
	addr
}

async fn start_with_dashboard(_dashboard_addr: Option<SocketAddr>) -> Harness {
	let addr = free_addr().await;

	let dir = std::env::temp_dir().join(format!("testd-engine-{}-{}", std::process::id(), addr.port()));
	std::fs::create_dir_all(&dir).unwrap();

	let resolver = Arc::new(RecordingResolver { applied: Mutex::new(Vec::new()) });
	let config = HostConfig {
		resolver: ResolverBackend::Dns,
		listen_addr: "127.0.0.1:0".parse().unwrap(),
		tld: "test".into(),
		caddyfile_path: dir.join("Caddyfile"),
		caddy_config_path: dir.join("global-Caddyfile"),
		hosts_path: PathBuf::from("/etc/hosts"),
		hosts_helper_path: dir.join("helper"),
		pki_dir: dir.join("pki"),
		edge_addr: "127.0.0.1:0".parse().unwrap(),
		edge_enabled: false,
		http_addr: "127.0.0.1:0".parse().unwrap(),
		answer_addr: std::net::Ipv4Addr::LOCALHOST,
		secret: SECRET.into(),
	};

	let access = Arc::new(Access::load(dir.join("tokens.json")).unwrap());
	let engine = Arc::new(HostEngine::new(config, resolver.clone(), Arc::clone(&access)));
	let registrations = engine.registrations();
	let listener = TcpListener::bind(addr).await.unwrap();
	let (stop, mut stopped) = oneshot::channel::<()>();
	tokio::spawn(async move {
		tokio::select! {
			result = engine.serve(listener) => { result.ok(); }
			_ = &mut stopped => {}
		}
	});

	Harness { addr, resolver, registrations, access, token: SECRET.to_owned(), stop: Some(stop) }
}

impl Drop for Harness {
	fn drop(&mut self) {
		if let Some(stop) = self.stop.take() {
			stop.send(()).ok();
		}
	}
}

struct Client {
	reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
	writer: tokio::net::tcp::OwnedWriteHalf,
}

impl Client {
	async fn connect(addr: SocketAddr, token: &str) -> Self {
		Self::connect_token(addr, token).await
	}

	async fn connect_token(addr: SocketAddr, token: &str) -> Self {
		Self::connect_auth(addr, Auth { token: token.to_owned(), request_token: None }).await
	}

	async fn connect_auth(addr: SocketAddr, auth: Auth) -> Self {
		Self::try_connect_auth(addr, auth).await.expect("authentication failed")
	}

	async fn try_connect_auth(addr: SocketAddr, auth: Auth) -> Option<Self> {
		let stream = TcpStream::connect(addr).await.unwrap();
		let (reader, mut writer) = stream.into_split();
		send(&mut writer, &auth).await.unwrap();
		let mut reader = BufReader::new(reader);
		match recv::<_, Response>(&mut reader).await.unwrap().unwrap() {
			Response::Ok => Some(Self { reader, writer }),
			Response::Error { .. } => None,
			_ => panic!("unexpected auth response"),
		}
	}

	async fn request(&mut self, request: Request) -> Response {
		send(&mut self.writer, &request).await.unwrap();
		recv(&mut self.reader).await.unwrap().unwrap()
	}
}

fn register(domain: &str, target: &str, force: bool) -> Request {
	Request::Register { domain: domain.into(), target: target.into(), force }
}

#[tokio::test]
async fn duplicate_claim_is_rejected_and_names_the_owner() {
	let harness = start().await;
	let mut alice = Client::connect(harness.addr, &harness.token).await;
	let mut bob = Client::connect(harness.addr, &harness.token).await;

	alice.request(register("app", "3000", false)).await;
	match bob.request(register("app", "4000", false)).await {
		Response::Error { message } => {
			assert!(message.contains("already registered by connection"), "{message}")
		},
		other => panic!("duplicate claim must be rejected, got {other:?}"),
	}
}

#[tokio::test]
async fn force_takes_over_a_claim() {
	let harness = start().await;
	let mut alice = Client::connect(harness.addr, &harness.token).await;
	let mut bob = Client::connect(harness.addr, &harness.token).await;

	assert!(matches!(alice.request(register("app", "3000", false)).await, Response::Ok));
	assert!(matches!(bob.request(register("app", "4000", true)).await, Response::Ok));

	let applied = harness.resolver.applied.lock().unwrap().clone();
	assert_eq!(applied.len(), 1);
	assert_eq!(harness.registrations.lock().await.snapshot()[0].target, format!("{}:4000", harness.addr.ip()));
}

#[tokio::test]
async fn disconnecting_the_displaced_client_keeps_the_new_owner() {
	let harness = start().await;
	let mut alice = Client::connect(harness.addr, &harness.token).await;
	let mut bob = Client::connect(harness.addr, &harness.token).await;

	alice.request(register("app", "3000", false)).await;
	bob.request(register("app", "4000", true)).await;

	// Alice's connection closes. Eviction must be scoped to her own claims.
	drop(alice);
	tokio::time::sleep(std::time::Duration::from_millis(100)).await;

	let applied = harness.resolver.applied.lock().unwrap().clone();
	assert_eq!(applied.len(), 1, "bob's claim must survive alice's disconnect");
	assert_eq!(harness.registrations.lock().await.snapshot()[0].target, format!("{}:4000", harness.addr.ip()));

	bob.request(Request::Deregister { domain: "app".into() }).await;
	let applied = harness.resolver.applied.lock().unwrap().clone();
	assert!(applied.is_empty());
}

#[tokio::test]
async fn non_owner_cannot_deregister() {
	let harness = start().await;
	let mut alice = Client::connect(harness.addr, &harness.token).await;
	let mut bob = Client::connect(harness.addr, &harness.token).await;

	alice.request(register("app", "3000", false)).await;
	match bob.request(Request::Deregister { domain: "app".into() }).await {
		Response::Error { message } => assert!(message.contains("owned by"), "{message}"),
		other => panic!("non-owner deregistration must fail, got {other:?}"),
	}
}

#[tokio::test]
async fn two_claims_on_one_connection_are_both_released() {
	let harness = start().await;
	let mut alice = Client::connect(harness.addr, &harness.token).await;
	alice.request(register("app", "3000", false)).await;
	alice.request(register("api.app", "4000", false)).await;
	assert_eq!(harness.resolver.applied.lock().unwrap().len(), 2);

	drop(alice);
	tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	assert!(harness.resolver.applied.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_name_is_still_rejected_for_other_connections_only() {
	let harness = start().await;
	let mut alice = Client::connect(harness.addr, &harness.token).await;
	// Re-registering your own name updates the target.
	alice.request(register("app", "3000", false)).await;
	assert!(matches!(alice.request(register("app", "4000", false)).await, Response::Ok));
	let snapshot = harness.registrations.lock().await.snapshot();
	let map: HashMap<_, _> = snapshot.iter().map(|r| (r.domain.clone(), r.target.clone())).collect();
	assert_eq!(map["app.test"], format!("{}:4000", harness.addr.ip()));
}

/// Open a connection that asks the host for a token instead of presenting one.
async fn request_access(harness: &Harness, label: &str, names: &[&str]) -> (Client, String) {
	let stream = TcpStream::connect(harness.addr).await.unwrap();
	let (read, mut writer) = stream.into_split();
	let names = names.iter().map(|name| (*name).to_owned()).collect();
	let request_token = TokenRequest { label: label.to_owned(), names };
	let auth = Auth { token: String::new(), request_token: Some(request_token) };
	send(&mut writer, &auth).await.unwrap();
	let mut reader = BufReader::new(read);
	match recv(&mut reader).await.unwrap().unwrap() {
		Response::Pending { id } => (Client { reader, writer }, id),
		other => panic!("expected a pending response, got {other:?}"),
	}
}

#[tokio::test]
async fn an_approved_request_issues_a_working_token() {
	let harness = start().await;
	let (mut waiting, id) = request_access(&harness, "alex@laptop", &["app", "api"]).await;
	assert_eq!(harness.access.pending().len(), 1);

	let Approved::Token(issued) = harness.access.approve(&id).unwrap() else { panic!("expected a token") };
	match recv::<_, Response>(&mut waiting.reader).await.unwrap().unwrap() {
		Response::Token { token } => assert_eq!(token, issued.token),
		other => panic!("expected a token, got {other:?}"),
	}
	assert_eq!(issued.names.as_deref(), Some(&["api.test".to_owned(), "app.test".to_owned()][..]));
	// The approved connection continues without a second authentication.
	assert!(matches!(waiting.request(register("app", "3000", false)).await, Response::Ok));

	// The same token opens later connections for the names it was granted.
	let mut later = Client::connect(harness.addr, &issued.token).await;
	assert!(matches!(later.request(register("api", "4000", false)).await, Response::Ok));

	harness.access.revoke(&issued.id).unwrap();
	assert!(
		Client::try_connect_auth(harness.addr, Auth { token: issued.token, request_token: None })
			.await
			.is_none()
	);
}

#[tokio::test]
async fn a_denied_request_is_told_why() {
	let harness = start().await;
	let (mut waiting, id) = request_access(&harness, "alex@laptop", &["app"]).await;
	harness.access.deny(&id).unwrap();
	match recv::<_, Response>(&mut waiting.reader).await.unwrap().unwrap() {
		Response::Error { message } => assert!(message.contains("denied"), "{message}"),
		other => panic!("expected an error, got {other:?}"),
	}
	assert!(harness.access.tokens().is_empty());
}

#[tokio::test]
async fn a_closed_connection_removes_its_pending_request() {
	let harness = start().await;
	let (waiting, id) = request_access(&harness, "alex@laptop", &["app"]).await;
	drop(waiting);
	for _ in 0..100 {
		if harness.access.pending().is_empty() {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(20)).await;
	}
	assert!(harness.access.pending().is_empty(), "request {id} should be gone");
}

/// One HTTP/1.1 request against a listener that may still be starting.
async fn http(addr: SocketAddr, request: &str) -> String {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let mut stream = None;
	for _ in 0..100 {
		if let Ok(stream_) = TcpStream::connect(addr).await {
			stream = Some(stream_);
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(20)).await;
	}
	let mut stream = stream.expect("listener accepted a connection");
	stream.write_all(request.as_bytes()).await.unwrap();
	let mut out = Vec::new();
	stream.read_to_end(&mut out).await.unwrap();
	String::from_utf8_lossy(&out).into_owned()
}

fn get(path: &str, headers: &[(&str, &str)]) -> String {
	let mut request = format!("GET {path} HTTP/1.1\r\nHost: testd.test\r\n");
	for (name, value) in headers {
		request.push_str(&format!("{name}: {value}\r\n"));
	}
	request.push_str("Connection: close\r\n\r\n");
	request
}

/// One dashboard mutation from loopback, with the header that proves intent.
fn post(path: &str, body: &str) -> String {
	format!(
		"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nx-testd-request: 1\r\nContent-Type: application/json\r\n\
		 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len()
	)
}

#[tokio::test]
async fn stopping_a_name_keeps_the_grant() {
	let harness = start().await;
	let (mut waiting, id) = request_access(&harness, "alex@laptop", &["app"]).await;
	let Approved::Token(issued) = harness.access.approve(&id).unwrap() else { panic!("expected a token") };
	match recv::<_, Response>(&mut waiting.reader).await.unwrap().unwrap() {
		Response::Token { token } => assert_eq!(token, issued.token),
		other => panic!("expected a token, got {other:?}"),
	}
	assert!(matches!(waiting.request(register("app", "3000", false)).await, Response::Ok));

	let page = http(harness.addr, &post("/stop/app.test", "")).await;
	assert!(page.starts_with("HTTP/1.1 200"), "{page}");

	let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), recv::<_, Response>(&mut waiting.reader))
		.await
		.expect("the owner is told to stop")
		.unwrap()
		.unwrap();
	assert!(matches!(&stopped, Response::Stopped { domain } if domain == "app.test"), "{stopped:?}");
	assert!(harness.registrations.lock().await.snapshot().is_empty());

	// The grant is untouched, so the same token publishes the name again
	// without asking the operator for anything.
	let mut again = Client::connect(harness.addr, &issued.token).await;
	assert!(matches!(again.request(register("app", "3000", false)).await, Response::Ok));
}

#[tokio::test]
async fn deleting_one_name_keeps_the_rest() {
	let harness = start().await;
	let (mut waiting, id) = request_access(&harness, "alex@laptop", &["app", "api"]).await;
	let Approved::Token(issued) = harness.access.approve(&id).unwrap() else { panic!("expected a token") };
	match recv::<_, Response>(&mut waiting.reader).await.unwrap().unwrap() {
		Response::Token { token } => assert_eq!(token, issued.token),
		other => panic!("expected a token, got {other:?}"),
	}
	assert!(matches!(waiting.request(register("app", "3000", false)).await, Response::Ok));
	assert!(matches!(waiting.request(register("api", "4000", false)).await, Response::Ok));

	let page = http(harness.addr, &post("/delete/api.test", "")).await;
	assert!(page.starts_with("HTTP/1.1 200"), "{page}");

	// Only the deleted name is withdrawn, and the connection stays open.
	let notice = tokio::time::timeout(std::time::Duration::from_secs(5), recv::<_, Response>(&mut waiting.reader))
		.await
		.expect("the leaf is told its name lost its grant")
		.unwrap();
	assert!(matches!(&notice, Some(Response::NameRevoked { domain }) if domain == "api.test"), "{notice:?}");
	let snapshot = harness.registrations.lock().await.snapshot();
	assert_eq!(snapshot.len(), 1, "only one name was deleted: {snapshot:?}");
	assert_eq!(snapshot[0].domain, "app.test");

	// The token still covers the other name for a later connection.
	let mut later = Client::connect(harness.addr, &issued.token).await;
	assert!(matches!(later.request(register("app", "5000", true)).await, Response::Ok));

	// Publishing the deleted name again asks the operator for a grant.
	let request = register("api", "4000", false);
	send(&mut waiting.writer, &request).await.unwrap();
	let pending = tokio::time::timeout(std::time::Duration::from_secs(5), recv::<_, Response>(&mut waiting.reader))
		.await
		.expect("the leaf is told a grant is pending")
		.unwrap()
		.unwrap();
	let id = match pending {
		Response::PendingGrant { id, domain } => {
			assert_eq!(domain, "api.test");
			id
		},
		other => panic!("expected a pending grant, got {other:?}"),
	};
	assert!(matches!(harness.access.approve(&id).unwrap(), Approved::Name));
	let done = tokio::time::timeout(std::time::Duration::from_secs(5), recv::<_, Response>(&mut waiting.reader))
		.await
		.expect("the held registration completes")
		.unwrap()
		.unwrap();
	assert!(matches!(done, Response::Ok), "{done:?}");
	assert_eq!(harness.registrations.lock().await.snapshot().len(), 2);
}

#[tokio::test]
async fn a_denied_name_grant_keeps_the_name_out() {
	let harness = start().await;
	let (mut waiting, id) = request_access(&harness, "alex@laptop", &["app"]).await;
	let Approved::Token(_) = harness.access.approve(&id).unwrap() else { panic!("expected a token") };
	match recv::<_, Response>(&mut waiting.reader).await.unwrap().unwrap() {
		Response::Token { .. } => {},
		other => panic!("expected a token, got {other:?}"),
	}
	assert!(matches!(waiting.request(register("app", "3000", false)).await, Response::Ok));

	let request = register("api", "4000", false);
	send(&mut waiting.writer, &request).await.unwrap();
	let pending = tokio::time::timeout(std::time::Duration::from_secs(5), recv::<_, Response>(&mut waiting.reader))
		.await
		.expect("the leaf is told a grant is pending")
		.unwrap()
		.unwrap();
	let id = match pending {
		Response::PendingGrant { id, domain } => {
			assert_eq!(domain, "api.test");
			id
		},
		other => panic!("expected a pending grant, got {other:?}"),
	};
	assert_eq!(harness.access.pending()[0].names, vec!["api.test".to_owned()]);
	harness.access.deny(&id).unwrap();
	let denied = tokio::time::timeout(std::time::Duration::from_secs(5), recv::<_, Response>(&mut waiting.reader))
		.await
		.expect("the held registration is refused")
		.unwrap()
		.unwrap();
	match denied {
		Response::Error { message } => assert!(message.contains("denied"), "{message}"),
		other => panic!("expected a denial, got {other:?}"),
	}
	assert_eq!(harness.registrations.lock().await.snapshot().len(), 1);
}

#[tokio::test]
async fn a_name_without_an_issued_grant_cannot_be_deleted() {
	let harness = start().await;
	let mut alice = Client::connect(harness.addr, &harness.token).await;
	assert!(matches!(alice.request(register("app", "3000", false)).await, Response::Ok));

	let page = http(harness.addr, &post("/delete/app.test", "")).await;
	assert!(page.starts_with("HTTP/1.1 400"), "{page}");
	assert!(page.contains("no issued grant"), "the refusal names the reason: {page}");
	assert_eq!(harness.registrations.lock().await.snapshot().len(), 1, "a refused delete keeps the name");
}

#[tokio::test]
async fn revoking_a_token_closes_the_connections_that_use_it() {
	let harness = start().await;
	let (mut waiting, id) = request_access(&harness, "alex@laptop", &["app"]).await;
	let Approved::Token(issued) = harness.access.approve(&id).unwrap() else { panic!("expected a token") };
	match recv::<_, Response>(&mut waiting.reader).await.unwrap().unwrap() {
		Response::Token { token } => assert_eq!(token, issued.token),
		other => panic!("expected a token, got {other:?}"),
	}
	assert!(matches!(waiting.request(register("app", "3000", false)).await, Response::Ok));

	let body = format!("{{\"id\":\"{}\"}}", issued.id);
	let page = http(harness.addr, &post("/api/local/tokens/revoke", &body)).await;
	assert!(page.starts_with("HTTP/1.1 200"), "{page}");

	let notice = tokio::time::timeout(std::time::Duration::from_secs(5), recv::<_, Response>(&mut waiting.reader))
		.await
		.expect("the leaf is told its grant was revoked")
		.unwrap();
	assert!(matches!(notice, Some(Response::GrantRevoked)), "{notice:?}");
	let end = tokio::time::timeout(std::time::Duration::from_secs(5), recv::<_, Response>(&mut waiting.reader))
		.await
		.expect("the host closes the connection")
		.unwrap();
	assert!(end.is_none(), "expected the connection to end, got {end:?}");

	for _ in 0..100 {
		if harness.registrations.lock().await.snapshot().is_empty() {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(20)).await;
	}
	assert!(harness.registrations.lock().await.snapshot().is_empty(), "a revoked credential must not keep publishing");
}

#[tokio::test]
async fn the_dashboard_offers_stop_and_grant_delete() {
	let harness = start().await;
	// A leaf on the operator secret has a name but no grant to delete.
	let mut alice = Client::connect(harness.addr, &harness.token).await;
	assert!(matches!(alice.request(register("app", "3000", false)).await, Response::Ok));
	let page = http(harness.addr, &get("/", &[]).replace("Host: testd.test", "Host: 127.0.0.1")).await;
	assert!(page.contains("stopName('app.test'"), "every name can be stopped: {page}");
	assert!(!page.contains("deleteGrant('app.test'"), "the operator secret has no grant to delete: {page}");

	// A leaf admitted with an issued token offers both actions.
	let (mut waiting, id) = request_access(&harness, "alex@laptop", &["api"]).await;
	harness.access.approve(&id).unwrap();
	match recv::<_, Response>(&mut waiting.reader).await.unwrap().unwrap() {
		Response::Token { .. } => {},
		other => panic!("expected a token, got {other:?}"),
	}
	assert!(matches!(waiting.request(register("api", "4000", false)).await, Response::Ok));
	let page = http(harness.addr, &get("/", &[]).replace("Host: testd.test", "Host: 127.0.0.1")).await;
	assert!(page.contains("deleteGrant('api.test'"), "a granted name can have its grant deleted: {page}");
}

#[tokio::test]
async fn the_loopback_dashboard_is_local_and_exposes_local_actions() {
	let harness = start_with_dashboard(None).await;

	let local_get = |path: &str| get(path, &[]).replace("Host: testd.test", "Host: 127.0.0.1");
	let page = http(harness.addr, &local_get("/")).await;
	assert!(page.starts_with("HTTP/1.1 200"), "{page}");
	assert!(page.contains("Quick launches"), "the local dashboard shows local actions: {page}");
	assert!(page.contains("Free version"), "the local dashboard carries its edition label: {page}");
	assert!(page.contains("data-theme-choice=\"dark\""), "the local dashboard has a theme switch: {page}");
	for placeholder in ["{tld}", "{domains}", "{domain_count}", "{shares}", "{share_count}", "{advisory}", "{version}"]
	{
		assert!(!page.contains(placeholder), "the dashboard renders {placeholder}: {page}");
	}
	assert!(!page.contains("name=\"token\""), "the loopback page does not ask for a token: {page}");

	let launches = http(harness.addr, &local_get("/api/local/launches")).await;
	assert!(!launches.starts_with("HTTP/1.1 404"), "local routes are served locally: {launches}");

	let rebinding = http(harness.addr, &get("/", &[])).await;
	assert!(rebinding.starts_with("HTTP/1.1 403"), "a foreign Host is refused: {rebinding}");
}

#[tokio::test]
async fn silent_and_partial_authentication_connections_have_deadlines() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let harness = start().await;
	let mut silent = TcpStream::connect(harness.addr).await.unwrap();
	let mut partial = TcpStream::connect(harness.addr).await.unwrap();
	partial.write_all(b"{\"token\":").await.unwrap();
	let check = async {
		let mut byte = [0];
		assert!(matches!(silent.read(&mut byte).await, Ok(0) | Err(_)));
		assert!(matches!(partial.read(&mut byte).await, Ok(0) | Err(_)));
	};
	tokio::time::timeout(std::time::Duration::from_secs(12), check)
		.await
		.expect("intake deadlines");
}

#[tokio::test]
async fn oversized_http_headers_are_refused() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let harness = start().await;
	let mut stream = TcpStream::connect(harness.addr).await.unwrap();
	let head = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Large: {}\r\n\r\n", "a".repeat(40 * 1024));
	stream.write_all(head.as_bytes()).await.unwrap();
	let mut byte = [0];
	let closed = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut byte))
		.await
		.unwrap();
	assert!(matches!(closed, Ok(0) | Err(_)));
}

async fn approved_leaf(harness: &Harness, names: &[&str]) -> (Client, testd_daemon::access::IssuedToken) {
	let (mut leaf, request) = request_access(harness, "release-check", names).await;
	let Approved::Token(token) = harness.access.approve(&request).unwrap() else { panic!("expected token") };
	assert!(matches!(recv::<_, Response>(&mut leaf.reader).await.unwrap(), Some(Response::Token { .. })));
	(leaf, token)
}

#[tokio::test]
async fn revocation_bursts_cannot_leave_old_claims_alive() {
	let harness = start().await;
	let mut leaves = Vec::new();
	for index in 0..40 {
		let name = format!("app{index}");
		let (mut leaf, token) = approved_leaf(&harness, &[&name]).await;
		assert!(matches!(leaf.request(register(&name, "3000", false)).await, Response::Ok));
		leaves.push((leaf, token));
	}
	/* No await: revocations coalesce before the engine gets scheduled again. */
	for (_, token) in &leaves {
		harness.access.revoke(&token.id).unwrap();
	}
	for (leaf, _) in &mut leaves {
		let notice = tokio::time::timeout(std::time::Duration::from_secs(3), recv::<_, Response>(&mut leaf.reader))
			.await
			.expect("revocation notice")
			.unwrap();
		assert!(matches!(notice, Some(Response::GrantRevoked)), "{notice:?}");
	}
	assert!(harness.registrations.lock().await.snapshot().is_empty());
}

#[tokio::test]
async fn disconnect_during_a_name_request_cancels_even_a_pipelined_request() {
	let harness = start().await;
	let (mut leaf, _) = approved_leaf(&harness, &["app"]).await;
	send(&mut leaf.writer, &register("api", "3000", false)).await.unwrap();
	assert!(matches!(recv::<_, Response>(&mut leaf.reader).await.unwrap(), Some(Response::PendingGrant { .. })));
	send(&mut leaf.writer, &register("app", "4000", false)).await.unwrap();
	drop(leaf);
	tokio::time::timeout(std::time::Duration::from_secs(3), async {
		while !harness.access.pending().is_empty() {
			tokio::time::sleep(std::time::Duration::from_millis(10)).await;
		}
	})
	.await
	.expect("disconnected request is cancelled");
	assert!(harness.registrations.lock().await.snapshot().is_empty());
}

#[tokio::test]
async fn approval_preserves_a_partially_received_pipelined_frame() {
	use tokio::io::AsyncWriteExt;
	let harness = start().await;
	let (mut leaf, _) = approved_leaf(&harness, &["app"]).await;
	send(&mut leaf.writer, &register("api", "3000", false)).await.unwrap();
	let Some(Response::PendingGrant { id, .. }) = recv::<_, Response>(&mut leaf.reader).await.unwrap() else {
		panic!("expected name request")
	};
	let frame = serde_json::to_vec(&register("app", "4000", false)).unwrap();
	let middle = frame.len() / 2;
	leaf.writer.write_all(&frame[..middle]).await.unwrap();
	tokio::time::sleep(std::time::Duration::from_millis(20)).await;
	harness.access.approve(&id).unwrap();
	assert!(matches!(recv::<_, Response>(&mut leaf.reader).await.unwrap(), Some(Response::Ok)));
	leaf.writer.write_all(&frame[middle..]).await.unwrap();
	leaf.writer.write_all(b"\n").await.unwrap();
	let reply = tokio::time::timeout(std::time::Duration::from_secs(3), recv::<_, Response>(&mut leaf.reader))
		.await
		.expect("pipeline survives approval")
		.unwrap();
	assert!(matches!(reply, Some(Response::Ok)), "{reply:?}");
}

#[tokio::test]
async fn oversized_authentication_closes_only_the_offending_connection() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let harness = start().await;
	let mut stream = TcpStream::connect(harness.addr).await.unwrap();
	stream
		.write_all(&vec![b'{'; testd_core::protocol::MAX_FRAME_BYTES + 1])
		.await
		.unwrap();
	let mut byte = [0];
	let closed = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut byte))
		.await
		.unwrap();
	assert!(matches!(closed, Ok(0) | Err(_)));
	assert!(matches!(
		Client::connect(harness.addr, &harness.token)
			.await
			.request(register("app", "3000", false))
			.await,
		Response::Ok
	));
}
