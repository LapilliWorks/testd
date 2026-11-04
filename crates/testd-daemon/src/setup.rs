//! First-run setup, served to the GUI dialog on an ephemeral loopback port.
//!
//! This is deliberately not part of the dashboard: without a config there is no
//! dashboard, and the setup surface must not be reachable at the dashboard name.
//! The Tauri app starts it, opens its URL, and starts the daemon once the page
//! asks to finish.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use testd_core::config::{
	CaddyDetection, DEFAULT_DNS_PORT, PendingConfig, TLD, config_dir, default_http_addr, detect_caddy_config,
	finish_pending_config, generate_operator_secret, has_pending_config, read_operator_secret, read_pending_config,
	write_pending_config,
};

use crate::assets;
use crate::certificate::{self, CertificateStatus};
use crate::http::{header_value, read_body, read_http_line, respond, respond_json};

/// A custom header cannot be sent by a cross-site form and forces a CORS
/// preflight, which this server does not grant.
const REQUEST_HEADER: &str = "x-testd-request";
const MAX_HEAD: usize = 16 * 1024;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Shortest operator secret the setup page accepts; generated ones are longer.
const MIN_SECRET_LEN: usize = 16;

/// A running setup surface.
pub struct Setup {
	/// Loopback URL the dialog should open.
	pub url: String,
	/// The same address as `url`, for tests and callers that need it.
	pub addr: SocketAddr,
	finish: tokio::sync::mpsc::UnboundedReceiver<FinishRequest>,
}

impl Setup {
	/// Block until the dialog asks to finish.
	///
	/// Returns the channel the caller must use to report whether the daemon
	/// started. Call this from outside a tokio runtime.
	pub fn wait(&mut self) -> Option<tokio::sync::oneshot::Sender<Result<String, String>>> {
		self.finish.blocking_recv().map(|request| request.reply)
	}
}

struct FinishRequest {
	reply: tokio::sync::oneshot::Sender<Result<String, String>>,
}

struct State {
	stop: tokio::sync::watch::Sender<bool>,
	finish: tokio::sync::mpsc::UnboundedSender<FinishRequest>,
}

/// Bind the setup listener on an ephemeral loopback port and start serving.
pub fn start(rt: &tokio::runtime::Handle) -> io::Result<Setup> {
	let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
	listener.set_nonblocking(true)?;
	let listener = TcpListener::from_std(listener)?;
	let addr = listener.local_addr()?;
	let (finish, finish_rx) = tokio::sync::mpsc::unbounded_channel();
	let (stop, stop_rx) = tokio::sync::watch::channel(false);
	let state = Arc::new(State { stop, finish });
	rt.spawn(serve(listener, state, stop_rx));
	Ok(Setup { url: format!("http://{addr}/"), addr, finish: finish_rx })
}

async fn serve(listener: TcpListener, state: Arc<State>, mut stop: tokio::sync::watch::Receiver<bool>) {
	loop {
		tokio::select! {
			_ = stop.changed() => break,
			accepted = listener.accept() => {
				let Ok((stream, peer)) = accepted else { break };
				// The listener is already loopback-bound; this is belt and braces.
				if !peer.ip().is_loopback() {
					continue;
				}
				let state = Arc::clone(&state);
				tokio::spawn(async move {
					if let Err(e) = handle(stream, state).await {
						eprintln!("[setup]  {e}");
					}
				});
			},
		}
	}
}

async fn handle(stream: TcpStream, state: Arc<State>) -> io::Result<()> {
	let (reader, mut writer) = tokio::io::split(stream);
	let mut reader = BufReader::new(reader);

	let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
	let Some(request_line) = read_http_line(&mut reader, 8 * 1024, deadline).await? else { return Ok(()) };
	let mut parts = request_line.split_whitespace();
	let method = parts.next().unwrap_or("").to_owned();
	let target = parts.next().unwrap_or("/").to_owned();

	let mut headers: Vec<(String, String)> = Vec::new();
	let mut remaining = MAX_HEAD.saturating_sub(request_line.len());
	loop {
		let line = read_http_line(&mut reader, remaining, deadline)
			.await?
			.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete HTTP headers"))?;
		remaining -= line.len();
		let line = line.trim_end();
		if line.is_empty() {
			break;
		}
		if let Some((name, value)) = line.split_once(':') {
			headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
		}
	}

	// The setup surface must stay a loopback page, not a rebinding target.
	if !is_loopback_host(header_value(&headers, "host")) {
		return respond(&mut writer, "403 Forbidden", "text/plain", b"Loopback Host required.").await;
	}
	if method != "GET" && method != "POST" {
		return respond(&mut writer, "405 Method Not Allowed", "text/plain", b"Method Not Allowed").await;
	}
	if method == "POST" && header_value(&headers, REQUEST_HEADER) != Some("1") {
		return respond(&mut writer, "403 Forbidden", "text/plain", b"A setup request header is required.").await;
	}

	let path = target.split('?').next().unwrap_or("/").to_owned();
	let body = if method == "POST" {
		tokio::time::timeout(REQUEST_TIMEOUT, read_body(&mut reader, &headers))
			.await
			.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP body timed out"))??
	} else {
		Vec::new()
	};

	match (method.as_str(), path.as_str()) {
		("GET", "/") => {
			let page = assets::load(assets::SETUP_HTML);
			respond(&mut writer, "200 OK", "text/html; charset=utf-8", page.as_bytes()).await
		},
		("GET", "/dashboard.css") => {
			let css = assets::load(assets::DASHBOARD_CSS);
			respond(&mut writer, "200 OK", "text/css; charset=utf-8", css.as_bytes()).await
		},
		("GET", "/api/setup/state") => {
			let status = setup_state().await;
			respond_json(&mut writer, "200 OK", &status).await
		},
		("POST", "/api/setup/resolver") => handle_resolver(&mut writer).await,
		("POST", "/api/setup/certificate") => handle_certificate(&mut writer).await,
		("POST", "/api/setup/secret") => handle_secret(&mut writer, &body).await,
		("POST", "/api/setup/finish") => handle_finish(&mut writer, &state, &body).await,
		_ => respond(&mut writer, "404 Not Found", "text/plain", b"Not Found").await,
	}
}

fn is_loopback_host(host: Option<&str>) -> bool {
	let Some(host) = host else { return false };
	let name = match host.strip_prefix('[') {
		Some(rest) => rest.split(']').next().unwrap_or(""),
		None => host.split(':').next().unwrap_or(""),
	};
	matches!(name, "localhost" | "127.0.0.1" | "::1")
}

fn resolver_addr() -> SocketAddr {
	SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_PORT))
}

#[derive(Serialize)]
struct SetupState {
	resolver: bool,
	certificate: Option<CertificateStatus>,
}

async fn setup_state() -> SetupState {
	let resolver = tokio::task::spawn_blocking(|| testd_setup::is_os_resolver_configured(TLD, resolver_addr()))
		.await
		.unwrap_or(false);
	let status = tokio::task::spawn_blocking(|| certificate::status(&pki_dir()))
		.await
		.ok()
		.and_then(Result::ok);
	SetupState { resolver, certificate: status }
}

async fn handle_resolver(writer: &mut (impl AsyncWriteExt + Unpin)) -> io::Result<()> {
	match tokio::task::spawn_blocking(|| testd_setup::setup_os_resolver_gui(TLD, resolver_addr())).await {
		Ok(Ok(())) => respond_json(writer, "200 OK", &serde_json::json!({ "ok": true })).await,
		Ok(Err(e)) => {
			respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e.to_string() })).await
		},
		Err(e) => {
			respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e.to_string() })).await
		},
	}
}

async fn handle_certificate(writer: &mut (impl AsyncWriteExt + Unpin)) -> io::Result<()> {
	match tokio::task::spawn_blocking(|| certificate::install(&pki_dir())).await {
		Ok(Ok(status)) => respond_json(writer, "200 OK", &status).await,
		Ok(Err(e)) => respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e })).await,
		Err(e) => {
			respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e.to_string() })).await
		},
	}
}

#[derive(Deserialize, Default)]
struct SecretRequest {
	#[serde(default)]
	secret: String,
	#[serde(default)]
	regenerate: bool,
}

async fn handle_secret(writer: &mut (impl AsyncWriteExt + Unpin), body: &[u8]) -> io::Result<()> {
	let request: SecretRequest = serde_json::from_slice(body).unwrap_or_default();
	let mut pending = pending_or_default();
	if !request.secret.is_empty() {
		match validate_operator_secret(&request.secret) {
			Ok(secret) => pending.secret = secret,
			Err(e) => return respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
		}
	} else if request.regenerate || pending.secret.is_empty() {
		let existing = if request.regenerate { None } else { read_operator_secret() };
		pending.secret = match existing {
			Some(secret) => secret,
			None => match generate_operator_secret() {
				Ok(secret) => secret,
				Err(e) => {
					return respond_json(
						writer,
						"500 Internal Server Error",
						&serde_json::json!({ "error": e.to_string() }),
					)
					.await;
				},
			},
		};
	}
	if let Err(e) = write_pending_config(&pending) {
		return respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e.to_string() })).await;
	}
	respond_json(writer, "200 OK", &serde_json::json!({ "secret": pending.secret })).await
}

#[derive(Deserialize)]
struct FinishBody {
	#[serde(default)]
	secret: String,
}

async fn handle_finish(writer: &mut (impl AsyncWriteExt + Unpin), state: &State, body: &[u8]) -> io::Result<()> {
	let request: FinishBody = serde_json::from_slice(body).unwrap_or(FinishBody { secret: String::new() });
	let secret = match validate_operator_secret(&request.secret) {
		Ok(secret) => secret,
		Err(e) => return respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
	};

	let mut pending = pending_or_default();
	pending.step = 3;
	pending.caddy_config_path = configure_external_front();
	pending.secret = secret;
	if let Err(e) = finish_pending_config(&pending) {
		return respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e.to_string() })).await;
	}

	let (reply, reply_rx) = tokio::sync::oneshot::channel();
	if state.finish.send(FinishRequest { reply }).is_err() {
		return respond_json(
			writer,
			"503 Service Unavailable",
			&serde_json::json!({ "error": "the setup dialog is gone" }),
		)
		.await;
	}

	match reply_rx.await {
		Ok(Ok(url)) => {
			respond_json(writer, "200 OK", &serde_json::json!({ "url": url })).await?;
			let _ = state.stop.send(true);
			Ok(())
		},
		Ok(Err(e)) => respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e })).await,
		Err(_) => {
			respond_json(writer, "503 Service Unavailable", &serde_json::json!({ "error": "the setup dialog is gone" }))
				.await
		},
	}
}

fn pki_dir() -> std::path::PathBuf {
	config_dir().join("pki")
}

fn pending_or_default() -> PendingConfig {
	if has_pending_config()
		&& let Ok(pending) = read_pending_config()
	{
		return pending;
	}
	PendingConfig { step: 0, caddy_config_path: String::new(), secret: String::new() }
}

fn validate_operator_secret(secret: &str) -> Result<String, String> {
	let secret = secret.trim().to_owned();
	if secret.len() < MIN_SECRET_LEN {
		return Err(format!("the operator secret must be at least {MIN_SECRET_LEN} characters"));
	}
	if !secret
		.chars()
		.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
	{
		return Err("the operator secret may use ASCII letters, digits, and - _ . ~".into());
	}
	Ok(secret)
}

/// Configure an external Caddy front when one is installed.
///
/// The built-in edge needs no Caddy, so this is best-effort: a failure leaves
/// the path empty instead of blocking setup. Mirrors the CLI, which only
/// touches a Caddyfile that already exists.
fn configure_external_front() -> String {
	let CaddyDetection::Found { path } = detect_caddy_config() else {
		return String::new();
	};

	let managed = config_dir().join("Caddyfile");
	let content = crate::edge::caddyfile(TLD, default_http_addr());
	if let Err(e) = write_managed_caddyfile(&managed, &content) {
		eprintln!("[warn]   could not write {}: {e}", managed.display());
		return String::new();
	}
	if let Err(e) = testd_setup::write_caddyfile_import_gui(Path::new(&path), &managed) {
		eprintln!("[warn]   could not update {path}: {e}");
		return String::new();
	}
	path
}

fn write_managed_caddyfile(path: &Path, content: &str) -> io::Result<()> {
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	std::fs::write(path, content)
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	async fn http(addr: SocketAddr, request: &str) -> String {
		let mut stream = TcpStream::connect(addr).await.unwrap();
		stream.write_all(request.as_bytes()).await.unwrap();
		let mut out = Vec::new();
		stream.read_to_end(&mut out).await.unwrap();
		String::from_utf8_lossy(&out).into_owned()
	}

	fn get(path: &str, host: &str) -> String {
		format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
	}

	#[tokio::test]
	async fn the_setup_page_is_loopback_only() {
		let setup = start(&tokio::runtime::Handle::current()).unwrap();
		let addr = setup.addr;

		let page = http(addr, &get("/", "127.0.0.1")).await;
		assert!(page.starts_with("HTTP/1.1 200"), "{page}");
		assert!(page.contains("Set up testd"), "{page}");
		assert!(page.contains("/dashboard.css"), "{page}");

		let css = http(addr, &get("/dashboard.css", "localhost")).await;
		assert!(css.starts_with("HTTP/1.1 200"), "{css}");
		assert!(css.contains(":root"), "{css}");

		// A rebinding page uses its own name; the setup surface refuses it.
		let foreign = http(addr, &get("/", "evil.test")).await;
		assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");
	}

	#[tokio::test]
	async fn setup_mutations_need_the_request_header() {
		let setup = start(&tokio::runtime::Handle::current()).unwrap();
		let request = "POST /api/setup/resolver HTTP/1.1\r\nHost: 127.0.0.1\r\n\
			Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
		let response = http(setup.addr, request).await;
		assert!(response.starts_with("HTTP/1.1 403"), "{response}");
	}
}
