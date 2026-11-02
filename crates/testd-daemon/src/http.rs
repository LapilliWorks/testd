//! The loopback dashboard: names, shares, quick launches, and certificates.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;

use testd_core::Registration;

use crate::access::Access;
use crate::engine::{Connections, OperatorAction, OperatorRequest};
use crate::launch::LaunchBook;
use crate::registry::Claim;

#[cfg(debug_assertions)]
const DASHBOARD_TEMPLATE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dashboard.html");

/// State shared by every dashboard request.
pub struct HttpContext {
	pub tld: String,
	pub pki_dir: PathBuf,
	/// Per-run token for the dashboard. Mutations and API reads require it.
	pub local_token: Option<String>,
	pub registrations: crate::engine::Registrations,
	/// Live connections, to tell a name's grant from a bare registration.
	pub connections: Arc<Connections>,
	/// Operator actions that need the engine loop.
	pub operator_tx: tokio::sync::mpsc::Sender<OperatorRequest>,
	pub launches: Option<Arc<LaunchBook>>,
	pub health_refresh: Option<Arc<dyn Fn() + Send + Sync>>,
	/// Present when the daemon owns shares; the dashboard lists and stops them.
	pub shares: Option<Arc<crate::share::Shares>>,
	/// Issued leaf tokens and access requests awaiting approval.
	pub access: Arc<Access>,
	/// Registration changes, for live dashboard updates.
	pub engine_events: tokio::sync::broadcast::Sender<crate::engine::EngineEvent>,
}

/// Launch definitions, JSON mutations, and certificate output all fit.
const MAX_BODY: usize = 256 * 1024;
const MAX_HEAD: usize = 32 * 1024;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// A custom header cannot be sent by a cross-site form and forces a CORS
/// preflight, which this server does not grant.
const REQUEST_HEADER: &str = "x-testd-request";
const TOKEN_HEADER: &str = "x-testd-token";

pub async fn handle(stream: PeekedStream, ctx: &HttpContext, peer: SocketAddr) -> io::Result<()> {
	if !peer.ip().is_loopback() {
		let (_, mut writer) = tokio::io::split(stream);
		return respond(&mut writer, "403 Forbidden", "text/plain", b"The dashboard is loopback-only.").await;
	}
	handle_stream(stream, ctx).await
}

async fn handle_stream<S>(stream: S, ctx: &HttpContext) -> io::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
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

	// A DNS rebinding page must not become a local admin client.
	if !is_loopback_host(header_value(&headers, "host")) {
		return respond(&mut writer, "403 Forbidden", "text/plain", b"Loopback Host required.").await;
	}

	let path = target.split('?').next().unwrap_or("/").to_owned();

	if method != "GET" && method != "POST" {
		return respond(&mut writer, "405 Method Not Allowed", "text/plain", b"Method Not Allowed").await;
	}

	// Mutations carry a custom header: a cross-site form cannot set it, and a
	// cross-origin fetch cannot pass the preflight.
	if method == "POST" && header_value(&headers, REQUEST_HEADER) != Some("1") {
		return respond(&mut writer, "403 Forbidden", "text/plain", b"A dashboard request header is required.").await;
	}

	if requires_dashboard_auth(&method, &path) && !authorized(&headers, ctx.local_token.as_deref()) {
		return respond(&mut writer, "401 Unauthorized", "text/plain", b"A dashboard token is required.").await;
	}

	let body = if method == "POST" {
		tokio::time::timeout(REQUEST_TIMEOUT, read_body(&mut reader, &headers))
			.await
			.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP body timed out"))??
	} else {
		Vec::new()
	};

	match (method.as_str(), path.as_str()) {
		("GET", "/") => serve_dashboard(&mut writer, ctx).await,
		("GET", "/api/status") => serve_status(&mut writer, ctx).await,
		("GET", "/api/local/state") => serve_state(&mut writer, ctx).await,
		("GET", "/api/local/events") => serve_events(&mut writer, ctx).await,
		("GET", "/ca.crt") => serve_ca_cert(&mut writer, &ctx.pki_dir).await,
		("GET", "/ok.svg") => {
			respond(&mut writer, "200 OK", "image/svg+xml", br#"<svg xmlns="http://www.w3.org/2000/svg"/>"#).await
		},
		("GET", "/api/local/launches") => handle_launches(&mut writer, ctx).await,
		("POST", "/api/local/launches/save") => handle_launch_save(&mut writer, ctx, &body).await,
		("POST", "/api/local/launches/delete") => handle_launch_delete(&mut writer, ctx, &body).await,
		("POST", "/api/local/launches/start") => handle_launch_start(&mut writer, ctx, &body).await,
		("POST", "/api/local/launches/stop") => handle_launch_stop(&mut writer, ctx, &body).await,
		("POST", "/api/local/launches/rebind") => handle_launch_rebind(&mut writer, ctx, &body).await,
		("GET", "/api/local/requests") => respond_json(&mut writer, "200 OK", &ctx.access.pending()).await,
		("POST", "/api/local/requests/approve") => handle_request_decision(&mut writer, ctx, &body, true).await,
		("POST", "/api/local/requests/deny") => handle_request_decision(&mut writer, ctx, &body, false).await,
		("GET", "/api/local/tokens") => respond_json(&mut writer, "200 OK", &ctx.access.tokens()).await,
		("POST", "/api/local/tokens/revoke") => handle_token_revoke(&mut writer, ctx, &body).await,
		("GET", "/api/local/certificate") => handle_certificate_status(&mut writer, ctx).await,
		("POST", "/api/local/certificate/install") => handle_certificate_install(&mut writer, ctx).await,
		("POST", "/api/local/certificate/remove") => handle_certificate_remove(&mut writer, ctx).await,
		("POST", p) if p.starts_with("/unshare/") => handle_unshare(&mut writer, ctx, &p["/unshare/".len()..]).await,
		("POST", p) if p.starts_with("/stop/") => handle_stop(&mut writer, ctx, &p["/stop/".len()..]).await,
		("POST", p) if p.starts_with("/delete/") => handle_delete_grant(&mut writer, ctx, &p["/delete/".len()..]).await,
		_ => respond(&mut writer, "404 Not Found", "text/plain", b"Not Found").await,
	}
}

async fn read_http_line<R: tokio::io::AsyncBufRead + Unpin>(
	reader: &mut R,
	limit: usize,
	deadline: tokio::time::Instant,
) -> io::Result<Option<String>> {
	let line = tokio::time::timeout_at(deadline, testd_core::protocol::read_line(reader, limit))
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP headers timed out"))??;
	line.map(|bytes| String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)))
		.transpose()
}

fn requires_dashboard_auth(method: &str, path: &str) -> bool {
	method == "POST" || path.starts_with("/api/local/")
}

fn authorized(headers: &[(String, String)], expected: Option<&str>) -> bool {
	let Some(expected) = expected.filter(|token| !token.is_empty()) else { return false };
	let Some(actual) = header_value(headers, TOKEN_HEADER) else { return false };
	constant_time_eq(expected.as_bytes(), actual.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
	if left.len() != right.len() {
		return false;
	}
	left.iter().zip(right).fold(0u8, |difference, (a, b)| difference | (a ^ b)) == 0
}

fn is_loopback_host(host: Option<&str>) -> bool {
	let Some(host) = host else { return false };
	let name = match host.strip_prefix('[') {
		Some(rest) => rest.split(']').next().unwrap_or(""),
		None => host.split(':').next().unwrap_or(""),
	};
	matches!(name, "localhost" | "127.0.0.1" | "::1")
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
	headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

async fn serve_dashboard<W: AsyncWriteExt + Unpin>(writer: &mut W, ctx: &HttpContext) -> io::Result<()> {
	let dashboard = dashboard_claims(ctx).await;
	let shares = match &ctx.shares {
		Some(shares) => shares.list().await,
		None => Vec::new(),
	};
	let body = render_dashboard(ctx, &dashboard.claims, &dashboard.granted, &shares);
	respond(writer, "200 OK", "text/html; charset=utf-8", body.as_bytes()).await
}

/// Claims and the names that carry an issued grant, for the dashboard.
struct DashboardClaims {
	claims: Vec<Claim>,
	granted: HashSet<String>,
}

async fn dashboard_claims(ctx: &HttpContext) -> DashboardClaims {
	// A share's name is answered by the edge for the provider's benefit; it is
	// not a registration, so it belongs in the shares card, not the name list.
	let (claims, aliases) = {
		let registry = ctx.registrations.lock().await;
		(registry.claims(), registry.aliases())
	};
	let aliases: HashSet<String> = aliases.into_iter().map(|alias| alias.domain).collect();
	let claims: Vec<Claim> = claims
		.into_iter()
		.filter(|claim| !aliases.contains(&claim.registration.domain))
		.collect();
	// A name has a grant to delete only when its leaf was admitted with an
	// issued token. The operator secret and the local launch token are not
	// per-leaf grants.
	let granted: HashSet<String> = claims
		.iter()
		.filter(|claim| ctx.connections.grant(claim.connection).is_some())
		.map(|claim| claim.registration.domain.clone())
		.collect();
	DashboardClaims { claims, granted }
}

#[derive(serde::Serialize)]
struct DashboardState {
	tld: String,
	domains: Vec<DomainView>,
	advisory: Vec<String>,
	shares: Vec<crate::share::ShareView>,
	launches: Vec<crate::launch::LaunchView>,
	requests: Vec<crate::access::PendingView>,
	tokens: Vec<crate::access::TokenView>,
}

#[derive(serde::Serialize)]
struct DomainView {
	domain: String,
	target: String,
	project: Option<String>,
	granted: bool,
}

async fn dashboard_state(ctx: &HttpContext) -> DashboardState {
	let dashboard = dashboard_claims(ctx).await;
	let regs: Vec<Registration> = dashboard.claims.iter().map(|claim| claim.registration.clone()).collect();
	let domains = dashboard
		.claims
		.iter()
		.map(|claim| DomainView {
			domain: claim.registration.domain.clone(),
			target: claim.registration.target.clone(),
			project: testd_core::naming::project_label(&claim.registration.domain).map(str::to_owned),
			granted: dashboard.granted.contains(&claim.registration.domain),
		})
		.collect();
	DashboardState {
		tld: ctx.tld.clone(),
		advisory: advisory(&regs),
		domains,
		shares: match &ctx.shares {
			Some(shares) => shares.list().await,
			None => Vec::new(),
		},
		launches: ctx.launches.as_ref().map(|book| book.list()).unwrap_or_default(),
		requests: ctx.access.pending(),
		tokens: ctx.access.tokens(),
	}
}

async fn serve_state<W: AsyncWriteExt + Unpin>(writer: &mut W, ctx: &HttpContext) -> io::Result<()> {
	respond_json(writer, "200 OK", &dashboard_state(ctx).await).await
}

/// Server-sent snapshots. The browser reads the stream with `fetch`, so the
/// per-run token stays in a request header instead of the URL.
async fn serve_events<W: AsyncWriteExt + Unpin>(writer: &mut W, ctx: &HttpContext) -> io::Result<()> {
	// Subscribe before the first snapshot so a change during the snapshot still
	// wakes the stream; duplicate snapshots are suppressed below.
	let mut engine_events = ctx.engine_events.subscribe();
	let mut access_changes = Some(ctx.access.state_changes());
	let mut launch_changes = ctx.launches.as_ref().map(|book| book.state_changes());
	let mut share_changes = ctx.shares.as_ref().map(|shares| shares.state_changes());

	const HEADERS: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n\
		Cache-Control: no-store\r\nConnection: keep-alive\r\nX-Accel-Buffering: no\r\n\
		X-Content-Type-Options: nosniff\r\nContent-Security-Policy: frame-ancestors 'none'\r\n\r\n";
	write_sse(writer, HEADERS.as_bytes()).await?;

	let mut last = serde_json::to_string(&dashboard_state(ctx).await).unwrap_or_default();
	write_sse(writer, format!("event: state\ndata: {last}\n\n").as_bytes()).await?;

	let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
	heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	heartbeat.tick().await;

	loop {
		let changed = tokio::select! {
			_ = heartbeat.tick() => {
				write_sse(writer, b": keep-alive\n\n").await?;
				false
			},
			result = engine_events.recv() => match result {
				Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
				Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
			},
			changed = wait_change(&mut access_changes) => {
				if !changed { return Ok(()); }
				true
			},
			changed = wait_change(&mut launch_changes) => {
				if !changed { return Ok(()); }
				true
			},
			changed = wait_change(&mut share_changes) => {
				if !changed { return Ok(()); }
				true
			},
		};
		if !changed {
			continue;
		}
		let next = serde_json::to_string(&dashboard_state(ctx).await).unwrap_or_default();
		if next != last {
			write_sse(writer, format!("event: state\ndata: {next}\n\n").as_bytes()).await?;
			last = next;
		}
	}
}

/// Wait on an optional change channel. Without one, the branch never fires.
async fn wait_change<T: Clone>(receiver: &mut Option<tokio::sync::watch::Receiver<T>>) -> bool {
	match receiver {
		Some(receiver) => receiver.changed().await.is_ok(),
		None => std::future::pending().await,
	}
}

async fn write_sse<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
	tokio::time::timeout(RESPONSE_TIMEOUT, async {
		writer.write_all(data).await?;
		writer.flush().await
	})
	.await
	.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "event stream write timed out"))?
}

async fn serve_status<W: AsyncWriteExt + Unpin>(writer: &mut W, ctx: &HttpContext) -> io::Result<()> {
	let regs = ctx.registrations.lock().await.snapshot();
	let body = serde_json::json!({
		"tld": ctx.tld,
		"domains": regs.iter().map(|reg| serde_json::json!({
			"domain": reg.domain,
			"target": reg.target,
			"project": testd_core::naming::project_label(&reg.domain),
		})).collect::<Vec<_>>(),
		"advisory": advisory(&regs),
		"shares": match &ctx.shares {
			Some(shares) => serde_json::to_value(shares.list().await).unwrap_or_default(),
			None => serde_json::Value::Array(Vec::new()),
		},
	});
	respond(writer, "200 OK", "application/json", serde_json::to_string_pretty(&body).unwrap_or_default().as_bytes())
		.await
}

fn render_dashboard(
	ctx: &HttpContext,
	claims: &[Claim],
	granted: &HashSet<String>,
	shares: &[crate::share::ShareView],
) -> String {
	let regs: Vec<Registration> = claims.iter().map(|claim| claim.registration.clone()).collect();
	let advisory_html = if advisory(&regs).is_empty() {
		String::new()
	} else {
		let mut html = String::from(
			r#"<section class="card" id="advisory"><div class="card-head"><div><div class="card-title-row"><h2>Advisory</h2><span class="pill pill-warn">Attention</span></div></div></div><div class="card-body"><ul class="advisory">"#,
		);
		for item in advisory(&regs) {
			html.push_str(&format!("<li>{}</li>", escape(&item)));
		}
		html.push_str("</ul></div></section>");
		html
	};

	load_dashboard_template()
		.replace("{tld}", &escape(&ctx.tld))
		.replace("{domains}", &render_domains(claims, granted))
		.replace("{domain_count}", &regs.len().to_string())
		.replace("{shares}", &render_shares(shares))
		.replace("{share_count}", &shares.len().to_string())
		.replace("{advisory}", &advisory_html)
		.replace("{version}", env!("CARGO_PKG_VERSION"))
}

pub struct PeekedStream {
	first: Option<u8>,
	inner: TcpStream,
}

impl PeekedStream {
	pub fn new(first: u8, inner: TcpStream) -> Self {
		Self { first: Some(first), inner }
	}
}

impl AsyncRead for PeekedStream {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		// Yield the peeked byte first, then delegate to the inner stream.
		if let Some(byte) = this.first.take() {
			buf.put_slice(&[byte]);
			return Poll::Ready(Ok(()));
		}
		Pin::new(&mut this.inner).poll_read(cx, buf)
	}
}

impl AsyncWrite for PeekedStream {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}
}

async fn read_body<R>(reader: &mut BufReader<R>, headers: &[(String, String)]) -> io::Result<Vec<u8>>
where
	R: AsyncRead + Unpin,
{
	let len = header_value(headers, "content-length")
		.and_then(|value| value.parse::<usize>().ok())
		.unwrap_or(0);
	if len == 0 {
		return Ok(Vec::new());
	}
	if len > MAX_BODY {
		return Err(io::Error::new(io::ErrorKind::InvalidData, "request body too large"));
	}
	let mut body = vec![0u8; len];
	reader.read_exact(&mut body).await?;
	Ok(body)
}

async fn respond<W: AsyncWriteExt + Unpin>(
	writer: &mut W,
	status: &str,
	content_type: &str,
	body: &[u8],
) -> io::Result<()> {
	respond_with(writer, status, content_type, body, &[]).await
}

async fn respond_with<W: AsyncWriteExt + Unpin>(
	writer: &mut W,
	status: &str,
	content_type: &str,
	body: &[u8],
	extra: &[(&str, String)],
) -> io::Result<()> {
	let mut header = format!(
		"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\
		 X-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\n\
		 Content-Security-Policy: frame-ancestors 'none'\r\n",
		body.len()
	);
	for (name, value) in extra {
		header.push_str(&format!("{name}: {value}\r\n"));
	}
	header.push_str("\r\n");
	tokio::time::timeout(RESPONSE_TIMEOUT, async {
		writer.write_all(header.as_bytes()).await?;
		writer.write_all(body).await?;
		writer.flush().await
	})
	.await
	.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP response write timed out"))?
}

fn advisory(regs: &[Registration]) -> Vec<String> {
	let mut advice = Vec::new();
	if regs.len() > 20 {
		advice.push(format!("{} names on one host. A second host spreads the load.", regs.len()));
	}
	advice
}

fn load_dashboard_template() -> String {
	#[cfg(debug_assertions)]
	{
		std::fs::read_to_string(DASHBOARD_TEMPLATE_PATH)
			.unwrap_or_else(|e| format!("failed to load dashboard.html: {e}"))
	}
	#[cfg(not(debug_assertions))]
	{
		include_str!("../dashboard.html").to_owned()
	}
}

const TRASH_ICON: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>"#;
/// A block: stop the leaf, keep its grant.
const STOP_ICON: &str = r#"<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="1.5" fill="currentColor"/></svg>"#;

fn render_shares(shares: &[crate::share::ShareView]) -> String {
	if shares.is_empty() {
		return r#"<p class="empty"><strong>No shares</strong><span>Start one with <code>testd share &lt;name&gt;</code>.</span></p>"#
			.to_owned();
	}
	let mut rows = String::from(r#"<ul class="rows">"#);
	for share in shares {
		rows.push_str(&format!(
			r#"<li class="row"><div class="row-main"><a class="row-title" href="{url}" target="_blank" rel="noreferrer">{url}</a><span class="row-meta">{name} · {exposure} <span class="tag">{provider}</span></span></div><button class="btn btn-sm btn-danger" type="button" onclick="unshare('{name}', this)">Stop</button></li>"#,
			url = escape(&share.url),
			name = escape(&share.name),
			exposure = escape(share.exposure.label()),
			provider = escape(&share.provider),
		));
	}
	rows.push_str("</ul>");
	rows
}

fn render_domains(claims: &[Claim], granted: &HashSet<String>) -> String {
	if claims.is_empty() {
		return r#"<p class="empty"><strong>No active domains</strong><span>Names appear here while a dev environment is connected.</span></p>"#
			.to_owned();
	}

	let regs: Vec<Registration> = claims.iter().map(|claim| claim.registration.clone()).collect();
	let groups = testd_core::naming::group_by_project(&regs);
	let show_headings = groups.len() > 1;
	let mut html = String::new();
	for (project, items) in &groups {
		if show_headings {
			let label = (*project).map_or_else(|| "single-label".to_owned(), escape);
			html.push_str(&format!(
				r#"<h3 class="group">{label}<span class="count">{count}</span></h3>"#,
				count = items.len()
			));
		}
		html.push_str(r#"<ul class="rows">"#);
		for reg in items {
			let domain = escape(&reg.domain);
			// Only leaves with an issued token have a grant to delete.
			let delete = if granted.contains(&reg.domain) {
				format!(
					r#"<button class="icon-btn" type="button" aria-label="Delete the grant for {domain}" title="Delete this leaf's grant (it must request access again)" onclick="deleteGrant('{domain}', this)">{TRASH_ICON}</button>"#
				)
			} else {
				String::new()
			};
			html.push_str(&format!(
				r#"<li class="row"><div class="row-main"><a class="row-title" href="https://{domain}" target="_blank" rel="noreferrer">{domain}</a><span class="row-meta">{target}</span></div><div class="row-actions"><button class="icon-btn icon-btn-stop" type="button" aria-label="Stop the leaf that publishes {domain}" title="Stop this leaf (keeps its grant)" onclick="stopName('{domain}', this)">{stop}</button>{delete}</div></li>"#,
				target = escape(&reg.target),
				stop = STOP_ICON,
			));
		}
		html.push_str("</ul>");
	}
	html
}

fn escape(value: &str) -> String {
	value
		.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&#39;")
}

async fn handle_unshare<W: AsyncWriteExt + Unpin>(writer: &mut W, ctx: &HttpContext, name: &str) -> io::Result<()> {
	if name.is_empty() {
		return respond(writer, "400 Bad Request", "text/plain", b"Missing share name.").await;
	}
	let Some(shares) = &ctx.shares else {
		return respond(writer, "503 Service Unavailable", "text/plain", b"Sharing is not available.").await;
	};
	if shares.stop(name).await {
		respond(writer, "200 OK", "text/plain", b"ok").await
	} else {
		respond(writer, "404 Not Found", "text/plain", b"No such share.").await
	}
}

async fn handle_stop<W: AsyncWriteExt + Unpin>(writer: &mut W, ctx: &HttpContext, domain: &str) -> io::Result<()> {
	if domain.is_empty() {
		return respond(writer, "400 Bad Request", "text/plain", b"Missing domain.").await;
	}
	operator(writer, ctx, OperatorAction::Stop { domain: domain.to_owned() }).await
}

async fn handle_delete_grant<W: AsyncWriteExt + Unpin>(
	writer: &mut W,
	ctx: &HttpContext,
	domain: &str,
) -> io::Result<()> {
	if domain.is_empty() {
		return respond(writer, "400 Bad Request", "text/plain", b"Missing domain.").await;
	}
	operator(writer, ctx, OperatorAction::DeleteGrant { domain: domain.to_owned() }).await
}

/// Run one dashboard action in the engine loop and report its outcome.
async fn operator<W: AsyncWriteExt + Unpin>(
	writer: &mut W,
	ctx: &HttpContext,
	action: OperatorAction,
) -> io::Result<()> {
	let (answer, response) = tokio::sync::oneshot::channel();
	if ctx.operator_tx.send(OperatorRequest { action, respond: answer }).await.is_err() {
		return respond(writer, "500 Internal Server Error", "text/plain", b"Engine unavailable.").await;
	}
	match response.await {
		Ok(Ok(())) => respond(writer, "200 OK", "text/plain", b"ok").await,
		Ok(Err(e)) => respond(writer, "400 Bad Request", "text/plain", e.as_bytes()).await,
		Err(_) => respond(writer, "500 Internal Server Error", "text/plain", b"Engine unavailable.").await,
	}
}

#[derive(serde::Deserialize)]
struct IdRequest {
	id: String,
}

#[derive(serde::Deserialize)]
struct RebindRequest {
	id: String,
	domain: String,
	target: String,
}

fn launch_book(ctx: &HttpContext) -> Result<&Arc<LaunchBook>, String> {
	ctx.launches
		.as_ref()
		.ok_or_else(|| "quick launches are not available".to_owned())
}

async fn handle_launches<W>(writer: &mut W, ctx: &HttpContext) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	match launch_book(ctx) {
		Ok(book) => respond_json(writer, "200 OK", &book.list()).await,
		Err(e) => respond_json(writer, "503 Service Unavailable", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_launch_save<W>(writer: &mut W, ctx: &HttpContext, body: &[u8]) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let result = (|| {
		let book = launch_book(ctx)?;
		let definition: crate::launch::LaunchDefinition =
			serde_json::from_slice(body).map_err(|e| format!("invalid request: {e}"))?;
		book.upsert(definition)
	})();
	match result {
		Ok(value) => respond_json(writer, "200 OK", &value).await,
		Err(e) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_launch_delete<W>(writer: &mut W, ctx: &HttpContext, body: &[u8]) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let result = (|| {
		let book = launch_book(ctx)?;
		let request: IdRequest = serde_json::from_slice(body).map_err(|e| format!("invalid request: {e}"))?;
		book.delete(&request.id)
	})();
	match result {
		Ok(()) => respond_json(writer, "200 OK", &serde_json::json!({ "ok": true })).await,
		Err(e) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_launch_start<W>(writer: &mut W, ctx: &HttpContext, body: &[u8]) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let result = (|| {
		let book = launch_book(ctx)?;
		let request: IdRequest = serde_json::from_slice(body).map_err(|e| format!("invalid request: {e}"))?;
		book.start(&request.id)
	})();
	match result {
		Ok(()) => respond_json(writer, "200 OK", &serde_json::json!({ "ok": true })).await,
		Err(e) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_launch_stop<W>(writer: &mut W, ctx: &HttpContext, body: &[u8]) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let result = (|| {
		let book = launch_book(ctx)?;
		let request: IdRequest = serde_json::from_slice(body).map_err(|e| format!("invalid request: {e}"))?;
		book.stop(&request.id)
	})();
	match result {
		Ok(()) => respond_json(writer, "200 OK", &serde_json::json!({ "ok": true })).await,
		Err(e) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_launch_rebind<W>(writer: &mut W, ctx: &HttpContext, body: &[u8]) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let result = async {
		let book = launch_book(ctx)?;
		let request: RebindRequest = serde_json::from_slice(body).map_err(|e| format!("invalid request: {e}"))?;
		book.rebind(&request.id, request.domain, request.target).await
	}
	.await;
	match result {
		Ok(()) => respond_json(writer, "200 OK", &serde_json::json!({ "ok": true })).await,
		Err(e) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_request_decision<W>(writer: &mut W, ctx: &HttpContext, body: &[u8], approve: bool) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let request: IdRequest = match serde_json::from_slice(body) {
		Ok(request) => request,
		Err(e) => {
			return respond_json(
				writer,
				"400 Bad Request",
				&serde_json::json!({ "error": format!("invalid request: {e}") }),
			)
			.await;
		},
	};
	let result = if approve { ctx.access.approve(&request.id).map(|_| ()) } else { ctx.access.deny(&request.id) };
	match result {
		Ok(()) => respond_json(writer, "200 OK", &serde_json::json!({ "ok": true })).await,
		Err(e) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_token_revoke<W>(writer: &mut W, ctx: &HttpContext, body: &[u8]) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let request: IdRequest = match serde_json::from_slice(body) {
		Ok(request) => request,
		Err(e) => {
			return respond_json(
				writer,
				"400 Bad Request",
				&serde_json::json!({ "error": format!("invalid request: {e}") }),
			)
			.await;
		},
	};
	match ctx.access.revoke(&request.id) {
		Ok(()) => respond_json(writer, "200 OK", &serde_json::json!({ "ok": true })).await,
		Err(e) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_certificate_status<W>(writer: &mut W, ctx: &HttpContext) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	match crate::certificate::status(&ctx.pki_dir) {
		Ok(status) => respond_json(writer, "200 OK", &status).await,
		Err(e) => respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e })).await,
	}
}

async fn handle_certificate_install<W>(writer: &mut W, ctx: &HttpContext) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let pki_dir = ctx.pki_dir.clone();
	let result = tokio::task::spawn_blocking(move || crate::certificate::install(&pki_dir)).await;
	match result {
		Ok(Ok(status)) => {
			if let Some(refresh) = &ctx.health_refresh {
				refresh();
			}
			respond_json(writer, "200 OK", &status).await
		},
		Ok(Err(e)) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
		Err(e) => {
			respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e.to_string() })).await
		},
	}
}

async fn handle_certificate_remove<W>(writer: &mut W, ctx: &HttpContext) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let pki_dir = ctx.pki_dir.clone();
	let result = tokio::task::spawn_blocking(move || crate::certificate::remove(&pki_dir)).await;
	match result {
		Ok(Ok(status)) => {
			if let Some(refresh) = &ctx.health_refresh {
				refresh();
			}
			respond_json(writer, "200 OK", &status).await
		},
		Ok(Err(e)) => respond_json(writer, "400 Bad Request", &serde_json::json!({ "error": e })).await,
		Err(e) => {
			respond_json(writer, "500 Internal Server Error", &serde_json::json!({ "error": e.to_string() })).await
		},
	}
}

async fn respond_json<W>(writer: &mut W, status: &str, value: &impl serde::Serialize) -> io::Result<()>
where
	W: AsyncWriteExt + Unpin,
{
	let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"serialization failed\"}".to_vec());
	respond(writer, status, "application/json", &body).await
}

async fn serve_ca_cert<W: AsyncWriteExt + Unpin>(writer: &mut W, pki_dir: &Path) -> io::Result<()> {
	let cert_path = pki_dir.join("root.crt");
	match std::fs::read(&cert_path) {
		Ok(cert) => respond(writer, "200 OK", "application/x-x509-ca-cert", &cert).await,
		Err(_) => {
			let msg = format!("CA certificate not found at {}", cert_path.display());
			respond(writer, "404 Not Found", "text/plain", msg.as_bytes()).await
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn a_dashboard_client_that_stops_reading_cannot_hold_a_writer_forever() {
		let (mut writer, _unread_peer) = tokio::io::duplex(1);
		let result = tokio::time::timeout(
			RESPONSE_TIMEOUT + std::time::Duration::from_secs(1),
			respond(&mut writer, "200 OK", "text/plain", b"fixture"),
		)
		.await
		.expect("dashboard writes have a deadline");
		assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
	}
}
