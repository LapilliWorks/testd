//! Public and tailnet sharing: one tunnel per registered name, owned by the daemon.
//!
//! The tunnel has to outlive the terminal that asked for it, so the daemon
//! starts and stops the provider. The lifetime is the name's: when the
//! registration goes, the tunnel goes with it.
//!
//! Providers are spawned, never linked and never called through an SDK. They
//! differ in what they expose (public internet or tailnet), what target they
//! accept, and how their public URL becomes known, so each one owns those three
//! answers:
//!
//! | Provider | Exposure | Target | URL |
//! |---|---|---|---|
//! | `cloudflared` | public | any reachable target | printed by the provider |
//! | `ngrok` | public | any reachable target | printed by the provider |
//! | `tailscale` | tailnet | loopback only | `tailscale status --json` |

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc};

use crate::engine::Registrations;

/// Provider used when the caller does not choose one.
pub const DEFAULT_PROVIDER: &str = "cloudflared";
/// How long a provider may take to report its public URL.
const URL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the startup sweep waits for `tailscale serve status`.
const SWEEP_TIMEOUT: Duration = Duration::from_secs(5);

/// Where a share is reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
	/// Anyone with the URL, like `cloudflared` and `ngrok`.
	Public,
	/// Devices on the tailnet only, like `tailscale serve`.
	Tailnet,
}

impl Exposure {
	pub fn label(self) -> &'static str {
		match self {
			Exposure::Public => "public",
			Exposure::Tailnet => "tailnet",
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
	Cloudflared,
	Tailscale,
	Ngrok,
}

impl Provider {
	pub fn parse(value: &str) -> Option<Self> {
		match value.trim().to_ascii_lowercase().as_str() {
			"cloudflared" | "cloudflare" => Some(Provider::Cloudflared),
			"tailscale" | "ts" => Some(Provider::Tailscale),
			"ngrok" => Some(Provider::Ngrok),
			_ => None,
		}
	}

	pub fn name(self) -> &'static str {
		match self {
			Provider::Cloudflared => "cloudflared",
			Provider::Tailscale => "tailscale",
			Provider::Ngrok => "ngrok",
		}
	}

	pub fn exposure(self) -> Exposure {
		match self {
			Provider::Cloudflared | Provider::Ngrok => Exposure::Public,
			Provider::Tailscale => Exposure::Tailnet,
		}
	}

	/// Binary invoked for this provider.
	pub fn binary(self) -> &'static str {
		self.name()
	}

	/// Whether the provider must be pointed at the local edge instead of at the
	/// registration target.
	pub fn needs_front(self) -> bool {
		matches!(self, Provider::Tailscale)
	}

	/// Arguments that start the share, given the address it proxies to.
	fn start_args(self, upstream: &str) -> Vec<String> {
		match self {
			Provider::Cloudflared => {
				vec!["tunnel".into(), "--no-autoupdate".into(), "--url".into(), format!("http://{upstream}")]
			},
			// `ngrok http` takes a host:port, not a URL.
			Provider::Ngrok => vec!["http".into(), upstream.to_owned()],
			// `serve` writes config and returns; there is no long-running child.
			Provider::Tailscale => vec!["serve".into(), "--bg".into(), format!("http://{upstream}")],
		}
	}

	/// Arguments that remove the share again. `None` means killing the child.
	fn stop_args(self) -> Option<Vec<String>> {
		match self {
			Provider::Cloudflared | Provider::Ngrok => None,
			// Scoped to this serve port, so other serve entries are left alone.
			Provider::Tailscale => Some(vec!["serve".into(), "--https=443".into(), "off".into()]),
		}
	}

	/// The public URL in a provider log line.
	fn url_from_line(self, line: &str) -> Option<String> {
		// Stop at whitespace, a quote, a pipe, or the first path segment; providers
		// print URLs inside tables, banners, and JSON log records.
		let rest = &line[line.find("https://")? + "https://".len()..];
		let host = rest
			.split(|c: char| c.is_whitespace() || c == '|' || c == '/' || c == '"' || c == '\\')
			.next()?;
		let known = match self {
			Provider::Cloudflared => host.ends_with(".trycloudflare.com") && host != "api.trycloudflare.com",
			Provider::Ngrok => {
				host.ends_with(".ngrok-free.app")
					|| host.ends_with(".ngrok-free.dev")
					|| host.ends_with(".ngrok.io")
					|| host.ends_with(".ngrok.app")
			},
			Provider::Tailscale => host.ends_with(".ts.net"),
		};
		known.then(|| format!("https://{host}"))
	}
}

/// One active share, as the CLI and the tray see it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareView {
	pub name: String,
	pub provider: String,
	pub exposure: Exposure,
	pub target: String,
	pub url: String,
}

/// The local edge a provider can point at instead of the raw target.
///
/// Pointing a provider here keeps the request shape browsers get: the edge
/// answers the share's name and proxies to the registration target, so a
/// container or LAN target works and the app sees its registered name.
#[derive(Clone)]
pub struct Front {
	/// The edge's names, so the share's name can be answered locally.
	pub registry: Registrations,
	/// Plain HTTP listener of the edge.
	pub plain_addr: SocketAddr,
}

/// The daemon's set of tunnels.
pub struct Shares {
	default: Provider,
	/// Overrides the binary for the selected provider; tests and odd installs.
	binary: Option<PathBuf>,
	/// The local edge, for providers that cannot reach the target themselves.
	front: Option<Front>,
	active: Mutex<BTreeMap<String, Active>>,
	/// Serializes the startup sweep against a tailscale share starting.
	reclaim: Mutex<()>,
}

struct Active {
	provider: Provider,
	target: String,
	url: String,
	/// Present for providers that stay running.
	child: Option<Child>,
	/// Cleanup command for providers that configure and return.
	stop_args: Option<Vec<String>>,
	/// Name the edge answers on the provider's behalf.
	alias: Option<String>,
}

impl Shares {
	/// Default provider from `TESTD_TUNNEL_PROVIDER`, binary from `TESTD_TUNNEL`.
	pub fn from_env(front: Option<Front>) -> Self {
		let default = std::env::var("TESTD_TUNNEL_PROVIDER")
			.ok()
			.and_then(|value| Provider::parse(&value))
			.unwrap_or(Provider::Cloudflared);
		let binary = std::env::var_os("TESTD_TUNNEL")
			.filter(|value| !value.is_empty())
			.map(PathBuf::from);
		Self { default, binary, front, active: Mutex::new(BTreeMap::new()), reclaim: Mutex::new(()) }
	}

	pub fn new(default: Provider, binary: Option<PathBuf>, front: Option<Front>) -> Self {
		Self { default, binary, front, active: Mutex::new(BTreeMap::new()), reclaim: Mutex::new(()) }
	}

	/// Start a share for `name` at `target`. Returns the public URL.
	pub async fn start(&self, name: &str, target: &str, provider: Option<Provider>) -> Result<String> {
		let provider = provider.unwrap_or(self.default);
		if provider.needs_front() && self.front.is_none() {
			bail!(
				"{} needs the plain HTTP routing listener, and this daemon has none; \
				 share with cloudflared or ngrok instead",
				provider.name()
			);
		}

		{
			let active = self.active.lock().await;
			if let Some(existing) = active.get(name) {
				bail!("{name} is already shared at {} ({})", existing.url, existing.provider.name());
			}
		}

		// Spawn outside the lock: a slow provider must not block `list` or `stop`.
		let binary = self.binary_for(provider);
		let share = self.spawn(provider, &binary, name, target).await?;

		let mut active = self.active.lock().await;
		if let Some(existing) = active.get(name) {
			let url = existing.url.clone();
			drop(active);
			self.release(share).await;
			bail!("{name} is already shared at {url}");
		}
		let url = share.url.clone();
		active.insert(name.to_owned(), share);
		Ok(url)
	}

	/// Stop sharing `name`. Returns whether it was shared.
	pub async fn stop(&self, name: &str) -> bool {
		let removed = self.active.lock().await.remove(name);
		match removed {
			Some(share) => {
				self.release(share).await;
				true
			},
			None => false,
		}
	}

	pub async fn list(&self) -> Vec<ShareView> {
		self.active
			.lock()
			.await
			.iter()
			.map(|(name, share)| ShareView {
				name: name.clone(),
				provider: share.provider.name().to_owned(),
				exposure: share.provider.exposure(),
				target: share.target.clone(),
				url: share.url.clone(),
			})
			.collect()
	}

	/// Stop every share whose name is no longer in `names`.
	pub async fn retain(&self, names: &[String]) {
		let stale: Vec<String> = {
			let active = self.active.lock().await;
			active.keys().filter(|name| !names.contains(name)).cloned().collect()
		};
		for name in stale {
			if self.stop(&name).await {
				eprintln!("[share]  {name} is no longer registered; the share is closed");
			}
		}
	}

	/// Clear `serve` entries a previous run left behind.
	///
	/// `serve --bg` writes config that outlives this process, while the alias that
	/// made the name answer does not; the leftover would answer with a 404 until
	/// someone shares again. Only an entry whose root handler proxies to this
	/// host's edge is ours, so every other serve entry is left alone.
	pub async fn reclaim(&self) {
		let Some(front) = &self.front else { return };
		let _sweep = self.reclaim.lock().await;
		// A live share owns its serve entry; the sweep must not mistake it for a
		// leftover. The lock makes a start either finish before this check or wait
		// for the sweep, so the two cannot interleave.
		if !self.active.lock().await.is_empty() {
			return;
		}

		let binary = self.binary_for(Provider::Tailscale);
		let upstream = format!("http://{}", front.plain_addr);
		let args = vec!["serve".to_owned(), "status".to_owned(), "--json".to_owned()];
		let Ok(Some(output)) = run_briefly(&binary, &args, SWEEP_TIMEOUT).await else { return };
		if !output.status.success() {
			return;
		}
		for port in leftover_serves(&String::from_utf8_lossy(&output.stdout), &upstream) {
			let args = vec!["serve".to_owned(), format!("--https={port}"), "off".to_owned()];
			match run_briefly(&binary, &args, SWEEP_TIMEOUT).await {
				Ok(Some(output)) if output.status.success() => {
					eprintln!("[share]  cleared a leftover tailscale serve on :{port} pointing at {upstream}");
				},
				Ok(Some(output)) => eprintln!(
					"[warn]   could not clear the leftover tailscale serve on :{port} ({}); run `{} serve reset`",
					output.status,
					binary.display()
				),
				Ok(None) => eprintln!("[warn]   the leftover tailscale serve on :{port} took too long to clear"),
				Err(e) => eprintln!("[warn]   could not clear the leftover tailscale serve on :{port}: {e}"),
			}
		}
	}

	/// Stop everything, for an orderly shutdown.
	pub async fn shutdown(&self) {
		let names: Vec<String> = self.active.lock().await.keys().cloned().collect();
		for name in names {
			self.stop(&name).await;
		}
	}

	fn binary_for(&self, provider: Provider) -> PathBuf {
		self.binary.clone().unwrap_or_else(|| PathBuf::from(provider.binary()))
	}

	async fn spawn(&self, provider: Provider, binary: &Path, name: &str, target: &str) -> Result<Active> {
		if provider.needs_front() {
			return self.spawn_through_front(binary, name, target).await;
		}

		let args = provider.start_args(target);
		let mut child = spawn_with_retry(binary, &args, true)
			.await
			.with_context(|| format!("start {} (install it, or set TESTD_TUNNEL to its path)", binary.display()))?;
		let url = self.read_url(&mut child, provider, binary).await?;
		Ok(Active { provider, target: target.to_owned(), url, child: Some(child), stop_args: None, alias: None })
	}

	/// Point a provider at the local edge and teach the edge the name it serves.
	///
	/// Requests then look exactly like browser requests: the edge answers the
	/// share's name and proxies to the registration target, so a container or LAN
	/// target works and the app sees the name it was registered under.
	async fn spawn_through_front(&self, binary: &Path, name: &str, target: &str) -> Result<Active> {
		// A sweep that runs while serve config is being written would turn it off.
		let _sweep = self.reclaim.lock().await;
		let front = self
			.front
			.as_ref()
			.context("the built-in edge is not running, so the provider has no local front")?
			.clone();
		let host = self.tailscale_host(binary).await?;
		let upstream = format!("http://{}", front.plain_addr);
		let status =
			match run_briefly(binary, &["serve".to_owned(), "status".to_owned(), "--json".to_owned()], SWEEP_TIMEOUT)
				.await
			{
				Ok(Some(output)) if output.status.success() => String::from_utf8_lossy(&output.stdout).into_owned(),
				Ok(Some(output)) => bail!("tailscale serve status failed with {}", output.status),
				Ok(None) => bail!("tailscale serve status timed out"),
				Err(e) => bail!("could not inspect tailscale serve: {e}"),
			};
		if !can_take_over_443(&status, &upstream) {
			bail!("tailscale serve already has configuration on :443; refusing to overwrite it");
		}

		front.registry.lock().await.set_alias(&host, target);
		let args = Provider::Tailscale.start_args(&front.plain_addr.to_string());
		let started = run_with_retry(binary, &args).await;
		let failed = match started {
			Ok(output) if output.status.success() => false,
			Ok(output) => {
				eprintln!("[warn]   {} {} exited with {}", binary.display(), args.join(" "), output.status);
				true
			},
			Err(e) => {
				eprintln!("[warn]   could not start {}: {e}", binary.display());
				true
			},
		};
		if failed {
			front.registry.lock().await.remove_alias(&host);
			bail!("tailscale serve did not start for {name}");
		}

		Ok(Active {
			provider: Provider::Tailscale,
			target: target.to_owned(),
			url: format!("https://{host}"),
			child: None,
			stop_args: Provider::Tailscale.stop_args(),
			alias: Some(host),
		})
	}

	/// First URL a provider prints, from either stream.
	///
	/// The readers keep draining after the URL, because a provider that blocks on
	/// a full pipe would stop serving.
	async fn read_url(&self, child: &mut Child, provider: Provider, binary: &Path) -> Result<String> {
		let (tx, mut rx) = mpsc::channel::<String>(4);

		let drain = |stream: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>>| {
			let Some(stream) = stream else { return };
			let tx = tx.clone();
			tokio::spawn(async move {
				let mut lines = BufReader::new(stream).lines();
				let mut sent = false;
				while let Ok(Some(line)) = lines.next_line().await {
					if !sent && let Some(url) = provider.url_from_line(&line) {
						sent = true;
						let _ = tx.send(url).await;
					}
				}
			});
		};
		drain(
			child
				.stdout
				.take()
				.map(|out| Box::new(out) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
		);
		drain(
			child
				.stderr
				.take()
				.map(|err| Box::new(err) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
		);
		drop(tx);

		match tokio::time::timeout(URL_TIMEOUT, rx.recv()).await {
			Ok(Some(url)) => Ok(url),
			Ok(None) => bail!("{} exited before printing a URL", binary.display()),
			Err(_) => bail!("{} printed no URL in {}s", binary.display(), URL_TIMEOUT.as_secs()),
		}
	}

	/// This node's stable tailnet name, from `tailscale status --json`.
	async fn tailscale_host(&self, binary: &Path) -> Result<String> {
		let args = vec!["status".to_owned(), "--json".to_owned()];
		let output = run_with_retry(binary, &args)
			.await
			.with_context(|| format!("run {} status --json", binary.display()))?;
		if !output.status.success() {
			bail!("{} status --json failed with {}", binary.display(), output.status);
		}
		status_host(&String::from_utf8_lossy(&output.stdout))
			.ok_or_else(|| anyhow!("no tailnet DNS name in {} status --json", binary.display()))
	}

	/// Kill a child, or run the provider's cleanup command.
	async fn release(&self, share: Active) {
		if let Some(alias) = &share.alias
			&& let Some(front) = &self.front
		{
			front.registry.lock().await.remove_alias(alias);
		}

		if let Some(mut child) = share.child {
			let _ = child.kill().await;
			return;
		}
		if share.stop_args.is_none() {
			return;
		}
		let binary = self.binary_for(share.provider);
		if share.provider == Provider::Tailscale {
			let Some(front) = &self.front else { return };
			let upstream = format!("http://{}", front.plain_addr);
			let status = match run_briefly(
				&binary,
				&["serve".to_owned(), "status".to_owned(), "--json".to_owned()],
				SWEEP_TIMEOUT,
			)
			.await
			{
				Ok(Some(output)) if output.status.success() => String::from_utf8_lossy(&output.stdout).into_owned(),
				_ => {
					eprintln!("[warn]   could not inspect tailscale serve; leaving :443 alone");
					return;
				},
			};
			if !leftover_serves(&status, &upstream).contains(&443) {
				eprintln!("[warn]   tailscale serve :443 has other handlers; leaving it in place");
				return;
			}
		}
		let args = share.stop_args.unwrap_or_default();
		let result = run_with_retry(&binary, &args).await;
		match result {
			Ok(output) if output.status.success() => {},
			Ok(output) => eprintln!(
				"[warn]   {} {} exited with {}; run `{} serve reset` if the share is still up",
				binary.display(),
				args.join(" "),
				output.status,
				binary.display()
			),
			Err(e) => eprintln!("[warn]   could not stop the {} share: {e}", share.provider.name()),
		}
	}
}

/// This node's tailnet name, from `tailscale status --json`.
pub fn status_host(status: &str) -> Option<String> {
	let value: serde_json::Value = serde_json::from_str(status).ok()?;
	let name = value.get("Self")?.get("DNSName")?.as_str()?.trim_end_matches('.');
	if name.is_empty() { None } else { Some(name.to_owned()) }
}

/// Serve ports whose entire handler set is our root handler. A port with any
/// additional handler is not ours to turn off.
fn leftover_serves(status: &str, upstream: &str) -> Vec<u16> {
	let Ok(value) = serde_json::from_str::<serde_json::Value>(status) else { return Vec::new() };
	let Some(web) = value.get("Web").and_then(|web| web.as_object()) else { return Vec::new() };
	let mut ports: Vec<u16> = Vec::new();
	for (host_port, entry) in web {
		let Some(handlers) = entry.get("Handlers").and_then(|handlers| handlers.as_object()) else {
			continue;
		};
		if handlers.len() != 1 {
			continue;
		}
		let proxy = handlers
			.get("/")
			.and_then(|handler| handler.get("Proxy"))
			.and_then(|proxy| proxy.as_str());
		if proxy != Some(upstream) {
			continue;
		}
		if let Some(port) = host_port.rsplit(':').next().and_then(|port| port.parse::<u16>().ok())
			&& !ports.contains(&port)
		{
			ports.push(port);
		}
	}
	ports.sort_unstable();
	ports
}

/// Whether starting a root handler on :443 would leave someone else's handlers
/// in place to be removed by the next `serve --https=443 off`.
fn can_take_over_443(status: &str, upstream: &str) -> bool {
	let Ok(value) = serde_json::from_str::<serde_json::Value>(status) else { return false };
	let Some(web) = value.get("Web").and_then(|web| web.as_object()) else { return true };
	web.iter()
		.filter(|(host_port, _)| host_port.ends_with(":443"))
		.all(|(_, entry)| {
			let Some(handlers) = entry.get("Handlers").and_then(|handlers| handlers.as_object()) else {
				return false;
			};
			handlers.len() == 1
				&& handlers
					.get("/")
					.and_then(|handler| handler.get("Proxy"))
					.and_then(|proxy| proxy.as_str())
					== Some(upstream)
		})
}

/// How often a spawn is retried when the kernel reports the binary as busy.
const BUSY_RETRIES: usize = 5;
/// `ETXTBSY`: the file is open for writing elsewhere, usually a binary that was
/// just installed. It clears within milliseconds.
const ETXTBSY: i32 = 26;

/// Start a provider, retrying while the kernel reports the binary as busy.
async fn spawn_with_retry(binary: &Path, args: &[String], piped: bool) -> Result<Child> {
	let mut attempts = 0;
	loop {
		let mut command = Command::new(binary);
		command.args(args);
		if piped {
			command.stdout(Stdio::piped()).stderr(Stdio::piped());
		}
		command.kill_on_drop(true);
		match command.spawn() {
			Ok(child) => return Ok(child),
			Err(e) if e.raw_os_error() == Some(ETXTBSY) && attempts < BUSY_RETRIES => {
				attempts += 1;
				tokio::time::sleep(Duration::from_millis(20)).await;
			},
			Err(e) => return Err(e.into()),
		}
	}
}

/// Run a provider command with a deadline. `None` means it was still running when
/// the deadline passed; dropping the child kills it.
async fn run_briefly(binary: &Path, args: &[String], limit: Duration) -> Result<Option<std::process::Output>> {
	let child = spawn_with_retry(binary, args, true).await?;
	match tokio::time::timeout(limit, child.wait_with_output()).await {
		Ok(result) => Ok(Some(result?)),
		Err(_) => Ok(None),
	}
}

/// Run a provider command to completion, with the same busy retry.
async fn run_with_retry(binary: &Path, args: &[String]) -> Result<std::process::Output> {
	let mut attempts = 0;
	loop {
		match Command::new(binary).args(args).output().await {
			Ok(output) => return Ok(output),
			Err(e) if e.raw_os_error() == Some(ETXTBSY) && attempts < BUSY_RETRIES => {
				attempts += 1;
				tokio::time::sleep(Duration::from_millis(20)).await;
			},
			Err(e) => return Err(e.into()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reads_the_cloudflared_tunnel_url() {
		let line = "2026-10-30T10:00:00Z INF |  https://brave-otter-harbor.trycloudflare.com  |";
		assert_eq!(
			Provider::Cloudflared.url_from_line(line).as_deref(),
			Some("https://brave-otter-harbor.trycloudflare.com")
		);
		assert!(
			Provider::Cloudflared
				.url_from_line("INF https://api.trycloudflare.com docs")
				.is_none()
		);
		assert!(Provider::Cloudflared.url_from_line("INF connecting...").is_none());
	}

	#[test]
	fn reads_the_ngrok_tunnel_url_from_a_log_record() {
		let line = r#"t=2026-10-30T10:00:00+0000 lvl=info msg="started tunnel" obj=tunnels name=command_line addr=127.0.0.1:3000 url=https://1a2b-3c4d.ngrok-free.app"#;
		assert_eq!(Provider::Ngrok.url_from_line(line).as_deref(), Some("https://1a2b-3c4d.ngrok-free.app"));
		assert!(Provider::Ngrok.url_from_line("https://example.com").is_none());
	}

	#[test]
	fn reads_the_tailnet_name() {
		let status = r#"{"Self":{"DNSName":"node-a.tailnet.ts.net.","HostName":"node-a"}}"#;
		assert_eq!(status_host(status).as_deref(), Some("node-a.tailnet.ts.net"));
		assert!(status_host(r#"{"Self":{}}"#).is_none());
		assert!(status_host("not json").is_none());
	}

	#[test]
	fn finds_only_the_serve_entries_that_point_at_this_edge() {
		let status = r#"{"Web":{
			"node-a.tailnet.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"}}},
			"node-a.tailnet.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"}}},
			"node-a.tailnet.ts.net:10000":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"}}}
		}}"#;
		assert_eq!(leftover_serves(status, "http://127.0.0.1:7740"), vec![443, 10000]);
		assert!(leftover_serves(status, "http://127.0.0.1:7741").is_empty());
		assert!(leftover_serves("", "http://127.0.0.1:7740").is_empty());
		assert!(leftover_serves(r#"{"Web":{}}"#, "http://127.0.0.1:7740").is_empty());
	}

	#[test]
	fn a_foreign_handler_on_443_blocks_the_share() {
		let upstream = "http://127.0.0.1:7740";
		let ours = r#"{"Web":{"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"}}}}}"#;
		let foreign = r#"{"Web":{"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"},"/api":{"Proxy":"http://127.0.0.1:9000"}}}}}"#;
		assert!(can_take_over_443(ours, upstream));
		assert!(!can_take_over_443(foreign, upstream));
		assert!(can_take_over_443(r#"{"Web":{}}"#, upstream));
		assert_eq!(leftover_serves(foreign, upstream), Vec::<u16>::new());
	}

	#[test]
	fn only_tailscale_needs_the_local_front() {
		assert!(Provider::Tailscale.needs_front());
		assert!(!Provider::Cloudflared.needs_front());
		assert!(!Provider::Ngrok.needs_front());
	}

	#[test]
	fn providers_expose_where_they_reach() {
		assert_eq!(Provider::Cloudflared.exposure(), Exposure::Public);
		assert_eq!(Provider::Ngrok.exposure(), Exposure::Public);
		assert_eq!(Provider::Tailscale.exposure(), Exposure::Tailnet);
		assert_eq!(Provider::parse("TS"), Some(Provider::Tailscale));
		assert_eq!(Provider::parse("cloudflare"), Some(Provider::Cloudflared));
		assert_eq!(Provider::parse("mystery"), None);
	}
}
