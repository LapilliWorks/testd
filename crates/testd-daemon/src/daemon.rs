//! Daemon: loads config, starts the resolver and edge, runs the host engine.
//!
//! Single entry point for both headless and GUI modes. The GUI gets the engine
//! handle to subscribe to events; the headless mode just calls `run()`.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use testd_core::config::{DEFAULT_DNS_PORT, ResolverBackend, config_dir, load_host_config};
use testd_setup::Elevation;

use crate::access::{Access, PendingView};
use crate::control::ControlServer;
use crate::edge::{self, Edge, EdgeContext};
use crate::engine::HostEngine;
use crate::health::{Action, Health, HealthMonitor, Notice, PkiRoot, RootAuthority};
use crate::launch::LaunchBook;
use crate::resolver::Resolver;
use crate::resolver::dns::DnsResolver;
use crate::resolver::hosts::HostsResolver;

/// A configured, ready-to-run host daemon.
pub struct Daemon {
	pub engine: Arc<HostEngine>,
	resolver: Arc<dyn Resolver>,
	tld: String,
	edge: Option<Edge>,
	health: Arc<HealthMonitor>,
	/// Tunnels this daemon owns, so a share outlives the terminal that asked.
	shares: Arc<crate::share::Shares>,
	/// Issued leaf tokens and waiting requests.
	access: Arc<Access>,
	/// Present while the loopback URL-action channel is listening; dropping it
	/// removes the control file.
	_control: Option<ControlServer>,
	/// Quick launches owned by this daemon.
	launches: Arc<LaunchBook>,
	/// Held for the daemon's lifetime; dropping it releases the instance lock.
	_instance_lock: std::fs::File,
}

impl Daemon {
	/// Load config and create the daemon. System changes use `sudo`, for the CLI.
	pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
		Self::new_with_elevation(Elevation::Sudo).await
	}

	/// Load config and create the daemon; system changes use a native GUI dialog.
	pub async fn new_gui() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
		Self::new_with_elevation(Elevation::Gui).await
	}

	pub async fn new_with_elevation(elevation: Elevation) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
		let _instance_lock = acquire_instance_lock()?;
		let config = load_host_config()?;
		let tld = testd_core::config::host_tld().to_owned();

		if config.secret.is_empty() {
			eprintln!(
				"[warn]   no operator secret in [host]; only approved leaf tokens can register until `testd init` writes one"
			);
		}

		let resolver: Arc<dyn Resolver> = match config.resolver {
			ResolverBackend::Dns => {
				let dns = DnsResolver::start(&tld, config.answer_addr, elevation)
					.await
					.map_err(|e| format!("failed to start the DNS server on 127.0.0.1:{DEFAULT_DNS_PORT}: {e}"))?;
				eprintln!("DNS server listening on {}", dns.listen_addr());
				Arc::new(dns)
			},
			ResolverBackend::Hosts => {
				if cfg!(windows) {
					return Err("the hosts resolver is not supported on Windows; use resolver = \"dns\"".into());
				}
				if !config.hosts_helper_path.exists() {
					return Err(format!(
						"hosts helper not found: {}\nrun `testd setup-hosts-helper` to install it",
						config.hosts_helper_path.display()
					)
					.into());
				}
				Arc::new(HostsResolver::new(&tld, &config.hosts_helper_path, &config.hosts_path))
			},
		};

		// Prime resolution with testd.{tld} before any client connects.
		resolver.apply(&[])?;

		let access = Arc::new(Access::load_default()?);
		let mut engine = HostEngine::new(config.clone(), Arc::clone(&resolver), Arc::clone(&access));
		let launches = Arc::new(LaunchBook::load());
		engine.set_launches(Arc::clone(&launches));

		let root = config
			.edge_enabled
			.then(|| Arc::new(PkiRoot::new(config.pki_dir.clone())) as Arc<dyn RootAuthority>);
		let health = Arc::new(HealthMonitor::new(tld.clone(), Arc::clone(&resolver), root, elevation));
		let health_for_http = Arc::clone(&health);
		engine.set_health_refresh(move || {
			health_for_http.probe(true);
		});

		// Providers that cannot reach a container or LAN target point at the plain
		// edge listener instead; the edge learns the share's name as an alias.
		let front =
			crate::share::Front { registry: engine.registrations(), plain_addr: local_client_addr(config.http_addr) };
		let shares = Arc::new(crate::share::Shares::from_env(Some(front)));
		engine.set_shares(Arc::clone(&shares));

		// `tailscale serve --bg` survives this process while the alias that made
		// the name answer does not, so clear the leftovers off the startup path.
		{
			let shares = Arc::clone(&shares);
			tokio::spawn(async move { shares.reclaim().await });
		}

		// A share belongs to its name: when the registration goes, the tunnel goes.
		{
			let shares = Arc::clone(&shares);
			tokio::spawn(retain_shares(shares, engine.subscribe(), engine.registrations(), tld.clone()));
		}

		let control = match ControlServer::start(
			Arc::clone(&health),
			local_client_addr(config.listen_addr),
			Arc::clone(&shares),
			engine.registrations(),
			Arc::clone(&access),
			tld.clone(),
		)
		.await
		{
			Ok(server) => {
				engine.set_local_token(server.token().to_owned());
				Some(server)
			},
			Err(e) => {
				eprintln!("[warn]   control channel unavailable: {e}");
				None
			},
		};

		let engine = Arc::new(engine);

		// The plain listener is always needed: an external front owns TLS when the
		// built-in edge is disabled. Only the TLS listener follows `edge_enabled`.
		let mut context = EdgeContext::new(tld.clone(), engine.registrations());
		context.trust_forwarded_for = config.trust_forwarded_for;
		let tls_addr = config.edge_enabled.then_some(config.edge_addr);
		let edge = edge::start(Arc::new(context), tls_addr, config.http_addr, &config.pki_dir)?;
		if config.edge_enabled {
			eprintln!("[edge]   https://*.{} on {}", tld, edge.tls_addr);
		}
		eprintln!("[edge]   http://{} for external fronts", edge.http_addr);

		// The tray used to install the root on startup; keep that policy in the
		// daemon, but never prompt a terminal for `testd host`.
		health.start(elevation == Elevation::Gui);
		spawn_request_notices(Arc::clone(&access), Arc::clone(&health));

		Ok(Self {
			engine,
			resolver,
			tld,
			edge: Some(edge),
			health,
			shares,
			access,
			_control: control,
			launches,
			_instance_lock,
		})
	}

	/// The daemon's tunnels. A share lives here, not in the CLI process.
	pub fn shares(&self) -> Arc<crate::share::Shares> {
		Arc::clone(&self.shares)
	}

	/// Waiting leaf token requests, oldest first.
	pub fn pending_requests(&self) -> Vec<PendingView> {
		self.access.pending()
	}

	/// Changes to the waiting request list, for frontends that show an alert icon.
	pub fn request_changes(&self) -> tokio::sync::watch::Receiver<Vec<PendingView>> {
		self.access.changes()
	}

	/// The TLD this host serves.
	pub fn tld(&self) -> &str {
		&self.tld
	}

	/// Authenticated dashboard URL, including the per-run control token.
	pub fn dashboard_url(&self) -> Result<String, String> {
		crate::control::dashboard_url()
			.map_err(|e| e.to_string())?
			.ok_or_else(|| "the control channel is unavailable".to_owned())
	}

	/// Run the engine. Blocks until the listener fails.
	pub async fn run(&self) -> io::Result<()> {
		self.engine.run().await
	}

	/// The current prerequisites a browser needs.
	pub fn health(&self) -> Health {
		self.health.health()
	}

	/// Health changes, for frontends that render status.
	pub fn health_changes(&self) -> tokio::sync::watch::Receiver<Health> {
		self.health.subscribe()
	}

	/// Re-probe immediately after a frontend changes trust or resolver state.
	pub fn refresh_health(&self) -> Health {
		self.health.probe(true)
	}

	/// Notices emitted on health changes, for diagnostics.
	pub fn notices(&self) -> tokio::sync::broadcast::Receiver<Notice> {
		self.health.notices()
	}

	/// Client credentials for GUI-supervised local launches.
	///
	/// The token is the per-run control token; the daemon accepts it only from
	/// loopback. A missing control channel means quick launches are unavailable.
	pub fn local_client_config(&self) -> Result<testd_core::config::ClientConfig, String> {
		crate::control::client_config()
	}

	/// Stop supervised launches before the process exits.
	pub async fn shutdown(&self) {
		self.launches.shutdown().await;
	}

	/// Repair a prerequisite. Runs the privileged helper off the runtime.
	pub async fn repair(&self, action: Action) -> Result<(), String> {
		let monitor = Arc::clone(&self.health);
		match tokio::task::spawn_blocking(move || monitor.repair(action)).await {
			Ok(Ok(())) => Ok(()),
			Ok(Err(e)) => Err(e.to_string()),
			Err(e) => Err(e.to_string()),
		}
	}

	/// Handle a `testd://` action URL, as delivered by a notification or an OS
	/// URL-scheme handler.
	pub async fn handle_url(&self, url: &str) -> Result<(), String> {
		let action = Action::parse(url).ok_or_else(|| format!("unknown testd action: {url}"))?;
		self.repair(action).await
	}
}

/// A lagged registration subscriber must still close shares after revocation.
async fn retain_shares(
	shares: Arc<crate::share::Shares>,
	mut events: tokio::sync::broadcast::Receiver<crate::engine::EngineEvent>,
	registry: crate::engine::Registrations,
	tld: String,
) {
	let suffix = format!(".{tld}");
	loop {
		let registrations = match events.recv().await {
			Ok(crate::engine::EngineEvent::Changed(registrations)) => registrations,
			Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => registry.lock().await.snapshot(),
			Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
		};
		let names: Vec<String> = registrations
			.into_iter()
			.map(|registration| {
				registration
					.domain
					.strip_suffix(&suffix)
					.unwrap_or(&registration.domain)
					.to_owned()
			})
			.collect();
		shares.retain(&names).await;
	}
}

/// Announce each newly waiting request through the desktop notifier.
///
/// The access store publishes its whole waiting list, so a burst or a missed
/// wakeup still announces every id that was not seen before.
fn spawn_request_notices(access: Arc<Access>, health: Arc<HealthMonitor>) {
	let mut changes = access.changes();
	tokio::spawn(async move {
		let mut seen: HashSet<String> = HashSet::new();
		loop {
			if changes.changed().await.is_err() {
				return;
			}
			let pending = changes.borrow_and_update().clone();
			for request in pending.iter().filter(|request| !seen.contains(&request.id)) {
				health.emit(Notice::token_request(&request.label, &request.address));
			}
			seen = pending.into_iter().map(|request| request.id).collect();
		}
	});
}

impl Drop for Daemon {
	fn drop(&mut self) {
		self.resolver.cleanup().ok();
		if let Some(edge) = self.edge.take() {
			drop(edge);
		}
	}
}

/// Take an exclusive advisory lock so a second daemon (tray plus headless, or
/// two trays) fails fast instead of fighting over the port and the CA files.
fn acquire_instance_lock() -> std::io::Result<std::fs::File> {
	use fs2::FileExt;

	let dir = config_dir();
	std::fs::create_dir_all(&dir)?;
	let path = dir.join("daemon.lock");
	let file = std::fs::OpenOptions::new()
		.create(true)
		.truncate(false)
		.write(true)
		.open(&path)?;
	file.try_lock_exclusive().map_err(|_| {
		std::io::Error::new(
			std::io::ErrorKind::AlreadyExists,
			format!("another testd daemon is already running (lock: {})", path.display()),
		)
	})?;
	Ok(file)
}

/// The local client connects to the same listener over loopback.
fn local_client_addr(listen: SocketAddr) -> SocketAddr {
	if listen.ip().is_unspecified() { SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port()) } else { listen }
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;
	use crate::engine::EngineEvent;
	use crate::share::{Provider, Shares};
	use std::os::unix::fs::PermissionsExt;

	#[tokio::test]
	async fn a_lagged_subscriber_still_stops_a_share_whose_name_left() {
		let dir = tempfile::tempdir().unwrap();
		let provider = dir.path().join("provider");
		std::fs::write(&provider, "#!/bin/sh\necho 'https://fixture.trycloudflare.com' >&2\nexec sleep 30\n").unwrap();
		std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o700)).unwrap();
		let shares = Arc::new(Shares::new(Provider::Cloudflared, Some(provider), None));
		shares.start("app", "127.0.0.1:3000", None).await.unwrap();
		let registry = Arc::new(tokio::sync::Mutex::new(crate::registry::Registry::default()));
		let (sender, receiver) = tokio::sync::broadcast::channel(1);
		for _ in 0..3 {
			sender.send(EngineEvent::Changed(Vec::new())).unwrap();
		}
		let task = tokio::spawn(retain_shares(Arc::clone(&shares), receiver, registry, "test".into()));
		tokio::time::timeout(std::time::Duration::from_secs(3), async {
			while !shares.list().await.is_empty() {
				tokio::task::yield_now().await;
			}
		})
		.await
		.expect("a missed registration event cannot keep a share alive");
		drop(sender);
		task.await.unwrap();
	}
}
