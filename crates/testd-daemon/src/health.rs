//! Host health: probe the prerequisites a browser needs, repair them, and tell
//! the desktop about problems.
//!
//! The daemon owns this state so the tray and `testd host` behave the same.
//! Frontends render [`Health`] and forward user actions; delivery, deduplication,
//! and the repair itself stay here.
//!
//! Notification actions carry a `testd://` URL. The daemon parses the action
//! identifier returned by the notification system, so no OS URL-scheme handler
//! is needed for in-process notifications. An action that needs input (a sudo
//! password, UAC consent) still works when the elevation helper can prompt;
//! actions that would need input the notification cannot collect are not
//! modelled as notification actions.

use std::collections::BTreeSet;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use testd_core::config::{DEFAULT_DNS_PORT, ResolverBackend, load_host_config};
use testd_setup::Elevation;
use tokio::sync::{broadcast, watch};

use crate::resolver::Resolver;
use crate::resolver::hosts::HostsResolver;

/// How often the daemon re-checks the resolver route and the root CA.
const PROBE_INTERVAL: Duration = Duration::from_secs(10);
/// The CA store lookup is the expensive probe; run it every sixth tick.
const ROOT_CHECK_TICKS: u32 = 6;

/// Prerequisites a browser needs before `https://<name>.<tld>` works.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Health {
	pub resolver: bool,
	pub root_trusted: bool,
}

impl Health {
	pub fn healthy(self) -> bool {
		self.resolver && self.root_trusted
	}
}

/// A repair the user can trigger from a notification or a menu.
///
/// The URL form is the action identifier carried by the notification. It also
/// gives every frontend one stable name for the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
	SetupResolver,
	TrustRoot,
}

impl Action {
	pub fn url(self) -> &'static str {
		match self {
			Self::SetupResolver => "testd://fix/resolver",
			Self::TrustRoot => "testd://fix/certificate",
		}
	}

	pub fn label(self) -> &'static str {
		match self {
			Self::SetupResolver => "Set up DNS",
			Self::TrustRoot => "Trust certificate",
		}
	}

	/// Accept both the URL identifier and the button label.
	///
	/// XDG and Windows return the identifier; the legacy macOS notification
	/// stack returns the label of the pressed button.
	pub fn parse(value: &str) -> Option<Self> {
		match value {
			"testd://fix/resolver" | "Set up DNS" => Some(Self::SetupResolver),
			"testd://fix/certificate" | "Trust certificate" => Some(Self::TrustRoot),
			_ => None,
		}
	}
}

/// Something the desktop should know about.
#[derive(Debug, Clone)]
pub struct Notice {
	pub title: String,
	pub body: String,
	pub action: Option<Action>,
}

impl Notice {
	fn resolver(tld: &str) -> Self {
		Self {
			title: "DNS routing is not set up".into(),
			body: format!("Names ending in .{tld} do not resolve from other devices. Set up DNS on this host."),
			action: Some(Action::SetupResolver),
		}
	}

	fn certificate() -> Self {
		Self {
			title: "Certificate is not trusted".into(),
			body: "Browsers reject the local HTTPS certificate. Trust the testd root once per device.".into(),
			action: Some(Action::TrustRoot),
		}
	}

	fn repair_failed(action: Action, error: &str) -> Self {
		Self {
			title: "Setup repair failed".into(),
			body: format!("{} failed: {error}", action.label()),
			action: Some(action),
		}
	}

	pub(crate) fn token_request(label: &str, address: &str) -> Self {
		Self {
			title: format!("Token request from {label}"),
			body: format!("{address} is waiting for approval. Open the dashboard to approve or deny it."),
			action: None,
		}
	}
}

/// Which component a notice belongs to. Used to notify once per problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum NoticeKey {
	Resolver,
	Root,
}

/// The root CA as the monitor sees it. Tests substitute a fake.
pub(crate) trait RootAuthority: Send + Sync {
	fn is_trusted(&self) -> bool;
	fn install(&self, elevation: Elevation) -> io::Result<()>;

	/// Whether the daemon may install trust on its own at startup.
	fn auto_trust_allowed(&self) -> bool {
		true
	}
}

/// Marker in the PKI directory: the user removed root trust explicitly.
///
/// The tray installs trust at startup for fresh installs. Without this marker,
/// removing trust from the maintenance UI would be undone on the next launch.
const AUTO_TRUST_DISABLED: &str = "trust-disabled";

/// Record whether the daemon may install root trust without being asked.
pub fn set_auto_trust(pki_dir: &Path, allowed: bool) -> io::Result<()> {
	let path = pki_dir.join(AUTO_TRUST_DISABLED);
	if allowed {
		match std::fs::remove_file(&path) {
			Ok(()) => Ok(()),
			Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
			Err(e) => Err(e),
		}
	} else {
		std::fs::create_dir_all(pki_dir)?;
		std::fs::write(path, b"removed by the user\n")
	}
}

/// The real root CA in the daemon's PKI directory.
pub(crate) struct PkiRoot {
	pki_dir: PathBuf,
}

impl PkiRoot {
	pub(crate) fn new(pki_dir: PathBuf) -> Self {
		Self { pki_dir }
	}

	fn pem(&self) -> Option<String> {
		std::fs::read_to_string(self.pki_dir.join("root.crt")).ok()
	}
}

impl RootAuthority for PkiRoot {
	fn is_trusted(&self) -> bool {
		self.pem().is_some_and(|pem| testd_setup::is_root_trusted(&pem))
	}

	fn install(&self, elevation: Elevation) -> io::Result<()> {
		let Some(pem) = self.pem() else {
			return Err(io::Error::new(io::ErrorKind::NotFound, "root certificate is missing"));
		};
		if !testd_setup::is_root_trusted(&pem) {
			match elevation {
				Elevation::Gui => testd_setup::trust_root_gui(&pem),
				Elevation::Sudo => testd_setup::trust_root(&pem),
			}?;
		}
		set_auto_trust(&self.pki_dir, true)
	}

	fn auto_trust_allowed(&self) -> bool {
		!self.pki_dir.join(AUTO_TRUST_DISABLED).exists()
	}
}

/// A resolver for the one-shot URL handler.
///
/// It only configures the OS route; applying names is the daemon's job. The
/// route still points at the daemon's eventual DNS listener.
struct OsResolver {
	tld: String,
	elevation: Elevation,
}

impl OsResolver {
	fn listen_addr() -> SocketAddr {
		SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_PORT))
	}
}

impl Resolver for OsResolver {
	fn apply(&self, _names: &[crate::resolver::ResolvedName]) -> io::Result<()> {
		Ok(())
	}

	fn ensure_os(&self) -> io::Result<()> {
		if self.tld == "localhost" {
			return Ok(());
		}
		let addr = Self::listen_addr();
		if testd_setup::is_os_resolver_configured(&self.tld, addr) {
			return Ok(());
		}
		self.elevation.setup_os_resolver(&self.tld, addr)
	}

	fn is_os_configured(&self) -> bool {
		self.tld == "localhost" || testd_setup::is_os_resolver_configured(&self.tld, Self::listen_addr())
	}

	fn cleanup(&self) -> io::Result<()> {
		Ok(())
	}
}

/// Run a single repair without starting the daemon.
///
/// Used by `testd url` when no daemon is running, for example when a stale
/// notification is activated. The elevation strategy still controls the prompt.
pub fn repair_once(action: Action, elevation: Elevation) -> Result<(), String> {
	let config = load_host_config().map_err(|e| e.to_string())?;
	let resolver: Arc<dyn Resolver> = match config.resolver {
		ResolverBackend::Dns => Arc::new(OsResolver { tld: config.tld.clone(), elevation }),
		ResolverBackend::Hosts => {
			Arc::new(HostsResolver::new(&config.tld, &config.hosts_helper_path, &config.hosts_path))
		},
	};
	let root = config
		.edge_enabled
		.then(|| Arc::new(PkiRoot::new(config.pki_dir.clone())) as Arc<dyn RootAuthority>);
	let monitor = HealthMonitor::new(config.tld, resolver, root, elevation);
	monitor.repair(action).map_err(|e| e.to_string())
}

/// Probes health, emits notices on changes, and runs repairs.
pub(crate) struct HealthMonitor {
	tld: String,
	resolver: Arc<dyn Resolver>,
	root: Option<Arc<dyn RootAuthority>>,
	elevation: Elevation,
	health: watch::Sender<Health>,
	notices: broadcast::Sender<Notice>,
	notified: Mutex<BTreeSet<NoticeKey>>,
	/// Privileged repairs are serialized so two triggers do not race the
	/// elevation prompt or the system stores.
	repairs: Mutex<()>,
	started: AtomicBool,
}

impl HealthMonitor {
	pub(crate) fn new(
		tld: String,
		resolver: Arc<dyn Resolver>,
		root: Option<Arc<dyn RootAuthority>>,
		elevation: Elevation,
	) -> Self {
		let (health, _) = watch::channel(Health::default());
		let (notices, _) = broadcast::channel(16);
		Self {
			tld,
			resolver,
			root,
			elevation,
			health,
			notices,
			notified: Mutex::new(BTreeSet::new()),
			repairs: Mutex::new(()),
			started: AtomicBool::new(false),
		}
	}

	pub(crate) fn health(&self) -> Health {
		*self.health.borrow()
	}

	pub(crate) fn subscribe(&self) -> watch::Receiver<Health> {
		self.health.subscribe()
	}

	pub(crate) fn notices(&self) -> broadcast::Receiver<Notice> {
		self.notices.subscribe()
	}

	/// Start the probe loop and desktop notification delivery.
	///
	/// `auto_trust` is for the GUI elevation path: the tray used to install the
	/// root itself at startup, and this keeps that behavior without putting the
	/// logic in the frontend. Headless hosts leave it off so a terminal is never
	/// prompted unexpectedly; `testd init` and `testd doctor --fix` own that.
	pub(crate) fn start(self: &Arc<Self>, auto_trust: bool) {
		if self.started.swap(true, Ordering::SeqCst) {
			return;
		}
		// Subscribe before the first probe so startup problems reach the
		// notification task instead of being dropped with no receiver.
		let notices = self.notices.subscribe();
		if auto_trust && !self.is_root_trusted() && self.auto_trust_allowed() {
			// A refusal is not an error here: the ordinary probe below reports
			// the remaining problem, and the user can retry from the notice.
			let _ = self.install_root();
		}
		self.probe(true);

		let monitor = Arc::clone(self);
		tokio::spawn(async move { monitor.run_probes().await });

		// Notifications are an OS/desktop concern. A session without a
		// notification service still gets the stderr notice from `emit`.
		if self.notifications_enabled() {
			let monitor = Arc::clone(self);
			tokio::spawn(async move { monitor.run_notifier(notices).await });
		}
	}

	/// Probe both prerequisites. `check_root` skips the CA store lookup on
	/// ticks that do not need it.
	pub(crate) fn probe(&self, check_root: bool) -> Health {
		let next = Health {
			resolver: self.resolver.is_os_configured(),
			root_trusted: if check_root { self.is_root_trusted() } else { self.health().root_trusted },
		};
		self.publish(next);
		next
	}

	/// Repair a prerequisite. Blocking: privileged helpers may wait for a
	/// password or a consent dialog.
	pub(crate) fn repair(&self, action: Action) -> io::Result<()> {
		let _repairing = self.repairs.lock().expect("repair lock poisoned");
		let result = match action {
			Action::SetupResolver => self.resolver.ensure_os(),
			Action::TrustRoot => self.install_root(),
		};
		match result {
			Ok(()) => {
				self.probe(true);
				Ok(())
			},
			Err(e) => {
				self.emit(Notice::repair_failed(action, &e.to_string()));
				Err(e)
			},
		}
	}

	fn is_root_trusted(&self) -> bool {
		self.root.as_ref().is_none_or(|root| root.is_trusted())
	}

	fn auto_trust_allowed(&self) -> bool {
		self.root.as_ref().is_none_or(|root| root.auto_trust_allowed())
	}

	fn notifications_enabled(&self) -> bool {
		// The legacy macOS notification callback needs the main run loop, which
		// only the GUI process has. A headless `testd host` would block a thread
		// forever waiting for an action, so it only logs.
		#[cfg(target_os = "macos")]
		if self.elevation == Elevation::Sudo {
			return false;
		}
		desktop_session()
	}

	fn install_root(&self) -> io::Result<()> {
		match &self.root {
			Some(root) => root.install(self.elevation),
			None => Ok(()),
		}
	}

	fn publish(&self, next: Health) {
		if self.health() != next {
			self.health.send_replace(next);
		}

		let mut notified = self.notified.lock().expect("health notices poisoned");
		if next.resolver {
			notified.remove(&NoticeKey::Resolver);
		} else if notified.insert(NoticeKey::Resolver) {
			self.emit(Notice::resolver(&self.tld));
		}
		if next.root_trusted {
			notified.remove(&NoticeKey::Root);
		} else if notified.insert(NoticeKey::Root) {
			self.emit(Notice::certificate());
		}
	}

	pub(crate) fn emit(&self, notice: Notice) {
		eprintln!("[notice] {}: {}", notice.title, notice.body);
		let _ = self.notices.send(notice);
	}

	async fn run_probes(self: Arc<Self>) {
		let mut ticker = tokio::time::interval(PROBE_INTERVAL);
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		ticker.tick().await;

		let mut ticks = 0u32;
		loop {
			ticker.tick().await;
			ticks = ticks.wrapping_add(1);
			let check_root = ticks.is_multiple_of(ROOT_CHECK_TICKS);
			let monitor = Arc::clone(&self);
			// The resolver probe spawns a process on some platforms.
			if tokio::task::spawn_blocking(move || monitor.probe(check_root)).await.is_err() {
				eprintln!("[warn]   health probe task failed");
			}
		}
	}

	async fn run_notifier(self: Arc<Self>, mut notices: broadcast::Receiver<Notice>) {
		loop {
			match notices.recv().await {
				Ok(notice) => {
					let monitor = Arc::clone(&self);
					// The handle waits for the user, which can take arbitrarily
					// long; keep it off the tokio blocking pool.
					std::thread::spawn(move || monitor.notify(notice));
				},
				Err(broadcast::error::RecvError::Lagged(dropped)) => {
					eprintln!("[warn]   dropped {dropped} health notices");
				},
				Err(broadcast::error::RecvError::Closed) => return,
			}
		}
	}

	fn notify(self: Arc<Self>, notice: Notice) {
		let mut notification = notify_rust::Notification::new();
		notification.appname("testd").summary(&notice.title).body(&notice.body);
		#[cfg(target_os = "windows")]
		notification.app_id("dev.testd.host");
		if let Some(action) = notice.action {
			notification.action(action.url(), action.label());
		}

		let handle = match notification.show() {
			Ok(handle) => handle,
			Err(e) => {
				eprintln!("[warn]   desktop notification failed: {e}");
				return;
			},
		};
		let Some(action) = notice.action else { return };

		// macOS can only deliver this callback while the main run loop is
		// alive; `notifications_enabled` keeps headless CLI runs out.
		handle.wait_for_action(|id| {
			let chosen = Action::parse(id).or_else(|| (id == "default").then_some(action));
			let Some(chosen) = chosen else { return };
			if let Err(e) = self.repair(chosen) {
				eprintln!("[warn]   repair failed: {e}");
			}
		});
	}
}

/// Whether this process has a desktop notification service to talk to.
fn desktop_session() -> bool {
	#[cfg(target_os = "linux")]
	{
		std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
	}
	#[cfg(not(target_os = "linux"))]
	{
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::resolver::ResolvedName;
	use std::sync::atomic::AtomicBool;

	struct FakeResolver {
		configured: AtomicBool,
	}

	impl FakeResolver {
		fn new(configured: bool) -> Self {
			Self { configured: AtomicBool::new(configured) }
		}
	}

	impl Resolver for FakeResolver {
		fn apply(&self, _names: &[ResolvedName]) -> io::Result<()> {
			Ok(())
		}

		fn ensure_os(&self) -> io::Result<()> {
			self.configured.store(true, Ordering::SeqCst);
			Ok(())
		}

		fn is_os_configured(&self) -> bool {
			self.configured.load(Ordering::SeqCst)
		}

		fn cleanup(&self) -> io::Result<()> {
			Ok(())
		}
	}

	struct FakeRoot {
		trusted: AtomicBool,
		fail_install: AtomicBool,
	}

	impl FakeRoot {
		fn new(trusted: bool) -> Self {
			Self { trusted: AtomicBool::new(trusted), fail_install: AtomicBool::new(false) }
		}
	}

	impl RootAuthority for FakeRoot {
		fn is_trusted(&self) -> bool {
			self.trusted.load(Ordering::SeqCst)
		}

		fn install(&self, _elevation: Elevation) -> io::Result<()> {
			if self.fail_install.load(Ordering::SeqCst) {
				return Err(io::Error::new(io::ErrorKind::PermissionDenied, "cancelled"));
			}
			self.trusted.store(true, Ordering::SeqCst);
			Ok(())
		}
	}

	fn monitor(resolver: bool, trusted: bool) -> HealthMonitor {
		HealthMonitor::new(
			"test".into(),
			Arc::new(FakeResolver::new(resolver)),
			Some(Arc::new(FakeRoot::new(trusted))),
			Elevation::Gui,
		)
	}

	#[test]
	fn auto_trust_marker_round_trips() {
		let dir = tempfile::tempdir().unwrap();
		let pki = dir.path().join("pki");
		assert!(PkiRoot::new(pki.clone()).auto_trust_allowed());

		set_auto_trust(&pki, false).unwrap();
		assert!(!PkiRoot::new(pki.clone()).auto_trust_allowed());

		set_auto_trust(&pki, true).unwrap();
		assert!(PkiRoot::new(pki).auto_trust_allowed());
	}

	#[test]
	fn actions_round_trip_through_urls_and_labels() {
		for action in [Action::SetupResolver, Action::TrustRoot] {
			assert_eq!(Action::parse(action.url()), Some(action));
			assert_eq!(Action::parse(action.label()), Some(action));
		}
		assert_eq!(Action::parse("testd://fix/unknown"), None);
		assert_eq!(Action::parse("__closed"), None);
	}

	#[test]
	fn healthy_probe_emits_no_notice() {
		let monitor = monitor(true, true);
		let mut notices = monitor.notices();
		monitor.probe(true);
		assert!(notices.try_recv().is_err());
		assert!(monitor.health().healthy());
	}

	#[test]
	fn missing_problems_notify_once_until_repaired() {
		let monitor = monitor(false, false);
		let mut notices = monitor.notices();

		monitor.probe(true);
		let first = notices.try_recv().unwrap();
		assert_eq!(first.action, Some(Action::SetupResolver));
		let second = notices.try_recv().unwrap();
		assert_eq!(second.action, Some(Action::TrustRoot));

		// A later probe of the same broken state is silent.
		monitor.probe(true);
		assert!(notices.try_recv().is_err());
	}

	#[test]
	fn repair_clears_the_notice_and_rearms_it() {
		let resolver = Arc::new(FakeResolver::new(false));
		let monitor =
			HealthMonitor::new("test".into(), resolver.clone(), Some(Arc::new(FakeRoot::new(false))), Elevation::Gui);
		let mut notices = monitor.notices();
		monitor.probe(true);
		while notices.try_recv().is_ok() {}

		monitor.repair(Action::SetupResolver).unwrap();
		assert!(monitor.health().resolver);
		assert!(notices.try_recv().is_err());

		// Losing the route again notifies again.
		resolver.configured.store(false, Ordering::SeqCst);
		monitor.probe(true);
		assert_eq!(notices.try_recv().unwrap().action, Some(Action::SetupResolver));
	}

	#[test]
	fn failed_repair_emits_a_notice() {
		let root = Arc::new(FakeRoot::new(false));
		root.fail_install.store(true, Ordering::SeqCst);
		let monitor = HealthMonitor::new("test".into(), Arc::new(FakeResolver::new(false)), Some(root), Elevation::Gui);
		let mut notices = monitor.notices();
		monitor.probe(true);
		while notices.try_recv().is_ok() {}

		assert!(monitor.repair(Action::TrustRoot).is_err());
		let notice = notices.try_recv().unwrap();
		assert_eq!(notice.action, Some(Action::TrustRoot));
		assert!(notice.body.contains("cancelled"));
	}
}
