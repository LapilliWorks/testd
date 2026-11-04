//! Tray icon and daemon lifecycle.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::webview::WebviewWindowBuilder;
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager};
use tauri_plugin_deep_link::DeepLinkExt;

use testd_daemon::daemon::Daemon;
use testd_daemon::engine::EngineEvent;
use testd_daemon::health::{Action, Health};
use testd_daemon::launch::LaunchView;
use testd_daemon::share::ShareView;

/// Append a timestamped line to the file named by `TESTD_TRAY_TRACE`.
/// Tray and menu behavior has no other observable surface on Windows.
pub(crate) fn trace(message: &str) {
	let Some(path) = std::env::var_os("TESTD_TRAY_TRACE") else {
		return;
	};
	let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) else {
		return;
	};
	let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
		return;
	};
	let _ = writeln!(file, "{:.3} {message}", now.as_secs_f64());
}

/// What a menu click asks the async loop to do. Menu events run on the app's
/// main thread, where anything that re-enters the menu or the OS freezes the
/// whole UI.
enum MenuAction {
	ToggleAutostart,
	StopDomain(String),
	StartLaunch(String),
	StopLaunch(String),
	/// `None` is this machine.
	OpenShare(String),
	StopShare(String),
}

/// Items the event handler updates in place. Replacing an open popup with
/// `set_menu` closes it and, on Windows, leaves the tray unable to open it again,
/// so menu clicks only ever change item state.
struct MenuHandles {
	autostart: CheckMenuItem<tauri::Wry>,
}

type SharedHandles = std::sync::Arc<std::sync::Mutex<Option<MenuHandles>>>;

fn show_autostart(handles: &SharedHandles, enabled: bool) {
	let item = {
		let Ok(guard) = handles.lock() else { return };
		guard.as_ref().map(|handles| handles.autostart.clone())
	};
	if let Some(item) = item {
		let _ = item.set_checked(enabled);
	}
}

/// Everything the menu renders. Passed as one value so adding a row does not
/// reshuffle a long argument list again.
struct MenuState<'a> {
	regs: &'a [testd_core::Registration],
	health: Health,
	autostart: bool,
	shares: &'a [ShareView],
	launches: &'a [LaunchRow],
	tld: &'a str,
}

/// The part of a launch the menu renders. Kept separate from [`LaunchView`] so
/// a new log line does not rebuild an open menu.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LaunchRow {
	id: String,
	label: String,
	running: bool,
}

/// Build a complete tray menu from the current registrations and health.
fn build_menu(app: &AppHandle, state: &MenuState<'_>, handles: &SharedHandles) -> tauri::Result<Menu<tauri::Wry>> {
	let MenuState { regs, health, autostart, shares, launches, tld } = *state;
	let mut items: Vec<Box<dyn tauri::menu::IsMenuItem<tauri::Wry>>> = Vec::new();
	// A missing prerequisite is the first thing to act on, and the red icon
	// points here.
	if !health.resolver {
		items.push(Box::new(MenuItem::with_id(app, "setup-dns", "Set up DNS", true, None::<&str>)?));
	}
	if !health.root_trusted {
		items.push(Box::new(MenuItem::with_id(app, "trust-root", "Trust certificate", true, None::<&str>)?));
	}
	if !health.healthy() {
		items.push(Box::new(PredefinedMenuItem::separator(app)?));
	}

	if regs.is_empty() {
		items.push(Box::new(MenuItem::with_id(app, "no-domains", "No active domains", false, None::<&str>)?));
	} else {
		for r in regs {
			items.push(Box::new(domain_item(app, r)?));
		}
	}
	// The dashboard is a local name like any other, and the last row is where a
	// user looks for it after scanning the live names.
	items.push(Box::new(MenuItem::with_id(
		app,
		"dashboard-open",
		format!("testd.{tld} → dashboard"),
		true,
		None::<&str>,
	)?));

	items.push(Box::new(PredefinedMenuItem::separator(app)?));

	if !launches.is_empty() {
		// A heading, not an action. Start and stop live on each launch.
		items.push(Box::new(MenuItem::with_id(app, "quick-launches", "Quick launches", false, None::<&str>)?));
		for launch in launches {
			let submenu = Submenu::with_id(app, format!("launch:{}", launch.id), &launch.label, true)?;
			let (id, action) = if launch.running {
				(format!("launch-stop:{}", launch.id), "stop")
			} else {
				(format!("launch-start:{}", launch.id), "start")
			};
			submenu.append(&MenuItem::with_id(app, id, action, true, None::<&str>)?)?;
			items.push(Box::new(submenu));
		}
		items.push(Box::new(PredefinedMenuItem::separator(app)?));
	}

	if !shares.is_empty() {
		for share in shares {
			let label = format!("Shared: {} → {} ({})", share.name, share.url, share.exposure.label());
			items.push(Box::new(MenuItem::with_id(
				app,
				format!("share-open:{}", share.name),
				label,
				true,
				None::<&str>,
			)?));
			items.push(Box::new(MenuItem::with_id(
				app,
				format!("share-stop:{}", share.name),
				format!("Stop sharing {}", share.name),
				true,
				None::<&str>,
			)?));
		}
		items.push(Box::new(PredefinedMenuItem::separator(app)?));
	}

	let autostart_item = CheckMenuItem::with_id(app, "autostart", "Launch at login", true, autostart, None::<&str>)?;
	items.push(Box::new(autostart_item.clone()));
	items.push(Box::new(MenuItem::with_id(app, "quit", "Exit", true, None::<&str>)?));

	if let Ok(mut slot) = handles.lock() {
		*slot = Some(MenuHandles { autostart: autostart_item });
	}

	let refs: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> =
		items.iter().map(|i| &**i as &dyn tauri::menu::IsMenuItem<tauri::Wry>).collect();
	Menu::with_items(app, &refs)
}

/// One name, with open and stop beneath it. A menu item cannot both act and hold
/// children, so the name itself is a submenu.
fn domain_item(app: &AppHandle, reg: &testd_core::Registration) -> tauri::Result<Submenu<tauri::Wry>> {
	let label = format!("{} → {}", reg.domain, reg.target);
	let submenu = Submenu::with_id(app, format!("domain:{}", reg.domain), label, true)?;
	submenu.append(&MenuItem::with_id(app, format!("domain-open:{}", reg.domain), "open", true, None::<&str>)?)?;
	submenu.append(&MenuItem::with_id(app, format!("domain-stop:{}", reg.domain), "stop", true, None::<&str>)?)?;
	Ok(submenu)
}

/// The menu's view of every saved launch.
fn summarize_launches(views: &[LaunchView]) -> Vec<LaunchRow> {
	views
		.iter()
		.map(|view| LaunchRow { id: view.definition.id.clone(), label: launch_label(view), running: view.running })
		.collect()
}

/// `label :port`, using the live target when a launch detected its own port.
fn launch_label(view: &LaunchView) -> String {
	let mut ports: Vec<&str> = Vec::new();
	for entry in &view.definition.entries {
		let target = view
			.states
			.iter()
			.find(|state| state.domain == entry.domain)
			.map(|state| state.target.as_str())
			.unwrap_or(entry.target.as_str());
		if let Some(port) = target_port(target)
			&& !ports.contains(&port)
		{
			ports.push(port);
		}
	}
	if ports.is_empty() {
		view.definition.label.clone()
	} else {
		format!("{} :{}", view.definition.label, ports.join(", :"))
	}
}

/// The numeric port of a target, if it names one.
fn target_port(target: &str) -> Option<&str> {
	let target = target.trim();
	if target.is_empty() || target.eq_ignore_ascii_case("auto") {
		return None;
	}
	let port = match target.strip_prefix('[') {
		Some(rest) => rest.split_once("]:").map(|(_, port)| port)?,
		None => target.rsplit_once(':').map_or(target, |(_, port)| port),
	};
	(!port.is_empty() && port.chars().all(|c| c.is_ascii_digit())).then_some(port)
}

/// What the tray icon should say before the user opens the menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IconState {
	/// No action needed.
	Healthy,
	/// A leaf is waiting for a token.
	Request,
	/// A browser prerequisite is missing or a repair failed.
	Alert,
}

impl IconState {
	/// A broken prerequisite outranks a pending request, because the red icon
	/// and its menu items point at the repair.
	fn current(healthy: bool, has_request: bool) -> Self {
		if !healthy {
			Self::Alert
		} else if has_request {
			Self::Request
		} else {
			Self::Healthy
		}
	}

	/// Only the neutral icon is a macOS template; colored states must keep their
	/// color.
	fn as_template(self) -> bool {
		self == Self::Healthy
	}
}

/// Tray icon for the current platform.
///
/// macOS receives a template image, so a single dark-ink asset adapts to the
/// menu bar appearance. Windows and Linux trays have no template mechanism and
/// may be either light or dark, so they get the plate variant: an opaque
/// rounded square that carries its own background.
fn tray_icon(state: IconState) -> tauri::Result<Image<'static>> {
	#[cfg(target_os = "macos")]
	let bytes: &'static [u8] = match state {
		IconState::Healthy => include_bytes!("../icons/tray-on-light.png"),
		IconState::Request => include_bytes!("../icons/tray-on-light-request.png"),
		IconState::Alert => include_bytes!("../icons/tray-on-light-alert.png"),
	};
	#[cfg(not(target_os = "macos"))]
	let bytes: &'static [u8] = match state {
		IconState::Healthy => include_bytes!("../icons/tray-plate.png"),
		IconState::Request => include_bytes!("../icons/tray-plate-request.png"),
		IconState::Alert => include_bytes!("../icons/tray-plate-alert.png"),
	};
	Image::from_bytes(bytes)
}

/// Apply a repair off the main thread. The daemon publishes the resulting
/// health change, which rebuilds the menu and icon.
fn run_action(rt: &tokio::runtime::Handle, daemon: Arc<Daemon>, action: Action) {
	rt.spawn(async move {
		match daemon.repair(action).await {
			Ok(()) => trace("health repair applied"),
			Err(e) => trace(&format!("health repair failed: {e}")),
		}
	});
}

/// Whether the OS currently starts the tray at login.
fn autostart_enabled(app: &AppHandle) -> bool {
	use tauri_plugin_autostart::ManagerExt;
	app.autolaunch().is_enabled().unwrap_or(false)
}

/// Enable launch at login on the first start, and never again automatically.
///
/// From then on the tray's "Launch at login" checkbox is the control: the marker
/// records that the first attempt succeeded, so a user who unticks it is not
/// overridden on the next launch, and a failed first attempt retries.
fn enable_autostart_once(app: &AppHandle) {
	use tauri_plugin_autostart::ManagerExt;

	let marker = testd_core::config::config_dir().join("autostart.initialized");
	if marker.exists() {
		return;
	}
	match app.autolaunch().enable() {
		Ok(()) => {
			trace("launch at login enabled");
			if let Some(parent) = marker.parent() {
				let _ = std::fs::create_dir_all(parent);
			}
			let _ = std::fs::write(&marker, b"1\n");
		},
		Err(e) => trace(&format!("launch at login not enabled: {e}")),
	}
}

/// Run a `testd://` action delivered by the deep-link plugin or the CLI.
pub fn handle_url(app: &AppHandle, url: &str) {
	let Some(daemon) = app.try_state::<Arc<Daemon>>() else {
		trace(&format!("url before the daemon is ready: {url}"));
		return;
	};
	let rt = app.state::<Arc<tokio::runtime::Runtime>>();
	let daemon = Arc::clone(daemon.inner());
	let url = url.to_owned();
	trace(&format!("url action: {url}"));
	rt.spawn(async move {
		match daemon.handle_url(&url).await {
			Ok(()) => trace("url action applied"),
			Err(e) => trace(&format!("url action failed: {e}")),
		}
	});
}

/// Consume the URL that launched this process, if any.
///
/// Used after the daemon starts, including after the setup page writes the
/// first config, because the URL may have arrived while there was no daemon.
pub fn handle_current_url(app: &AppHandle) {
	let Ok(Some(urls)) = app.deep_link().get_current() else {
		return;
	};
	for url in urls {
		handle_url(app, url.as_str());
	}
}

/// Open the dashboard in a webview window, or focus the existing one.
///
/// The page is the daemon's loopback dashboard, the same bytes a browser gets,
/// so this is a window around the site, not a second UI.
pub fn open_dashboard(app: &AppHandle, url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	if let Some(window) = app.get_webview_window("dashboard") {
		window.show()?;
		window.set_focus()?;
		return Ok(());
	}
	let window = WebviewWindowBuilder::new(app, "dashboard", tauri::WebviewUrl::External(url.parse()?))
		.title("testd")
		.inner_size(1040.0, 800.0)
		.min_inner_size(720.0, 520.0)
		.center()
		.build()?;
	window.set_focus()?;
	Ok(())
}

/// Initialize the daemon, build the system tray, and spawn the engine.
pub fn start_daemon(
	app: &AppHandle,
	rt: Arc<tokio::runtime::Runtime>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let _guard = rt.enter();

	// First trace line identifies the running binary and its tauri build.
	trace(&format!(
		"start {} tauri {} at {}",
		env!("CARGO_PKG_NAME"),
		tauri::VERSION,
		std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default(),
	));

	let daemon = Arc::new(rt.block_on(async { Daemon::new_gui().await })?);
	enable_autostart_once(app);
	let health = daemon.health();
	let dashboard_url = daemon.engine.local_dashboard_url();
	let tld = daemon.tld().to_owned();
	// A menu event runs on the app's main thread. Anything that calls back into
	// the menu or the OS from there freezes the whole window, so clicks only post
	// a message and the async loop does the work.
	let (action_tx, action_rx) = tokio::sync::mpsc::unbounded_channel::<MenuAction>();

	let autostart = autostart_enabled(app);
	let shares = rt.block_on(async { daemon.shares().list().await });
	let launches = summarize_launches(&daemon.launches().list());
	let handles: SharedHandles = std::sync::Arc::new(std::sync::Mutex::new(None));
	let menu = build_menu(
		app,
		&MenuState { regs: &[], health, autostart, shares: &shares, launches: &launches, tld: &tld },
		&handles,
	)?;

	// Subscribe before reading the current value, so a request made while the
	// tray is being built is not missed.
	let mut request_changes = daemon.request_changes();
	let mut has_request = !request_changes.borrow().is_empty();
	let mut icon_state = IconState::current(health.healthy(), has_request);
	let icon = tray_icon(icon_state)?;
	let click_dashboard = dashboard_url.clone();
	let action_daemon = Arc::clone(&daemon);
	let action_rt = rt.handle().clone();
	let action_menu = action_tx.clone();
	let tray = TrayIconBuilder::new()
		.icon(icon)
		.icon_as_template(icon_state.as_template())
		.menu(&menu)
		.show_menu_on_left_click(true)
		.on_tray_icon_event(|_, event| trace(&format!("tray event: {event:?}")))
		.on_menu_event(move |app, event| {
			let id = event.id.as_ref();
			trace(&format!("menu event: {id}"));
			if id == "quit" {
				app.exit(0);
			} else if id == "setup-dns" {
				run_action(&action_rt, Arc::clone(&action_daemon), Action::SetupResolver);
			} else if id == "trust-root" {
				run_action(&action_rt, Arc::clone(&action_daemon), Action::TrustRoot);
			} else if id == "autostart" {
				// Read and write the login item off the main thread.
				let _ = action_menu.send(MenuAction::ToggleAutostart);
			} else if id == "dashboard-open" {
				if let Err(e) = open_dashboard(app, &click_dashboard) {
					trace(&format!("dashboard window failed: {e}"));
				}
			} else if let Some(domain) = id.strip_prefix("domain-open:") {
				let url = format!("https://{domain}");
				let _ = open::that(&url);
			} else if let Some(domain) = id.strip_prefix("domain-stop:") {
				let _ = action_menu.send(MenuAction::StopDomain(domain.to_owned()));
			} else if let Some(launch) = id.strip_prefix("launch-start:") {
				let _ = action_menu.send(MenuAction::StartLaunch(launch.to_owned()));
			} else if let Some(launch) = id.strip_prefix("launch-stop:") {
				let _ = action_menu.send(MenuAction::StopLaunch(launch.to_owned()));
			} else if let Some(name) = id.strip_prefix("share-open:") {
				let _ = action_menu.send(MenuAction::OpenShare(name.to_owned()));
			} else if let Some(name) = id.strip_prefix("share-stop:") {
				let _ = action_menu.send(MenuAction::StopShare(name.to_owned()));
			} else if id.starts_with("domain:")
				|| id.starts_with("launch:")
				|| id == "quick-launches"
				|| id == "no-domains"
			{
				// Submenu headers and headings are not actions.
			}
		})
		.build(app)?;
	trace("tray built");

	// Bind before returning so a caller can open the dashboard immediately. The
	// accept loop still runs in the background.
	let listener = rt.block_on(async { daemon.engine.bind().await })?;
	let mut events = daemon.engine.subscribe();
	let engine = daemon.engine.clone();
	let engine_app = app.clone();

	tokio::spawn(async move {
		if let Err(e) = engine.serve(listener).await {
			// eprintln! goes nowhere in a GUI build without a console.
			trace(&format!("engine error: {e}"));
			eprintln!("engine error: {e}");
			engine_app.exit(1);
		}
	});

	// Keep the daemon alive for the lifetime of the app.
	app.manage(Arc::clone(&daemon));

	// Trace daemon notices even though the daemon delivers them to the desktop.
	let mut notices = daemon.notices();
	tokio::spawn(async move {
		loop {
			match notices.recv().await {
				Ok(notice) => trace(&format!("notice: {}: {}", notice.title, notice.body)),
				Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
				Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
			}
		}
	});

	// Rebuild the menu and icon on registration or health changes. Clicks
	// post messages here instead, so nothing re-enters the UI from the menu event.
	let tray_id = tray.id().clone();
	let menu_app = app.clone();
	let mut health_changes = daemon.health_changes();
	let node_daemon = Arc::clone(&daemon);
	let mut action_rx = action_rx;
	let menu_handles = std::sync::Arc::clone(&handles);
	let menu_tld = tld.clone();
	tokio::spawn(async move {
		// Replacing a menu that is on screen destroys its popup handle, which
		// closes it. Only rebuild when something really differs.
		let mut regs: Vec<testd_core::Registration> = Vec::new();
		let mut health = health;
		let mut autostart = autostart_enabled(&menu_app);
		let mut shares = shares;
		let mut launches = launches;
		let mut ticker = tokio::time::interval(Duration::from_secs(5));
		let mut launch_ticker = tokio::time::interval(Duration::from_secs(1));

		loop {
			let mut rebuild = false;
			tokio::select! {
				_ = ticker.tick() => {
					// The login item can also change outside the tray.
					let current = autostart_enabled(&menu_app);
					if current != autostart {
						autostart = current;
						show_autostart(&menu_handles, current);
					}
					// Shares are started from the CLI, so poll for changes.
					let current = node_daemon.shares().list().await;
					if current != shares {
						shares = current;
						rebuild = true;
					}
				},
				_ = launch_ticker.tick() => {
					let current = summarize_launches(&node_daemon.launches().list());
					if current != launches {
						launches = current;
						rebuild = true;
					}
				},
				event = events.recv() => match event {
					Ok(EngineEvent::Changed(next)) => {
						if next != regs {
							trace(&format!("engine changed: {} domains", next.len()));
							regs = next;
							rebuild = true;
						}
					},
					Err(_) => break,
				},
				changed = health_changes.changed() => {
					if changed.is_err() {
						break;
					}
					let next = *health_changes.borrow_and_update();
					if next != health {
						trace(&format!("health: {next:?}"));
						health = next;
						rebuild = true;
					}
				},
				changed = request_changes.changed() => {
					if changed.is_err() {
						break;
					}
					let current = !request_changes.borrow_and_update().is_empty();
					if current != has_request {
						trace(&format!("token request: {}", if current { "pending" } else { "resolved" }));
						has_request = current;
					}
				},
				action = action_rx.recv() => {
					let Some(action) = action else { break };
					// The popup is still closing; touching the OS or the items
					// immediately is what froze the UI.
					tokio::time::sleep(Duration::from_millis(150)).await;
					match action {
						MenuAction::StopDomain(domain) => {
							match node_daemon.stop_domain(&domain).await {
								Ok(()) => trace(&format!("domain stopped: {domain}")),
								Err(e) => trace(&format!("domain stop failed: {e}")),
							}
						},
						MenuAction::StartLaunch(id) => {
							let book = node_daemon.launches();
							match book.start(&id) {
								Ok(()) => trace(&format!("launch started: {id}")),
								Err(e) => trace(&format!("launch start failed: {e}")),
							}
							let current = summarize_launches(&book.list());
							if current != launches {
								launches = current;
								rebuild = true;
							}
						},
						MenuAction::StopLaunch(id) => {
							let book = node_daemon.launches();
							match book.stop(&id) {
								Ok(()) => trace(&format!("launch stopping: {id}")),
								Err(e) => trace(&format!("launch stop failed: {e}")),
							}
							let current = summarize_launches(&book.list());
							if current != launches {
								launches = current;
								rebuild = true;
							}
						},
						MenuAction::ToggleAutostart => {
							use tauri_plugin_autostart::ManagerExt;
							let manager = menu_app.autolaunch();
							let enabled = manager.is_enabled().unwrap_or(false);
							let result = if enabled { manager.disable() } else { manager.enable() };
							match result {
								Ok(()) => trace(&format!("launch at login {}", if enabled { "disabled" } else { "enabled" })),
								Err(e) => trace(&format!("launch at login toggle failed: {e}")),
							}
							autostart = autostart_enabled(&menu_app);
							show_autostart(&menu_handles, autostart);
						},
						MenuAction::OpenShare(name) => {
							let url = node_daemon
								.shares()
								.list()
								.await
								.into_iter()
								.find(|share| share.name == name)
								.map(|share| share.url);
							match url {
								Some(url) => {
									let _ = open::that(&url);
								},
								None => trace(&format!("share {name} is gone")),
							}
						},
						MenuAction::StopShare(name) => {
							if node_daemon.shares().stop(&name).await {
								trace(&format!("share stopped: {name}"));
								shares = node_daemon.shares().list().await;
								rebuild = true;
							}
						},
					}
				},
			}

			let next_icon = IconState::current(health.healthy(), has_request);
			if !rebuild && next_icon == icon_state {
				continue;
			}

			let Some(tray) = menu_app.tray_by_id(&tray_id) else {
				continue;
			};

			if rebuild {
				// Swapping the menu while its popup is still closing is the failure
				// mode; give it a moment.
				tokio::time::sleep(Duration::from_millis(150)).await;
				let state =
					MenuState { regs: &regs, health, autostart, shares: &shares, launches: &launches, tld: &menu_tld };
				match build_menu(&menu_app, &state, &menu_handles) {
					Ok(menu) => match tray.set_menu(Some(menu)) {
						Ok(()) => trace("menu replaced"),
						Err(e) => trace(&format!("menu replace failed: {e}")),
					},
					Err(e) => trace(&format!("menu build failed: {e}")),
				}
			}

			if next_icon != icon_state {
				icon_state = next_icon;
				match tray_icon(icon_state) {
					Ok(icon) => {
						if let Err(e) = tray.set_icon_with_as_template(Some(icon), icon_state.as_template()) {
							trace(&format!("icon update failed: {e}"));
						}
					},
					Err(e) => trace(&format!("icon load failed: {e}")),
				}
			}
		}
	});

	Ok(())
}
