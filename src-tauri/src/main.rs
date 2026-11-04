#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod tray;

use std::sync::Arc;

use tauri::Manager;
use tauri::webview::WebviewWindowBuilder;
use tauri_plugin_deep_link::DeepLinkExt;

use testd_core::config::{config_dir, has_pending_config};
use testd_daemon::daemon::Daemon;

fn config_exists() -> bool {
	config_dir().join("config.toml").exists()
}

fn needs_init() -> bool {
	!config_exists() || has_pending_config()
}

fn main() {
	let rt = Arc::new(tokio::runtime::Runtime::new().expect("failed to create tokio runtime"));

	let rt_clone = Arc::clone(&rt);
	tauri::Builder::default()
		// Must be first so a URL launch reaches the running instance instead of
		// failing on the daemon lock.
		.plugin(tauri_plugin_single_instance::init(|_app, _argv, _cwd| {}))
		.plugin(tauri_plugin_deep_link::init())
		// Launch at login is enabled once, on first start; see tray::enable_autostart_once.
		.plugin({
			#[allow(unused_mut)]
			let mut builder = tauri_plugin_autostart::Builder::new().app_name("dev.testd.host");
			#[cfg(target_os = "macos")]
			{
				builder = builder.macos_launcher(tauri_plugin_autostart::MacosLauncher::LaunchAgent);
			}
			builder.build()
		})
		.manage(rt_clone)
		.setup(move |app| {
			let handle = app.handle().clone();
			app.deep_link().on_open_url(move |event| {
				for url in event.urls() {
					tray::handle_url(&handle, url.as_str());
				}
			});

			// macOS declares the scheme in Info.plist. Linux and Windows learn it
			// at runtime; skip dev builds so the scheme does not point at target/.
			#[cfg(any(windows, target_os = "linux"))]
			if (!cfg!(debug_assertions) || std::env::var_os("TESTD_REGISTER_SCHEME").is_some())
				&& let Err(e) = app.deep_link().register_all()
			{
				tray::trace(&format!("scheme registration failed: {e}"));
				eprintln!("[warn]   URL scheme registration failed: {e}");
			}

			if needs_init() {
				start_setup(app.handle().clone(), Arc::clone(&rt))?;
			} else {
				// Tray-only mode: hide from dock.
				#[cfg(target_os = "macos")]
				app.set_activation_policy(tauri::ActivationPolicy::Accessory);

				tray::start_daemon(&app.handle().clone(), Arc::clone(&rt)).expect("failed to start daemon");
				tray::handle_current_url(&app.handle().clone());
			}

			Ok(())
		})
		.build(tauri::generate_context!())
		.expect("error building testd host")
		.run(|app, event| match event {
			// The dashboard window is optional; the tray keeps the app alive. A
			// setup window is the whole app, so closing it may exit.
			tauri::RunEvent::ExitRequested { code, api, .. } => {
				tray::trace(&format!("exit requested: code={code:?}"));
				if code.is_none() && app.try_state::<Arc<Daemon>>().is_some() {
					api.prevent_exit();
				}
			},
			tauri::RunEvent::Exit => {
				if let Some(daemon) = app.try_state::<Arc<Daemon>>() {
					let rt = app.state::<Arc<tokio::runtime::Runtime>>();
					rt.block_on(daemon.shutdown());
				}
				tray::trace("exited");
			},
			_ => {},
		});
}

/// Serve the first-run setup on an ephemeral loopback port and open it.
///
/// The settings page runs in a webview but talks HTTP to the daemon crate, not
/// IPC: one page, one stylesheet, and no second UI stack to keep in step.
fn start_setup(app: tauri::AppHandle, rt: Arc<tokio::runtime::Runtime>) -> Result<(), Box<dyn std::error::Error>> {
	let mut setup = testd_daemon::setup::start(rt.handle())?;
	WebviewWindowBuilder::new(&app, "setup", tauri::WebviewUrl::External(setup.url.parse()?))
		.title("Testd Setup")
		.inner_size(760.0, 820.0)
		.center()
		.build()?;

	std::thread::spawn(move || {
		// Blocks until the page asks to finish; the receiver is not used inside
		// the runtime, so a dedicated thread keeps the main loop free.
		let Some(reply) = setup.wait() else { return };

		let main_app = app.clone();
		let main_rt = Arc::clone(&rt);
		let (done_tx, done_rx) = std::sync::mpsc::channel();
		if let Err(e) = app.run_on_main_thread(move || {
			let result = tray::start_daemon(&main_app, main_rt)
				.map(|()| main_app.state::<Arc<Daemon>>().engine.local_dashboard_url());
			if let Ok(url) = &result {
				tray::handle_current_url(&main_app);
				if let Some(window) = main_app.get_webview_window("setup") {
					let _ = window.close();
				}
				#[cfg(target_os = "macos")]
				let _ = main_app.set_activation_policy(tauri::ActivationPolicy::Accessory);
				if let Err(e) = tray::open_dashboard(&main_app, url) {
					tray::trace(&format!("dashboard window failed: {e}"));
				}
			}
			let _ = done_tx.send(result);
		}) {
			let _ = reply.send(Err(format!("cannot reach the main thread: {e}")));
			return;
		}

		let result = match done_rx.recv() {
			Ok(result) => result,
			Err(_) => Err("the daemon did not start".to_owned()),
		};
		let _ = reply.send(result);
	});

	Ok(())
}
