#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod init;
mod tray;

use std::sync::Arc;

use tauri::Manager;
use tauri::webview::WebviewWindowBuilder;
use tauri_plugin_deep_link::DeepLinkExt;

use testd_core::config::{config_dir, has_pending_config};

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
		.invoke_handler(tauri::generate_handler![
			init::check_resolver,
			init::setup_resolver,
			init::certificate_status,
			init::install_certificate,
			init::operator_secret,
			init::read_pending,
			init::save_pending,
			init::finish_init,
		])
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

			if !needs_init() {
				// Tray-only mode: hide from dock.
				#[cfg(target_os = "macos")]
				app.set_activation_policy(tauri::ActivationPolicy::Accessory);

				tray::start_daemon(&app.handle().clone(), Arc::clone(&rt)).expect("failed to start daemon");
				tray::handle_current_url(&app.handle().clone());
			} else {
				// Show the init wizard (fresh or resuming from pending).
				WebviewWindowBuilder::new(app, "init", tauri::WebviewUrl::App("index.html".into()))
					.title("Testd Setup")
					.inner_size(640.0, 520.0)
					.resizable(false)
					.center()
					.build()?;
			}

			Ok(())
		})
		.build(tauri::generate_context!())
		.expect("error building testd host")
		.run(|app, event| match event {
			// Prevent exit when the init window closes: the app continues as a tray icon.
			// Allow programmatic exits (code is Some) from e.g. the tray Quit button.
			tauri::RunEvent::ExitRequested { code, api, .. } => {
				tray::trace(&format!("exit requested: code={code:?}"));
				if code.is_none() {
					api.prevent_exit();
				}
			},
			tauri::RunEvent::Exit => {
				if let Some(daemon) = app.try_state::<Arc<testd_daemon::daemon::Daemon>>() {
					let rt = app.state::<Arc<tokio::runtime::Runtime>>();
					rt.block_on(daemon.shutdown());
				}
				tray::trace("exited");
			},
			_ => {},
		});
}
