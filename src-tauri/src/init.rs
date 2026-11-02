//! Tauri commands for the init wizard.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Manager};

use testd_core::config::{
	DEFAULT_DNS_PORT, PendingConfig, TLD, config_dir, finish_pending_config, has_pending_config, read_pending_config,
	write_pending_config,
};
use testd_daemon::certificate::{self, CertificateStatus};

use crate::tray;

// --- Resolver (step 1) ---

#[tauri::command]
pub fn check_resolver() -> bool {
	let addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_PORT));
	testd_setup::is_os_resolver_configured(TLD, addr)
}

#[tauri::command]
pub fn setup_resolver() -> Result<(), String> {
	let addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_PORT));
	testd_setup::setup_os_resolver_gui(TLD, addr).map_err(|e| e.to_string())
}

// --- Certificate (step 2) ---

/// The location the CLI and the config template use for the CA.
fn pki_dir() -> PathBuf {
	config_dir().join("pki")
}

/// Reading a status can create the CA on first use, so it runs off the main thread.
#[tauri::command]
pub async fn certificate_status() -> Result<CertificateStatus, String> {
	let dir = pki_dir();
	tauri::async_runtime::spawn_blocking(move || certificate::status(&dir))
		.await
		.map_err(|e| e.to_string())?
}

/// Installing trust prompts for authorization; keep the window responsive.
#[tauri::command]
pub async fn install_certificate() -> Result<CertificateStatus, String> {
	let dir = pki_dir();
	tauri::async_runtime::spawn_blocking(move || certificate::install(&dir))
		.await
		.map_err(|e| e.to_string())?
}

// --- Operator secret (step 3) ---

/// Shortest operator secret the wizard accepts; generated ones are longer.
const MIN_SECRET_LEN: usize = 16;

fn pending_or_default() -> PendingConfig {
	read_pending_config().unwrap_or_else(|_| PendingConfig {
		step: 0,
		caddy_config_path: String::new(),
		secret: String::new(),
	})
}

/// Validate a secret the wizard produced or the operator edited.
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

/// The wizard's operator secret: keep the pending choice, else reuse the host
/// config, else generate one and remember it so a resumed setup keeps it.
#[tauri::command]
pub fn operator_secret(regenerate: Option<bool>) -> Result<String, String> {
	let mut pending = pending_or_default();
	if regenerate == Some(true) || pending.secret.is_empty() {
		let existing = if regenerate == Some(true) { None } else { testd_core::config::read_operator_secret() };
		pending.secret = match existing {
			Some(secret) => secret,
			None => testd_core::config::generate_operator_secret().map_err(|e| e.to_string())?,
		};
		write_pending_config(&pending).map_err(|e| e.to_string())?;
	}
	Ok(pending.secret)
}

// --- Pending config state ---

#[derive(Serialize)]
pub struct PendingState {
	pub step: u8,
}

#[tauri::command]
pub fn read_pending() -> Option<PendingState> {
	if !has_pending_config() {
		return None;
	}
	let pending = read_pending_config().ok()?;
	Some(PendingState { step: pending.step })
}

#[tauri::command]
pub fn save_pending(step: u8, secret: Option<String>) -> Result<(), String> {
	let mut pending = pending_or_default();
	if let Some(secret) = secret {
		pending.secret = secret;
	}
	pending.step = step;
	write_pending_config(&pending).map_err(|e| e.to_string())
}

// --- Finish ---

/// Configure an external Caddy front when one is installed.
///
/// The built-in edge needs no Caddy, so this is best-effort: a failure leaves
/// the path empty instead of blocking setup. Mirrors the CLI, which only
/// touches a Caddyfile that already exists.
fn configure_external_front() -> String {
	use testd_core::config::{CaddyDetection, default_http_addr, detect_caddy_config};

	let CaddyDetection::Found { path } = detect_caddy_config() else {
		return String::new();
	};

	let managed = config_dir().join("Caddyfile");
	let content = testd_daemon::edge::caddyfile(TLD, default_http_addr());
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

fn write_managed_caddyfile(path: &Path, content: &str) -> std::io::Result<()> {
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent)?;
	}
	std::fs::write(path, content)
}

/// Finalize init: write real config, close init window, start daemon.
#[tauri::command]
pub fn finish_init(app: AppHandle, secret: String) -> Result<(), String> {
	let mut pending = pending_or_default();
	pending.step = 3;
	pending.caddy_config_path = configure_external_front();
	pending.secret = validate_operator_secret(&secret)?;
	finish_pending_config(&pending).map_err(|e| e.to_string())?;

	// Close the init window and switch to tray-only mode.
	if let Some(window) = app.get_webview_window("init") {
		window.close().ok();
	}
	#[cfg(target_os = "macos")]
	app.set_activation_policy(tauri::ActivationPolicy::Accessory)
		.map_err(|e| e.to_string())?;

	let rt = app.state::<Arc<tokio::runtime::Runtime>>();
	tray::start_daemon(&app, Arc::clone(&rt)).map_err(|e| e.to_string())?;
	tray::handle_current_url(&app);
	Ok(())
}
