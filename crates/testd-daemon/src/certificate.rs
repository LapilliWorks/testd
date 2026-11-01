//! Local certificate maintenance for the dashboard.
//!
//! The browser UI can install or remove system trust only on the host. These
//! functions are called from the loopback listener; the authenticated listener
//! never exposes them.

use std::path::Path;

use serde::Serialize;

use crate::health;

#[derive(Debug, Clone, Serialize)]
pub struct CertificateStatus {
	pub trusted: bool,
	pub pki_dir: String,
	pub root_path: String,
	pub subject: String,
	pub issuer: String,
	pub fingerprint_sha256: String,
	pub not_after: String,
	pub summary: String,
	pub leaf_lifetime_hours: i64,
}

fn load_root_pem(pki_dir: &Path) -> Result<String, String> {
	let ca = testd_pki::Ca::load_or_init(pki_dir).map_err(|e| e.to_string())?;
	Ok(ca.root_cert_pem().to_owned())
}

pub fn status(pki_dir: &Path) -> Result<CertificateStatus, String> {
	let pem = load_root_pem(pki_dir)?;
	let info = testd_pki::inspect_certificate(&pem).map_err(|e| e.to_string())?;
	Ok(CertificateStatus {
		trusted: testd_setup::is_root_trusted(&pem),
		pki_dir: pki_dir.display().to_string(),
		root_path: pki_dir.join("root.crt").display().to_string(),
		summary: info.summary(),
		subject: info.subject,
		issuer: info.issuer,
		fingerprint_sha256: info.fingerprint_sha256,
		not_after: info.not_after,
		leaf_lifetime_hours: testd_pki::LEAF_LIFETIME_HOURS,
	})
}

/// Install the root and allow the daemon to keep it trusted on the next start.
pub fn install(pki_dir: &Path) -> Result<CertificateStatus, String> {
	let pem = load_root_pem(pki_dir)?;
	if !testd_setup::is_root_trusted(&pem) {
		testd_setup::trust_root_gui(&pem).map_err(|e| e.to_string())?;
	}
	health::set_auto_trust(pki_dir, true).map_err(|e| e.to_string())?;
	status(pki_dir)
}

/// Remove the root and remember that the user does not want it reinstalled.
pub fn remove(pki_dir: &Path) -> Result<CertificateStatus, String> {
	let pem = load_root_pem(pki_dir)?;
	if testd_setup::is_root_trusted(&pem) {
		testd_setup::untrust_root_gui(&pem).map_err(|e| e.to_string())?;
	}
	health::set_auto_trust(pki_dir, false).map_err(|e| e.to_string())?;
	status(pki_dir)
}
