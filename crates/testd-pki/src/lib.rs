//! Local CA and on-demand leaf certificates.
//!
//! Layout under the PKI directory:
//! - `root.crt` / `root.key`: the trust root, installed in the OS trust store once
//! - `node.crt` / `node.key`: the local intermediate that signs short-lived leaves
//!
//! Serving needs only the intermediate. The root key is optional: a host whose
//! root key lives in an offline seed serves from `node.crt` / `node.key` alone
//! and only needs `root.key` to recreate a lost intermediate.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use rcgen::{
	BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
	KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// How long a minted leaf is valid. Browsers never see a CRL for a private CA,
/// so this bounds the damage from a compromised intermediate.
pub const LEAF_LIFETIME_HOURS: i64 = 24;

/// The local certificate authority.
pub struct Ca {
	root_cert_pem: String,
	dir: PathBuf,
	intermediate: Mutex<Intermediate>,
}

struct Intermediate {
	cert_pem: String,
	issuer: Issuer<'static, KeyPair>,
	not_after: i64,
}

impl Ca {
	/// Load the CA from `dir`, creating the root and node intermediate on first use.
	pub fn load_or_init(dir: &Path) -> Result<Self> {
		std::fs::create_dir_all(dir).context("create PKI directory")?;

		let root_cert_path = dir.join("root.crt");
		let root_key_path = dir.join("root.key");
		let node_cert_path = dir.join("node.crt");
		let node_key_path = dir.join("node.key");

		let (root_cert_pem, root_issuer) = if root_cert_path.exists() {
			let cert = std::fs::read_to_string(&root_cert_path).context("read root certificate")?;
			// The root key may have been moved into an offline seed; serving does not need it.
			let issuer = match std::fs::read_to_string(&root_key_path) {
				Ok(key) => {
					let key = KeyPair::from_pem(&key).context("parse root key")?;
					Some(Issuer::from_ca_cert_pem(&cert, key).context("load root issuer")?)
				},
				Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
				Err(e) => return Err(e).context("read root key"),
			};
			(cert, issuer)
		} else {
			anyhow::ensure!(
				!node_cert_path.exists(),
				"node.crt exists without root.crt; the PKI directory is inconsistent"
			);
			let (cert_pem, issuer) = generate_root()?;
			write_private(&root_key_path, issuer.key().serialize_pem().as_bytes())?;
			write_private(&root_cert_path, cert_pem.as_bytes())?;
			(cert_pem, Some(issuer))
		};

		let (node_cert_pem, node_issuer) = if node_cert_path.exists() && node_key_path.exists() {
			let cert = std::fs::read_to_string(&node_cert_path).context("read node certificate")?;
			let key = std::fs::read_to_string(&node_key_path).context("read node key")?;
			let key = KeyPair::from_pem(&key).context("parse node key")?;
			let issuer = Issuer::from_ca_cert_pem(&cert, key).context("load node issuer")?;
			(cert, issuer)
		} else {
			let root_issuer = root_issuer.as_ref().with_context(|| {
				format!(
					"{} is missing and the root key is not on this host; restore it or delete {} to create a new CA",
					node_cert_path.display(),
					dir.display()
				)
			})?;
			let (cert_pem, issuer) = generate_intermediate(root_issuer)?;
			write_private(&node_key_path, issuer.key().serialize_pem().as_bytes())?;
			write_private(&node_cert_path, cert_pem.as_bytes())?;
			(cert_pem, issuer)
		};

		let not_after = certificate_expiry(&node_cert_pem)?;
		let ca = Self {
			root_cert_pem,
			dir: dir.to_owned(),
			intermediate: Mutex::new(Intermediate { cert_pem: node_cert_pem, issuer: node_issuer, not_after }),
		};
		/* Validate and renew before serving, including after a long shutdown. */
		drop(ca.intermediate()?);
		Ok(ca)
	}

	pub fn root_cert_pem(&self) -> &str {
		&self.root_cert_pem
	}

	/// The root as a DER certificate, for trust-store installation and TLS roots.
	pub fn root_cert_der(&self) -> Result<CertificateDer<'static>> {
		pem_to_der(&self.root_cert_pem)
	}

	/// Mint a leaf for `hostname`, returning the PEM chain (leaf, intermediate).
	pub fn mint_pem(&self, hostname: &str) -> Result<(String, String)> {
		let intermediate = self.intermediate()?;
		let params = leaf_params(hostname)?;
		let key = KeyPair::generate().context("generate leaf key")?;
		let cert = params.signed_by(&key, &intermediate.issuer).context("sign leaf")?;
		let chain = cert.pem() + &intermediate.cert_pem;
		Ok((chain, key.serialize_pem()))
	}

	/// Mint a leaf for `hostname`, returning the DER chain and key for rustls.
	pub fn mint_der(&self, hostname: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
		let intermediate = self.intermediate()?;
		let params = leaf_params(hostname)?;
		let key = KeyPair::generate().context("generate leaf key")?;
		let cert = params.signed_by(&key, &intermediate.issuer).context("sign leaf")?;

		let leaf = cert.der().clone();
		let intermediate = pem_to_der(&intermediate.cert_pem)?;
		let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
		Ok((vec![leaf, intermediate], key))
	}

	fn intermediate(&self) -> Result<MutexGuard<'_, Intermediate>> {
		let mut intermediate = self.intermediate.lock().expect("CA lock poisoned");
		let now = time::OffsetDateTime::now_utc().unix_timestamp();
		let leaf_lifetime = LEAF_LIFETIME_HOURS * 3600;
		anyhow::ensure!(
			certificate_expiry(&self.root_cert_pem)? > now + leaf_lifetime,
			"the local root has expired or is expiring; back up {}, reinitialize the PKI and reinstall root trust",
			self.dir.display()
		);
		if intermediate.not_after <= now + leaf_lifetime * 2 {
			let root_key = self.dir.join("root.key");
			if root_key.exists() {
				let key = KeyPair::from_pem(&std::fs::read_to_string(&root_key)?)?;
				let root = Issuer::from_ca_cert_pem(&self.root_cert_pem, key)?;
				/* Retain the signing key: renewal replaces only the certificate atomically. */
				let key = KeyPair::from_pem(&intermediate.issuer.key().serialize_pem())?;
				let renewed = generate_intermediate_with_key(&root, key)?;
				backup_intermediate(&self.dir)?;
				let path = self.dir.join("node.crt");
				let temporary = self.dir.join("node.crt.new");
				write_private(&temporary, renewed.0.as_bytes())?;
				std::fs::rename(temporary, path).context("replace renewed intermediate")?;
				*intermediate =
					Intermediate { not_after: certificate_expiry(&renewed.0)?, cert_pem: renewed.0, issuer: renewed.1 };
			} else {
				anyhow::ensure!(
					intermediate.not_after > now + leaf_lifetime,
					"local intermediate expired or is expiring; restore {} and restart testd (or run testd doctor --fix)",
					root_key.display()
				);
			}
		}
		Ok(intermediate)
	}

	/// Build a rustls `CertifiedKey` for `hostname`.
	pub fn certified_key(&self, hostname: &str) -> Result<Arc<rustls::sign::CertifiedKey>> {
		let (chain, key) = self.mint_der(hostname)?;
		let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
			.map_err(|e| anyhow::anyhow!("unsupported leaf key: {e}"))?;
		Ok(Arc::new(rustls::sign::CertifiedKey::new(chain, signing_key)))
	}
}

fn root_params() -> Result<CertificateParams> {
	let mut params = CertificateParams::new(Vec::<String>::new())?;
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
	params.distinguished_name = distinguished_name("testd root");
	params.serial_number = Some(random_serial());
	params.use_authority_key_identifier_extension = true;
	params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
	params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
	Ok(params)
}

/// Generate a new root and return its PEM plus a signing issuer.
fn generate_root() -> Result<(String, Issuer<'static, KeyPair>)> {
	let key = KeyPair::generate().context("generate root key")?;
	let params = root_params()?;
	let cert = params.self_signed(&key).context("self-sign root")?;
	let pem = cert.pem();
	Ok((pem, Issuer::new(params, key)))
}

/// Generate a node intermediate signed by `root`.
fn generate_intermediate(root: &Issuer<'_, KeyPair>) -> Result<(String, Issuer<'static, KeyPair>)> {
	generate_intermediate_with_key(root, KeyPair::generate().context("generate node key")?)
}

fn generate_intermediate_with_key(
	root: &Issuer<'_, KeyPair>,
	key: KeyPair,
) -> Result<(String, Issuer<'static, KeyPair>)> {
	let mut params = CertificateParams::new(vec!["testd-intermediate".to_owned()])?;
	params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
	params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
	params.distinguished_name = distinguished_name("testd intermediate");
	params.serial_number = Some(random_serial());
	params.use_authority_key_identifier_extension = true;
	params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
	params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

	let cert = params.signed_by(&key, root).context("sign node intermediate")?;
	Ok((cert.pem(), Issuer::new(params, key)))
}

/// Inspect existing files without creating or modifying the CA.
pub fn check_validity(dir: &Path) -> Result<()> {
	let minimum = time::OffsetDateTime::now_utc().unix_timestamp() + LEAF_LIFETIME_HOURS * 3600;
	for name in ["root.crt", "node.crt"] {
		let path = dir.join(name);
		let pem = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
		anyhow::ensure!(
			certificate_expiry(&pem)? > minimum,
			"{} is expired or expiring; run testd doctor --fix and restart the daemon; restore root.key if needed",
			path.display()
		);
	}
	Ok(())
}

fn certificate_expiry(pem: &str) -> Result<i64> {
	let der = pem_to_der(pem)?;
	let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref())
		.map_err(|error| anyhow::anyhow!("parse CA validity: {error}"))?;
	Ok(cert.validity().not_after.timestamp())
}

fn backup_intermediate(dir: &Path) -> Result<()> {
	let timestamp = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
	let backup = dir.join("backups").join(timestamp.to_string());
	std::fs::create_dir_all(&backup)?;
	for name in ["node.crt", "node.key"] {
		let path = dir.join(name);
		if path.exists() {
			write_private(&backup.join(name), &std::fs::read(path)?)?;
		}
	}
	Ok(())
}

fn leaf_params(hostname: &str) -> Result<CertificateParams> {
	let mut params = CertificateParams::new(vec![hostname.to_owned()])?;
	params.is_ca = IsCa::NoCa;
	params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
	params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
	params.use_authority_key_identifier_extension = true;
	params.distinguished_name = distinguished_name(hostname);
	params.serial_number = Some(random_serial());
	params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
	params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(LEAF_LIFETIME_HOURS);
	Ok(params)
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
	let mut name = DistinguishedName::new();
	name.push(DnType::CommonName, common_name);
	name
}

/// A random 128-bit serial number.
fn random_serial() -> SerialNumber {
	let mut bytes = [0u8; 16];
	getrandom::fill(&mut bytes).expect("random bytes");
	bytes[0] &= 0x7f; // keep it positive
	SerialNumber::from(bytes.to_vec())
}

fn pem_to_der(pem: &str) -> Result<CertificateDer<'static>> {
	use rustls::pki_types::pem::PemObject;
	CertificateDer::from_pem_slice(pem.as_bytes()).context("parse certificate PEM")
}

/// Human-readable facts about a certificate, for maintenance screens.
#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
	pub subject: String,
	pub issuer: String,
	pub fingerprint_sha256: String,
	pub not_after: String,
}

impl CertificateInfo {
	/// Single-line summary for install output and setup screens.
	pub fn summary(&self) -> String {
		format!("{}; SHA-256 {}; expires {}", self.subject, self.fingerprint_sha256, self.not_after)
	}
}

/// Parse a PEM certificate and compute its SHA-256 fingerprint.
///
/// The fingerprint is the lowercase hex digest of the DER encoding, without
/// separators, so it can be compared with OS certificate tools directly.
pub fn inspect_certificate(pem: &str) -> Result<CertificateInfo> {
	let der = pem_to_der(pem)?;
	let (_, certificate) =
		x509_parser::parse_x509_certificate(der.as_ref()).map_err(|e| anyhow::anyhow!("parse certificate: {e}"))?;
	let digest = Sha256::digest(der.as_ref());
	let validity = certificate.validity();
	let not_after = validity
		.not_after
		.to_rfc2822()
		.unwrap_or_else(|_| validity.not_after.to_string());

	Ok(CertificateInfo {
		subject: certificate.subject().to_string(),
		issuer: certificate.issuer().to_string(),
		fingerprint_sha256: hex(&digest),
		not_after,
	})
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Write a secret file readable only by the current user.
fn write_private(path: &Path, content: &[u8]) -> Result<()> {
	#[cfg(unix)]
	{
		use std::io::Write;
		use std::os::unix::fs::OpenOptionsExt;

		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.mode(0o600)
			.open(path)?;
		file.write_all(content)?;
		file.sync_all()?;
	}
	#[cfg(not(unix))]
	{
		std::fs::write(path, content)?;
	}
	Ok(())
}

#[cfg(test)]
mod inspect_tests {
	use super::*;

	#[test]
	fn inspects_the_generated_root() {
		let dir = tempfile::tempdir().unwrap();
		let ca = Ca::load_or_init(dir.path()).unwrap();
		let info = inspect_certificate(ca.root_cert_pem()).unwrap();
		assert!(info.subject.contains("testd root"), "{}", info.subject);
		assert_eq!(info.issuer, info.subject);
		assert_eq!(info.fingerprint_sha256.len(), 64);
		assert!(info.fingerprint_sha256.chars().all(|c| c.is_ascii_hexdigit()));
		let summary = info.summary();
		assert!(summary.contains(&info.subject), "{summary}");
		assert!(summary.contains(&info.fingerprint_sha256), "{summary}");
		assert!(summary.contains(&info.not_after), "{summary}");
	}
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;

	use super::*;

	fn temp_dir() -> PathBuf {
		use std::sync::atomic::{AtomicU64, Ordering};
		static NEXT: AtomicU64 = AtomicU64::new(0);
		let dir = std::env::temp_dir().join(format!(
			"testd-pki-{}-{}",
			std::process::id(),
			NEXT.fetch_add(1, Ordering::Relaxed)
		));
		std::fs::create_dir_all(&dir).unwrap();
		dir
	}

	#[test]
	fn creates_and_reloads_a_ca() {
		let dir = temp_dir();
		let ca = Ca::load_or_init(&dir).unwrap();
		let root_pem = ca.root_cert_pem().to_owned();
		drop(ca);

		let reloaded = Ca::load_or_init(&dir).unwrap();
		assert_eq!(reloaded.root_cert_pem(), root_pem);
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn mints_a_leaf_chain_for_a_hostname() {
		let dir = temp_dir();
		let ca = Ca::load_or_init(&dir).unwrap();
		let (chain, key) = ca.mint_pem("app.example.test").unwrap();
		assert!(chain.contains("BEGIN CERTIFICATE"));
		assert!(key.contains("BEGIN PRIVATE KEY"));
		assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2, "leaf plus intermediate");

		let (der_chain, _) = ca.mint_der("app.example.test").unwrap();
		assert_eq!(der_chain.len(), 2);
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn distinct_serials_and_keys_per_leaf() {
		let dir = temp_dir();
		let ca = Ca::load_or_init(&dir).unwrap();
		let (first, _) = ca.mint_der("a.test").unwrap();
		let (second, _) = ca.mint_der("b.test").unwrap();
		assert_ne!(first[0].as_ref(), second[0].as_ref());
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn a_missing_intermediate_is_recreated_from_the_root() {
		let dir = temp_dir();
		Ca::load_or_init(&dir).unwrap();
		std::fs::remove_file(dir.join("node.crt")).unwrap();
		std::fs::remove_file(dir.join("node.key")).unwrap();

		let ca = Ca::load_or_init(&dir).unwrap();
		assert!(ca.mint_pem("app.test").unwrap().0.matches("BEGIN CERTIFICATE").count() == 2);
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn serves_without_the_root_key() {
		let dir = temp_dir();
		let ca = Ca::load_or_init(&dir).unwrap();
		let root_pem = ca.root_cert_pem().to_owned();
		drop(ca);
		std::fs::remove_file(dir.join("root.key")).unwrap();

		let ca = Ca::load_or_init(&dir).expect("the node intermediate is enough to serve");
		assert_eq!(ca.root_cert_pem(), root_pem);
		let (chain, _) = ca.mint_pem("app.test").unwrap();
		assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2, "leaf plus intermediate");
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn a_missing_intermediate_without_the_root_key_is_reported() {
		let dir = temp_dir();
		Ca::load_or_init(&dir).unwrap();
		for name in ["node.crt", "node.key", "root.key"] {
			std::fs::remove_file(dir.join(name)).unwrap();
		}

		let err = Ca::load_or_init(&dir)
			.err()
			.expect("cannot recreate the intermediate without the root key");
		let message = format!("{err:#}");
		assert!(message.contains("root key"), "{message}");
		assert!(message.contains(dir.to_str().unwrap()), "{message}");
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn mints_without_the_root_key_after_reload() {
		let dir = temp_dir();
		let ca = Ca::load_or_init(&dir).unwrap();
		drop(ca);
		std::fs::remove_file(dir.join("root.key")).unwrap();

		let ca = Ca::load_or_init(&dir).unwrap();
		let (der, _) = ca.mint_der("app.test").unwrap();
		assert_eq!(der.len(), 2, "leaf plus intermediate");
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn renews_an_expired_intermediate_without_changing_root_trust() {
		let dir = tempfile::tempdir().unwrap();
		let ca = Ca::load_or_init(dir.path()).unwrap();
		let root = ca.root_cert_pem().to_owned();
		let old_cert = ca.intermediate.lock().unwrap().cert_pem.clone();
		ca.intermediate.lock().unwrap().not_after = 0;
		ca.mint_der("app.test").unwrap();
		assert_eq!(ca.root_cert_pem(), root);
		assert_ne!(ca.intermediate.lock().unwrap().cert_pem, old_cert);
		let backups = std::fs::read_dir(dir.path().join("backups")).unwrap().collect::<Vec<_>>();
		assert_eq!(backups.len(), 1);
		let saved = backups[0].as_ref().unwrap().path();
		assert_eq!(std::fs::read_to_string(saved.join("node.crt")).unwrap(), old_cert);
		Ca::load_or_init(dir.path()).unwrap().mint_der("app.test").unwrap();
	}

	#[test]
	fn expiry_without_the_root_key_has_an_actionable_error() {
		let dir = tempfile::tempdir().unwrap();
		let ca = Ca::load_or_init(dir.path()).unwrap();
		std::fs::remove_file(dir.path().join("root.key")).unwrap();
		ca.intermediate.lock().unwrap().not_after = 0;
		let error = ca.mint_der("app.test").unwrap_err().to_string();
		assert!(error.contains("restore") && error.contains("root.key"), "{error}");
	}

	#[test]
	fn startup_renews_an_expired_certificate_on_disk() {
		let dir = tempfile::tempdir().unwrap();
		let ca = Ca::load_or_init(dir.path()).unwrap();
		let root_key = KeyPair::from_pem(&std::fs::read_to_string(dir.path().join("root.key")).unwrap()).unwrap();
		let root = Issuer::from_ca_cert_pem(ca.root_cert_pem(), root_key).unwrap();
		let key = KeyPair::from_pem(&std::fs::read_to_string(dir.path().join("node.key")).unwrap()).unwrap();
		let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
		params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
		params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
		params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
		params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
		let expired = params.signed_by(&key, &root).unwrap().pem();
		write_private(&dir.path().join("node.crt"), expired.as_bytes()).unwrap();
		assert!(check_validity(dir.path()).is_err());
		let renewed = Ca::load_or_init(dir.path()).unwrap();
		assert_eq!(renewed.root_cert_pem(), ca.root_cert_pem());
		check_validity(dir.path()).unwrap();
		renewed.mint_der("app.test").unwrap();
	}

	#[cfg(unix)]
	#[test]
	fn secrets_are_private() {
		use std::os::unix::fs::PermissionsExt;
		let dir = temp_dir();
		Ca::load_or_init(&dir).unwrap();
		let mode = std::fs::metadata(dir.join("root.key")).unwrap().permissions().mode();
		assert_eq!(mode & 0o077, 0, "root key must not be group/world readable");
		std::fs::remove_dir_all(&dir).ok();
	}
}
