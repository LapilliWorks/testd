//! Validation for registration names and reverse-proxy targets.
//!
//! Both values are interpolated into the managed Caddyfile, so they must be
//! strict: no whitespace, newlines, braces, or other Caddyfile syntax.

use std::net::SocketAddr;

/// Normalize a bare domain name: trim and lowercase.
pub fn normalize_domain(domain: &str) -> String {
	domain.trim().to_ascii_lowercase()
}

/// Normalize a domain that may include the configured TLD suffix.
/// `myapp.test` becomes `myapp` when `tld` is `test`.
pub fn normalize_bare_domain(domain: &str, tld: &str) -> String {
	let domain = normalize_domain(domain);
	match domain.strip_suffix(&format!(".{tld}")) {
		Some(stripped) => stripped.to_owned(),
		None => domain,
	}
}

/// Validate a bare domain name (without the TLD) and its resulting FQDN length.
pub fn validate_domain(domain: &str, tld: &str) -> Result<(), String> {
	if domain.len() + 1 + tld.len() > 253 {
		return Err(format!("domain too long: {domain:?}"));
	}
	validate_domain_labels(domain)
}

/// Validate the labels of a bare domain name, without knowing the TLD.
/// Used by clients, which do not necessarily know the host's TLD.
pub fn validate_domain_labels(domain: &str) -> Result<(), String> {
	if domain.is_empty() {
		return Err("domain is empty".into());
	}
	for label in domain.split('.') {
		validate_label(label)?;
	}
	Ok(())
}

/// A name directly under the TLD (`app` in `app.test`). These are fragile:
/// they are cross-site with every other project's names and collide across projects.
pub fn is_single_label(domain: &str) -> bool {
	!domain.contains('.')
}

/// Hint shown when a single-label name is registered.
pub const SINGLE_LABEL_HINT: &str =
	"Prefer <service>.<project>.<tld>, for example app.example.test. Single-label names collide across projects.";

/// Whether a name is inside a token's prefix scope.
/// A prefix `example` covers `example` and `app.example`, not `badexample`.
pub fn name_in_scope(domain: &str, prefix: &str) -> bool {
	if prefix.is_empty() {
		return true;
	}
	domain == prefix || domain.ends_with(&format!(".{prefix}"))
}

/// Validate a target: a bare port, `host:port`, `ip:port`, or `[ipv6]:port`.
pub fn validate_target(target: &str) -> Result<(), String> {
	if target.is_empty() {
		return Err("target is empty".into());
	}
	if target.len() > 512 {
		return Err("target too long".into());
	}

	if let Ok(port) = target.parse::<u16>() {
		return validate_port(port);
	}
	if target.parse::<SocketAddr>().is_ok() {
		return Ok(());
	}

	let Some((host, port)) = target.rsplit_once(':') else {
		return Err(format!("target must be a port, host:port, or ip:port: {target:?}"));
	};
	let port: u16 = port.parse().map_err(|_| format!("invalid port in target: {target:?}"))?;
	validate_port(port)?;

	if host.is_empty() {
		return Err(format!("missing host in target: {target:?}"));
	}
	if host.len() > 253 {
		return Err(format!("host too long in target: {target:?}"));
	}
	for label in host.split('.') {
		validate_label(label)?;
	}
	Ok(())
}

fn validate_label(label: &str) -> Result<(), String> {
	if label.is_empty() {
		return Err("empty label in domain".into());
	}
	if label.len() > 63 {
		return Err(format!("label too long: {label:?}"));
	}
	if label.starts_with('-') || label.ends_with('-') {
		return Err(format!("label starts or ends with a hyphen: {label:?}"));
	}
	if !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
		return Err(format!("invalid character in label: {label:?}"));
	}
	Ok(())
}

fn validate_port(port: u16) -> Result<(), String> {
	if port == 0 {
		return Err("port 0 is not a valid proxy target".into());
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn accepts_valid_domains() {
		assert!(validate_domain("myapp", "test").is_ok());
		assert!(validate_domain("api.myapp", "test").is_ok());
		assert!(validate_domain("my-app2", "test").is_ok());
		assert!(validate_domain("a", "test").is_ok());
	}

	#[test]
	fn rejects_invalid_domains() {
		assert!(validate_domain("", "test").is_err());
		assert!(validate_domain("my app.test", "test").is_err());
		assert!(validate_domain("my app", "test").is_err());
		assert!(validate_domain("myapp{", "test").is_err());
		assert!(validate_domain("-myapp", "test").is_err());
		assert!(validate_domain("myapp-", "test").is_err());
		assert!(validate_domain("my..app", "test").is_err());
		assert!(validate_domain("app\nfoo", "test").is_err());
		assert!(validate_domain(&"a".repeat(64), "test").is_err());
		assert!(validate_domain(&"a".repeat(250), "test").is_err());
	}

	#[test]
	fn prefix_scope_respects_label_boundaries() {
		assert!(name_in_scope("example", "example"));
		assert!(name_in_scope("app.example", "example"));
		assert!(name_in_scope("api.app.example", "example"));
		assert!(!name_in_scope("badexample", "example"));
		assert!(!name_in_scope("example.dev", "example"));
		assert!(name_in_scope("anything.dev", ""));
	}

	#[test]
	fn detects_single_label_names() {
		assert!(is_single_label("app"));
		assert!(!is_single_label("app.example"));
		assert!(!is_single_label("a.b.c"));
	}

	#[test]
	fn normalizes_tld_suffix() {
		assert_eq!(normalize_bare_domain("MyApp.test", "test"), "myapp");
		assert_eq!(normalize_bare_domain("MyApp", "test"), "myapp");
		assert_eq!(normalize_bare_domain("test", "test"), "test");
		assert_eq!(normalize_bare_domain(" myapp ", "test"), "myapp");
	}

	#[test]
	fn accepts_valid_targets() {
		assert!(validate_target("3000").is_ok());
		assert!(validate_target("10.0.0.5:3000").is_ok());
		assert!(validate_target("host.docker.internal:3000").is_ok());
		assert!(validate_target("[::1]:3000").is_ok());
	}

	#[test]
	fn rejects_invalid_targets() {
		assert!(validate_target("").is_err());
		assert!(validate_target("0").is_err());
		assert!(validate_target("65536").is_err());
		assert!(validate_target(":3000").is_err());
		assert!(validate_target("myapp:0").is_err());
		assert!(validate_target("my app:3000").is_err());
		assert!(validate_target("myapp:3000\n}").is_err());
		assert!(validate_target("myapp {").is_err());
	}
}
