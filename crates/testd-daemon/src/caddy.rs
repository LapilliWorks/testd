//! Caddy integration for users who keep an external front.
//!
//! The built-in edge serves HTTPS directly; Caddy is optional. This module only
//! reloads a global config and probes the edge state.

use std::io;
use std::path::Path;

/// Reload Caddy so a changed global config takes effect.
pub async fn reload(config_path: &Path) -> io::Result<()> {
	let binary = testd_core::config::find_caddy_binary()
		.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "caddy not found"))?;
	let output = tokio::process::Command::new(binary)
		.args(["reload", "--config"])
		.arg(config_path)
		.stdout(std::process::Stdio::null())
		.stderr(std::process::Stdio::piped())
		.output()
		.await?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(io::Error::other(format!("Caddy reload failed: {}", stderr.trim())));
	}
	Ok(())
}

/// Health of the HTTPS edge: something serves `testd.{tld}` with a trusted certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeStatus {
	/// The edge serves the domain and the certificate validates against system roots.
	Trusted,
	/// The edge serves the domain but the certificate is not trusted.
	Untrusted,
	/// Nothing is serving the domain on the edge port.
	Unreachable,
	/// Could not determine the state (curl missing, timeout, unexpected error).
	Unknown,
}

/// Probe the HTTPS edge for `testd.{tld}` on `port` via loopback, bypassing DNS.
///
/// Two requests: an insecure one to establish whether the edge serves the domain
/// at all, then a verifying one to check system trust. Both are GET requests.
pub fn probe(tld: &str, port: u16) -> EdgeStatus {
	let host = format!("testd.{tld}");
	let insecure = match curl_exit(&host, port, true) {
		None => return EdgeStatus::Unknown,
		Some(code) => code,
	};
	if insecure != 0 {
		return EdgeStatus::Unreachable;
	}
	classify(curl_exit(&host, port, false))
}

/// Build curl arguments for a GET request to `https://{host}/ok.svg` via loopback.
fn probe_args(host: &str, port: u16, insecure: bool) -> Vec<String> {
	let mut args: Vec<String> = [
		"--silent",
		"--show-error",
		"--max-time",
		"2",
		// Never route the probe through an HTTP proxy (corporate proxies would
		// otherwise turn a healthy local edge into "unreachable").
		"--noproxy",
		"*",
		"--resolve",
	]
	.iter()
	.map(|arg| (*arg).to_owned())
	.collect();
	args.push(format!("{host}:{port}:127.0.0.1"));
	if insecure {
		args.push("--insecure".into());
	}
	// Schannel treats a private root's missing revocation information as an
	// error. The probe is loopback-only, so skipping revocation is safe.
	#[cfg(windows)]
	args.push("--ssl-no-revoke".into());
	args.push(format!("https://{host}:{port}/ok.svg"));
	args
}

/// Run the probe request. Returns curl's exit code, or `None` when curl is unavailable.
fn curl_exit(host: &str, port: u16, insecure: bool) -> Option<i32> {
	std::process::Command::new(curl_binary())
		.args(probe_args(host, port, insecure))
		.output()
		.ok()
		.and_then(|out| out.status.code())
}

fn curl_binary() -> std::path::PathBuf {
	#[cfg(windows)]
	{
		// Prefer the inbox Schannel build; PATH may point at a different curl
		// in an elevated or shimmed environment.
		let system = std::path::PathBuf::from(r"C:\Windows\System32\curl.exe");
		if system.is_file() {
			return system;
		}
		std::path::PathBuf::from("curl.exe")
	}
	#[cfg(not(windows))]
	{
		std::path::PathBuf::from("curl")
	}
}

fn classify(code: Option<i32>) -> EdgeStatus {
	match code {
		Some(0) => EdgeStatus::Trusted,
		// 60: certificate verify failed, 77: CA certificate problem.
		Some(60) | Some(77) => EdgeStatus::Untrusted,
		// 7: connection refused, 28: timeout.
		Some(7) | Some(28) => EdgeStatus::Unreachable,
		_ => EdgeStatus::Unknown,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn probe_bypasses_proxy_and_uses_loopback() {
		let args = probe_args("testd.test", 443, false);
		assert!(args.windows(2).any(|pair| pair[0] == "--noproxy" && pair[1] == "*"));
		assert!(
			args.windows(2)
				.any(|pair| pair[0] == "--resolve" && pair[1] == "testd.test:443:127.0.0.1")
		);
		assert_eq!(args.last().unwrap(), "https://testd.test:443/ok.svg");
		assert!(!args.iter().any(|arg| arg == "--insecure"));

		let insecure = probe_args("testd.test", 8443, true);
		assert!(insecure.iter().any(|arg| arg == "--insecure"));
		assert!(
			insecure
				.windows(2)
				.any(|pair| pair[0] == "--resolve" && pair[1] == "testd.test:8443:127.0.0.1")
		);
	}

	#[test]
	fn curl_exit_codes_map_to_status() {
		assert_eq!(classify(Some(0)), EdgeStatus::Trusted);
		assert_eq!(classify(Some(60)), EdgeStatus::Untrusted);
		assert_eq!(classify(Some(77)), EdgeStatus::Untrusted);
		assert_eq!(classify(Some(7)), EdgeStatus::Unreachable);
		assert_eq!(classify(Some(28)), EdgeStatus::Unreachable);
		assert_eq!(classify(Some(1)), EdgeStatus::Unknown);
		assert_eq!(classify(None), EdgeStatus::Unknown);
	}
}
