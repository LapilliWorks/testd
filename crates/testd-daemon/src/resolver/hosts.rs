//! Hosts file resolver: invokes the `testd-hosts-helper` script via sudo
//! to write a managed block in `/etc/hosts`.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{ResolvedName, Resolver};

pub struct HostsResolver {
	tld: String,
	helper_path: PathBuf,
	hosts_path: PathBuf,
}

impl HostsResolver {
	pub fn new(tld: &str, helper_path: &Path, hosts_path: &Path) -> Self {
		Self { tld: tld.to_owned(), helper_path: helper_path.to_owned(), hosts_path: hosts_path.to_owned() }
	}

	/// Invoke the helper script via sudo, piping domain list to stdin.
	fn invoke(&self, names: &[ResolvedName]) -> io::Result<()> {
		let mut child = Command::new("sudo")
			.arg("--non-interactive")
			.arg(&self.helper_path)
			.arg("--tld")
			.arg(&self.tld)
			.arg("--hosts-path")
			.arg(&self.hosts_path)
			.stdin(std::process::Stdio::piped())
			.stderr(std::process::Stdio::piped())
			.spawn()?;

		// Write NDJSON domain list to stdin.
		if let Some(mut stdin) = child.stdin.take() {
			use std::io::Write;
			for name in names {
				writeln!(stdin, "\"{}\"", name.domain)?;
			}
		}

		let output = child.wait_with_output()?;
		if output.status.success() {
			Ok(())
		} else {
			let stderr = String::from_utf8_lossy(&output.stderr);
			Err(io::Error::other(format!("hosts helper failed: {}", stderr.trim())))
		}
	}
}

impl Resolver for HostsResolver {
	fn apply(&self, names: &[ResolvedName]) -> io::Result<()> {
		// Mirror the DNS backend: the dashboard name resolves even with no
		// registrations, so `testd.<tld>` must be in the hosts block.
		let mut all = Vec::with_capacity(names.len() + 1);
		all.push(ResolvedName::new(format!("testd.{}", self.tld), std::net::Ipv4Addr::LOCALHOST));
		all.extend_from_slice(names);
		self.invoke(&all)
	}

	fn cleanup(&self) -> io::Result<()> {
		self.invoke(&[])
	}
}
