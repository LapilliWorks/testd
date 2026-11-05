//! DNS resolution for registered domains through a local DNS server.

pub mod dns;

use std::io;
use std::net::Ipv4Addr;

/// A name and the IPv4 address the browser should reach for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
	pub domain: String,
	pub address: Ipv4Addr,
}

impl ResolvedName {
	pub fn new(domain: impl Into<String>, address: Ipv4Addr) -> Self {
		Self { domain: domain.into(), address }
	}
}

/// A resolver applies the current name table to the system's DNS resolution.
pub trait Resolver: Send + Sync {
	/// Update resolution to reflect the current names.
	fn apply(&self, names: &[ResolvedName]) -> io::Result<()>;

	/// Make sure the OS routes `.<tld>` queries here. Called lazily, on the
	/// first registration from another machine, so a local-only host never
	/// needs root or touches the system resolver.
	fn ensure_os(&self) -> io::Result<()> {
		Ok(())
	}

	/// Whether the OS already routes `.<tld>` queries here.
	fn is_os_configured(&self) -> bool {
		true
	}

	/// Clear the registered names when the daemon stops.
	fn cleanup(&self) -> io::Result<()>;
}
