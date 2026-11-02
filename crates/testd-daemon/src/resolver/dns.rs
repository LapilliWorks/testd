//! DNS resolver: runs a minimal DNS server answering queries for registered domains.
//!
//! The server listens on a local UDP port and responds to A record queries for
//! domains in the registration set. All other queries get NXDOMAIN.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use simple_dns::rdata::{A, RData};
use simple_dns::{Packet, PacketFlag, QCLASS, QTYPE, Question, ResourceRecord};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use super::{ResolvedName, Resolver};
use testd_core::config::DEFAULT_DNS_PORT;

/// Shared state between the DNS server task and the resolver interface.
type DomainMap = Arc<RwLock<HashMap<String, Ipv4Addr>>>;

pub struct DnsResolver {
	tld: String,
	domains: DomainMap,
	listen_addr: SocketAddr,
	answer_addr: Ipv4Addr,
	elevation: testd_setup::Elevation,
}

impl DnsResolver {
	/// Create a new DNS resolver and start the server task.
	pub async fn start(tld: &str, answer_addr: Ipv4Addr, elevation: testd_setup::Elevation) -> io::Result<Self> {
		let listen_addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_PORT));
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));

		let socket = UdpSocket::bind(listen_addr).await?;
		let server_domains = domains.clone();
		let server_tld = tld.to_owned();

		tokio::spawn(async move {
			if let Err(e) = run_server(socket, server_domains, &server_tld).await {
				eprintln!("DNS server error: {e}");
			}
		});

		Ok(Self { tld: tld.to_owned(), domains, listen_addr, answer_addr, elevation })
	}

	/// The address the DNS server is listening on.
	pub fn listen_addr(&self) -> SocketAddr {
		self.listen_addr
	}
}

impl Resolver for DnsResolver {
	fn ensure_os(&self) -> io::Result<()> {
		if self.tld == "localhost" {
			return Ok(());
		}
		if testd_setup::is_os_resolver_configured(&self.tld, self.listen_addr) {
			return Ok(());
		}
		eprintln!("[resolver] configuring .{} to {}\n", self.tld, self.listen_addr);
		self.elevation.setup_os_resolver(&self.tld, self.listen_addr)
	}

	fn is_os_configured(&self) -> bool {
		self.tld == "localhost" || testd_setup::is_os_resolver_configured(&self.tld, self.listen_addr)
	}

	fn apply(&self, names: &[ResolvedName]) -> io::Result<()> {
		let mut map = HashMap::new();
		// Built-in domain always resolves to the answer address too.
		map.insert(format!("testd.{}", self.tld), self.answer_addr);
		for name in names {
			map.insert(name.domain.clone(), name.address);
		}

		// Update the shared state. block_in_place is fine: the lock is uncontended.
		let domains = self.domains.clone();
		tokio::task::block_in_place(|| {
			let rt = tokio::runtime::Handle::current();
			rt.block_on(async {
				let mut lock = domains.write().await;
				*lock = map;
			});
		});

		Ok(())
	}

	fn cleanup(&self) -> io::Result<()> {
		self.apply(&[])
	}
}

/// Run the DNS server loop, answering queries from the domain map.
async fn run_server(socket: UdpSocket, domains: DomainMap, tld: &str) -> io::Result<()> {
	let mut buf = vec![0u8; 512];

	loop {
		let (len, src) = socket.recv_from(&mut buf).await?;
		let response = match handle_query(&buf[..len], &domains, tld).await {
			Ok(data) => data,
			Err(()) => continue, // Malformed query: drop it
		};
		socket.send_to(&response, src).await?;
	}
}

/// Parse a DNS query and build a response.
async fn handle_query(query_bytes: &[u8], domains: &DomainMap, tld: &str) -> Result<Vec<u8>, ()> {
	let query = Packet::parse(query_bytes).map_err(|_| ())?;
	let mut response = query.into_reply();
	response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);

	let tld_suffix = format!(".{tld}");
	let mut unknown_name = false;

	for question in response.questions.iter() {
		// simple_dns omits the trailing dot; normalize to be safe.
		let name = question.qname.to_string();
		let name = name.trim_end_matches('.');

		if question.qtype != QTYPE::TYPE(simple_dns::TYPE::A) || question.qclass != QCLASS::CLASS(simple_dns::CLASS::IN)
		{
			continue;
		}

		if !name.ends_with(&tld_suffix) {
			// Not our zone: answer authoritatively with NXDOMAIN.
			unknown_name = true;
			continue;
		}

		let map = domains.read().await;

		match map.get(name) {
			Some(&ip) => push_a(&mut response.answers, question, ip),
			None => unknown_name = true,
		}
	}

	if response.answers.is_empty() && unknown_name {
		*response.rcode_mut() = simple_dns::RCODE::NameError;
	}

	response.build_bytes_vec().map_err(|_| ())
}

fn push_a<'a>(answers: &mut Vec<ResourceRecord<'a>>, question: &Question<'a>, ip: Ipv4Addr) {
	let rdata = RData::A(A { address: u32::from(ip) });
	let record = ResourceRecord::new(question.qname.clone(), simple_dns::CLASS::IN, 5, rdata);
	answers.push(record);
}

#[cfg(test)]
mod tests {
	use super::*;
	use simple_dns::{CLASS, TYPE, Name, QCLASS, QTYPE, Question, RCODE};

	fn query(name: &str) -> Vec<u8> {
		let mut packet = Packet::new_query(1);
		packet.questions.push(Question::new(
			Name::new(name).unwrap(),
			QTYPE::TYPE(TYPE::A),
			QCLASS::CLASS(CLASS::IN),
			false,
		));
		packet.build_bytes_vec().unwrap()
	}

	#[tokio::test]
	async fn known_name_resolves_and_unknown_name_is_nxdomain() {
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
		domains.write().await.insert("myapp.test".into(), Ipv4Addr::LOCALHOST);

		let reply = handle_query(&query("myapp.test"), &domains, "test").await.unwrap();
		let packet = Packet::parse(&reply).unwrap();
		assert_eq!(packet.rcode(), RCODE::NoError);
		assert_eq!(packet.answers.len(), 1);

		let reply = handle_query(&query("nope.test"), &domains, "test").await.unwrap();
		let packet = Packet::parse(&reply).unwrap();
		assert_eq!(packet.rcode(), RCODE::NameError);
		assert!(packet.answers.is_empty());

		// Names outside the configured zone are not ours to answer.
		let reply = handle_query(&query("other.dev"), &domains, "test").await.unwrap();
		let packet = Packet::parse(&reply).unwrap();
		assert_eq!(packet.rcode(), RCODE::NameError);
	}
}
