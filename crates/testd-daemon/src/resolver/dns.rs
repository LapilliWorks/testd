//! DNS resolver: runs a minimal DNS server answering queries for registered domains.
//!
//! The server listens on a local UDP port and responds to A record queries for
//! registered domains. Unknown A names get NXDOMAIN; other types receive no answer.

use std::collections::{HashMap, hash_map::Entry};
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
		let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_PORT))).await?;
		Self::start_with_socket(tld, answer_addr, elevation, socket)
	}

	/// Start with an already-bound loopback socket in a Tokio runtime.
	pub fn start_with_socket(
		tld: &str,
		answer_addr: Ipv4Addr,
		elevation: testd_setup::Elevation,
		socket: UdpSocket,
	) -> io::Result<Self> {
		let listen_addr = socket.local_addr()?;
		check_loopback(listen_addr)?;
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
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

fn check_loopback(addr: SocketAddr) -> io::Result<()> {
	if !addr.ip().is_loopback() {
		return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS listener must bind to loopback"));
	}
	Ok(())
}

impl Resolver for DnsResolver {
	fn ensure_os(&self) -> io::Result<()> {
		if testd_setup::is_os_resolver_configured(&self.tld, self.listen_addr) {
			return Ok(());
		}
		eprintln!("[resolver] configuring .{} to {}\n", self.tld, self.listen_addr);
		self.elevation.setup_os_resolver(&self.tld, self.listen_addr)
	}

	fn is_os_configured(&self) -> bool {
		testd_setup::is_os_resolver_configured(&self.tld, self.listen_addr)
	}

	fn apply(&self, names: &[ResolvedName]) -> io::Result<()> {
		let mut map = HashMap::new();
		// Built-in domain always resolves to the answer address too.
		insert_domain(&mut map, &format!("testd.{}", self.tld), self.answer_addr)?;
		for name in names {
			insert_domain(&mut map, &name.domain, name.address)?;
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

fn canonical_name(name: &str) -> String {
	name.trim_end_matches('.').to_ascii_lowercase()
}

fn insert_domain(domains: &mut HashMap<String, Ipv4Addr>, name: &str, address: Ipv4Addr) -> io::Result<()> {
	match domains.entry(canonical_name(name)) {
		Entry::Vacant(entry) => {
			entry.insert(address);
			Ok(())
		},
		Entry::Occupied(entry) if *entry.get() == address => Ok(()),
		Entry::Occupied(entry) => Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("conflicting DNS addresses for {}: {} and {address}", entry.key(), entry.get()),
		)),
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

	let tld_suffix = format!(".{}", canonical_name(tld));
	let mut unknown_name = false;

	for question in response.questions.iter() {
		if question.qtype != QTYPE::TYPE(simple_dns::TYPE::A) || question.qclass != QCLASS::CLASS(simple_dns::CLASS::IN)
		{
			continue;
		}

		/* Display conversion must not merge label boundaries or replace invalid bytes. */
		if question
			.qname
			.as_bytes()
			.any(|label| label.contains(&b'.') || std::str::from_utf8(label).is_err())
		{
			unknown_name = true;
			continue;
		}
		let name = canonical_name(&question.qname.to_string());
		if !name.ends_with(&tld_suffix) {
			// Not our zone: answer authoritatively with NXDOMAIN.
			unknown_name = true;
			continue;
		}

		let map = domains.read().await;

		match map.get(&name) {
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

	#[test]
	fn supplied_listeners_must_be_loopback() {
		for address in ["127.0.0.1:1234", "[::1]:1234"] {
			assert!(check_loopback(address.parse().unwrap()).is_ok(), "{address}");
		}
		for address in ["0.0.0.0:1234", "192.0.2.1:1234", "[::]:1234", "[2001:db8::1]:1234"] {
			let error = check_loopback(address.parse().unwrap()).unwrap_err();
			assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{address}");
		}
	}

	fn query(name: &str, record_type: TYPE, class: CLASS) -> Vec<u8> {
		let mut packet = Packet::new_query(1);
		packet.questions.push(Question::new(
			Name::new(name).unwrap(),
			QTYPE::TYPE(record_type),
			QCLASS::CLASS(class),
			false,
		));
		packet.build_bytes_vec().unwrap()
	}

	#[tokio::test]
	async fn registered_a_queries_return_the_configured_address() {
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
		let address = Ipv4Addr::new(192, 0, 2, 42);
		domains.write().await.insert("myapp.test".into(), address);

		let reply = handle_query(&query("myapp.test", TYPE::A, CLASS::IN), &domains, "test")
			.await
			.unwrap();
		let packet = Packet::parse(&reply).unwrap();
		assert_eq!(packet.rcode(), RCODE::NoError);
		assert!(packet.has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
		assert_eq!(packet.answers.len(), 1);
		assert_eq!(packet.answers[0].rdata, RData::A(A { address: u32::from(address) }));
	}

	#[tokio::test]
	async fn unknown_names_and_other_zones_do_not_resolve() {
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
		domains.write().await.insert("myapp.test".into(), Ipv4Addr::LOCALHOST);

		for name in ["nope.test", "NOPE.TEST", "other.dev", "OTHER.DEV", "myapp.test.example", "myapptest"] {
			let reply = handle_query(&query(name, TYPE::A, CLASS::IN), &domains, "test").await.unwrap();
			let packet = Packet::parse(&reply).unwrap();
			assert_eq!(packet.rcode(), RCODE::NameError, "{name}");
			assert!(packet.answers.is_empty(), "{name}");
		}
	}

	#[tokio::test]
	async fn other_record_types_and_classes_never_return_an_a_record() {
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
		domains.write().await.insert("myapp.test".into(), Ipv4Addr::LOCALHOST);

		for (record_type, class) in [(TYPE::AAAA, CLASS::IN), (TYPE::A, CLASS::CH)] {
			let reply = handle_query(&query("myapp.test", record_type, class), &domains, "test")
				.await
				.unwrap();
			let packet = Packet::parse(&reply).unwrap();
			assert!(packet.answers.is_empty(), "{record_type:?} {class:?}");
		}
	}

	#[tokio::test]
	async fn dns_labels_are_case_insensitive() {
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
		domains.write().await.insert("myapp.test".into(), Ipv4Addr::LOCALHOST);

		for name in ["myapp.test", "MYAPP.TEST", "MYAPP.test", "myapp.TEST", "MyApP.TeSt", "MyApP.TeSt."] {
			let reply = handle_query(&query(name, TYPE::A, CLASS::IN), &domains, "test").await.unwrap();
			let packet = Packet::parse(&reply).unwrap();
			assert_eq!(packet.rcode(), RCODE::NoError, "{name}");
			assert_eq!(packet.answers.len(), 1, "{name}");
			assert_eq!(packet.answers[0].rdata, RData::A(A { address: u32::from(Ipv4Addr::LOCALHOST) }), "{name}");
			assert_eq!(packet.questions[0].qname.to_string(), name.trim_end_matches('.'));
			assert_eq!(packet.answers[0].name.to_string(), name.trim_end_matches('.'));
		}
	}

	async fn resolver(tld: &str) -> DnsResolver {
		let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		DnsResolver::start_with_socket(tld, Ipv4Addr::LOCALHOST, testd_setup::Elevation::Sudo, socket).unwrap()
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn applied_names_and_the_configured_zone_are_case_insensitive() {
		let resolver = resolver("TeSt").await;
		let address = Ipv4Addr::new(192, 0, 2, 42);
		resolver
			.apply(&[
				ResolvedName::new("MyApp.TeSt", address),
				ResolvedName::new("MYAPP.TEST", address),
				ResolvedName::new("myapp.test.", address),
			])
			.unwrap();

		for (name, expected) in [("myapp.test", address), ("MYAPP.TEST", address), ("TESTD.TEST", Ipv4Addr::LOCALHOST)]
		{
			let reply = handle_query(&query(name, TYPE::A, CLASS::IN), &resolver.domains, "TeSt")
				.await
				.unwrap();
			let packet = Packet::parse(&reply).unwrap();
			assert_eq!(packet.rcode(), RCODE::NoError, "{name}");
			assert_eq!(packet.answers.len(), 1, "{name}");
			assert_eq!(packet.answers[0].rdata, RData::A(A { address: u32::from(expected) }), "{name}");
		}
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn conflicting_case_variants_leave_the_previous_state_unchanged() {
		let resolver = resolver("test").await;
		let first = Ipv4Addr::new(192, 0, 2, 1);
		let second = Ipv4Addr::new(192, 0, 2, 2);
		resolver.apply(&[ResolvedName::new("kept.test", first)]).unwrap();

		for names in [
			vec![ResolvedName::new("New.test", first), ResolvedName::new("NEW.TEST", second)],
			vec![ResolvedName::new("TESTD.TEST", first)],
		] {
			let error = resolver.apply(&names).unwrap_err();
			assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
			assert!(error.to_string().contains("conflicting DNS addresses"));
			let reply = handle_query(&query("kept.test", TYPE::A, CLASS::IN), &resolver.domains, "test")
				.await
				.unwrap();
			let packet = Packet::parse(&reply).unwrap();
			assert_eq!(packet.rcode(), RCODE::NoError);
			assert_eq!(packet.answers.len(), 1);
			assert_eq!(packet.answers[0].rdata, RData::A(A { address: u32::from(first) }));
			let map = resolver.domains.read().await;
			assert_eq!(map.len(), 2);
			assert_eq!(map.get("kept.test"), Some(&first));
			assert_eq!(map.get("testd.test"), Some(&Ipv4Addr::LOCALHOST));
		}
	}

	#[tokio::test]
	async fn ambiguous_wire_labels_cannot_impersonate_mapped_names() {
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
		domains.write().await.insert("myapp.test".into(), Ipv4Addr::LOCALHOST);
		domains.write().await.insert("my\u{fffd}app.test".into(), Ipv4Addr::LOCALHOST);
		for label_bytes in [vec![&b"myapp.test"[..]], vec![&b"my\xffapp"[..], &b"test"[..]]] {
			let labels: Vec<_> = label_bytes.into_iter().map(simple_dns::Label::new_unchecked).collect();
			let mut packet = Packet::new_query(1);
			packet.questions.push(Question::new(
				Name::new_with_labels(&labels),
				QTYPE::TYPE(TYPE::A),
				QCLASS::CLASS(CLASS::IN),
				false,
			));
			let reply = handle_query(&packet.build_bytes_vec().unwrap(), &domains, "test")
				.await
				.unwrap();
			let reply = Packet::parse(&reply).unwrap();
			assert_eq!(reply.rcode(), RCODE::NameError, "{labels:?}");
			assert!(reply.answers.is_empty(), "{labels:?}");
		}
	}

	#[tokio::test]
	async fn malformed_queries_are_rejected() {
		let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
		for bytes in [&[][..], &[0, 1, 2, 3][..]] {
			assert!(handle_query(bytes, &domains, "test").await.is_err());
		}
	}
}
