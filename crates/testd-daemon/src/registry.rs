//! Claim registry: name ownership and eviction.
//!
//! Ownership is `(name, connection)`. A claim belongs to the connection that
//! created it; a different connection may only take it over with `force`, and
//! disconnecting only evicts the claims that connection owns.
//!
//! A claim carries no identity; the connection is the whole owner.

use std::collections::HashMap;

use testd_core::Registration;

/// A registration plus the connection that owns it.
#[derive(Debug, Clone)]
pub struct Claim {
	pub registration: Registration,
	pub connection: u64,
}

/// Why a registration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
	/// Another connection owns the name.
	Duplicate { owner: u64 },
	/// The name is managed by the engine itself.
	Reserved,
}

impl std::fmt::Display for RegisterError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Duplicate { owner } => write!(f, "name is already registered by connection {owner}"),
			Self::Reserved => write!(f, "name is reserved"),
		}
	}
}

/// Why a deregistration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeregisterError {
	NotFound,
	NotOwner { owner: u64 },
}

/// Result of a successful registration: the claim it displaced, if any.
#[derive(Debug, Default)]
pub struct Registered {
	pub displaced: Option<Claim>,
}

#[derive(Debug, Default)]
pub struct Registry {
	claims: HashMap<String, Claim>,
	/// Extra names the edge answers, such as a tailnet name for a share. They
	/// have no owning connection: the share manager adds and removes them.
	aliases: HashMap<String, Registration>,
	next_connection: u64,
}

impl Registry {
	/// Allocate an id for a new client connection.
	pub fn connection_id(&mut self) -> u64 {
		self.next_connection += 1;
		self.next_connection
	}

	pub fn len(&self) -> usize {
		self.claims.len()
	}

	pub fn is_empty(&self) -> bool {
		self.claims.is_empty()
	}

	/// One claim by name, with the connection that owns it.
	pub fn claim(&self, domain: &str) -> Option<&Claim> {
		self.claims.get(domain)
	}

	/// Every claim with its owning connection, for the dashboard.
	pub fn claims(&self) -> Vec<Claim> {
		let mut claims: Vec<Claim> = self.claims.values().cloned().collect();
		claims.sort_by(|a, b| a.registration.domain.cmp(&b.registration.domain));
		claims
	}

	/// Register a claim for a connection.
	///
	/// Re-registering an owned name updates its target. A name owned by another
	/// connection is rejected unless `force` is set. `reserved` lists names the
	/// engine manages itself (e.g. the dashboard).
	pub fn register(
		&mut self,
		connection: u64,
		registration: Registration,
		force: bool,
		reserved: &[&str],
	) -> Result<Registered, RegisterError> {
		if reserved.contains(&registration.domain.as_str()) {
			return Err(RegisterError::Reserved);
		}

		let displaced = match self.claims.get(&registration.domain) {
			Some(existing) if existing.connection != connection && !force => {
				return Err(RegisterError::Duplicate { owner: existing.connection });
			},
			Some(existing) if existing.connection != connection => Some(existing.clone()),
			_ => None,
		};

		self.claims
			.insert(registration.domain.clone(), Claim { registration, connection });
		Ok(Registered { displaced })
	}

	/// Remove a claim owned by this connection.
	pub fn deregister(&mut self, connection: u64, domain: &str) -> Result<Registration, DeregisterError> {
		let Some(existing) = self.claims.get(domain) else {
			return Err(DeregisterError::NotFound);
		};
		if existing.connection != connection {
			return Err(DeregisterError::NotOwner { owner: existing.connection });
		}
		Ok(self.claims.remove(domain).expect("checked above").registration)
	}

	/// Remove a claim regardless of owner (dashboard / operator action).
	pub fn deregister_any(&mut self, domain: &str) -> Option<Claim> {
		self.claims.remove(domain)
	}

	/// Roll back a registration that could not be published.
	pub fn restore(&mut self, connection: u64, domain: &str, previous: Option<Claim>) {
		match previous {
			Some(claim) => {
				self.claims.insert(domain.to_owned(), claim);
			},
			None => self.release_one(connection, domain),
		}
	}

	/// Remove a specific claim if a connection still owns it.
	pub fn release_one(&mut self, connection: u64, domain: &str) {
		if self.claims.get(domain).is_some_and(|claim| claim.connection == connection) {
			self.claims.remove(domain);
		}
	}

	/// Remove every claim owned by a connection. Returns what was removed.
	pub fn release(&mut self, connection: u64) -> Vec<Registration> {
		let domains: Vec<String> = self
			.claims
			.iter()
			.filter(|(_, claim)| claim.connection == connection)
			.map(|(domain, _)| domain.clone())
			.collect();
		domains
			.into_iter()
			.filter_map(|domain| self.claims.remove(&domain).map(|claim| claim.registration))
			.collect()
	}

	/// Local registrations only, sorted by name.
	pub fn local_snapshot(&self) -> Vec<Registration> {
		let mut regs: Vec<Registration> = self.claims.values().map(|claim| claim.registration.clone()).collect();
		regs.sort_by(|a, b| a.domain.cmp(&b.domain));
		regs
	}

	/// Point the edge at `target` for `domain` without a client claim.
	pub fn set_alias(&mut self, domain: &str, target: &str) {
		self.aliases
			.insert(domain.to_owned(), Registration { domain: domain.to_owned(), target: target.to_owned() });
	}

	/// Drop an alias. Returns whether it existed.
	pub fn remove_alias(&mut self, domain: &str) -> bool {
		self.aliases.remove(domain).is_some()
	}

	/// Names the edge answers on a share's behalf. They are not registrations,
	/// so the dashboard lists them as shares instead of as active names.
	pub fn aliases(&self) -> Vec<Registration> {
		let mut names: Vec<Registration> = self.aliases.values().cloned().collect();
		names.sort_by(|a, b| a.domain.cmp(&b.domain));
		names
	}

	/// Current serving registrations, aliases included, sorted by name.
	pub fn snapshot(&self) -> Vec<Registration> {
		let mut merged: HashMap<String, Registration> = self
			.claims
			.iter()
			.map(|(domain, claim)| (domain.clone(), claim.registration.clone()))
			.collect();
		for (domain, registration) in &self.aliases {
			merged.insert(domain.clone(), registration.clone());
		}
		let mut regs: Vec<Registration> = merged.into_values().collect();
		regs.sort_by(|a, b| a.domain.cmp(&b.domain));
		regs
	}

	pub fn contains(&self, domain: &str) -> bool {
		self.claims.contains_key(domain) || self.aliases.contains_key(domain)
	}

	/// Look up a single live registration. Aliases win over client claims.
	pub fn get(&self, domain: &str) -> Option<Registration> {
		self.aliases
			.get(domain)
			.cloned()
			.or_else(|| self.claims.get(domain).map(|claim| claim.registration.clone()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn registration(domain: &str, target: &str) -> Registration {
		Registration { domain: domain.into(), target: target.into() }
	}

	#[test]
	fn a_second_connection_needs_force_to_take_a_name() {
		let mut registry = Registry::default();
		let first = registry.connection_id();
		let second = registry.connection_id();
		registry
			.register(first, registration("app.test", "127.0.0.1:3000"), false, &[])
			.unwrap();

		let rejected = registry
			.register(second, registration("app.test", "127.0.0.1:4000"), false, &[])
			.unwrap_err();
		assert_eq!(rejected, RegisterError::Duplicate { owner: first });

		let taken = registry
			.register(second, registration("app.test", "127.0.0.1:4000"), true, &[])
			.unwrap();
		assert_eq!(taken.displaced.unwrap().connection, first);
		assert_eq!(registry.get("app.test").unwrap().target, "127.0.0.1:4000");
	}

	#[test]
	fn only_the_owner_can_deregister() {
		let mut registry = Registry::default();
		let first = registry.connection_id();
		let second = registry.connection_id();
		registry
			.register(first, registration("app.test", "127.0.0.1:3000"), false, &[])
			.unwrap();

		assert_eq!(registry.deregister(second, "app.test").unwrap_err(), DeregisterError::NotOwner { owner: first });
		assert_eq!(registry.deregister(first, "app.test").unwrap().domain, "app.test");
		assert!(registry.get("app.test").is_none());
	}

	#[test]
	fn releasing_a_connection_leaves_other_claims() {
		let mut registry = Registry::default();
		let first = registry.connection_id();
		let second = registry.connection_id();
		registry
			.register(first, registration("one.test", "127.0.0.1:3000"), false, &[])
			.unwrap();
		registry
			.register(second, registration("two.test", "127.0.0.1:4000"), false, &[])
			.unwrap();

		let released = registry.release(first);
		assert_eq!(released.len(), 1);
		assert_eq!(registry.local_snapshot().len(), 1);
		assert!(registry.get("two.test").is_some());
	}

	#[test]
	fn reserved_names_are_refused() {
		let mut registry = Registry::default();
		let connection = registry.connection_id();
		assert_eq!(
			registry
				.register(connection, registration("testd.test", "127.0.0.1:3000"), false, &["testd.test"])
				.unwrap_err(),
			RegisterError::Reserved
		);
	}

	#[test]
	fn an_alias_is_served_beside_claims_and_leaves_with_the_share() {
		let mut registry = Registry::default();
		let connection = registry.connection_id();
		registry
			.register(connection, registration("app.test", "192.168.1.9:3000"), false, &[])
			.unwrap();
		registry.set_alias("node.tail.ts.net", "192.168.1.9:3000");

		assert_eq!(registry.snapshot().len(), 2);
		assert_eq!(registry.aliases().len(), 1);
		assert!(registry.contains("node.tail.ts.net"));

		assert!(registry.remove_alias("node.tail.ts.net"));
		assert!(!registry.contains("node.tail.ts.net"));
		assert_eq!(registry.snapshot().len(), 1);
	}
}
