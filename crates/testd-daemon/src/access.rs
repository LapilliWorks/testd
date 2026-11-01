//! Access requests and issued leaf tokens.
//!
//! A leaf without a credential asks the host for one. The request stays on its
//! connection until an operator approves or denies it from the dashboard or the
//! CLI. An approved token is persisted here so later runs authenticate without
//! another prompt and so a restart does not lock every leaf out.
//!
//! A token owns a set of granted names. Deleting one grant removes that name
//! from the token without touching its other names; publishing it again asks
//! the operator for a grant on that one name.
//!
//! The operator secret is a separate bootstrap credential. It stays in the
//! host config and is never handed to a remote leaf as part of this flow.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use testd_core::config::{config_dir, write_private};
use tokio::sync::{broadcast, oneshot, watch};

/// How long a request waits for an operator before the client is told it expired.
pub const REQUEST_TTL: Duration = Duration::from_secs(120);
/// Requests held at once, so an unauthenticated client cannot fill memory.
const MAX_PENDING: usize = 32;
/// Revocation ids kept for a listener that falls behind.
const REVOCATION_DEPTH: usize = 32;
/// Labels come from the client and are shown to the approver.
const MAX_LABEL: usize = 120;
/// Names one request may carry. A client cannot flood the approver.
const MAX_NAMES: usize = 64;

/// A credential the host issued to one leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedToken {
	pub id: String,
	pub token: String,
	pub label: String,
	/// Unix seconds.
	pub created_at: u64,
	#[serde(default)]
	pub last_seen_at: Option<u64>,
	/// Names this token may publish. `None` marks a token issued before
	/// per-name grants, which may publish any name.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub names: Option<Vec<String>>,
}

/// What the CLI and dashboard show for an issued token. The token itself is
/// deliberately absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenView {
	pub id: String,
	pub label: String,
	pub created_at: u64,
	pub last_seen_at: Option<u64>,
	/// The granted names, or `None` for a token that predates per-name grants.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub names: Option<Vec<String>>,
}

impl From<&IssuedToken> for TokenView {
	fn from(token: &IssuedToken) -> Self {
		Self {
			id: token.id.clone(),
			label: token.label.clone(),
			created_at: token.created_at,
			last_seen_at: token.last_seen_at,
			names: token.names.clone(),
		}
	}
}

/// What the CLI and dashboard show for a waiting request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingView {
	pub id: String,
	pub label: String,
	pub address: String,
	/// Names the operator is asked to grant.
	pub names: Vec<String>,
	pub requested_at: u64,
}

/// The operator's answer to a request.
#[derive(Debug)]
pub enum Decision {
	Approve(IssuedToken),
	/// A name was added to the grants of the leaf's existing token.
	ApproveName,
	Deny,
}

/// What an approval produced, for callers that need the issued token.
#[derive(Debug)]
pub enum Approved {
	Token(IssuedToken),
	Name,
}

/// The daemon's view of issued tokens and waiting requests.
pub struct Access {
	path: PathBuf,
	state: Mutex<State>,
	/// Waiting requests, published to frontends that show approval state.
	changes: watch::Sender<Vec<PendingView>>,
	/// Token ids published on revocation so live connections can be closed.
	revocations: broadcast::Sender<String>,
}

#[derive(Default)]
struct State {
	tokens: Vec<IssuedToken>,
	pending: HashMap<String, Pending>,
}

struct Pending {
	label: String,
	address: String,
	names: Vec<String>,
	kind: PendingKind,
	requested_at: u64,
	created: Instant,
	decision: oneshot::Sender<Decision>,
}

/// What approval of a request does.
enum PendingKind {
	/// Issue a new token that carries the requested names.
	Token,
	/// Add one name to the grants of an existing token.
	Name { token_id: String },
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TokenFile {
	#[serde(default)]
	tokens: Vec<IssuedToken>,
}

impl Access {
	/// Load issued tokens from `tokens.json` in the testd config directory.
	pub fn load_default() -> io::Result<Self> {
		Self::load(config_dir().join("tokens.json"))
	}

	/// Load issued tokens from `path`. A missing file is an empty store.
	pub fn load(path: PathBuf) -> io::Result<Self> {
		let state = match std::fs::read(&path) {
			Ok(data) => {
				let file: TokenFile = serde_json::from_slice(&data)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))?;
				State { tokens: file.tokens, pending: HashMap::new() }
			},
			Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
			Err(e) => return Err(e),
		};
		let (changes, _) = watch::channel(Vec::new());
		let (revocations, _) = broadcast::channel(REVOCATION_DEPTH);
		Ok(Self { path, state: Mutex::new(state), changes, revocations })
	}

	/// The current waiting list, also delivered as changes to frontends.
	pub fn changes(&self) -> watch::Receiver<Vec<PendingView>> {
		self.changes.subscribe()
	}

	/// Token ids as they are revoked. The engine closes their connections.
	pub fn revocations(&self) -> broadcast::Receiver<String> {
		self.revocations.subscribe()
	}

	/// Queue a token request for the operator. The returned receiver resolves
	/// when the request is approved or denied; dropping it cancels the wait.
	pub fn request(
		&self,
		label: &str,
		address: &str,
		names: Vec<String>,
	) -> Result<(String, oneshot::Receiver<Decision>), String> {
		let mut state = self.state.lock().expect("access lock poisoned");
		let names = clean_names(&names);
		self.enqueue(&mut state, clean_label(label), address.to_owned(), names, PendingKind::Token)
	}

	/// Queue a request for one more name on an existing token.
	pub fn request_name(
		&self,
		token_id: &str,
		name: &str,
		address: &str,
	) -> Result<(String, oneshot::Receiver<Decision>), String> {
		let mut state = self.state.lock().expect("access lock poisoned");
		let Some(token) = state.tokens.iter().find(|token| token.id == token_id) else {
			return Err("the grant for this connection no longer exists".into());
		};
		let label = token.label.clone();
		let names = clean_names(&[name.to_owned()]);
		self.enqueue(&mut state, label, address.to_owned(), names, PendingKind::Name { token_id: token_id.to_owned() })
	}

	fn enqueue(
		&self,
		state: &mut State,
		label: String,
		address: String,
		names: Vec<String>,
		kind: PendingKind,
	) -> Result<(String, oneshot::Receiver<Decision>), String> {
		let before = state.pending.len();
		state.pending.retain(|_, pending| pending.created.elapsed() < REQUEST_TTL);
		if state.pending.len() != before {
			self.publish(state);
		}
		if state.pending.len() >= MAX_PENDING {
			return Err("too many access requests are already waiting for approval".into());
		}

		let id = loop {
			let id = random_text(6);
			if !state.pending.contains_key(&id) {
				break id;
			}
		};
		let (decision, receiver) = oneshot::channel();
		state.pending.insert(
			id.clone(),
			Pending { label, address, names, kind, requested_at: now_secs(), created: Instant::now(), decision },
		);
		self.publish(state);
		Ok((id, receiver))
	}

	/// Forget a request, for example when the waiting connection closes.
	pub fn cancel(&self, id: &str) {
		let mut state = self.state.lock().expect("access lock poisoned");
		if state.pending.remove(id).is_some() {
			self.publish(&state);
		}
	}

	/// Approve a request. A token request issues a new token with the requested
	/// names; a name request adds one name to the token it names. The waiting
	/// connection hears about it only after the store is safely persisted.
	pub fn approve(&self, id: &str) -> Result<Approved, String> {
		let mut state = self.state.lock().expect("access lock poisoned");
		let Some(pending) = state.pending.remove(id) else {
			return Err(format!("request {id} is not pending"));
		};
		self.publish(&state);
		if pending.created.elapsed() >= REQUEST_TTL {
			return Err(format!("request {id} expired"));
		}

		match pending.kind {
			PendingKind::Token => {
				let token = new_token(&pending.label, pending.names.clone());
				state.tokens.push(token.clone());
				if let Err(e) = self.save(&state) {
					state.tokens.retain(|issued| issued.id != token.id);
					return Err(format!("failed to save the issued token: {e}"));
				}
				if pending.decision.send(Decision::Approve(token.clone())).is_err() {
					state.tokens.retain(|issued| issued.id != token.id);
					if let Err(e) = self.save(&state) {
						eprintln!("[warn]   failed to persist token removal: {e}");
					}
					return Err(format!("request {id} disconnected before the token was delivered"));
				}
				Ok(Approved::Token(token))
			},
			PendingKind::Name { token_id } => {
				let Some(index) = state.tokens.iter().position(|token| token.id == token_id) else {
					return Err(format!("request {id} refers to a grant that no longer exists"));
				};
				let Some(name) = pending.names.first().cloned() else {
					return Err(format!("request {id} names no domain"));
				};
				let before = state.tokens[index].names.clone();
				if let Some(names) = state.tokens[index].names.as_mut()
					&& !names.contains(&name)
				{
					names.push(name);
					if let Err(e) = self.save(&state) {
						state.tokens[index].names = before;
						return Err(format!("failed to save the token store: {e}"));
					}
				}
				// A legacy token already allowed every name, and a caller that
				// disconnected keeps the grant the operator approved.
				let _ = pending.decision.send(Decision::ApproveName);
				Ok(Approved::Name)
			},
		}
	}

	/// Refuse a request. The waiting connection is told it was denied.
	pub fn deny(&self, id: &str) -> Result<(), String> {
		let mut state = self.state.lock().expect("access lock poisoned");
		let Some(pending) = state.pending.remove(id) else {
			return Err(format!("request {id} is not pending"));
		};
		self.publish(&state);
		let _ = pending.decision.send(Decision::Deny);
		Ok(())
	}

	/// Waiting requests, oldest first, with expired ones removed.
	pub fn pending(&self) -> Vec<PendingView> {
		let mut state = self.state.lock().expect("access lock poisoned");
		let before = state.pending.len();
		state.pending.retain(|_, pending| pending.created.elapsed() < REQUEST_TTL);
		if state.pending.len() != before {
			self.publish(&state);
		}
		Self::snapshot(&state)
	}

	/// Issued tokens, oldest first. No secret is returned.
	pub fn tokens(&self) -> Vec<TokenView> {
		let state = self.state.lock().expect("access lock poisoned");
		let mut tokens: Vec<&IssuedToken> = state.tokens.iter().collect();
		tokens.sort_by_key(|token| (token.created_at, token.id.as_str()));
		tokens.into_iter().map(TokenView::from).collect()
	}

	/// Remove an issued token and every name it grants. Connections admitted
	/// with it are closed and their claims released by the engine; later
	/// connections are refused.
	pub fn revoke(&self, id: &str) -> Result<(), String> {
		let mut state = self.state.lock().expect("access lock poisoned");
		let Some(index) = state.tokens.iter().position(|token| token.id == id) else {
			return Err(format!("token {id} does not exist"));
		};
		let revoked = state.tokens.remove(index);
		if let Err(e) = self.save(&state) {
			state.tokens.insert(index, revoked);
			return Err(format!("failed to save the token store: {e}"));
		}
		drop(state);
		// Nobody listening only means no live connection used it.
		let _ = self.revocations.send(id.to_owned());
		Ok(())
	}

	/// Check a presented token and record that it was used.
	pub fn authenticate(&self, token: &str) -> Option<IssuedToken> {
		let mut state = self.state.lock().expect("access lock poisoned");
		let now = now_secs();
		let issued = state.tokens.iter_mut().find(|issued| issued.token == token)?;
		issued.last_seen_at = Some(now);
		let issued = issued.clone();
		if let Err(e) = self.save(&state) {
			eprintln!("[warn]   failed to record token use: {e}");
		}
		Some(issued)
	}

	/// Whether a token may publish `name`. A legacy token with no name list
	/// may publish any name.
	pub fn allows(&self, token_id: &str, name: &str) -> bool {
		let state = self.state.lock().expect("access lock poisoned");
		match state.tokens.iter().find(|token| token.id == token_id) {
			Some(token) => token
				.names
				.as_ref()
				.is_none_or(|names| names.iter().any(|granted| granted == name)),
			None => false,
		}
	}

	/// Delete the grant for one name. `live` is what the token publishes right
	/// now, used to pin a legacy token whose grant list predates per-name
	/// control. Other names keep their grants.
	pub fn remove_name(&self, token_id: &str, name: &str, live: &[String]) -> Result<(), String> {
		let mut state = self.state.lock().expect("access lock poisoned");
		let Some(index) = state.tokens.iter().position(|token| token.id == token_id) else {
			return Err(format!("token {token_id} does not exist"));
		};
		let before = state.tokens[index].names.clone();
		let source = before.as_deref().unwrap_or(live);
		let mut names: Vec<String> = source.iter().filter(|granted| granted.as_str() != name).cloned().collect();
		names.sort();
		names.dedup();
		state.tokens[index].names = Some(names);
		if let Err(e) = self.save(&state) {
			state.tokens[index].names = before;
			return Err(format!("failed to save the token store: {e}"));
		}
		Ok(())
	}

	fn snapshot(state: &State) -> Vec<PendingView> {
		let mut requests: Vec<PendingView> = state
			.pending
			.iter()
			.map(|(id, pending)| PendingView {
				id: id.clone(),
				label: pending.label.clone(),
				address: pending.address.clone(),
				names: pending.names.clone(),
				requested_at: pending.requested_at,
			})
			.collect();
		requests.sort_by_key(|request| request.requested_at);
		requests
	}

	fn publish(&self, state: &State) {
		let _ = self.changes.send(Self::snapshot(state));
	}

	fn save(&self, state: &State) -> io::Result<()> {
		if let Some(parent) = self.path.parent() {
			std::fs::create_dir_all(parent)?;
		}
		let file = TokenFile { tokens: state.tokens.clone() };
		let mut data = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
		data.push(b'\n');

		// Write then rename so a crash never leaves a half-written token store.
		let tmp = self.path.with_extension("json.tmp");
		write_private(&tmp, &data)?;
		std::fs::rename(&tmp, &self.path)
	}

	/// Path of the token store, for diagnostics and tests.
	pub fn path(&self) -> &Path {
		&self.path
	}
}

fn new_token(label: &str, names: Vec<String>) -> IssuedToken {
	IssuedToken {
		id: random_text(6),
		token: random_text(32),
		label: clean_label(label),
		created_at: now_secs(),
		last_seen_at: None,
		names: Some(clean_names(&names)),
	}
}

fn random_text(bytes: usize) -> String {
	let mut buffer = vec![0u8; bytes];
	getrandom::fill(&mut buffer).expect("failed to obtain random bytes");
	URL_SAFE_NO_PAD.encode(buffer)
}

fn now_secs() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn clean_names(names: &[String]) -> Vec<String> {
	let mut names: Vec<String> = names
		.iter()
		.map(|name| name.trim().to_owned())
		.filter(|name| !name.is_empty())
		.take(MAX_NAMES)
		.collect();
	names.sort();
	names.dedup();
	names
}

fn clean_label(label: &str) -> String {
	let cleaned: String = label.chars().filter(|c| !c.is_control()).take(MAX_LABEL).collect();
	let cleaned = cleaned.trim();
	if cleaned.is_empty() { "unknown client".into() } else { cleaned.to_owned() }
}

#[cfg(test)]
mod tests {
	use super::*;

	fn access() -> (tempfile::TempDir, Access) {
		let dir = tempfile::tempdir().unwrap();
		let access = Access::load(dir.path().join("tokens.json")).unwrap();
		(dir, access)
	}

	fn names(names: &[&str]) -> Vec<String> {
		names.iter().map(|name| (*name).to_owned()).collect()
	}

	#[tokio::test]
	async fn an_approved_request_issues_a_persisted_token() {
		let (dir, access) = access();
		let (id, decision) = access.request("alex@laptop", "192.168.1.9:5000", names(&["app.test"])).unwrap();
		assert_eq!(access.pending().len(), 1);

		let Approved::Token(issued) = access.approve(&id).unwrap() else { panic!("expected a token") };
		assert!(matches!(decision.await.unwrap(), Decision::Approve(token) if token.token == issued.token));
		assert!(access.pending().is_empty());
		assert_eq!(access.tokens().len(), 1);

		let reloaded = Access::load(dir.path().join("tokens.json")).unwrap();
		assert_eq!(reloaded.authenticate(&issued.token).unwrap().id, issued.id);

		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let mode = std::fs::metadata(reloaded.path()).unwrap().permissions().mode() & 0o777;
			assert_eq!(mode, 0o600);
		}
	}

	#[tokio::test]
	async fn a_denied_request_does_not_issue_a_token() {
		let (_dir, access) = access();
		let (id, decision) = access.request("alex@laptop", "192.168.1.9:5000", names(&["app.test"])).unwrap();
		access.deny(&id).unwrap();
		assert!(matches!(decision.await.unwrap(), Decision::Deny));
		assert!(access.tokens().is_empty());
		assert!(access.pending().is_empty());
	}

	#[tokio::test]
	async fn an_unknown_request_cannot_be_approved_or_denied() {
		let (_dir, access) = access();
		assert!(access.approve("missing").unwrap_err().contains("not pending"));
		assert!(access.deny("missing").unwrap_err().contains("not pending"));
	}

	#[tokio::test]
	async fn a_revoked_token_stops_authenticating() {
		let (_dir, access) = access();
		let (id, _decision) = access.request("alex@laptop", "192.168.1.9:5000", names(&["app.test"])).unwrap();
		let Approved::Token(issued) = access.approve(&id).unwrap() else { panic!("expected a token") };

		assert!(access.authenticate(&issued.token).is_some());
		access.revoke(&issued.id).unwrap();
		assert!(access.authenticate(&issued.token).is_none());
		assert!(access.revoke(&issued.id).unwrap_err().contains("does not exist"));
	}

	#[tokio::test]
	async fn a_revocation_is_published_for_live_connections() {
		let (_dir, access) = access();
		let (id, _decision) = access.request("alex@laptop", "192.168.1.9:5000", names(&["app.test"])).unwrap();
		let Approved::Token(issued) = access.approve(&id).unwrap() else { panic!("expected a token") };
		let mut revocations = access.revocations();

		access.revoke(&issued.id).unwrap();
		assert_eq!(revocations.recv().await.unwrap(), issued.id);
	}

	#[tokio::test]
	async fn a_cancelled_request_leaves_no_pending_entry() {
		let (_dir, access) = access();
		let (id, _decision) = access.request("alex@laptop", "192.168.1.9:5000", names(&["app.test"])).unwrap();
		access.cancel(&id);
		assert!(access.pending().is_empty());
		assert!(access.approve(&id).is_err());
	}

	#[test]
	fn labels_are_clean_and_bounded() {
		assert_eq!(clean_label("  alex@laptop\n"), "alex@laptop");
		assert_eq!(clean_label("\u{7}"), "unknown client");
		assert_eq!(clean_label(&"x".repeat(500)).len(), MAX_LABEL);
	}

	#[tokio::test]
	async fn changes_report_waiting_requests() {
		let (_dir, access) = access();
		let mut changes = access.changes();
		assert!(changes.borrow().is_empty());

		let (id, _decision) = access.request("alex@laptop", "192.168.1.9:5000", names(&["app.test"])).unwrap();
		changes.changed().await.unwrap();
		assert_eq!(changes.borrow_and_update().len(), 1);

		access.deny(&id).unwrap();
		changes.changed().await.unwrap();
		assert!(changes.borrow_and_update().is_empty());
	}

	#[tokio::test]
	async fn a_token_grants_only_the_names_it_asked_for() {
		let (dir, access) = access();
		let (id, _decision) = access
			.request(
				"alex@laptop",
				"192.168.1.9:5000",
				names(&["app.example.test", "app.example.test", "api.example.test"]),
			)
			.unwrap();
		let Approved::Token(issued) = access.approve(&id).unwrap() else { panic!("expected a token") };

		assert!(access.allows(&issued.id, "app.example.test"));
		assert!(access.allows(&issued.id, "api.example.test"));
		assert!(!access.allows(&issued.id, "other.example.test"));
		assert_eq!(issued.names.as_deref(), Some(&["api.example.test".to_owned(), "app.example.test".to_owned()][..]));

		let reloaded = Access::load(dir.path().join("tokens.json")).unwrap();
		assert!(reloaded.allows(&issued.id, "app.example.test"));
		assert!(!reloaded.allows(&issued.id, "other.example.test"));
	}

	#[tokio::test]
	async fn deleting_one_name_keeps_the_other_grants() {
		let (_dir, access) = access();
		let (id, _decision) = access
			.request("alex@laptop", "192.168.1.9:5000", names(&["app.test", "api.test"]))
			.unwrap();
		let Approved::Token(issued) = access.approve(&id).unwrap() else { panic!("expected a token") };

		access.remove_name(&issued.id, "api.test", &[]).unwrap();
		assert!(access.allows(&issued.id, "app.test"));
		assert!(!access.allows(&issued.id, "api.test"));
	}

	#[tokio::test]
	async fn a_name_request_extends_an_existing_token() {
		let (_dir, access) = access();
		let (id, _decision) = access.request("alex@laptop", "192.168.1.9:5000", names(&["app.test"])).unwrap();
		let Approved::Token(issued) = access.approve(&id).unwrap() else { panic!("expected a token") };
		assert!(!access.allows(&issued.id, "api.test"));

		let (request, decision) = access.request_name(&issued.id, "api.test", "192.168.1.9:5000").unwrap();
		let pending = access.pending();
		assert_eq!(pending.len(), 1);
		assert_eq!(pending[0].names, vec!["api.test".to_owned()]);
		assert_eq!(pending[0].label, "alex@laptop");
		assert!(matches!(access.approve(&request).unwrap(), Approved::Name));
		assert!(matches!(decision.await.unwrap(), Decision::ApproveName));
		assert!(access.allows(&issued.id, "api.test"));
		assert!(access.allows(&issued.id, "app.test"));
	}

	#[test]
	fn a_legacy_token_allows_every_name() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("tokens.json");
		let legacy = r#"{"tokens":[{"id":"old","token":"secret","label":"old leaf","created_at":1}]}"#;
		std::fs::write(&path, legacy).unwrap();
		let access = Access::load(path).unwrap();

		assert!(access.allows("old", "anything.test"));
		// Deleting one name pins the legacy token to what it publishes now.
		let live = names(&["app.test", "api.test"]);
		access.remove_name("old", "api.test", &live).unwrap();
		assert!(access.allows("old", "app.test"));
		assert!(!access.allows("old", "api.test"));
		assert!(!access.allows("old", "anything.test"));
	}

	#[test]
	fn a_corrupt_store_fails_loudly() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("tokens.json");
		std::fs::write(&path, b"not json").unwrap();
		assert!(Access::load(path).is_err());
	}
	#[test]
	fn an_approved_token_grants_only_the_requested_name() {
		let (_dir, access) = access();
		let (id, _decision) = access.request("leaf", "127.0.0.1:5000", vec!["app.example.test".into()]).unwrap();
		let approved = access.approve(&id).unwrap();
		let Approved::Token(token) = approved else { panic!("expected a token") };
		assert!(access.allows(&token.id, "app.example.test"));
		assert!(!access.allows(&token.id, "api.example.test"));
	}

}
