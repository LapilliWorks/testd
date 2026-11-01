//! Access requests and issued leaf tokens: placeholder until the token flow lands.
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::{broadcast, oneshot, watch};

pub const REQUEST_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IssuedToken {
	pub id: String,
	pub token: String,
	pub label: String,
	pub created_at: u64,
	pub last_seen_at: Option<u64>,
	pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenView {
	pub id: String,
	pub label: String,
	pub created_at: u64,
	pub last_seen_at: Option<u64>,
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingView {
	pub id: String,
	pub label: String,
	pub address: String,
	pub names: Vec<String>,
	pub requested_at: u64,
}

#[derive(Debug)]
pub enum Decision {
	Approve(IssuedToken),
	ApproveName,
	Deny,
}

#[derive(Debug)]
pub enum Approved {
	Token(IssuedToken),
	Name,
}

pub struct Access {
	path: PathBuf,
	changes: watch::Sender<Vec<PendingView>>,
	changes_rx: watch::Receiver<Vec<PendingView>>,
	revocations: broadcast::Sender<String>,
	revocations_rx: broadcast::Receiver<String>,
}

impl Default for Access {
	fn default() -> Self {
		let (changes, changes_rx) = watch::channel(Vec::new());
		let (revocations, revocations_rx) = broadcast::channel(8);
		Self { path: PathBuf::from("tokens.json"), changes, changes_rx, revocations, revocations_rx }
	}
}

impl Access {
	pub fn load_default() -> io::Result<Self> {
		Ok(Self::default())
	}

	pub fn load(path: PathBuf) -> io::Result<Self> {
		let mut access = Self::default();
		access.path = path;
		Ok(access)
	}

	pub fn changes(&self) -> watch::Receiver<Vec<PendingView>> {
		self.changes_rx.clone()
	}

	pub fn revocations(&self) -> broadcast::Receiver<String> {
		self.revocations_rx.resubscribe()
	}

	pub fn request(
		&self,
		_label: &str,
		_address: &str,
		_names: Vec<String>,
	) -> Result<(String, oneshot::Receiver<Decision>), String> {
		Err("token requests are not available yet".into())
	}

	pub fn request_name(
		&self,
		_token_id: &str,
		_name: &str,
		_address: &str,
	) -> Result<(String, oneshot::Receiver<Decision>), String> {
		Err("token requests are not available yet".into())
	}

	pub fn cancel(&self, _id: &str) {}

	pub fn approve(&self, id: &str) -> Result<Approved, String> {
		Err(format!("request {id} is not pending"))
	}

	pub fn deny(&self, _id: &str) -> Result<(), String> {
		Err("token requests are not available yet".into())
	}

	pub fn pending(&self) -> Vec<PendingView> {
		Vec::new()
	}

	pub fn tokens(&self) -> Vec<TokenView> {
		Vec::new()
	}

	pub fn revoke(&self, _id: &str) -> Result<(), String> {
		Err("token revocation is not available yet".into())
	}

	pub fn authenticate(&self, _token: &str) -> Option<IssuedToken> {
		None
	}

	pub fn allows(&self, _token_id: &str, _name: &str) -> bool {
		false
	}

	pub fn remove_name(&self, _token_id: &str, _name: &str, _live: &[String]) -> Result<(), String> {
		Err("per-name grants are not available yet".into())
	}

	pub fn path(&self) -> &Path {
		&self.path
	}

	#[allow(dead_code)]
	fn publish(&self, _state: ()) {
		let _ = self.changes.send(Vec::new());
		let _ = self.revocations.send(String::new());
	}
}
