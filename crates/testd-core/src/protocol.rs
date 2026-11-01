//! Client-host protocol over persistent TCP connections using NDJSON framing.
//!
//! Connection lifecycle:
//! 1. Connect → send [`Auth`] with a token, or ask the host to issue one
//! 2. If a token was requested, wait for `Pending` and then `Token` or `Error`
//! 3. Send [`Request::Register`]: registration lives as long as the connection
//! 4. Optionally send [`Request::Deregister`] for immediate cleanup
//! 5. On disconnect (graceful or crash), all registrations on the connection are evicted
//!
//! A claim belongs to the connection that created it. A different connection
//! may not take a name unless it asks for `force`, and eviction only removes
//! claims held by the connection that is closing.
//!
//! The host can also speak first: [`Response::Stopped`] stops a leaf that an
//! operator stopped from the dashboard, [`Response::NameRevoked`] withdraws one
//! granted name, and [`Response::GrantRevoked`] tells the leaf that its whole
//! credential was deleted and must be requested again.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// First message on a new connection: either present a token or ask for one.
#[derive(Debug, Serialize, Deserialize)]
pub struct Auth {
	/// Bearer token. Empty when the client is asking for one instead.
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub token: String,
	/// Ask the host to issue a token instead of presenting one.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub request_token: Option<TokenRequest>,
}

/// A client asking the host's operator for a credential.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
	/// Human-readable identity shown to the operator deciding the request.
	pub label: String,
	/// Names the credential should be allowed to publish, with or without the
	/// host's TLD. The operator approves them together with the token.
	#[serde(default)]
	pub names: Vec<String>,
}

/// Message sent from a dev client to the host daemon over an authenticated connection.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
	/// Register a domain. The registration stays alive as long as the connection is open.
	Register {
		domain: String,
		target: String,
		/// Take the name from another connection.
		#[serde(default)]
		force: bool,
	},
	/// Immediately evict a registration (graceful shutdown).
	Deregister { domain: String },
}

/// Response sent from the host daemon back to the client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
	Ok,
	/// A token request is queued for the operator on the host.
	Pending {
		/// Request id shown in the dashboard and the CLI.
		id: String,
	},
	/// The host approved a token request.
	Token {
		token: String,
	},
	/// The host is waiting for the operator to grant `domain` to this leaf.
	/// The request that triggered it stays open until the operator decides.
	PendingGrant {
		/// Request id shown in the dashboard and the CLI.
		id: String,
		domain: String,
	},
	/// An operator stopped the leaf that publishes `domain`. Stop the process
	/// it supervises and do not reconnect. The credential and its grants are
	/// still valid, so a later run publishes the names again without asking.
	Stopped {
		/// The name whose leaf was stopped.
		domain: String,
	},
	/// An operator deleted the grant for `domain`. Stop publishing that name
	/// and drop it from the reconnect set; the credential still covers the
	/// leaf's other names. Registering it again asks the operator for a new
	/// grant.
	NameRevoked {
		/// The name as the host knows it, with the host's TLD.
		domain: String,
	},
	/// An operator deleted this leaf's whole grant. The credential is no longer
	/// valid: forget the stored copy and request access again.
	GrantRevoked,
	Error {
		message: String,
	},
}

// -- NDJSON framing --

/// Serialize a message as a single JSON line and flush.
pub async fn send<W: AsyncWrite + Unpin>(writer: &mut W, msg: &impl Serialize) -> std::io::Result<()> {
	let mut line = serde_json::to_vec(msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
	line.push(b'\n');
	writer.write_all(&line).await?;
	writer.flush().await
}

/// Read one JSON line and deserialize. Returns `None` on EOF.
pub async fn recv<R: AsyncBufRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> std::io::Result<Option<T>> {
	let mut line = String::new();
	let n = reader.read_line(&mut line).await?;
	if n == 0 {
		return Ok(None);
	}
	let msg = serde_json::from_str(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
	Ok(Some(msg))
}
