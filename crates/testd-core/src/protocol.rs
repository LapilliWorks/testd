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

/// How the host wants a client to handle an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorDisposition {
	Terminal,
	Retryable,
	/// An unrecognized disposition must not prevent older clients from reading the error.
	#[serde(other)]
	Unknown,
}

/// Response sent from the host daemon back to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
		/// Absent from older hosts; clients retain their prior retry behavior.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		disposition: Option<ErrorDisposition>,
	},
}

impl Response {
	/// An unclassified error, compatible with hosts that predate dispositions.
	pub fn error(message: impl Into<String>) -> Self {
		Self::Error { message: message.into(), disposition: None }
	}

	/// An error that requires an operator or client change before retrying.
	pub fn terminal_error(message: impl Into<String>) -> Self {
		Self::Error { message: message.into(), disposition: Some(ErrorDisposition::Terminal) }
	}
}

// -- NDJSON framing --

/// Serialize a message as a single JSON line and flush.
pub async fn send<W: AsyncWrite + Unpin>(writer: &mut W, msg: &impl Serialize) -> std::io::Result<()> {
	let mut line = serde_json::to_vec(msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
	line.push(b'\n');
	writer.write_all(&line).await?;
	writer.flush().await
}

/// Maximum NDJSON frame, including its newline.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Read one bounded line. Returns `None` on EOF; partial lines are refused.
pub async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
	let mut line = Vec::new();
	if read_line_into(reader, &mut line, limit).await? { Ok(Some(line)) } else { Ok(None) }
}

/// Keep partial bytes in caller-owned state when the read can be cancelled.
pub async fn read_line_into<R: AsyncBufRead + Unpin>(
	reader: &mut R,
	line: &mut Vec<u8>,
	limit: usize,
) -> std::io::Result<bool> {
	loop {
		let buffer = reader.fill_buf().await?;
		if buffer.is_empty() {
			return if line.is_empty() {
				Ok(false)
			} else {
				Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "incomplete frame"))
			};
		}
		let count = buffer
			.iter()
			.position(|byte| *byte == b'\n')
			.map_or(buffer.len(), |index| index + 1);
		if count > limit.saturating_sub(line.len()) {
			return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame size limit exceeded"));
		}
		line.extend_from_slice(&buffer[..count]);
		reader.consume(count);
		if line.last() == Some(&b'\n') {
			return Ok(true);
		}
	}
}

/// Read one JSON line and deserialize. Returns `None` on EOF.
pub async fn recv<R: AsyncBufRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> std::io::Result<Option<T>> {
	let Some(line) = read_line(reader, MAX_FRAME_BYTES).await? else { return Ok(None) };
	let msg = serde_json::from_slice(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
	Ok(Some(msg))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn error_dispositions_remain_compatible_with_older_and_newer_peers() {
		#[derive(Deserialize)]
		#[serde(tag = "type")]
		enum LegacyResponse {
			Error { message: String },
		}

		let encoded = serde_json::to_string(&Response::terminal_error("already registered")).unwrap();
		let LegacyResponse::Error { message } = serde_json::from_str(&encoded).unwrap();
		assert_eq!(message, "already registered");

		let legacy = r#"{"type":"Error","message":"old host"}"#;
		assert!(matches!(serde_json::from_str::<Response>(legacy).unwrap(), Response::Error { disposition: None, .. }));
		assert_eq!(serde_json::to_string(&Response::error("old host")).unwrap(), legacy);

		let future = r#"{"type":"Error","message":"new host","disposition":"future"}"#;
		assert!(matches!(
			serde_json::from_str::<Response>(future).unwrap(),
			Response::Error { disposition: Some(ErrorDisposition::Unknown), .. }
		));
	}

	#[tokio::test]
	async fn frames_are_bounded_and_newline_terminated() {
		let mut reader = &b"1234\nnext\n"[..];
		assert_eq!(read_line(&mut reader, 5).await.unwrap().unwrap(), b"1234\n");
		assert!(read_line(&mut reader, 4).await.is_err());
		assert!(read_line(&mut &b"partial"[..], 64).await.is_err());
		assert!(read_line(&mut &b""[..], 64).await.unwrap().is_none());
	}

	#[tokio::test]
	async fn oversized_authentication_is_refused() {
		let bytes = vec![b'{'; MAX_FRAME_BYTES + 1];
		assert!(recv::<_, Auth>(&mut bytes.as_slice()).await.is_err());
	}
}
