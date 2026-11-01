//! Shared types and configuration for testd.

pub mod config;
pub mod naming;
pub mod protocol;
pub mod validate;

pub use naming::{group_by_project, project_label};

/// A name the host serves: the FQDN and the address it proxies to.
///
/// A registration carries no identity: the connection owns it for as long as
/// the client keeps the connection open.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Registration {
	pub domain: String,
	pub target: String,
}
