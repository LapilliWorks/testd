//! Sharing placeholder until the tunnel providers land.
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::engine::Registrations;

pub const DEFAULT_PROVIDER: &str = "cloudflared";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
	Public,
	Tailnet,
}

impl Exposure {
	pub fn label(self) -> &'static str {
		match self {
			Exposure::Public => "public",
			Exposure::Tailnet => "tailnet",
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
	Cloudflared,
	Tailscale,
	Ngrok,
}

impl Provider {
	pub fn parse(value: &str) -> Option<Self> {
		match value.trim().to_ascii_lowercase().as_str() {
			"cloudflared" | "cloudflare" => Some(Provider::Cloudflared),
			"tailscale" | "ts" => Some(Provider::Tailscale),
			"ngrok" => Some(Provider::Ngrok),
			_ => None,
		}
	}

	pub fn name(self) -> &'static str {
		match self {
			Provider::Cloudflared => "cloudflared",
			Provider::Tailscale => "tailscale",
			Provider::Ngrok => "ngrok",
		}
	}

	pub fn exposure(self) -> Exposure {
		match self {
			Provider::Cloudflared | Provider::Ngrok => Exposure::Public,
			Provider::Tailscale => Exposure::Tailnet,
		}
	}

	pub fn binary(self) -> &'static str {
		self.name()
	}

	pub fn needs_front(self) -> bool {
		matches!(self, Provider::Tailscale)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareView {
	pub name: String,
	pub provider: String,
	pub exposure: Exposure,
	pub target: String,
	pub url: String,
}

#[derive(Clone)]
pub struct Front {
	pub registry: Registrations,
	pub plain_addr: SocketAddr,
}

pub struct Shares {
	#[allow(dead_code)]
	front: Option<Front>,
	#[allow(dead_code)]
	binary: Option<PathBuf>,
}

impl Shares {
	pub fn from_env(front: Option<Front>) -> Self {
		Self { front, binary: None }
	}

	pub fn new(_default: Provider, binary: Option<PathBuf>, front: Option<Front>) -> Self {
		Self { front, binary }
	}

	pub async fn start(&self, _name: &str, _target: &str, _provider: Option<Provider>) -> Result<String, String> {
		Err("sharing is not available yet".into())
	}

	pub async fn stop(&self, _name: &str) -> bool {
		false
	}

	pub async fn list(&self) -> Vec<ShareView> {
		Vec::new()
	}

	pub async fn retain(&self, _names: &[String]) {}

	pub async fn reclaim(&self) {}

	pub async fn shutdown(&self) {}
}

pub fn status_host(_status: &str) -> Option<String> {
	None
}
