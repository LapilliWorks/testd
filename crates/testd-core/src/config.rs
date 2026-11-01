use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: u16 = 7737;
/// UDP port for the built-in DNS server.
///
/// Windows NRPT rules cannot target a non-standard DNS port, so the server
/// listens on 53 there. macOS and Linux use 7753 to avoid a privileged port.
#[cfg(windows)]
pub const DEFAULT_DNS_PORT: u16 = 53;
#[cfg(not(windows))]
pub const DEFAULT_DNS_PORT: u16 = 7753;
pub const DEFAULT_TLD: &str = "test";
/// Default plain HTTP routing port for an external front.
pub const DEFAULT_HTTP_PORT: u16 = 7740;

/// DNS resolution backend for registered domains.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverBackend {
	/// Built-in UDP DNS server (no root required).
	#[default]
	Dns,
	/// Managed block in `/etc/hosts` (requires write access to hosts file).
	Hosts,
}

/// Host daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
	/// DNS resolution backend.
	#[serde(default)]
	pub resolver: ResolverBackend,
	/// Address to listen on for client connections.
	#[serde(default = "defaults::listen_addr")]
	pub listen_addr: SocketAddr,
	/// TLD to append to registered domain names.
	#[serde(default = "defaults::tld")]
	pub tld: String,
	/// Path to the managed Caddyfile (written by testd).
	#[serde(default = "defaults::caddyfile_path")]
	pub caddyfile_path: PathBuf,
	/// Path to the global Caddyfile (for `caddy reload`).
	#[serde(default = "defaults::caddy_config_path")]
	pub caddy_config_path: PathBuf,
	/// Path to the hosts file.
	#[serde(default = "defaults::hosts_path")]
	pub hosts_path: PathBuf,
	/// Path to the hosts helper script (invoked via sudo).
	#[serde(default = "defaults::hosts_helper_path")]
	pub hosts_helper_path: PathBuf,
	/// Local CA and host intermediate.
	#[serde(default = "defaults::pki_dir")]
	pub pki_dir: PathBuf,
	/// Address the built-in HTTPS edge binds. Needs port 443 privileges.
	#[serde(default = "defaults::edge_addr")]
	pub edge_addr: SocketAddr,
	/// Set false to run without the built-in TLS edge (external front only).
	#[serde(default = "defaults::bool_true")]
	pub edge_enabled: bool,
	/// Plain HTTP routing listener for an external front and `testd export-caddyfile`.
	#[serde(default = "defaults::http_addr")]
	pub http_addr: SocketAddr,
	/// A record returned for registered names.
	#[serde(default = "defaults::answer_addr")]
	pub answer_addr: std::net::Ipv4Addr,
	/// The operator secret a client presents to register names.
	#[serde(default)]
	pub secret: String,
}

impl HostConfig {
	/// Loopback endpoint of the client listener, whatever address it binds.
	pub fn local_client_addr(&self) -> SocketAddr {
		if self.listen_addr.ip().is_unspecified() {
			SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), self.listen_addr.port())
		} else {
			self.listen_addr
		}
	}

	/// The loopback URL the local dashboard answers on: the same port clients use.
	pub fn local_dashboard_url(&self) -> String {
		format!("http://{}", self.local_client_addr())
	}
}

/// Dev-side node profiles. Stored in `~/.config/testd/leaf.toml`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LeafConfig {
	/// Profile used when nothing overrides it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub default_profile: Option<String>,
	#[serde(default)]
	pub profiles: BTreeMap<String, NodeProfile>,
}

/// One ordered set of reachable nodes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NodeProfile {
	#[serde(default)]
	pub hosts: Vec<String>,
}

/// Project-local, commit-safe configuration. Stored in `.testd.toml`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
	/// Credential profile to use for this project.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub token_profile: Option<String>,
}

/// Resolved leaf settings for one invocation.
#[derive(Debug, Clone)]
pub struct ClientConfig {
	pub token: String,
	pub token_profile: String,
	pub hosts: Vec<String>,
	pub node_profile: String,
}

pub const DEFAULT_PROFILE: &str = "default";

/// The default plain HTTP routing address.
pub fn default_http_addr() -> SocketAddr {
	SocketAddr::from(([127, 0, 0, 1], DEFAULT_HTTP_PORT))
}

/// Returns the config directory.
///
/// Unix: `~/.config/testd/`. Windows: `%APPDATA%\testd`.
pub fn config_dir() -> PathBuf {
	#[cfg(windows)]
	{
		let base = std::env::var_os("APPDATA")
			.map(PathBuf::from)
			.unwrap_or_else(|| home_dir().join("AppData").join("Roaming"));
		base.join("testd")
	}
	#[cfg(not(windows))]
	{
		home_dir().join(".config").join("testd")
	}
}

/// User home directory. Windows has no `HOME` by default.
fn home_dir() -> PathBuf {
	let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
	let value = std::env::var_os(variable).unwrap_or_else(|| panic!("{variable} environment variable not set"));
	PathBuf::from(value)
}

/// Returns the config file path inside [`config_dir`].
pub fn config_path() -> PathBuf {
	config_dir().join("config.toml")
}

/// Check whether a config file already exists.
pub fn config_exists() -> bool {
	config_path().exists()
}

const CONFIG_TEMPLATE: &str = include_str!("../../../config.example.toml");

/// Escape a value for a TOML basic string. Windows paths contain backslashes.
fn toml_escape(value: &str) -> String {
	value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render the host config template with the given values, safely escaped for TOML.
/// Without a secret the template keeps the commented placeholder.
fn render_config(caddy_config_path: &str, tld: &str, secret: Option<&str>) -> String {
	let secret_line = match secret {
		Some(secret) => format!("secret = \"{}\"", toml_escape(secret)),
		None => "# secret = \"...\"".to_owned(),
	};
	// The secret goes last so its contents are never expanded as placeholders.
	CONFIG_TEMPLATE
		.replace("{caddy_config_path}", &toml_escape(caddy_config_path))
		.replace("{tld}", &toml_escape(tld))
		.replace("{secret}", &secret_line)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_tray_opens_the_loopback_dashboard_even_with_the_edge_on() {
		let mut config: HostConfig = toml::from_str("").unwrap();
		config.edge_enabled = true;
		config.edge_addr = "0.0.0.0:443".parse().unwrap();
		config.listen_addr = "0.0.0.0:7737".parse().unwrap();
		assert_eq!(config.local_dashboard_url(), "http://127.0.0.1:7737");
	}

	#[test]
	fn the_local_client_endpoint_follows_the_bind_address() {
		let mut config: HostConfig = toml::from_str("").unwrap();
		config.listen_addr = "0.0.0.0:7800".parse().unwrap();
		assert_eq!(config.local_client_addr().to_string(), "127.0.0.1:7800");
		config.listen_addr = "10.0.0.5:7800".parse().unwrap();
		assert_eq!(config.local_client_addr().to_string(), "10.0.0.5:7800");
	}

	#[test]
	fn the_node_secret_serves_the_default_profile_on_loopback() {
		let hosts = ["127.0.0.1:7737".to_owned(), "[::1]:7737".to_owned(), "localhost:7737".to_owned()];
		assert_eq!(credential_from_node("default", &hosts, "secret").as_deref(), Some("secret"));
	}

	#[test]
	fn the_node_secret_never_leaves_the_machine_or_a_named_profile() {
		let loopback = ["127.0.0.1:7737".to_owned()];
		let remote = ["192.168.1.5:7737".to_owned()];
		assert_eq!(credential_from_node("default", &remote, "secret"), None);
		assert_eq!(credential_from_node("ci", &loopback, "secret"), None);
		assert_eq!(credential_from_node("default", &loopback, ""), None);
	}

	#[test]
	fn loopback_endpoints_are_recognised() {
		for value in ["127.0.0.1:7737", "127.1.2.3:7737", "[::1]:7737", "localhost:7737", "LOCALHOST:7737"] {
			assert!(is_loopback_endpoint(value), "{value} should be loopback");
		}
		for value in ["192.168.1.5:7737", "dextral:7737", "0.0.0.0:7737"] {
			assert!(!is_loopback_endpoint(value), "{value} should not be loopback");
		}
	}

	#[test]
	fn default_dns_port_matches_platform() {
		#[cfg(windows)]
		assert_eq!(DEFAULT_DNS_PORT, 53);
		#[cfg(not(windows))]
		assert_eq!(DEFAULT_DNS_PORT, 7753);
	}

	#[test]
	fn host_addr_accepts_hostnames_and_ip_literals() {
		for value in ["127.0.0.1:7737", "dextral:7737", "localhost:7737", "[::1]:7737"] {
			assert!(validate_host_addr(value).is_ok(), "{value} should be valid");
		}
	}

	#[test]
	fn host_addr_rejects_malformed_endpoints() {
		for value in ["dextral", "127.0.0.1:bad", ":7737", "[]:7737", "127.0.0.1:70000"] {
			let result = validate_host_addr(value);
			assert!(result.is_err(), "{value} should be invalid");
		}
	}

	#[test]
	fn generated_secrets_are_pronounceable_and_carry_128_bits() {
		let secret = generate_operator_secret().unwrap();
		let decoded = covo::decode(&secret).expect("generated secret uses the covo alphabet");
		assert_eq!(decoded.len(), 16);
		assert!(secret.len() >= 16, "{secret}");
	}

	#[test]
	fn config_template_escapes_windows_paths() {
		let caddyfile = r"C:\Users\me\AppData\Roaming\caddy\Caddyfile";
		let rendered = render_config(caddyfile, "test", Some("s3cret"));
		let table: toml::Table = toml::from_str(&rendered).expect("rendered config should parse");
		assert_eq!(table["host"]["caddy_config_path"].as_str(), Some(caddyfile));
		assert_eq!(table["host"]["secret"].as_str(), Some("s3cret"));
	}

	#[test]
	fn config_template_leaves_the_secret_commented_when_absent() {
		let rendered = render_config("", "test", None);
		let table: toml::Table = toml::from_str(&rendered).expect("rendered config should parse");
		assert!(table["host"].get("secret").is_none(), "{rendered}");
	}
}

/// Write a host config file, replacing an existing one. Used by idempotent `init`.
pub fn write_config_force(caddy_config_path: &str, tld: &str, secret: Option<&str>) -> io::Result<PathBuf> {
	let dir = config_dir();
	std::fs::create_dir_all(&dir)?;

	let path = config_path();
	let content = render_config(caddy_config_path, tld, secret);
	write_private(&path, content.as_bytes())?;
	Ok(path)
}

/// Path of the leaf node-profile file.
pub fn leaf_path() -> PathBuf {
	config_dir().join("leaf.toml")
}

/// Directory holding per-profile credential files.
pub fn credentials_dir() -> PathBuf {
	config_dir().join("credentials")
}

/// Path of one credential file.
pub fn credential_path(profile: &str) -> PathBuf {
	credentials_dir().join(profile)
}

/// Path of the project-local config, searched upward from the working directory.
pub fn find_project_config_path() -> Option<PathBuf> {
	let mut dir = std::env::current_dir().ok()?;
	loop {
		let candidate = dir.join(".testd.toml");
		if candidate.is_file() {
			return Some(candidate);
		}
		if !dir.pop() {
			return None;
		}
	}
}

/// Load leaf node profiles. A missing file is an empty config.
pub fn load_leaf_config() -> Result<LeafConfig, ConfigError> {
	let path = leaf_path();
	let content = match std::fs::read_to_string(&path) {
		Ok(content) => content,
		Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(LeafConfig::default()),
		Err(e) => return Err(ConfigError::Io(path, e)),
	};
	toml::from_str(&content).map_err(|e| ConfigError::Parse(path, e))
}

/// Load the nearest project config. `None` when no `.testd.toml` is found.
pub fn load_project_config() -> Result<Option<ProjectConfig>, ConfigError> {
	let Some(path) = find_project_config_path() else { return Ok(None) };
	let content = std::fs::read_to_string(&path).map_err(|e| ConfigError::Io(path.clone(), e))?;
	let config = toml::from_str(&content).map_err(|e| ConfigError::Parse(path, e))?;
	Ok(Some(config))
}

/// Read one credential file. Returns `None` when it does not exist.
pub fn read_credential(profile: &str) -> Result<Option<String>, ConfigError> {
	validate_profile_name(profile)?;
	let path = credential_path(profile);
	let token = match std::fs::read_to_string(&path) {
		Ok(token) => token.trim().to_owned(),
		Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
		Err(e) => return Err(ConfigError::Io(path, e)),
	};
	Ok((!token.is_empty()).then_some(token))
}

/// Forget a stored credential. A missing file is already cleared.
pub fn clear_credential(profile: &str) -> Result<(), ConfigError> {
	validate_profile_name(profile)?;
	let path = credential_path(profile);
	match std::fs::remove_file(&path) {
		Ok(()) => Ok(()),
		Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
		Err(e) => Err(ConfigError::Io(path, e)),
	}
}

/// Store a credential for a profile, readable only by this user.
pub fn write_credential(profile: &str, token: &str) -> Result<(), ConfigError> {
	validate_profile_name(profile)?;
	let path = credential_path(profile);
	let dir = credentials_dir();
	std::fs::create_dir_all(&dir).map_err(|e| ConfigError::Io(dir, e))?;
	write_private(&path, token.as_bytes()).map_err(|e| ConfigError::Io(path, e))
}

/// Profile names are file names, so only allow a conservative character set.
pub fn validate_profile_name(profile: &str) -> Result<(), ConfigError> {
	if profile.is_empty()
		|| profile.starts_with('.')
		|| !profile
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
	{
		return Err(ConfigError::InvalidProfile(profile.to_owned()));
	}
	Ok(())
}

/// Write a file readable only by the current user. The config contains the
/// secret, so it must not be world-readable on a multi-user machine.
pub fn write_private(path: &Path, content: &[u8]) -> io::Result<()> {
	#[cfg(unix)]
	{
		use std::io::Write;
		use std::os::unix::fs::OpenOptionsExt;

		let mut file = std::fs::OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.mode(0o600)
			.open(path)?;
		file.write_all(content)?;
		file.sync_all()?;
	}
	#[cfg(not(unix))]
	{
		std::fs::write(path, content)?;
	}
	Ok(())
}

/// Read the raw config table, if the file exists and parses.
pub fn read_config_table() -> Option<toml::Table> {
	let content = std::fs::read_to_string(config_path()).ok()?;
	toml::from_str(&content).ok()
}

/// The operator secret from the host config, when one is set.
pub fn read_operator_secret() -> Option<String> {
	table_operator_secret(&read_config_table()?)
}

fn table_operator_secret(table: &toml::Table) -> Option<String> {
	let secret = table.get("host")?.get("secret")?.as_str()?;
	(!secret.is_empty()).then(|| secret.to_owned())
}

/// Generate a fresh operator secret: 16 random bytes encoded as pronounceable
/// consonant-vowel groups.
pub fn generate_operator_secret() -> io::Result<String> {
	let mut bytes = [0u8; 16];
	getrandom::fill(&mut bytes).map_err(io::Error::other)?;
	Ok(covo::encode(&bytes))
}

/// Write the operator secret into an existing host config, preserving other keys.
pub fn write_operator_secret(secret: &str) -> io::Result<()> {
	let path = config_path();
	let text = std::fs::read_to_string(&path)?;
	let mut table: toml::Table = toml::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
	let host = table.entry("host").or_insert_with(|| toml::Value::Table(toml::Table::new()));
	let toml::Value::Table(host) = host else {
		return Err(io::Error::new(io::ErrorKind::InvalidData, "[host] is not a table"));
	};
	host.insert("secret".to_owned(), toml::Value::String(secret.to_owned()));
	let content = toml::to_string_pretty(&table).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
	write_private(&path, content.as_bytes())
}

// --- Pending config (init state machine) ---

/// State stored in `config.toml.pending` during init.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingConfig {
	/// Last completed init step (1-based).
	pub step: u8,
	/// Path to the global Caddyfile.
	pub caddy_config_path: String,
	/// TLD to append to registered names.
	#[serde(default = "defaults::tld")]
	pub tld: String,
	/// Operator secret chosen by the setup wizard.
	#[serde(default)]
	pub secret: String,
}

fn pending_config_path() -> PathBuf {
	config_dir().join("config.toml.pending")
}

/// Check whether a pending init exists.
pub fn has_pending_config() -> bool {
	pending_config_path().exists()
}

/// Read the pending init state, if any.
pub fn read_pending_config() -> io::Result<PendingConfig> {
	let path = pending_config_path();
	let content = std::fs::read_to_string(&path)?;
	let table: toml::Table = toml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

	let init = table
		.get("init")
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing [init] section"))?;

	let step = init.get("step").and_then(|v| v.as_integer()).unwrap_or(0) as u8;
	let caddy_config_path = init.get("caddy_config_path").and_then(|v| v.as_str()).unwrap_or("").to_owned();
	let tld = init.get("tld").and_then(|v| v.as_str()).unwrap_or(DEFAULT_TLD).to_owned();
	let secret = init.get("secret").and_then(|v| v.as_str()).unwrap_or("").to_owned();

	Ok(PendingConfig { step, caddy_config_path, tld, secret })
}

/// Write or update the pending init state.
pub fn write_pending_config(pending: &PendingConfig) -> io::Result<()> {
	let dir = config_dir();
	std::fs::create_dir_all(&dir)?;

	let content = format!(
		"[init]\nstep = {}\ncaddy_config_path = \"{}\"\ntld = \"{}\"\nsecret = \"{}\"\n",
		pending.step,
		toml_escape(&pending.caddy_config_path),
		toml_escape(&pending.tld),
		toml_escape(&pending.secret),
	);
	write_private(&pending_config_path(), content.as_bytes())
}

/// Finalize init: write the real config from the pending state and remove the pending file.
pub fn finish_pending_config(pending: &PendingConfig) -> io::Result<PathBuf> {
	let dir = config_dir();
	std::fs::create_dir_all(&dir)?;

	let config_path = dir.join("config.toml");
	let secret = (!pending.secret.is_empty()).then_some(pending.secret.as_str());
	let content = render_config(&pending.caddy_config_path, &pending.tld, secret);
	write_private(&config_path, content.as_bytes())?;

	// Remove the pending file.
	let _ = std::fs::remove_file(pending_config_path());
	Ok(config_path)
}

/// Load host config from `~/.config/testd/config.toml`.
pub fn load_host_config() -> Result<HostConfig, ConfigError> {
	load_config("host")
}

/// Resolve leaf settings from project config, node profiles, credentials, and
/// the environment. Explicit arguments win over environment variables.
pub fn load_client_config(
	explicit_hosts: Option<Vec<String>>,
	token_profile: Option<&str>,
	node_profile: Option<&str>,
) -> Result<ClientConfig, ConfigError> {
	let project = load_project_config()?.unwrap_or_default();
	let leaf = load_leaf_config()?;

	let token_profile = std::env::var("TESTD_TOKEN_PROFILE")
		.ok()
		.filter(|value| !value.is_empty())
		.or_else(|| token_profile.map(str::to_owned))
		.or(project.token_profile)
		.unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
	validate_profile_name(&token_profile)?;

	let node_profile = std::env::var("TESTD_PROFILE")
		.ok()
		.filter(|value| !value.is_empty())
		.or_else(|| node_profile.map(str::to_owned))
		.or(leaf.default_profile.clone())
		.unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
	validate_profile_name(&node_profile)?;

	let hosts = explicit_hosts
		.or_else(hosts_from_env)
		.or_else(|| leaf.profiles.get(&node_profile).map(|profile| profile.hosts.clone()))
		.filter(|hosts| !hosts.is_empty())
		.unwrap_or_else(local_host_addr);
	for host in &hosts {
		validate_host_addr(host)?;
	}

	let token = match std::env::var("TESTD_TOKEN").ok().filter(|value| !value.is_empty()) {
		Some(token) => token,
		// No credential is not an error: the client asks the host for a token.
		None => read_credential(&token_profile)?
			.or_else(|| node_operator_secret(&token_profile, &hosts))
			.unwrap_or_default(),
	};

	Ok(ClientConfig { token, token_profile, hosts, node_profile })
}

/// Default endpoints: the node's own client listener when this machine is a host.
fn local_host_addr() -> Vec<String> {
	match load_host_config() {
		Ok(config) => vec![config.local_client_addr().to_string()],
		Err(_) => vec![defaults::host_addr()],
	}
}

/// The operator secret in the host config is a credential on the node itself.
fn node_operator_secret(token_profile: &str, hosts: &[String]) -> Option<String> {
	let secret = load_host_config().ok()?.secret;
	credential_from_node(token_profile, hosts, &secret)
}

/// Offer the node's own secret only to the default profile and only for
/// loopback endpoints, so it is never sent to another machine.
fn credential_from_node(token_profile: &str, hosts: &[String], secret: &str) -> Option<String> {
	if token_profile != DEFAULT_PROFILE || secret.is_empty() {
		return None;
	}
	hosts.iter().all(|host| is_loopback_endpoint(host)).then(|| secret.to_owned())
}

fn is_loopback_endpoint(endpoint: &str) -> bool {
	let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
	let host = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')).unwrap_or(host);
	host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn hosts_from_env() -> Option<Vec<String>> {
	if let Ok(value) = std::env::var("TESTD_HOSTS") {
		let hosts: Vec<String> = value
			.split(',')
			.map(str::trim)
			.filter(|part| !part.is_empty())
			.map(str::to_owned)
			.collect();
		if !hosts.is_empty() {
			return Some(hosts);
		}
	}
	std::env::var("TESTD_HOST")
		.ok()
		.filter(|value| !value.is_empty())
		.map(|host| vec![host])
}

/// Validate a `host:port` endpoint without resolving it, so a typo fails at
/// startup instead of every reconnect. IPv6 literals must be bracketed.
pub fn validate_host_addr(value: &str) -> Result<(), ConfigError> {
	let invalid = || ConfigError::InvalidHostAddr(value.to_owned());

	let (host, port) = value.rsplit_once(':').ok_or_else(invalid)?;
	if port.parse::<u16>().is_err() {
		return Err(invalid());
	}

	let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
	if host.is_empty() {
		return Err(invalid());
	}
	Ok(())
}

/// Read the host config file and extract the named section.
fn load_config<T: serde::de::DeserializeOwned>(section: &str) -> Result<T, ConfigError> {
	let path = config_dir().join("config.toml");
	let content = std::fs::read_to_string(&path).map_err(|_| ConfigError::NotFound(path.clone()))?;
	let table: toml::Table = toml::from_str(&content).map_err(|e| ConfigError::Parse(path.clone(), e))?;

	let section_value = table.get(section).ok_or(ConfigError::MissingSection(section.to_string()))?;
	T::deserialize(section_value.clone()).map_err(|e| ConfigError::Parse(path, e))
}

#[derive(Debug)]
pub enum ConfigError {
	/// Config file not found.
	NotFound(PathBuf),
	/// Missing required section (e.g. [host]).
	MissingSection(String),
	/// `host:port` endpoint is invalid.
	InvalidHostAddr(String),
	/// Profile name is invalid.
	InvalidProfile(String),
	/// Failed to read a config file.
	Io(PathBuf, io::Error),
	/// Failed to parse config file.
	Parse(PathBuf, toml::de::Error),
}

const INIT_HINT: &str = "run `testd init` on the host to write the operator secret";

impl std::fmt::Display for ConfigError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::NotFound(path) => write!(f, "config not found: {}\n{INIT_HINT}", path.display()),
			Self::MissingSection(section) => write!(f, "missing [{section}] section in config"),
			Self::InvalidHostAddr(value) => {
				write!(f, "invalid host {value:?}: expected host:port, e.g. 127.0.0.1:7737 or [::1]:7737")
			},
			Self::InvalidProfile(value) => {
				write!(f, "invalid profile {value:?}: use letters, digits, `.`, `-`, or `_`")
			},
			Self::Io(path, err) => write!(f, "failed to read {}: {err}", path.display()),
			Self::Parse(path, err) => write!(f, "failed to parse {}: {err}", path.display()),
		}
	}
}

impl std::error::Error for ConfigError {}

/// Result of Caddyfile detection.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CaddyDetection {
	/// Caddy is installed and a config file was found at this path.
	Found { path: String },
	/// Caddy is installed but no config file exists. `expected` is the best-guess location.
	Missing { expected: String },
	/// Caddy doesn't appear to be installed.
	NoCaddy,
}

/// Detect Caddy installation and config file location.
pub fn detect_caddy_config() -> CaddyDetection {
	if find_caddy_binary().is_none() {
		return CaddyDetection::NoCaddy;
	}

	let paths = defaults::caddy_config_paths();
	if let Some(found) = paths.iter().find(|p| p.exists()) {
		CaddyDetection::Found { path: found.to_string_lossy().into_owned() }
	} else {
		let expected = paths.into_iter().next().unwrap_or_else(|| "/etc/caddy/Caddyfile".into());
		CaddyDetection::Missing { expected: expected.to_string_lossy().into_owned() }
	}
}

/// Locate the Caddy executable, checking `PATH` first, then well-known install
/// locations (GUI apps on macOS often run with a restricted `PATH`).
pub fn find_caddy_binary() -> Option<PathBuf> {
	let binary = if cfg!(windows) { "caddy.exe" } else { "caddy" };

	if let Some(found) = std::env::var_os("PATH").and_then(|path| {
		std::env::split_paths(&path)
			.map(|dir| dir.join(binary))
			.find(|candidate| candidate.is_file())
	}) {
		return Some(found);
	}

	known_caddy_binaries().into_iter().find(|p| p.is_file())
}

fn known_caddy_binaries() -> Vec<PathBuf> {
	#[cfg(target_os = "macos")]
	{
		vec![
			PathBuf::from("/opt/homebrew/bin/caddy"),
			PathBuf::from("/usr/local/bin/caddy"),
			PathBuf::from("/usr/bin/caddy"),
		]
	}
	#[cfg(all(unix, not(target_os = "macos")))]
	{
		vec![PathBuf::from("/usr/local/bin/caddy"), PathBuf::from("/usr/bin/caddy")]
	}
	#[cfg(windows)]
	{
		vec![PathBuf::from(r"C:\Program Files\Caddy\caddy.exe")]
	}
	#[cfg(not(any(unix, windows)))]
	{
		Vec::new()
	}
}

/// Check if Caddy is installed.
pub fn is_caddy_installed() -> bool {
	find_caddy_binary().is_some()
}

mod defaults {
	use std::net::SocketAddr;
	use std::path::PathBuf;

	pub fn listen_addr() -> SocketAddr {
		SocketAddr::from(([0, 0, 0, 0], super::DEFAULT_PORT))
	}

	pub fn host_addr() -> String {
		format!("127.0.0.1:{}", super::DEFAULT_PORT)
	}

	pub fn tld() -> String {
		super::DEFAULT_TLD.into()
	}

	pub fn caddyfile_path() -> PathBuf {
		super::config_dir().join("Caddyfile")
	}

	/// Known Caddyfile paths in priority order.
	pub fn caddy_config_paths() -> Vec<PathBuf> {
		#[cfg(target_os = "macos")]
		{
			vec![PathBuf::from("/opt/homebrew/etc/Caddyfile"), PathBuf::from("/etc/caddy/Caddyfile")]
		}
		#[cfg(all(unix, not(target_os = "macos")))]
		{
			vec![PathBuf::from("/etc/caddy/Caddyfile")]
		}
		#[cfg(windows)]
		{
			vec![PathBuf::from(r"C:\Program Files\Caddy\Caddyfile")]
		}
		#[cfg(not(any(unix, windows)))]
		{
			Vec::new()
		}
	}

	/// Default Caddyfile path (first known path, whether or not it exists).
	/// Used as a fallback for config deserialization defaults.
	pub fn caddy_config_path() -> PathBuf {
		caddy_config_paths()
			.into_iter()
			.next()
			.unwrap_or_else(|| "/etc/caddy/Caddyfile".into())
	}

	pub fn hosts_path() -> PathBuf {
		"/etc/hosts".into()
	}

	pub fn hosts_helper_path() -> PathBuf {
		"/usr/local/libexec/testd-hosts-helper".into()
	}

	pub fn pki_dir() -> PathBuf {
		super::config_dir().join("pki")
	}

	pub fn edge_addr() -> SocketAddr {
		SocketAddr::from(([0, 0, 0, 0], 443))
	}

	pub fn http_addr() -> SocketAddr {
		SocketAddr::from(([127, 0, 0, 1], 7740))
	}

	pub fn answer_addr() -> std::net::Ipv4Addr {
		std::net::Ipv4Addr::LOCALHOST
	}

	pub fn bool_true() -> bool {
		true
	}
}
