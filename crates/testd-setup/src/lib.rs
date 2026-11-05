//! One-time setup operations for testd:
//! - OS resolver configuration (routing `.<tld>` queries to the testd DNS server)
//! - Caddyfile import line management

use std::io;
use std::net::SocketAddr;
use std::path::Path;

#[cfg(target_os = "linux")]
mod linux_resolver;
#[cfg(target_os = "linux")]
mod ownership;

/// Spawn a child without popping a console window from a windowless parent.
///
/// A console child of a GUI process gets a new console window unless
/// `CREATE_NO_WINDOW` is set. The tray probes the system on a timer, so every
/// probe used to flash a PowerShell or certutil window.
#[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
fn silent_command(program: &str) -> std::process::Command {
	let mut command = std::process::Command::new(program);
	#[cfg(target_os = "windows")]
	{
		use std::os::windows::process::CommandExt;
		const CREATE_NO_WINDOW: u32 = 0x0800_0000;
		command.creation_flags(CREATE_NO_WINDOW);
	}
	command
}

// --- Detection ---

/// Check whether the OS resolver is already configured for `.<tld>`.
/// Returns `true` if the resolver is set up and pointing to the expected address.
pub fn is_os_resolver_configured(tld: &str, addr: SocketAddr) -> bool {
	#[cfg(target_os = "macos")]
	return is_os_resolver_configured_macos(tld, addr);

	#[cfg(target_os = "linux")]
	return is_os_resolver_configured_linux(tld, addr);

	#[cfg(target_os = "windows")]
	return is_os_resolver_configured_windows(tld, addr);

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	false
}

/// macOS: check /etc/resolver/{tld} for a nameserver entry pointing to our port.
#[cfg(target_os = "macos")]
fn is_os_resolver_configured_macos(tld: &str, addr: SocketAddr) -> bool {
	let path = format!("/etc/resolver/{tld}");
	let Ok(content) = std::fs::read_to_string(&path) else { return false };

	let mut has_nameserver = false;
	let mut has_port = false;
	for line in content.lines() {
		let line = line.trim();
		if let Some(value) = line.strip_prefix("nameserver") {
			let ip = value.trim();
			// Accept any loopback or local IP: the important part is the port.
			has_nameserver = !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok();
		} else if let Some(value) = line.strip_prefix("port") {
			has_port = value.trim().parse::<u16>().ok() == Some(addr.port());
		}
	}
	has_nameserver && has_port
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct GlobalResolverState {
	dns: Vec<String>,
	domains: Vec<String>,
	link_domains: Vec<String>,
}

#[cfg(target_os = "linux")]
impl GlobalResolverState {
	fn has_link_route(&self, tld: &str) -> bool {
		self.link_domains
			.iter()
			.any(|domain| domain.trim_start_matches('~').trim_end_matches('.').eq_ignore_ascii_case(tld))
	}

	fn is_compatible(&self, tld: &str, addr: SocketAddr) -> bool {
		if self.dns.len() != 1 || self.domains.len() != 1 || self.has_link_route(tld) {
			return false;
		}
		let server = self.dns[0]
			.parse::<SocketAddr>()
			.ok()
			.or_else(|| self.dns[0].parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)));
		let domain = self.domains[0].strip_prefix('~').map(|domain| domain.trim_end_matches('.'));
		server == Some(addr) && domain.is_some_and(|domain| domain.eq_ignore_ascii_case(tld))
	}
}

#[cfg(target_os = "linux")]
fn resolvectl_global_values(output: &str) -> io::Result<Vec<String>> {
	let mut lines = output.lines();
	let global = lines
		.next()
		.and_then(|line| line.strip_prefix("Global:"))
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "resolvectl did not report global settings"))?;
	let mut values: Vec<String> = global.split_whitespace().map(str::to_owned).collect();
	for line in lines {
		if !line.starts_with(char::is_whitespace) {
			break;
		}
		values.extend(line.split_whitespace().map(str::to_owned));
	}
	Ok(values)
}

#[cfg(target_os = "linux")]
fn resolvectl_link_domains(output: &str) -> io::Result<Vec<String>> {
	let mut lines = output.lines();
	if !lines.next().is_some_and(|line| line.starts_with("Global:")) {
		return Err(io::Error::new(io::ErrorKind::InvalidData, "resolvectl did not report global settings"));
	}
	let mut domains = Vec::new();
	let mut in_link = false;
	for line in lines {
		if line.starts_with("Link ") {
			let (_, values) = line
				.rsplit_once("):")
				.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid resolvectl link output"))?;
			in_link = true;
			domains.extend(values.split_whitespace().map(str::to_owned));
		} else if line.starts_with(char::is_whitespace) {
			if in_link {
				domains.extend(line.split_whitespace().map(str::to_owned));
			}
		} else if !line.is_empty() {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid resolvectl link output"));
		}
	}
	Ok(domains)
}

#[cfg(target_os = "linux")]
fn global_resolver_state(dns: &str, domains: &str) -> io::Result<GlobalResolverState> {
	Ok(GlobalResolverState {
		dns: resolvectl_global_values(dns)?,
		domains: resolvectl_global_values(domains)?,
		link_domains: resolvectl_link_domains(domains)?,
	})
}

#[cfg(target_os = "linux")]
fn systemd_probe(program: &str, args: &[&str]) -> io::Result<String> {
	let output = silent_command(program)
		.args(args)
		.env("LC_ALL", "C")
		.env("SYSTEMD_COLORS", "0")
		.env("SYSTEMD_PAGER", "cat")
		.env("COLUMNS", "10000")
		.output()?;
	if !output.status.success() {
		return Err(io::Error::other(format!("{program} {} failed", args.join(" "))));
	}
	let text = String::from_utf8(output.stdout).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	if text.contains('\0') {
		return Err(io::Error::new(io::ErrorKind::InvalidData, "systemd probe returned a NUL byte"));
	}
	Ok(text.trim_end_matches('\n').to_owned())
}

#[cfg(target_os = "linux")]
fn linux_resolver_outputs() -> io::Result<(String, String)> {
	Ok((systemd_probe("resolvectl", &["dns"])?, systemd_probe("resolvectl", &["domain"])?))
}

#[cfg(target_os = "linux")]
fn is_os_resolver_configured_linux(tld: &str, addr: SocketAddr) -> bool {
	let Ok((dns, domains)) = linux_resolver_outputs() else { return false };
	global_resolver_state(&dns, &domains).is_ok_and(|state| state.is_compatible(tld, addr))
}

#[cfg(any(target_os = "linux", test))]
fn dns_server_value(addr: SocketAddr) -> String {
	addr.to_string()
}

/// Path where the Linux resolver route is written.
///
/// A `[Resolve]` drop-in rather than `resolvectl dns lo`/`domain lo`: setting
/// link configuration through resolvectl needs systemd-networkd, which is
/// inactive or absent on machines where NetworkManager owns the links. A
/// drop-in is read by systemd-resolved itself, so it works on either stack, and
/// it survives NetworkManager reconnects and reboots.
#[cfg(target_os = "linux")]
const RESOLVED_DROPIN_DIR: &str = "/etc/systemd/resolved.conf.d";
#[cfg(target_os = "linux")]
const RESOLVED_DROPIN: &str = "/etc/systemd/resolved.conf.d/90-testd.conf";

/// The drop-in that routes `.<tld>` to the testd DNS server.
///
/// `Domains=~<tld>` is a routing-only domain: queries under it go to the
/// servers in this scope, and no other name is routed there. The server list
/// holds only testd's server, which answers NXDOMAIN for anything outside its
/// zone, so it must not share a scope with other servers.
#[cfg(any(target_os = "linux", test))]
fn resolved_dropin(tld: &str, addr: SocketAddr) -> String {
	format!(
		"# Managed by testd; removed by `testd uninstall`.\n\
[Resolve]\n\
DNS={}\n\
Domains=~{tld}\n",
		dns_server_value(addr)
	)
}

/// `DNS=` and `Domains=` accumulate across systemd-resolved configuration;
/// an empty assignment clears the list, and only `[Resolve]` counts.
#[cfg(any(target_os = "linux", test))]
fn resolved_global_values(files: &[String]) -> (Option<String>, Option<String>) {
	let mut dns = Vec::new();
	let mut domains = Vec::new();
	for content in files {
		let mut in_resolve = false;
		for line in content.lines() {
			let line = line.trim();
			if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
				continue;
			}
			if line.starts_with('[') {
				in_resolve = line == "[Resolve]";
				continue;
			}
			if !in_resolve {
				continue;
			}
			let Some((key, value)) = line.split_once('=') else { continue };
			let values = match key.trim() {
				"DNS" => &mut dns,
				"Domains" => &mut domains,
				_ => continue,
			};
			let value = value.trim();
			if value.is_empty() {
				values.clear();
			} else {
				values.push(value);
			}
		}
	}
	let joined = |values: Vec<&str>| (!values.is_empty()).then(|| values.join(" "));
	(joined(dns), joined(domains))
}

#[cfg(target_os = "linux")]
fn resolved_active() -> bool {
	silent_command("systemctl")
		.args(["is-active", "--quiet", "systemd-resolved"])
		.status()
		.is_ok_and(|status| status.success())
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum LinuxResolverPreflight {
	Compatible,
	Ready { snapshot: String },
}

#[cfg(target_os = "linux")]
fn assess_linux_resolver(
	tld: &str,
	addr: SocketAddr,
	dns_output: &str,
	domain_output: &str,
	configuration: &str,
) -> io::Result<LinuxResolverPreflight> {
	let state = global_resolver_state(dns_output, domain_output)?;
	if state.is_compatible(tld, addr) {
		return Ok(LinuxResolverPreflight::Compatible);
	}
	if state.has_link_route(tld) {
		return Err(io::Error::new(
			io::ErrorKind::AlreadyExists,
			format!("systemd-resolved already has a per-link route for .{tld}; testd will not change it"),
		));
	}
	if !state.dns.is_empty() || !state.domains.is_empty() {
		return Err(io::Error::new(
			io::ErrorKind::AlreadyExists,
			format!(
				"systemd-resolved has global DNS {:?} and domains {:?}; testd will not change them",
				state.dns, state.domains
			),
		));
	}
	let (dns, domains) = resolved_global_values(&[configuration.to_owned()]);
	let existing: Vec<String> = [("DNS", dns), ("Domains", domains)]
		.into_iter()
		.filter_map(|(key, value)| value.map(|value| format!("{key}={value}")))
		.collect();
	if !existing.is_empty() {
		return Err(io::Error::new(
			io::ErrorKind::AlreadyExists,
			format!("systemd-resolved configuration contains global {}; testd will not change it", existing.join(" ")),
		));
	}
	Ok(LinuxResolverPreflight::Ready {
		snapshot: linux_resolver::snapshot_hash(dns_output, domain_output, configuration),
	})
}

/// Inspect the live global scope and systemd's merged configuration before
/// authorizing a route that would share or replace global DNS settings.
#[cfg(target_os = "linux")]
fn linux_resolver_preflight(tld: &str, addr: SocketAddr) -> io::Result<LinuxResolverPreflight> {
	if !resolved_active() {
		return Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"systemd-resolved is not active; run `systemctl enable --now systemd-resolved` first",
		));
	}
	let (dns, domains) = linux_resolver_outputs()?;
	if global_resolver_state(&dns, &domains)?.is_compatible(tld, addr) {
		return Ok(LinuxResolverPreflight::Compatible);
	}
	let configuration = systemd_probe("systemd-analyze", &["cat-config", "systemd/resolved.conf"])?;
	assess_linux_resolver(tld, addr, &dns, &domains, &configuration)
}

#[cfg(target_os = "windows")]
fn is_os_resolver_configured_windows(tld: &str, addr: SocketAddr) -> bool {
	let Ok(output) = silent_command("powershell")
		.args(["-NoProfile", "-NonInteractive", "-Command", &nrpt_query_command(tld)])
		.output()
	else {
		return false;
	};
	let stdout = String::from_utf8_lossy(&output.stdout);
	nrpt_has_name_server(&stdout, addr)
}

#[cfg(any(target_os = "windows", test))]
fn nrpt_query_command(tld: &str) -> String {
	format!(
		"Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '.{tld}' }} | ForEach-Object {{ $_.NameServers }}"
	)
}

#[cfg(any(target_os = "windows", test))]
fn nrpt_has_name_server(output: &str, addr: SocketAddr) -> bool {
	let expected = addr.ip().to_string();
	output.split_whitespace().any(|server| server == expected)
}

/// Commands needed to configure the OS resolver for a given TLD and DNS address.
#[cfg(target_os = "macos")]
fn resolver_commands(tld: &str, addr: SocketAddr) -> Vec<String> {
	let path = format!("/etc/resolver/{tld}");
	let content = format!("nameserver {}\\nport {}\\n", addr.ip(), addr.port());
	vec![
		"mkdir -p /etc/resolver".to_owned(),
		format!("printf '{content}' > {path}"),
		"dscacheutil -flushcache".to_owned(),
		"killall -HUP mDNSResponder".to_owned(),
	]
}

/// How to obtain the privileges for a one-time system change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
	/// `sudo` on the terminal; assumes a TTY.
	Sudo,
	/// Native OS authorization dialog (osascript, pkexec, UAC).
	Gui,
}

impl Elevation {
	#[cfg(target_os = "linux")]
	fn linux_authorizer(self) -> &'static str {
		match self {
			Self::Sudo => "sudo",
			Self::Gui => "pkexec",
		}
	}

	/// Configure the OS resolver using this strategy.
	pub fn setup_os_resolver(self, tld: &str, addr: SocketAddr) -> io::Result<()> {
		match self {
			Self::Sudo => setup_os_resolver(tld, addr),
			Self::Gui => setup_os_resolver_gui(tld, addr),
		}
	}
}

// --- CLI entry point (sudo) ---

/// Configure the OS to forward `.<tld>` queries to the given DNS server address.
/// Uses `sudo`: requires a TTY for password input.
pub fn setup_os_resolver(tld: &str, addr: SocketAddr) -> io::Result<()> {
	#[cfg(target_os = "macos")]
	return setup_sudo_unix(tld, addr);

	#[cfg(target_os = "linux")]
	return linux_resolver::setup(tld, addr, Elevation::Sudo);

	#[cfg(target_os = "windows")]
	return setup_gui_windows(tld, addr);

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for DNS resolver setup"))
}

/// Run each resolver command individually with `sudo`.
#[cfg(target_os = "macos")]
fn setup_sudo_unix(tld: &str, addr: SocketAddr) -> io::Result<()> {
	for cmd in resolver_commands(tld, addr) {
		let status = silent_command("sudo").args(["sh", "-c", &cmd]).status()?;
		if !status.success() {
			return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("failed to run: {cmd}")));
		}
	}
	Ok(())
}

// --- GUI entry point (native auth dialogs) ---

/// Configure the OS to forward `.<tld>` queries to the given DNS server address.
/// Uses native OS authentication dialogs: suitable for GUI apps without a TTY.
pub fn setup_os_resolver_gui(tld: &str, addr: SocketAddr) -> io::Result<()> {
	#[cfg(target_os = "macos")]
	return setup_gui_macos(tld, addr);

	#[cfg(target_os = "linux")]
	return linux_resolver::setup(tld, addr, Elevation::Gui);

	#[cfg(target_os = "windows")]
	return setup_gui_windows(tld, addr);

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for DNS resolver setup"))
}

/// macOS: use `osascript` with `with administrator privileges` for a native auth dialog.
#[cfg(target_os = "macos")]
fn setup_gui_macos(tld: &str, addr: SocketAddr) -> io::Result<()> {
	let script = resolver_commands(tld, addr).join(" && ");
	let osascript = format!("do shell script \"{script}\" with administrator privileges");

	let status = silent_command("osascript").args(["-e", &osascript]).status()?;
	if !status.success() {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"resolver setup failed (user cancelled or auth error)",
		));
	}
	Ok(())
}

/// Windows: install the NRPT rule through the audited elevated helper. The
/// helper prompts for UAC only when this process is not already elevated.
#[cfg(target_os = "windows")]
fn setup_gui_windows(tld: &str, addr: SocketAddr) -> io::Result<()> {
	let name_server = addr.ip().to_string();
	run_windows_helper("InstallNrpt", &[("Tld", tld), ("NameServer", name_server.as_str())])
}

// --- CA trust ---

/// Trust Caddy's local CA so browsers accept `https://*.{tld}` without warnings.
/// Uses `sudo` on the CLI; requires a TTY for password input.
pub fn trust_caddy_ca() -> io::Result<()> {
	#[cfg(any(target_os = "macos", target_os = "linux"))]
	return sudo_run(&caddy_binary()?, &["trust"]);

	#[cfg(target_os = "windows")]
	return run_elevated_windows(&caddy_binary()?, &["trust"]);

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for CA trust"))
}

/// Trust Caddy's local CA via a native OS authentication dialog (for GUI apps).
pub fn trust_caddy_ca_gui() -> io::Result<()> {
	#[cfg(target_os = "macos")]
	return trust_gui_macos(&caddy_binary()?);

	#[cfg(target_os = "linux")]
	return trust_gui_linux(&caddy_binary()?);

	#[cfg(target_os = "windows")]
	return run_elevated_windows(&caddy_binary()?, &["trust"]);

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for CA trust"))
}

fn caddy_binary() -> io::Result<std::path::PathBuf> {
	testd_core::config::find_caddy_binary()
		.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "caddy not found; install Caddy or add it to PATH"))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sudo_run(binary: &Path, args: &[&str]) -> io::Result<()> {
	let status = silent_command("sudo").arg(binary).args(args).status()?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "command failed (user cancelled or auth error)"));
	}
	Ok(())
}

#[cfg(target_os = "macos")]
fn trust_gui_macos(binary: &Path) -> io::Result<()> {
	let script = format!("{} trust", shell_quote(&binary.to_string_lossy()));
	let script = script.replace('\\', "\\\\").replace('"', "\\\"");
	let status = silent_command("osascript")
		.args(["-e", &format!("do shell script \"{script}\" with administrator privileges")])
		.status()?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "CA trust failed (user cancelled or auth error)"));
	}
	Ok(())
}

#[cfg(target_os = "linux")]
fn trust_gui_linux(binary: &Path) -> io::Result<()> {
	let status = silent_command("pkexec").arg(binary).arg("trust").status()?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "CA trust failed (user cancelled or auth error)"));
	}
	Ok(())
}

#[cfg(target_os = "windows")]
fn run_elevated_windows(binary: &Path, args: &[&str]) -> io::Result<()> {
	let arg_list: Vec<String> = args.iter().map(|arg| format!("'{arg}'")).collect();
	let command = format!(
		"Start-Process -FilePath '{}' -ArgumentList {} -Verb RunAs -Wait",
		binary.display(),
		arg_list.join(",")
	);
	let status = silent_command("powershell").args(["-Command", &command]).status()?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "CA trust failed (user cancelled or auth error)"));
	}
	Ok(())
}

/// Quote a value for safe interpolation into a POSIX shell command string.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn shell_quote(value: &str) -> String {
	format!("'{}'", value.replace('\'', r"'\''"))
}

// --- Teardown ---

/// Remove the OS resolver configuration for `.<tld>`.
pub fn teardown_os_resolver(tld: &str) -> io::Result<()> {
	#[cfg(target_os = "macos")]
	return teardown_macos(tld);

	#[cfg(target_os = "linux")]
	return linux_resolver::teardown(tld, Elevation::Sudo);

	#[cfg(target_os = "windows")]
	return teardown_windows(tld);

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for DNS resolver teardown"))
}

#[cfg(target_os = "macos")]
fn teardown_macos(tld: &str) -> io::Result<()> {
	let path = format!("/etc/resolver/{tld}");
	let status = silent_command("sudo").args(["rm", "-f", &path]).status()?;
	if !status.success() {
		return Err(io::Error::other(format!("sudo rm {path} failed")));
	}
	let status = silent_command("sudo").args(["dscacheutil", "-flushcache"]).status()?;
	if !status.success() {
		return Err(io::Error::other("sudo dscacheutil -flushcache failed"));
	}
	let status = silent_command("sudo").args(["killall", "-HUP", "mDNSResponder"]).status()?;
	if !status.success() {
		return Err(io::Error::other("sudo killall -HUP mDNSResponder failed"));
	}
	Ok(())
}

#[cfg(target_os = "windows")]
fn teardown_windows(tld: &str) -> io::Result<()> {
	run_windows_helper("RemoveNrpt", &[("Tld", tld)])
}

// --- Caddyfile import ---

/// Render a path for a Caddyfile import, using forward slashes.
/// Caddy accepts both separators on Windows, and forward slashes avoid backslash escaping.
fn render_caddyfile_path(path: &Path) -> String {
	path.to_string_lossy().replace('\\', "/")
}

/// Check whether the global Caddyfile already imports the managed testd Caddyfile.
pub fn has_caddyfile_import(caddyfile_path: &Path, import_path: &Path) -> bool {
	let Ok(content) = std::fs::read_to_string(caddyfile_path) else { return false };
	let import_path = render_caddyfile_path(import_path);
	content.lines().any(|line| {
		line.trim()
			.strip_prefix("import ")
			.is_some_and(|imported| imported.replace('\\', "/") == import_path)
	})
}

/// Build the new Caddyfile content with the import line appended.
/// Returns `None` if the import is already present.
fn build_caddyfile_with_import(caddyfile_path: &Path, import_path: &Path) -> Option<String> {
	if has_caddyfile_import(caddyfile_path, import_path) {
		return None;
	}
	let import_line = format!("import {}", render_caddyfile_path(import_path));
	let content = std::fs::read_to_string(caddyfile_path).unwrap_or_default();

	let mut new_content = content;
	if !new_content.is_empty() && !new_content.ends_with('\n') {
		new_content.push('\n');
	}
	new_content.push_str(&import_line);
	new_content.push('\n');
	Some(new_content)
}

/// Write content to a file via `sudo tee`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sudo_write(path: &Path, content: &str) -> io::Result<()> {
	use std::io::Write;
	use std::process::{Command, Stdio};

	let mut child = Command::new("sudo")
		.args(["tee", &path.display().to_string()])
		.stdin(Stdio::piped())
		.stdout(Stdio::null())
		.spawn()?;
	child.stdin.take().unwrap().write_all(content.as_bytes())?;
	let status = child.wait()?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "sudo tee failed"));
	}
	Ok(())
}

/// Write content to a file via a native GUI auth dialog.
#[cfg(target_os = "macos")]
fn gui_write(path: &Path, content: &str) -> io::Result<()> {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD;

	/* osascript cannot pipe stdin; pass the public Caddyfile as base64 and let
	the elevated shell write its own root-only temp file. */
	let encoded = STANDARD.encode(content.as_bytes());
	let target = shell_quote(&path.display().to_string());
	let command = format!(
		"tmp=$(mktemp /var/root/testd-caddy.XXXXXX) && trap 'rm -f $tmp' EXIT && \
		 printf '%s' '{encoded}' | base64 -D > $tmp && cat $tmp > {target}"
	);
	let script = format!("do shell script \"{command}\" with administrator privileges");
	let status = silent_command("osascript").args(["-e", &script]).status()?;
	if !status.success() {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"Caddyfile write failed (user cancelled or auth error)",
		));
	}
	Ok(())
}

/// Write content to a file via pkexec (polkit).
#[cfg(target_os = "linux")]
fn gui_write(path: &Path, content: &str) -> io::Result<()> {
	use std::io::Write;
	use std::process::{Command, Stdio};

	let mut child = Command::new("pkexec")
		.args(["tee", &path.display().to_string()])
		.stdin(Stdio::piped())
		.stdout(Stdio::null())
		.spawn()?;
	child.stdin.take().unwrap().write_all(content.as_bytes())?;
	let status = child.wait()?;
	if !status.success() {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"Caddyfile write failed (user cancelled or auth error)",
		));
	}
	Ok(())
}

/// Write content to a file via UAC elevation.
#[cfg(target_os = "windows")]
fn gui_write(path: &Path, content: &str) -> io::Result<()> {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD;

	let encoded = STANDARD.encode(content.as_bytes());
	let target = powershell_single_quote(&path.display().to_string());
	let script =
		format!("$bytes = [Convert]::FromBase64String('{encoded}'); [IO.File]::WriteAllBytes({target}, $bytes)");
	let encoded_command = powershell_encoded(&script);
	let argument = format!("-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded_command}");
	let command = format!(
		"$ErrorActionPreference = 'Stop'; $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ErrorAction Stop -ArgumentList {}; exit $p.ExitCode",
		powershell_single_quote(&argument)
	);
	let status = silent_command("powershell")
		.args(["-NoProfile", "-Command", &command])
		.status()?;
	if !status.success() {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"Caddyfile write failed (user cancelled or auth error)",
		));
	}
	Ok(())
}

/// Add the testd import line to the global Caddyfile if not already present.
/// Creates the file if it doesn't exist. Falls back to `sudo` on permission denied.
pub fn write_caddyfile_import(caddyfile_path: &Path, import_path: &Path) -> io::Result<()> {
	let Some(new_content) = build_caddyfile_with_import(caddyfile_path, import_path) else {
		return Ok(());
	};

	match std::fs::write(caddyfile_path, &new_content) {
		Ok(()) => Ok(()),
		Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
			#[cfg(any(target_os = "macos", target_os = "linux"))]
			return sudo_write(caddyfile_path, &new_content);

			#[cfg(target_os = "windows")]
			return gui_write(caddyfile_path, &new_content);

			#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
			Err(e)
		},
		Err(e) => Err(e),
	}
}

/// Add the testd import line to the global Caddyfile via native GUI auth dialog.
/// Tries direct write first; escalates with a native auth prompt on permission denied.
pub fn write_caddyfile_import_gui(caddyfile_path: &Path, import_path: &Path) -> io::Result<()> {
	let Some(new_content) = build_caddyfile_with_import(caddyfile_path, import_path) else {
		return Ok(());
	};

	match std::fs::write(caddyfile_path, &new_content) {
		Ok(()) => Ok(()),
		Err(e) if e.kind() == io::ErrorKind::PermissionDenied => gui_write(caddyfile_path, &new_content),
		Err(e) => Err(e),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(any(target_os = "macos", target_os = "linux"))]
	#[test]
	fn shell_quote_escapes_single_quotes() {
		assert_eq!(shell_quote("/usr/local/bin/caddy"), "'/usr/local/bin/caddy'");
		assert_eq!(shell_quote("/tmp/it's here"), r"'/tmp/it'\''s here'");
	}

	#[test]
	fn testd_root_names_accept_legacy_and_pronounceable_suffixes() {
		let suffix = covo::encode(b"test");
		assert!(is_testd_root_cn("testd root"));
		assert!(is_testd_root_cn(&format!("testd root {suffix}")));
		assert!(!is_testd_root_cn("testd root testing"));
		assert!(!is_testd_root_cn("testd root testing-extra"));
		assert!(!is_testd_root_cn("testd root 0123abcd"));
		assert!(!is_testd_root_cn("testd root ragiba fihula visuba"));
		assert!(!is_testd_root_cn("testd intermediate"));
	}

	#[test]
	fn trust_removal_requires_a_certificate_before_elevation() {
		for pem in ["", " \t\n"] {
			assert_eq!(untrust_root(pem).unwrap_err().kind(), io::ErrorKind::InvalidInput);
			assert_eq!(untrust_root_gui(pem).unwrap_err().kind(), io::ErrorKind::InvalidInput);
		}
	}

	#[test]
	fn macos_root_list_parses_every_certificate() {
		let output = "keychain: \"/Library/Keychains/System.keychain\"\n\
		-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n\
		SHA-1 hash: 1111111111111111111111111111111111111111\n\
		-----BEGIN CERTIFICATE-----\nBwgJ\n-----END CERTIFICATE-----\n";
		let roots = parse_macos_roots(output);
		assert_eq!(roots.len(), 2);
		assert!(roots[0].pem.contains("AAEC"));
		assert!(roots[1].pem.contains("BwgJ"));
		assert_eq!(roots[0].hash.len(), 40);
		assert_ne!(roots[0].hash, roots[1].hash);
	}

	#[test]
	fn sha1_hex_matches_a_known_digest() {
		assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn linux_resolver_requires_an_exact_compatible_global_scope() {
		let addr: SocketAddr = "127.0.0.1:7753".parse().unwrap();
		let dns = "Global: 127.0.0.1:7753\nLink 2 (eth0): 1.1.1.1\n";
		let domains = "Global: ~test\nLink 2 (eth0): ~corp\n";
		let state = global_resolver_state(dns, domains).unwrap();
		assert!(state.is_compatible("test", addr));
		let extra_dns = global_resolver_state("Global: 127.0.0.1:7753\n        1.1.1.1\n", domains).unwrap();
		assert!(!extra_dns.is_compatible("test", addr));
		let extra_domain = global_resolver_state(dns, "Global: ~test ~corp\n").unwrap();
		assert!(!extra_domain.is_compatible("test", addr));
		let similar_domain = global_resolver_state(dns, "Global: ~testing\n").unwrap();
		assert!(!similar_domain.is_compatible("test", addr));
		let link_conflict = global_resolver_state(dns, "Global: ~test\nLink 2 (eth0): ~TEST.\n").unwrap();
		assert!(!link_conflict.is_compatible("test", addr));
		let equivalent = global_resolver_state(dns, "Global: ~TEST.\n").unwrap();
		assert!(equivalent.is_compatible("test", addr));
		let ipv6: SocketAddr = "[::1]:7753".parse().unwrap();
		let ipv6_state = global_resolver_state("Global: [0:0:0:0:0:0:0:1]:7753\n", domains).unwrap();
		assert!(ipv6_state.is_compatible("test", ipv6));
		assert_eq!(dns_server_value(ipv6), "[::1]:7753");
		assert!(global_resolver_state("Link 2 (eth0): 1.1.1.1\n", domains).is_err());
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn linux_resolver_preflight_refuses_existing_or_pending_global_settings() {
		let addr: SocketAddr = "127.0.0.1:7753".parse().unwrap();
		let empty = "Global:";
		assert!(matches!(
			assess_linux_resolver("test", addr, empty, empty, "# no global settings\n").unwrap(),
			LinuxResolverPreflight::Ready { .. }
		));
		assert_eq!(
			assess_linux_resolver("test", addr, "Global: 127.0.0.1:7753", "Global: ~test", "DNS=1.1.1.1").unwrap(),
			LinuxResolverPreflight::Compatible
		);
		for (dns, domains, config) in [
			("Global: 1.1.1.1", empty, ""),
			(empty, "Global: ~corp", ""),
			(empty, "Global:\nLink 2 (eth0):\n        TEST.\n", ""),
			(empty, empty, "# /usr/lib/systemd/resolved.conf.d/40-vendor.conf\n[Resolve]\nDNS=9.9.9.9\n"),
			(empty, empty, "# /run/systemd/resolved.conf.d/70-corp.conf\n[Resolve]\nDomains=~corp\n"),
		] {
			let error = assess_linux_resolver("test", addr, dns, domains, config).unwrap_err();
			assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
		}
		let reset = "[Resolve]\nDNS=1.1.1.1\nDomains=~corp\n[Resolve]\nDNS=\nDomains=\n";
		assert!(matches!(
			assess_linux_resolver("test", addr, empty, empty, reset).unwrap(),
			LinuxResolverPreflight::Ready { .. }
		));
	}

	#[cfg(target_os = "macos")]
	#[test]
	fn macos_resolver_writes_the_route_and_flushes_the_cache() {
		let addr: SocketAddr = "127.0.0.1:7753".parse().unwrap();
		let commands = resolver_commands("test", addr);
		assert_eq!(commands.len(), 4);
		assert!(commands[1].contains("/etc/resolver/test"));
		assert!(commands[1].contains("nameserver 127.0.0.1"));
		assert!(commands[1].contains("port 7753"));
		assert_eq!(commands[2], "dscacheutil -flushcache");
		assert_eq!(commands[3], "killall -HUP mDNSResponder");
	}

	#[test]
	fn resolved_dropin_routes_only_the_testd_domain() {
		let addr: SocketAddr = "127.0.0.1:7753".parse().unwrap();
		let dropin = resolved_dropin("test", addr);
		assert!(dropin.contains("[Resolve]\nDNS=127.0.0.1:7753\nDomains=~test\n"), "{dropin}");
		assert!(!dropin.contains("Domains=~."), "{dropin}");
	}

	#[test]
	fn resolved_global_values_clear_lists_on_empty_assignment() {
		let files = vec![
			"[Resolve]\nDNS=1.1.1.1\nDomains=~corp\n".to_owned(),
			"[Resolve]\nDNS=10.0.0.1\n".to_owned(),
			"[Resolve]\nDNS=\n".to_owned(),
		];
		let (dns, domains) = resolved_global_values(&files);
		assert_eq!(dns, None, "an empty assignment clears the list");
		assert_eq!(domains.as_deref(), Some("~corp"));
	}

	#[test]
	fn resolved_global_values_accumulate_lists_until_reset() {
		let files = vec![
			"[Resolve]\nDNS=1.1.1.1\nDomains=~corp\n".to_owned(),
			"[Resolve]\nDNS=9.9.9.9\nDomains=~dev\n".to_owned(),
		];
		let (dns, domains) = resolved_global_values(&files);
		assert_eq!(dns.as_deref(), Some("1.1.1.1 9.9.9.9"));
		assert_eq!(domains.as_deref(), Some("~corp ~dev"));
	}

	#[test]
	fn resolved_global_values_ignore_comments_and_other_sections() {
		let files = vec!["# DNS=9.9.9.9\n[Resolve]\n; DNS=8.8.8.8\n[Internet]\nDNS=7.7.7.7\n".to_owned()];
		assert_eq!(resolved_global_values(&files), (None, None));
	}

	#[test]
	fn nrpt_query_selects_name_servers_for_namespace() {
		let command = nrpt_query_command("test");
		assert!(command.contains("Namespace -eq '.test'"));
		assert!(command.contains("NameServers"));
	}

	#[test]
	fn nrpt_detection_matches_server_ip() {
		let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
		assert!(nrpt_has_name_server("127.0.0.1\r\n", addr));
		assert!(!nrpt_has_name_server("1.1.1.1\r\n", addr));
		assert!(!nrpt_has_name_server("", addr));
	}

	#[test]
	fn import_path_is_rendered_with_forward_slashes() {
		assert_eq!(render_caddyfile_path(Path::new(r"C:\Users\me\Caddyfile")), "C:/Users/me/Caddyfile");
	}

	#[test]
	fn detects_imports_written_with_either_separator() {
		let dir = std::env::temp_dir().join(format!("testd-setup-slashes-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let caddyfile = dir.join("Caddyfile");
		std::fs::write(&caddyfile, "import C:\\Users\\me\\managed\n").unwrap();
		assert!(has_caddyfile_import(&caddyfile, Path::new(r"C:\Users\me\managed")));
		std::fs::remove_dir_all(&dir).ok();
	}

	#[test]
	fn import_line_is_appended_once() {
		let dir = std::env::temp_dir().join(format!("testd-setup-test-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let caddyfile = dir.join("Caddyfile");
		let managed = dir.join("managed");
		std::fs::write(&caddyfile, ":8080\n").unwrap();

		let content = build_caddyfile_with_import(&caddyfile, &managed).expect("import should be added");
		assert!(content.starts_with(":8080\n"));
		assert!(content.ends_with(&format!("import {}\n", render_caddyfile_path(&managed))));

		std::fs::write(&caddyfile, &content).unwrap();
		assert!(build_caddyfile_with_import(&caddyfile, &managed).is_none());

		std::fs::remove_dir_all(&dir).ok();
	}
}

// --- root CA trust ---

/// Prefix of the testd root common name; new roots append a pronounceable name.
#[cfg(any(target_os = "macos", test))]
const ROOT_CN: &str = "testd root";

/// One certificate returned by `security find-certificate`, with the SHA-1
/// used to delete that exact item rather than the first item with its name.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq)]
struct MacRoot {
	hash: String,
	pem: String,
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_roots(output: &str) -> Vec<MacRoot> {
	let mut roots = Vec::new();
	let mut pem = String::new();
	for line in output.lines() {
		if line == "-----BEGIN CERTIFICATE-----" {
			pem.clear();
			pem.push_str(line);
			pem.push('\n');
		} else if line == "-----END CERTIFICATE-----" {
			pem.push_str(line);
			pem.push('\n');
			if let Ok(der) = pem_to_der(&pem) {
				roots.push(MacRoot { hash: sha1_hex(&der), pem: normalize_pem(&pem) });
			}
			pem.clear();
		} else if !pem.is_empty() {
			pem.push_str(line);
			pem.push('\n');
		}
	}
	roots
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn sha1_hex(bytes: &[u8]) -> String {
	use sha1::{Digest, Sha1};

	Sha1::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether the testd root is already in the system trust store.
pub fn is_root_trusted(cert_pem: &str) -> bool {
	#[cfg(target_os = "linux")]
	return is_root_trusted_linux(cert_pem);

	#[cfg(target_os = "macos")]
	return is_root_trusted_macos(cert_pem);

	#[cfg(target_os = "windows")]
	return is_root_trusted_windows(cert_pem);

	#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
	false
}

#[cfg(target_os = "linux")]
fn system_root_path() -> std::path::PathBuf {
	std::path::PathBuf::from(trust_layout().anchor)
}

/// Where a distro keeps local CA anchors and how it rebuilds the trust bundle.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct TrustLayout<'a> {
	directory: &'a str,
	anchor: &'a str,
	reload: &'a str,
}

/// Debian and Ubuntu ship `update-ca-certificates` and read anchors from the
/// local directory; Fedora and RHEL ship `update-ca-trust` and read the pki
/// anchors. Pick by the tools that actually have to run, and keep the
/// long-standing layout where neither is recognised.
#[cfg(target_os = "linux")]
fn trust_layout_for(has_update_ca_certificates: bool, has_fedora_anchors: bool) -> TrustLayout<'static> {
	if has_fedora_anchors && !has_update_ca_certificates {
		TrustLayout {
			directory: "/etc/pki/ca-trust/source/anchors",
			anchor: "/etc/pki/ca-trust/source/anchors/testd-root.crt",
			reload: "update-ca-trust extract",
		}
	} else {
		TrustLayout {
			directory: "/usr/local/share/ca-certificates",
			anchor: "/usr/local/share/ca-certificates/testd-root.crt",
			reload: "update-ca-certificates",
		}
	}
}

#[cfg(target_os = "linux")]
fn trust_layout() -> TrustLayout<'static> {
	let debian = ["/usr/sbin/update-ca-certificates", "/usr/bin/update-ca-certificates"]
		.iter()
		.any(|path| std::path::Path::new(path).exists());
	let fedora = std::path::Path::new("/usr/bin/update-ca-trust").exists()
		&& std::path::Path::new("/etc/pki/ca-trust/source/anchors").is_dir();
	trust_layout_for(debian, fedora)
}

#[cfg(target_os = "linux")]
const TRUST_ANCHOR_CONFLICT: i32 = 17;
#[cfg(target_os = "linux")]
const TRUST_OWNERSHIP_UNRECORDED: i32 = 18;

#[cfg(target_os = "linux")]
fn trust_owner_marker(layout: &TrustLayout<'_>) -> std::path::PathBuf {
	std::path::PathBuf::from(format!("{}.owner", layout.anchor))
}

#[cfg(target_os = "linux")]
fn trust_install_script(layout: &TrustLayout<'_>) -> String {
	let directory = shell_quote(layout.directory);
	let anchor = shell_quote(layout.anchor);
	let marker = shell_quote(&trust_owner_marker(layout).to_string_lossy());
	let template = shell_quote(&format!("{}/.testd-root.XXXXXX", layout.directory));
	let owner_template = shell_quote(&format!("{}/.testd-owner.XXXXXX", layout.directory));
	let reload = layout.reload;
	// Record ownership only after exclusively linking the new anchor. The ID is
	// passed on stdin rather than exposing it in the privileged command line.
	format!(
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n\
		IFS= read -r owner || exit 1\n\
		[ -n \"$owner\" ] || exit 1\n\
		mkdir -p {directory} || exit 1\n\
		temporary=$(mktemp {template}) || exit 1\n\
		trap 'rm -f -- \"$temporary\"' EXIT\n\
		owner_temporary=$(mktemp {owner_template}) || exit 1\n\
		trap 'rm -f -- \"$temporary\" \"$owner_temporary\"' EXIT\n\
		cat > \"$temporary\" || exit 1\n\
		chmod 0644 \"$temporary\" || exit 1\n\
		owner_hash=$(printf '%s' \"$owner\" | sha256sum) || exit 1\n\
		owner_hash=${{owner_hash%% *}}\n\
		fingerprint=$(stat -c '%d:%i:%u:%g:%a' -- \"$temporary\") || exit 1\n\
		printf '%s\\n%s\\n' \"$owner_hash\" \"$fingerprint\" > \"$owner_temporary\" || exit 1\n\
		chmod 0600 \"$owner_temporary\" || exit 1\n\
		if [ -e {marker} ] || [ -L {marker} ]; then exit {TRUST_ANCHOR_CONFLICT}; fi\n\
		if ln -T -- \"$temporary\" {anchor} 2>/dev/null; then\n\
		  ln -T -- \"$owner_temporary\" {marker} 2>/dev/null || exit {TRUST_OWNERSHIP_UNRECORDED}\n\
		  {reload} || exit 1\n\
		elif [ -e {anchor} ] || [ -L {anchor} ]; then\n\
		  exit {TRUST_ANCHOR_CONFLICT}\n\
		else\n\
		  exit 1\n\
		fi"
	)
}

#[cfg(target_os = "linux")]
fn trust_anchor_conflict(path: &Path) -> io::Error {
	io::Error::new(
		io::ErrorKind::AlreadyExists,
		format!(
			"{} or its ownership record conflicts with the requested trust; testd did not overwrite it",
			path.display()
		),
	)
}

#[cfg(target_os = "linux")]
fn trust_ownership_conflict(path: &Path) -> io::Error {
	io::Error::new(
		io::ErrorKind::AlreadyExists,
		format!("{} is unowned by this installation or has changed; trust was not removed", path.display()),
	)
}

#[cfg(target_os = "linux")]
fn system_entry_present(path: &Path) -> io::Result<bool> {
	match std::fs::symlink_metadata(path) {
		Ok(_) => Ok(true),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
		Err(error) => Err(error),
	}
}

#[cfg(target_os = "linux")]
fn owned_trust_input(owner: &ownership::InstallationId, cert_pem: &str) -> Vec<u8> {
	format!("{}\n{cert_pem}", owner.as_str()).into_bytes()
}

#[cfg(target_os = "linux")]
fn single_anchor_der(pem: &str) -> io::Result<Vec<u8>> {
	if pem.matches("-----BEGIN CERTIFICATE-----").count() != 1 {
		return Err(io::Error::new(io::ErrorKind::InvalidData, "expected one root certificate"));
	}
	pem_to_der(pem)
}

#[cfg(target_os = "linux")]
fn existing_linux_anchor(path: &Path, cert_pem: &str) -> io::Result<bool> {
	let expected = single_anchor_der(cert_pem)?;
	match std::fs::read_to_string(path) {
		Ok(installed) if single_anchor_der(&installed).is_ok_and(|der| der == expected) => Ok(true),
		Ok(_) => Err(trust_anchor_conflict(path)),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
		Err(error) => Err(io::Error::new(error.kind(), format!("cannot inspect {}: {error}", path.display()))),
	}
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_with_stdin(mut command: std::process::Command, input: &[u8]) -> io::Result<std::process::ExitStatus> {
	use std::io::Write;
	use std::process::Stdio;

	command.stdin(Stdio::piped());
	let mut child = command.spawn()?;
	let mut stdin = child.stdin.take().expect("stdin was requested");
	stdin.write_all(input)?;
	drop(stdin);
	child.wait()
}

#[cfg(target_os = "linux")]
fn trust_remove_script(layout: &TrustLayout<'_>) -> String {
	let anchor = shell_quote(layout.anchor);
	let marker = shell_quote(&trust_owner_marker(layout).to_string_lossy());
	let template = shell_quote(&format!("{}/.testd-remove.XXXXXX", layout.directory));
	let reload = layout.reload;
	format!(
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n\
		IFS= read -r owner || exit 1\n\
		[ -n \"$owner\" ] || exit 1\n\
		temporary=$(mktemp {template}) || exit 1\n\
		trap 'rm -f -- \"$temporary\"' EXIT\n\
		cat > \"$temporary\" || exit 1\n\
		if [ ! -e {marker} ] && [ ! -L {marker} ]; then\n\
		  if [ -e {anchor} ] || [ -L {anchor} ]; then exit {TRUST_ANCHOR_CONFLICT}; fi\n\
		  exit 0\n\
		fi\n\
		[ -f {marker} ] && [ ! -L {marker} ] || exit {TRUST_ANCHOR_CONFLICT}\n\
		marker_access=$(stat -c '%u:%a' -- {marker}) || exit {TRUST_ANCHOR_CONFLICT}\n\
		[ \"$marker_access\" = \"$(id -u):600\" ] || exit {TRUST_ANCHOR_CONFLICT}\n\
		{{\n\
		  IFS= read -r recorded_owner_hash || exit {TRUST_ANCHOR_CONFLICT}\n\
		  IFS= read -r recorded_fingerprint || exit {TRUST_ANCHOR_CONFLICT}\n\
		  unexpected=\n\
		  if IFS= read -r unexpected || [ -n \"$unexpected\" ]; then exit {TRUST_ANCHOR_CONFLICT}; fi\n\
		}} < {marker}\n\
		owner_hash=$(printf '%s' \"$owner\" | sha256sum) || exit 1\n\
		owner_hash=${{owner_hash%% *}}\n\
		[ \"$owner_hash\" = \"$recorded_owner_hash\" ] || exit {TRUST_ANCHOR_CONFLICT}\n\
		if [ -e {anchor} ] || [ -L {anchor} ]; then\n\
		  [ -f {anchor} ] && [ ! -L {anchor} ] || exit {TRUST_ANCHOR_CONFLICT}\n\
		  fingerprint=$(stat -c '%d:%i:%u:%g:%a' -- {anchor}) || exit {TRUST_ANCHOR_CONFLICT}\n\
		  [ \"$fingerprint\" = \"$recorded_fingerprint\" ] || exit {TRUST_ANCHOR_CONFLICT}\n\
		  cmp -s -- \"$temporary\" {anchor} || exit {TRUST_ANCHOR_CONFLICT}\n\
		  rm -- {anchor} || exit 1\n\
		fi\n\
		{reload} || exit 1\n\
		rm -- {marker} || exit 1"
	)
}

#[cfg(target_os = "linux")]
fn is_root_trusted_linux(cert_pem: &str) -> bool {
	existing_linux_anchor(&system_root_path(), cert_pem).is_ok_and(|installed| installed)
}

#[cfg(any(target_os = "macos", test))]
fn is_testd_root_cn(common_name: &str) -> bool {
	if common_name == ROOT_CN {
		return true;
	}
	let Some(suffix) = common_name.strip_prefix(ROOT_CN).and_then(|rest| rest.strip_prefix(' ')) else {
		return false;
	};
	covo::decode(suffix).is_ok_and(|bytes| bytes.len() == 4 && covo::encode(&bytes) == suffix)
}

#[cfg(target_os = "macos")]
fn certificate_common_name(pem: &str) -> Option<String> {
	let der = pem_to_der(pem).ok()?;
	let (_, certificate) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
	let name = certificate.subject().iter_common_name().next()?;
	Some(name.as_str().ok()?.to_owned())
}

#[cfg(target_os = "macos")]
fn macos_testd_roots() -> io::Result<Vec<MacRoot>> {
	let output = silent_command("security")
		.args(["find-certificate", "-a", "-p", "/Library/Keychains/System.keychain"])
		.output()?;
	if !output.status.success() {
		return Ok(Vec::new());
	}
	let mut roots = parse_macos_roots(&String::from_utf8_lossy(&output.stdout));
	roots.retain(|root| certificate_common_name(&root.pem).is_some_and(|name| is_testd_root_cn(&name)));
	Ok(roots)
}

#[cfg(target_os = "macos")]
fn is_root_trusted_macos(cert_pem: &str) -> bool {
	let Ok(roots) = macos_testd_roots() else { return false };
	// More than one testd root is stale state from an earlier run. Treating it
	// as untrusted makes init and doctor --fix replace the whole set.
	roots.len() == 1 && roots[0].pem == normalize_pem(cert_pem)
}

#[cfg(target_os = "macos")]
fn delete_macos_roots(roots: &[MacRoot]) -> io::Result<()> {
	for root in roots {
		let status = silent_command("sudo")
			.args(["security", "delete-certificate", "-t", "-Z", &root.hash, "/Library/Keychains/System.keychain"])
			.status()?;
		if !status.success() {
			return Err(io::Error::other(format!("failed to remove testd root {}", root.hash)));
		}
	}
	Ok(())
}

#[cfg(target_os = "macos")]
fn delete_macos_roots_script(roots: &[MacRoot]) -> String {
	roots
		.iter()
		.map(|root| {
			format!("security delete-certificate -t -Z {} /Library/Keychains/System.keychain || exit 1; ", root.hash)
		})
		.collect()
}

#[cfg(target_os = "windows")]
fn is_root_trusted_windows(cert_pem: &str) -> bool {
	let Ok(der) = pem_to_der(cert_pem) else { return false };
	let thumbprint = sha1_hex(&der);
	let Ok(output) = silent_command("certutil").args(["-store", "Root"]).output() else {
		return false;
	};
	let store = compact_hex(&String::from_utf8_lossy(&output.stdout)).to_ascii_lowercase();
	store.contains(&thumbprint.to_ascii_lowercase())
}

/// Keep only hex digits so `certutil`'s spaced thumbprint output can be compared.
#[cfg(any(target_os = "windows", test))]
fn compact_hex(value: &str) -> String {
	value.chars().filter(|c| c.is_ascii_hexdigit()).collect()
}

/// Install the testd root into the system trust store via `sudo`.
pub fn trust_root(cert_pem: &str) -> io::Result<()> {
	#[cfg(target_os = "linux")]
	return trust_root_linux(cert_pem, Elevation::Sudo);

	#[cfg(target_os = "macos")]
	return trust_root_macos(cert_pem);

	#[cfg(target_os = "windows")]
	return trust_root_windows(cert_pem);

	#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for trust installation"))
}

/// Install the testd root via a native GUI authorization dialog.
pub fn trust_root_gui(cert_pem: &str) -> io::Result<()> {
	#[cfg(target_os = "linux")]
	{
		trust_root_linux(cert_pem, Elevation::Gui)
	}
	#[cfg(target_os = "macos")]
	{
		use base64::Engine;
		use base64::engine::general_purpose::STANDARD;

		let roots = macos_testd_roots()?;
		// `do shell script` does not inherit stdin. Pass the public certificate
		// as base64 and let the elevated shell create its own root-only file.
		let encoded = STANDARD.encode(cert_pem.as_bytes());
		let script = format!(
			"{}tmp=$(mktemp /var/root/testd-root.XXXXXX) && trap 'rm -f $tmp' EXIT && \
			 printf '%s' '{encoded}' | base64 -D > $tmp && \
			 security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $tmp",
			delete_macos_roots_script(&roots)
		);
		let status = silent_command("osascript")
			.args(["-e", &format!("do shell script \"{script}\" with administrator privileges")])
			.status()?;
		if !status.success() {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"root CA install failed (cancelled or auth error)",
			));
		}
		Ok(())
	}
	#[cfg(target_os = "windows")]
	{
		trust_root_windows(cert_pem)
	}
	#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for trust installation"))
}

#[cfg(target_os = "linux")]
fn trust_root_linux(cert_pem: &str, elevation: Elevation) -> io::Result<()> {
	let layout = trust_layout();
	let anchor = Path::new(layout.anchor);
	if existing_linux_anchor(anchor, cert_pem)? {
		return Ok(());
	}
	let owner = ownership::InstallationId::load_or_create()?;
	let script = trust_install_script(&layout);
	let mut command = silent_command(elevation.linux_authorizer());
	command.args(["sh", "-c", &script]);
	let status = run_with_stdin(command, &owned_trust_input(&owner, cert_pem))?;
	match status.code() {
		Some(0) => Ok(()),
		Some(TRUST_ANCHOR_CONFLICT) => Err(trust_anchor_conflict(anchor)),
		Some(TRUST_OWNERSHIP_UNRECORDED) => Err(io::Error::other(format!(
			"{} was created but ownership could not be recorded; inspect the file before retrying",
			anchor.display()
		))),
		_ => Err(io::Error::other("root CA install or trust-store update failed")),
	}
}

#[cfg(target_os = "macos")]
fn trust_root_macos(cert_pem: &str) -> io::Result<()> {
	// Remove every old testd root first. The same CN can be present more than
	// once after failed runs, and `add-trusted-cert` cannot reliably set trust
	// on a duplicate item.
	delete_macos_roots(&macos_testd_roots()?)?;
	let script = "tmp=$(mktemp /var/root/testd-root.XXXXXX) && trap 'rm -f $tmp' EXIT && \
		cat > $tmp && security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $tmp";
	let mut command = silent_command("sudo");
	command.args(["sh", "-c", script]);
	let status = run_with_stdin(command, cert_pem.as_bytes())?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root CA install failed"));
	}
	Ok(())
}

#[cfg(target_os = "windows")]
fn trust_root_windows(cert_pem: &str) -> io::Result<()> {
	// Windows certificate APIs load DER reliably; PEM support depends on the
	// .NET version, so convert once before handing the file to the helper. The
	// expected thumbprint comes from the PEM, not from the mutable temp file.
	let der = pem_to_der(cert_pem)?;
	let thumbprint = sha1_hex(&der);
	let tmp = std::env::temp_dir().join(format!("testd-root-{}.cer", std::process::id()));
	std::fs::write(&tmp, &der)?;
	let result = {
		let cert_path = tmp.display().to_string();
		run_windows_helper("InstallRoot", &[("CertPath", cert_path.as_str()), ("Thumbprint", thumbprint.as_str())])
	};
	let _ = std::fs::remove_file(&tmp);
	result
}

fn require_root_certificate(cert_pem: &str) -> io::Result<()> {
	if cert_pem.trim().is_empty() {
		return Err(io::Error::new(io::ErrorKind::InvalidInput, "root certificate is required to identify trust"));
	}
	Ok(())
}

/// Remove the testd root from the system trust store via `sudo`.
///
/// Removal is safe to repeat: a certificate that is already gone is not an
/// error, so an uninstall can run after a partial failure.
pub fn untrust_root(cert_pem: &str) -> io::Result<()> {
	require_root_certificate(cert_pem)?;

	#[cfg(target_os = "linux")]
	return untrust_root_linux(cert_pem, Elevation::Sudo);

	#[cfg(target_os = "macos")]
	return untrust_root_macos();

	#[cfg(target_os = "windows")]
	return untrust_root_windows(cert_pem);

	#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for trust removal"))
}

/// Remove the testd root via a native GUI authorization dialog.
pub fn untrust_root_gui(cert_pem: &str) -> io::Result<()> {
	require_root_certificate(cert_pem)?;

	#[cfg(target_os = "linux")]
	{
		untrust_root_linux(cert_pem, Elevation::Gui)
	}
	#[cfg(target_os = "macos")]
	{
		let roots = macos_testd_roots()?;
		if roots.is_empty() {
			return Ok(());
		}
		let script = delete_macos_roots_script(&roots);
		let status = silent_command("osascript")
			.args(["-e", &format!("do shell script \"{script}\" with administrator privileges")])
			.status()?;
		if !status.success() {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"root CA removal failed (cancelled or auth error)",
			));
		}
		Ok(())
	}
	#[cfg(target_os = "windows")]
	{
		untrust_root_windows(cert_pem)
	}
	#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for trust removal"))
}

#[cfg(target_os = "linux")]
fn untrust_root_linux(cert_pem: &str, elevation: Elevation) -> io::Result<()> {
	single_anchor_der(cert_pem)?;
	let layout = trust_layout();
	let anchor = Path::new(layout.anchor);
	let marker = trust_owner_marker(&layout);
	let has_anchor = system_entry_present(anchor)?;
	let has_marker = system_entry_present(&marker)?;
	if !has_anchor && !has_marker {
		return Ok(());
	}
	if !has_marker {
		return Err(trust_ownership_conflict(anchor));
	}
	let owner = ownership::InstallationId::load()?.ok_or_else(|| trust_ownership_conflict(anchor))?;
	let script = trust_remove_script(&layout);
	let mut command = silent_command(elevation.linux_authorizer());
	command.args(["sh", "-c", &script]);
	let status = run_with_stdin(command, &owned_trust_input(&owner, cert_pem))?;
	match status.code() {
		Some(0) => Ok(()),
		Some(TRUST_ANCHOR_CONFLICT) => Err(trust_ownership_conflict(anchor)),
		_ => Err(io::Error::other("root CA removal or trust-store update failed")),
	}
}

#[cfg(target_os = "macos")]
fn untrust_root_macos() -> io::Result<()> {
	// Uninstall removes every testd root, including duplicates left by earlier
	// failed runs. Deleting by CN removes only one item and can leave the rest.
	delete_macos_roots(&macos_testd_roots()?)
}

#[cfg(target_os = "windows")]
fn untrust_root_windows(cert_pem: &str) -> io::Result<()> {
	if !is_root_trusted_windows(cert_pem) {
		return Ok(());
	}
	let der = pem_to_der(cert_pem)?;
	let thumbprint = sha1_hex(&der);
	run_windows_helper("RemoveRoot", &[("Thumbprint", thumbprint.as_str())])
}

/// Decode the first CERTIFICATE block in a PEM document to DER.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
fn pem_to_der(pem: &str) -> io::Result<Vec<u8>> {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD;

	let begin = "-----BEGIN CERTIFICATE-----";
	let end = "-----END CERTIFICATE-----";
	let start = pem
		.find(begin)
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing certificate"))?;
	let body = &pem[start + begin.len()..];
	let stop = body
		.find(end)
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unterminated certificate"))?;
	let encoded: String = body[..stop].chars().filter(|c| !c.is_whitespace()).collect();
	STANDARD
		.decode(encoded.as_bytes())
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid certificate PEM: {e}")))
}

#[cfg(target_os = "windows")]
const WINDOWS_ELEVATED_SCRIPT: &str = include_str!("../../../scripts/testd-elevated.ps1");

/// Quote a value for a PowerShell single-quoted string.
#[cfg(any(target_os = "windows", test))]
fn powershell_single_quote(value: &str) -> String {
	format!("'{}'", value.replace('\'', "''"))
}

#[cfg(target_os = "windows")]
fn windows_helper_command(action: &str, args: &[(&str, &str)]) -> String {
	// Embed the trusted helper source in the encoded command. A temp script
	// could be replaced between the write and the elevated launch.
	let script = powershell_single_quote(WINDOWS_ELEVATED_SCRIPT);
	let mut invocation = format!("& ([ScriptBlock]::Create({script})) -Action {}", powershell_single_quote(action));
	for (name, value) in args {
		invocation.push_str(&format!(" -{name} {}", powershell_single_quote(value)));
	}
	invocation
}

/// PowerShell's -EncodedCommand takes UTF-16LE base64. Encoding the whole
/// invocation keeps paths and arguments out of a re-quotable command line.
#[cfg(target_os = "windows")]
fn powershell_encoded(script: &str) -> String {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD;

	let mut bytes = Vec::with_capacity(script.len() * 2);
	for unit in script.encode_utf16() {
		bytes.extend_from_slice(&unit.to_le_bytes());
	}
	STANDARD.encode(bytes)
}

#[cfg(target_os = "windows")]
fn is_windows_elevated() -> bool {
	let command = "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";
	silent_command("powershell")
		.args(["-NoProfile", "-Command", command])
		.output()
		.ok()
		.is_some_and(|output| String::from_utf8_lossy(&output.stdout).trim().eq_ignore_ascii_case("true"))
}

/// Run one action through the audited helper. If the process is not elevated,
/// the helper is launched with `-Verb RunAs`, so only the helper is elevated.
#[cfg(target_os = "windows")]
fn run_windows_helper(action: &str, args: &[(&str, &str)]) -> io::Result<()> {
	let encoded = powershell_encoded(&windows_helper_command(action, args));
	if is_windows_elevated() {
		silent_command("powershell")
			.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encoded])
			.status()
			.and_then(require_helper_success)
	} else {
		let argument_line = format!("-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}");
		let command = format!(
			"$ErrorActionPreference = 'Stop'; $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ErrorAction Stop -ArgumentList {}; exit $p.ExitCode",
			powershell_single_quote(&argument_line)
		);
		silent_command("powershell")
			.args(["-NoProfile", "-Command", &command])
			.status()
			.and_then(require_helper_success)
	}
}

#[cfg(target_os = "windows")]
fn require_helper_success(status: std::process::ExitStatus) -> io::Result<()> {
	if status.success() {
		Ok(())
	} else {
		Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"elevated testd helper failed (cancelled, denied, or invalid arguments)",
		))
	}
}

/// Compare certificates ignoring line-ending and trailing-whitespace noise.
#[cfg(any(target_os = "macos", test))]
fn normalize_pem(pem: &str) -> String {
	pem.lines().map(str::trim_end).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod trust_tests {
	use super::*;

	#[test]
	fn pem_normalization_ignores_line_endings() {
		assert_eq!(normalize_pem("a\r\nb\r\n"), normalize_pem("a\nb\n"));
	}

	#[cfg(target_os = "linux")]
	fn trust_install_fixture_script(anchor: &Path) -> String {
		let layout = TrustLayout {
			directory: anchor.parent().unwrap().to_str().unwrap(),
			anchor: anchor.to_str().unwrap(),
			reload: "printf '%s\\n' reloaded >> \"$TESTD_TRUST_LOG\"",
		};
		trust_install_script(&layout)
	}

	#[cfg(target_os = "linux")]
	fn trust_install_fixture(anchor: &Path, reload_log: &Path) -> std::process::Command {
		let mut command = std::process::Command::new("sh");
		command
			.args(["-c", &trust_install_fixture_script(anchor)])
			.env("TESTD_TRUST_LOG", reload_log);
		command
	}

	#[cfg(target_os = "linux")]
	fn trust_remove_fixture(anchor: &Path, reload_log: &Path) -> std::process::Command {
		let layout = TrustLayout {
			directory: anchor.parent().unwrap().to_str().unwrap(),
			anchor: anchor.to_str().unwrap(),
			reload: "printf '%s\\n' reloaded >> \"$TESTD_TRUST_LOG\"",
		};
		let mut command = std::process::Command::new("sh");
		command
			.args(["-c", &trust_remove_script(&layout)])
			.env("TESTD_TRUST_LOG", reload_log);
		command
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_removal_does_not_adopt_a_compatible_existing_anchor() {
		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		std::fs::write(&anchor, "testd certificate").unwrap();
		let reload_log = fixture.path().join("reload.log");
		let status =
			run_with_stdin(trust_remove_fixture(&anchor, &reload_log), b"installation-a\ntestd certificate").unwrap();
		assert!(!status.success(), "an unowned anchor must be reported");
		assert_eq!(std::fs::read_to_string(anchor).unwrap(), "testd certificate");
		assert!(!reload_log.exists());
	}

	#[cfg(target_os = "linux")]
	fn install_owned_anchor(anchor: &Path) {
		let log = anchor.parent().unwrap().join("install.log");
		let status = run_with_stdin(trust_install_fixture(anchor, &log), b"installation-a\ntestd certificate").unwrap();
		assert!(status.success());
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn owned_trust_can_be_removed_and_removal_is_repeatable() {
		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		let marker = fixture.path().join("testd-root.crt.owner");
		install_owned_anchor(&anchor);
		let log = fixture.path().join("remove.log");
		for _ in 0..2 {
			let status =
				run_with_stdin(trust_remove_fixture(&anchor, &log), b"installation-a\ntestd certificate").unwrap();
			assert!(status.success());
		}
		assert!(!anchor.exists());
		assert!(!marker.exists());
		assert_eq!(std::fs::read_to_string(log).unwrap(), "reloaded\n");
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn another_installation_cannot_remove_owned_trust() {
		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		let marker = fixture.path().join("testd-root.crt.owner");
		install_owned_anchor(&anchor);
		let record = std::fs::read(&marker).unwrap();
		let log = fixture.path().join("remove.log");
		let status = run_with_stdin(trust_remove_fixture(&anchor, &log), b"installation-b\ntestd certificate").unwrap();
		assert_eq!(status.code(), Some(TRUST_ANCHOR_CONFLICT));
		assert_eq!(std::fs::read_to_string(anchor).unwrap(), "testd certificate");
		assert_eq!(std::fs::read(marker).unwrap(), record);
		assert!(!log.exists());
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_removal_preserves_changed_anchors() {
		use std::os::unix::fs::{PermissionsExt, symlink};

		for change in ["content", "replacement", "permissions", "symlink"] {
			let fixture = tempfile::tempdir().unwrap();
			let anchor = fixture.path().join("testd-root.crt");
			let marker = fixture.path().join("testd-root.crt.owner");
			let original = fixture.path().join("original.crt");
			install_owned_anchor(&anchor);
			let record = std::fs::read(&marker).unwrap();
			match change {
				"content" => std::fs::write(&anchor, "changed certificate").unwrap(),
				"replacement" => {
					std::fs::rename(&anchor, &original).unwrap();
					std::fs::write(&anchor, "testd certificate").unwrap();
				},
				"permissions" => std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o600)).unwrap(),
				"symlink" => {
					std::fs::rename(&anchor, &original).unwrap();
					symlink(&original, &anchor).unwrap();
				},
				_ => unreachable!(),
			}
			let before = std::fs::read(&anchor).unwrap();
			let log = fixture.path().join("remove.log");
			let status =
				run_with_stdin(trust_remove_fixture(&anchor, &log), b"installation-a\ntestd certificate").unwrap();
			assert_eq!(status.code(), Some(TRUST_ANCHOR_CONFLICT), "{change}");
			assert_eq!(std::fs::read(&anchor).unwrap(), before, "{change}");
			assert_eq!(std::fs::read(&marker).unwrap(), record, "{change}");
			assert!(!log.exists(), "{change}");
		}
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_removal_preserves_changed_ownership_records() {
		use std::os::unix::fs::{PermissionsExt, symlink};

		for change in ["contents", "permissions", "symlink"] {
			let fixture = tempfile::tempdir().unwrap();
			let anchor = fixture.path().join("testd-root.crt");
			let marker = fixture.path().join("testd-root.crt.owner");
			install_owned_anchor(&anchor);
			match change {
				"contents" => std::fs::write(&marker, "another owner\nchanged\n").unwrap(),
				"permissions" => std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o644)).unwrap(),
				"symlink" => {
					let original = fixture.path().join("original.owner");
					std::fs::rename(&marker, &original).unwrap();
					symlink(original, &marker).unwrap();
				},
				_ => unreachable!(),
			}
			let before = std::fs::read(&marker).unwrap();
			let log = fixture.path().join("remove.log");
			let status =
				run_with_stdin(trust_remove_fixture(&anchor, &log), b"installation-a\ntestd certificate").unwrap();
			assert_eq!(status.code(), Some(TRUST_ANCHOR_CONFLICT), "{change}");
			assert_eq!(std::fs::read_to_string(&anchor).unwrap(), "testd certificate", "{change}");
			assert_eq!(std::fs::read(&marker).unwrap(), before, "{change}");
			assert!(!log.exists(), "{change}");
		}
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_removal_retries_a_failed_store_update() {
		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		let marker = fixture.path().join("testd-root.crt.owner");
		install_owned_anchor(&anchor);
		let layout = TrustLayout {
			directory: fixture.path().to_str().unwrap(),
			anchor: anchor.to_str().unwrap(),
			reload: "sh -c 'exit 1'",
		};
		let mut command = std::process::Command::new("sh");
		command.args(["-c", &trust_remove_script(&layout)]);
		let status = run_with_stdin(command, b"installation-a\ntestd certificate").unwrap();
		assert!(!status.success());
		assert!(!anchor.exists());
		assert!(marker.exists());
		let log = fixture.path().join("remove.log");
		let status = run_with_stdin(trust_remove_fixture(&anchor, &log), b"installation-a\ntestd certificate").unwrap();
		assert!(status.success());
		assert!(!marker.exists());
		assert_eq!(std::fs::read_to_string(log).unwrap(), "reloaded\n");
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_install_does_not_replace_an_unrelated_anchor() {
		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("anchors/testd-root.crt");
		std::fs::create_dir_all(anchor.parent().unwrap()).unwrap();
		std::fs::write(&anchor, "foreign certificate").unwrap();
		let reload_log = fixture.path().join("reload.log");
		let status =
			run_with_stdin(trust_install_fixture(&anchor, &reload_log), b"installation-a\ntestd certificate").unwrap();
		assert!(!status.success(), "a conflicting anchor must be reported");
		assert_eq!(std::fs::read_to_string(&anchor).unwrap(), "foreign certificate");
		assert!(!reload_log.exists(), "trust must not be reloaded after a conflict");
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_install_creates_an_anchor_without_overwriting() {
		use std::os::unix::fs::PermissionsExt;

		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("anchors ' local/testd-root.crt");
		let reload_log = fixture.path().join("reload.log");
		let status =
			run_with_stdin(trust_install_fixture(&anchor, &reload_log), b"installation-a\ntestd certificate").unwrap();
		assert!(status.success());
		assert_eq!(std::fs::read_to_string(&anchor).unwrap(), "testd certificate");
		assert_eq!(std::fs::metadata(&anchor).unwrap().permissions().mode() & 0o777, 0o644);
		let marker = anchor.with_file_name("testd-root.crt.owner");
		let record = std::fs::read_to_string(&marker).unwrap();
		assert_eq!(record.lines().next().unwrap().len(), 64);
		assert!(!record.contains("installation-a"));
		assert_eq!(std::fs::metadata(marker).unwrap().permissions().mode() & 0o777, 0o600);
		assert_eq!(std::fs::read_to_string(reload_log).unwrap(), "reloaded\n");
		assert_eq!(std::fs::read_dir(anchor.parent().unwrap()).unwrap().count(), 2);
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn compatible_existing_anchor_is_used_without_replacement() {
		const EXPECTED: &str = "-----BEGIN CERTIFICATE-----\nAAECAwQ=\n-----END CERTIFICATE-----\n";
		const WRAPPED: &str = "-----BEGIN CERTIFICATE-----\r\nAAEC\r\nAwQ=\r\n-----END CERTIFICATE-----\r\n";
		const FOREIGN: &str = "-----BEGIN CERTIFICATE-----\nAAECAwU=\n-----END CERTIFICATE-----\n";

		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		std::fs::write(&anchor, WRAPPED).unwrap();
		assert!(existing_linux_anchor(&anchor, EXPECTED).unwrap());
		assert_eq!(std::fs::read_to_string(&anchor).unwrap(), WRAPPED);
		assert_eq!(existing_linux_anchor(&anchor, FOREIGN).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
		std::fs::write(&anchor, format!("{WRAPPED}{WRAPPED}")).unwrap();
		assert_eq!(existing_linux_anchor(&anchor, EXPECTED).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_install_preserves_a_dangling_anchor_symlink() {
		use std::os::unix::fs::symlink;

		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		let target = fixture.path().join("missing.crt");
		symlink(&target, &anchor).unwrap();
		let reload_log = fixture.path().join("reload.log");
		let status =
			run_with_stdin(trust_install_fixture(&anchor, &reload_log), b"installation-a\ntestd certificate").unwrap();
		assert_eq!(status.code(), Some(TRUST_ANCHOR_CONFLICT));
		assert_eq!(std::fs::read_link(&anchor).unwrap(), target);
		assert!(!target.exists());
		assert!(!reload_log.exists());
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_install_preserves_a_directory_at_the_anchor_path() {
		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		std::fs::create_dir(&anchor).unwrap();
		let reload_log = fixture.path().join("reload.log");
		let status =
			run_with_stdin(trust_install_fixture(&anchor, &reload_log), b"installation-a\ntestd certificate").unwrap();
		assert_eq!(status.code(), Some(TRUST_ANCHOR_CONFLICT));
		assert_eq!(std::fs::read_dir(anchor).unwrap().count(), 0);
		assert!(!reload_log.exists());
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_install_preserves_an_anchor_created_during_authorization() {
		use std::os::unix::fs::PermissionsExt;

		for existing in ["foreign", "testd certificate"] {
			let fixture = tempfile::tempdir().unwrap();
			let anchor = fixture.path().join("testd-root.crt");
			let reload_log = fixture.path().join("reload.log");
			let bin = fixture.path().join("bin");
			std::fs::create_dir(&bin).unwrap();
			let link = bin.join("ln");
			std::fs::write(
				&link,
				"#!/bin/sh\n\
				for argument do target=$argument; done\n\
				printf '%s' \"$TESTD_RACE_CERTIFICATE\" > \"$target\"\n\
				exit 1\n",
			)
			.unwrap();
			std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o700)).unwrap();
			let script = trust_install_fixture_script(&anchor)
				.replace("ln -T --", &format!("{} -T --", shell_quote(&link.to_string_lossy())));
			let mut command = std::process::Command::new("sh");
			command
				.args(["-c", &script])
				.env("TESTD_TRUST_LOG", &reload_log)
				.env("TESTD_RACE_CERTIFICATE", existing);
			let status = run_with_stdin(command, b"installation-a\ntestd certificate").unwrap();
			assert_eq!(status.code(), Some(TRUST_ANCHOR_CONFLICT));
			assert_eq!(std::fs::read_to_string(anchor).unwrap(), existing);
			assert!(!reload_log.exists());
		}
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_install_preserves_a_preexisting_ownership_record() {
		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		let marker = fixture.path().join("testd-root.crt.owner");
		std::fs::write(&marker, "another installation").unwrap();
		let log = fixture.path().join("reload.log");
		let status =
			run_with_stdin(trust_install_fixture(&anchor, &log), b"installation-a\ntestd certificate").unwrap();
		assert_eq!(status.code(), Some(TRUST_ANCHOR_CONFLICT));
		assert!(!anchor.exists());
		assert_eq!(std::fs::read_to_string(marker).unwrap(), "another installation");
		assert!(!log.exists());
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_install_preserves_an_ownership_record_created_during_authorization() {
		use std::os::unix::fs::PermissionsExt;

		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		let marker = fixture.path().join("testd-root.crt.owner");
		let log = fixture.path().join("reload.log");
		let link = fixture.path().join("fake-ln");
		std::fs::write(
			&link,
			"#!/bin/sh\n\
			for argument do target=$argument; done\n\
			case \"$target\" in\n\
			  *.owner) printf '%s' foreign > \"$target\"; exit 1 ;;\n\
			  *) exec /usr/bin/ln \"$@\" ;;\n\
			esac\n",
		)
		.unwrap();
		std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o700)).unwrap();
		let script = trust_install_fixture_script(&anchor)
			.replace("ln -T --", &format!("{} -T --", shell_quote(&link.to_string_lossy())));
		let mut command = std::process::Command::new("sh");
		command.args(["-c", &script]).env("TESTD_TRUST_LOG", &log);
		let status = run_with_stdin(command, b"installation-a\ntestd certificate").unwrap();
		assert_eq!(status.code(), Some(TRUST_OWNERSHIP_UNRECORDED));
		assert_eq!(std::fs::read_to_string(&anchor).unwrap(), "testd certificate");
		assert_eq!(std::fs::read_to_string(&marker).unwrap(), "foreign");
		assert!(!log.exists());
		let removal =
			run_with_stdin(trust_remove_fixture(&anchor, &log), b"installation-a\ntestd certificate").unwrap();
		assert_eq!(removal.code(), Some(TRUST_ANCHOR_CONFLICT));
		assert_eq!(std::fs::read_to_string(anchor).unwrap(), "testd certificate");
		assert_eq!(std::fs::read_to_string(marker).unwrap(), "foreign");
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_install_reports_a_failed_trust_store_update() {
		let fixture = tempfile::tempdir().unwrap();
		let anchor = fixture.path().join("testd-root.crt");
		let layout = TrustLayout {
			directory: fixture.path().to_str().unwrap(),
			anchor: anchor.to_str().unwrap(),
			reload: "sh -c 'exit 17'",
		};
		let mut command = std::process::Command::new("sh");
		command.args(["-c", &trust_install_script(&layout)]);
		let status = run_with_stdin(command, b"installation-a\ntestd certificate").unwrap();
		assert_eq!(status.code(), Some(1), "an update failure is not an anchor conflict");
		assert_eq!(std::fs::read_to_string(&anchor).unwrap(), "testd certificate");
		assert!(anchor.with_file_name("testd-root.crt.owner").exists());
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn trust_layout_follows_the_distro_tool() {
		let debian = trust_layout_for(true, false);
		assert_eq!(debian.anchor, "/usr/local/share/ca-certificates/testd-root.crt");
		assert_eq!(debian.reload, "update-ca-certificates");
		let fedora = trust_layout_for(false, true);
		assert_eq!(fedora.anchor, "/etc/pki/ca-trust/source/anchors/testd-root.crt");
		assert_eq!(fedora.reload, "update-ca-trust extract");
		assert_eq!(trust_layout_for(false, false).anchor, debian.anchor, "unrecognised distros keep the old layout");
		assert_eq!(trust_layout_for(true, true).anchor, debian.anchor);
	}

	#[test]
	fn powershell_single_quotes_escape_embedded_quotes() {
		assert_eq!(powershell_single_quote("plain"), "'plain'");
		assert_eq!(powershell_single_quote("a'b"), "'a''b'");
	}

	#[test]
	fn compact_hex_keeps_the_thumbprint_across_separators() {
		assert!(compact_hex("Cert Hash: 01 23:ab CD").to_ascii_lowercase().ends_with("0123abcd"));
	}

	#[test]
	fn pem_to_der_decodes_a_certificate_block() {
		assert_eq!(
			pem_to_der("-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n").unwrap(),
			vec![0, 1, 2]
		);
		assert!(pem_to_der("not a certificate").is_err());
	}
}
