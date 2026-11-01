//! One-time setup operations for testd:
//! - OS resolver configuration (routing `.<tld>` queries to the testd DNS server)
//! - Caddyfile import line management

use std::io;
use std::net::SocketAddr;
use std::path::Path;

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
fn is_os_resolver_configured_linux(tld: &str, addr: SocketAddr) -> bool {
	let Ok(output) = silent_command("resolvectl").args(["status"]).output() else {
		return false;
	};
	if !output.status.success() {
		return false;
	}
	let stdout = String::from_utf8_lossy(&output.stdout);
	// `resolvectl status` prints the global section first, then one block per
	// link; the route lives in the global section because it comes from a
	// `[Resolve]` drop-in rather than from per-link configuration.
	let global = stdout.split("\nLink ").next().unwrap_or_default();
	global.contains(&dns_server_value(addr)) && global.contains(&format!("~{tld}"))
}

#[cfg(any(target_os = "linux", test))]
fn dns_server_value(addr: SocketAddr) -> String {
	format!("{}:{}", addr.ip(), addr.port())
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

/// `DNS=` and `Domains=` as systemd-resolved merges them: the last assignment
/// wins, an empty assignment clears the list, and only `[Resolve]` counts.
/// Returns `None` for a key that is unset or cleared.
#[cfg(any(target_os = "linux", test))]
fn resolved_global_values(files: &[String]) -> (Option<String>, Option<String>) {
	let mut dns = None;
	let mut domains = None;
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
			let value = value.trim();
			let value = (!value.is_empty()).then(|| value.to_owned());
			match key.trim() {
				"DNS" => dns = value,
				"Domains" => domains = value,
				_ => {},
			}
		}
	}
	(dns, domains)
}

/// resolved.conf plus its drop-ins, except testd's own file.
#[cfg(target_os = "linux")]
fn resolved_conf_files() -> Vec<std::path::PathBuf> {
	let mut files = vec![std::path::PathBuf::from("/etc/systemd/resolved.conf")];
	let Ok(entries) = std::fs::read_dir(RESOLVED_DROPIN_DIR) else { return files };
	let mut dropins: Vec<std::path::PathBuf> = entries
		.flatten()
		.map(|entry| entry.path())
		.filter(|path| path.extension().is_some_and(|extension| extension == "conf"))
		.filter(|path| path != Path::new(RESOLVED_DROPIN))
		.collect();
	dropins.sort();
	files.extend(dropins);
	files
}

#[cfg(target_os = "linux")]
fn resolved_active() -> bool {
	silent_command("systemctl")
		.args(["is-active", "--quiet", "systemd-resolved"])
		.status()
		.is_ok_and(|status| status.success())
}

/// Refuse before elevating when the route cannot take effect, or when writing it
/// would replace global resolver settings that testd cannot merge with.
#[cfg(target_os = "linux")]
fn linux_resolver_preflight() -> io::Result<()> {
	if !resolved_active() {
		return Err(io::Error::new(
			io::ErrorKind::Unsupported,
			"systemd-resolved is not active; run `systemctl enable --now systemd-resolved` first",
		));
	}
	let files: Vec<String> = resolved_conf_files()
		.iter()
		.filter_map(|path| std::fs::read_to_string(path).ok())
		.collect();
	let (dns, domains) = resolved_global_values(&files);
	let existing: Vec<String> = [("DNS", dns), ("Domains", domains)]
		.into_iter()
		.filter_map(|(key, value)| value.map(|value| format!("{key}={value}")))
		.collect();
	if !existing.is_empty() {
		return Err(io::Error::new(
			io::ErrorKind::AlreadyExists,
			format!(
				"systemd-resolved already has global {} configured, which the testd drop-in would replace; \
				remove it from /etc/systemd/resolved.conf or its drop-ins, or use `resolver = \"hosts\"`",
				existing.join(" ")
			),
		));
	}
	Ok(())
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
	vec!["mkdir -p /etc/resolver".to_owned(), format!("printf '{content}' > {path}")]
}

#[cfg(target_os = "linux")]
fn resolver_commands(tld: &str, addr: SocketAddr) -> Vec<String> {
	let content = shell_quote(&resolved_dropin(tld, addr));
	vec![format!(
		"mkdir -p {RESOLVED_DROPIN_DIR} && printf '%s' {content} > {RESOLVED_DROPIN} \
		 && systemctl reload systemd-resolved"
	)]
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
	{
		linux_resolver_preflight()?;
		setup_sudo_unix(tld, addr)
	}

	#[cfg(target_os = "windows")]
	return setup_gui_windows(tld, addr);

	#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for DNS resolver setup"))
}

/// Run each resolver command individually with `sudo`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
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
	return setup_gui_linux(tld, addr);

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

/// Linux: use `pkexec` (polkit) for a native auth dialog.
#[cfg(target_os = "linux")]
fn setup_gui_linux(tld: &str, addr: SocketAddr) -> io::Result<()> {
	linux_resolver_preflight()?;
	let script = resolver_commands(tld, addr).join(" && ");

	let status = silent_command("pkexec").args(["sh", "-c", &script]).status()?;
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
	return teardown_linux(tld);

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
	Ok(())
}

#[cfg(target_os = "linux")]
fn teardown_linux(_tld: &str) -> io::Result<()> {
	let script = format!("rm -f {RESOLVED_DROPIN} && systemctl reload systemd-resolved");
	let _ = silent_command("sudo").args(["sh", "-c", &script]).status();
	// Configurations written by older versions live on the link, not in a drop-in.
	let _ = silent_command("sudo").args(["resolvectl", "revert", "lo"]).status();
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
	/* osascript can't pipe stdin, so pass content via a temp file. */
	let tmp = std::env::temp_dir().join("testd-caddyfile-import.tmp");
	std::fs::write(&tmp, content)?;

	let script =
		format!("do shell script \"cat '{}' > '{}'\" with administrator privileges", tmp.display(), path.display(),);
	let status = silent_command("osascript").args(["-e", &script]).status()?;
	let _ = std::fs::remove_file(&tmp);
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
	let tmp = std::env::temp_dir().join("testd-caddyfile-import.tmp");
	std::fs::write(&tmp, content)?;

	let cmd = format!("Copy-Item '{}' '{}'", tmp.display(), path.display());
	let status = silent_command("powershell")
		.args(["-Command", &format!("Start-Process powershell -Verb RunAs -Wait -ArgumentList '-Command','{cmd}'")])
		.status()?;
	let _ = std::fs::remove_file(&tmp);
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

	#[cfg(target_os = "linux")]
	#[test]
	fn linux_resolver_writes_a_dropin_instead_of_per_link_config() {
		let addr: SocketAddr = "127.0.0.1:7753".parse().unwrap();
		let commands = resolver_commands("test", addr);
		assert_eq!(commands.len(), 1);
		assert!(commands[0].contains("90-testd.conf"));
		assert!(commands[0].contains("systemctl reload systemd-resolved"));
		assert!(!commands[0].contains("resolvectl"));
	}

	#[test]
	fn resolved_dropin_routes_only_the_testd_domain() {
		let addr: SocketAddr = "127.0.0.1:7753".parse().unwrap();
		let dropin = resolved_dropin("test", addr);
		assert!(dropin.contains("[Resolve]\nDNS=127.0.0.1:7753\nDomains=~test\n"), "{dropin}");
		assert!(!dropin.contains("Domains=~."), "{dropin}");
	}

	#[test]
	fn resolved_global_values_follow_the_last_assignment() {
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
		assert!(content.ends_with(&format!("import {}\n", managed.display())));

		std::fs::write(&caddyfile, &content).unwrap();
		assert!(build_caddyfile_with_import(&caddyfile, &managed).is_none());

		std::fs::remove_dir_all(&dir).ok();
	}
}

// --- root CA trust ---

/// Common name of the testd root certificate.
#[cfg(target_os = "macos")]
const ROOT_CN: &str = "testd root";

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
	std::path::PathBuf::from("/usr/local/share/ca-certificates/testd-root.crt")
}

#[cfg(target_os = "linux")]
fn is_root_trusted_linux(cert_pem: &str) -> bool {
	let Ok(installed) = std::fs::read_to_string(system_root_path()) else { return false };
	normalize_pem(&installed) == normalize_pem(cert_pem)
}

#[cfg(target_os = "macos")]
fn is_root_trusted_macos(cert_pem: &str) -> bool {
	let Ok(output) = silent_command("security")
		.args(["find-certificate", "-a", "-p", "-c", ROOT_CN, "/Library/Keychains/System.keychain"])
		.output()
	else {
		return false;
	};
	if !output.status.success() {
		return false;
	}
	let installed = normalize_pem(&String::from_utf8_lossy(&output.stdout));
	installed.contains(&normalize_pem(cert_pem))
}

#[cfg(target_os = "windows")]
fn is_root_trusted_windows(cert_pem: &str) -> bool {
	let Ok(der) = pem_to_der(cert_pem) else { return false };
	let tmp = std::env::temp_dir().join(format!("testd-check-{}.cer", std::process::id()));
	if std::fs::write(&tmp, der).is_err() {
		return false;
	}
	let thumbprint = windows_cert_thumbprint(&tmp);
	let _ = std::fs::remove_file(&tmp);
	let Ok(thumbprint) = thumbprint else { return false };
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
	return trust_root_linux(cert_pem);

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
		let tmp = std::env::temp_dir().join("testd-root.crt");
		std::fs::write(&tmp, cert_pem)?;
		let destination = system_root_path();
		let script = format!(
			"mkdir -p /usr/local/share/ca-certificates && cp '{}' '{}' && update-ca-certificates",
			tmp.display(),
			destination.display()
		);
		let status = silent_command("pkexec").args(["sh", "-c", &script]).status()?;
		let _ = std::fs::remove_file(&tmp);
		if !status.success() {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"root CA install failed (cancelled or auth error)",
			));
		}
		Ok(())
	}
	#[cfg(target_os = "macos")]
	{
		let tmp = std::env::temp_dir().join("testd-root.crt");
		std::fs::write(&tmp, cert_pem)?;
		let script = format!(
			"security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{}'",
			tmp.display()
		);
		let status = silent_command("osascript")
			.args(["-e", &format!("do shell script \"{script}\" with administrator privileges")])
			.status()?;
		let _ = std::fs::remove_file(&tmp);
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
fn trust_root_linux(cert_pem: &str) -> io::Result<()> {
	let tmp = std::env::temp_dir().join(format!("testd-root-{}.crt", std::process::id()));
	std::fs::write(&tmp, cert_pem)?;
	let destination = system_root_path();
	let script = format!(
		"mkdir -p /usr/local/share/ca-certificates && cp '{}' '{}' && update-ca-certificates",
		tmp.display(),
		destination.display()
	);
	let status = silent_command("sudo").args(["sh", "-c", &script]).status();
	let _ = std::fs::remove_file(&tmp);
	let status = status?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root CA install failed"));
	}
	Ok(())
}

#[cfg(target_os = "macos")]
fn trust_root_macos(cert_pem: &str) -> io::Result<()> {
	let tmp = std::env::temp_dir().join(format!("testd-root-{}.crt", std::process::id()));
	std::fs::write(&tmp, cert_pem)?;
	let status = silent_command("sudo")
		.args(["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain"])
		.arg(&tmp)
		.status();
	let _ = std::fs::remove_file(&tmp);
	let status = status?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root CA install failed"));
	}
	Ok(())
}

#[cfg(target_os = "windows")]
fn trust_root_windows(cert_pem: &str) -> io::Result<()> {
	// Windows certificate APIs load DER reliably; PEM support depends on the
	// .NET version, so convert once before handing the file to the helper.
	let tmp = std::env::temp_dir().join(format!("testd-root-{}.cer", std::process::id()));
	std::fs::write(&tmp, pem_to_der(cert_pem)?)?;
	let result = windows_cert_thumbprint(&tmp).and_then(|thumbprint| {
		let cert_path = tmp.display().to_string();
		run_windows_helper("InstallRoot", &[("CertPath", cert_path.as_str()), ("Thumbprint", thumbprint.as_str())])
	});
	let _ = std::fs::remove_file(&tmp);
	result
}

/// Remove the testd root from the system trust store via `sudo`.
///
/// Removal is safe to repeat: a certificate that is already gone is not an
/// error, so an uninstall can run after a partial failure.
pub fn untrust_root(_cert_pem: &str) -> io::Result<()> {
	#[cfg(target_os = "linux")]
	return untrust_root_linux();

	#[cfg(target_os = "macos")]
	return untrust_root_macos();

	#[cfg(target_os = "windows")]
	return untrust_root_windows(_cert_pem);

	#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for trust removal"))
}

/// Remove the testd root via a native GUI authorization dialog.
pub fn untrust_root_gui(_cert_pem: &str) -> io::Result<()> {
	#[cfg(target_os = "linux")]
	{
		let destination = system_root_path();
		let script = format!("rm -f '{}' && update-ca-certificates", destination.display());
		let status = silent_command("pkexec").args(["sh", "-c", &script]).status()?;
		if !status.success() {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"root CA removal failed (cancelled or auth error)",
			));
		}
		Ok(())
	}
	#[cfg(target_os = "macos")]
	{
		let script =
			format!("security delete-certificate -c {} /Library/Keychains/System.keychain", shell_quote(ROOT_CN));
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
		untrust_root_windows(_cert_pem)
	}
	#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
	Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform for trust removal"))
}

#[cfg(target_os = "linux")]
fn untrust_root_linux() -> io::Result<()> {
	let destination = system_root_path();
	let script = format!("rm -f '{}' && update-ca-certificates", destination.display());
	let status = silent_command("sudo").args(["sh", "-c", &script]).status()?;
	if !status.success() {
		return Err(io::Error::new(io::ErrorKind::PermissionDenied, "root CA removal failed"));
	}
	Ok(())
}

#[cfg(target_os = "macos")]
fn untrust_root_macos() -> io::Result<()> {
	let status = silent_command("sudo")
		.args(["security", "delete-certificate", "-c", ROOT_CN, "/Library/Keychains/System.keychain"])
		.status()?;
	if status.success() {
		return Ok(());
	}
	// No matching certificate is the desired end state; report only a real
	// failure, such as a denied authorization.
	let present = silent_command("security")
		.args(["find-certificate", "-c", ROOT_CN, "/Library/Keychains/System.keychain"])
		.status()?;
	if !present.success() {
		return Ok(());
	}
	Err(io::Error::new(io::ErrorKind::PermissionDenied, "root CA removal failed"))
}

#[cfg(target_os = "windows")]
fn untrust_root_windows(cert_pem: &str) -> io::Result<()> {
	if !is_root_trusted_windows(cert_pem) {
		return Ok(());
	}
	let tmp = std::env::temp_dir().join(format!("testd-root-{}.cer", std::process::id()));
	std::fs::write(&tmp, pem_to_der(cert_pem)?)?;
	let result = windows_cert_thumbprint(&tmp)
		.and_then(|thumbprint| run_windows_helper("RemoveRoot", &[("Thumbprint", thumbprint.as_str())]));
	let _ = std::fs::remove_file(&tmp);
	result
}

/// Decode the first CERTIFICATE block in a PEM document to DER.
#[cfg(any(target_os = "windows", test))]
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
fn windows_helper_script() -> io::Result<std::path::PathBuf> {
	let dir = std::env::temp_dir().join(format!("testd-elevated-{}", std::process::id()));
	std::fs::create_dir_all(&dir)?;
	let path = dir.join("testd-elevated.ps1");
	std::fs::write(&path, WINDOWS_ELEVATED_SCRIPT)?;
	Ok(path)
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
	let script = windows_helper_script()?;
	let result = if is_windows_elevated() {
		let mut command = silent_command("powershell");
		command
			.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
			.arg(&script)
			.args(["-Action", action]);
		for (name, value) in args {
			command.arg(format!("-{name}")).arg(*value);
		}
		command.status().and_then(require_helper_success)
	} else {
		let mut argument_line =
			format!("-NoProfile -ExecutionPolicy Bypass -File \"{}\" -Action {}", script.display(), action);
		for (name, value) in args {
			argument_line.push_str(&format!(" -{name} \"{}\"", value.replace('"', "`\"")));
		}
		let command = format!(
			"$ErrorActionPreference = 'Stop'; $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ErrorAction Stop -ArgumentList {}; exit $p.ExitCode",
			powershell_single_quote(&argument_line)
		);
		silent_command("powershell")
			.args(["-NoProfile", "-Command", &command])
			.status()
			.and_then(require_helper_success)
	};
	let _ = std::fs::remove_dir_all(script.parent().unwrap_or(std::path::Path::new(".")));
	result
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

#[cfg(target_os = "windows")]
fn windows_cert_thumbprint(path: &std::path::Path) -> io::Result<String> {
	let command = format!(
		"([System.Security.Cryptography.X509Certificates.X509Certificate2]::new({})).Thumbprint",
		powershell_single_quote(&path.display().to_string())
	);
	let output = silent_command("powershell")
		.args(["-NoProfile", "-Command", &command])
		.output()?;
	if !output.status.success() {
		return Err(io::Error::new(io::ErrorKind::InvalidData, "cannot read certificate thumbprint"));
	}
	let thumbprint = String::from_utf8_lossy(&output.stdout).trim().to_owned();
	if thumbprint.is_empty() || !thumbprint.chars().all(|c| c.is_ascii_hexdigit()) {
		return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid certificate thumbprint"));
	}
	Ok(thumbprint)
}

/// Compare certificates ignoring line-ending and trailing-whitespace noise.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
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
