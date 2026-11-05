//! CLI-level tests: idempotent init, the fixed TLD, doctor exit codes.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn testd_command(home: &Path, args: &[&str]) -> Command {
	let mut command = Command::new(env!("CARGO_BIN_EXE_testd"));
	command
		.args(args)
		.env("HOME", home)
		.env("APPDATA", home.join("AppData/Roaming"))
		.env("USERPROFILE", home)
		.current_dir(home)
		.env_remove("TESTD_HOSTS")
		.env_remove("TESTD_HOST")
		.env_remove("TESTD_TLD")
		.env_remove("TESTD_HOST_TLD")
		.env_remove("TESTD_CADDYFILE")
		.env_remove("TESTD_YES")
		.env_remove("TESTD_TOKEN")
		.env_remove("TESTD_TOKEN_PROFILE")
		.env_remove("TESTD_PROFILE");
	command
}

fn testd(home: &Path, args: &[&str]) -> Output {
	testd_command(home, args).output().expect("run testd")
}

#[cfg(target_os = "linux")]
fn fake_sudo(home: &Path) -> (std::ffi::OsString, std::path::PathBuf) {
	use std::os::unix::fs::PermissionsExt;

	let bin = home.join("bin");
	std::fs::create_dir(&bin).unwrap();
	let sudo = bin.join("sudo");
	std::fs::write(&sudo, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TESTD_SUDO_LOG\"\nexit 0\n").unwrap();
	std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o700)).unwrap();
	let path = std::env::join_paths(
		std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())),
	)
	.unwrap();
	(path, home.join("sudo.log"))
}

fn init(home: &Path) -> Output {
	testd(home, &["init", "--caddyfile", ""])
}

fn config_dir(home: &Path) -> std::path::PathBuf {
	if cfg!(windows) { home.join("AppData/Roaming/testd") } else { home.join(".config/testd") }
}

fn config(home: &Path) -> String {
	std::fs::read_to_string(config_dir(home).join("config.toml")).expect("config exists")
}

fn operator_secret(home: &Path) -> String {
	let table: toml::Table = toml::from_str(&config(home)).expect("config parses");
	table["host"]["secret"].as_str().expect("init writes [host] secret").to_owned()
}

#[test]
fn cli_does_not_offer_a_hosts_helper_command() {
	let home = TempDir::new().unwrap();
	let help = testd(home.path(), &["--help"]);
	assert!(help.status.success());
	assert!(!String::from_utf8_lossy(&help.stdout).contains("setup-hosts-helper"));
	let removed = testd(home.path(), &["setup-hosts-helper", "--help"]);
	assert!(!removed.status.success(), "the removed command must not be accepted");
}

#[test]
fn init_is_idempotent() {
	let home = TempDir::new().unwrap();

	let first = init(home.path());
	assert!(first.status.success(), "first init failed: {}", String::from_utf8_lossy(&first.stderr));
	let config_before = config(home.path());

	let second = init(home.path());
	assert!(second.status.success(), "second init failed: {}", String::from_utf8_lossy(&second.stderr));
	assert_eq!(config_before, config(home.path()), "re-init must keep the host config");
}

#[test]
fn readme_host_configuration_uses_supported_keys() {
	let config: testd_core::config::HostConfig = toml::from_str("").unwrap();
	let value = toml::Value::try_from(config).unwrap();
	let host = value.as_table().unwrap();
	let section = include_str!("../README.md")
		.split_once("Useful `[host]` keys:")
		.expect("host configuration table exists")
		.1
		.split_once("\n\nClient state")
		.expect("host configuration table ends before client state")
		.0;
	let mut keys = 0;
	for line in section.lines().filter(|line| line.starts_with("| `")) {
		let key = line.split('`').nth(1).unwrap();
		assert!(host.contains_key(key), "README documents unsupported host setting {key}");
		keys += 1;
	}
	assert!(keys > 0, "host configuration table is empty");
}

#[test]
fn init_defaults_to_loopback_listeners() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());

	let table: toml::Value = toml::from_str(&config(home.path())).unwrap();
	let host: testd_core::config::HostConfig = table["host"].clone().try_into().unwrap();
	assert_eq!(host.listen_addr.to_string(), "127.0.0.1:7737");
	assert_eq!(host.edge_addr.to_string(), "127.0.0.1:443");
	assert_eq!(host.http_addr.to_string(), "127.0.0.1:7740");
	assert_eq!(host.local_dashboard_url(), "http://127.0.0.1:7737");
}

#[test]
fn init_writes_and_keeps_an_operator_secret() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());
	let first = operator_secret(home.path());
	assert!(first.len() >= 16, "secret too short: {first:?}");

	assert!(init(home.path()).status.success());
	assert_eq!(operator_secret(home.path()), first, "re-init must keep the operator secret");
}

#[test]
fn init_uses_the_fixed_test_tld() {
	let home = TempDir::new().unwrap();
	let out = init(home.path());
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

	let config = config(home.path());
	assert!(!config.contains("tld"), "the TLD is not configurable: {config}");
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(stderr.contains(".test"), "{stderr}");
}

#[test]
fn init_has_no_tld_option() {
	let home = TempDir::new().unwrap();
	let out = testd(home.path(), &["init", "--caddyfile", "", "--tld", "test"]);
	assert!(!out.status.success(), "--tld must no longer be accepted");
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(stderr.contains("unexpected argument"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn init_reports_an_already_configured_resolver() {
	use std::os::unix::fs::PermissionsExt;
	use testd_core::config::DEFAULT_DNS_PORT;

	let home = TempDir::new().unwrap();
	let bin = home.path().join("bin");
	std::fs::create_dir(&bin).unwrap();
	let resolvectl = bin.join("resolvectl");
	std::fs::write(
		&resolvectl,
		format!(
			"#!/bin/sh\ncase \"$1\" in\n  dns) printf 'Global: 127.0.0.1:{DEFAULT_DNS_PORT}\\n' ;;\n\
			  domain) printf 'Global: ~test\\n' ;;\n  *) exit 1 ;;\nesac\n"
		),
	)
	.unwrap();
	std::fs::set_permissions(&resolvectl, std::fs::Permissions::from_mode(0o755)).unwrap();

	let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
	let out = Command::new(env!("CARGO_BIN_EXE_testd"))
		.args(["init", "--caddyfile", ""])
		.env("HOME", home.path())
		.env("PATH", path)
		.env_remove("TESTD_HOST")
		.env_remove("TESTD_TLD")
		.env_remove("TESTD_HOST_TLD")
		.env_remove("TESTD_CADDYFILE")
		.env_remove("TESTD_YES")
		.env_remove("TESTD_TOKEN")
		.env_remove("TESTD_TOKEN_PROFILE")
		.env_remove("TESTD_PROFILE")
		.output()
		.expect("run testd");

	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(stderr.contains("already configured"), "{stderr}");
	assert!(!stderr.contains("deferred"), "{stderr}");
}

#[cfg(target_os = "linux")]
#[test]
fn uninstall_does_not_revert_unowned_loopback_resolver_settings() {
	let home = TempDir::new().unwrap();
	let (path, log) = fake_sudo(home.path());
	let _out = testd_command(home.path(), &["uninstall", "--keep-certificate"])
		.env("PATH", path)
		.env("TESTD_SUDO_LOG", &log)
		.output()
		.unwrap();
	let calls = std::fs::read_to_string(log).unwrap_or_default();
	assert!(!calls.contains("resolvectl revert lo"), "unowned link settings must remain: {calls}");
}

#[cfg(target_os = "linux")]
#[test]
fn uninstall_does_not_remove_a_configured_hosts_helper_path() {
	let home = TempDir::new().unwrap();
	let unrelated = home.path().join("unrelated-file");
	std::fs::write(&unrelated, "keep this file").unwrap();
	let config = config_dir(home.path()).join("config.toml");
	std::fs::create_dir_all(config.parent().unwrap()).unwrap();
	std::fs::write(&config, format!("[host]\nhosts_helper_path = {:?}\n", unrelated.to_str().unwrap())).unwrap();
	let (path, log) = fake_sudo(home.path());
	let out = testd_command(home.path(), &["uninstall", "--keep-resolver", "--keep-certificate"])
		.env("PATH", path)
		.env("TESTD_SUDO_LOG", &log)
		.output()
		.unwrap();
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "keep this file");
	let calls = std::fs::read_to_string(log).unwrap_or_default();
	assert!(calls.is_empty(), "uninstall must not remove helper files or sudoers rules: {calls}");
}

#[cfg(target_os = "linux")]
#[test]
fn uninstall_keeps_data_when_root_certificate_is_missing() {
	let home = TempDir::new().unwrap();
	let data = config_dir(home.path()).join("keep-me");
	std::fs::create_dir_all(data.parent().unwrap()).unwrap();
	std::fs::write(&data, "local data").unwrap();
	let (path, log) = fake_sudo(home.path());
	let out = testd_command(home.path(), &["uninstall", "--purge", "--keep-resolver"])
		.env("PATH", path)
		.env("TESTD_SUDO_LOG", &log)
		.output()
		.unwrap();
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(!out.status.success(), "missing certificate must be reported: {stderr}");
	assert!(stderr.contains("missing") && stderr.contains("trust was not removed"), "{stderr}");
	assert_eq!(std::fs::read_to_string(data).unwrap(), "local data");
	let calls = std::fs::read_to_string(log).unwrap_or_default();
	assert!(!calls.contains("testd-root.crt"), "unidentified trust must remain: {calls}");
}

#[test]
fn uninstall_purge_removes_local_data_without_system_changes() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());
	assert!(config_dir(home.path()).join("config.toml").exists());

	let out = testd(home.path(), &["uninstall", "--purge", "--keep-resolver", "--keep-certificate"]);
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	assert!(!config_dir(home.path()).exists());
}

#[test]
fn share_without_a_daemon_says_the_tunnel_lives_in_one() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());

	for args in [vec!["share", "app.example"], vec!["share", "--list"], vec!["share", "--stop", "app.example"]] {
		let out = testd(home.path(), &args);
		assert!(!out.status.success(), "{args:?} must fail without a daemon");
		let stderr = String::from_utf8_lossy(&out.stderr);
		assert!(stderr.contains("no daemon is running"), "{args:?}: {stderr}");
	}
}

#[test]
fn share_rejects_an_unknown_provider_before_asking_the_daemon() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());

	let out = testd(home.path(), &["share", "app.example", "--provider", "mystery"]);
	assert!(!out.status.success());
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(stderr.contains("unknown provider"), "{stderr}");
	assert!(stderr.contains("cloudflared"), "the message lists the providers: {stderr}");
}

#[test]
fn version_matches_the_package() {
	let output = std::process::Command::new(env!("CARGO_BIN_EXE_testd"))
		.arg("--version")
		.output()
		.unwrap();
	assert!(output.status.success());
	assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), concat!("testd ", env!("CARGO_PKG_VERSION")));
}

#[test]
fn access_ids_may_start_with_a_hyphen() {
	let home = TempDir::new().unwrap();
	for id in ["-abc1234", "-hbc1234", "--help12", "-Vbc1234", "--revoke"] {
		for args in [["approve", id].as_slice(), ["deny", id].as_slice(), ["tokens", "--revoke", id].as_slice()] {
			let output = testd(home.path(), args);
			/* Reach the missing-daemon error, not clap's parser/help/version handling. */
			assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
		}
	}
}

#[test]
fn doctor_missing_config_exits_1_with_json() {
	let home = TempDir::new().unwrap();
	let out = testd(home.path(), &["doctor", "--json"]);
	assert_eq!(out.status.code(), Some(1));
	let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");
	assert_eq!(value["exit_code"], 1);
	assert_eq!(value["ok"], false);
	assert_eq!(value["checks"][0]["name"], "config");
}

#[test]
fn run_warns_about_single_label_names_before_connecting() {
	let home = TempDir::new().unwrap();
	#[cfg(unix)]
	let command = ["true"];
	#[cfg(windows)]
	let command = ["cmd", "/C", "exit"];
	let args: Vec<&str> = ["run", "app:3000", "--host", "127.0.0.1:1", "--"]
		.into_iter()
		.chain(command)
		.collect();
	let out = testd(home.path(), &args);
	// The host is unreachable, but the warning comes before the connection phase.
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(stderr.contains("single-label") || stderr.contains("<service>.<project>.<tld>"), "{stderr}");
}

#[test]
fn a_leaf_without_a_credential_requests_one_and_saves_it() {
	use std::io::{BufRead, BufReader, Write};
	use std::net::TcpListener;

	let home = TempDir::new().unwrap();
	let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
	let addr = listener.local_addr().unwrap();
	let host = std::thread::spawn(move || {
		let (mut stream, _) = listener.accept().unwrap();
		let mut reader = BufReader::new(stream.try_clone().unwrap());

		let mut line = String::new();
		reader.read_line(&mut line).unwrap();
		let auth: serde_json::Value = serde_json::from_str(&line).unwrap();
		assert_eq!(auth["token"].as_str().unwrap_or_default(), "");
		assert!(auth["request_token"]["label"].as_str().is_some_and(|label| !label.is_empty()));
		assert_eq!(auth["request_token"]["names"], serde_json::json!([]));

		stream.write_all(b"{\"type\":\"Pending\",\"id\":\"req-1\"}\n").unwrap();
		stream.write_all(b"{\"type\":\"Token\",\"token\":\"issued-token\"}\n").unwrap();

		line.clear();
		reader.read_line(&mut line).unwrap();
		let request: serde_json::Value = serde_json::from_str(&line).unwrap();
		assert_eq!(request["type"], "Deregister");
		assert_eq!(request["domain"], "app");
		stream.write_all(b"{\"type\":\"Ok\"}\n").unwrap();
	});

	let out = testd(home.path(), &["deregister", "app", "--host", &addr.to_string()]);
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	host.join().expect("fake host completed");

	let credential = config_dir(home.path()).join("credentials/default");
	assert_eq!(std::fs::read_to_string(&credential).unwrap().trim(), "issued-token");
}

#[tokio::test]
async fn run_exits_with_the_host_rejection_instead_of_retrying() {
	use testd_core::protocol::{Auth, Request, Response, recv, send};
	use tokio::io::BufReader;
	use tokio::net::TcpListener;

	let home = TempDir::new().unwrap();
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let host = tokio::spawn(async move {
		let (stream, _) = listener.accept().await.unwrap();
		let (reader, mut writer) = stream.into_split();
		let mut reader = BufReader::new(reader);
		let auth: Auth = recv(&mut reader).await.unwrap().unwrap();
		assert_eq!(auth.token, "test-token");
		send(&mut writer, &Response::Ok).await.unwrap();
		let request: Request = recv(&mut reader).await.unwrap().unwrap();
		assert!(matches!(request, Request::Register { .. }));
		send(&mut writer, &Response::terminal_error("name is already registered"))
			.await
			.unwrap();
	});

	let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_testd"));
	command
		.args(["run", "app:3000", "--host", &addr.to_string()])
		.env("HOME", home.path())
		.env("APPDATA", home.path().join("AppData/Roaming"))
		.env("USERPROFILE", home.path())
		.env("TESTD_TOKEN", "test-token")
		.env_remove("TESTD_HOSTS")
		.env_remove("TESTD_HOST")
		.env_remove("TESTD_TOKEN_PROFILE")
		.env_remove("TESTD_PROFILE")
		.current_dir(home.path())
		.kill_on_drop(true);
	let output = tokio::time::timeout(std::time::Duration::from_secs(5), command.output())
		.await
		.expect("client kept retrying the rejected registration")
		.unwrap();
	host.await.unwrap();
	assert!(!output.status.success());
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(stderr.contains("name is already registered"), "{stderr}");
	assert!(!stderr.contains("retrying"), "{stderr}");
}

#[test]
fn host_config_has_no_leaf_credentials() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());
	let config = config(home.path());
	assert!(!config.contains("[client]"), "{config}");
	assert!(!config.contains("token ="), "{config}");
}
