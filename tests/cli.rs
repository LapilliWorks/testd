//! CLI-level tests: idempotent init, TLD modes, doctor exit codes.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn testd(home: &Path, args: &[&str]) -> Output {
	Command::new(env!("CARGO_BIN_EXE_testd"))
		.args(args)
		.env("HOME", home)
		.env_remove("TESTD_HOST")
		.env_remove("TESTD_TLD")
		.env_remove("TESTD_CADDYFILE")
		.env_remove("TESTD_YES")
		.env_remove("TESTD_TOKEN")
		.env_remove("TESTD_TOKEN_PROFILE")
		.env_remove("TESTD_PROFILE")
		.output()
		.expect("run testd")
}

fn init(home: &Path) -> Output {
	testd(home, &["init", "--caddyfile", ""])
}

fn config(home: &Path) -> String {
	std::fs::read_to_string(home.join(".config/testd/config.toml")).expect("config exists")
}

fn operator_secret(home: &Path) -> String {
	let table: toml::Table = toml::from_str(&config(home)).expect("config parses");
	table["host"]["secret"].as_str().expect("init writes [host] secret").to_owned()
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
fn init_writes_and_keeps_an_operator_secret() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());
	let first = operator_secret(home.path());
	assert!(first.len() >= 16, "secret too short: {first:?}");

	assert!(init(home.path()).status.success());
	assert_eq!(operator_secret(home.path()), first, "re-init must keep the operator secret");
}

#[test]
fn init_respects_tld_flag_and_localhost_skips_resolver() {
	let home = TempDir::new().unwrap();
	let out = testd(home.path(), &["init", "--caddyfile", "", "--tld", "localhost"]);
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

	let config = config(home.path());
	assert!(config.contains("tld = \"localhost\""), "{config}");
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(stderr.contains(".localhost"), "{stderr}");
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
		format!("#!/bin/sh\nprintf 'DNS Servers: 127.0.0.1:{DEFAULT_DNS_PORT}\\nDNS Domain: ~test\\n'\n"),
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

#[test]
fn uninstall_purge_removes_local_data_without_system_changes() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());
	assert!(home.path().join(".config/testd/config.toml").exists());

	let out = testd(home.path(), &["uninstall", "--purge", "--keep-resolver", "--keep-certificate"]);
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	assert!(!home.path().join(".config/testd").exists());
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
fn doctor_reports_localhost_resolver_as_not_needed() {
	let home = TempDir::new().unwrap();
	assert!(
		testd(home.path(), &["init", "--caddyfile", "", "--tld", "localhost"])
			.status
			.success()
	);

	let out = testd(home.path(), &["doctor", "--json"]);
	let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");
	let resolver = value["checks"]
		.as_array()
		.unwrap()
		.iter()
		.find(|c| c["name"] == "resolver")
		.unwrap();
	assert_eq!(resolver["ok"], true);
	assert!(resolver["detail"].as_str().unwrap().contains("localhost"));
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

	let credential = home.path().join(".config/testd/credentials/default");
	assert_eq!(std::fs::read_to_string(&credential).unwrap().trim(), "issued-token");
}

#[test]
fn environment_variables_are_accepted_as_inputs() {
	let home = TempDir::new().unwrap();
	let out = Command::new(env!("CARGO_BIN_EXE_testd"))
		.args(["init", "--caddyfile", ""])
		.env("HOME", home.path())
		.env("TESTD_TLD", "localhost")
		.output()
		.unwrap();
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	assert!(config(home.path()).contains("tld = \"localhost\""));
}

#[test]
fn host_config_has_no_leaf_credentials() {
	let home = TempDir::new().unwrap();
	assert!(init(home.path()).status.success());
	let config = config(home.path());
	assert!(!config.contains("[client]"), "{config}");
	assert!(!config.contains("token ="), "{config}");
}
