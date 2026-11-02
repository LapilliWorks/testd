mod host;

use std::io::IsTerminal;

use anyhow::Context;
use clap::{Parser, Subcommand};
use testd_client::Entry;
use testd_daemon::control::{self, Dispatch};
use testd_daemon::health::{self, Action};
use testd_setup::Elevation;

#[derive(Parser)]
#[command(name = "testd", version, about = "Local dev domain manager")]
struct Cli {
	#[command(subcommand)]
	command: Command,
}

#[derive(Subcommand)]
enum Command {
	/// Configure this machine as a host. Idempotent: re-running keeps the
	/// operator secret and only updates what changed.
	Init {
		/// Path to the global Caddyfile. Auto-detected if omitted.
		#[arg(long, env = "TESTD_CADDYFILE")]
		caddyfile: Option<String>,
		/// Accept every default without prompting.
		#[arg(long, short = 'y', env = "TESTD_YES")]
		yes: bool,
		/// Configure the OS resolver now instead of lazily on the first remote client.
		#[arg(long)]
		resolver_now: bool,
	},
	/// Register domain(s) and optionally wrap a command. Deregisters on exit.
	/// Without a command, holds the connection until Ctrl+C.
	///
	/// Each entry is name:port, or host:name:port to override the target host.
	/// Name defaults to current directory name with the :port shorthand.
	///
	/// Usage: testd run :3000
	///        testd run :3000 -- npm run dev
	///        testd run myapp:3000 -- npm run dev
	///        testd run frontend:3000 api:8080 -- npm run dev
	///        testd run 10.0.0.5:myapp:3000 -- npm run dev
	Run {
		/// name:port or host:name:port pairs.
		#[arg(num_args = 1.., required = true)]
		entries: Vec<String>,
		/// Take names owned by another connection.
		#[arg(long)]
		force: bool,
		/// Single node address. Overrides the node profile.
		#[arg(long, env = "TESTD_HOST")]
		host: Option<String>,
		/// Comma-separated node addresses. Overrides the node profile.
		#[arg(long, env = "TESTD_HOSTS")]
		hosts: Option<String>,
		/// Credential profile. Overrides the project config.
		#[arg(long)]
		token_profile: Option<String>,
		/// Node profile from `~/.config/testd/leaf.toml`.
		#[arg(long, env = "TESTD_PROFILE")]
		node_profile: Option<String>,
		/// Command to run. If omitted, holds registration until Ctrl+C.
		#[arg(last = true)]
		command: Vec<String>,
	},
	/// Deregister one or more domains.
	Deregister {
		/// Domain names (without the TLD).
		#[arg(required = true)]
		domains: Vec<String>,
		/// Single node address. Overrides the node profile.
		#[arg(long, env = "TESTD_HOST")]
		host: Option<String>,
		/// Comma-separated node addresses. Overrides the node profile.
		#[arg(long, env = "TESTD_HOSTS")]
		hosts: Option<String>,
		/// Credential profile. Overrides the project config.
		#[arg(long)]
		token_profile: Option<String>,
		/// Node profile from `~/.config/testd/leaf.toml`.
		#[arg(long, env = "TESTD_PROFILE")]
		node_profile: Option<String>,
	},
	/// Run the host daemon in headless mode.
	Host,
	/// Print the authenticated URL for the local dashboard.
	Dashboard,
	/// Handle a testd:// action URL, as delivered by an OS URL-scheme handler.
	Url {
		/// testd://fix/resolver or testd://fix/certificate.
		url: String,
	},
	/// Check host setup and optionally fix it.
	Doctor {
		/// Apply fixes that need privileges: configure the resolver, import the
		/// managed Caddyfile, trust the root CA.
		#[arg(long)]
		fix: bool,
		/// Print a machine-readable summary.
		#[arg(long)]
		json: bool,
	},
	/// Share a registered name. The tunnel lives in the daemon, not in this process.
	Share {
		/// Registered name, without the TLD.
		#[arg(required_unless_present_any = ["list", "stop"])]
		name: Option<String>,
		/// Stop sharing this name.
		#[arg(long, conflicts_with = "name")]
		stop: Option<String>,
		/// List active shares and their URLs.
		#[arg(long, conflicts_with_all = ["name", "stop"])]
		list: bool,
		/// Tunnel provider: cloudflared (default), tailscale, or ngrok.
		#[arg(long)]
		provider: Option<String>,
	},
	/// List access requests waiting for approval on this host.
	Requests,
	/// Approve a waiting access request. Its client receives a new token.
	Approve {
		/// Request id from `testd requests`.
		#[arg(allow_hyphen_values = true)]
		id: String,
	},
	/// Deny a waiting access request.
	Deny {
		/// Request id from `testd requests`.
		#[arg(allow_hyphen_values = true)]
		id: String,
	},
	/// List tokens issued to leaves, or revoke one.
	Tokens {
		/// Revoke this token id from `testd tokens`.
		#[arg(long, allow_hyphen_values = true)]
		revoke: Option<String>,
	},
	/// Print a Caddyfile that routes every name to the built-in edge.
	ExportCaddyfile,
	/// Remove system integration: the OS resolver route and trusted root.
	/// Local data stays unless --purge is passed. Stop the daemon first.
	Uninstall {
		/// Also delete the config directory, including the PKI and local state.
		#[arg(long)]
		purge: bool,
		/// Leave the OS resolver route in place.
		#[arg(long)]
		keep_resolver: bool,
		/// Leave the trusted root certificate in place.
		#[arg(long)]
		keep_certificate: bool,
	},
	/// Install the hosts helper and sudoers rule for the hosts resolver.
	SetupHostsHelper {
		/// Installation prefix. Script installs to {prefix}/libexec/testd-hosts-helper.
		#[arg(long, default_value = "/usr/local")]
		prefix: std::path::PathBuf,
	},
}

/// Infer domain from the current directory name.
fn infer_domain() -> anyhow::Result<String> {
	let cwd = std::env::current_dir()?;
	let name = cwd
		.file_name()
		.and_then(|n| n.to_str())
		.ok_or_else(|| anyhow::anyhow!("cannot infer domain from current directory"))?;
	Ok(name.to_owned())
}

/// Parse entries: ":3000", "myapp:3000", "10.0.0.5:myapp:3000".
fn parse_entries(raw: Vec<String>) -> anyhow::Result<Vec<Entry>> {
	let mut entries = Vec::with_capacity(raw.len());
	for s in raw {
		let parts: Vec<&str> = s.splitn(3, ':').collect();
		let entry = match parts.as_slice() {
			// ":3000" splits into ["", "3000"].
			[_, port] if s.starts_with(':') => {
				let port = parse_port(port, &s)?;
				Entry { domain: infer_domain()?, target: port.to_string() }
			},
			// "myapp:3000"
			[name, port] => {
				let port = parse_port(port, &s)?;
				Entry { domain: (*name).to_owned(), target: port.to_string() }
			},
			// "10.0.0.5:myapp:3000"
			[host, name, port] => {
				let port = parse_port(port, &s)?;
				Entry { domain: (*name).to_owned(), target: format!("{host}:{port}") }
			},
			_ => anyhow::bail!("invalid entry {s:?}: expected name:port or host:name:port"),
		};
		testd_core::validate::validate_domain_labels(&entry.domain).map_err(|e| anyhow::anyhow!(e))?;
		testd_core::validate::validate_target(&entry.target).map_err(|e| anyhow::anyhow!(e))?;
		if testd_core::validate::is_single_label(&entry.domain) {
			eprintln!("[testd] [warn]  {}: {}", entry.domain, testd_core::validate::SINGLE_LABEL_HINT);
		}
		entries.push(entry);
	}
	Ok(entries)
}

fn parse_port(s: &str, entry: &str) -> anyhow::Result<u16> {
	s.parse::<u16>().map_err(|_| anyhow::anyhow!("invalid port in {entry:?}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let cli = Cli::parse();

	match cli.command {
		Command::Init { caddyfile, yes, resolver_now } => init(caddyfile, yes, resolver_now).await,
		Command::Run { entries, force, host, hosts, token_profile, node_profile, command } => {
			let entries = parse_entries(entries)?;
			let config = leaf_config(host, hosts, token_profile, node_profile)?;
			if command.is_empty() {
				testd_client::register(&entries, force, config).await
			} else {
				testd_client::run(&entries, &command, force, config).await
			}
		},
		Command::Deregister { domains, host, hosts, token_profile, node_profile } => {
			let config = leaf_config(host, hosts, token_profile, node_profile)?;
			testd_client::deregister(&domains, config).await
		},
		Command::Host => host::run().await,
		Command::Dashboard => dashboard(),
		Command::Url { url } => url_action(&url),
		Command::Doctor { fix, json } => {
			let code = doctor(fix, json).await?;
			std::process::exit(code);
		},
		Command::Share { name, stop, list, provider } => share(name, stop, list, provider),
		Command::Requests => requests(),
		Command::Approve { id } => approve(&id),
		Command::Deny { id } => deny(&id),
		Command::Tokens { revoke } => tokens(revoke.as_deref()),
		Command::ExportCaddyfile => export_caddyfile(),
		Command::Uninstall { purge, keep_resolver, keep_certificate } => {
			uninstall(purge, keep_resolver, keep_certificate)
		},
		Command::SetupHostsHelper { prefix } => setup_hosts_helper(prefix),
	}
}

fn dashboard() -> anyhow::Result<()> {
	match control::dashboard_url()? {
		Some(url) => {
			println!("{url}");
			Ok(())
		},
		None => anyhow::bail!("{NO_DAEMON}"),
	}
}

/// Handle a `testd://` action without the GUI.
///
/// Prefer the running daemon so its health view and notifications update at
/// once. Fall back to a one-shot repair when the daemon is gone, for example a
/// notification that outlived it.
fn url_action(url: &str) -> anyhow::Result<()> {
	let action = Action::parse(url).ok_or_else(|| anyhow::anyhow!("unknown testd action: {url}"))?;
	match control::send_action(url)? {
		Dispatch::Handled(Ok(())) => return Ok(()),
		Dispatch::Handled(Err(e)) => return Err(anyhow::anyhow!("{e}")),
		Dispatch::NotRunning => {},
	}

	// An OS handler has no terminal, so prefer the native authorization dialog.
	let elevation = if std::io::stdin().is_terminal() { Elevation::Sudo } else { Elevation::Gui };
	health::repair_once(action, elevation).map_err(|e| anyhow::anyhow!("{e}"))
}

// --- init ---

/// Everything `init` needs to know about an existing config.
#[derive(Default)]
struct Existing {
	caddy_config_path: Option<String>,
	secret: Option<String>,
}

fn read_existing() -> Existing {
	let Some(table) = testd_core::config::read_config_table() else {
		return Existing::default();
	};
	let host = table.get("host");
	Existing {
		caddy_config_path: host
			.and_then(|h| h.get("caddy_config_path"))
			.and_then(|v| v.as_str())
			.filter(|v| !v.is_empty())
			.map(str::to_owned),
		secret: host
			.and_then(|h| h.get("secret"))
			.and_then(|v| v.as_str())
			.filter(|v| !v.is_empty())
			.map(str::to_owned),
	}
}

fn certificate_summary(pem: &str) -> String {
	testd_pki::inspect_certificate(pem)
		.map(|info| info.summary())
		.unwrap_or_else(|e| format!("certificate unreadable: {e}"))
}

async fn init(caddyfile: Option<String>, yes: bool, resolver_now: bool) -> anyhow::Result<()> {
	use testd_core::config::write_config_update;

	let existing = read_existing();
	let has_config = testd_core::config::config_exists();

	// Host init.
	eprintln!("testd: local dev domain manager\n");

	let tld = testd_core::config::host_tld();
	let interactive = std::io::stdin().is_terminal() && !yes;
	let allow_privileged = interactive || yes;

	/* Resolver setup is deferred by default; certificate trust is handled below. */
	eprintln!("[1/3] Resolver");
	if resolver_now {
		init_resolver_now(tld)?;
	} else if resolver_configured(tld) {
		eprintln!("      already configured: .{tld} queries resolve to {}\n", resolver_dns_addr());
	} else {
		eprintln!("      deferred: .{tld} is configured when the first client connects from another machine");
		eprintln!("      run `testd doctor --fix` to configure it now\n");
	}

	// [2/3] Local CA: browsers must trust the root once.
	eprintln!("[2/3] Certificate authority");
	let pki_dir = testd_core::config::config_dir().join("pki");
	let ca = testd_pki::Ca::load_or_init(&pki_dir)?;
	let info = testd_pki::inspect_certificate(ca.root_cert_pem())?;
	eprintln!("      root: {}", pki_dir.join("root.crt").display());
	eprintln!("      {}", info.summary());
	if testd_setup::is_root_trusted(ca.root_cert_pem()) {
		eprintln!("      trusted by the system\n");
	} else if allow_privileged {
		eprintln!("      installing the root into the system trust store (administrator privileges required)");
		match testd_setup::trust_root(ca.root_cert_pem()) {
			Ok(()) => eprintln!("      done\n"),
			Err(e) => {
				eprintln!("      warning: {e}");
				eprintln!("      run `testd doctor --fix` later\n");
			},
		}
	} else {
		eprintln!("      not trusted; run `testd doctor --fix` or `testd init --yes` to install it\n");
	}

	// [3/3] External front: optional. The built-in edge needs no Caddy.
	eprintln!("[3/3] External front (optional)");
	let caddy_config_path = if caddyfile.is_some() {
		init_caddyfile(caddyfile.or_else(|| std::env::var("TESTD_CADDYFILE").ok()), interactive, yes)?
	} else if existing.caddy_config_path.is_some() {
		init_caddyfile(existing.caddy_config_path.clone(), interactive, yes)?
	} else {
		match testd_core::config::detect_caddy_config() {
			testd_core::config::CaddyDetection::Found { .. } => init_caddyfile(None, interactive, yes)?,
			_ => {
				eprintln!("      Caddy not found; the built-in edge serves HTTPS directly");
				eprintln!("      `testd export-caddyfile` prints a config for an external front\n");
				String::new()
			},
		}
	};

	if !caddy_config_path.is_empty() {
		let managed = testd_core::config::config_dir().join("Caddyfile");
		let content = testd_daemon::edge::caddyfile(tld, http_addr_from_config());
		if let Some(parent) = managed.parent() {
			std::fs::create_dir_all(parent)?;
		}
		std::fs::write(&managed, content)?;
	}

	let has_existing_secret = existing.secret.is_some();
	let secret = match existing.secret {
		Some(secret) => secret,
		None => testd_core::config::generate_operator_secret()?,
	};
	let path = write_config_update(&caddy_config_path, Some(&secret))?;
	eprintln!("config written to {}", path.display());

	// The operator secret is the bootstrap credential. Re-running keeps it.
	if !has_existing_secret {
		eprintln!("operator secret written to [host] secret in {}", path.display());
		eprintln!("leaves request their own token on first run; approve with `testd requests` and `testd approve`");
		eprintln!("the secret is for this machine and for unattended clients that set TESTD_TOKEN");
	}
	eprintln!();

	init_show_dev_commands();
	if has_config {
		eprintln!("\nSetup refreshed. Run `testd host` to start the daemon.");
	} else {
		eprintln!("\nSetup complete. Run `testd host` to start the daemon.");
	}
	Ok(())
}

/// Write a new operator secret into an existing host config.
fn write_fresh_operator_secret() -> anyhow::Result<()> {
	let secret = testd_core::config::generate_operator_secret()?;
	testd_core::config::write_operator_secret(&secret)?;
	Ok(())
}

fn resolver_dns_addr() -> std::net::SocketAddr {
	use testd_core::config::DEFAULT_DNS_PORT;

	std::net::SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_PORT))
}

fn resolver_configured(tld: &str) -> bool {
	testd_setup::is_os_resolver_configured(tld, resolver_dns_addr())
}

/// Configure the OS resolver now. Requires sudo.
fn init_resolver_now(tld: &str) -> anyhow::Result<()> {
	let dns_addr = resolver_dns_addr();
	if resolver_configured(tld) {
		eprintln!("      already configured: .{tld} queries resolve to {dns_addr}\n");
		return Ok(());
	}
	eprintln!("      configuring .{tld} queries to {dns_addr} (administrator privileges required)");
	match testd_setup::setup_os_resolver(tld, dns_addr) {
		Ok(()) => eprintln!("      done\n"),
		Err(e) => eprintln!("      warning: setup failed: {e}\n"),
	}
	Ok(())
}

fn init_caddyfile(explicit: Option<String>, interactive: bool, yes: bool) -> anyhow::Result<String> {
	use testd_core::config::CaddyDetection;

	let managed = testd_core::config::config_dir().join("Caddyfile");

	let caddy_config_path = if let Some(path) = explicit {
		if path.is_empty() {
			eprintln!("      skipped: external front disabled");
			return Ok(String::new());
		}
		eprintln!("      using Caddyfile: {path}");
		path
	} else {
		match testd_core::config::detect_caddy_config() {
			CaddyDetection::Found { path } => {
				eprintln!("      detected Caddyfile: {path}");
				path
			},
			CaddyDetection::Missing { expected } => {
				eprintln!("      Caddy is installed but no Caddyfile was found; using {expected}");
				expected
			},
			CaddyDetection::NoCaddy => {
				eprintln!("      Caddy does not appear to be installed; skipping");
				return Ok(String::new());
			},
		}
	};

	let caddy_path = std::path::Path::new(&caddy_config_path);
	if testd_setup::has_caddyfile_import(caddy_path, &managed) {
		eprintln!("      already configured: {caddy_config_path} imports testd config\n");
		return Ok(caddy_config_path);
	}

	eprintln!("      the global Caddyfile needs to import the testd-managed config:");
	eprintln!("        import {}\n", managed.display());

	let should_write = if interactive {
		eprint!("      add this line to {caddy_config_path}? [Y/n] ");
		let mut answer = String::new();
		std::io::stdin().read_line(&mut answer)?;
		let answer = answer.trim();
		answer.is_empty() || answer.eq_ignore_ascii_case("y")
	} else {
		// Unattended without --yes: do not touch a file outside the config dir.
		yes && !caddy_config_path.is_empty()
	};

	if should_write {
		testd_setup::write_caddyfile_import(caddy_path, &managed)?;
		eprintln!("      done\n");
	} else {
		eprintln!("      skipped; add it manually or rerun with --yes\n");
	}

	Ok(caddy_config_path)
}

fn init_show_dev_commands() {
	eprintln!("Next steps");
	eprintln!("      On this machine:");
	eprintln!("        testd run app.example:3000");
	eprintln!();
	eprintln!("      From another machine:");
	eprintln!("        testd run --host <host-address> :3000");
	eprintln!("      The leaf asks for a token on first run. Approve it here:");
	eprintln!("        testd requests");
	eprintln!("        testd approve <id>");
	eprintln!();
	eprintln!("      For unattended clients, present the operator secret as TESTD_TOKEN instead");
	eprintln!();
	eprintln!("      Host addresses:");
	for iface in if_addrs::get_if_addrs().unwrap_or_default() {
		let ip = iface.ip();
		if ip.is_ipv6() || ip.is_loopback() {
			continue;
		}
		eprintln!("        {ip}  # {}", iface.name);
	}
	eprintln!();
}

// --- doctor ---

/// Exit codes: 0 ready, 1 configuration, 2 resolver, 3 HTTPS edge.
async fn doctor(fix: bool, json: bool) -> anyhow::Result<i32> {
	use std::net::SocketAddr;

	use testd_core::config::{
		DEFAULT_DNS_PORT, ResolverBackend, config_dir, config_path, find_caddy_binary, load_host_config,
	};
	use testd_daemon::caddy::{self, EdgeStatus};

	let mut checks: Vec<Check> = Vec::new();
	let mut exit = 0i32;

	if !config_path().exists() {
		checks.push(Check::fail(
			"config",
			format!("missing: {}", config_path().display()),
			"run `testd init` on the host",
		));
		return finish_doctor(checks, 1, json);
	}

	let config = match load_host_config() {
		Ok(config) => config,
		Err(e) => {
			checks.push(Check::fail("config", format!("error: {e}"), "run `testd init --yes` to refresh it"));
			return finish_doctor(checks, 1, json);
		},
	};
	checks.push(Check::ok("config", config_path().display().to_string()));
	let tld = testd_core::config::host_tld();

	if config.secret.is_empty() {
		if fix {
			match write_fresh_operator_secret() {
				Ok(()) => {
					checks.push(Check::ok("secret", format!("operator secret written to {}", config_path().display())))
				},
				Err(e) => {
					exit = exit.max(1);
					checks.push(Check::fail("secret", e.to_string(), "run `testd init --yes`"));
				},
			}
		} else {
			if exit == 0 {
				exit = 1;
			}
			checks.push(Check::fail(
				"secret",
				"no operator secret".to_owned(),
				"run `testd doctor --fix` to write one; existing clients keep their copy",
			));
		}
	} else {
		checks.push(Check::ok("secret", "operator secret set".to_owned()));
	}

	{
		let dns_addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_DNS_PORT));
		match config.resolver {
			ResolverBackend::Dns => {
				if testd_setup::is_os_resolver_configured(tld, dns_addr) {
					checks.push(Check::ok("resolver", format!("configured (DNS server on {dns_addr})")));
				} else if fix {
					match testd_setup::setup_os_resolver(tld, dns_addr) {
						Ok(()) if testd_setup::is_os_resolver_configured(tld, dns_addr) => {
							checks.push(Check::ok("resolver", format!("configured (DNS server on {dns_addr})")));
						},
						Ok(()) => checks.push(Check::fail(
							"resolver",
							"setup ran but the route is not reported".into(),
							"check `resolvectl status lo`",
						)),
						Err(e) => checks.push(Check::fail("resolver", e.to_string(), "run as a user with sudo")),
					}
				} else {
					exit = 2;
					checks.push(Check::fail(
						"resolver",
						"not configured".into(),
						"run `testd doctor --fix` or `testd init --resolver-now`",
					));
				}
			},
			ResolverBackend::Hosts => {
				if config.hosts_helper_path.exists() {
					checks.push(Check::ok(
						"resolver",
						format!("hosts helper present: {}", config.hosts_helper_path.display()),
					));
				} else {
					checks.push(Check::fail(
						"resolver",
						"hosts helper missing".into(),
						"run `testd setup-hosts-helper`",
					));
				}
			},
		}

		// `is_os_resolver_configured` only proves the route exists. Resolve the
		// dashboard name the way a browser does, through the OS resolver.
		let dashboard = format!("testd.{tld}");
		let expected = match config.resolver {
			ResolverBackend::Dns => std::net::IpAddr::V4(config.answer_addr),
			ResolverBackend::Hosts => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
		};
		let mut resolved = resolve_via_os(&dashboard);
		// The route can be correct while the host is not running yet. Answer the
		// dashboard name from a one-shot server so this checks the OS route
		// instead of requiring `testd host`. `false` means the port is taken,
		// usually by the running host.
		let mut probe_error = None;
		if matches!(config.resolver, ResolverBackend::Dns)
			&& !matches!(&resolved, Some(addrs) if addrs.contains(&expected))
		{
			match start_resolution_probe(tld, config.answer_addr).await {
				Ok(true) => {
					resolved = resolve_via_os_until(&dashboard, expected, std::time::Duration::from_secs(2)).await;
				},
				Ok(false) => {},
				Err(error) => probe_error = Some(error),
			}
		}
		// A route can exist while mDNSResponder or systemd-resolved still answers
		// from a stale cache. Rewriting the route also refreshes that cache.
		let resolved = if fix
			&& matches!(config.resolver, ResolverBackend::Dns)
			&& !matches!(&resolved, Some(addrs) if addrs.contains(&expected))
		{
			match testd_setup::setup_os_resolver(tld, dns_addr) {
				Ok(()) => resolve_via_os_until(&dashboard, expected, std::time::Duration::from_secs(5)).await,
				Err(_) => resolved,
			}
		} else {
			resolved
		};
		match resolved {
			Some(addrs) if addrs.contains(&expected) => {
				checks.push(Check::ok("resolution", format!("{dashboard} resolves to {expected}")));
			},
			Some(addrs) => {
				exit = exit.max(2);
				checks.push(Check::fail(
					"resolution",
					format!("{dashboard} resolves to {}, not {expected}", addrs_display(&addrs)),
					"look for a conflicting NRPT rule; on Windows run `ipconfig /flushdns`",
				));
			},
			None => {
				exit = exit.max(2);
				let detail = match probe_error {
					Some(error) => format!("{dashboard} does not resolve (resolution probe failed: {error})"),
					None => format!("{dashboard} does not resolve"),
				};
				checks.push(Check::fail("resolution", detail, "run `testd doctor --fix`"));
			},
		}
	}

	let pki_dir = config.pki_dir.clone();
	if config.edge_enabled {
		let validity =
			if fix { testd_pki::Ca::load_or_init(&pki_dir).map(|_| ()) } else { testd_pki::check_validity(&pki_dir) };
		match validity {
			Ok(()) => checks.push(Check::ok("pki", "root and intermediate can issue a valid leaf".into())),
			Err(error) => {
				exit = exit.max(3);
				checks.push(Check::fail(
					"pki",
					format!("{error:#}"),
					"run `testd doctor --fix`; restore root.key if needed",
				));
			},
		}
	}
	let root_cert = pki_dir.join("root.crt");
	let root_pem = std::fs::read_to_string(&root_cert).ok();
	if config.edge_enabled {
		match &root_pem {
			// Windows and macOS can hold stale certificates with the same CN. Always
			// reinstall the exact root when repairing.
			Some(pem) if fix && (cfg!(windows) || cfg!(target_os = "macos")) => match testd_setup::trust_root(pem) {
				Ok(()) => {
					checks.push(Check::ok("certificate", format!("root installed: {}", certificate_summary(pem))))
				},
				Err(e) => {
					exit = exit.max(3);
					checks.push(Check::fail("certificate", e.to_string(), "run `testd init --yes`"));
				},
			},
			Some(pem) if testd_setup::is_root_trusted(pem) => {
				checks.push(Check::ok("certificate", format!("root trusted: {}", root_cert.display())));
			},
			Some(pem) if fix => match testd_setup::trust_root(pem) {
				Ok(()) => {
					checks.push(Check::ok("certificate", format!("root installed: {}", certificate_summary(pem))))
				},
				Err(e) => {
					exit = exit.max(3);
					checks.push(Check::fail("certificate", e.to_string(), "run `testd init --yes`"));
				},
			},
			Some(_) => {
				exit = exit.max(3);
				checks.push(Check::fail("certificate", "root is not trusted".into(), "run `testd doctor --fix`"));
			},
			None => {
				exit = exit.max(3);
				checks.push(Check::fail(
					"certificate",
					format!("missing: {}", root_cert.display()),
					"run `testd init`",
				));
			},
		}
	} else {
		checks.push(Check::ok("certificate", "external front owns TLS trust".into()));
	}

	match find_caddy_binary() {
		Some(path) => checks.push(Check::ok("caddy", format!("{} (optional)", path.display()))),
		None if config.edge_enabled => {
			checks.push(Check::ok("caddy", "not installed; the built-in edge is used".into()))
		},
		None => checks.push(Check::ok("caddy", "not installed; an external front must terminate TLS".into())),
	}

	let managed = config_dir().join("Caddyfile");
	let global = &config.caddy_config_path;
	if global.as_os_str().is_empty() {
		checks.push(Check::ok("caddyfile", "no external front configured".into()));
	} else if !global.exists() {
		checks.push(Check::fail(
			"caddyfile",
			format!("missing: {}", global.display()),
			"create it or rerun `testd init`",
		));
	} else if testd_setup::has_caddyfile_import(global, &managed) {
		checks.push(Check::ok("caddyfile", format!("import present in {}", global.display())));
	} else if fix {
		testd_setup::write_caddyfile_import(global, &managed)?;
		checks.push(Check::ok("caddyfile", format!("import added to {}", global.display())));
	} else {
		checks.push(Check::fail(
			"caddyfile",
			format!("import missing in {}", global.display()),
			"run `testd doctor --fix`",
		));
	}

	if !global.as_os_str().is_empty() && find_caddy_binary().is_some() {
		if let Err(e) = caddy::reload(global).await {
			checks.push(Check::fail("reload", e.to_string(), "check the global Caddyfile"));
		} else {
			checks.push(Check::ok("reload", "Caddy reloaded".into()));
		}
	}

	let edge_port = if config.edge_enabled { config.edge_addr.port() } else { 443 };
	let mut status = caddy::probe(tld, edge_port);
	if config.edge_enabled
		&& status == EdgeStatus::Untrusted
		&& fix && let Some(pem) = &root_pem
	{
		match testd_setup::trust_root(pem) {
			Ok(()) => status = caddy::probe(tld, edge_port),
			Err(e) => checks.push(Check::fail("certificate", e.to_string(), "run `testd init --yes`")),
		}
	}
	match status {
		EdgeStatus::Trusted => checks.push(Check::ok("edge", "ready".into())),
		EdgeStatus::Untrusted => {
			exit = exit.max(3);
			checks.push(Check::fail("edge", "certificate not trusted".into(), "run `testd doctor --fix`"));
		},
		EdgeStatus::Unreachable => {
			exit = exit.max(3);
			checks.push(Check::fail(
				"edge",
				format!("nothing is serving HTTPS on port {edge_port}"),
				"start `testd host` (or Caddy) and rerun",
			));
		},
		EdgeStatus::Unknown => {
			exit = exit.max(3);
			checks.push(Check::fail("edge", "unknown (curl unavailable or timed out)".into(), "install curl"));
		},
	}

	finish_doctor(checks, exit, json)
}

/// Resolve a name through the OS resolver a browser uses, not the DNS server
/// directly, so NRPT, hosts entries, and caches are all exercised.
fn resolve_via_os(name: &str) -> Option<Vec<std::net::IpAddr>> {
	use std::net::ToSocketAddrs;

	let mut addrs: Vec<std::net::IpAddr> = (name, 443).to_socket_addrs().ok()?.map(|addr| addr.ip()).collect();
	addrs.sort();
	addrs.dedup();
	(!addrs.is_empty()).then_some(addrs)
}

/// Start a DNS server for the resolution check. It serves until the process
/// exits. Returns `false` when the DNS port is already in use, which usually
/// means the host owns it.
async fn start_resolution_probe(tld: &str, answer_addr: std::net::Ipv4Addr) -> std::io::Result<bool> {
	use testd_daemon::resolver::Resolver as _;

	match testd_daemon::resolver::dns::DnsResolver::start(tld, answer_addr, Elevation::Sudo).await {
		Ok(probe) => {
			probe.apply(&[])?;
			Ok(true)
		},
		Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => Ok(false),
		Err(error) => Err(error),
	}
}

/// Poll the OS resolver until it returns `expected` or the timeout elapses.
async fn resolve_via_os_until(
	name: &str,
	expected: std::net::IpAddr,
	timeout: std::time::Duration,
) -> Option<Vec<std::net::IpAddr>> {
	let deadline = tokio::time::Instant::now() + timeout;
	loop {
		let resolved = resolve_via_os(name);
		if matches!(&resolved, Some(addrs) if addrs.contains(&expected)) || tokio::time::Instant::now() >= deadline {
			return resolved;
		}
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	}
}

fn addrs_display(addrs: &[std::net::IpAddr]) -> String {
	addrs.iter().map(|addr| addr.to_string()).collect::<Vec<_>>().join(", ")
}

struct Check {
	name: &'static str,
	ok: bool,
	detail: String,
	fix: Option<&'static str>,
}

impl Check {
	fn ok(name: &'static str, detail: String) -> Self {
		Self { name, ok: true, detail, fix: None }
	}

	fn fail(name: &'static str, detail: String, fix: &'static str) -> Self {
		Self { name, ok: false, detail, fix: Some(fix) }
	}
}

fn finish_doctor(checks: Vec<Check>, exit: i32, json: bool) -> anyhow::Result<i32> {
	if json {
		let value = serde_json::json!({
			"ok": exit == 0,
			"exit_code": exit,
			"checks": checks.iter().map(|check| serde_json::json!({
				"name": check.name,
				"ok": check.ok,
				"detail": check.detail,
				"fix": check.fix,
			})).collect::<Vec<_>>(),
		});
		println!("{}", serde_json::to_string_pretty(&value)?);
		return Ok(exit);
	}

	eprintln!("testd doctor\n");
	let width = checks.iter().map(|check| check.name.len()).max().unwrap_or(0);
	for check in &checks {
		let mark = if check.ok { "ok  " } else { "fail" };
		eprintln!("{mark}  {:width$}  {}", check.name, check.detail, width = width);
		if let Some(fix) = check.fix {
			eprintln!("      {:width$}  -> {fix}", "", width = width);
		}
	}
	eprintln!();
	if exit == 0 {
		eprintln!("ready");
	} else {
		eprintln!("not ready (exit {exit})");
	}
	Ok(exit)
}

/// The configured plain HTTP routing address, or the default.
fn http_addr_from_config() -> std::net::SocketAddr {
	read_existing_table()
		.and_then(|table| {
			table
				.get("host")
				.and_then(|host| host.get("http_addr"))
				.and_then(|value| value.as_str())
				.and_then(|value| value.parse().ok())
		})
		.unwrap_or_else(testd_core::config::default_http_addr)
}

fn read_existing_table() -> Option<toml::Table> {
	testd_core::config::read_config_table()
}

/// Resolve the explicit node list for one run.
fn explicit_hosts(host: Option<String>, hosts: Option<String>) -> Option<Vec<String>> {
	let raw = hosts.or(host)?;
	let hosts: Vec<String> = raw
		.split(',')
		.map(str::trim)
		.filter(|value| !value.is_empty())
		.map(|value| {
			if value.contains(':') { value.to_owned() } else { format!("{value}:{}", testd_core::config::DEFAULT_PORT) }
		})
		.collect();
	(!hosts.is_empty()).then_some(hosts)
}

/// Load the leaf settings used by `run` and `deregister`.
fn leaf_config(
	host: Option<String>,
	hosts: Option<String>,
	token_profile: Option<String>,
	node_profile: Option<String>,
) -> anyhow::Result<testd_core::config::ClientConfig> {
	testd_core::config::load_client_config(
		explicit_hosts(host, hosts),
		token_profile.as_deref(),
		node_profile.as_deref(),
	)
	.context("failed to load leaf config")
}

fn share(name: Option<String>, stop: Option<String>, list: bool, provider: Option<String>) -> anyhow::Result<()> {
	use testd_daemon::control::{Dispatch, ShareStarted, list_shares, start_share, stop_share};
	use testd_daemon::share::Provider;

	const NOT_RUNNING: &str =
		"no daemon is running; a tunnel lives in the daemon, so start `testd host` or the tray first";

	if list {
		match list_shares()? {
			None => anyhow::bail!("{NOT_RUNNING}"),
			Some(shares) if shares.is_empty() => println!("no active shares"),
			Some(shares) => {
				for share in shares {
					println!("{} → {} ({} via {})", share.name, share.url, share.exposure.label(), share.provider);
				}
			},
		}
		return Ok(());
	}

	if let Some(name) = stop {
		return match stop_share(&name)? {
			Dispatch::Handled(Ok(())) => {
				println!("stopped sharing {name}");
				Ok(())
			},
			Dispatch::Handled(Err(message)) => anyhow::bail!(message),
			Dispatch::NotRunning => anyhow::bail!("{NOT_RUNNING}"),
		};
	}

	let name = name.context("give a name to share, or pass --list or --stop")?;
	let provider = match provider.as_deref() {
		None => None,
		Some(value) => Some(
			Provider::parse(value)
				.with_context(|| format!("unknown provider {value:?}; use cloudflared, tailscale, or ngrok"))?,
		),
	};

	match start_share(&name, provider)? {
		ShareStarted::Started(url) => {
			println!("shared {name} → {url}");
			Ok(())
		},
		ShareStarted::Failed(message) => anyhow::bail!(message),
		ShareStarted::NotRunning => anyhow::bail!("{NOT_RUNNING}"),
	}
}

const NO_DAEMON: &str = "no daemon is running; start `testd host` or the tray first";

fn requests() -> anyhow::Result<()> {
	match control::list_requests()? {
		None => anyhow::bail!("{NO_DAEMON}"),
		Some(requests) if requests.is_empty() => println!("no pending access requests"),
		Some(requests) => {
			for request in requests {
				let names = if request.names.is_empty() { "-".to_owned() } else { request.names.join(",") };
				println!(
					"{}  {}  {}  {}  {}",
					request.id,
					request.label,
					names,
					request.address,
					age(request.requested_at)
				);
			}
		},
	}
	Ok(())
}

fn approve(id: &str) -> anyhow::Result<()> {
	match control::approve_request(id)? {
		Dispatch::Handled(Ok(())) => {
			println!("approved {id}; the waiting client was told");
			Ok(())
		},
		Dispatch::Handled(Err(message)) => anyhow::bail!("{message}"),
		Dispatch::NotRunning => anyhow::bail!("{NO_DAEMON}"),
	}
}

fn deny(id: &str) -> anyhow::Result<()> {
	match control::deny_request(id)? {
		Dispatch::Handled(Ok(())) => {
			println!("denied {id}");
			Ok(())
		},
		Dispatch::Handled(Err(message)) => anyhow::bail!("{message}"),
		Dispatch::NotRunning => anyhow::bail!("{NO_DAEMON}"),
	}
}

fn tokens(revoke: Option<&str>) -> anyhow::Result<()> {
	if let Some(id) = revoke {
		return match control::revoke_token(id)? {
			Dispatch::Handled(Ok(())) => {
				println!("revoked {id}");
				Ok(())
			},
			Dispatch::Handled(Err(message)) => anyhow::bail!("{message}"),
			Dispatch::NotRunning => anyhow::bail!("{NO_DAEMON}"),
		};
	}

	match control::list_tokens()? {
		None => anyhow::bail!("{NO_DAEMON}"),
		Some(tokens) if tokens.is_empty() => println!("no issued tokens"),
		Some(tokens) => {
			for token in tokens {
				let names = match &token.names {
					Some(names) if names.is_empty() => "no names".to_owned(),
					Some(names) => names.join(","),
					None => "all names".to_owned(),
				};
				let seen = token
					.last_seen_at
					.map(|at| format!(", last used {}", age(at)))
					.unwrap_or_default();
				println!("{}  {}  [{}]  issued {}{seen}", token.id, token.label, names, age(token.created_at));
			}
		},
	}
	Ok(())
}

/// A short relative age for access listings.
fn age(seconds: u64) -> String {
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs();
	let age = now.saturating_sub(seconds);
	match age {
		0..=59 => format!("{age}s ago"),
		60..=3599 => format!("{}m ago", age / 60),
		3600..=86399 => format!("{}h ago", age / 3600),
		_ => format!("{}d ago", age / 86400),
	}
}

fn export_caddyfile() -> anyhow::Result<()> {
	let config = testd_core::config::load_host_config()?;
	let content = testd_daemon::edge::caddyfile(testd_core::config::host_tld(), config.http_addr);
	std::fs::create_dir_all(config.caddyfile_path.parent().unwrap_or(std::path::Path::new(".")))?;
	std::fs::write(&config.caddyfile_path, &content)?;
	eprintln!("wrote {}", config.caddyfile_path.display());
	eprintln!("add this line to your global Caddyfile:");
	eprintln!("  import {}", config.caddyfile_path.display());
	Ok(())
}

const HOSTS_HELPER_SCRIPT: &str = include_str!("../scripts/testd-hosts-helper");

fn uninstall(purge: bool, keep_resolver: bool, keep_certificate: bool) -> anyhow::Result<()> {
	let config = testd_core::config::load_host_config().ok();
	let tld = testd_core::config::host_tld();
	let mut errors = Vec::new();

	if !keep_resolver {
		eprintln!("removing the OS resolver route for .{tld}");
		if let Err(e) = testd_setup::teardown_os_resolver(tld) {
			errors.push(format!("resolver: {e}"));
		}
	}

	if !keep_certificate {
		remove_trusted_root(config.as_ref(), &mut errors);
	}

	remove_hosts_helper(config.as_ref(), &mut errors);

	if purge {
		if errors.is_empty() {
			remove_local_data(&mut errors);
		} else {
			eprintln!("local data kept because system cleanup failed; fix the errors and run again");
		}
	}

	if !errors.is_empty() {
		anyhow::bail!("uninstall is incomplete:\n  - {}", errors.join("\n  - "));
	}

	eprintln!("testd system integration removed");
	if !purge {
		eprintln!("local data kept in {}; pass --purge to remove it", testd_core::config::config_dir().display());
	}
	Ok(())
}

fn remove_trusted_root(config: Option<&testd_core::config::HostConfig>, errors: &mut Vec<String>) {
	let pki_dir = config
		.map(|config| config.pki_dir.clone())
		.unwrap_or_else(|| testd_core::config::config_dir().join("pki"));
	let path = pki_dir.join("root.crt");
	let mut removed = false;
	match std::fs::read_to_string(&path) {
		Ok(pem) => {
			eprintln!("removing the trusted root {}", path.display());
			match testd_setup::untrust_root(&pem) {
				Ok(()) => removed = true,
				Err(e) => errors.push(format!("certificate: {e}")),
			}
		},
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
			// Linux and macOS can remove their known anchors without the local
			// certificate. Windows needs it to derive the thumbprint.
			#[cfg(not(target_os = "windows"))]
			{
				match testd_setup::untrust_root("") {
					Ok(()) => {
						eprintln!("no root certificate at {}; removed the known anchors", path.display());
						removed = true;
					},
					Err(e) => errors.push(format!("certificate: {e}")),
				}
			}
			#[cfg(target_os = "windows")]
			errors.push(format!(
				"certificate: {} is missing; cannot identify the trusted root thumbprint, so trust was not removed",
				path.display()
			));
		},
		Err(e) => errors.push(format!("certificate: read {}: {e}", path.display())),
	}

	if removed
		&& (pki_dir.exists() || config.is_some())
		&& let Err(e) = testd_daemon::health::set_auto_trust(&pki_dir, false)
	{
		errors.push(format!("certificate: {e}"));
	}
}

fn remove_hosts_helper(config: Option<&testd_core::config::HostConfig>, errors: &mut Vec<String>) {
	use std::process::Command;

	let default_helper = std::path::PathBuf::from("/usr/local/libexec/testd-hosts-helper");
	let helper = config.map(|config| &config.hosts_helper_path).unwrap_or(&default_helper);
	if helper.exists() {
		eprintln!("removing the hosts helper {}", helper.display());
		match Command::new("sudo").args(["rm", "-f"]).arg(helper).status() {
			Ok(status) if status.success() => {},
			Ok(_) => errors.push("hosts helper: sudo rm failed".into()),
			Err(e) => errors.push(format!("hosts helper: {e}")),
		}
	}

	let sudoers = std::path::Path::new("/etc/sudoers.d/testd-hosts-helper");
	if sudoers.exists() {
		eprintln!("removing the sudoers rule {}", sudoers.display());
		match Command::new("sudo").args(["rm", "-f"]).arg(sudoers).status() {
			Ok(status) if status.success() => {},
			Ok(_) => errors.push("hosts helper: sudo rm of the sudoers rule failed".into()),
			Err(e) => errors.push(format!("hosts helper: {e}")),
		}
	}
}

fn remove_local_data(errors: &mut Vec<String>) {
	let dir = testd_core::config::config_dir();
	if !dir.exists() {
		return;
	}
	eprintln!("removing local data {}", dir.display());
	if let Err(e) = std::fs::remove_dir_all(&dir) {
		errors.push(format!("local data: {e}"));
	}
}

fn setup_hosts_helper(prefix: std::path::PathBuf) -> anyhow::Result<()> {
	use std::process::Command;

	if cfg!(windows) {
		anyhow::bail!("the hosts helper is not supported on Windows; use the built-in DNS resolver");
	}

	let libexec = prefix.join("libexec");
	let helper_path = libexec.join("testd-hosts-helper");

	eprintln!("installing hosts helper to {}", helper_path.display());

	// Create the libexec directory.
	let status = Command::new("sudo").args(["mkdir", "-p"]).arg(&libexec).status()?;
	if !status.success() {
		anyhow::bail!("failed to create {}", libexec.display());
	}

	// Write the script via sudo tee.
	let mut child = Command::new("sudo")
		.arg("tee")
		.arg(&helper_path)
		.stdin(std::process::Stdio::piped())
		.stdout(std::process::Stdio::null())
		.spawn()?;
	if let Some(mut stdin) = child.stdin.take() {
		use std::io::Write;
		stdin.write_all(HOSTS_HELPER_SCRIPT.as_bytes())?;
	}
	let status = child.wait()?;
	if !status.success() {
		anyhow::bail!("failed to write helper script");
	}

	// Make executable.
	let status = Command::new("sudo").args(["chmod", "755"]).arg(&helper_path).status()?;
	if !status.success() {
		anyhow::bail!("failed to chmod helper script");
	}

	// Install sudoers drop-in.
	let user = std::env::var("SUDO_USER")
		.or_else(|_| std::env::var("USER"))
		.or_else(|_| std::env::var("LOGNAME"))?;
	if user.is_empty() || !user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
		anyhow::bail!("refusing to write a sudoers rule for an invalid user name: {user:?}");
	}
	let sudoers_line = format!("{user} ALL=(root) NOPASSWD: {}\n", helper_path.display());
	let sudoers_path = "/etc/sudoers.d/testd-hosts-helper";

	eprintln!("installing sudoers rule to {sudoers_path}");

	let mut child = Command::new("sudo")
		.arg("tee")
		.arg(sudoers_path)
		.stdin(std::process::Stdio::piped())
		.stdout(std::process::Stdio::null())
		.spawn()?;
	if let Some(mut stdin) = child.stdin.take() {
		use std::io::Write;
		stdin.write_all(sudoers_line.as_bytes())?;
	}
	let status = child.wait()?;
	if !status.success() {
		anyhow::bail!("failed to write sudoers rule");
	}

	let status = Command::new("sudo").args(["chmod", "440", sudoers_path]).status()?;
	if !status.success() {
		anyhow::bail!("failed to chmod sudoers file");
	}

	// Verify the sudoers file is valid.
	let status = Command::new("sudo").args(["visudo", "-c", "-f", sudoers_path]).status()?;
	if !status.success() {
		eprintln!("warning: sudoers validation failed; you may need to fix {sudoers_path} manually");
	}

	eprintln!("\nHosts helper installed successfully.");
	eprintln!("Add this to your [host] config if it is not already set:");
	eprintln!("  resolver = \"hosts\"");
	eprintln!("  hosts_helper_path = \"{}\"", helper_path.display());

	Ok(())
}
