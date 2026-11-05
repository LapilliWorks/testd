//! Ownership-aware systemd-resolved integration.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{
	Elevation, LinuxResolverPreflight, RESOLVED_DROPIN, RESOLVED_DROPIN_DIR, global_resolver_state,
	linux_resolver_outputs, linux_resolver_preflight, ownership, resolved_dropin, run_with_stdin, shell_quote,
	silent_command, system_entry_present,
};

const CONFLICT: i32 = 17;
const OWNERSHIP_UNRECORDED: i32 = 18;

struct ResolverLayout<'a> {
	directory: &'a str,
	dropin: &'a str,
	reload: &'a str,
	dns_probe: &'a str,
	domain_probe: &'a str,
	config_probe: &'a str,
	active_probe: &'a str,
}

fn system_layout() -> ResolverLayout<'static> {
	ResolverLayout {
		directory: RESOLVED_DROPIN_DIR,
		dropin: RESOLVED_DROPIN,
		reload: "systemctl reload systemd-resolved",
		dns_probe: "resolvectl dns",
		domain_probe: "resolvectl domain",
		config_probe: "systemd-analyze cat-config systemd/resolved.conf",
		active_probe: "systemctl is-active --quiet systemd-resolved",
	}
}

fn owner_marker(layout: &ResolverLayout<'_>) -> PathBuf {
	PathBuf::from(format!("{}.owner", layout.dropin))
}

pub(super) fn snapshot_hash(dns: &str, domains: &str, configuration: &str) -> String {
	let mut digest = Sha256::new();
	for (index, value) in [dns, domains, configuration].into_iter().enumerate() {
		if index > 0 {
			digest.update([0]);
		}
		digest.update(value.trim_end_matches('\n').as_bytes());
	}
	digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_tld(tld: &str) -> io::Result<()> {
	testd_core::validate::validate_domain_labels(tld)
		.map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid resolver domain: {error}")))
}

fn install_script(layout: &ResolverLayout<'_>, tld: &str, addr: SocketAddr, expected_snapshot: &str) -> String {
	let directory = shell_quote(layout.directory);
	let dropin = shell_quote(layout.dropin);
	let marker = shell_quote(&owner_marker(layout).to_string_lossy());
	let template = shell_quote(&format!("{}/.testd-resolver.XXXXXX", layout.directory));
	let owner_template = shell_quote(&format!("{}/.testd-resolver-owner.XXXXXX", layout.directory));
	let content = shell_quote(&resolved_dropin(tld, addr));
	let tld = shell_quote(tld);
	let expected_snapshot = shell_quote(expected_snapshot);
	let ResolverLayout { reload, dns_probe, domain_probe, config_probe, active_probe, .. } = layout;
	// Recheck the live and on-disk state after authorization, then create the
	// drop-in and its ownership record without replacing an existing path.
	format!(
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n\
		LC_ALL=C; SYSTEMD_COLORS=0; SYSTEMD_PAGER=cat; COLUMNS=10000\n\
		export LC_ALL SYSTEMD_COLORS SYSTEMD_PAGER COLUMNS\n\
		IFS= read -r owner || exit 1\n\
		[ -n \"$owner\" ] || exit 1\n\
		dns=$({dns_probe}) || exit 1\n\
		domains=$({domain_probe}) || exit 1\n\
		configuration=$({config_probe}) || exit 1\n\
		snapshot=$(printf '%s\\0%s\\0%s' \"$dns\" \"$domains\" \"$configuration\" | sha256sum) || exit 1\n\
		snapshot=${{snapshot%% *}}\n\
		[ \"$snapshot\" = {expected_snapshot} ] || exit {CONFLICT}\n\
		{active_probe} || exit 1\n\
		mkdir -p {directory} || exit 1\n\
		temporary=$(mktemp {template}) || exit 1\n\
		trap 'rm -f -- \"$temporary\"' EXIT\n\
		owner_temporary=$(mktemp {owner_template}) || exit 1\n\
		trap 'rm -f -- \"$temporary\" \"$owner_temporary\"' EXIT\n\
		printf '%s' {content} > \"$temporary\" || exit 1\n\
		chmod 0644 \"$temporary\" || exit 1\n\
		owner_hash=$(printf '%s' \"$owner\" | sha256sum) || exit 1\n\
		owner_hash=${{owner_hash%% *}}\n\
		fingerprint=$(stat -c '%d:%i:%u:%g:%a' -- \"$temporary\") || exit 1\n\
		content_hash=$(sha256sum -- \"$temporary\") || exit 1\n\
		content_hash=${{content_hash%% *}}\n\
		printf '%s\\n%s\\n%s\\n%s\\n' \"$owner_hash\" \"$fingerprint\" \"$content_hash\" {tld} > \"$owner_temporary\" || exit 1\n\
		chmod 0600 \"$owner_temporary\" || exit 1\n\
		if [ -e {marker} ] || [ -L {marker} ]; then exit {CONFLICT}; fi\n\
		if ln -T -- \"$temporary\" {dropin} 2>/dev/null; then\n\
		  ln -T -- \"$owner_temporary\" {marker} 2>/dev/null || exit {OWNERSHIP_UNRECORDED}\n\
		  {reload} || exit 1\n\
		elif [ -e {dropin} ] || [ -L {dropin} ]; then\n\
		  exit {CONFLICT}\n\
		else\n\
		  exit 1\n\
		fi"
	)
}

fn remove_script(layout: &ResolverLayout<'_>, tld: &str) -> String {
	let dropin = shell_quote(layout.dropin);
	let marker = shell_quote(&owner_marker(layout).to_string_lossy());
	let tld = shell_quote(tld);
	let reload = layout.reload;
	format!(
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n\
		IFS= read -r owner || exit 1\n\
		[ -n \"$owner\" ] || exit 1\n\
		if [ ! -e {marker} ] && [ ! -L {marker} ]; then\n\
		  if [ -e {dropin} ] || [ -L {dropin} ]; then exit {CONFLICT}; fi\n\
		  exit 0\n\
		fi\n\
		[ -f {marker} ] && [ ! -L {marker} ] || exit {CONFLICT}\n\
		marker_access=$(stat -c '%u:%a' -- {marker}) || exit {CONFLICT}\n\
		[ \"$marker_access\" = \"$(id -u):600\" ] || exit {CONFLICT}\n\
		{{\n\
		  IFS= read -r recorded_owner_hash || exit {CONFLICT}\n\
		  IFS= read -r recorded_fingerprint || exit {CONFLICT}\n\
		  IFS= read -r recorded_content_hash || exit {CONFLICT}\n\
		  IFS= read -r recorded_tld || exit {CONFLICT}\n\
		  unexpected=\n\
		  if IFS= read -r unexpected || [ -n \"$unexpected\" ]; then exit {CONFLICT}; fi\n\
		}} < {marker}\n\
		owner_hash=$(printf '%s' \"$owner\" | sha256sum) || exit 1\n\
		owner_hash=${{owner_hash%% *}}\n\
		[ \"$owner_hash\" = \"$recorded_owner_hash\" ] || exit {CONFLICT}\n\
		[ \"$recorded_tld\" = {tld} ] || exit {CONFLICT}\n\
		if [ -e {dropin} ] || [ -L {dropin} ]; then\n\
		  [ -f {dropin} ] && [ ! -L {dropin} ] || exit {CONFLICT}\n\
		  fingerprint=$(stat -c '%d:%i:%u:%g:%a' -- {dropin}) || exit {CONFLICT}\n\
		  [ \"$fingerprint\" = \"$recorded_fingerprint\" ] || exit {CONFLICT}\n\
		  content_hash=$(sha256sum -- {dropin}) || exit {CONFLICT}\n\
		  content_hash=${{content_hash%% *}}\n\
		  [ \"$content_hash\" = \"$recorded_content_hash\" ] || exit {CONFLICT}\n\
		  rm -- {dropin} || exit 1\n\
		fi\n\
		{reload} || exit 1\n\
		rm -- {marker} || exit 1"
	)
}

fn conflict(path: &Path) -> io::Error {
	io::Error::new(
		io::ErrorKind::AlreadyExists,
		format!("resolver state or {} conflicts or has changed; testd left it untouched", path.display()),
	)
}

fn run_owned_script(
	script: &str,
	owner: &ownership::InstallationId,
	elevation: Elevation,
) -> io::Result<std::process::ExitStatus> {
	let mut command = silent_command(elevation.linux_authorizer());
	command.args(["sh", "-c", script]);
	run_with_stdin(command, format!("{}\n", owner.as_str()).as_bytes())
}

fn wait_for_compatible_resolver(
	tld: &str,
	addr: SocketAddr,
	mut probe: impl FnMut() -> io::Result<(String, String)>,
) -> io::Result<()> {
	for attempt in 0..5 {
		let (dns, domains) = probe().map_err(|error| {
			io::Error::other(format!("resolver route was installed but verification failed: {error}"))
		})?;
		let state = global_resolver_state(&dns, &domains).map_err(|error| {
			io::Error::other(format!("resolver route was installed but verification failed: {error}"))
		})?;
		if state.is_compatible(tld, addr) {
			return Ok(());
		}
		if attempt < 4 {
			std::thread::sleep(std::time::Duration::from_millis(100));
		}
	}
	Err(io::Error::other(
		"resolver route was installed but the global scope is not compatible; inspect it before retrying",
	))
}

pub(super) fn setup(tld: &str, addr: SocketAddr, elevation: Elevation) -> io::Result<()> {
	validate_tld(tld)?;
	let snapshot = match linux_resolver_preflight(tld, addr)? {
		LinuxResolverPreflight::Compatible => return Ok(()),
		LinuxResolverPreflight::Ready { snapshot } => snapshot,
	};
	let owner = ownership::InstallationId::load_or_create()?;
	let layout = system_layout();
	let dropin = Path::new(layout.dropin);
	let status = run_owned_script(&install_script(&layout, tld, addr, &snapshot), &owner, elevation)?;
	match status.code() {
		Some(0) => wait_for_compatible_resolver(tld, addr, linux_resolver_outputs),
		Some(CONFLICT) => Err(conflict(dropin)),
		Some(OWNERSHIP_UNRECORDED) => Err(io::Error::other(format!(
			"{} was created but ownership could not be recorded; inspect it before retrying",
			dropin.display()
		))),
		_ => Err(io::Error::other("resolver setup or systemd-resolved reload failed")),
	}
}

pub(super) fn teardown(tld: &str, elevation: Elevation) -> io::Result<()> {
	validate_tld(tld)?;
	let layout = system_layout();
	let dropin = Path::new(layout.dropin);
	let marker = owner_marker(&layout);
	let has_dropin = system_entry_present(dropin)?;
	let has_marker = system_entry_present(&marker)?;
	if !has_dropin && !has_marker {
		return Ok(());
	}
	if !has_marker {
		return Err(conflict(dropin));
	}
	let owner = ownership::InstallationId::load()?.ok_or_else(|| conflict(dropin))?;
	let status = run_owned_script(&remove_script(&layout, tld), &owner, elevation)?;
	match status.code() {
		Some(0) => Ok(()),
		Some(CONFLICT) => Err(conflict(dropin)),
		_ => Err(io::Error::other("resolver removal or systemd-resolved reload failed")),
	}
}

#[cfg(test)]
mod tests {
	use std::os::unix::fs::{PermissionsExt, symlink};
	use std::process::{Command, ExitStatus};

	use tempfile::TempDir;

	use super::*;

	const OWNER_A: &[u8] = b"installation-a\n";
	const OWNER_B: &[u8] = b"installation-b\n";
	const TLD: &str = "test";

	struct Fixture {
		root: TempDir,
		directory: PathBuf,
		dropin: PathBuf,
		dns: PathBuf,
		domains: PathBuf,
		configuration: PathBuf,
		log: PathBuf,
	}

	impl Fixture {
		fn new() -> Self {
			let root = tempfile::tempdir().unwrap();
			let directory = root.path().join("conf ' local");
			std::fs::create_dir(&directory).unwrap();
			let dropin = directory.join("90-testd.conf");
			let dns = root.path().join("dns");
			let domains = root.path().join("domains");
			let configuration = root.path().join("configuration");
			let log = root.path().join("reload.log");
			std::fs::write(&dns, "Global:\nLink 2 (eth0): 1.1.1.1\n").unwrap();
			std::fs::write(&domains, "Global:\nLink 2 (eth0): ~corp\n").unwrap();
			std::fs::write(&configuration, "# merged resolved.conf\n[Resolve]\n").unwrap();
			Self { root, directory, dropin, dns, domains, configuration, log }
		}

		fn layout(&self) -> ResolverLayout<'_> {
			ResolverLayout {
				directory: self.directory.to_str().unwrap(),
				dropin: self.dropin.to_str().unwrap(),
				reload: "printf '%s\\n' reloaded >> \"$TESTD_RESOLVER_LOG\"",
				dns_probe: "cat \"$TESTD_RESOLVER_DNS\"",
				domain_probe: "cat \"$TESTD_RESOLVER_DOMAINS\"",
				config_probe: "cat \"$TESTD_RESOLVER_CONFIG\"",
				active_probe: "true",
			}
		}

		fn snapshot(&self) -> String {
			snapshot_hash(
				&std::fs::read_to_string(&self.dns).unwrap(),
				&std::fs::read_to_string(&self.domains).unwrap(),
				&std::fs::read_to_string(&self.configuration).unwrap(),
			)
		}

		fn command(&self, script: &str) -> Command {
			let mut command = Command::new("sh");
			command
				.args(["-c", script])
				.env("TESTD_RESOLVER_DNS", &self.dns)
				.env("TESTD_RESOLVER_DOMAINS", &self.domains)
				.env("TESTD_RESOLVER_CONFIG", &self.configuration)
				.env("TESTD_RESOLVER_LOG", &self.log);
			command
		}

		fn install_script(&self, snapshot: &str) -> String {
			install_script(&self.layout(), TLD, "127.0.0.1:7753".parse().unwrap(), snapshot)
		}

		fn install(&self, owner: &[u8], snapshot: &str) -> ExitStatus {
			run_with_stdin(self.command(&self.install_script(snapshot)), owner).unwrap()
		}

		fn remove(&self, owner: &[u8], tld: &str) -> ExitStatus {
			run_with_stdin(self.command(&remove_script(&self.layout(), tld)), owner).unwrap()
		}

		fn marker(&self) -> PathBuf {
			owner_marker(&self.layout())
		}
	}

	#[test]
	fn installs_a_new_owned_route_and_removes_only_that_route() {
		let fixture = Fixture::new();
		let snapshot = fixture.snapshot();
		let script = fixture.install_script(&snapshot);
		assert!(!remove_script(&fixture.layout(), TLD).contains("resolvectl revert"));
		assert!(run_with_stdin(fixture.command(&script), OWNER_A).unwrap().success());
		assert_eq!(
			std::fs::read_to_string(&fixture.dropin).unwrap(),
			resolved_dropin(TLD, "127.0.0.1:7753".parse().unwrap())
		);
		assert_eq!(std::fs::metadata(&fixture.dropin).unwrap().permissions().mode() & 0o777, 0o644);
		let record = std::fs::read_to_string(fixture.marker()).unwrap();
		let lines: Vec<_> = record.lines().collect();
		assert_eq!(lines.len(), 4);
		assert_eq!(lines[0].len(), 64);
		assert_eq!(lines[3], TLD);
		assert!(!record.contains("installation-a"));
		assert_eq!(std::fs::metadata(fixture.marker()).unwrap().permissions().mode() & 0o777, 0o600);
		assert!(fixture.remove(OWNER_A, TLD).success());
		assert!(fixture.remove(OWNER_A, TLD).success());
		assert!(!fixture.dropin.exists());
		assert!(!fixture.marker().exists());
		assert_eq!(std::fs::read_to_string(&fixture.log).unwrap(), "reloaded\nreloaded\n");
		assert_eq!(std::fs::read_dir(&fixture.directory).unwrap().count(), 0);
	}

	#[test]
	fn preserves_preexisting_dropins_and_ownership_records() {
		for occupied in ["dropin", "marker", "symlink", "directory"] {
			let fixture = Fixture::new();
			let snapshot = fixture.snapshot();
			let target = fixture.root.path().join("missing.conf");
			match occupied {
				"dropin" => std::fs::write(&fixture.dropin, "foreign configuration").unwrap(),
				"marker" => std::fs::write(fixture.marker(), "foreign ownership").unwrap(),
				"symlink" => symlink(&target, &fixture.dropin).unwrap(),
				"directory" => std::fs::create_dir(&fixture.dropin).unwrap(),
				_ => unreachable!(),
			}
			let status = fixture.install(OWNER_A, &snapshot);
			assert_eq!(status.code(), Some(CONFLICT), "{occupied}");
			match occupied {
				"dropin" => assert_eq!(std::fs::read_to_string(&fixture.dropin).unwrap(), "foreign configuration"),
				"marker" => assert_eq!(std::fs::read_to_string(fixture.marker()).unwrap(), "foreign ownership"),
				"symlink" => {
					assert_eq!(std::fs::read_link(&fixture.dropin).unwrap(), target);
					assert!(!target.exists());
				},
				"directory" => assert_eq!(std::fs::read_dir(&fixture.dropin).unwrap().count(), 0),
				_ => unreachable!(),
			}
			assert!(!fixture.log.exists(), "{occupied}");
		}
	}

	#[test]
	fn refuses_runtime_or_configuration_changes_during_authorization() {
		for changed in ["dns", "domains", "configuration", "link"] {
			let fixture = Fixture::new();
			let snapshot = fixture.snapshot();
			match changed {
				"dns" => std::fs::write(&fixture.dns, "Global: 9.9.9.9\n").unwrap(),
				"domains" => std::fs::write(&fixture.domains, "Global: ~foreign\n").unwrap(),
				"configuration" => std::fs::write(&fixture.configuration, "[Resolve]\nDNS=9.9.9.9\n").unwrap(),
				"link" => std::fs::write(&fixture.dns, "Global:\nLink 2 (eth0): 8.8.8.8\n").unwrap(),
				_ => unreachable!(),
			}
			assert_eq!(fixture.install(OWNER_A, &snapshot).code(), Some(CONFLICT), "{changed}");
			assert!(!fixture.dropin.exists(), "{changed}");
			assert!(!fixture.marker().exists(), "{changed}");
			assert!(!fixture.log.exists(), "{changed}");
		}
	}

	#[test]
	fn refuses_a_dropin_or_marker_created_during_authorization() {
		for raced in ["dropin", "marker"] {
			let fixture = Fixture::new();
			let snapshot = fixture.snapshot();
			let target = if raced == "dropin" { fixture.dropin.clone() } else { fixture.marker() };
			let fake_link = fixture.root.path().join("fake-ln");
			std::fs::write(
				&fake_link,
				"#!/bin/sh\n\
				for argument do target=$argument; done\n\
				if [ \"$target\" = \"$TESTD_RACE_PATH\" ]; then\n\
				  printf '%s' foreign > \"$target\"; exit 1\n\
				fi\n\
				exec /usr/bin/ln \"$@\"\n",
			)
			.unwrap();
			std::fs::set_permissions(&fake_link, std::fs::Permissions::from_mode(0o700)).unwrap();
			let script = fixture
				.install_script(&snapshot)
				.replace("ln -T --", &format!("{} -T --", shell_quote(&fake_link.to_string_lossy())));
			let mut command = fixture.command(&script);
			command.env("TESTD_RACE_PATH", &target);
			let status = run_with_stdin(command, OWNER_A).unwrap();
			let expected = if raced == "dropin" { CONFLICT } else { OWNERSHIP_UNRECORDED };
			assert_eq!(status.code(), Some(expected), "{raced}");
			assert_eq!(std::fs::read_to_string(&target).unwrap(), "foreign", "{raced}");
			assert!(!fixture.log.exists(), "{raced}");
			if raced == "marker" {
				assert!(fixture.dropin.exists());
				assert_eq!(fixture.remove(OWNER_A, TLD).code(), Some(CONFLICT));
				assert_eq!(std::fs::read_to_string(target).unwrap(), "foreign");
				assert!(fixture.dropin.exists());
			} else {
				assert!(!fixture.marker().exists());
			}
		}
	}

	#[test]
	fn reports_inactive_resolver_and_failed_reload_without_claiming_success() {
		let inactive = Fixture::new();
		let mut layout = inactive.layout();
		layout.active_probe = "false";
		let script = install_script(&layout, TLD, "127.0.0.1:7753".parse().unwrap(), &inactive.snapshot());
		assert!(!run_with_stdin(inactive.command(&script), OWNER_A).unwrap().success());
		assert!(!inactive.dropin.exists());
		assert!(!inactive.marker().exists());

		let failed = Fixture::new();
		let mut layout = failed.layout();
		layout.reload = "sh -c 'exit 1'";
		let script = install_script(&layout, TLD, "127.0.0.1:7753".parse().unwrap(), &failed.snapshot());
		assert!(!run_with_stdin(failed.command(&script), OWNER_A).unwrap().success());
		assert!(failed.dropin.exists());
		assert!(failed.marker().exists());
	}

	#[test]
	fn verifies_the_live_scope_after_reload() {
		let addr: SocketAddr = "127.0.0.1:7753".parse().unwrap();
		let mut attempts = 0;
		wait_for_compatible_resolver(TLD, addr, || {
			attempts += 1;
			if attempts == 1 {
				Ok(("Global:".to_owned(), "Global:".to_owned()))
			} else {
				Ok(("Global: 127.0.0.1:7753".to_owned(), "Global: ~test".to_owned()))
			}
		})
		.unwrap();
		assert_eq!(attempts, 2);
		let error =
			wait_for_compatible_resolver(TLD, addr, || Ok(("Global: 1.1.1.1".to_owned(), "Global: ~corp".to_owned())))
				.unwrap_err();
		assert!(error.to_string().contains("not compatible"));
	}

	#[test]
	fn validates_the_resolver_domain_before_authorization() {
		assert!(validate_tld("testdcheck").is_ok());
		assert_eq!(validate_tld("test\nDNS=1.1.1.1").unwrap_err().kind(), io::ErrorKind::InvalidInput);
	}

	#[test]
	fn refuses_a_compatible_route_without_ownership() {
		let fixture = Fixture::new();
		let original = resolved_dropin(TLD, "127.0.0.1:7753".parse().unwrap());
		std::fs::write(&fixture.dropin, &original).unwrap();
		assert_eq!(fixture.remove(OWNER_A, TLD).code(), Some(CONFLICT));
		assert_eq!(std::fs::read_to_string(&fixture.dropin).unwrap(), original);
		assert!(!fixture.log.exists());
	}

	#[test]
	fn refuses_another_installation_or_domain() {
		let fixture = Fixture::new();
		assert!(fixture.install(OWNER_A, &fixture.snapshot()).success());
		let record = std::fs::read(fixture.marker()).unwrap();
		let content = std::fs::read(&fixture.dropin).unwrap();
		let before = std::fs::read_to_string(&fixture.log).unwrap();
		assert_eq!(fixture.remove(OWNER_B, TLD).code(), Some(CONFLICT));
		assert_eq!(fixture.remove(OWNER_A, "other").code(), Some(CONFLICT));
		assert_eq!(std::fs::read(&fixture.dropin).unwrap(), content);
		assert_eq!(std::fs::read(fixture.marker()).unwrap(), record);
		assert_eq!(std::fs::read_to_string(&fixture.log).unwrap(), before);
	}

	#[test]
	fn preserves_changed_owned_dropins() {
		for change in ["content", "replacement", "permissions", "symlink"] {
			let fixture = Fixture::new();
			assert!(fixture.install(OWNER_A, &fixture.snapshot()).success());
			let marker = std::fs::read(fixture.marker()).unwrap();
			let original = fixture.root.path().join("original.conf");
			match change {
				"content" => std::fs::write(&fixture.dropin, "changed configuration").unwrap(),
				"replacement" => {
					std::fs::rename(&fixture.dropin, &original).unwrap();
					std::fs::write(&fixture.dropin, std::fs::read(&original).unwrap()).unwrap();
				},
				"permissions" => {
					std::fs::set_permissions(&fixture.dropin, std::fs::Permissions::from_mode(0o600)).unwrap()
				},
				"symlink" => {
					std::fs::rename(&fixture.dropin, &original).unwrap();
					symlink(&original, &fixture.dropin).unwrap();
				},
				_ => unreachable!(),
			}
			let before = std::fs::read(&fixture.dropin).unwrap();
			let log = std::fs::read_to_string(&fixture.log).unwrap();
			assert_eq!(fixture.remove(OWNER_A, TLD).code(), Some(CONFLICT), "{change}");
			assert_eq!(std::fs::read(&fixture.dropin).unwrap(), before, "{change}");
			assert_eq!(std::fs::read(fixture.marker()).unwrap(), marker, "{change}");
			assert_eq!(std::fs::read_to_string(&fixture.log).unwrap(), log, "{change}");
		}
	}

	#[test]
	fn preserves_changed_ownership_records() {
		for change in ["contents", "permissions", "symlink"] {
			let fixture = Fixture::new();
			assert!(fixture.install(OWNER_A, &fixture.snapshot()).success());
			let marker = fixture.marker();
			match change {
				"contents" => std::fs::write(&marker, "another owner\nchanged\n").unwrap(),
				"permissions" => std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o644)).unwrap(),
				"symlink" => {
					let original = fixture.root.path().join("original.owner");
					std::fs::rename(&marker, &original).unwrap();
					symlink(original, &marker).unwrap();
				},
				_ => unreachable!(),
			}
			let before = std::fs::read(&marker).unwrap();
			let dropin = std::fs::read(&fixture.dropin).unwrap();
			let log = std::fs::read_to_string(&fixture.log).unwrap();
			assert_eq!(fixture.remove(OWNER_A, TLD).code(), Some(CONFLICT), "{change}");
			assert_eq!(std::fs::read(&marker).unwrap(), before, "{change}");
			assert_eq!(std::fs::read(&fixture.dropin).unwrap(), dropin, "{change}");
			assert_eq!(std::fs::read_to_string(&fixture.log).unwrap(), log, "{change}");
		}
	}

	#[test]
	fn retries_reload_after_an_interrupted_removal() {
		let fixture = Fixture::new();
		assert!(fixture.install(OWNER_A, &fixture.snapshot()).success());
		let mut layout = fixture.layout();
		layout.reload = "sh -c 'exit 1'";
		let status = run_with_stdin(fixture.command(&remove_script(&layout, TLD)), OWNER_A).unwrap();
		assert!(!status.success());
		assert!(!fixture.dropin.exists());
		assert!(fixture.marker().exists());
		assert!(fixture.remove(OWNER_A, TLD).success());
		assert!(!fixture.marker().exists());
		assert_eq!(std::fs::read_to_string(&fixture.log).unwrap(), "reloaded\nreloaded\n");
	}
}
