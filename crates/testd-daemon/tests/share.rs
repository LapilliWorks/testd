//! Provider shapes: what each one exposes, what it proxies, and how it reports
//! and withdraws its URL. The provider binaries are shell fakes.

#![cfg(unix)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex as AsyncMutex;

use testd_daemon::registry::Registry;
use testd_daemon::share::{Exposure, Front, Provider, Shares};

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
	use std::os::unix::fs::PermissionsExt;

	let path = dir.join(name);
	std::fs::write(&path, body).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
	path
}

fn front() -> Front {
	Front {
		registry: Arc::new(AsyncMutex::new(Registry::default())),
		plain_addr: "127.0.0.1:7740".parse::<SocketAddr>().unwrap(),
	}
}

#[tokio::test]
async fn a_cloudflared_share_reports_its_url_and_is_killed_on_stop() {
	let dir = tempfile::tempdir().unwrap();
	let provider = script(
		dir.path(),
		"cloudflared",
		"#!/bin/sh\necho 'INF |  https://brave-otter.trycloudflare.com  |' >&2\nexec sleep 30\n",
	);
	let shares = Shares::new(Provider::Cloudflared, Some(provider), None);

	let url = shares.start("app.example", "127.0.0.1:3000", None).await.unwrap();
	assert_eq!(url, "https://brave-otter.trycloudflare.com");

	let listed = shares.list().await;
	assert_eq!(listed.len(), 1);
	assert_eq!(listed[0].provider, "cloudflared");
	assert_eq!(listed[0].exposure, Exposure::Public);
	assert_eq!(listed[0].target, "127.0.0.1:3000");

	assert!(shares.stop("app.example").await);
	assert!(shares.list().await.is_empty());
}

#[tokio::test]
async fn a_provider_that_exits_before_its_url_is_read_does_not_start_a_share() {
	let dir = tempfile::tempdir().unwrap();
	let provider = script(
		dir.path(),
		"cloudflared",
		"#!/bin/sh\n( sleep 0.2; echo 'INF https://fixture.trycloudflare.com' >&2 ) &\nexit 23\n",
	);
	let shares = Shares::new(Provider::Cloudflared, Some(provider), None);
	let error = tokio::time::timeout(std::time::Duration::from_secs(5), shares.start("app", "127.0.0.1:3000", None))
		.await
		.expect("provider startup timed out")
		.unwrap_err();
	assert!(error.to_string().contains("exited during startup"), "{error}");
	assert!(shares.list().await.is_empty());
}

fn provider_waiting_to_exit(dir: &Path) -> (PathBuf, PathBuf) {
	let exit = dir.join("exit-provider");
	let body = format!(
		"#!/bin/sh\necho 'INF https://fixture.trycloudflare.com' >&2\n\
		 echo 'INF https://fixture.ngrok-free.app' >&2\n\
		 case \"$*\" in *:3000*|*:3002*) while [ ! -f '{}' ]; do sleep 0.05; done; exit 23 ;; \
		 *) exec sleep 30 ;; esac\n",
		exit.display()
	);
	(script(dir, "tunnel", &body), exit)
}

#[tokio::test]
async fn a_provider_exit_removes_only_its_share_and_notifies_observers() {
	let dir = tempfile::tempdir().unwrap();
	let (provider, exit) = provider_waiting_to_exit(dir.path());
	let shares = Shares::new(Provider::Cloudflared, Some(provider), None);
	shares.start("first.example", "127.0.0.1:3000", None).await.unwrap();
	shares.start("second.example", "127.0.0.1:3001", None).await.unwrap();
	shares
		.start("third.example", "127.0.0.1:3002", Some(Provider::Ngrok))
		.await
		.unwrap();
	let mut changes = shares.state_changes();

	std::fs::write(&exit, "exit").unwrap();
	tokio::time::timeout(std::time::Duration::from_secs(5), async {
		loop {
			changes.changed().await.unwrap();
			let active = shares.list().await;
			if active.len() == 1 {
				assert_eq!(active[0].name, "second.example");
				break;
			}
		}
	})
	.await
	.expect("provider exit should update the share list");
	assert!(shares.stop("second.example").await);
}

#[tokio::test]
async fn stopping_an_exiting_provider_does_not_remove_a_replacement_share() {
	let dir = tempfile::tempdir().unwrap();
	let (provider, exit) = provider_waiting_to_exit(dir.path());
	let shares = Arc::new(Shares::new(Provider::Cloudflared, Some(provider), None));
	shares.start("app.example", "127.0.0.1:3000", None).await.unwrap();

	let stopping = {
		let shares = Arc::clone(&shares);
		tokio::spawn(async move { shares.stop("app.example").await })
	};
	std::fs::write(&exit, "exit").unwrap();
	tokio::time::timeout(std::time::Duration::from_secs(5), stopping)
		.await
		.expect("stop did not finish")
		.unwrap();
	shares.start("app.example", "127.0.0.1:3001", None).await.unwrap();
	tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	let active = shares.list().await;
	assert_eq!(active.len(), 1);
	assert_eq!(active[0].target, "127.0.0.1:3001");
	assert!(shares.stop("app.example").await);
}

#[tokio::test]
async fn an_ngrok_share_reports_its_url_from_a_log_record() {
	let dir = tempfile::tempdir().unwrap();
	let provider = script(
		dir.path(),
		"ngrok",
		"#!/bin/sh\necho 'msg=\"started tunnel\" url=https://1a2b-3c4d.ngrok-free.app' >&2\nexec sleep 30\n",
	);
	let shares = Shares::new(Provider::Ngrok, Some(provider), None);

	let url = shares.start("app.example", "127.0.0.1:3000", None).await.unwrap();
	assert_eq!(url, "https://1a2b-3c4d.ngrok-free.app");
	assert_eq!(shares.list().await[0].exposure, Exposure::Public);
	shares.stop("app.example").await;
}

/// A fake `tailscale`: records the serve target, answers status, and marks the
/// scoped stop. `serve status --json` reports one entry of ours and one foreign.
fn tailscale(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
	let args = dir.join("serve-args");
	let stopped = dir.join("serve-off");
	let body = r#"#!/bin/sh
if [ "$1" = "serve" ] && [ "$2" = "status" ]; then
	echo '{"Web":{"node-a.tailnet.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"}}},"node-a.tailnet.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"}}}}}'
	exit 0
fi
case "$1" in
	serve)
		echo "$@" >> 'ARGS'
		if [ "$3" = "off" ]; then touch 'STOPPED'; fi
		exit 0 ;;
	status)
		echo '{"Self":{"DNSName":"node-a.tailnet.ts.net."}}'
		exit 0 ;;
esac
exit 1
"#
	.replace("ARGS", &args.display().to_string())
	.replace("STOPPED", &stopped.display().to_string());
	(script(dir, "tailscale", &body), args, stopped)
}

#[tokio::test]
async fn a_tailscale_share_proxies_the_edge_and_teaches_it_the_tailnet_name() {
	let dir = tempfile::tempdir().unwrap();
	let (provider, args_file, stopped) = tailscale(dir.path());
	let front = front();
	let registry = Arc::clone(&front.registry);
	let shares = Shares::new(Provider::Tailscale, Some(provider), Some(front));

	// A LAN target: the whole point of going through the edge.
	let url = shares.start("app.example", "192.168.1.9:3000", None).await.unwrap();
	assert_eq!(url, "https://node-a.tailnet.ts.net");
	assert_eq!(shares.list().await[0].exposure, Exposure::Tailnet);

	let args = std::fs::read_to_string(&args_file).unwrap();
	assert!(args.contains("http://127.0.0.1:7740"), "serve targets the edge: {args}");
	assert!(!args.contains("192.168.1.9"), "serve never talks to the target directly: {args}");

	let alias = registry
		.lock()
		.await
		.get("node-a.tailnet.ts.net")
		.expect("the edge answers the tailnet name");
	assert_eq!(alias.target, "192.168.1.9:3000");

	assert!(shares.stop("app.example").await);
	assert!(stopped.exists(), "stopping runs `serve --https=443 off`");
	assert!(registry.lock().await.get("node-a.tailnet.ts.net").is_none(), "the alias goes with the share");
	assert!(shares.list().await.is_empty());
}

#[tokio::test]
async fn a_restart_clears_the_serve_entry_it_left_behind() {
	let dir = tempfile::tempdir().unwrap();
	let (provider, args_file, stopped) = tailscale(dir.path());
	let shares = Shares::new(Provider::Tailscale, Some(provider), Some(front()));

	shares.reclaim().await;

	let args = std::fs::read_to_string(&args_file).unwrap();
	assert!(args.contains("--https=443 off"), "the entry pointing at our edge is cleared: {args}");
	assert!(!args.contains("--https=8443"), "another serve entry is left alone: {args}");
	assert!(stopped.exists());
}

#[tokio::test]
async fn a_sweep_leaves_a_live_share_alone() {
	let dir = tempfile::tempdir().unwrap();
	let (provider, _, stopped) = tailscale(dir.path());
	let shares = Shares::new(Provider::Tailscale, Some(provider), Some(front()));
	shares.start("app.example", "127.0.0.1:3000", None).await.unwrap();

	shares.reclaim().await;
	assert!(!stopped.exists(), "a live share's serve entry is not a leftover");

	shares.stop("app.example").await;
}

#[tokio::test]
async fn a_tailscale_share_without_the_plain_listener_is_refused() {
	let dir = tempfile::tempdir().unwrap();
	let (provider, _, _) = tailscale(dir.path());
	let shares = Shares::new(Provider::Tailscale, Some(provider), None);

	let error = shares
		.start("app.example", "192.168.1.9:3000", None)
		.await
		.unwrap_err()
		.to_string();
	assert!(error.contains("plain HTTP routing listener"), "{error}");
}

#[tokio::test]
async fn a_missing_provider_binary_is_reported() {
	let shares = Shares::new(Provider::Ngrok, Some(PathBuf::from("/nonexistent/ngrok")), None);
	let error = shares
		.start("app.example", "127.0.0.1:3000", None)
		.await
		.unwrap_err()
		.to_string();
	assert!(error.contains("/nonexistent/ngrok"), "{error}");
	assert!(error.contains("TESTD_TUNNEL"), "the message names the override: {error}");
}

#[tokio::test]
async fn a_name_that_leaves_the_registrations_loses_its_share() {
	let dir = tempfile::tempdir().unwrap();
	let provider = script(
		dir.path(),
		"cloudflared",
		"#!/bin/sh\necho 'INF https://kept-name.trycloudflare.com' >&2\nexec sleep 30\n",
	);
	let shares = Shares::new(Provider::Cloudflared, Some(provider), None);
	shares.start("app.example", "127.0.0.1:3000", None).await.unwrap();

	shares.retain(&["other.example".to_owned()]).await;
	assert!(shares.list().await.is_empty(), "a stale name closes its share");
}

#[tokio::test]
async fn an_explicit_provider_overrides_the_daemon_default() {
	let dir = tempfile::tempdir().unwrap();
	let provider =
		script(dir.path(), "tunnel", "#!/bin/sh\necho 'INF https://1a2b.ngrok-free.app' >&2\nexec sleep 30\n");
	let shares = Shares::new(Provider::Cloudflared, Some(provider), None);

	let url = shares
		.start("app.example", "127.0.0.1:3000", Some(Provider::Ngrok))
		.await
		.unwrap();
	assert_eq!(url, "https://1a2b.ngrok-free.app");
	assert_eq!(shares.list().await[0].provider, "ngrok");
	shares.stop("app.example").await;
}
