//! Headless host mode: runs the daemon without a GUI.

use anyhow::{Result, anyhow};

use testd_daemon::daemon::Daemon;

pub async fn run() -> Result<()> {
	let daemon = Daemon::new().await.map_err(|e| anyhow!("{e}"))?;

	// Run engine until interrupted.
	tokio::select! {
		result = daemon.run() => result?,
		_ = tokio::signal::ctrl_c() => {
			eprintln!("\n[stop]   shutting down");
		}
	}

	daemon.shutdown().await;

	// Daemon::drop clears registrations and the managed Caddyfile; the OS
	// resolver setup is one-time and intentionally left in place.
	drop(daemon);
	Ok(())
}
