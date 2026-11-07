//! Public and tailnet sharing: one tunnel per registered name, owned by the daemon.
//!
//! The tunnel has to outlive the terminal that asked for it, so the daemon
//! starts and stops the provider. A tunnel is bound to the owning connection
//! and target; a changed or removed claim cancels pending starts and stops it.
//!
//! Providers are spawned, never linked and never called through an SDK. They
//! differ in what they expose (public internet or tailnet), what target they
//! accept, and how their public URL becomes known, so each one owns those three
//! answers:
//!
//! | Provider | Exposure | Target | URL |
//! |---|---|---|---|
//! | `cloudflared` | public | any reachable target | printed by the provider |
//! | `ngrok` | public | any reachable target | printed by the provider |
//! | `tailscale` | tailnet | loopback only | `tailscale status --json` |

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc, watch};

use crate::engine::Registrations;
use crate::registry::{Claim, Registry};

/// Provider used when the caller does not choose one.
pub const DEFAULT_PROVIDER: &str = "cloudflared";
/// How long a provider may take to report its public URL.
const URL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the startup sweep waits for `tailscale serve status`.
const SWEEP_TIMEOUT: Duration = Duration::from_secs(5);
/// Detect a spawned provider's exit without holding the share lock while waiting.
const PROVIDER_EXIT_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// Bound waits for provider termination and pending-start cleanup.
const PROVIDER_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const SHARE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Where a share is reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
	/// Anyone with the URL, like `cloudflared` and `ngrok`.
	Public,
	/// Devices on the tailnet only, like `tailscale serve`.
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

	/// Binary invoked for this provider.
	pub fn binary(self) -> &'static str {
		self.name()
	}

	/// Whether the provider must be pointed at the local edge instead of at the
	/// registration target.
	pub fn needs_front(self) -> bool {
		matches!(self, Provider::Tailscale)
	}

	/// Arguments that start the share, given the address it proxies to.
	fn start_args(self, upstream: &str) -> Vec<String> {
		match self {
			Provider::Cloudflared => {
				vec!["tunnel".into(), "--no-autoupdate".into(), "--url".into(), format!("http://{upstream}")]
			},
			// `ngrok http` takes a host:port, not a URL.
			Provider::Ngrok => vec!["http".into(), upstream.to_owned()],
			// `serve` writes config and returns; there is no long-running child.
			Provider::Tailscale => vec!["serve".into(), "--bg".into(), format!("http://{upstream}")],
		}
	}

	/// Arguments that remove the share again. `None` means killing the child.
	fn stop_args(self) -> Option<Vec<String>> {
		match self {
			Provider::Cloudflared | Provider::Ngrok => None,
			// Scoped to this serve port, so other serve entries are left alone.
			Provider::Tailscale => Some(vec!["serve".into(), "--https=443".into(), "off".into()]),
		}
	}

	/// The public URL in a provider log line.
	fn url_from_line(self, line: &str) -> Option<String> {
		// Stop at whitespace, a quote, a pipe, or the first path segment; providers
		// print URLs inside tables, banners, and JSON log records.
		let rest = &line[line.find("https://")? + "https://".len()..];
		let host = rest
			.split(|c: char| c.is_whitespace() || c == '|' || c == '/' || c == '"' || c == '\\')
			.next()?;
		let known = match self {
			Provider::Cloudflared => host.ends_with(".trycloudflare.com") && host != "api.trycloudflare.com",
			Provider::Ngrok => {
				host.ends_with(".ngrok-free.app")
					|| host.ends_with(".ngrok-free.dev")
					|| host.ends_with(".ngrok.io")
					|| host.ends_with(".ngrok.app")
			},
			Provider::Tailscale => host.ends_with(".ts.net"),
		};
		known.then(|| format!("https://{host}"))
	}
}

/// One active share, as the CLI and the tray see it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareView {
	pub name: String,
	pub provider: String,
	pub exposure: Exposure,
	pub target: String,
	pub url: String,
}

/// The local edge a provider can point at instead of the raw target.
///
/// Pointing a provider here keeps the request shape browsers get: the edge
/// answers the share's name and proxies to the registration target, so a
/// container or LAN target works and the app sees its registered name.
#[derive(Clone)]
pub struct Front {
	/// Plain HTTP listener of the edge.
	pub plain_addr: SocketAddr,
}

/// The daemon's set of tunnels.
#[derive(Clone)]
pub struct Shares {
	default: Provider,
	/// Overrides the binary for the selected provider; tests and odd installs.
	binary: Option<PathBuf>,
	/// The local edge, for providers that cannot reach the target themselves.
	front: Option<Front>,
	registrations: Registrations,
	state: Arc<Mutex<ShareState>>,
	/// Serializes the startup sweep against a tailscale share starting.
	reclaim: Arc<Mutex<()>>,
	/// Any change to the active set, for live frontends.
	revision: watch::Sender<u64>,
}

#[derive(Default)]
struct ShareState {
	active: BTreeMap<String, Active>,
	pending: BTreeMap<String, Pending>,
	claim_changes: BTreeMap<String, Vec<Arc<()>>>,
	is_shutting_down: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClaimBinding {
	domain: String,
	connection: u64,
	target: String,
}

impl ClaimBinding {
	fn from_claim(claim: &Claim) -> Self {
		Self {
			domain: claim.registration.domain.clone(),
			connection: claim.connection,
			target: claim.registration.target.clone(),
		}
	}
}

#[derive(Clone)]
enum PendingResult {
	Running,
	Cleaned,
	Unverified(String),
}

struct Pending {
	identity: Arc<()>,
	binding: ClaimBinding,
	provider: Provider,
	cancel: watch::Sender<bool>,
	finished: watch::Sender<PendingResult>,
}

#[derive(Default)]
struct StopBatch {
	active: Vec<(String, Active)>,
	waiting: Vec<watch::Receiver<PendingResult>>,
	errors: Vec<String>,
}

#[derive(Default)]
pub(crate) struct DetachedShares {
	task: Option<tokio::task::JoinHandle<Result<()>>>,
}

pub(crate) struct ClaimTransition<'a> {
	shares: &'a Shares,
	state: tokio::sync::MutexGuard<'a, ShareState>,
}

#[derive(Clone)]
pub(crate) struct ClaimChange {
	inner: Arc<ClaimChangeInner>,
}

struct ClaimChangeInner {
	shares: Shares,
	domain: String,
	identity: Arc<()>,
	finished: AtomicBool,
}

impl ClaimChange {
	pub(crate) async fn finish(self) -> Result<()> {
		let result = self
			.inner
			.shares
			.end_claim_change(&self.inner.domain, &self.inner.identity)
			.await;
		self.inner.finished.store(true, Ordering::SeqCst);
		result
	}
}

impl Drop for ClaimChangeInner {
	fn drop(&mut self) {
		if self.finished.load(Ordering::SeqCst) {
			return;
		}
		let shares = self.shares.clone();
		let domain = self.domain.clone();
		let identity = Arc::clone(&self.identity);
		if let Ok(runtime) = tokio::runtime::Handle::try_current() {
			runtime.spawn(async move {
				if let Err(error) = shares.end_claim_change(&domain, &identity).await {
					eprintln!("[error]  could not reconcile an interrupted claim change: {error:#}");
				}
			});
		} else {
			eprintln!("[error]  interrupted claim change for {domain} could not be reconciled");
		}
	}
}

impl ClaimTransition<'_> {
	pub(crate) fn begin_change(&mut self, registry: &mut Registry, domain: &str) -> (ClaimChange, DetachedShares) {
		let identity = Arc::new(());
		self.state
			.claim_changes
			.entry(domain.to_owned())
			.or_default()
			.push(Arc::clone(&identity));
		let names: Vec<String> = self
			.state
			.pending
			.iter()
			.filter(|(_, pending)| pending.binding.domain == domain)
			.map(|(name, _)| name.clone())
			.collect();
		let mut batch = StopBatch::default();
		for name in names {
			Shares::detach_name(&mut self.state, registry, &name, &mut batch);
		}
		let change = ClaimChange {
			inner: Arc::new(ClaimChangeInner {
				shares: self.shares.clone(),
				domain: domain.to_owned(),
				identity,
				finished: AtomicBool::new(false),
			}),
		};
		(change, self.shares.queue_cleanup(batch))
	}

	pub(crate) fn detach_claims(&mut self, registry: &mut Registry, claims: &[Claim]) -> DetachedShares {
		let bindings: Vec<ClaimBinding> = claims.iter().map(ClaimBinding::from_claim).collect();
		self.detach_matching(registry, |binding| bindings.contains(binding))
	}

	pub(crate) fn detach_connections(&mut self, registry: &mut Registry, connections: &[u64]) -> DetachedShares {
		self.detach_matching(registry, |binding| connections.contains(&binding.connection))
	}

	pub(crate) fn detach_domain(&mut self, registry: &mut Registry, domain: &str) -> DetachedShares {
		self.detach_matching(registry, |binding| binding.domain == domain)
	}

	pub(crate) fn detach_unapplied(&mut self, registry: &mut Registry, claims: &[Claim]) -> DetachedShares {
		let bindings: Vec<ClaimBinding> = claims.iter().map(ClaimBinding::from_claim).collect();
		self.detach_matching(registry, |binding| !bindings.contains(binding))
	}

	fn detach_matching(&mut self, registry: &mut Registry, matches: impl Fn(&ClaimBinding) -> bool) -> DetachedShares {
		let names: Vec<String> = self
			.state
			.active
			.iter()
			.filter(|(_, share)| matches(&share.binding))
			.map(|(name, _)| name.clone())
			.chain(
				self.state
					.pending
					.iter()
					.filter(|(_, pending)| matches(&pending.binding))
					.map(|(name, _)| name.clone()),
			)
			.collect();
		let mut batch = StopBatch::default();
		for name in names {
			Shares::detach_name(&mut self.state, registry, &name, &mut batch);
		}
		self.shares.queue_cleanup(batch)
	}
}

#[derive(Debug)]
struct CleanupUnverified(String);

impl std::fmt::Display for CleanupUnverified {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(&self.0)
	}
}

impl std::error::Error for CleanupUnverified {}

enum PublishFailure {
	ClaimChanged,
	AliasConflict,
}

struct ShareStart {
	name: String,
	provider: Provider,
	owner: ClaimBinding,
	identity: Arc<()>,
	cancellation: watch::Receiver<bool>,
}

struct Active {
	/// Distinguishes a stopped share from a replacement with the same name.
	identity: Arc<()>,
	binding: ClaimBinding,
	provider: Provider,
	url: String,
	/// Present for providers that stay running.
	child: Option<Child>,
	/// Cleanup command for providers that configure and return.
	stop_args: Option<Vec<String>>,
	/// Name the edge answers on the provider's behalf.
	alias: Option<String>,
}

impl Shares {
	/// Default provider from `TESTD_TUNNEL_PROVIDER`, binary from `TESTD_TUNNEL`.
	pub fn from_env(front: Option<Front>, registrations: Registrations) -> Self {
		let default = std::env::var("TESTD_TUNNEL_PROVIDER")
			.ok()
			.and_then(|value| Provider::parse(&value))
			.unwrap_or(Provider::Cloudflared);
		let binary = std::env::var_os("TESTD_TUNNEL")
			.filter(|value| !value.is_empty())
			.map(PathBuf::from);
		Self::new(default, binary, front, registrations)
	}

	pub fn new(default: Provider, binary: Option<PathBuf>, front: Option<Front>, registrations: Registrations) -> Self {
		Self {
			default,
			binary,
			front,
			registrations,
			state: Arc::new(Mutex::new(ShareState::default())),
			reclaim: Arc::new(Mutex::new(())),
			revision: watch::channel(0).0,
		}
	}

	pub(crate) fn registrations(&self) -> &Registrations {
		&self.registrations
	}

	/// Any change to the active set, for live frontends.
	pub fn state_changes(&self) -> watch::Receiver<u64> {
		self.revision.subscribe()
	}

	fn bump(&self) {
		self.revision.send_modify(|revision| *revision = revision.wrapping_add(1));
	}

	/// Start a share bound to the current registered connection and target.
	pub async fn start(&self, name: &str, domain: &str, provider: Option<Provider>) -> Result<String> {
		if name.is_empty()
			|| !domain
				.strip_prefix(name)
				.is_some_and(|suffix| suffix.starts_with('.') && suffix.len() > 1)
		{
			bail!("share name does not match its registered domain");
		}
		let provider = self.checked_provider(provider)?;
		let registry = self.registrations.lock().await;
		let claim = registry
			.claim(domain)
			.ok_or_else(|| anyhow!("{name} is not registered on this host"))?;
		let binding = ClaimBinding::from_claim(claim);
		let (identity, cancellation) = self.reserve(name, provider, binding.clone()).await?;
		drop(registry);
		self.run_start(ShareStart { name: name.to_owned(), provider, owner: binding, identity, cancellation })
			.await
	}

	fn checked_provider(&self, provider: Option<Provider>) -> Result<Provider> {
		let provider = provider.unwrap_or(self.default);
		if provider.needs_front() && self.front.is_none() {
			bail!(
				"{} needs the plain HTTP routing listener, and this daemon has none; \
				 share with cloudflared or ngrok instead",
				provider.name()
			);
		}
		Ok(provider)
	}

	async fn reserve(
		&self,
		name: &str,
		provider: Provider,
		binding: ClaimBinding,
	) -> Result<(Arc<()>, watch::Receiver<bool>)> {
		let mut state = self.state.lock().await;
		if state.is_shutting_down {
			bail!("the share manager is shutting down");
		}
		if state.claim_changes.contains_key(&binding.domain) {
			bail!("{} is being registered; wait for its result before sharing", binding.domain);
		}
		if let Some(existing) = state.active.get(name) {
			bail!("{name} is already shared at {} ({})", existing.url, existing.provider.name());
		}
		if state.pending.contains_key(name) {
			bail!("{name} is already starting or stopping a share");
		}
		if state.active.values().any(|share| share.binding.domain == binding.domain)
			|| state.pending.values().any(|share| share.binding.domain == binding.domain)
		{
			bail!("{} already has a share starting, running, or stopping", binding.domain);
		}
		if provider == Provider::Tailscale
			&& (state.active.values().any(|share| share.provider == provider)
				|| state.pending.values().any(|share| share.provider == provider))
		{
			bail!("tailscale serve is already owned by another share");
		}
		let identity = Arc::new(());
		let (cancel, cancellation) = watch::channel(false);
		let (finished, _) = watch::channel(PendingResult::Running);
		state
			.pending
			.insert(name.to_owned(), Pending { identity: Arc::clone(&identity), binding, provider, cancel, finished });
		Ok((identity, cancellation))
	}

	async fn run_start(&self, start: ShareStart) -> Result<String> {
		let name = start.name.clone();
		let identity = Arc::clone(&start.identity);
		let shares = self.clone();
		match tokio::spawn(async move {
			let result = shares.finish_start(start).await;
			if let Err(error) = &result {
				eprintln!("[share]  start did not complete: {error:#}");
			}
			result
		})
		.await
		{
			Ok(result) => result,
			Err(error) => {
				self.abandon_pending(&name, &identity, &error.to_string()).await;
				Err(error).context("share start task failed; provider cleanup is unverified")
			},
		}
	}

	async fn finish_start(&self, start: ShareStart) -> Result<String> {
		let binary = self.binary_for(start.provider);
		let mut cancellation = start.cancellation.clone();
		let spawned = self.spawn(&start, &binary, &mut cancellation).await;
		let mut share = match spawned {
			Ok(share) => share,
			Err(error) => {
				if error.is::<CleanupUnverified>() {
					self.abandon_pending(&start.name, &start.identity, &error.to_string()).await;
				} else {
					self.finish_pending(&start.name, &start.identity).await;
				}
				return Err(error);
			},
		};
		let startup = match share.child.as_mut() {
			Some(child) => child.try_wait().context("check the provider after startup"),
			None => Ok(None),
		};
		match startup {
			Ok(Some(status)) => {
				self.finish_pending(&start.name, &start.identity).await;
				bail!("{} exited during startup with {status}", start.provider.name());
			},
			Err(error) => {
				self.finish_release(&start.name, share).await?;
				return Err(error);
			},
			Ok(None) => {},
		}

		let binding = &start.owner;
		let mut registry = self.registrations.lock().await;
		let valid = registry
			.claim(&binding.domain)
			.is_some_and(|claim| ClaimBinding::from_claim(claim) == *binding);
		let mut share = Some(share);
		let published = self
			.publish(&start.name, &start.identity, &mut share, &mut registry, valid)
			.await;
		drop(registry);
		match published {
			Ok(url) => Ok(url),
			Err(PublishFailure::ClaimChanged) => {
				self.finish_release(&start.name, share.expect("unpublished share")).await?;
				bail!("the claim or pending share for {} changed during startup", start.name);
			},
			Err(PublishFailure::AliasConflict) => {
				let error = "the provider alias changed during startup; inspect the provider state";
				self.abandon_pending(&start.name, &start.identity, error).await;
				Err(CleanupUnverified(error.to_owned()).into())
			},
		}
	}

	async fn publish(
		&self,
		name: &str,
		identity: &Arc<()>,
		share: &mut Option<Active>,
		registry: &mut Registry,
		valid: bool,
	) -> std::result::Result<String, PublishFailure> {
		let mut state = self.state.lock().await;
		let may_publish = state
			.pending
			.get(name)
			.is_some_and(|pending| Arc::ptr_eq(&pending.identity, identity) && !*pending.cancel.borrow());
		if !valid || !may_publish || state.is_shutting_down || state.active.contains_key(name) {
			return Err(PublishFailure::ClaimChanged);
		}
		let candidate = share.as_ref().expect("share can only be published once");
		if let Some(alias) = &candidate.alias {
			if registry.contains(alias) {
				return Err(PublishFailure::AliasConflict);
			}
			registry.set_alias(alias, &candidate.binding.target);
		}
		let pending = state.pending.remove(name).expect("checked above");
		let share = share.take().expect("share can only be published once");
		let url = share.url.clone();
		let child_identity = share.child.as_ref().map(|_| Arc::clone(&share.identity));
		state.active.insert(name.to_owned(), share);
		pending.finished.send_replace(PendingResult::Cleaned);
		drop(state);
		self.bump();
		if let Some(identity) = child_identity {
			self.watch_provider(name.to_owned(), identity);
		}
		Ok(url)
	}

	async fn finish_pending(&self, name: &str, identity: &Arc<()>) {
		let mut state = self.state.lock().await;
		if state
			.pending
			.get(name)
			.is_some_and(|pending| Arc::ptr_eq(&pending.identity, identity))
		{
			let pending = state.pending.remove(name).expect("checked above");
			pending.finished.send_replace(PendingResult::Cleaned);
		}
	}

	async fn abandon_pending(&self, name: &str, identity: &Arc<()>, error: &str) {
		let state = self.state.lock().await;
		if let Some(pending) = state.pending.get(name)
			&& Arc::ptr_eq(&pending.identity, identity)
		{
			pending.cancel.send_replace(true);
			pending.finished.send_replace(PendingResult::Unverified(error.to_owned()));
		}
	}

	async fn finish_release(&self, name: &str, share: Active) -> Result<()> {
		let identity = Arc::clone(&share.identity);
		match self.release(share).await {
			Ok(()) => {
				self.finish_pending(name, &identity).await;
				Ok(())
			},
			Err(error) => {
				self.abandon_pending(name, &identity, &error.to_string()).await;
				Err(CleanupUnverified(format!("could not stop share {name}: {error:#}")).into())
			},
		}
	}

	/// Remove an exited child without confusing it with a replacement share.
	fn watch_provider(&self, name: String, identity: Arc<()>) {
		let state = Arc::downgrade(&self.state);
		let revision = self.revision.clone();
		tokio::spawn(async move {
			let mut reported_failure = false;
			loop {
				tokio::time::sleep(PROVIDER_EXIT_CHECK_INTERVAL).await;
				let Some(state) = state.upgrade() else { return };
				let mut shares = state.lock().await;
				let Some(share) = shares.active.get_mut(&name) else { return };
				if !Arc::ptr_eq(&share.identity, &identity) {
					return;
				}
				let Some(child) = share.child.as_mut() else { return };
				match child.try_wait() {
					Ok(None) => reported_failure = false,
					Ok(Some(status)) => {
						let provider = share.provider.name();
						shares.active.remove(&name);
						drop(shares);
						eprintln!("[share]  {name} closed: {provider} exited with {status}");
						revision.send_modify(|value| *value = value.wrapping_add(1));
						return;
					},
					Err(error) => {
						if !reported_failure {
							eprintln!("[warn]   could not check the provider for {name}: {error}");
							reported_failure = true;
						}
					},
				}
			}
		});
	}

	/// Stop a live or pending share and report provider cleanup failures.
	pub async fn stop(&self, name: &str) -> Result<bool> {
		let mut registry = self.registrations.lock().await;
		let mut state = self.state.lock().await;
		let mut batch = StopBatch::default();
		Self::detach_name(&mut state, &mut registry, name, &mut batch);
		drop(state);
		drop(registry);
		let found = !batch.active.is_empty() || !batch.waiting.is_empty() || !batch.errors.is_empty();
		let detached = self.queue_cleanup(batch);
		self.finish_detached(detached).await?;
		Ok(found)
	}

	pub async fn list(&self) -> Vec<ShareView> {
		self.state
			.lock()
			.await
			.active
			.iter()
			.map(|(name, share)| ShareView {
				name: name.clone(),
				provider: share.provider.name().to_owned(),
				exposure: share.provider.exposure(),
				target: share.binding.target.clone(),
				url: share.url.clone(),
			})
			.collect()
	}

	fn detach_name(state: &mut ShareState, registry: &mut Registry, name: &str, detached: &mut StopBatch) {
		if let Some(share) = state.active.remove(name) {
			let (cancel, _) = watch::channel(true);
			let (finished, _) = watch::channel(PendingResult::Running);
			let alias_error = share.alias.as_ref().and_then(|alias| {
				if registry
					.aliases()
					.iter()
					.any(|entry| entry.domain == *alias && entry.target == share.binding.target)
				{
					registry.remove_alias(alias);
					None
				} else {
					Some(format!("provider alias {alias} changed; leaving provider state untouched"))
				}
			});
			if let Some(error) = &alias_error {
				finished.send_replace(PendingResult::Unverified(error.clone()));
				detached.errors.push(error.clone());
			}
			state.pending.insert(
				name.to_owned(),
				Pending {
					identity: Arc::clone(&share.identity),
					binding: share.binding.clone(),
					provider: share.provider,
					cancel,
					finished,
				},
			);
			if alias_error.is_none() {
				detached.active.push((name.to_owned(), share));
			}
		} else if let Some(pending) = state.pending.get(name) {
			pending.cancel.send_replace(true);
			detached.waiting.push(pending.finished.subscribe());
		}
	}

	/// Acquire after the registry lock and before changing any claim.
	pub(crate) async fn claim_transition(&self) -> ClaimTransition<'_> {
		ClaimTransition { shares: self, state: self.state.lock().await }
	}

	fn queue_cleanup(&self, batch: StopBatch) -> DetachedShares {
		if batch.active.is_empty() && batch.waiting.is_empty() && batch.errors.is_empty() {
			return DetachedShares::default();
		}
		let shares = self.clone();
		DetachedShares {
			task: Some(tokio::spawn(async move {
				let result = shares.finish_stop_batch(batch).await;
				if let Err(error) = &result {
					eprintln!("[error]  share cleanup failed: {error:#}");
				}
				result
			})),
		}
	}

	pub(crate) async fn finish_detached(&self, detached: DetachedShares) -> Result<()> {
		match detached.task {
			Some(task) => task.await.context("share cleanup task failed")?,
			None => Ok(()),
		}
	}

	async fn finish_stop_batch(&self, detached: StopBatch) -> Result<()> {
		if !detached.active.is_empty() || !detached.errors.is_empty() {
			self.bump();
		}
		let mut errors = detached.errors;
		for (name, share) in detached.active {
			if let Err(error) = self.finish_release(&name, share).await {
				errors.push(error.to_string());
			}
			self.bump();
		}
		for mut finished in detached.waiting {
			loop {
				let result = finished.borrow_and_update().clone();
				match result {
					PendingResult::Cleaned => break,
					PendingResult::Unverified(error) => {
						errors.push(error);
						break;
					},
					PendingResult::Running => {},
				}
				match tokio::time::timeout(SHARE_CLEANUP_TIMEOUT, finished.changed()).await {
					Ok(Ok(())) => {},
					_ => {
						errors.push("a pending share ended without confirmed cleanup".to_owned());
						break;
					},
				}
			}
		}
		if !errors.is_empty() {
			bail!("{}", errors.join("; "));
		}
		Ok(())
	}

	async fn end_claim_change(&self, domain: &str, identity: &Arc<()>) -> Result<()> {
		let mut registry = self.registrations.lock().await;
		let mut state = self.state.lock().await;
		if let Some(changes) = state.claim_changes.get_mut(domain) {
			changes.retain(|change| !Arc::ptr_eq(change, identity));
			if changes.is_empty() {
				state.claim_changes.remove(domain);
			}
		}
		let mut batch = StopBatch::default();
		if !state.claim_changes.contains_key(domain) {
			let current = registry.claim(domain).map(ClaimBinding::from_claim);
			let names: Vec<String> = state
				.active
				.iter()
				.filter(|(_, share)| share.binding.domain == domain && Some(&share.binding) != current.as_ref())
				.map(|(name, _)| name.clone())
				.chain(
					state
						.pending
						.iter()
						.filter(|(_, pending)| {
							pending.binding.domain == domain && Some(&pending.binding) != current.as_ref()
						})
						.map(|(name, _)| name.clone()),
				)
				.collect();
			for name in names {
				Self::detach_name(&mut state, &mut registry, &name, &mut batch);
			}
		}
		drop(state);
		drop(registry);
		let detached = self.queue_cleanup(batch);
		self.finish_detached(detached).await
	}

	/// Stop shares whose owning connection or target no longer matches the live claim.
	pub(crate) async fn reconcile(&self) -> Result<()> {
		let mut registry = self.registrations.lock().await;
		let valid = |binding: &ClaimBinding| {
			registry
				.claim(&binding.domain)
				.is_some_and(|claim| ClaimBinding::from_claim(claim) == *binding)
		};
		let mut state = self.state.lock().await;
		let stale: Vec<String> = state
			.active
			.iter()
			.filter(|(_, share)| !state.claim_changes.contains_key(&share.binding.domain) && !valid(&share.binding))
			.map(|(name, _)| name.clone())
			.chain(
				state
					.pending
					.iter()
					.filter(|(_, pending)| {
						!state.claim_changes.contains_key(&pending.binding.domain) && !valid(&pending.binding)
					})
					.map(|(name, _)| name.clone()),
			)
			.collect();
		let mut batch = StopBatch::default();
		for name in stale {
			Self::detach_name(&mut state, &mut registry, &name, &mut batch);
		}
		drop(state);
		let detached = self.queue_cleanup(batch);
		drop(registry);
		self.finish_detached(detached).await
	}

	/// Clear `serve` entries a previous run left behind.
	///
	/// `serve --bg` writes config that outlives this process, while the alias that
	/// made the name answer does not; the leftover would answer with a 404 until
	/// someone shares again. Only an entry whose root handler proxies to this
	/// host's edge is ours, so every other serve entry is left alone.
	pub async fn reclaim(&self) {
		let Some(front) = &self.front else { return };
		let _sweep = self.reclaim.lock().await;
		// A live share owns its serve entry; the sweep must not mistake it for a
		// leftover. The lock makes a start either finish before this check or wait
		// for the sweep, so the two cannot interleave.
		{
			let state = self.state.lock().await;
			if !state.active.is_empty() || !state.pending.is_empty() {
				return;
			}
		}

		let binary = self.binary_for(Provider::Tailscale);
		let upstream = format!("http://{}", front.plain_addr);
		let args = vec!["serve".to_owned(), "status".to_owned(), "--json".to_owned()];
		let Ok(Some(output)) = run_briefly(&binary, &args, SWEEP_TIMEOUT).await else { return };
		if !output.status.success() {
			return;
		}
		for port in leftover_serves(&String::from_utf8_lossy(&output.stdout), &upstream) {
			let args = vec!["serve".to_owned(), format!("--https={port}"), "off".to_owned()];
			match run_briefly(&binary, &args, SWEEP_TIMEOUT).await {
				Ok(Some(output)) if output.status.success() => {
					eprintln!("[share]  cleared a leftover tailscale serve on :{port} pointing at {upstream}");
				},
				Ok(Some(output)) => eprintln!(
					"[warn]   could not clear the leftover tailscale serve on :{port} ({}); run `{} serve reset`",
					output.status,
					binary.display()
				),
				Ok(None) => eprintln!("[warn]   the leftover tailscale serve on :{port} took too long to clear"),
				Err(e) => eprintln!("[warn]   could not clear the leftover tailscale serve on :{port}: {e}"),
			}
		}
	}

	/// Stop everything, including pending starts, for an orderly shutdown.
	pub async fn shutdown(&self) -> Result<()> {
		let mut registry = self.registrations.lock().await;
		let mut state = self.state.lock().await;
		state.is_shutting_down = true;
		let names: Vec<String> = state.active.keys().chain(state.pending.keys()).cloned().collect();
		let mut batch = StopBatch::default();
		for name in names {
			Self::detach_name(&mut state, &mut registry, &name, &mut batch);
		}
		drop(state);
		drop(registry);
		let detached = self.queue_cleanup(batch);
		self.finish_detached(detached).await
	}

	fn binary_for(&self, provider: Provider) -> PathBuf {
		self.binary.clone().unwrap_or_else(|| PathBuf::from(provider.binary()))
	}

	async fn spawn(
		&self,
		start: &ShareStart,
		binary: &Path,
		cancellation: &mut watch::Receiver<bool>,
	) -> Result<Active> {
		let ShareStart { name, provider, .. } = start;
		let target = &start.owner.target;
		if provider.needs_front() {
			return self.spawn_through_front(start, binary, cancellation).await;
		}
		if *cancellation.borrow() {
			bail!("share start for {name} was cancelled");
		}
		let args = provider.start_args(target);
		let mut child = spawn_with_retry(binary, &args, true)
			.await
			.with_context(|| format!("start {} (install it, or set TESTD_TUNNEL to its path)", binary.display()))?;
		let result = tokio::select! {
			biased;
			_ = wait_for_cancellation(cancellation) => Err(anyhow!("share start for {name} was cancelled")),
			url = self.read_url(&mut child, *provider, binary) => url,
		};
		let url = match result {
			Ok(url) => url,
			Err(error) => {
				if let Err(cleanup) = stop_child(&mut child).await {
					return Err(CleanupUnverified(format!("{error}; provider cleanup failed: {cleanup}")).into());
				}
				return Err(error);
			},
		};
		Ok(Active {
			identity: Arc::clone(&start.identity),
			binding: start.owner.clone(),
			provider: *provider,
			url,
			child: Some(child),
			stop_args: None,
			alias: None,
		})
	}

	/// Point a provider at the local edge and teach the edge the name it serves.
	///
	/// Requests then look exactly like browser requests: the edge answers the
	/// share's name and proxies to the registration target, so a container or LAN
	/// target works and the app sees the name it was registered under.
	async fn spawn_through_front(
		&self,
		start: &ShareStart,
		binary: &Path,
		cancellation: &mut watch::Receiver<bool>,
	) -> Result<Active> {
		let ShareStart { name, .. } = start;
		// A sweep that runs while serve config is being written would turn it off.
		let _sweep = tokio::select! {
			biased;
			_ = wait_for_cancellation(cancellation) => bail!("share start for {name} was cancelled"),
			guard = self.reclaim.lock() => guard,
		};
		let front = self
			.front
			.as_ref()
			.context("the built-in edge is not running, so the provider has no local front")?
			.clone();
		let host = tokio::select! {
			biased;
			_ = wait_for_cancellation(cancellation) => bail!("share start for {name} was cancelled"),
			result = self.tailscale_host(binary) => result?,
		};
		let upstream = format!("http://{}", front.plain_addr);
		let status_args = ["serve".to_owned(), "status".to_owned(), "--json".to_owned()];
		let status = tokio::select! {
			biased;
			_ = wait_for_cancellation(cancellation) => bail!("share start for {name} was cancelled"),
			result = run_briefly(binary, &status_args, SWEEP_TIMEOUT) => {
				match result {
					Ok(Some(output)) if output.status.success() => String::from_utf8_lossy(&output.stdout).into_owned(),
					Ok(Some(output)) => bail!("tailscale serve status failed with {}", output.status),
					Ok(None) => bail!("tailscale serve status timed out"),
					Err(e) => bail!("could not inspect tailscale serve: {e}"),
				}
			},
		};
		if !can_take_over_443(&status, &upstream) {
			bail!("tailscale serve already has configuration on :443; refusing to overwrite it");
		}
		{
			let registry = self.registrations.lock().await;
			if *cancellation.borrow()
				|| !registry
					.claim(&start.owner.domain)
					.is_some_and(|claim| ClaimBinding::from_claim(claim) == start.owner)
			{
				bail!("share start for {name} was cancelled");
			}
			if registry.contains(&host) {
				bail!("the provider alias {host} is already in use");
			}
		}

		let args = Provider::Tailscale.start_args(&front.plain_addr.to_string());
		let started = tokio::select! {
			biased;
			_ = wait_for_cancellation(cancellation) => Err(anyhow!("share start was cancelled")),
			result = run_with_retry(binary, &args) => result.and_then(|output| {
				if output.status.success() { Ok(()) } else { Err(anyhow!("provider exited with {}", output.status)) }
			}),
		};
		if let Err(error) = started {
			return Err(CleanupUnverified(format!(
				"tailscale serve for {name} may have changed despite {error}; inspect its state"
			))
			.into());
		}

		Ok(Active {
			identity: Arc::clone(&start.identity),
			binding: start.owner.clone(),
			provider: Provider::Tailscale,
			url: format!("https://{host}"),
			child: None,
			stop_args: Provider::Tailscale.stop_args(),
			alias: Some(host),
		})
	}

	/// First URL a provider prints, from either stream.
	///
	/// The readers keep draining after the URL, because a provider that blocks on
	/// a full pipe would stop serving.
	async fn read_url(&self, child: &mut Child, provider: Provider, binary: &Path) -> Result<String> {
		let (tx, mut rx) = mpsc::channel::<String>(4);

		let drain = |stream: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>>| {
			let Some(stream) = stream else { return };
			let tx = tx.clone();
			tokio::spawn(async move {
				let mut lines = BufReader::new(stream).lines();
				let mut sent = false;
				while let Ok(Some(line)) = lines.next_line().await {
					if !sent && let Some(url) = provider.url_from_line(&line) {
						sent = true;
						let _ = tx.send(url).await;
					}
				}
			});
		};
		drain(
			child
				.stdout
				.take()
				.map(|out| Box::new(out) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
		);
		drain(
			child
				.stderr
				.take()
				.map(|err| Box::new(err) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
		);
		drop(tx);

		match tokio::time::timeout(URL_TIMEOUT, rx.recv()).await {
			Ok(Some(url)) => Ok(url),
			Ok(None) => bail!("{} exited before printing a URL", binary.display()),
			Err(_) => bail!("{} printed no URL in {}s", binary.display(), URL_TIMEOUT.as_secs()),
		}
	}

	/// This node's stable tailnet name, from `tailscale status --json`.
	async fn tailscale_host(&self, binary: &Path) -> Result<String> {
		let args = vec!["status".to_owned(), "--json".to_owned()];
		let output = run_with_retry(binary, &args)
			.await
			.with_context(|| format!("run {} status --json", binary.display()))?;
		if !output.status.success() {
			bail!("{} status --json failed with {}", binary.display(), output.status);
		}
		status_host(&String::from_utf8_lossy(&output.stdout))
			.ok_or_else(|| anyhow!("no tailnet DNS name in {} status --json", binary.display()))
	}

	/// Kill a child, or run the provider's cleanup command.
	async fn release(&self, share: Active) -> Result<()> {
		let _sweep = if share.provider == Provider::Tailscale { Some(self.reclaim.lock().await) } else { None };
		if let Some(mut child) = share.child {
			return stop_child(&mut child).await.context("stop provider process");
		}
		if share.stop_args.is_none() {
			return Ok(());
		}
		let binary = self.binary_for(share.provider);
		if share.provider == Provider::Tailscale {
			let front = self.front.as_ref().context("the tailscale front is missing during cleanup")?;
			let upstream = format!("http://{}", front.plain_addr);
			let status = match run_briefly(
				&binary,
				&["serve".to_owned(), "status".to_owned(), "--json".to_owned()],
				SWEEP_TIMEOUT,
			)
			.await
			{
				Ok(Some(output)) if output.status.success() => String::from_utf8_lossy(&output.stdout).into_owned(),
				_ => bail!("could not inspect tailscale serve; leaving :443 alone"),
			};
			if serde_json::from_str::<serde_json::Value>(&status).is_err() {
				bail!("tailscale serve returned malformed status; leaving :443 alone");
			}
			if !leftover_serves(&status, &upstream).contains(&443) {
				bail!("tailscale serve :443 changed; leaving it in place");
			}
		}
		let args = share.stop_args.unwrap_or_default();
		let output = run_with_retry(&binary, &args).await?;
		if !output.status.success() {
			bail!("{} {} exited with {}; inspect the provider state", binary.display(), args.join(" "), output.status);
		}
		Ok(())
	}
}

/// This node's tailnet name, from `tailscale status --json`.
pub fn status_host(status: &str) -> Option<String> {
	let value: serde_json::Value = serde_json::from_str(status).ok()?;
	let name = value.get("Self")?.get("DNSName")?.as_str()?.trim_end_matches('.');
	if name.is_empty() { None } else { Some(name.to_owned()) }
}

/// Serve ports whose entire handler set is our root handler. A port with any
/// additional handler is not ours to turn off.
fn leftover_serves(status: &str, upstream: &str) -> Vec<u16> {
	let Ok(value) = serde_json::from_str::<serde_json::Value>(status) else { return Vec::new() };
	let Some(web) = value.get("Web").and_then(|web| web.as_object()) else { return Vec::new() };
	let mut ports: Vec<u16> = Vec::new();
	for (host_port, entry) in web {
		let Some(handlers) = entry.get("Handlers").and_then(|handlers| handlers.as_object()) else {
			continue;
		};
		if handlers.len() != 1 {
			continue;
		}
		let proxy = handlers
			.get("/")
			.and_then(|handler| handler.get("Proxy"))
			.and_then(|proxy| proxy.as_str());
		if proxy != Some(upstream) {
			continue;
		}
		if let Some(port) = host_port.rsplit(':').next().and_then(|port| port.parse::<u16>().ok())
			&& !ports.contains(&port)
		{
			ports.push(port);
		}
	}
	ports.sort_unstable();
	ports
}

/// Whether starting a root handler on :443 would leave someone else's handlers
/// in place to be removed by the next `serve --https=443 off`.
fn can_take_over_443(status: &str, upstream: &str) -> bool {
	let Ok(value) = serde_json::from_str::<serde_json::Value>(status) else { return false };
	let Some(web) = value.get("Web").and_then(|web| web.as_object()) else { return true };
	web.iter()
		.filter(|(host_port, _)| host_port.ends_with(":443"))
		.all(|(_, entry)| {
			let Some(handlers) = entry.get("Handlers").and_then(|handlers| handlers.as_object()) else {
				return false;
			};
			handlers.len() == 1
				&& handlers
					.get("/")
					.and_then(|handler| handler.get("Proxy"))
					.and_then(|proxy| proxy.as_str())
					== Some(upstream)
		})
}

async fn stop_child(child: &mut Child) -> Result<()> {
	if child.try_wait()?.is_none() {
		tokio::time::timeout(PROVIDER_STOP_TIMEOUT, child.kill())
			.await
			.context("provider termination timed out")??;
	}
	Ok(())
}

async fn wait_for_cancellation(cancellation: &mut watch::Receiver<bool>) {
	loop {
		if *cancellation.borrow_and_update() || cancellation.changed().await.is_err() {
			return;
		}
	}
}

/// How often a spawn is retried when the kernel reports the binary as busy.
const BUSY_RETRIES: usize = 5;
/// `ETXTBSY`: the file is open for writing elsewhere, usually a binary that was
/// just installed. It clears within milliseconds.
const ETXTBSY: i32 = 26;

/// Start a provider, retrying while the kernel reports the binary as busy.
async fn spawn_with_retry(binary: &Path, args: &[String], piped: bool) -> Result<Child> {
	let mut attempts = 0;
	loop {
		let mut command = Command::new(binary);
		command.args(args);
		if piped {
			command.stdout(Stdio::piped()).stderr(Stdio::piped());
		}
		command.kill_on_drop(true);
		match command.spawn() {
			Ok(child) => return Ok(child),
			Err(e) if e.raw_os_error() == Some(ETXTBSY) && attempts < BUSY_RETRIES => {
				attempts += 1;
				tokio::time::sleep(Duration::from_millis(20)).await;
			},
			Err(e) => return Err(e.into()),
		}
	}
}

/// Run a provider command with a deadline. `None` means it was still running when
/// the deadline passed; dropping the child kills it.
async fn run_briefly(binary: &Path, args: &[String], limit: Duration) -> Result<Option<std::process::Output>> {
	let child = spawn_with_retry(binary, args, true).await?;
	match tokio::time::timeout(limit, child.wait_with_output()).await {
		Ok(result) => Ok(Some(result?)),
		Err(_) => Ok(None),
	}
}

/// Run a provider command with a deadline and the same busy retry.
async fn run_with_retry(binary: &Path, args: &[String]) -> Result<std::process::Output> {
	run_briefly(binary, args, URL_TIMEOUT)
		.await?
		.ok_or_else(|| anyhow!("{} {} timed out", binary.display(), args.join(" ")))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reads_the_cloudflared_tunnel_url() {
		let line = "2026-10-30T10:00:00Z INF |  https://brave-otter-harbor.trycloudflare.com  |";
		assert_eq!(
			Provider::Cloudflared.url_from_line(line).as_deref(),
			Some("https://brave-otter-harbor.trycloudflare.com")
		);
		assert!(
			Provider::Cloudflared
				.url_from_line("INF https://api.trycloudflare.com docs")
				.is_none()
		);
		assert!(Provider::Cloudflared.url_from_line("INF connecting...").is_none());
	}

	#[test]
	fn reads_the_ngrok_tunnel_url_from_a_log_record() {
		let line = r#"t=2026-10-30T10:00:00+0000 lvl=info msg="started tunnel" obj=tunnels name=command_line addr=127.0.0.1:3000 url=https://1a2b-3c4d.ngrok-free.app"#;
		assert_eq!(Provider::Ngrok.url_from_line(line).as_deref(), Some("https://1a2b-3c4d.ngrok-free.app"));
		assert!(Provider::Ngrok.url_from_line("https://example.com").is_none());
	}

	#[test]
	fn reads_the_tailnet_name() {
		let status = r#"{"Self":{"DNSName":"node-a.tailnet.ts.net.","HostName":"node-a"}}"#;
		assert_eq!(status_host(status).as_deref(), Some("node-a.tailnet.ts.net"));
		assert!(status_host(r#"{"Self":{}}"#).is_none());
		assert!(status_host("not json").is_none());
	}

	#[test]
	fn finds_only_the_serve_entries_that_point_at_this_edge() {
		let status = r#"{"Web":{
			"node-a.tailnet.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"}}},
			"node-a.tailnet.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"}}},
			"node-a.tailnet.ts.net:10000":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"}}}
		}}"#;
		assert_eq!(leftover_serves(status, "http://127.0.0.1:7740"), vec![443, 10000]);
		assert!(leftover_serves(status, "http://127.0.0.1:7741").is_empty());
		assert!(leftover_serves("", "http://127.0.0.1:7740").is_empty());
		assert!(leftover_serves(r#"{"Web":{}}"#, "http://127.0.0.1:7740").is_empty());
	}

	#[test]
	fn a_foreign_handler_on_443_blocks_the_share() {
		let upstream = "http://127.0.0.1:7740";
		let ours = r#"{"Web":{"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"}}}}}"#;
		let foreign = r#"{"Web":{"node.tail.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7740"},"/api":{"Proxy":"http://127.0.0.1:9000"}}}}}"#;
		assert!(can_take_over_443(ours, upstream));
		assert!(!can_take_over_443(foreign, upstream));
		assert!(can_take_over_443(r#"{"Web":{}}"#, upstream));
		assert_eq!(leftover_serves(foreign, upstream), Vec::<u16>::new());
	}

	#[test]
	fn only_tailscale_needs_the_local_front() {
		assert!(Provider::Tailscale.needs_front());
		assert!(!Provider::Cloudflared.needs_front());
		assert!(!Provider::Ngrok.needs_front());
	}

	#[test]
	fn providers_expose_where_they_reach() {
		assert_eq!(Provider::Cloudflared.exposure(), Exposure::Public);
		assert_eq!(Provider::Ngrok.exposure(), Exposure::Public);
		assert_eq!(Provider::Tailscale.exposure(), Exposure::Tailnet);
		assert_eq!(Provider::parse("TS"), Some(Provider::Tailscale));
		assert_eq!(Provider::parse("cloudflare"), Some(Provider::Cloudflared));
		assert_eq!(Provider::parse("mystery"), None);
	}
}
