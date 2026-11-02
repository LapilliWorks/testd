//! Quick launches: saved commands with names owned for the command's lifetime.
//!
//! This is a local-only feature. The dashboard serves it from the loopback
//! listener; the authenticated listener never exposes process control.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch};

use testd_client::Entry;
use testd_client::supervisor::{self, EntryState, LaunchEvent, LaunchSpec, OutputStream};
use testd_core::config::{config_dir, write_private};

const FILE: &str = "launches.json";
const MAX_LOG_LINES: usize = 500;

/// One name:target pair in a saved launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchEntryDef {
	pub domain: String,
	/// Empty, `auto`, a port, or an explicit `host:port`.
	#[serde(default)]
	pub target: String,
}

/// A saved quick launch. Running state is deliberately separate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchDefinition {
	#[serde(default)]
	pub id: String,
	pub label: String,
	pub program: String,
	#[serde(default)]
	pub args: Vec<String>,
	#[serde(default)]
	pub cwd: Option<String>,
	#[serde(default)]
	pub env: Vec<(String, String)>,
	pub entries: Vec<LaunchEntryDef>,
	#[serde(default)]
	pub share: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchView {
	#[serde(flatten)]
	pub definition: LaunchDefinition,
	pub running: bool,
	pub states: Vec<EntryStateView>,
	pub logs: Vec<LogLine>,
	pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryStateView {
	pub domain: String,
	pub target: String,
	pub state: EntryState,
	pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
	pub stream: OutputStream,
	pub line: String,
}

#[derive(Default)]
struct RunState {
	running: bool,
	states: Vec<EntryStateView>,
	logs: VecDeque<LogLine>,
	error: Option<String>,
}

struct RebindRequest {
	domain: String,
	target: String,
	respond: oneshot::Sender<Result<(), String>>,
}

struct Running {
	stop: mpsc::Sender<()>,
	rebind: mpsc::Sender<RebindRequest>,
	state: Arc<Mutex<RunState>>,
	done: watch::Receiver<bool>,
}

/// Definitions plus the currently running supervisors.
pub struct LaunchBook {
	definitions: Mutex<Vec<LaunchDefinition>>,
	running: Mutex<HashMap<String, Running>>,
	path: PathBuf,
	/// Any change to definitions or live state, for live frontends.
	revision: watch::Sender<u64>,
}

impl LaunchBook {
	pub fn load() -> Self {
		Self::load_from(path())
	}

	fn load_from(path: PathBuf) -> Self {
		let definitions = match std::fs::read(&path) {
			Ok(data) => match serde_json::from_slice::<Vec<LaunchDefinition>>(&data) {
				Ok(definitions) => definitions,
				Err(e) => {
					eprintln!("[warn]   could not parse {}: {e}", path.display());
					Vec::new()
				},
			},
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
			Err(e) => {
				eprintln!("[warn]   could not read {}: {e}", path.display());
				Vec::new()
			},
		};
		Self {
			definitions: Mutex::new(definitions),
			running: Mutex::new(HashMap::new()),
			path,
			revision: watch::channel(0).0,
		}
	}

	/// Any change to launch definitions or live state, for live frontends.
	pub fn state_changes(&self) -> watch::Receiver<u64> {
		self.revision.subscribe()
	}

	fn bump(&self) {
		self.revision.send_modify(|revision| *revision = revision.wrapping_add(1));
	}

	fn save(&self) -> Result<(), String> {
		let definitions = self.definitions.lock().expect("launch definitions poisoned").clone();
		let data = serde_json::to_vec_pretty(&definitions).map_err(|e| e.to_string())?;
		let path = &self.path;
		if let Some(parent) = path.parent() {
			std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
		}
		let tmp = path.with_extension("json.tmp");
		write_private(&tmp, &data).map_err(|e| e.to_string())?;
		#[cfg(windows)]
		if path.exists() {
			std::fs::remove_file(path).map_err(|e| e.to_string())?;
		}
		std::fs::rename(tmp, path).map_err(|e| e.to_string())
	}

	pub fn upsert(&self, mut definition: LaunchDefinition) -> Result<LaunchDefinition, String> {
		if definition.label.trim().is_empty() {
			return Err("a launch needs a label".into());
		}
		if definition.program.trim().is_empty() {
			return Err("a launch needs a program".into());
		}
		if definition.entries.is_empty() {
			return Err("a launch needs at least one name".into());
		}
		let mut domains = std::collections::HashSet::new();
		for entry in &definition.entries {
			if entry.domain.trim().is_empty() {
				return Err("every entry needs a name".into());
			}
			if !domains.insert(entry.domain.clone()) {
				return Err(format!("duplicate name: {}", entry.domain));
			}
		}
		if definition.id.is_empty() {
			definition.id = new_id();
		}

		let mut definitions = self.definitions.lock().expect("launch definitions poisoned");
		match definitions.iter_mut().find(|saved| saved.id == definition.id) {
			Some(saved) => *saved = definition.clone(),
			None => definitions.push(definition.clone()),
		}
		drop(definitions);
		self.save()?;
		self.bump();
		Ok(definition)
	}

	pub fn delete(&self, id: &str) -> Result<(), String> {
		let running = self.running.lock().expect("launch state poisoned");
		if running
			.get(id)
			.is_some_and(|state| state.state.lock().expect("launch state poisoned").running)
		{
			return Err("stop the launch before deleting it".into());
		}
		drop(running);
		self.definitions
			.lock()
			.expect("launch definitions poisoned")
			.retain(|saved| saved.id != id);
		self.running.lock().expect("launch state poisoned").remove(id);
		self.save()?;
		self.bump();
		Ok(())
	}

	/// Every definition with its live state, output, and last error.
	pub fn list(&self) -> Vec<LaunchView> {
		let definitions = self.definitions.lock().expect("launch definitions poisoned").clone();
		let running = self.running.lock().expect("launch state poisoned");
		definitions
			.into_iter()
			.map(|definition| {
				let live = running.get(&definition.id).map(|state| {
					let state = state.state.lock().expect("launch state poisoned");
					(state.running, state.states.clone(), state.logs.iter().cloned().collect(), state.error.clone())
				});
				let (is_running, states, logs, error) = live.unwrap_or_default();
				LaunchView { definition, running: is_running, states, logs, error }
			})
			.collect()
	}

	/// Start a saved launch. The supervisor connects before spawning the child;
	/// that work happens off the request so the dashboard stays responsive.
	pub fn start(self: &Arc<Self>, id: &str) -> Result<(), String> {
		let running = self.running.lock().expect("launch state poisoned");
		if running
			.get(id)
			.is_some_and(|state| state.state.lock().expect("launch state poisoned").running)
		{
			return Err("launch is already running".into());
		}
		drop(running);

		let definition = self
			.definitions
			.lock()
			.expect("launch definitions poisoned")
			.iter()
			.find(|saved| saved.id == id)
			.cloned()
			.ok_or_else(|| format!("no launch with id {id}"))?;

		let config = crate::control::client_config()?;
		let mut spec = LaunchSpec::new(
			PathBuf::from(&definition.program),
			definition
				.entries
				.iter()
				.map(|entry| Entry::new(entry.domain.clone(), entry.target.clone()))
				.collect(),
		);
		spec.args = definition.args.clone();
		spec.cwd = definition.cwd.clone().filter(|cwd| !cwd.is_empty()).map(PathBuf::from);
		spec.env = definition.env.clone();
		spec.share = definition.share;

		let (stop, stop_rx) = mpsc::channel(1);
		let (rebind, rebind_rx) = mpsc::channel(4);
		let state = Arc::new(Mutex::new(RunState { running: true, ..RunState::default() }));
		let (done_tx, done) = watch::channel(false);
		self.running
			.lock()
			.expect("launch state poisoned")
			.insert(id.to_owned(), Running { stop, rebind, state: Arc::clone(&state), done });
		self.bump();

		let book = Arc::clone(self);
		let id = id.to_owned();
		tokio::spawn(async move {
			run_launch(book, id, spec, config, stop_rx, rebind_rx, state).await;
			let _ = done_tx.send(true);
		});
		Ok(())
	}

	pub fn stop(&self, id: &str) -> Result<(), String> {
		let running = self.running.lock().expect("launch state poisoned");
		let Some(state) = running.get(id) else { return Ok(()) };
		if state.stop.try_send(()).is_err() {
			return Err("launch is already stopping".into());
		}
		self.bump();
		Ok(())
	}

	pub async fn rebind(&self, id: &str, domain: String, target: String) -> Result<(), String> {
		let (respond, response) = oneshot::channel();
		let sender = {
			let running = self.running.lock().expect("launch state poisoned");
			running.get(id).map(|state| state.rebind.clone())
		};
		let Some(sender) = sender else { return Err("launch is not running".into()) };
		sender
			.send(RebindRequest { domain, target, respond })
			.await
			.map_err(|_| "launch stopped".to_owned())?;
		response.await.map_err(|_| "launch stopped".to_owned())?
	}

	/// Stop every running launch. Called when the daemon shuts down.
	pub async fn shutdown(&self) {
		let running: Vec<(mpsc::Sender<()>, watch::Receiver<bool>)> = self
			.running
			.lock()
			.expect("launch state poisoned")
			.values()
			.map(|state| (state.stop.clone(), state.done.clone()))
			.collect();
		for (stop, done) in &running {
			if !*done.borrow() {
				let _ = stop.send(()).await;
			}
		}
		for (_, done) in running {
			let mut done = done;
			if *done.borrow() {
				continue;
			}
			let _ = tokio::time::timeout(Duration::from_secs(5), done.changed()).await;
		}
	}
}

fn path() -> PathBuf {
	config_dir().join(FILE)
}

fn new_id() -> String {
	static NEXT: AtomicU64 = AtomicU64::new(1);
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
	format!("{now:x}-{:x}", NEXT.fetch_add(1, Ordering::SeqCst))
}

async fn run_launch(
	book: Arc<LaunchBook>,
	id: String,
	spec: LaunchSpec,
	config: testd_core::config::ClientConfig,
	mut stop: mpsc::Receiver<()>,
	mut rebind: mpsc::Receiver<RebindRequest>,
	state: Arc<Mutex<RunState>>,
) {
	let mut launch = match supervisor::launch(spec, config).await {
		Ok(launch) => launch,
		Err(e) => {
			let mut state = state.lock().expect("launch state poisoned");
			state.running = false;
			state.error = Some(format!("{e:#}"));
			drop(state);
			book.bump();
			return;
		},
	};
	let Some(mut events) = launch.take_events() else {
		state.lock().expect("launch state poisoned").running = false;
		book.bump();
		return;
	};

	loop {
		tokio::select! {
			event = events.recv() => {
				let Some(event) = event else { break };
				record(&state, &event);
				let changed = matches!(&event, LaunchEvent::State { .. } | LaunchEvent::Exited { .. } | LaunchEvent::Failed { .. });
				if changed {
					book.bump();
				}
				let done = matches!(&event, LaunchEvent::Exited { .. } | LaunchEvent::Failed { .. });
				if done {
					break;
				}
			},
			Some(()) = stop.recv() => {
				let _ = launch.stop().await;
				while let Ok(event) = events.try_recv() {
					record(&state, &event);
				}
				book.bump();
				break;
			},
			Some(request) = rebind.recv() => {
				let result = launch.rebind(&request.domain, &request.target).await;
				let _ = request.respond.send(result);
			},
		}
	}
	book.finish(&id);
}

impl LaunchBook {
	fn finish(&self, id: &str) {
		if let Some(running) = self.running.lock().expect("launch state poisoned").get(id) {
			running.state.lock().expect("launch state poisoned").running = false;
		}
		self.bump();
	}
}

fn record(state: &Arc<Mutex<RunState>>, event: &LaunchEvent) {
	let mut state = state.lock().expect("launch state poisoned");
	match event {
		LaunchEvent::State { domain, target, state: entry, error } => {
			if let Some(existing) = state.states.iter_mut().find(|item| item.domain == *domain) {
				existing.target = target.clone();
				existing.state = *entry;
				existing.error = error.clone();
			} else {
				state.states.push(EntryStateView {
					domain: domain.clone(),
					target: target.clone(),
					state: *entry,
					error: error.clone(),
				});
			}
		},
		LaunchEvent::Output { stream, line } => {
			if state.logs.len() == MAX_LOG_LINES {
				state.logs.pop_front();
			}
			state.logs.push_back(LogLine { stream: *stream, line: line.clone() });
		},
		LaunchEvent::Failed { message } => {
			state.running = false;
			state.error = Some(message.clone());
		},
		LaunchEvent::Exited { .. } => state.running = false,
		LaunchEvent::Started { .. } => {},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn definition(id: &str) -> LaunchDefinition {
		LaunchDefinition {
			id: id.into(),
			label: "app".into(),
			program: "/bin/true".into(),
			args: Vec::new(),
			cwd: None,
			env: Vec::new(),
			entries: vec![LaunchEntryDef { domain: "app.example".into(), target: "3000".into() }],
			share: false,
		}
	}

	fn book(path: PathBuf) -> LaunchBook {
		LaunchBook {
			definitions: Mutex::new(Vec::new()),
			running: Mutex::new(HashMap::new()),
			path,
			revision: watch::channel(0).0,
		}
	}

	#[test]
	fn definitions_round_trip_and_reject_duplicates() {
		let dir = tempfile::tempdir().unwrap();
		let book = book(dir.path().join("launches.json"));
		let saved = book.upsert(definition("one")).unwrap();
		assert_eq!(saved.id, "one");
		assert_eq!(book.list().len(), 1);

		let mut duplicate = definition("one");
		duplicate.entries.push(duplicate.entries[0].clone());
		assert!(book.upsert(duplicate).is_err());
	}

	#[test]
	fn omitting_the_id_assigns_one() {
		let dir = tempfile::tempdir().unwrap();
		let book = book(dir.path().join("launches.json"));
		let saved = book.upsert(definition("")).unwrap();
		assert!(!saved.id.is_empty());
	}
}
