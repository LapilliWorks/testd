//! Quick launches placeholder until the supervisor wiring lands.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use testd_client::supervisor::{EntryState, OutputStream};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchEntryDef {
	pub domain: String,
	#[serde(default)]
	pub target: String,
}

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

pub struct LaunchBook {
	definitions: Mutex<Vec<LaunchDefinition>>,
	#[allow(dead_code)]
	path: PathBuf,
}

impl Default for LaunchBook {
	fn default() -> Self {
		Self { definitions: Mutex::new(Vec::new()), path: PathBuf::from("launches.json") }
	}
}

impl LaunchBook {
	pub fn load() -> Self {
		Self::default()
	}

	pub fn upsert(&self, definition: LaunchDefinition) -> Result<LaunchDefinition, String> {
		self.definitions.lock().expect("launch lock poisoned").push(definition.clone());
		Ok(definition)
	}

	pub fn delete(&self, id: &str) -> Result<(), String> {
		self.definitions.lock().expect("launch lock poisoned").retain(|definition| definition.id != id);
		Ok(())
	}

	pub fn list(&self) -> Vec<LaunchView> {
		self.definitions
			.lock()
			.expect("launch lock poisoned")
			.iter()
			.cloned()
			.map(|definition| LaunchView {
				definition,
				running: false,
				states: Vec::new(),
				logs: Vec::new(),
				error: None,
			})
			.collect()
	}

	pub fn start(self: &Arc<Self>, _id: &str) -> Result<(), String> {
		Err("quick launches are not available yet".into())
	}

	pub fn stop(&self, _id: &str) -> Result<(), String> {
		Err("quick launches are not available yet".into())
	}

	pub async fn rebind(&self, _id: &str, _domain: String, _target: String) -> Result<(), String> {
		Err("quick launches are not available yet".into())
	}

	pub async fn shutdown(&self) {}
}
