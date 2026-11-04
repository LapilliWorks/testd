//! Static files served by the dashboard and the setup server.
//!
//! Release builds embed them; development reads from the crate directory so an
//! edit does not need a rebuild.

pub const DASHBOARD_HTML: &str = "dashboard.html";
pub const DASHBOARD_CSS: &str = "dashboard.css";
pub const SETUP_HTML: &str = "setup.html";

/// Load one of the known assets by name.
pub fn load(name: &str) -> String {
	#[cfg(debug_assertions)]
	{
		let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
		std::fs::read_to_string(&path).unwrap_or_else(|e| format!("failed to load {}: {e}", path.display()))
	}
	#[cfg(not(debug_assertions))]
	{
		match name {
			DASHBOARD_HTML => include_str!("../dashboard.html"),
			DASHBOARD_CSS => include_str!("../dashboard.css"),
			SETUP_HTML => include_str!("../setup.html"),
			_ => "",
		}
		.to_owned()
	}
}
