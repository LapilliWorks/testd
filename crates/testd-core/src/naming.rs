//! Registration names and how they group.
//!
//! Names are `<service>.<project>.<tld>`, and the TLD is appended by the host,
//! so a stored name is `<service>.<project>`. The daemon and the tray share
//! this rule so a name lands in the same group everywhere.

use std::cmp::Ordering;

use crate::Registration;

/// Project label of a stored name: every label between the service label and
/// the TLD. `app.example` → `example`, `api.sub.example` → `sub.example`.
/// A single-label name (`app`) has no project.
pub fn project_label(domain: &str) -> Option<&str> {
	match domain.split_once('.') {
		Some((service, project)) if !service.is_empty() && !project.is_empty() => Some(project),
		_ => None,
	}
}

/// Group registrations by project, in display order: projects alphabetically,
/// single-label names last. Registrations keep the order the engine gave them.
pub fn group_by_project<'a>(regs: &'a [Registration]) -> Vec<(Option<&'a str>, Vec<&'a Registration>)> {
	let mut groups: Vec<(Option<&'a str>, Vec<&'a Registration>)> = Vec::new();
	for reg in regs {
		let project = project_label(&reg.domain);
		match groups.iter_mut().find(|(existing, _)| *existing == project) {
			Some((_, items)) => items.push(reg),
			None => groups.push((project, vec![reg])),
		}
	}
	groups.sort_by(|(a, _), (b, _)| match (a, b) {
		(Some(a), Some(b)) => a.cmp(b),
		(Some(_), None) => Ordering::Less,
		(None, Some(_)) => Ordering::Greater,
		(None, None) => Ordering::Equal,
	});
	groups
}

#[cfg(test)]
mod tests {
	use super::*;

	fn reg(domain: &str) -> Registration {
		Registration { domain: domain.into(), target: "127.0.0.1:3000".into() }
	}

	#[test]
	fn project_is_between_service_and_tld() {
		assert_eq!(project_label("app.example"), Some("example"));
		assert_eq!(project_label("api.sub.example"), Some("sub.example"));
		assert_eq!(project_label("app"), None);
		assert_eq!(project_label("app."), None);
		assert_eq!(project_label(".example"), None);
	}

	#[test]
	fn groups_sort_projects_then_single_label() {
		let regs = vec![reg("app"), reg("web.beta"), reg("api.alpha"), reg("api.beta")];
		let groups = group_by_project(&regs);
		let labels: Vec<Option<&str>> = groups.iter().map(|(project, _)| *project).collect();
		assert_eq!(labels, vec![Some("alpha"), Some("beta"), None]);
		let beta: Vec<&str> = groups[1].1.iter().map(|reg| reg.domain.as_str()).collect();
		assert_eq!(beta, vec!["web.beta", "api.beta"]);
	}

	#[test]
	fn empty_input_has_no_groups() {
		assert!(group_by_project(&[]).is_empty());
	}
}
