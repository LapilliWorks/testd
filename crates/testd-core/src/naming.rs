//! Registration names and how they group.
//!
//! Names are `<service>.<project>.<tld>`, and the TLD is appended by the host,
//! so a stored name is `<service>.<project>`. The daemon and the tray share
//! this rule so a name lands in the same group everywhere.
//!
//! Token grants store full names (`<service>.<project>.<tld>`), and access
//! labels show their project next to the leaf that asked for them.

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

/// Project label of a fully qualified name: every label between the service
/// label and the TLD. `app.example.test` → `example`, `api.sub.example.test` →
/// `sub.example`, `app.test` → none.
fn fqdn_project_label(domain: &str) -> Option<&str> {
	let (service, rest) = domain.split_once('.')?;
	let (project, tld) = rest.rsplit_once('.')?;
	(!service.is_empty() && !project.is_empty() && !tld.is_empty()).then_some(project)
}

/// Display name for an access request or an issued token: the leaf's own label
/// plus the project(s) its names belong to. `alex@laptop` with
/// `app.example.test` becomes `alex@laptop:example`. Names without a project,
/// and a grant that may publish any name, add nothing.
pub fn access_label(label: &str, names: Option<&[String]>) -> String {
	let mut projects: Vec<&str> = names
		.unwrap_or_default()
		.iter()
		.filter_map(|name| fqdn_project_label(name))
		.collect();
	projects.sort_unstable();
	projects.dedup();
	if projects.is_empty() { label.to_owned() } else { format!("{label}:{}", projects.join(",")) }
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

	fn names(names: &[&str]) -> Vec<String> {
		names.iter().map(|name| (*name).to_owned()).collect()
	}

	#[test]
	fn access_label_appends_the_projects_it_covers() {
		assert_eq!(access_label("alex@laptop", Some(&names(&["app.example.test"]))), "alex@laptop:example");
		assert_eq!(access_label("alex@laptop", Some(&names(&["api.sub.example.test"]))), "alex@laptop:sub.example");
		assert_eq!(
			access_label("alex@laptop", Some(&names(&["web.beta.test", "app.alpha.test", "api.alpha.test"]))),
			"alex@laptop:alpha,beta"
		);
	}

	#[test]
	fn access_label_without_a_project_stays_bare() {
		assert_eq!(access_label("alex@laptop", Some(&[])), "alex@laptop");
		assert_eq!(access_label("alex@laptop", Some(&names(&["app.test", "api"]))), "alex@laptop");
		assert_eq!(access_label("alex@laptop", None), "alex@laptop");
	}
}
