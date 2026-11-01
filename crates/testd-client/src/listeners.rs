//! Discover TCP listeners owned by a process tree.
//!
//! Used by supervised launches before registration. The result is a hint for
//! picking a target; an explicit target always wins.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One listening TCP socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
	pub address: IpAddr,
	pub port: u16,
	pub pid: u32,
}

/// List listening TCP sockets owned by `root_pid` or its descendants.
pub fn discover(root_pid: u32) -> Result<Vec<Listener>, String> {
	let pids = process_tree(root_pid)?;
	listeners_for(&pids)
}

/// Why a listener could not be selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
	/// Nothing is listening yet, or nothing matches the port hint.
	NoListener,
	/// Several ports are open and no hint disambiguates them.
	Ambiguous(Vec<String>),
}

impl std::fmt::Display for SelectError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::NoListener => write!(f, "no TCP listener found"),
			Self::Ambiguous(candidates) => write!(f, "multiple listening ports; choose one: {}", candidates.join(", ")),
		}
	}
}

/// Pick a dialable target from the listeners.
///
/// A port hint narrows the set. Without one, exactly one listening port is
/// required; multiple ports are ambiguous and reported with the candidates.
pub fn select(listeners: &[Listener], port: Option<u16>, share: bool) -> Result<String, SelectError> {
	let candidates: Vec<&Listener> = listeners.iter().filter(|l| port.is_none_or(|p| l.port == p)).collect();
	if candidates.is_empty() {
		return Err(SelectError::NoListener);
	}

	let ports: std::collections::BTreeSet<u16> = candidates.iter().map(|l| l.port).collect();
	if ports.len() > 1 {
		let names: Vec<String> = candidates.iter().map(|l| dial(l.address, l.port)).collect();
		return Err(SelectError::Ambiguous(names));
	}

	let port = *ports.iter().next().expect("non-empty");
	let mut targets: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
	for listener in candidates {
		let address = dialable(listener.address, share);
		targets.insert(dial(address, port));
	}

	// A wildcard bind yields several concrete addresses. Prefer loopback for a
	// local target and a non-loopback address for a shared one.
	let preferred = targets.iter().find(|target| {
		let loopback = target.starts_with("127.") || target.starts_with("[::1]");
		if share { !loopback } else { loopback }
	});
	Ok(preferred
		.cloned()
		.unwrap_or_else(|| targets.iter().next().expect("non-empty").clone()))
}

fn dialable(address: IpAddr, share: bool) -> IpAddr {
	if !address.is_unspecified() {
		return address;
	}
	if share {
		return first_nonloopback(address.is_ipv4()).unwrap_or(if address.is_ipv4() {
			IpAddr::V4(Ipv4Addr::LOCALHOST)
		} else {
			IpAddr::V6(Ipv6Addr::LOCALHOST)
		});
	}
	if address.is_ipv4() { IpAddr::V4(Ipv4Addr::LOCALHOST) } else { IpAddr::V6(Ipv6Addr::LOCALHOST) }
}

fn first_nonloopback(ipv4: bool) -> Option<IpAddr> {
	let interfaces = if_addrs::get_if_addrs().ok()?;
	interfaces.into_iter().map(|iface| iface.ip()).find(|ip| {
		ip.is_ipv4() == ipv4
			&& !ip.is_loopback()
			&& !ip.is_unspecified()
			&& !matches!(ip, IpAddr::V4(v4) if v4.is_link_local())
			&& !matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
	})
}

fn dial(address: IpAddr, port: u16) -> String {
	match address {
		IpAddr::V4(_) => format!("{address}:{port}"),
		IpAddr::V6(_) => format!("[{address}]:{port}"),
	}
}

#[cfg(target_os = "linux")]
fn process_tree(root_pid: u32) -> Result<Vec<u32>, String> {
	use std::collections::HashMap;

	let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
	for entry in std::fs::read_dir("/proc").map_err(|e| format!("read /proc: {e}"))? {
		let Ok(entry) = entry else { continue };
		let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
		let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else { continue };
		let Some(parent) = parent_from_stat(&stat) else { continue };
		children.entry(parent).or_default().push(pid);
	}

	let mut tree = vec![root_pid];
	let mut index = 0;
	while index < tree.len() {
		let pid = tree[index];
		index += 1;
		if let Some(kids) = children.get(&pid) {
			tree.extend(kids.iter().copied());
		}
	}
	Ok(tree)
}

#[cfg(target_os = "linux")]
fn parent_from_stat(stat: &str) -> Option<u32> {
	// Format: pid (comm) state ppid pgrp ...
	let rest = stat.rsplit_once(')')?.1;
	rest.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(target_os = "linux")]
fn listeners_for(pids: &[u32]) -> Result<Vec<Listener>, String> {
	use std::collections::{HashMap, HashSet};

	let mut by_inode: HashMap<u32, u32> = HashMap::new();
	for pid in pids {
		let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
		for entry in entries.flatten() {
			let Ok(target) = std::fs::read_link(entry.path()) else { continue };
			let Some(target) = target.to_str() else { continue };
			let Some(inode) = target.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) else {
				continue;
			};
			if let Ok(inode) = inode.parse() {
				by_inode.entry(inode).or_insert(*pid);
			}
		}
	}

	let mut listeners = Vec::new();
	let mut seen = HashSet::new();
	for pid in pids {
		for file in ["tcp", "tcp6"] {
			let Ok(table) = std::fs::read_to_string(format!("/proc/{pid}/net/{file}")) else { continue };
			for line in table.lines().skip(1) {
				let fields: Vec<&str> = line.split_whitespace().collect();
				if fields.len() < 10 || fields[3] != "0A" {
					continue;
				}
				let Ok(inode) = fields[9].parse::<u32>() else { continue };
				if !by_inode.contains_key(&inode) || !seen.insert(inode) {
					continue;
				}
				let Some((address, port)) = parse_proc_address(fields[1]) else { continue };
				listeners.push(Listener { address, port, pid: by_inode[&inode] });
			}
		}
	}
	listeners.sort_by_key(|l| (l.port, l.address.to_string()));
	Ok(listeners)
}

#[cfg(target_os = "linux")]
fn parse_proc_address(value: &str) -> Option<(IpAddr, u16)> {
	let (address, port) = value.split_once(':')?;
	let port = u16::from_str_radix(port, 16).ok()?;
	let address = match address.len() {
		8 => {
			let raw = u32::from_str_radix(address, 16).ok()?;
			IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
		},
		32 => {
			let mut bytes = [0u8; 16];
			for (index, chunk) in address.as_bytes().chunks(8).enumerate() {
				let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
				bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
			}
			IpAddr::V6(Ipv6Addr::from(bytes))
		},
		_ => return None,
	};
	Some((address, port))
}

#[cfg(target_os = "macos")]
fn process_tree(root_pid: u32) -> Result<Vec<u32>, String> {
	use std::collections::HashMap;
	let output = std::process::Command::new("ps")
		.args(["-axo", "pid=,ppid="])
		.output()
		.map_err(|e| format!("ps: {e}"))?;
	let text = String::from_utf8_lossy(&output.stdout);
	let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
	for line in text.lines() {
		let mut parts = line.split_whitespace();
		let (Some(pid), Some(parent)) = (parts.next(), parts.next()) else { continue };
		let (Ok(pid), Ok(parent)) = (pid.parse::<u32>(), parent.parse::<u32>()) else { continue };
		children.entry(parent).or_default().push(pid);
	}
	let mut tree = vec![root_pid];
	let mut index = 0;
	while index < tree.len() {
		let pid = tree[index];
		index += 1;
		if let Some(kids) = children.get(&pid) {
			tree.extend(kids.iter().copied());
		}
	}
	Ok(tree)
}

#[cfg(target_os = "macos")]
fn listeners_for(pids: &[u32]) -> Result<Vec<Listener>, String> {
	let list = pids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
	let output = std::process::Command::new("/usr/sbin/lsof")
		.args(["-nP", "-a", "-p", &list, "-iTCP", "-sTCP:LISTEN", "-F", "pn"])
		.output()
		.map_err(|e| format!("lsof: {e}"))?;
	let text = String::from_utf8_lossy(&output.stdout);
	let mut listeners = Vec::new();
	let mut pid = 0u32;
	for line in text.lines() {
		if let Some(value) = line.strip_prefix('p') {
			pid = value.parse().unwrap_or(0);
		} else if let Some(value) = line.strip_prefix('n')
			&& let Some((address, port)) = value.rsplit_once(':')
			&& let Ok(port) = port.parse()
		{
			let address = address.trim_start_matches('[').trim_end_matches(']');
			let address = match address {
				"*" => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
				_ => match address.parse() {
					Ok(address) => address,
					Err(_) => continue,
				},
			};
			listeners.push(Listener { address, port, pid });
		}
	}
	listeners.sort_by_key(|l| (l.port, l.address.to_string()));
	Ok(listeners)
}

#[cfg(windows)]
fn process_tree(root_pid: u32) -> Result<Vec<u32>, String> {
	use std::collections::HashMap;
	let script = "Get-CimInstance Win32_Process | ForEach-Object { '{0} {1}' -f $_.ProcessId,$_.ParentProcessId }";
	let text = powershell(script)?;
	let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
	for line in text.lines() {
		let mut parts = line.split_whitespace();
		let (Some(pid), Some(parent)) = (parts.next(), parts.next()) else { continue };
		let (Ok(pid), Ok(parent)) = (pid.parse::<u32>(), parent.parse::<u32>()) else { continue };
		children.entry(parent).or_default().push(pid);
	}
	let mut tree = vec![root_pid];
	let mut index = 0;
	while index < tree.len() {
		let pid = tree[index];
		index += 1;
		if let Some(kids) = children.get(&pid) {
			tree.extend(kids.iter().copied());
		}
	}
	Ok(tree)
}

#[cfg(windows)]
fn listeners_for(pids: &[u32]) -> Result<Vec<Listener>, String> {
	use std::collections::HashSet;
	let script = "Get-NetTCPConnection -State Listen | ForEach-Object { '{0} {1} {2}' -f $_.LocalAddress,$_.LocalPort,$_.OwningProcess }";
	let text = powershell(script)?;
	let pids: HashSet<u32> = pids.iter().copied().collect();
	let mut listeners = Vec::new();
	for line in text.lines() {
		let mut parts = line.split_whitespace();
		let (Some(address), Some(port), Some(pid)) = (parts.next(), parts.next(), parts.next()) else { continue };
		let (Ok(address), Ok(port), Ok(pid)) = (address.parse(), port.parse(), pid.parse::<u32>()) else { continue };
		if pids.contains(&pid) {
			listeners.push(Listener { address, port, pid });
		}
	}
	listeners.sort_by_key(|l| (l.port, l.address.to_string()));
	Ok(listeners)
}

#[cfg(windows)]
fn powershell(script: &str) -> Result<String, String> {
	use std::os::windows::process::CommandExt;
	const CREATE_NO_WINDOW: u32 = 0x0800_0000;
	let output = std::process::Command::new("powershell")
		.args(["-NoProfile", "-NonInteractive", "-Command", script])
		.creation_flags(CREATE_NO_WINDOW)
		.output()
		.map_err(|e| format!("powershell: {e}"))?;
	if !output.status.success() {
		return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
	}
	Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn process_tree(_root_pid: u32) -> Result<Vec<u32>, String> {
	Err("listener discovery is not implemented on this platform".to_owned())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn listeners_for(_pids: &[u32]) -> Result<Vec<Listener>, String> {
	Err("listener discovery is not implemented on this platform".to_owned())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn listener(address: &str, port: u16) -> Listener {
		Listener { address: address.parse().unwrap(), port, pid: 1 }
	}

	#[test]
	fn selects_the_requested_port() {
		let listeners = vec![listener("127.0.0.1", 3000), listener("127.0.0.1", 5173)];
		assert_eq!(select(&listeners, Some(5173), false).unwrap(), "127.0.0.1:5173");
		assert_eq!(select(&listeners, Some(4000), false), Err(SelectError::NoListener));
	}

	#[test]
	fn refuses_ambiguous_ports() {
		let listeners = vec![listener("127.0.0.1", 3000), listener("127.0.0.1", 5173)];
		assert!(matches!(select(&listeners, None, false), Err(SelectError::Ambiguous(_))));
	}

	#[test]
	fn prefers_loopback_for_wildcard_binds() {
		let listeners = vec![listener("0.0.0.0", 3000)];
		assert_eq!(select(&listeners, None, false).unwrap(), "127.0.0.1:3000");
	}

	#[test]
	fn formats_ipv6_targets_with_brackets() {
		let listeners = vec![listener("::1", 3000)];
		assert_eq!(select(&listeners, None, false).unwrap(), "[::1]:3000");
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn finds_a_listener_owned_by_a_child() {
		use std::io::{BufRead, BufReader};
		use std::process::{Command, Stdio};

		let script = "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); print(s.getsockname()[1], flush=True); time.sleep(30)";
		let Ok(mut child) = Command::new("python3")
			.args(["-c", script])
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.spawn()
		else {
			return;
		};
		let stdout = child.stdout.take().expect("stdout");
		let mut line = String::new();
		BufReader::new(stdout).read_line(&mut line).unwrap();
		let port: u16 = line.trim().parse().unwrap();

		let listeners = discover(child.id()).unwrap();
		assert!(
			listeners
				.iter()
				.any(|l| l.pid == child.id() && l.port == port && l.address.is_loopback()),
			"listeners: {listeners:?}"
		);
		let _ = child.kill();
		let _ = child.wait();
	}
}
