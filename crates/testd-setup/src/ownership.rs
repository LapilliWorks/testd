//! Private identity used to distinguish installations sharing system state.

use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(super) struct InstallationId(String);

impl InstallationId {
	pub(super) fn load() -> io::Result<Option<Self>> {
		Self::load_at(&ownership_path())
	}

	pub(super) fn load_or_create() -> io::Result<Self> {
		Self::load_or_create_at(&ownership_path())
	}

	pub(super) fn as_str(&self) -> &str {
		&self.0
	}

	fn load_at(path: &Path) -> io::Result<Option<Self>> {
		let metadata = match std::fs::symlink_metadata(path) {
			Ok(metadata) => metadata,
			Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
			Err(error) => return Err(error),
		};
		if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				format!("{} must be a private regular file", path.display()),
			));
		}
		let content = std::fs::read_to_string(path)?;
		let value = content.trim();
		let valid = covo::decode(value).is_ok_and(|bytes| bytes.len() == 16 && covo::encode(&bytes) == value);
		if !valid {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!("invalid ownership ID at {}", path.display()),
			));
		}
		Ok(Some(Self(value.to_owned())))
	}

	fn load_or_create_at(path: &Path) -> io::Result<Self> {
		if let Some(id) = Self::load_at(path)? {
			return Ok(id);
		}
		let parent = path
			.parent()
			.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent"))?;
		std::fs::create_dir_all(parent)?;
		let value = testd_core::config::generate_operator_secret()?;
		let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
			Ok(file) => file,
			Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
				return Self::load_at(path)?.ok_or(error);
			},
			Err(error) => return Err(error),
		};
		file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
		writeln!(file, "{value}")?;
		file.sync_all()?;
		std::fs::File::open(parent)?.sync_all()?;
		Ok(Self(value))
	}
}

fn ownership_path() -> PathBuf {
	testd_core::config::config_dir().join("system-ownership-id")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn creates_a_private_id_and_reuses_it() {
		let fixture = tempfile::tempdir().unwrap();
		let path = fixture.path().join("state/system-ownership-id");
		let first = InstallationId::load_or_create_at(&path).unwrap();
		let second = InstallationId::load_or_create_at(&path).unwrap();
		assert_eq!(first.as_str(), second.as_str());
		assert_eq!(covo::decode(first.as_str()).unwrap().len(), 16);
		assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
	}

	#[test]
	fn concurrent_creation_never_replaces_the_winning_id() {
		use std::sync::{Arc, Barrier};

		let fixture = tempfile::tempdir().unwrap();
		let path = fixture.path().join("system-ownership-id");
		let barrier = Arc::new(Barrier::new(8));
		let results = std::thread::scope(|scope| {
			let mut threads = Vec::new();
			for _ in 0..8 {
				let barrier = Arc::clone(&barrier);
				let path = &path;
				threads.push(scope.spawn(move || {
					barrier.wait();
					InstallationId::load_or_create_at(path).map(|id| id.0)
				}));
			}
			threads.into_iter().map(|thread| thread.join().unwrap()).collect::<Vec<_>>()
		});
		let winner = InstallationId::load_at(&path).unwrap().unwrap();
		let successes: Vec<_> = results.iter().filter_map(|result| result.as_ref().ok()).collect();
		assert!(!successes.is_empty());
		assert!(successes.iter().all(|id| id.as_str() == winner.as_str()));
	}

	#[test]
	fn rejects_public_or_invalid_ids_without_changing_them() {
		let fixture = tempfile::tempdir().unwrap();
		let path = fixture.path().join("system-ownership-id");
		std::fs::write(&path, "not an ownership id\n").unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
		assert_eq!(InstallationId::load_or_create_at(&path).err().unwrap().kind(), io::ErrorKind::PermissionDenied);
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
		assert_eq!(InstallationId::load_or_create_at(&path).err().unwrap().kind(), io::ErrorKind::InvalidData);
		assert_eq!(std::fs::read_to_string(path).unwrap(), "not an ownership id\n");
	}

	#[test]
	fn refuses_a_symlink_instead_of_following_it() {
		let fixture = tempfile::tempdir().unwrap();
		let target = fixture.path().join("target");
		std::fs::write(&target, "leave me").unwrap();
		let path = fixture.path().join("system-ownership-id");
		std::os::unix::fs::symlink(&target, &path).unwrap();
		assert_eq!(InstallationId::load_or_create_at(&path).err().unwrap().kind(), io::ErrorKind::PermissionDenied);
		assert_eq!(std::fs::read_to_string(target).unwrap(), "leave me");
	}
}
