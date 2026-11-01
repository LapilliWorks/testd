import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import json
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load(name, path):
	spec = importlib.util.spec_from_file_location(name, path)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


release = load('release', ROOT / 'scripts/release.py')
runner = load('release_checks', ROOT / 'tests/release/run.py')


class ReleaseTests(unittest.TestCase):
	def test_workspace_versions_match(self):
		release.check_version('0.1.0')
		with self.assertRaises(ValueError):
			release.check_version('0.2.0')

	def test_homebrew_definitions_use_real_cached_bytes_and_both_architectures(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			for name in ['testd-0.1.0-source.tar.gz', 'Testd_0.1.0_aarch64.dmg', 'Testd_0.1.0_x64.dmg']:
				(root / name).write_bytes(name.encode())
			release.homebrew(SimpleNamespace(version='0.1.0', artifacts=root, output=root / 'tap'))
			formula = (root / 'tap/testd.rb').read_text()
			cask = (root / 'tap/testd-gui.rb').read_text()
			self.assertIn(release.digest(root / 'testd-0.1.0-source.tar.gz'), formula)
			self.assertIn(release.digest(root / 'Testd_0.1.0_aarch64.dmg'), cask)
			self.assertIn(release.digest(root / 'Testd_0.1.0_x64.dmg'), cask)
			self.assertNotIn('@VERSION@', formula + cask)
			self.assertIn('arch arm:', cask)
			self.assertIn('doctor --json", 1', formula)

	def test_checksums_detect_modification_and_unlisted_files(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			artifact = root / 'binary'
			artifact.write_bytes(b'original')
			release.checksums(root)
			runner.verify_checksums(root)
			(root / 'unlisted').write_bytes(b'extra')
			with self.assertRaises(ValueError):
				runner.verify_checksums(root)
			artifact.write_bytes(b'changed')
			with self.assertRaises(ValueError):
				runner.verify_checksums(root)

	def test_sbom_staging_is_independent_of_tool_filenames(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			for relative, name in [('.', 'testd'), ('src-tauri', 'testd-gui'), ('crates/testd-core', 'testd-core')]:
				member = root / relative
				member.mkdir(parents=True, exist_ok=True)
				(member / 'Cargo.toml').write_text(f'[package]\nname = "{name}"\n')
				(member / 'bom.json').write_text(json.dumps({'bomFormat': 'CycloneDX',
					'metadata': {'component': {'name': name}}}))
			with patch.object(release, 'ROOT', root):
				release.collect_sbom(root / 'staged')
			self.assertEqual(len(list((root / 'staged').glob('*.cdx.json'))), 3)

	def test_archive_paths_cannot_escape_the_report_directory(self):
		for path in ['../private', '/etc/passwd', 'C:/Windows/file', '..\\private']:
			with self.subTest(path=path), self.assertRaises(ValueError):
				runner.safe_members([path])
		runner.safe_members(['testd-0.1.0/testd', 'testd-0.1.0/README.md'])

	def test_upgrade_preserves_values_but_allows_new_defaults(self):
		before = {'host': {'tld': 'localhost', 'secret': 'original'}}
		runner.assert_preserved_config(before, {'host': {**before['host'], 'new_default': 1}})
		with self.assertRaises(RuntimeError):
			runner.assert_preserved_config(before, {'host': {'tld': 'localhost', 'secret': 'changed'}})

	def test_manual_checks_are_not_invented_from_headings(self):
		items = runner.checklist_items('# Build\n- [ ] First check\n      continued\n\n- [ ] Second check\n')
		self.assertEqual(items, ['First check continued', 'Second check'])


if __name__ == '__main__':
	unittest.main()
