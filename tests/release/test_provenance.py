import contextlib
import importlib.util
import io
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('provenance_runner', ROOT / 'tests/release/run.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@unittest.skipUnless(shutil.which('git'), 'Git is not installed')
class ProvenanceTests(unittest.TestCase):
	def fixture(self, temporary):
		root = pathlib.Path(temporary)
		repository = root / 'repo'
		repository.mkdir()
		env = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': str(root / 'no-git-config')}
		def git(*args):
			return subprocess.run(['git', *args], cwd=repository, env=env, capture_output=True,
				check=True, timeout=30).stdout
		git('init', '-q')
		(repository / 'tracked.txt').write_bytes(b'before\n')
		(repository / 'mode.sh').write_bytes(b'#!/bin/sh\n')
		git('add', 'tracked.txt', 'mode.sh')
		git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
			'commit', '-q', '--no-verify', '-m', 'fixture')
		return root, repository, env, git

	def test_opt_in_retains_tracked_changes_and_mode_without_untracked_contents(self):
		with tempfile.TemporaryDirectory() as temporary:
			root, repository, env, git = self.fixture(temporary)
			tracked = repository / 'tracked.txt'
			tracked.write_bytes(b'staged change\n')
			git('add', 'tracked.txt')
			git('update-index', '--chmod=+x', 'mode.sh')
			tracked.write_bytes(b'unstaged change\n')
			untracked = repository / 'untracked.txt'
			untracked.write_bytes(b'private untracked fixture\n')
			args = SimpleNamespace(report=root / 'report', suite='fixture', include_git_diff=True)
			with patch.object(runner, 'ROOT', repository), patch.dict(os.environ, env, clear=True), \
					contextlib.redirect_stdout(io.StringIO()):
				run = runner.Run(args)
			staged = (run.output / 'git-diff-staged.patch').read_bytes()
			unstaged = (run.output / 'git-diff-unstaged.patch').read_bytes()
			self.assertIn(b'staged change', staged)
			self.assertIn(b'old mode 100644\nnew mode 100755', staged)
			self.assertIn(b'unstaged change', unstaged)
			self.assertNotIn(b'private untracked fixture', staged + unstaged)
			self.assertEqual(run.metadata['source_diff']['untracked_contents'], 'not captured')
			self.assertTrue(run.metadata['source_diff']['consistent'])
			self.assertFalse(run.metadata.get('incomplete', False))
			self.assertEqual(git('show', ':tracked.txt'), b'staged change\n')
			self.assertEqual(tracked.read_bytes(), b'unstaged change\n')
			self.assertEqual(untracked.read_bytes(), b'private untracked fixture\n')

	def test_tracked_changes_during_capture_mark_report_incomplete(self):
		with tempfile.TemporaryDirectory() as temporary:
			root, repository, env, _ = self.fixture(temporary)
			args = SimpleNamespace(report=root / 'report', suite='fixture', include_git_diff=True)
			with patch.object(runner, 'ROOT', repository), patch.dict(os.environ, env, clear=True), \
					patch.object(runner, 'git_diff', side_effect=[b'before', b'', b'after', b'']), \
					contextlib.redirect_stdout(io.StringIO()):
				run = runner.Run(args)
			self.assertFalse(run.metadata['source_diff']['consistent'])
			self.assertTrue(run.metadata['incomplete'])
			self.assertEqual(run.results[-1]['name'], 'source-provenance')
			self.assertEqual(run.results[-1]['status'], 'skip')

	def test_default_does_not_save_git_diffs(self):
		with tempfile.TemporaryDirectory() as temporary:
			root, repository, env, _ = self.fixture(temporary)
			(repository / 'tracked.txt').write_text('change\n', encoding='utf-8')
			args = SimpleNamespace(report=root / 'report', suite='fixture')
			with patch.object(runner, 'ROOT', repository), patch.dict(os.environ, env, clear=True), \
					contextlib.redirect_stdout(io.StringIO()):
				run = runner.Run(args)
			self.assertTrue(run.metadata['dirty'])
			self.assertNotIn('source_diff', run.metadata)
			self.assertFalse(list(run.output.glob('git-diff-*.patch')))


if __name__ == '__main__':
	unittest.main()
