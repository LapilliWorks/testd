import contextlib
import importlib.util
import io
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/test_platform.py'


def load_script():
	spec = importlib.util.spec_from_file_location('testd_platform_scripts', SCRIPT)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


class PlatformScriptsTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.script = load_script()

	def test_release_runner_can_expose_a_zero_argument_main(self):
		original_argv = sys.argv
		observed = []
		def zero_argument_main():
			observed.append(sys.argv[1:])
			return 7
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script.runner, 'main', side_effect=zero_argument_main) as run:
			self.assertEqual(self.script.main('Linux', []), 7)
			run.assert_called_once_with()
		self.assertEqual(observed, [['automated']])
		self.assertIs(sys.argv, original_argv)

	def test_entry_point_accepts_a_zero_argument_release_runner(self):
		name = {'Linux': 'linux', 'Darwin': 'macos', 'Windows': 'windows'}.get(platform.system())
		if name is None:
			self.skipTest('the platform entry points cover Linux, macOS, and Windows')
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory).resolve()
			(root / 'scripts').mkdir()
			(root / 'tests/release').mkdir(parents=True)
			shutil.copy2(ROOT / f'scripts/test-{name}.py', root / f'scripts/test-{name}.py')
			shutil.copy2(SCRIPT, root / 'scripts/test_platform.py')
			runner = root / 'tests/release/run.py'
			runner.write_text('import json,sys\n'
				'def stub(): pass\n'
				'automated=contracts=audit=native_build_target=backup_build_candidate=candidate_build_environment=stub\n'
				'def main():\n\tprint(json.dumps(sys.argv[1:]))\n\treturn 0\n', encoding='utf-8')
			report = root / 'report'
			result = subprocess.run([sys.executable, str(root / f'scripts/test-{name}.py'), '--gui',
				'--report', str(report)], cwd=root, capture_output=True, text=True, timeout=10)
			self.assertEqual(result.returncode, 0, result.stderr)
			self.assertEqual(json.loads(result.stdout), ['automated', '--gui', '--report', str(report)])
			self.assertFalse(report.exists())

	def test_release_runner_arguments_are_restored_after_an_exception(self):
		original_argv = sys.argv
		for error in (RuntimeError('fixture'), SystemExit(2)):
			with self.subTest(error=type(error).__name__), patch.object(self.script.runner, 'main', side_effect=error):
				with self.assertRaises(type(error)):
					self.script.run_cli(['contracts'])
			self.assertIs(sys.argv, original_argv)

	def test_outdated_release_runner_fails_with_an_actionable_message(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script.runner, 'automated', None), patch.object(self.script.runner, 'main') as run, \
			contextlib.redirect_stderr(io.StringIO()) as stderr:
			with self.assertRaises(SystemExit) as error:
				self.script.main('Linux', [])
			self.assertEqual(error.exception.code, 2)
			self.assertIn('tests/release/run.py', stderr.getvalue())
			self.assertIn('out of sync', stderr.getvalue())
			run.assert_not_called()

	def test_defaults_to_the_automated_sequence(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script, 'run_cli', return_value=0) as run:
			self.assertEqual(self.script.main('Linux', []), 0)
			run.assert_called_once_with(['automated'])

	def test_gui_option_is_forwarded_to_automated_checks(self):
		with patch.object(self.script.platform, 'system', return_value='Darwin'), \
			patch.object(self.script, 'run_cli', return_value=0) as run:
			self.script.main('Darwin', ['--gui'])
			run.assert_called_once_with(['automated', '--gui'])

	def test_all_defaults_to_an_automatically_built_candidate(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script, 'run_cli', return_value=2) as run:
			self.assertEqual(self.script.main('Linux', ['all']), 2)
			run.assert_called_once_with(['all'])

	def test_all_forwards_candidates_artifacts_and_explicit_system_scope(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory).resolve()
			cli = root / 'candidate'
			app = root / 'app'
			assets = root / 'assets'
			cli.write_text('fixture', encoding='utf-8')
			app.write_text('fixture', encoding='utf-8')
			assets.mkdir()
			report = root / 'report'
			arguments = ['all', '--bin', str(cli), '--app', str(app), '--artifacts', str(assets),
				'--no-previous-release', '--interactive', '--report', str(report), '--system']
			with patch.object(self.script.platform, 'system', return_value='Windows'), \
				patch.object(self.script, 'is_ephemeral_report', return_value=False), \
				patch.object(self.script, 'run_cli', return_value=0) as run:
				self.assertEqual(self.script.main('Windows', arguments), 0)
				run.assert_called_once_with(arguments)
			self.assertFalse(report.exists())

	def test_all_requires_the_matching_orchestrator(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script.runner, 'all_suites', None), patch.object(self.script, 'run_cli') as run, \
			contextlib.redirect_stderr(io.StringIO()) as stderr:
			with self.assertRaises(SystemExit) as error:
				self.script.main('Linux', ['all'])
			self.assertEqual(error.exception.code, 2)
			self.assertIn('out of sync', stderr.getvalue())
			run.assert_not_called()

	def test_all_reports_a_missing_doctest_output_helper(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory).resolve()
			(root / 'tests/release').mkdir(parents=True)
			(root / 'tests/release/all_checks.py').touch()
			with patch.object(self.script, 'ROOT', root), patch.object(self.script.platform, 'system', return_value='Linux'), \
				patch.object(self.script, 'run_cli') as run, contextlib.redirect_stderr(io.StringIO()) as stderr:
				with self.assertRaises(SystemExit) as error:
					self.script.main('Linux', ['all'])
				self.assertEqual(error.exception.code, 2)
				self.assertIn('doctest_output.py', stderr.getvalue())
				run.assert_not_called()

	def test_all_rejects_incomplete_or_irrelevant_options(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script, 'run_cli') as run, contextlib.redirect_stderr(io.StringIO()):
			for arguments in (['all', '--interactive'], ['all', '--system'], ['all', '--app', 'candidate'],
				['all', '--previous-bin', 'candidate'], ['automated', '--plan'], ['contracts', '--artifacts', 'assets']):
				with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
					self.script.main('Linux', arguments)
			run.assert_not_called()

	def test_wrong_platform_fails_without_running_a_suite(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script, 'run_cli') as run, contextlib.redirect_stderr(io.StringIO()):
			with self.assertRaises(SystemExit) as error:
				self.script.main('Windows', [])
			self.assertEqual(error.exception.code, 2)
			run.assert_not_called()

	def test_host_requires_a_candidate_and_a_new_report(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory).resolve()
			candidate = root / 'testd'
			candidate.write_text('fixture', encoding='utf-8')
			report = root / 'report'
			with patch.object(self.script.platform, 'system', return_value='Linux'), \
				patch.object(self.script, 'run_cli', return_value=0) as run:
				self.script.main('Linux', ['host', '--bin', str(candidate), '--report', str(report)])
				run.assert_called_once_with(['host', '--bin', str(candidate), '--report', str(report)])
				self.assertFalse(report.exists())
			with patch.object(self.script.platform, 'system', return_value='Linux'), \
				patch.object(self.script, 'run_cli') as run, contextlib.redirect_stderr(io.StringIO()):
				for arguments in (['host'], ['host', '--bin', str(candidate)],
					['host', '--bin', str(candidate), '--report', str(candidate)]):
					with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
						self.script.main('Linux', arguments)
				run.assert_not_called()

	def test_host_can_build_a_candidate_only_when_explicitly_requested(self):
		with tempfile.TemporaryDirectory() as directory:
			report = pathlib.Path(directory).resolve() / 'report'
			with patch.object(self.script.platform, 'system', return_value='Linux'), \
				patch.object(self.script, 'is_ephemeral_report', return_value=False), \
				patch.object(self.script, 'run_cli', return_value=0) as run:
				self.script.main('Linux', ['host', '--build', '--report', str(report)])
				run.assert_called_once_with(['host', '--report', str(report)])
			self.assertFalse(report.exists())

	def test_system_host_checks_require_an_interactive_affirmative_confirmation(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory).resolve()
			candidate = root / 'testd'
			candidate.write_text('fixture', encoding='utf-8')
			arguments = ['host', '--bin', str(candidate), '--report', str(root / 'report'), '--system']
			terminal = Mock()
			with patch.object(self.script.platform, 'system', return_value='Linux'), \
				patch.object(self.script, 'is_ephemeral_report', return_value=False), \
				patch.object(self.script.sys, 'stdin', terminal), patch.object(self.script, 'run_cli', return_value=0) as run, \
				contextlib.redirect_stderr(io.StringIO()):
				terminal.isatty.return_value = False
				with self.assertRaises(SystemExit):
					self.script.main('Linux', arguments)
				run.assert_not_called()
				terminal.isatty.return_value = True
				with patch('builtins.input', return_value='no'):
					with self.assertRaises(SystemExit):
						self.script.main('Linux', arguments)
				run.assert_not_called()
				with patch('builtins.input', return_value='yes'):
					self.script.main('Linux', arguments)
				run.assert_called_once_with(arguments)

	def test_privileged_and_desktop_reports_cannot_be_in_the_temp_directory(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory).resolve()
			candidate = root / 'candidate'
			candidate.write_text('fixture', encoding='utf-8')
			with patch.object(self.script.platform, 'system', return_value='Linux'), \
				patch.object(self.script, 'run_cli') as run, contextlib.redirect_stderr(io.StringIO()):
				for arguments in (['host', '--bin', str(candidate), '--report', str(root / 'host'), '--system'],
					['host', '--build', '--report', str(root / 'build')],
					['desktop', '--app', str(candidate), '--report', str(root / 'desktop')]):
					with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
						self.script.main('Linux', arguments)
				run.assert_not_called()

	def test_desktop_and_browser_forward_only_relevant_options(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory).resolve()
			candidate = root / 'candidate'
			candidate.write_text('fixture', encoding='utf-8')
			with patch.object(self.script.platform, 'system', return_value='Windows'), \
				patch.object(self.script, 'is_ephemeral_report', return_value=False), \
				patch.object(self.script, 'run_cli', return_value=0) as run:
				desktop = ['desktop', '--app', str(candidate), '--report', str(root / 'desktop')]
				self.script.main('Windows', desktop)
				run.assert_called_with(desktop)
				browser = ['browser', '--bin', str(candidate), '--report', str(root / 'browser'), '--edge-port', '8443']
				self.script.main('Windows', browser)
				run.assert_called_with(browser)

	def test_invalid_or_irrelevant_options_fail_before_running_a_suite(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script, 'run_cli') as run, contextlib.redirect_stderr(io.StringIO()):
			for arguments in (['--system'], ['contracts', '--gui'], ['audit', '--port', '2'],
				['automated', '--build'], ['host', '--build', '--bin', 'candidate'],
				['browser', '--port', '65535'], ['browser', '--edge-port', '0']):
				with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
					self.script.main('Linux', arguments)
			run.assert_not_called()

	def test_platform_entry_points_offer_help_without_launching_a_suite(self):
		for name in ('linux', 'macos', 'windows'):
			with self.subTest(platform=name):
				result = subprocess.run([sys.executable, str(ROOT / f'scripts/test-{name}.py'), '--help'],
					cwd=ROOT, capture_output=True, text=True, timeout=10)
				self.assertEqual(result.returncode, 0, result.stderr)
				self.assertIn('automated', result.stdout)
				self.assertIn('host', result.stdout)

	def test_entry_points_ignore_a_preloaded_shadow_module(self):
		for name in ('linux', 'macos', 'windows'):
			with self.subTest(platform=name):
				script = str(ROOT / f'scripts/test-{name}.py')
				code = ("import runpy,sys,types; module=types.ModuleType('test_platform'); "
					"module.main=lambda: 0; sys.modules['test_platform']=module; "
					f"sys.argv=[{script!r}, '--help']; runpy.run_path({script!r}, run_name='__main__')")
				result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True, timeout=10)
				self.assertEqual(result.returncode, 0, result.stderr)
				self.assertIn('automated', result.stdout)

	def test_entry_points_ignore_shadow_modules_with_safe_path_enabled(self):
		with tempfile.TemporaryDirectory() as directory:
			(pathlib.Path(directory) / 'test_platform.py').write_text('def main():\n\treturn 0\n', encoding='utf-8')
			env = {**os.environ, 'PYTHONPATH': directory, 'PYTHONSAFEPATH': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
			for name in ('linux', 'macos', 'windows'):
				with self.subTest(platform=name):
					result = subprocess.run([sys.executable, str(ROOT / f'scripts/test-{name}.py'), '--help'],
						cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
					self.assertEqual(result.returncode, 0, result.stderr)
					self.assertIn('automated', result.stdout)


if __name__ == '__main__':
	unittest.main()
