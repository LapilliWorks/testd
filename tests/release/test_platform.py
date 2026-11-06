import contextlib
import importlib.util
import io
import os
import pathlib
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

	def test_defaults_to_the_automated_sequence(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script.runner, 'main', return_value=0) as run:
			self.assertEqual(self.script.main('Linux', []), 0)
			run.assert_called_once_with(['automated'])

	def test_gui_option_is_forwarded_to_automated_checks(self):
		with patch.object(self.script.platform, 'system', return_value='Darwin'), \
			patch.object(self.script.runner, 'main', return_value=0) as run:
			self.script.main('Darwin', ['--gui'])
			run.assert_called_once_with(['automated', '--gui'])

	def test_wrong_platform_fails_without_running_a_suite(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script.runner, 'main') as run, contextlib.redirect_stderr(io.StringIO()):
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
				patch.object(self.script.runner, 'main', return_value=0) as run:
				self.script.main('Linux', ['host', '--bin', str(candidate), '--report', str(report)])
				run.assert_called_once_with(['host', '--bin', str(candidate), '--report', str(report)])
				self.assertFalse(report.exists())
			with patch.object(self.script.platform, 'system', return_value='Linux'), \
				patch.object(self.script.runner, 'main') as run, contextlib.redirect_stderr(io.StringIO()):
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
				patch.object(self.script.runner, 'main', return_value=0) as run:
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
				patch.object(self.script.sys, 'stdin', terminal), patch.object(self.script.runner, 'main', return_value=0) as run, \
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
				patch.object(self.script.runner, 'main') as run, contextlib.redirect_stderr(io.StringIO()):
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
				patch.object(self.script.runner, 'main', return_value=0) as run:
				desktop = ['desktop', '--app', str(candidate), '--report', str(root / 'desktop')]
				self.script.main('Windows', desktop)
				run.assert_called_with(desktop)
				browser = ['browser', '--bin', str(candidate), '--report', str(root / 'browser'), '--edge-port', '8443']
				self.script.main('Windows', browser)
				run.assert_called_with(browser)

	def test_invalid_or_irrelevant_options_fail_before_running_a_suite(self):
		with patch.object(self.script.platform, 'system', return_value='Linux'), \
			patch.object(self.script.runner, 'main') as run, contextlib.redirect_stderr(io.StringIO()):
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
