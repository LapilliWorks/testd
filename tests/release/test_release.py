import importlib.util
import hashlib
import io
import locale
import os
import pathlib
import re
import shutil
import signal
import tempfile
import unittest
import subprocess
import sys
import threading
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch
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
state = load('system_state', ROOT / 'tests/release/system_state.py')


class ReleaseTests(unittest.TestCase):
	def test_advisory_exceptions_are_limited_to_the_dbus_merger(self):
		policy = release.tomllib.loads((ROOT / 'deny.toml').read_text())
		self.assertEqual(set(policy['advisories']['ignore']), {
			'RUSTSEC-2026-0370', 'RUSTSEC-2026-0371', 'RUSTSEC-2026-0372',
		})
		self.assertNotIn('unmaintained', policy['advisories'])
		self.assertEqual(policy['bans']['wildcards'], 'deny')
		self.assertIn({'name': 'openssl'}, policy['bans']['deny'])

	def test_core_and_ci_checks_match_declared_msrvs(self):
		run = Mock(args=SimpleNamespace(gui=True, strict=True))
		with patch.object(runner.shutil, 'which', return_value='installed'):
			runner.core(run)
		commands = {call.args[0]: call.args[1] for call in run.command.call_args_list}
		workspace = release.tomllib.loads((ROOT / 'Cargo.toml').read_text())
		tray = release.tomllib.loads((ROOT / 'src-tauri/Cargo.toml').read_text())
		workflow = (ROOT / '.github/workflows/ci.yml').read_text()
		for name, version in [
			('msrv-cli', workspace['workspace']['package']['rust-version']),
			('msrv-tray', tray['package']['rust-version']),
		]:
			with self.subTest(name=name):
				self.assertEqual(commands[name][1], f'+{version}.0')
				self.assertIn(f"toolchain: '{version}.0'", workflow)

	def test_notification_dependency_is_not_downgraded_to_4_17(self):
		manifest = release.tomllib.loads((ROOT / 'crates/testd-daemon/Cargo.toml').read_text())
		self.assertEqual(manifest['dependencies']['notify-rust'], '4.18')

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


class ConsoleOutputTests(unittest.TestCase):
	"""PowerShell decodes a child's bytes with the console code page, not UTF-8."""

	def test_redirected_output_follows_the_console_code_page(self):
		stream = Mock()
		stream.isatty.return_value = False
		with patch.object(runner, 'SYSTEM', 'Windows'), \
			patch.object(runner, 'console_code_page', return_value=936), \
			patch.object(runner.sys, 'stdout', stream), patch.object(runner.sys, 'stderr', stream):
			runner.match_redirected_encoding()
		self.assertEqual(stream.reconfigure.call_count, 2)
		stream.reconfigure.assert_called_with(encoding='cp936', errors='replace')

	def test_utf8_console_and_attached_terminals_keep_utf8(self):
		for code_page, terminal in [(65001, False), (936, True), (0, False)]:
			with self.subTest(code_page=code_page, terminal=terminal):
				stream = Mock()
				stream.isatty.return_value = terminal
				with patch.object(runner, 'SYSTEM', 'Windows'), \
					patch.object(runner, 'console_code_page', return_value=code_page), \
					patch.object(runner.sys, 'stdout', stream), patch.object(runner.sys, 'stderr', stream):
					runner.match_redirected_encoding()
				stream.reconfigure.assert_not_called()

	def test_other_platforms_are_untouched(self):
		with patch.object(runner, 'SYSTEM', 'Linux'):
			self.assertIsNone(runner.console_encoding())


class FakeHost(state.Host):
	"""In-memory host so the snapshot and restore rules run without root."""

	def __init__(self, system='Linux', tld='testdcheck'):
		super().__init__(system, tld)
		self.files = {}
		self.certificates = {}
		self.commands = []

	def command(self, argv, privileged=False):
		argv = [str(item) for item in argv]
		self.commands.append((argv, privileged))
		if argv[0] == 'install':
			self.files[argv[-1]] = pathlib.Path(argv[-2]).read_bytes()
		elif argv[0] == 'rm':
			self.files.pop(argv[-1], None)
		elif argv[:2] == ['security', 'find-certificate']:
			return ''.join(state.encode_pem(der) for der in self.certificates.values())
		elif argv[:2] == ['security', 'delete-certificate']:
			self.certificates.pop(argv[3], None)
		elif argv[:2] == ['security', 'add-trusted-cert']:
			for der in state.decode_pem(pathlib.Path(argv[-1]).read_text()):
				self.certificates[hashlib.sha1(der).hexdigest()] = der
		return ''

	def exists(self, path):
		return str(path) in self.files or str(path) == state.KEYCHAIN

	def read(self, path):
		return self.files[str(path)]

	def mode(self, path):
		return 0o644


class SystemStateTests(unittest.TestCase):
	def test_snapshot_accepts_an_artifact_override(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup, [{'path': '/tmp/self-test-only'}])
			self.assertEqual([entry['path'] for entry in state.load(backup)['files']], ['/tmp/self-test-only'])
			self.assertEqual(len(state.files(host)), 2)

	def test_self_test_artifacts_keep_the_paths_but_drop_the_resolver_reload(self):
		host = FakeHost()
		artifacts = state.self_test_artifacts(host)
		self.assertEqual([entry['path'] for entry in artifacts], [entry['path'] for entry in state.files(host)])
		self.assertEqual([entry['reload'] for entry in artifacts if entry['reload'] and entry['reload'][0] == 'systemctl'], [])

	def test_occupied_reports_integration_the_self_test_cannot_use(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			host.files = {state.files(host)[0]['path']: b'live route'}
			backup = pathlib.Path(temporary) / 'linux'
			state.snapshot(host, backup)
			self.assertEqual(state.occupied(backup), [state.files(host)[0]['path']])
			host = FakeHost('Darwin')
			host.certificates = {hashlib.sha1(b'live root').hexdigest(): b'live root'}
			backup = pathlib.Path(temporary) / 'darwin'
			state.snapshot(host, backup)
			self.assertEqual(len(state.occupied(backup)), 1)
			host = FakeHost('Windows')
			backup = pathlib.Path(temporary) / 'windows'
			state.snapshot(host, backup)
			self.assertEqual(state.occupied(backup), [])
			(backup / 'nrpt.json').write_bytes(
				b'\xef\xbb\xbf' + json.dumps([{'Signature': {'Namespace': '.testdrestore'}}]).encode())
			self.assertEqual(state.occupied(backup), ['NRPT rule for .testdrestore'])

	def test_self_test_refuses_a_host_that_already_has_integration(self):
		host = FakeHost()
		host.files = {state.files(host)[0]['path']: b'live route'}
		with patch.object(state, 'Host', return_value=host), redirect_stdout(io.StringIO()):
			problems = state.self_test('Linux')
		self.assertTrue(any('already installed' in problem for problem in problems), problems)

	def test_restore_targets_match_the_product(self):
		"""The suite must restore the paths testd-setup writes, not a copy of them."""
		setup = (ROOT / 'crates/testd-setup/src/lib.rs').read_text()
		for item in state.files(FakeHost()):
			self.assertIn(item['path'], setup)
		macos = state.files(FakeHost('Darwin', 'testdcheck'))[0]['path']
		self.assertIn(macos.rsplit('/', 1)[0], setup)
		windows = (ROOT / 'tests/release/windows-system-state.ps1').read_text()
		elevated = (ROOT / 'scripts/testd-elevated.ps1').read_text()
		for script in (windows, elevated):
			self.assertIn('+ $Tld', script, 'NRPT namespaces must stay scoped to the TLD')
		self.assertIn('testd root', windows)

	def test_linux_restore_returns_the_exact_previous_bytes(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			resolver, trusted = state.files(host)[0]['path'], state.files(host)[1]['path']
			host.files = {resolver: b'[Resolve]\nDNS=1.1.1.1\n', trusted: b'original root'}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.files = {resolver: b'[Resolve]\nDNS=127.0.0.1:7753\n', trusted: b'test root'}
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(host.files[resolver], b'[Resolve]\nDNS=1.1.1.1\n')
			self.assertEqual(host.files[trusted], b'original root')
			self.assertTrue((backup / state.RESTORED).is_file())

	def test_linux_restore_removes_integration_that_was_absent(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			for item in state.files(host):
				host.files[item['path']] = b'installed by doctor --fix'
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(host.files, {})
			reloads = [argv for argv, _ in host.commands if argv[0] in ('systemctl', 'update-ca-certificates')]
			self.assertEqual(reloads, [item['reload'] for item in state.files(host)])

	def test_restore_is_idempotent(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			host.files = {state.files(host)[1]['path']: b'root'}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.files[state.files(host)[1]['path']] = b'replaced'
			self.assertEqual(state.restore(host, backup), [])
			commands = len(host.commands)
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(host.files[state.files(host)[1]['path']], b'root')
			self.assertEqual(len(host.commands), commands, 'a completed restore should not reload again')

	def test_restore_fixes_a_host_that_drifted_after_a_completed_restore(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			self.assertEqual(state.restore(host, backup), [])
			host.files[state.files(host)[0]['path']] = b'drifted'
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(host.files, {})

	def test_restore_rejects_a_tampered_backup(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			host.files = {state.files(host)[1]['path']: b'root'}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			manifest = state.load(backup)
			(backup / manifest['files'][1]['blob']).write_bytes(b'tampered')
			problems = state.restore(host, backup)
			self.assertTrue(any('modified' in problem for problem in problems), problems)
			self.assertFalse((backup / state.RESTORED).exists())

	def test_verify_reports_drift_after_restore(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.files[state.files(host)[0]['path']] = b'drifted'
			problems = state.verify(host, backup)
			self.assertEqual([problem.split(':')[0] for problem in problems], [state.files(host)[0]['path']])

	def test_macos_restore_deletes_extras_by_thumbprint(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost('Darwin')
			kept, extra = b'kept root', b'extra root'
			host.certificates = {hashlib.sha1(kept).hexdigest(): kept}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.certificates[hashlib.sha1(extra).hexdigest()] = extra
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(list(host.certificates.values()), [kept])
			deletes = [argv for argv, _ in host.commands if argv[:2] == ['security', 'delete-certificate']]
			self.assertEqual(deletes, [['security', 'delete-certificate', '-Z',
				hashlib.sha1(extra).hexdigest(), state.KEYCHAIN]])

	def test_macos_restore_reinstalls_a_missing_root(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost('Darwin')
			root = b'pre-existing root'
			host.certificates = {hashlib.sha1(root).hexdigest(): root}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.certificates = {}
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(list(host.certificates.values()), [root])
			installs = [argv for argv, _ in host.commands if argv[:2] == ['security', 'add-trusted-cert']]
			self.assertEqual(installs[0][2:6], ['-d', '-r', 'trustRoot', '-k'])

	def test_windows_restore_delegates_to_the_elevated_script(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost('Windows')
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			self.assertEqual(state.restore(host, backup), [])
			commands = [argv for argv, _ in host.commands if argv[0] == 'powershell']
			actions = [re.search(r"-Action '([^']+)'", argv[-1]).group(1) for argv in commands]
			self.assertEqual(actions, ['Snapshot', 'Restore', 'Verify'])
			self.assertTrue(all(privileged for argv, privileged in host.commands if argv[0] == 'powershell'))

	def test_windows_commands_force_utf8_and_quote_their_arguments(self):
		# The child has to emit UTF-8 itself: a parse error is printed before the
		# script runs, and 5.1 otherwise uses the console code page for messages.
		script = state.windows_command('Snapshot', "C:\\Users\\o'brien\\state", 'testdcheck')
		self.assertEqual(script[:5], ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command'])
		command = script[-1]
		self.assertIn('[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)', command)
		self.assertIn("-Action 'Snapshot'", command)
		self.assertIn("-Destination 'C:\\Users\\o''brien\\state'", command)
		self.assertIn("-Tld 'testdcheck'", command)
		fixture = state.windows_fixture_command('testdcheck')[-1]
		self.assertIn('[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)', fixture)
		self.assertIn("-Tld 'testdcheck'", fixture)

	def test_snapshot_is_required_and_platform_bound(self):
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(state.HostError):
				state.load(pathlib.Path(temporary) / 'system-before')
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			with self.assertRaises(state.HostError):
				state.restore(FakeHost('Darwin'), backup)


class HostSystemTests(unittest.TestCase):
	def create_run(self, directory):
		args = SimpleNamespace(report=pathlib.Path(directory) / 'report', suite='host',
			system=True, service=False, bin=None)
		with redirect_stdout(io.StringIO()):
			return runner.Run(args)

	def test_failed_host_checks_still_restore_the_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			events = []

			def snapshot(*args, **kwargs):
				events.append('snapshot')
				return pathlib.Path('system-before')

			with patch.object(runner, 'binary', return_value=pathlib.Path('/bin/true')), \
				patch.object(runner, 'check_ports'), \
				patch.object(runner, 'system_snapshot', side_effect=snapshot), \
				patch.object(runner, 'system_restore', side_effect=lambda *a, **k: events.append('restore')), \
				patch.object(run, 'command', side_effect=RuntimeError('host checks failed')):
				with self.assertRaises(RuntimeError):
					runner.host(run)
			self.assertEqual(events, ['snapshot', 'restore'])

	def test_busy_fixture_ports_are_refused_before_the_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			with patch.object(runner, 'binary', return_value=pathlib.Path('/bin/true')), \
				patch.object(runner, 'check_ports', side_effect=RuntimeError('port busy')), \
				patch.object(runner, 'system_snapshot', side_effect=AssertionError('snapshot ran too early')):
				with self.assertRaises(RuntimeError):
					runner.host(run)

	def test_plain_host_run_does_not_touch_system_state(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			run.args.system = False
			with patch.object(runner, 'binary', return_value=pathlib.Path('/bin/true')), \
				patch.object(runner, 'check_ports'), \
				patch.object(runner, 'system_snapshot') as snapshot, \
				patch.object(runner, 'system_restore') as restore, \
				patch.object(run, 'command', return_value='ok    doctor --fix\n'):
				runner.host(run)
			snapshot.assert_not_called()
			restore.assert_not_called()

	def test_system_snapshot_checks_sudo_through_the_terminal(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			fake = SimpleNamespace(Host=lambda *args, **kwargs: None,
				snapshot=lambda host, backup: backup / 'manifest.json')
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'require'), \
				patch.object(runner, 'helper', return_value=fake), \
				patch.object(run, 'command', return_value='') as command, \
				redirect_stdout(io.StringIO()):
				runner.system_snapshot(run, 'testdcheck')
			command.assert_called_once_with('sudo-ready', ['sudo', '-n', 'true'], terminal=True)

	def test_host_checks_keep_the_terminal_only_for_system_runs(self):
		for system in (False, True):
			with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
				run = self.create_run(directory)
				run.args.system = system
				with patch.object(runner, 'binary', return_value=pathlib.Path('/bin/true')), \
					patch.object(runner, 'check_ports'), \
					patch.object(runner, 'system_snapshot'), \
					patch.object(runner, 'system_restore'), \
					patch.object(run, 'command', return_value='ok    doctor --fix\n') as command, \
					redirect_stdout(io.StringIO()):
					runner.host(run)
				self.assertEqual(command.call_args.kwargs['terminal'], system)


class CommandOutputTests(unittest.TestCase):
	def create_run(self, directory):
		args = SimpleNamespace(report=pathlib.Path(directory) / 'report', suite='fixture')
		with redirect_stdout(io.StringIO()):
			return runner.Run(args)

	def test_both_streams_are_mirrored_and_retained(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			stdout, stderr = io.StringIO(), io.StringIO()
			code = "import os; os.write(1, b'output\\n'); os.write(2, b'diagnostic\\n')"
			with redirect_stdout(stdout), redirect_stderr(stderr):
				text = run.command('streams', [sys.executable, '-c', code])
			self.assertIn('output\n', stdout.getvalue())
			self.assertNotIn('\ndiagnostic\n', stdout.getvalue())
			self.assertEqual(stderr.getvalue(), 'diagnostic\n')
			self.assertIn('output\n', text)
			self.assertIn('diagnostic\n', text)
			log = (run.output / '00-streams.log').read_text()
			self.assertIn('output\n', log)
			self.assertIn('diagnostic\n', log)

	def test_utf8_output_is_decoded_where_the_locale_is_not_utf8(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			stdout = io.StringIO()
			code = "import os; os.write(1, 'caf\u00e9 \u251c\u2500 tree\\n'.encode())"
			with redirect_stdout(stdout), redirect_stderr(io.StringIO()), \
				patch.object(locale, 'getpreferredencoding', return_value='cp1252'):
				text = run.command('utf8', [sys.executable, '-c', code])
			self.assertEqual(text, 'café ├─ tree\n')
			self.assertIn('café ├─ tree\n', stdout.getvalue())
			self.assertNotIn('Ã', stdout.getvalue())
			self.assertEqual((run.output / '00-utf8.log').read_bytes(), 'café ├─ tree\n'.encode())

	def test_child_interpreters_are_forced_into_utf8_mode(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			code = "import os; os.write(1, os.environ['PYTHONUTF8'].encode())"
			with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
				self.assertEqual(run.command('utf8-mode', [sys.executable, '-c', code]), '1')

	def test_a_command_environment_keeps_its_own_values(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			env = dict(os.environ, TESTD_ENCODING_MARKER='kept')
			code = "import os; os.write(1, os.environ['TESTD_ENCODING_MARKER'].encode())"
			with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
				self.assertEqual(run.command('env', [sys.executable, '-c', code], env=env), 'kept')

	def test_the_sudo_check_keeps_the_terminal_attached(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			with patch.object(runner.subprocess, 'Popen', wraps=subprocess.Popen) as popen, \
				redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
				run.command('sudo-ready', [sys.executable, '-c', 'pass'], terminal=True)
			self.assertIsNone(popen.call_args.kwargs['stdin'])
			self.assertFalse(popen.call_args.kwargs['start_new_session'])
			if runner.SYSTEM != 'Windows':
				self.assertEqual(popen.call_args.kwargs['process_group'], 0)

	def test_other_checks_detach_from_the_terminal(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			with patch.object(runner.subprocess, 'Popen', wraps=subprocess.Popen) as popen, \
				redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
				run.command('detached', [sys.executable, '-c', 'pass'])
			self.assertIs(popen.call_args.kwargs['stdin'], subprocess.DEVNULL)
			self.assertEqual(popen.call_args.kwargs['start_new_session'], runner.SYSTEM != 'Windows')
			self.assertNotIn('process_group', popen.call_args.kwargs)

	def test_a_detached_child_is_signalled_alone(self):
		process = Mock(pid=4321)
		with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner.os, 'getpgid', return_value=1), \
			patch.object(runner.os, 'killpg') as killpg:
			runner.stop_command(process, signal.SIGTERM)
		process.send_signal.assert_called_once_with(signal.SIGTERM)
		killpg.assert_not_called()

	def test_a_session_leader_takes_its_group_down(self):
		process = Mock(pid=4321)
		with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner.os, 'getpgid', return_value=4321), \
			patch.object(runner.os, 'killpg') as killpg:
			runner.stop_command(process, signal.SIGTERM)
		killpg.assert_called_once_with(4321, signal.SIGTERM)

	def test_partial_lines_reach_the_terminal_and_log_before_exit(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			acknowledged = pathlib.Path(directory) / 'acknowledged'

			class LiveOutput(io.StringIO):
				def write(self, value):
					if value == 'ready':
						if b'ready' not in (run.output / '00-live.log').read_bytes():
							raise RuntimeError('the live log was not flushed')
						acknowledged.touch()
					return super().write(value)

			code = (
				"import os, pathlib, sys, time\n"
				"os.write(1, b'ready')\n"
				"deadline = time.monotonic() + 3\n"
				"while not pathlib.Path(sys.argv[1]).exists():\n"
				"    if time.monotonic() >= deadline: sys.exit(1)\n"
				"    time.sleep(0.01)\n"
			)
			with redirect_stdout(LiveOutput()), redirect_stderr(io.StringIO()):
				self.assertEqual(run.command('live', [sys.executable, '-c', code, str(acknowledged)]), 'ready')
			self.assertTrue(acknowledged.exists())

	def test_failures_keep_output_and_the_exit_status(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			stdout, stderr = io.StringIO(), io.StringIO()
			code = "import os, sys; os.write(1, b'output\\n'); os.write(2, b'failure\\n'); sys.exit(7)"
			with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(RuntimeError):
				run.command('failure', [sys.executable, '-c', code])
			self.assertEqual(run.results[-1]['status'], 'fail')
			self.assertIn('exit 7', run.results[-1]['detail'])
			self.assertIn('output\n', stdout.getvalue())
			self.assertIn('failure\n', stderr.getvalue())
			self.assertIn('failure\n', (run.output / '00-failure.log').read_text())

	def test_timeout_retains_and_mirrors_output(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			stdout, stderr = io.StringIO(), io.StringIO()
			code = "import os, time; os.write(1, b'output\\n'); os.write(2, b'diagnostic\\n'); time.sleep(60)"
			with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(subprocess.TimeoutExpired):
				run.command('timeout', [sys.executable, '-c', code], timeout=1)
			self.assertEqual(run.results[-1]['status'], 'fail')
			self.assertIn('output\n', stdout.getvalue())
			self.assertIn('diagnostic\n', stderr.getvalue())
			self.assertIn('diagnostic\n', (run.output / '00-timeout.log').read_text())

	def test_operator_interrupt_keeps_live_output(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			ready = threading.Event()
			original_wait = subprocess.Popen.wait
			should_interrupt = True

			class LiveOutput(io.StringIO):
				def write(self, value):
					if value == 'ready':
						ready.set()
					return super().write(value)

			def interrupt_once(process, timeout=None):
				nonlocal should_interrupt
				if should_interrupt:
					should_interrupt = False
					if not ready.wait(3):
						raise RuntimeError('the child output never reached the terminal')
					raise KeyboardInterrupt
				return original_wait(process, timeout=timeout)

			code = "import os, time; os.write(1, b'ready'); time.sleep(60)"
			with redirect_stdout(LiveOutput()), redirect_stderr(io.StringIO()):
				with patch.object(subprocess.Popen, 'wait', interrupt_once):
					text = run.command('interrupt', [sys.executable, '-c', code], interrupt_ok=True)
			self.assertEqual(text, 'ready')
			self.assertEqual((run.output / '00-interrupt.log').read_text(), 'ready')
			self.assertEqual(run.results[-1]['status'], 'pass')


POWERSHELLS = [engine for engine in (shutil.which('powershell'), shutil.which('pwsh')) if engine]
PARSE_COMMAND = (
	'$errors = $null;'
	'[void][System.Management.Automation.Language.Parser]::ParseInput('
	'[IO.File]::ReadAllText({path}, [Text.UTF8Encoding]::new($false)), [ref]$null, [ref]$errors);'
	'$errors | ForEach-Object { "line {0}, column {1}: {2}" -f '
	'$_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message };'
	'if ($errors.Count -gt 0) { exit 1 }'
)


def script_syntax_errors(engine, path):
	command = PARSE_COMMAND.replace('{path}', state.powershell_quote(path))
	result = subprocess.run([engine, '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True)
	return result.returncode, (result.stdout + result.stderr).decode('utf-8', errors='replace').strip()


@unittest.skipUnless(POWERSHELLS, 'PowerShell is not installed')
class PowerShellScriptTests(unittest.TestCase):
	"""A broken script only fails when the release suite runs, so parse it here.

	The parser is the one the child actually uses: a literal such as
	"NRPT rules for $Namespace: expected" is read as a drive-qualified variable
	and rejected while parsing, which took the whole Windows snapshot down.
	"""

	def test_every_release_script_parses(self):
		scripts = sorted(path for folder in ('scripts', 'tests')
			for path in (ROOT / folder).rglob('*.ps1'))
		self.assertTrue(scripts, 'no PowerShell scripts under scripts/ or tests/')
		for engine in POWERSHELLS:
			for script in scripts:
				with self.subTest(engine=pathlib.Path(engine).name, script=str(script.relative_to(ROOT))):
					code, output = script_syntax_errors(engine, script)
					self.assertEqual(code, 0, f'{script.relative_to(ROOT)}: {output}')


if __name__ == '__main__':
	unittest.main()
