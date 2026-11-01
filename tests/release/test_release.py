import importlib.util
import hashlib
import io
import pathlib
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
			actions = [argv[argv.index('-Action') + 1] for argv, _ in host.commands if argv[0] == 'powershell']
			self.assertEqual(actions, ['Snapshot', 'Restore', 'Verify'])
			self.assertTrue(all(privileged for argv, privileged in host.commands if argv[0] == 'powershell'))

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


if __name__ == '__main__':
	unittest.main()
