import contextlib
import importlib.util
import hashlib
import http.client
import io
import locale
import os
import pathlib
import re
import shutil
import signal
import socket
import tempfile
import unittest
import subprocess
import sys
import tarfile
import threading
import time
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


def workspace_version():
	return release.tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']


def fixture_symlink(test, path, target, **options):
	try:
		path.symlink_to(target, **options)
	except OSError as error:
		if os.name == 'nt' and getattr(error, 'winerror', None) in (50, 1314):
			test.skipTest(f'Windows symlink creation is unavailable: {error}')
		raise


class ReleaseTests(unittest.TestCase):
	def test_powershell_is_required_only_on_windows(self):
		self.assertFalse(powershell_skip_reason('Windows').startswith('not applicable:'))
		for system in ('Darwin', 'Linux'):
			self.assertTrue(powershell_skip_reason(system).startswith('not applicable:'))

	def test_windows_symlink_capability_skip_is_not_a_pass(self):
		path = Mock()
		unavailable = OSError('fixture privilege unavailable')
		unavailable.winerror = 1314
		path.symlink_to.side_effect = unavailable
		with patch.object(os, 'name', 'nt'), self.assertRaises(unittest.SkipTest):
			fixture_symlink(self, path, 'target')
		unexpected = OSError('unexpected I/O failure')
		unexpected.winerror = 5
		path.symlink_to.side_effect = unexpected
		with patch.object(os, 'name', 'nt'), self.assertRaisesRegex(OSError, 'unexpected'):
			fixture_symlink(self, path, 'target')

	def test_advisory_exceptions_are_limited_to_documented_maintenance_notices(self):
		policy = release.tomllib.loads((ROOT / 'deny.toml').read_text())
		self.assertEqual(set(policy['advisories']['ignore']), {
			'RUSTSEC-2024-0370', 'RUSTSEC-2026-0370', 'RUSTSEC-2026-0371', 'RUSTSEC-2026-0372',
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
		versions = [workspace['workspace']['package']['rust-version'], tray['package']['rust-version']]
		for name, version in zip(('msrv-cli', 'msrv-tray'), versions):
			with self.subTest(name=name):
				self.assertEqual(commands[name][1], f'+{version}.0')
		toolchains = ' '.join(f'{version}.0' for version in versions)
		self.assertIn(f'rustup toolchain install {toolchains} --profile minimal', workflow)

	def test_release_core_uses_the_absolute_browser_fixture_path(self):
		run = Mock(args=SimpleNamespace(gui=False, strict=True))
		with patch.object(runner.shutil, 'which', return_value='installed'):
			runner.core(run)
		command = next(call.args[1] for call in run.command.call_args_list if call.args[0] == 'browser-fixture-tests')
		self.assertEqual(command, ['bun', 'test', str(ROOT / 'tests/release/browser.test.ts')])

	def test_ci_uses_the_runner_with_the_absolute_browser_fixture_path(self):
		workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
		test_job = workflow.split('\n  test:\n', 1)[1].split('\n  fedora:\n', 1)[0]
		self.assertIn('scripts/test-${{ matrix.platform }}.py ci --report ci-reports', test_job)
		self.assertNotIn('bun test tests/release/browser.test.ts', test_job)
		checks = runner.helper('all_checks')
		stage = next(stage for stage in checks.AllChecks(None, None, SimpleNamespace(suite='ci')).stages()
			if stage.name == 'browser-server-fixtures')
		child = Mock()
		child.command.return_value = ''
		with patch.object(checks.shutil, 'which', return_value='installed'):
			stage.action(child)
		self.assertEqual(child.command.call_args.args[1],
			['bun', '--no-install', 'test', str(ROOT / 'tests/release/browser.test.ts')])

	def test_ci_provisions_supported_platforms_and_uploads_only_status_summaries(self):
		workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
		test_job = workflow.split('\n  test:\n', 1)[1].split('\n  site:\n', 1)[0]
		for platform in ('ubuntu-24.04', 'macos-15', 'macos-15-intel', 'windows-2025'):
			self.assertIn(f'os: {platform}', test_job)
		for prerequisite in ("python-version: '3.14'", 'cargo-nextest,cargo-deny',
				'bun install --frozen-lockfile', 'persist-credentials: false', 'timeout-minutes: 90'):
			self.assertIn(prerequisite, test_job)
		self.assertIn('container: fedora:44', test_job)
		self.assertIn('runuser -u testd-ci --preserve-environment', test_job)
		self.assertIn('path: ci-reports/ci-summary.json', test_job)
		self.assertNotRegex(test_job, r'(?m)^\s+path: ci-reports/?\s*$')
		self.assertNotIn('continue-on-error:', test_job)
		self.assertIn('/ci-reports/', (ROOT / '.gitignore').read_text(encoding='utf-8'))
		dependencies = (ROOT / '.github/actions/linux-dependencies/action.yml').read_text(encoding='utf-8')
		self.assertIn('fedora)', dependencies)
		self.assertIn('dnf install -y gcc gcc-c++', dependencies)
		for package in ('webkit2gtk4.1-devel', 'libappindicator-gtk3-devel', 'unzip', 'systemd'):
			self.assertIn(package, dependencies)

	@unittest.skipUnless(shutil.which('bun'), 'Bun is not installed')
	def test_link_checker_uses_the_isolated_site_output(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			(root / 'docs').mkdir()
			(root / 'index.html').write_text('<a href="/docs/">Docs</a>', encoding='utf-8')
			(root / 'docs/index.html').write_text('<h1 id="top">Docs</h1>', encoding='utf-8')
			env = {**os.environ, 'TESTD_SITE_OUT_DIR': str(root)}
			command = ['bun', str(ROOT / 'scripts/check-links.ts')]
			result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
			self.assertEqual(result.returncode, 0, result.stderr)
			self.assertIn('2 pages ok', result.stdout)
			(root / 'index.html').write_text('<a href="/missing">Missing</a>', encoding='utf-8')
			result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
			self.assertNotEqual(result.returncode, 0)
			self.assertIn('/missing', result.stderr)

	def test_release_core_runs_known_contracts_in_both_rust_test_modes(self):
		for nextest in (True, False):
			with self.subTest(nextest=nextest):
				run = Mock(args=SimpleNamespace(gui=False, strict=True))
				def which(name):
					return None if name == 'cargo-nextest' and not nextest else 'installed'
				with patch.object(runner.shutil, 'which', side_effect=which):
					runner.core(run)
				command = next(call.args[1] for call in run.command.call_args_list if call.args[0] == 'rust-tests')
				if nextest:
					self.assertIn('--run-ignored', command)
					self.assertEqual(command[command.index('--run-ignored') + 1], 'all')
				else:
					self.assertIn('--include-ignored', command)

	def test_ci_always_runs_ignored_contracts_and_gates_release_builds(self):
		workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
		checks = runner.helper('all_checks')
		stages = checks.AllChecks(None, None, SimpleNamespace(suite='ci')).stages()
		for name in ('contracts-msrv', 'cli-stable', 'workspace-stable'):
			child = Mock()
			child.command.return_value = ''
			with patch.object(checks.shutil, 'which', return_value='installed'):
				next(stage for stage in stages if stage.name == name).action(child)
			command = child.command.call_args.args[1]
			self.assertEqual(command[command.index('--run-ignored') + 1], 'all')
		for job, following in (('bundle', 'sbom'), ('sbom', 'release')):
			section = workflow.split(f'\n  {job}:\n', 1)[1].split(f'\n  {following}:\n', 1)[0]
			self.assertIn('needs: [test, fedora]', section)

	def test_notification_dependency_is_not_downgraded_to_4_17(self):
		manifest = release.tomllib.loads((ROOT / 'crates/testd-daemon/Cargo.toml').read_text())
		self.assertEqual(manifest['dependencies']['notify-rust'], '4.18')

	def test_windows_host_script_captures_expected_failures_through_the_helper(self):
		"""PowerShell 5.1 turns redirected native stderr into a terminating error."""
		script = (ROOT / 'tests/host/windows.ps1').read_text()
		self.assertEqual(script.count('2>&1'), 1, 'capture native output only through Invoke-Captured')
		self.assertIn("$ErrorActionPreference = 'Continue'", script)

	def test_windows_host_script_hands_curl_bodies_through_a_file(self):
		"""PowerShell 5.1 breaks a native argument that holds spaces and quotes."""
		script = (ROOT / 'tests/host/windows.ps1').read_text()
		self.assertIn('--data-binary "@$bodyFile"', script)
		self.assertNotIn('--data $Body', script)

	def test_windows_state_snapshot_does_not_remove_rules_or_roots(self):
		script = (ROOT / 'tests/release/windows-system-state.ps1').read_text()
		self.assertIn("$ConfirmPreference = 'None'", script)
		self.assertNotIn('certutil.exe -delstore', script)
		self.assertNotIn('Remove-DnsClientNrptRule', script)
		self.assertNotIn('Remove-CimInstance', script)

	def test_windows_product_helper_does_not_wait_for_confirmation(self):
		script = (ROOT / 'scripts/testd-elevated.ps1').read_text()
		self.assertIn("$ConfirmPreference = 'None'", script)
		self.assertIn('certutil.exe -delstore -f Root', script)
		self.assertIn('Remove-DnsClientNrptRule -Name $rule.Name -Force', script)
		self.assertNotIn('Remove-CimInstance', script)

	def test_workspace_versions_match(self):
		release.check_version(workspace_version())
		with self.assertRaises(ValueError):
			release.check_version('0.0.0')

	def test_homebrew_definitions_use_real_cached_bytes_and_both_architectures(self):
		version = workspace_version()
		source = f'testd-{version}-source.tar.gz'
		arm = f'Testd_{version}_aarch64.dmg'
		intel = f'Testd_{version}_x64.dmg'
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			for name in [source, arm, intel]:
				(root / name).write_bytes(name.encode())
			release.homebrew(SimpleNamespace(version=version, artifacts=root, output=root / 'tap'))
			formula = (root / 'tap/testd.rb').read_text()
			cask = (root / 'tap/testd-gui.rb').read_text()
			self.assertIn(release.digest(root / source), formula)
			self.assertIn(release.digest(root / arm), cask)
			self.assertIn(release.digest(root / intel), cask)
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


class ArtifactInstallFixture:
	version = '0.1.0-alpha'

	def __init__(self, directory, rollback_change=None):
		root = pathlib.Path(directory)
		self.output = root / 'report'
		self.output.mkdir()
		self.cli = root / 'candidate'
		self.cli.write_bytes(b'candidate')
		previous = root / 'previous'
		previous.write_bytes(b'previous')
		self.args = SimpleNamespace(previous_bin=previous)
		self.metadata = {}
		self.steps = []
		self.records = []
		self.rollback_change = rollback_change

	def command(self, name, command, env=None):
		self.steps.append(name)
		if name == 'archive-version':
			return f'testd {self.version}\n'
		home = pathlib.Path(env['HOME'])
		config = home / ('AppData/Roaming/testd' if runner.SYSTEM == 'Windows' else '.config/testd')
		if name in ('upgrade-base-init', 'fresh-init'):
			(config / 'pki').mkdir(parents=True)
			(config / 'pki/root.crt').write_bytes(b'root certificate')
			(config / 'pki/root.key').write_bytes(b'root key')
			(config / 'config.toml').write_text('[host]\nsecret = "original"\n')
		elif name == 're-init':
			if not (self.output / 'fresh-state-before-upgrade-0.tar.gz').exists():
				raise AssertionError('upgrade ran without a persisted backup')
			(config / 'config.toml').write_text('[host]\nsecret = "original"\nnew_value = "kept"\n')
		elif name == 'rollback-init':
			if not (self.output / 'fresh-state-before-rollback-0.tar.gz').exists():
				raise AssertionError('rollback ran without a persisted backup')
			if self.rollback_change == 'config':
				(config / 'config.toml').write_text('[host]\nsecret = "original"\n')
			elif self.rollback_change == 'certificate':
				(config / 'pki/root.crt').write_bytes(b'changed certificate')
			elif self.rollback_change == 'key':
				(config / 'pki/root.key').write_bytes(b'changed key')
		else:
			raise AssertionError(f'unexpected command {name}')
		return ''

	def record(self, name, status, detail=''):
		self.records.append((name, status, detail))


class PlatformSequenceTests(unittest.TestCase):
	def test_automated_sequence_runs_the_documented_non_gui_checks(self):
		run = Mock(args=SimpleNamespace(gui=False))
		with patch.object(runner, 'require') as required:
			runner.automated(run)
		self.assertEqual([call.args[0] for call in required.call_args_list], ['cargo', 'rustup', 'cargo-nextest', 'bun'])
		commands = {call.args[0]: call.args[1] for call in run.command.call_args_list}
		self.assertEqual(commands['format'], ['cargo', '+stable', 'fmt', '--all', '--', '--check'])
		self.assertEqual(commands['clippy'], ['cargo', '+stable', 'clippy', '--workspace', '--all-targets',
			'--exclude', 'testd-gui', '--locked', '--', '-D', 'warnings'])
		self.assertEqual(commands['rust-tests'], ['cargo', '+1.89.0', 'nextest', 'run', '--workspace',
			'--exclude', 'testd-gui', '--locked', *runner.NEXTEST_OUTPUT_OPTIONS])
		self.assertEqual(commands['release-script-tests'], [sys.executable, '-m', 'unittest', 'discover',
			'-s', 'tests/release', '-p', 'test_*.py', '-v'])
		self.assertEqual(commands['browser-fixture-tests'], ['bun', 'test', str(ROOT / 'tests/release/browser.test.ts')])

	def test_gui_sequence_adds_the_tray_msrv_and_full_workspace_tests(self):
		run = Mock(args=SimpleNamespace(gui=True))
		with patch.object(runner, 'require'):
			runner.automated(run)
		commands = {call.args[0]: call.args[1] for call in run.command.call_args_list}
		self.assertEqual(commands['msrv-tray'], ['cargo', '+1.90.0', 'check', '-p', 'testd-gui', '--locked'])
		self.assertEqual(commands['gui-workspace-tests'], ['cargo', '+stable', 'nextest', 'run', '--workspace', '--locked',
			*runner.NEXTEST_OUTPUT_OPTIONS])

	def test_contract_sequence_includes_ignored_cases_without_fail_fast(self):
		run = Mock(args=SimpleNamespace(gui=False))
		with patch.object(runner, 'require'):
			runner.contracts(run)
		command = run.command.call_args.args[1]
		self.assertEqual(command, ['cargo', '+1.89.0', 'nextest', 'run', '--workspace', '--exclude',
			'testd-gui', '--locked', '--run-ignored', 'all', '--no-fail-fast', *runner.NEXTEST_OUTPUT_OPTIONS])

	def test_dependency_audit_covers_the_whole_workspace(self):
		run = Mock(args=SimpleNamespace(gui=False))
		with patch.object(runner, 'require') as required:
			runner.audit(run)
		self.assertEqual([call.args[0] for call in required.call_args_list], ['cargo', 'rustup', 'cargo-deny'])
		self.assertEqual(run.command.call_args.args[1], ['cargo', '+stable', 'deny', '--workspace', '--locked', 'check'])

	def test_service_suite_loads_its_helper_from_the_release_runner_directory(self):
		run = Mock()
		checks = Mock()
		with patch.object(runner, 'helper', return_value=checks) as helper, \
			patch.object(runner, 'binary', return_value=pathlib.Path('candidate')):
			runner.service(run)
		helper.assert_called_once_with('service')
		checks.run_service.assert_called_once_with(run, pathlib.Path('candidate'), runner.SYSTEM)

	def test_candidate_build_flags_distinguish_checkouts_and_preserve_existing_flags(self):
		run = Mock(metadata={'commit': 'fixture'})
		with patch.dict(os.environ, {'RUSTFLAGS': '-C debuginfo=0'}, clear=True), \
			patch.object(runner, 'ROOT', pathlib.Path('/checkout-a')):
			first = runner.candidate_build_environment(run)
		with patch.dict(os.environ, {'RUSTFLAGS': '-C debuginfo=0'}, clear=True), \
			patch.object(runner, 'ROOT', pathlib.Path('/checkout-b')):
			second = runner.candidate_build_environment(run)
		self.assertIn('-C debuginfo=0', first['RUSTFLAGS'])
		self.assertIn('-C metadata=testd-check-', first['RUSTFLAGS'])
		self.assertNotEqual(first['RUSTFLAGS'], second['RUSTFLAGS'])
		with patch.dict(os.environ, {'CARGO_ENCODED_RUSTFLAGS': '-C\x1fdebuginfo=0'}, clear=True):
			encoded = runner.candidate_build_environment(run)
		self.assertIn('-C\x1fdebuginfo=0\x1f-C\x1fmetadata=testd-check-', encoded['CARGO_ENCODED_RUSTFLAGS'])

	def test_native_target_is_read_from_the_stable_toolchain(self):
		run = Mock()
		run.command.return_value = 'rustc 1.99.0\nhost: x86_64-unknown-linux-gnu\nrelease: 1.99.0\n'
		self.assertEqual(runner.native_build_target(run, {}), 'x86_64-unknown-linux-gnu')
		run.command.assert_called_once_with('rustc-host', ['rustc', '+stable', '-vV'], 60, env={})
		for target in ('../../outside', '..', '.', ''):
			with self.subTest(target=target):
				run.command.return_value = f'rustc 1.99.0\nhost: {target}\n'
				with self.assertRaisesRegex(RuntimeError, 'native Rust target'):
					runner.native_build_target(run, {})

	def test_automatic_build_refuses_an_explicit_cross_target(self):
		run = Mock(args=SimpleNamespace(bin=None), metadata={'commit': 'fixture'})
		with patch.dict(os.environ, {'CARGO_BUILD_TARGET': 'another-target'}):
			with self.assertRaisesRegex(RuntimeError, 'CARGO_BUILD_TARGET'):
				runner.binary(run)
		run.command.assert_not_called()

	def test_build_keeps_a_verified_backup_of_an_existing_candidate(self):
		for system, name, triple in [('Linux', 'testd', 'x86_64-unknown-linux-gnu'),
			('Windows', 'testd.exe', 'x86_64-pc-windows-msvc')]:
			with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
				root = pathlib.Path(directory).resolve()
				candidate = root / 'target' / triple / 'release' / name
				candidate.parent.mkdir(parents=True)
				candidate.write_bytes(b'previous candidate')
				report = root / 'report'
				report.mkdir()
				run = Mock(args=SimpleNamespace(bin=None), output=report, metadata={})
				run.command.side_effect = lambda *args, **kwargs: candidate.write_bytes(b'new candidate')
				with patch.object(runner, 'SYSTEM', system), patch.dict(os.environ, {'CARGO_TARGET_DIR': str(root / 'target')}), \
					patch.object(runner, 'native_build_target', return_value=triple):
					self.assertEqual(runner.binary(run), candidate)
				self.assertEqual((report / f'pre-build-{name}').read_bytes(), b'previous candidate')
				self.assertEqual(candidate.read_bytes(), b'new candidate')
				self.assertEqual(run.metadata['binaries'][str(candidate)], runner.file_digest(candidate))
				self.assertEqual(run.command.call_args.args[1], ['cargo', '+stable', 'build', '--release',
					'--bin', 'testd', '--locked', '--target', triple])

	@unittest.skipIf(os.name == 'nt', 'not applicable: the synthetic cargo fixture uses a Unix shell')
	def test_build_sequence_runs_with_a_real_child_and_retains_the_backup(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory).resolve()
			target = root / 'target'
			triple = 'x86_64-unknown-linux-gnu'
			candidate = target / triple / 'release/testd'
			candidate.parent.mkdir(parents=True)
			candidate.write_bytes(b'old executable')
			fake_bin = root / 'bin'
			fake_bin.mkdir()
			fake_rustc = fake_bin / 'rustc'
			fake_rustc.write_text(f'#!/bin/sh\nprintf "host: {triple}\\n"\n', encoding='utf-8')
			fake_rustc.chmod(0o700)
			fake_cargo = fake_bin / 'cargo'
			fake_cargo.write_text(f'#!/bin/sh\nprintf "new executable" > "$CARGO_TARGET_DIR/{triple}/release/testd"\n'
				'printf "%s" "$RUSTFLAGS" > "$CARGO_TARGET_DIR/flags"\n', encoding='utf-8')
			fake_cargo.chmod(0o700)
			args = SimpleNamespace(report=root / 'report', suite='fixture', bin=None)
			with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
				run = runner.Run(args)
				with patch.dict(os.environ, {'PATH': f'{fake_bin}{os.pathsep}{os.environ.get("PATH", "")}',
					'CARGO_TARGET_DIR': str(target)}):
					os.environ.pop('CARGO_BUILD_TARGET', None)
					os.environ.pop('CARGO_ENCODED_RUSTFLAGS', None)
					self.assertEqual(runner.binary(run), candidate)
			self.assertEqual((run.output / 'pre-build-testd').read_bytes(), b'old executable')
			self.assertEqual(candidate.read_bytes(), b'new executable')
			self.assertIn('metadata=testd-check-', (target / 'flags').read_text(encoding='utf-8'))
			self.assertEqual(run.metadata['binaries'][str(candidate)], runner.file_digest(candidate))

	def test_repeated_builds_keep_each_prior_candidate(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory)
			candidate = root / 'testd'
			run = Mock(output=root)
			candidate.write_bytes(b'first')
			runner.backup_build_candidate(run, candidate)
			candidate.write_bytes(b'second')
			runner.backup_build_candidate(run, candidate)
			self.assertEqual((root / 'pre-build-testd').read_bytes(), b'first')
			self.assertEqual((root / 'pre-build-2-testd').read_bytes(), b'second')

	def test_build_refuses_an_unverified_backup_before_compiling(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory)
			triple = 'x86_64-unknown-linux-gnu'
			candidate = root / 'target' / triple / 'release/testd'
			candidate.parent.mkdir(parents=True)
			candidate.write_bytes(b'previous candidate')
			run = Mock(args=SimpleNamespace(bin=None), output=root, metadata={})
			def corrupt_copy(source, destination):
				destination.write_bytes(b'corrupt backup')
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.dict(os.environ, {'CARGO_TARGET_DIR': str(root / 'target')}), \
				patch.object(runner, 'native_build_target', return_value=triple), \
				patch.object(runner.shutil, 'copy2', side_effect=corrupt_copy):
				with self.assertRaisesRegex(RuntimeError, 'verify the pre-build candidate backup'):
					runner.binary(run)
			run.command.assert_not_called()
			self.assertEqual(candidate.read_bytes(), b'previous candidate')

	def test_build_refuses_a_preexisting_candidate_symlink(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory)
			target = root / 'unrelated'
			target.write_bytes(b'keep')
			triple = 'x86_64-unknown-linux-gnu'
			candidate = root / 'target' / triple / 'release/testd'
			candidate.parent.mkdir(parents=True)
			fixture_symlink(self, candidate, target)
			run = Mock(args=SimpleNamespace(bin=None), output=root, metadata={})
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.dict(os.environ, {'CARGO_TARGET_DIR': str(root / 'target')}), \
				patch.object(runner, 'native_build_target', return_value=triple):
				with self.assertRaisesRegex(RuntimeError, 'candidate.*symlink'):
					runner.binary(run)
			run.command.assert_not_called()
			self.assertEqual(target.read_bytes(), b'keep')


class ArtifactInstallTests(unittest.TestCase):
	def test_artifact_smoke_does_not_run_system_cleanup(self):
		with tempfile.TemporaryDirectory() as directory:
			fixture = ArtifactInstallFixture(directory)
			runner.fresh_install(fixture, fixture.cli, 0, fixture.version)
			self.assertNotIn('uninstall-local-state', fixture.steps)
			self.assertTrue((fixture.output / 'fresh-home-0').is_dir())
			self.assertTrue(any(name == 'archive-init-and-reinit' and status == 'pass'
				for name, status, _ in fixture.records))

	def test_artifact_runner_marks_real_uninstall_blocked(self):
		with tempfile.TemporaryDirectory() as directory:
			fixture = ArtifactInstallFixture(directory)
			assets = pathlib.Path(directory) / 'assets'
			assets.mkdir()
			(assets / f'testd-{fixture.version}-x86_64-unknown-linux-gnu.tar.gz').touch()
			fixture.args.artifacts = assets
			fixture.args.require_checksums = False
			fixture.args.host = fixture.args.service = fixture.args.system = False
			def extract(_archive, destination):
				destination.mkdir()
				(destination / 'testd').write_bytes(b'candidate')
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'extract_archive', side_effect=extract):
				runner.artifacts(fixture)
			self.assertNotIn('uninstall-local-state', fixture.steps)
			self.assertTrue(any(name == 'uninstall' and status == 'skip' and detail.startswith('blocked:')
				for name, status, detail in fixture.records))

	def test_upgrade_and_rollback_preserve_state_with_backups(self):
		with tempfile.TemporaryDirectory() as directory:
			fixture = ArtifactInstallFixture(directory)
			runner.fresh_install(fixture, fixture.cli, 0, fixture.version)
			self.assertEqual(fixture.steps, [
				'archive-version', 'upgrade-base-init', 're-init', 'rollback-init',
			])
			for step in ('upgrade', 'rollback'):
				with tarfile.open(fixture.output / f'fresh-state-before-{step}-0.tar.gz') as backup:
					config = backup.extractfile('testd/config.toml').read()
					self.assertIn(b'secret = "original"', config)
					if step != 'upgrade':
						self.assertIn(b'new_value = "kept"', config)
			self.assertTrue(any(name == 'rollback' and status == 'pass' for name, status, _ in fixture.records))

	def test_fresh_install_without_a_previous_binary_skips_rollback(self):
		with tempfile.TemporaryDirectory() as directory:
			fixture = ArtifactInstallFixture(directory)
			fixture.args.previous_bin = None
			runner.fresh_install(fixture, fixture.cli, 0, fixture.version)
			self.assertIn('fresh-init', fixture.steps)
			self.assertNotIn('rollback-init', fixture.steps)
			self.assertTrue((fixture.output / 'fresh-state-before-upgrade-0.tar.gz').is_file())
			self.assertTrue((fixture.output / 'fresh-home-0').is_dir())

	def test_artifact_loop_stops_after_incomplete_system_cleanup(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			assets = root / 'assets'
			assets.mkdir()
			for version in ('0.1.0', '0.2.0'):
				(assets / f'testd-{version}-x86_64-unknown-linux-gnu.tar.gz').touch()
			output = root / 'report'
			output.mkdir()
			run = SimpleNamespace(args=SimpleNamespace(artifacts=assets, require_checksums=False, host=True,
				system=True, service=False, bin=None), output=output, metadata={}, record=Mock())
			def extract(archive, destination):
				destination.mkdir()
				(destination / 'testd').write_text('fixture', encoding='utf-8')
			def host(child):
				child.metadata['incomplete'] = True
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner.platform, 'machine', return_value='x86_64'), \
					patch.object(runner, 'extract_archive', side_effect=extract) as extracted, \
					patch.object(runner, 'fresh_install'), patch.object(runner, 'host', side_effect=host) as host_run:
				runner.artifacts(run)
			self.assertEqual(extracted.call_count, 1)
			host_run.assert_called_once()
			run.record.assert_any_call('artifact-remaining', 'skip',
				'blocked: earlier system or service cleanup is incomplete')

	def test_rollback_rejects_lost_configuration_or_root_material(self):
		for change in ('config', 'certificate', 'key'):
			with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
				fixture = ArtifactInstallFixture(directory, rollback_change=change)
				with self.assertRaisesRegex(RuntimeError, 'rollback'):
					runner.fresh_install(fixture, fixture.cli, 0, fixture.version)
				self.assertTrue((fixture.output / 'fresh-state-before-rollback-0.tar.gz').is_file())
				self.assertNotIn('uninstall-local-state', fixture.steps)


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
		self.modes = {}
		self.identities = {}
		self.certificates = {}
		self.certificate_names = {}
		self.commands = []

	def command(self, argv, privileged=False):
		argv = [str(item) for item in argv]
		self.commands.append((argv, privileged))
		if argv[0] == 'powershell' and "-Action 'Snapshot'" in argv[-1]:
			match = re.search(r"-Destination '([^']+)'", argv[-1])
			if match:
				directory = pathlib.Path(match.group(1))
				(directory / 'nrpt.json').write_text('[]', encoding='utf-8')
				(directory / 'roots').mkdir()
		elif argv[:2] == ['security', 'find-certificate']:
			return ''.join(state.encode_pem(der) for der in self.certificates.values())
		elif argv[:2] == ['security', 'delete-certificate']:
			self.certificates.pop(argv[3], None)
		elif argv[:2] == ['security', 'add-trusted-cert']:
			for der in state.decode_pem(pathlib.Path(argv[-1]).read_text()):
				self.certificates[hashlib.sha1(der).hexdigest()] = der
		return ''

	def certificate_common_name(self, der):
		return self.certificate_names.get(der, state.KEYCHAIN_PREFIX)

	def exists(self, path):
		return str(path) in self.files or str(path) == state.KEYCHAIN

	def read(self, path):
		return self.files[str(path)]

	def regular(self, path):
		return str(path) in self.files

	def directory(self, path):
		return True

	def mode(self, path):
		return self.modes.get(str(path), 0o644)

	def identity(self, path):
		return self.identities.get(str(path), str(path))

	def fingerprint(self, path):
		return [self.identity(path), self.mode(path)]

	def create(self, path, data, mode=0o644):
		path = str(path)
		if self.exists(path):
			raise state.HostError(f'{path} already exists')
		self.files[path] = data
		self.modes[path] = mode
		return self.fingerprint(path)

	def remove_owned(self, path, proof):
		path = str(path)
		if proof['fingerprint'] != self.fingerprint(path) or proof['sha256'] != state.digest(self.read(path)):
			raise state.HostError(f'{path}: identity changed')
		self.commands.append((['remove-owned', path], True))
		del self.files[path]
		self.modes.pop(path, None)


class SystemStateTests(unittest.TestCase):
	def test_dangling_symlinks_count_as_existing_integration(self):
		with tempfile.TemporaryDirectory() as temporary:
			path = pathlib.Path(temporary) / 'anchor'
			fixture_symlink(self, path, pathlib.Path(temporary) / 'missing')
			self.assertTrue(state.Host('Linux', 'testdcheck').exists(path))

	@unittest.skipIf(os.name == 'nt', 'not applicable: Unix fixture file operations are not used on Windows')
	def test_fixture_file_creation_and_removal_are_exclusive_and_identity_checked(self):
		class LocalHost(state.Host):
			def argv(self, argv, privileged=False):
				return list(argv)

		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			host = LocalHost('Linux', 'testdcheck')
			missing = root / 'missing' / 'fixture'
			with self.assertRaises(state.HostError):
				host.create(missing, b'fixture')
			self.assertFalse(missing.parent.exists())
			path = root / 'fixture'
			path.write_bytes(b'pre-existing')
			with self.assertRaises(state.HostError):
				host.create(path, b'fixture')
			self.assertEqual(path.read_bytes(), b'pre-existing')
			path.unlink()
			target = root / 'unrelated'
			target.write_bytes(b'keep')
			path.symlink_to(target)
			with self.assertRaises(state.HostError):
				host.create(path, b'fixture')
			self.assertEqual(target.read_bytes(), b'keep')
			path.unlink()
			fingerprint = host.create(path, b'fixture')
			self.assertEqual(host.fingerprint(path), fingerprint)
			proof = {'fingerprint': fingerprint, 'sha256': state.digest(b'fixture')}
			host.remove_owned(path, proof)
			self.assertFalse(path.exists())
			host.create(path, b'fixture')
			proof = {'fingerprint': host.fingerprint(path), 'sha256': state.digest(b'fixture')}
			path.unlink()
			path.write_bytes(b'replacement')
			with self.assertRaises(state.HostError):
				host.remove_owned(path, proof)
			self.assertEqual(path.read_bytes(), b'replacement')
			self.assertEqual(target.read_bytes(), b'keep')

	def test_snapshot_rejects_missing_or_linked_system_directories(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			with patch.object(host, 'directory', return_value=False), \
					self.assertRaisesRegex(state.HostError, 'missing or a symlink'):
				state.snapshot(host, backup)
			self.assertFalse(backup.exists())
			self.assertEqual(host.commands, [])

	def test_snapshot_accepts_an_artifact_override(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup, [{'path': '/tmp/self-test-only'}])
			self.assertEqual([entry['path'] for entry in state.load(backup)['files']], ['/tmp/self-test-only'])
			self.assertEqual(len(state.files(host)), 4)

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

	def test_windows_snapshot_refuses_missing_or_malformed_store_evidence(self):
		for change in ('rules-missing', 'roots-missing', 'malformed'):
			with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
				host = FakeHost('Windows')
				backup = pathlib.Path(temporary) / 'windows'
				state.snapshot(host, backup)
				if change == 'rules-missing': (backup / 'nrpt.json').unlink()
				if change == 'roots-missing': (backup / 'roots').rmdir()
				if change == 'malformed': (backup / 'nrpt.json').write_text('{}', encoding='utf-8')
				with self.assertRaises(state.HostError):
					state.occupied(backup)

	def test_self_test_refuses_a_host_that_already_has_integration(self):
		host = FakeHost()
		host.files = {state.files(host)[0]['path']: b'live route'}
		with tempfile.TemporaryDirectory() as temporary, patch.object(state, 'Host', return_value=host), \
				redirect_stdout(io.StringIO()):
			problems = state.self_test('Linux', workdir=pathlib.Path(temporary) / 'persisted')
		self.assertTrue(any('already installed' in problem for problem in problems), problems)

	def test_self_test_retains_a_new_workdir_and_restores_after_an_exception(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			workdir = pathlib.Path(temporary) / 'persisted'
			path = state.files(host)[0]['path']
			def failed_install(host, directory, workdir):
				contents = b'partial fixture'
				fingerprint = host.create(path, contents)
				state.record_owned_file(host, directory, path, fingerprint, state.digest(contents))
				raise RuntimeError('fixture failed')
			with patch.object(state, 'Host', return_value=host), \
				patch.object(state, 'install_fixture', side_effect=failed_install), redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'fixture failed'):
					state.self_test('Linux', workdir=workdir)
			self.assertNotIn(path, host.files)
			self.assertTrue((workdir / 'system-before' / state.MANIFEST).is_file())
			self.assertTrue((workdir / 'system-before' / state.RESTORED).is_file())

	def test_self_test_never_reuses_an_existing_workdir(self):
		with tempfile.TemporaryDirectory() as temporary:
			workdir = pathlib.Path(temporary) / 'existing'
			workdir.mkdir()
			marker = workdir / 'keep'
			marker.write_text('existing evidence', encoding='utf-8')
			with patch.object(state, 'Host', return_value=FakeHost()), self.assertRaises(FileExistsError):
				state.self_test('Linux', workdir=workdir)
			self.assertEqual(marker.read_text(encoding='utf-8'), 'existing evidence')

	def test_self_test_requires_a_workdir_even_for_library_callers(self):
		with patch.object(state, 'Host') as host, self.assertRaisesRegex(state.HostError, 'persisted work directory'):
			state.self_test('Linux')
		host.assert_not_called()

	def test_self_test_cli_rejects_missing_temporary_or_noninteractive_workdirs(self):
		with tempfile.TemporaryDirectory() as temporary:
			workdir = pathlib.Path(temporary) / 'self-test'
			for arguments in (['--self-test'], ['--self-test', '--workdir', str(workdir)]):
				with self.subTest(arguments=arguments), patch.object(state, 'self_test') as self_test, \
						redirect_stderr(io.StringIO()):
					with self.assertRaises(SystemExit) as error:
						state.main(arguments)
					self.assertEqual(error.exception.code, 2)
					self_test.assert_not_called()
			with patch.object(state, 'temporary_path', return_value=False), \
					patch.object(state.sys, 'stdin', SimpleNamespace(isatty=lambda: False)), \
					patch.object(state, 'self_test') as self_test, redirect_stderr(io.StringIO()):
				with self.assertRaises(SystemExit) as error:
					state.main(['--self-test', '--workdir', str(workdir)])
				self.assertEqual(error.exception.code, 2)
				self_test.assert_not_called()

	def test_self_test_cli_requires_disposable_host_confirmation(self):
		workdir = pathlib.Path('persisted-self-test')
		with patch.object(state, 'temporary_path', return_value=False), \
				patch.object(state.sys, 'stdin', SimpleNamespace(isatty=lambda: True)), \
				patch('builtins.input', return_value='no'), patch.object(state, 'self_test') as self_test, \
				redirect_stderr(io.StringIO()):
			with self.assertRaises(SystemExit) as error:
				state.main(['--self-test', '--workdir', str(workdir)])
			self.assertEqual(error.exception.code, 2)
			self_test.assert_not_called()

	def test_self_test_cli_forwards_the_workdir_after_confirmation(self):
		workdir = pathlib.Path('persisted-self-test')
		with patch.object(state, 'temporary_path', return_value=False), \
				patch.object(state.sys, 'stdin', SimpleNamespace(isatty=lambda: True)), \
				patch('builtins.input', return_value='yes'), patch.object(state, 'self_test', return_value=[]) as self_test, \
				redirect_stdout(io.StringIO()):
			self.assertEqual(state.main(['--self-test', '--workdir', str(workdir)]), 2)
		self_test.assert_called_once_with(workdir=workdir)

	def test_restore_targets_match_the_product(self):
		"""The suite must restore the paths testd-setup writes, not a copy of them."""
		setup = (ROOT / 'crates/testd-setup/src/lib.rs').read_text()
		artifacts = state.files(FakeHost())
		for item in artifacts[:2]:
			self.assertIn(item['path'], setup)
		self.assertEqual(artifacts[2]['path'], artifacts[1]['path'] + '.owner')
		self.assertIn('format!("{}.owner", layout.anchor)', setup)
		self.assertEqual(artifacts[3]['path'], artifacts[0]['path'] + '.owner')
		resolver = (ROOT / 'crates/testd-setup/src/linux_resolver.rs').read_text()
		self.assertIn('format!("{}.owner", layout.dropin)', resolver)
		macos = state.files(FakeHost('Darwin', 'testdcheck'))[0]['path']
		self.assertIn(macos.rsplit('/', 1)[0], setup)
		windows = (ROOT / 'tests/release/windows-system-state.ps1').read_text()
		elevated = (ROOT / 'scripts/testd-elevated.ps1').read_text()
		for script in (windows, elevated):
			self.assertIn('+ $Tld', script, 'NRPT namespaces must stay scoped to the TLD')
		self.assertIn('testd root', windows)

	def test_self_test_uses_a_dedicated_root_and_blocks_unowned_windows_rules(self):
		self.assertEqual(state.FIXTURE_KEYCHAIN_NAME, 'testd root testing')
		windows = (ROOT / 'tests/release/windows-system-fixture.ps1').read_text()
		self.assertIn('blocked', windows)
		self.assertNotIn('Add-DnsClientNrptRule', windows)
		with tempfile.TemporaryDirectory() as temporary, patch.object(state, 'Host') as host, \
				self.assertRaisesRegex(state.HostError, 'NRPT ownership'):
			state.self_test('Windows', workdir=pathlib.Path(temporary) / 'workdir')
		host.assert_not_called()

	def test_keychain_scope_accepts_new_roots_but_not_the_fixture(self):
		self.assertTrue(state.is_testd_root_name('testd root'))
		self.assertTrue(state.is_testd_root_name('testd root vitoba-borubi-hikola'))
		self.assertTrue(state.is_testd_root_name('testd root bafaba-roputa'))
		self.assertFalse(state.is_testd_root_name('testd root testing'))
		self.assertFalse(state.is_testd_root_name('testd root 0123abcd'))
		self.assertFalse(state.is_testd_root_name('testd root testing-extra'))
		self.assertTrue(state.is_snapshot_root_name('testd root testing'))
		self.assertTrue(state.is_snapshot_root_name('testd root vitoba-borubi-hikola'))

	def test_linux_restore_does_not_replace_changed_preexisting_files(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			resolver, trusted = state.files(host)[0]['path'], state.files(host)[1]['path']
			host.files = {resolver: b'[Resolve]\nDNS=1.1.1.1\n', trusted: b'original root'}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.files = {resolver: b'[Resolve]\nDNS=127.0.0.1:7753\n', trusted: b'another root'}
			before = dict(host.files)
			problems = state.restore(host, backup)
			self.assertTrue(any('pre-existing state changed' in problem for problem in problems), problems)
			self.assertEqual(host.files, before)
			self.assertEqual(host.commands, [])
			self.assertFalse((backup / state.RESTORED).exists())

	def test_linux_restore_removes_integration_that_was_absent(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			for item in state.files(host):
				fingerprint = host.create(item['path'], b'owned fixture')
				state.record_owned_file(host, backup, item['path'], fingerprint, state.digest(b'owned fixture'))
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(host.files, {})
			expected = [item['reload'] for item in state.files(host) if item.get('reload')]
			reloads = [argv for argv, _ in host.commands if argv in expected]
			self.assertEqual(reloads, expected)

	def test_fixture_ownership_is_not_recorded_after_a_racing_replacement(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			path = state.files(host)[0]['path']
			fingerprint = host.create(path, b'fixture')
			host.files[path] = b'unrelated replacement'
			host.identities[path] = 'replacement inode'
			with self.assertRaisesRegex(state.HostError, 'cannot prove'):
				state.record_owned_file(host, backup, path, fingerprint, state.digest(b'fixture'))
			self.assertFalse(state.owned_file_path(backup, path).exists())
			self.assertTrue(state.restore(host, backup))
			self.assertEqual(host.files[path], b'unrelated replacement')
			self.assertEqual(host.commands, [])

	def test_restore_never_deletes_a_new_unowned_system_file(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			path = state.files(host)[0]['path']
			host.files[path] = b'another installation'
			problems = state.restore(host, backup)
			self.assertTrue(any('no proof of test ownership' in problem for problem in problems), problems)
			self.assertEqual(host.files[path], b'another installation')
			self.assertEqual(host.commands, [])

	def test_restore_refuses_a_replaced_or_changed_fixture(self):
		for change in ('identity', 'content', 'mode'):
			with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
				host = FakeHost()
				backup = pathlib.Path(temporary) / 'system-before'
				state.snapshot(host, backup)
				path = state.files(host)[1]['path']
				fingerprint = host.create(path, b'fixture')
				state.record_owned_file(host, backup, path, fingerprint, state.digest(b'fixture'))
				if change == 'identity': host.identities[path] = 'other inode'
				if change == 'content': host.files[path] = b'another certificate'
				if change == 'mode': host.modes[path] = 0o600
				before = dict(host.files)
				problems = state.restore(host, backup)
				self.assertTrue(any('ownership no longer matches' in problem for problem in problems), problems)
				self.assertEqual(host.files, before)
				self.assertEqual(host.commands, [])

	def test_linux_trust_layout_follows_the_distro_tool(self):
		debian = ('/usr/local/share/ca-certificates/testd-root.crt', ['update-ca-certificates'])
		fedora = ('/etc/pki/ca-trust/source/anchors/testd-root.crt', ['update-ca-trust', 'extract'])
		self.assertEqual(state.linux_trust(True, False), debian)
		self.assertEqual(state.linux_trust(False, True), fedora)
		self.assertEqual(state.linux_trust(False, False), debian, 'unrecognised distros keep the old layout')
		self.assertEqual(state.linux_trust(True, True), debian)

	def test_restore_leaves_an_untouched_consumer_alone(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(host.commands, [], 'nothing changed, so nothing needs a privileged reload')

	def test_restore_does_not_replace_an_unchanged_owned_anchor(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			anchor, marker = (item['path'] for item in state.files(host)[1:3])
			host.files = {anchor: b'original root', marker: b'original ownership'}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			self.assertEqual(state.restore(host, backup), [])
			self.assertEqual(host.commands, [], 'unchanged files must retain their inode')

	def test_restore_refuses_a_changed_owned_anchor(self):
		for change in ('content', 'identity', 'mode'):
			with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
				host = FakeHost()
				anchor, marker = (item['path'] for item in state.files(host)[1:3])
				host.files = {anchor: b'original root', marker: b'original ownership'}
				backup = pathlib.Path(temporary) / 'system-before'
				state.snapshot(host, backup)
				if change == 'content':
					host.files[anchor] = b'later change'
				elif change == 'identity':
					host.identities[anchor] = 'replacement inode'
				else:
					host.modes[anchor] = 0o600
				before = dict(host.files)
				problems = state.restore(host, backup)
				self.assertTrue(any('pre-existing state changed' in problem for problem in problems), problems)
				self.assertEqual(host.files, before)
				self.assertEqual(host.commands, [])

	def test_restore_refuses_a_replaced_owned_resolver(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			artifacts = state.files(host)
			resolver, marker = artifacts[0]['path'], artifacts[3]['path']
			host.files = {resolver: b'original route', marker: b'original ownership'}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.identities[resolver] = 'replacement inode'
			problems = state.restore(host, backup)
			self.assertTrue(any('pre-existing state changed' in problem for problem in problems), problems)
			self.assertEqual(host.files[resolver], b'original route')
			self.assertEqual(host.files[marker], b'original ownership')
			self.assertEqual(host.commands, [])

	def test_restore_is_idempotent(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			path = state.files(host)[1]['path']
			fingerprint = host.create(path, b'owned fixture')
			state.record_owned_file(host, backup, path, fingerprint, state.digest(b'owned fixture'))
			self.assertEqual(state.restore(host, backup), [])
			commands = len(host.commands)
			self.assertEqual(state.restore(host, backup), [])
			self.assertNotIn(path, host.files)
			self.assertEqual(len(host.commands), commands, 'a completed restore should not reload again')

	def test_restore_leaves_unowned_drift_after_a_completed_restore(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			self.assertEqual(state.restore(host, backup), [])
			path = state.files(host)[0]['path']
			host.files[path] = b'unrelated later route'
			problems = state.restore(host, backup)
			self.assertTrue(any('no proof of test ownership' in problem for problem in problems), problems)
			self.assertEqual(host.files[path], b'unrelated later route')
			self.assertEqual(host.commands, [])

	def test_restore_rejects_a_tampered_backup(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			host.files = {state.files(host)[1]['path']: b'root'}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			manifest = state.load(backup)
			(backup / manifest['files'][1]['blob']).write_bytes(b'tampered')
			with self.assertRaisesRegex(state.HostError, 'backed-up copy is missing or modified'):
				state.restore(host, backup)
			self.assertFalse((backup / state.RESTORED).exists())

	def test_restore_refuses_unexpected_paths_tlds_and_reload_commands(self):
		for change in ('path', 'tld', 'reload', 'duplicate'):
			with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
				host = FakeHost()
				backup = pathlib.Path(temporary) / 'system-before'
				state.snapshot(host, backup)
				manifest = state.load(backup)
				if change == 'path': manifest['files'][0]['path'] = '/etc/unrelated'
				if change == 'tld': manifest['tld'] = 'example.com'
				if change == 'reload': manifest['files'][0]['reload'] = ['sh', '-c', 'unexpected']
				if change == 'duplicate': manifest['files'][1] = manifest['files'][0]
				(backup / state.MANIFEST).write_text(json.dumps(manifest), encoding='utf-8')
				with self.assertRaises(state.HostError):
					state.restore(host, backup)
				self.assertEqual(host.commands, [])

	def test_verify_reports_drift_after_restore(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.files[state.files(host)[0]['path']] = b'drifted'
			problems = state.verify(host, backup)
			self.assertEqual([problem.split(':')[0] for problem in problems], [state.files(host)[0]['path']])

	def test_macos_duplicate_certificate_identity_blocks_cleanup(self):
		host = FakeHost('Darwin')
		root = b'fixture root'
		encoded = state.encode_pem(root)
		with patch.object(host, 'command', return_value=encoded + encoded) as command, \
				self.assertRaisesRegex(state.HostError, 'duplicate certificate SHA-1'):
			state.keychain_certificates(host)
		self.assertEqual(command.call_count, 1)
		self.assertEqual(command.call_args.args[0][:2], ['security', 'find-certificate'])

	def test_macos_fixture_cannot_adopt_a_preexisting_certificate(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost('Darwin')
			root = b'pre-existing root'
			host.certificates = {hashlib.sha1(root).hexdigest(): root}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			with self.assertRaisesRegex(state.HostError, 'already present'):
				state.record_owned_certificate(backup, root)
			self.assertEqual(host.certificates, {hashlib.sha1(root).hexdigest(): root})

	def test_macos_restore_removes_only_the_exact_recorded_fixture_certificate(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost('Darwin')
			kept, fixture, unrelated = b'kept root', b'fixture root', b'unrelated root'
			host.certificates = {hashlib.sha1(kept).hexdigest(): kept}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			state.record_owned_certificate(backup, fixture)
			host.certificates[hashlib.sha1(fixture).hexdigest()] = fixture
			host.certificates[hashlib.sha1(unrelated).hexdigest()] = unrelated
			problems = state.restore(host, backup)
			self.assertTrue(any('no test ownership proof' in problem for problem in problems), problems)
			self.assertEqual(set(host.certificates.values()), {kept, unrelated})
			deletes = [argv for argv, _ in host.commands if argv[:2] == ['security', 'delete-certificate']]
			self.assertEqual(deletes, [['security', 'delete-certificate', '-Z',
				hashlib.sha1(fixture).hexdigest(), state.KEYCHAIN]])

	def test_macos_restore_does_not_reinstall_a_missing_preexisting_root(self):
		with tempfile.TemporaryDirectory() as temporary:
			host = FakeHost('Darwin')
			root = b'pre-existing root'
			host.certificates = {hashlib.sha1(root).hexdigest(): root}
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			host.certificates = {}
			problems = state.restore(host, backup)
			self.assertTrue(any('not reinstalled' in problem for problem in problems), problems)
			self.assertEqual(host.certificates, {})
			self.assertFalse(any(argv[:2] == ['security', 'add-trusted-cert'] for argv, _ in host.commands))

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

	def test_snapshot_is_required_and_platform_bound(self):
		with tempfile.TemporaryDirectory() as temporary:
			with self.assertRaises(state.HostError):
				state.load(pathlib.Path(temporary) / 'system-before')
			host = FakeHost()
			backup = pathlib.Path(temporary) / 'system-before'
			state.snapshot(host, backup)
			with self.assertRaises(state.HostError):
				state.restore(FakeHost('Darwin'), backup)


class ReleaseEntrySafetyTests(unittest.TestCase):
	def test_hosted_ci_does_not_run_privileged_state_changes(self):
		workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
		self.assertIn('-k SystemStateTests', workflow)
		self.assertNotIn('system_state.py --self-test', workflow)
		self.assertNotIn('tests/release/run.py host --system', workflow)
		self.assertNotIn('tests/release/run.py artifacts', workflow)
		self.assertNotIn('pull_request_target:', workflow)

	def test_restore_report_requires_interactive_confirmation_before_recovery(self):
		for terminal, answer in ((False, 'yes'), (True, 'no')):
			with self.subTest(terminal=terminal, answer=answer), \
					patch.object(runner.sys, 'stdin', SimpleNamespace(isatty=lambda: terminal)), \
					patch('builtins.input', return_value=answer), patch.object(runner, 'restore_report') as restore, \
					redirect_stderr(io.StringIO()):
				with self.assertRaises(SystemExit) as error:
					runner.main(['--restore-report', 'existing-report'])
				self.assertEqual(error.exception.code, 2)
				restore.assert_not_called()

	def test_recovery_does_not_claim_the_shared_trust_store_was_restored(self):
		with tempfile.TemporaryDirectory() as temporary:
			backup = pathlib.Path(temporary) / 'system-before'
			backup.mkdir()
			(backup / 'manifest.json').write_text('{}', encoding='utf-8')
			fake = SimpleNamespace(load=lambda path: {'created': 'fixture', 'system': 'Linux', 'tld': 'testdcheck'},
				Host=lambda *args: None, restore=lambda host, path: [])
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'helper', return_value=fake), \
					redirect_stdout(io.StringIO()) as output:
				self.assertEqual(runner.restore_report(pathlib.Path(temporary)), 2)
			self.assertIn('Shared trust-store output', output.getvalue())

	def test_system_and_service_checks_cannot_share_a_dirty_snapshot(self):
		for arguments in (['host', '--system', '--service'],
				['artifacts', '--artifacts', 'fixtures', '--host', '--system', '--service']):
			with self.subTest(arguments=arguments), patch.object(runner, 'Run') as run, redirect_stderr(io.StringIO()):
				with self.assertRaises(SystemExit) as error:
					runner.main(arguments)
				self.assertEqual(error.exception.code, 2)
				run.assert_not_called()

	def test_only_inapplicable_skips_leave_the_report_complete(self):
		for detail, incomplete in (('not applicable: another OS', False), ('Bun is not installed', True),
				('blocked: no browser evidence', True), ('', True)):
			with self.subTest(detail=detail), tempfile.TemporaryDirectory() as temporary:
				args = SimpleNamespace(report=pathlib.Path(temporary) / 'report', suite='core')
				with redirect_stdout(io.StringIO()):
					run = runner.Run(args)
					run.record('fixture', 'skip', detail)
				self.assertEqual(run.metadata.get('incomplete', False), incomplete)

	def test_disposable_suites_refuse_to_run_without_a_persisted_report(self):
		for arguments in (['host', '--system'], ['browser'], ['desktop'], ['service'],
				['host', '--service'], ['artifacts', '--artifacts', 'fixtures'],
				['artifacts', '--host', '--system', '--artifacts', 'fixtures']):
			with self.subTest(arguments=arguments), patch.object(runner, 'Run') as run, redirect_stderr(io.StringIO()):
				with self.assertRaises(SystemExit) as error:
					runner.main(arguments)
				self.assertEqual(error.exception.code, 2)
				run.assert_not_called()

	def test_disposable_suites_refuse_temporary_and_noninteractive_reports(self):
		with tempfile.TemporaryDirectory() as temporary:
			report = str(pathlib.Path(temporary) / 'report')
			with patch.object(runner, 'Run') as run, redirect_stderr(io.StringIO()):
				with self.assertRaises(SystemExit):
					runner.main(['host', '--system', '--report', report])
				run.assert_not_called()
			with patch.object(runner, 'helper') as helper, \
					patch.object(runner.sys, 'stdin', SimpleNamespace(isatty=lambda: False)), \
					patch.object(runner, 'Run') as run, redirect_stderr(io.StringIO()):
				helper.return_value.is_ephemeral.return_value = False
				with self.assertRaises(SystemExit):
					runner.main(['host', '--system', '--report', report])
				run.assert_not_called()

	def test_disposable_suites_refuse_a_declined_confirmation(self):
		with tempfile.TemporaryDirectory() as temporary:
			report = str(pathlib.Path(temporary) / 'report')
			with patch.object(runner, 'helper') as helper, \
					patch.object(runner.sys, 'stdin', SimpleNamespace(isatty=lambda: True)), \
					patch('builtins.input', return_value='no'), patch.object(runner, 'Run') as run, \
					redirect_stderr(io.StringIO()):
				helper.return_value.is_ephemeral.return_value = False
				with self.assertRaises(SystemExit):
					runner.main(['host', '--system', '--report', report])
				run.assert_not_called()


class HostSystemTests(unittest.TestCase):
	def create_run(self, directory):
		args = SimpleNamespace(report=pathlib.Path(directory) / 'report', suite='host',
			system=True, service=False, bin=None)
		with redirect_stdout(io.StringIO()):
			return runner.Run(args)

	def test_host_coverage_distinguishes_zero_expected_and_missing_checks(self):
		cases = (
			('passed 12, failed 0, skipped 0\n', False, False, None),
			('skip  system changes disabled (fixture)\npassed 12, failed 0, skipped 1\n', False, False,
				'not applicable:'),
			('skip  system checks blocked until ownership\npassed 12, failed 0, skipped 1\n', False, False,
				'not applicable:'),
			('skip  launch at login not configured\npassed 12, failed 0, skipped 1\n', False, True, 'blocked:'),
			('skip  system checks blocked until ownership\n'
				'skip  launch-at-login entry not validated against the candidate (debug)\n'
				'passed 12, failed 0, skipped 2\n', False, True, 'blocked:'),
			('skip  system changes disabled (fixture)\npassed 12, failed 0, skipped 1\n', True, True, 'blocked:'),
			('passed 12, failed 0, skipped 1\n', False, True, 'blocked:'),
			('passed 0, failed 0, skipped 0\n', False, True, 'blocked:'),
			('no summary', False, True, 'blocked:'),
		)
		for text, system, incomplete, prefix in cases:
			with self.subTest(text=text, system=system), tempfile.TemporaryDirectory() as temporary:
				run = self.create_run(temporary)
				run.args.system = system
				with redirect_stdout(io.StringIO()):
					runner.record_host_coverage(run, text)
				self.assertEqual(run.metadata.get('incomplete', False), incomplete)
				if prefix:
					self.assertTrue(any(item['detail'].startswith(prefix) for item in run.results), run.results)
				else:
					self.assertEqual(run.results, [])

	def test_ci_host_scope_excludes_only_actual_desktop_evidence(self):
		cases = (
			('launch at login not configured yet (start the tray once): fixture', False),
			('launch-at-login entry not validated against the candidate (fixture)', False),
			('launch at login not configured', True),
			('python is needed to start a quick launch in this check', True),
		)
		for reason, incomplete in cases:
			with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
				run = self.create_run(temporary)
				run.args.system = False
				text = f'skip  {reason}\npassed 12, failed 0, skipped 1\n'
				with redirect_stdout(io.StringIO()):
					runner.record_host_coverage(run, text, scope='ci')
				self.assertEqual(run.metadata.get('incomplete', False), incomplete)
				self.assertEqual(run.results[0]['name'], 'host-coverage' if incomplete else 'host-desktop-coverage')

	def test_ci_host_scope_cannot_enable_system_integration(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			with patch.object(runner, 'binary') as binary, patch.object(runner, 'system_snapshot') as snapshot, \
					self.assertRaisesRegex(RuntimeError, 'cannot change system integration'):
				runner.host(run, scope='ci')
			binary.assert_not_called()
			snapshot.assert_not_called()

	def test_shutdown_port_check_retries_without_stopping_an_existing_listener(self):
		with patch.object(runner, 'check_ports', side_effect=[RuntimeError('busy'), None]) as ports, \
				patch.object(runner.time, 'sleep') as sleep:
			runner.wait_for_fixture_ports([7737], [7753])
		self.assertEqual(ports.call_count, 2)
		sleep.assert_called_once()
		with patch.object(runner, 'check_ports', side_effect=RuntimeError('still busy')) as ports, \
				self.assertRaisesRegex(RuntimeError, 'still busy'):
			runner.wait_for_fixture_ports([7737], [7753], timeout=0)
		ports.assert_called_once()

	def test_host_summary_failure_is_not_accepted_as_success(self):
		with tempfile.TemporaryDirectory() as temporary:
			run = self.create_run(temporary)
			with redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'failed checks'):
				runner.record_host_coverage(run, 'passed 12, failed 1, skipped 0\n')
			self.assertEqual(run.results[-1]['status'], 'fail')

	def test_unowned_platform_system_checks_stop_before_build_or_snapshot(self):
		for system in ('Darwin', 'Windows'):
			with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
				run = self.create_run(directory)
				with patch.object(runner, 'SYSTEM', system), patch.object(runner, 'binary') as binary, \
						patch.object(runner, 'system_snapshot') as snapshot, \
						self.assertRaisesRegex(RuntimeError, 'ownership is enforced'):
					runner.host(run)
				binary.assert_not_called()
				snapshot.assert_not_called()

	def test_linux_cleanup_requires_the_fixture_ownership_id_and_retains_local_data(self):
		with tempfile.TemporaryDirectory() as temporary:
			run = self.create_run(temporary)
			home = pathlib.Path(temporary) / 'fixture-home'
			cli = pathlib.Path(temporary) / 'candidate'
			owner = home / '.config/testd/system-ownership-id'
			with patch.dict(os.environ, {'TESTD_TOKEN': 'real-secret'}), \
					patch.object(run, 'command') as command:
				runner.cleanup_owned_linux_integration(run, cli, home, 'testdcheck', True)
				command.assert_not_called()
				owner.parent.mkdir(parents=True)
				owner.write_text('fixture-owner', encoding='utf-8')
				runner.cleanup_owned_linux_integration(run, cli, home, 'testdcheck', True)
			self.assertEqual(command.call_args.args[:3], ('system-owned-cleanup', [str(cli), 'uninstall'], 300))
			self.assertNotIn('--purge', command.call_args.args[1])
			self.assertEqual(command.call_args.kwargs['env']['HOME'], str(home))
			self.assertEqual(command.call_args.kwargs['env']['TESTD_HOST_TLD'], 'testdcheck')
			self.assertNotIn('TESTD_TOKEN', command.call_args.kwargs['env'])
			self.assertTrue(command.call_args.kwargs['terminal'])
			self.assertTrue(owner.is_file())

	def test_cleanup_keeps_the_candidate_path_representation(self):
		with tempfile.TemporaryDirectory() as temporary:
			run = self.create_run(temporary)
			home = pathlib.Path(temporary) / 'fixture-home'
			owner = home / '.config/testd/system-ownership-id'
			owner.parent.mkdir(parents=True)
			owner.write_text('fixture-owner', encoding='utf-8')
			for cli in (pathlib.PurePosixPath('/fixture/candidate'),
					pathlib.PureWindowsPath('C:/fixture/candidate.exe')):
				with self.subTest(path=str(cli)), patch.object(run, 'command') as command:
					runner.cleanup_owned_linux_integration(run, cli, home, 'testdcheck', True)
					self.assertEqual(command.call_args.args[1], [str(cli), 'uninstall'])

	@unittest.skipIf(os.name == 'nt', 'not applicable: Linux ownership cleanup uses Unix paths')
	def test_linux_cleanup_refuses_a_linked_ownership_path(self):
		with tempfile.TemporaryDirectory() as temporary:
			run = self.create_run(temporary)
			home = pathlib.Path(temporary) / 'fixture-home'
			config = home / '.config'
			config.mkdir(parents=True)
			target = pathlib.Path(temporary) / 'unrelated'
			target.mkdir()
			(target / 'system-ownership-id').write_text('keep', encoding='utf-8')
			(config / 'testd').symlink_to(target, target_is_directory=True)
			with patch.object(run, 'command') as command, self.assertRaisesRegex(RuntimeError, 'symlink'):
				runner.cleanup_owned_linux_integration(run, pathlib.Path('/candidate'), home, 'testdcheck', True)
			command.assert_not_called()
			self.assertEqual((target / 'system-ownership-id').read_text(encoding='utf-8'), 'keep')

	def test_cleanup_refuses_ambiguous_fixture_directories(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			(root / 'testd-host-one').mkdir()
			(root / 'testd-host-two').mkdir()
			with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
				runner.host_fixture_home(root)
			self.assertEqual(len(list(root.iterdir())), 2)

	def test_failed_host_checks_still_restore_the_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			cli = pathlib.Path(directory) / 'candidate'
			cli.write_bytes(b'fixture')
			events = []

			def snapshot(*args, **kwargs):
				events.append('snapshot')
				return pathlib.Path('system-before')

			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'require'), \
				patch.object(runner, 'binary', return_value=cli), patch.object(runner, 'check_ports'), \
				patch.object(runner, 'system_snapshot', side_effect=snapshot), \
				patch.object(runner, 'system_restore', side_effect=lambda *a, **k: events.append('restore')), \
				patch.object(run, 'command', side_effect=RuntimeError('host checks failed')):
				with self.assertRaisesRegex(RuntimeError, 'host checks failed'):
					runner.host(run)
			self.assertEqual(events, ['snapshot', 'restore'])

	def test_busy_fixture_ports_are_refused_before_the_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			cli = pathlib.Path(directory) / 'candidate'
			cli.write_bytes(b'fixture')
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'binary', return_value=cli), \
				patch.object(runner, 'check_ports', side_effect=RuntimeError('port busy')), \
				patch.object(runner, 'system_snapshot') as snapshot:
				with self.assertRaisesRegex(RuntimeError, 'port busy'):
					runner.host(run)
			snapshot.assert_not_called()

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
				snapshot=lambda host, backup: backup / 'manifest.json', occupied=lambda backup: [])
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'require'), \
				patch.object(runner, 'helper', return_value=fake), \
				patch.object(run, 'command', return_value='') as command, \
				redirect_stdout(io.StringIO()):
				runner.system_snapshot(run, 'testdcheck')
			command.assert_called_once_with('sudo-ready', ['sudo', '-n', 'true'], terminal=True)

	def test_system_snapshot_refuses_preexisting_integration(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			host = FakeHost()
			marker = state.files(host)[2]['path']
			host.files[marker] = b'another installation'
			fake = SimpleNamespace(Host=lambda *args, **kwargs: host, snapshot=state.snapshot, occupied=state.occupied)
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'helper', return_value=fake), \
				redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'clean disposable host'):
					runner.system_snapshot(run, 'testdcheck', interactive=True)
			backup = run.output / 'system-before'
			self.assertEqual(state.occupied(backup), [marker])
			self.assertEqual(host.files[marker], b'another installation')
			self.assertEqual(host.commands, [])

	def test_host_checks_keep_the_terminal_only_for_system_runs(self):
		for system in (False, True):
			with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
				run = self.create_run(directory)
				run.args.system = system
				cli = pathlib.Path(directory) / 'candidate'
				cli.write_bytes(b'fixture')
				output = 'ok    doctor --fix\npassed 1, failed 0, skipped 0\n'
				with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'require'), \
					patch.object(runner, 'binary', return_value=cli), patch.object(runner, 'check_ports'), \
					patch.object(runner, 'system_snapshot'), patch.object(runner, 'system_restore'), \
					patch.object(run, 'command', return_value=output) as command, redirect_stdout(io.StringIO()):
					runner.host(run)
				self.assertEqual(command.call_args.kwargs['terminal'], system)
				self.assertFalse(run.metadata.get('incomplete', False))


class ManualContractTests(unittest.TestCase):
	def test_test_matrix_links_resolve(self):
		readme = ROOT / 'tests/README.md'
		links = re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)', readme.read_text(encoding='utf-8'))
		self.assertTrue(links)
		for link in links:
			with self.subTest(link=link):
				self.assertTrue((readme.parent / link).is_file())

	def test_manual_checklists_have_unique_traceable_ids(self):
		paths = [ROOT / 'tests/host/gui-checklist.md', *sorted((ROOT / 'tests/manual').glob('*.md'))]
		self.assertGreaterEqual(len(paths), 5)
		ids = []
		for path in paths:
			with self.subTest(path=path.name):
				items = runner.checklist_items(path.read_text(encoding='utf-8'))
				self.assertTrue(items, f'{path.name} has no manual contracts')
				for item in items:
					match = re.match(r'^([A-Z]+-\d{2}):', item)
					self.assertIsNotNone(match, f'{path.name}: {item}')
					ids.append(match.group(1))
		self.assertEqual(len(ids), len(set(ids)), 'manual contract ids must be unique')


@unittest.skipUnless(os.name != 'nt' and shutil.which('bash'),
	'not applicable: Unix host scripts are not used on Windows' if os.name == 'nt' else 'Bash is not installed')
class UnixHostContractTests(unittest.TestCase):
	def test_host_script_discards_operator_tokens_and_remote_hosts(self):
		with tempfile.TemporaryDirectory() as temporary:
			script = ('source tests/host/lib.sh; '
				"printf '%s|%s|%s|%s' \"${TESTD_TOKEN-unset}\" \"${TESTD_HOSTS-unset}\" "
				'"${TESTD_TUNNEL-unset}" "$TESTD_HOST_TLD"')
			env = {**os.environ, 'TESTD_HOST_OUTPUT_DIR': temporary, 'TESTD_HOST_TLD': 'testdcheck',
				'TESTD_TOKEN': 'real-secret', 'TESTD_HOSTS': 'remote.example', 'TESTD_TUNNEL': 'real-provider'}
			result = subprocess.run(['bash', '-c', script], cwd=ROOT, env=env, capture_output=True, text=True, timeout=15)
			self.assertEqual(result.returncode, 0, result.stderr)
			self.assertEqual(result.stdout, 'unset|unset|unset|testdcheck')

	def test_macos_system_scripts_refuse_before_touching_the_host(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			marker = root / 'keep'
			marker.write_text('existing data', encoding='utf-8')
			env = {**os.environ, 'HOME': temporary, 'TESTD_HOST_TEST_SYSTEM': '1',
				'TESTD_HOST_OUTPUT_DIR': str(root / 'output')}
			for script in ('tests/host/macos.sh', 'tests/release/macos-resolver-probe.sh'):
				with self.subTest(script=script):
					result = subprocess.run(['bash', script], cwd=ROOT, env=env, capture_output=True, text=True, timeout=15)
					self.assertEqual(result.returncode, 2)
					self.assertIn('blocked', result.stderr)
					self.assertEqual(marker.read_text(encoding='utf-8'), 'existing data')
					self.assertFalse((root / 'output').exists())

	def test_test_contract_documents_trigger_the_ci_test_job(self):
		with tempfile.TemporaryDirectory() as directory:
			fake_git = pathlib.Path(directory) / 'git'
			fake_git.write_text("#!/bin/sh\ncase \"$1\" in\n"
				"  cat-file) exit 0 ;;\n  diff) printf '%s\\n' \"$CHANGED_FILE\" ;;\n  *) exit 1 ;;\nesac\n",
				encoding='utf-8')
			fake_git.chmod(0o700)
			for index, path in enumerate(['README.md', 'tests/README.md', 'tests/manual/browser.md',
				'tests/host/gui-checklist.md']):
				with self.subTest(path=path):
					output = pathlib.Path(directory) / f'output-{index}'
					env = {**os.environ, 'PATH': f'{directory}{os.pathsep}{os.environ.get("PATH", "")}',
						'EVENT': 'push', 'BASE': 'fixture', 'GITHUB_REF': 'refs/heads/master',
						'GITHUB_OUTPUT': str(output), 'CHANGED_FILE': path}
					subprocess.run(['bash', 'scripts/ci-changes.sh'], cwd=ROOT, env=env, timeout=5, check=True)
					self.assertEqual(output.read_text(), 'rust=true\nrelease=false\nsite=false\n')

	def test_system_trust_requires_a_successful_dashboard_response(self):
		script = '''
set -eu
source tests/host/common.sh
TLD=testdcheck
system_http_status() {
	[ "$1" = 'testd.testdcheck' ] && [ "$2" = '/ok.svg' ]
	printf '%s' "$HTTP_STATUS"
}
pass() { printf 'pass:%s' "$1"; }
fail() { printf 'fail:%s' "$1"; }
check_system_trust
'''
		for code, expected in [('200', 'pass'), ('404', 'fail'), ('000', 'fail')]:
			with self.subTest(status=code):
				result = subprocess.run(['bash', '-c', script], cwd=ROOT, env={**os.environ, 'HTTP_STATUS': code},
					capture_output=True, text=True, timeout=5, check=True)
				self.assertEqual(result.stdout, f'{expected}:system trust store accepts the edge certificate')


class DesktopRunnerTests(unittest.TestCase):
	def create_run(self, directory):
		app = pathlib.Path(directory) / 'candidate'
		app.write_text('fixture', encoding='utf-8')
		args = SimpleNamespace(report=pathlib.Path(directory) / 'report', suite='desktop', app=app)
		with redirect_stdout(io.StringIO()):
			return runner.Run(args)

	def test_unowned_platform_desktop_checks_stop_before_launch_or_snapshot(self):
		for system in ('Darwin', 'Windows'):
			with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
				run = self.create_run(directory)
				with patch.object(runner, 'SYSTEM', system), patch.object(runner, 'system_snapshot') as snapshot, \
						patch.object(runner.subprocess, 'Popen') as launch, \
						self.assertRaisesRegex(RuntimeError, 'ownership is enforced'):
					runner.desktop(run)
				snapshot.assert_not_called()
				launch.assert_not_called()

	def test_linux_desktop_requires_its_candidate_cli_before_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'system_snapshot') as snapshot, \
					self.assertRaisesRegex(RuntimeError, 'provide --bin'):
				runner.desktop(run)
			snapshot.assert_not_called()

	def test_linux_desktop_refuses_a_missing_cleanup_cli_before_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			run.args.bin = pathlib.Path(directory) / 'missing-cli'
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'system_snapshot') as snapshot, \
					self.assertRaisesRegex(RuntimeError, 'missing or not executable'):
				runner.desktop(run)
			snapshot.assert_not_called()

	@unittest.skipIf(os.name == 'nt', 'not applicable: Linux desktop cleanup uses executable Unix files')
	def test_linux_desktop_does_not_run_a_replaced_cleanup_cli(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			cli = pathlib.Path(directory) / 'cli'
			cli.write_text('original', encoding='utf-8')
			cli.chmod(0o700)
			run.args.bin = cli
			process = Mock()
			process.poll.return_value = None
			terminal = Mock()
			terminal.isatty.return_value = True
			def launch(*args, **kwargs):
				cli.write_text('replacement', encoding='utf-8')
				return process
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.dict(os.environ, {'HOME': directory}), \
					patch.object(runner.sys, 'stdin', terminal), patch.object(runner.time, 'sleep'), \
					patch.object(runner, 'check_ports'), patch.object(runner.threading, 'Thread'), \
					patch.object(runner.subprocess, 'Popen', side_effect=launch), \
					patch.object(runner, 'checklist_items', return_value=['fixture']), \
					patch.object(runner, 'ask', side_effect=['y', 'q', 'y']), \
					patch.object(runner, 'system_snapshot', return_value=pathlib.Path(directory) / 'before'), \
					patch.object(runner, 'system_restore') as restore, \
					patch.object(runner, 'cleanup_owned_linux_integration') as cleanup, redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'candidate CLI changed'):
					runner.desktop(run)
			cleanup.assert_not_called()
			restore.assert_called_once()
			self.assertEqual(cli.read_text(encoding='utf-8'), 'replacement')
			self.assertTrue(any(item['name'] == 'system-owned-cleanup' and item['status'] == 'fail' for item in run.results))

	@unittest.skipIf(os.name == 'nt', 'not applicable: Linux desktop cleanup uses executable Unix files')
	def test_linux_desktop_refuses_occupied_ports_before_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			cli = pathlib.Path(directory) / 'cli'
			cli.write_text('fixture', encoding='utf-8')
			cli.chmod(0o700)
			run.args.bin = cli
			terminal = Mock()
			terminal.isatty.return_value = True
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.dict(os.environ, {'HOME': directory}), \
					patch.object(runner.sys, 'stdin', terminal), \
					patch.object(runner, 'check_ports', side_effect=RuntimeError('port occupied')), \
					patch.object(runner, 'system_snapshot') as snapshot, patch.object(runner.subprocess, 'Popen') as launch:
				with self.assertRaisesRegex(RuntimeError, 'port occupied'):
					runner.desktop(run)
			snapshot.assert_not_called()
			launch.assert_not_called()

	@unittest.skipIf(os.name == 'nt', 'not applicable: Linux desktop cleanup uses executable Unix files')
	def test_linux_desktop_defers_product_cleanup_if_ports_are_still_occupied(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			cli = pathlib.Path(directory) / 'cli'
			cli.write_text('fixture', encoding='utf-8')
			cli.chmod(0o700)
			run.args.bin = cli
			process = Mock()
			process.poll.return_value = None
			terminal = Mock()
			terminal.isatty.return_value = True
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.dict(os.environ, {'HOME': directory}), \
					patch.object(runner.sys, 'stdin', terminal), patch.object(runner.time, 'sleep'), \
					patch.object(runner, 'check_ports'), \
					patch.object(runner, 'wait_for_fixture_ports', side_effect=RuntimeError('port still occupied')), \
					patch.object(runner.threading, 'Thread'), patch.object(runner.subprocess, 'Popen', return_value=process), \
					patch.object(runner, 'checklist_items', return_value=['fixture']), \
					patch.object(runner, 'ask', side_effect=['y', 'q', 'y']), \
					patch.object(runner, 'system_snapshot', return_value=pathlib.Path(directory) / 'before'), \
					patch.object(runner, 'system_restore') as restore, \
					patch.object(runner, 'cleanup_owned_linux_integration') as cleanup, redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'port still occupied'):
					runner.desktop(run)
			cleanup.assert_not_called()
			restore.assert_called_once()
			self.assertTrue(any(item['name'] == 'fixture-shutdown' and item['status'] == 'fail' for item in run.results))

	def test_desktop_user_data_paths_follow_the_product(self):
		with patch.object(runner, 'SYSTEM', 'Windows'), patch.dict(os.environ, {'APPDATA': '/roaming'}, clear=True):
			self.assertEqual(runner.desktop_config_dir(), pathlib.Path('/roaming/testd'))
		with patch.object(runner, 'SYSTEM', 'Windows'), patch.dict(os.environ, {'USERPROFILE': '/user'}, clear=True):
			self.assertEqual(runner.desktop_config_dir(), pathlib.Path('/user/AppData/Roaming/testd'))
		with patch.object(runner, 'SYSTEM', 'Linux'), patch.dict(os.environ, {'HOME': '/user'}, clear=True):
			self.assertEqual(runner.desktop_config_dir(), pathlib.Path('/user/.config/testd'))

	def test_desktop_refuses_a_broken_user_data_symlink(self):
		with tempfile.TemporaryDirectory() as directory:
			config = pathlib.Path(directory) / '.config'
			config.mkdir()
			fixture_symlink(self, config / 'testd', config / 'missing', target_is_directory=True)
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.dict(os.environ, {'HOME': directory}):
				with self.assertRaisesRegex(RuntimeError, 'existing testd user data'):
					runner.require_fresh_desktop_user()
			self.assertTrue((config / 'testd').is_symlink())

	def test_desktop_checklist_has_unique_contract_ids(self):
		text = (ROOT / 'tests/host/gui-checklist.md').read_text(encoding='utf-8')
		items = runner.checklist_items(text)
		ids = [re.match(r'^(GUI-\d{2}):', item) for item in items]
		self.assertGreaterEqual(len(items), 20)
		self.assertTrue(all(ids), 'every desktop item needs a contract id')
		self.assertEqual(len({match.group(1) for match in ids}), len(items))

	def test_desktop_refuses_an_empty_checklist_before_system_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			terminal = Mock()
			terminal.isatty.return_value = True
			with patch.object(runner, 'require_owned_product_integration'), \
				patch.object(runner, 'SYSTEM', 'Windows'), patch.dict(os.environ, {'APPDATA': directory}), \
				patch.object(runner.sys, 'stdin', terminal), patch.object(runner, 'checklist_items', return_value=[]), \
				patch.object(runner, 'ask', return_value='y'), \
				patch.object(runner, 'system_snapshot', side_effect=AssertionError('snapshot ran too early')) as snapshot:
				with self.assertRaisesRegex(RuntimeError, 'no desktop checklist items'):
					runner.desktop(run)
			snapshot.assert_not_called()

	def test_desktop_domain_matches_the_product_tld(self):
		config = (ROOT / 'crates/testd-core/src/config.rs').read_text(encoding='utf-8')
		match = re.search(r'pub const TLD: &str = "([^"]+)";', config)
		self.assertIsNotNone(match)
		self.assertEqual(runner.DESKTOP_TLD, match.group(1))

	def test_desktop_snapshots_the_wizard_domain_and_clears_the_test_override(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			backup = pathlib.Path(directory) / 'system-before'
			terminal = Mock()
			terminal.isatty.return_value = True
			with patch.object(runner, 'require_owned_product_integration'), \
				patch.object(runner, 'SYSTEM', 'Windows'), patch.object(runner, 'HOST_TLD', 'testdcheck'), \
				patch.dict(os.environ, {'TESTD_HOST_TLD': 'different', 'TESTD_TOKEN': 'secret', 'APPDATA': directory}), \
				patch.object(runner.sys, 'stdin', terminal), \
				patch.object(runner, 'system_snapshot', return_value=backup) as snapshot, \
				patch.object(runner, 'system_restore') as restore, patch.object(runner.subprocess, 'Popen') as launch, \
				patch.object(runner, 'checklist_items', return_value=['fixture']), \
				patch.object(runner, 'ask', side_effect=['y', 'q', 'y']), redirect_stdout(io.StringIO()):
				runner.desktop(run)
			snapshot.assert_called_once_with(run, 'test', interactive=True)
			restore.assert_called_once_with(run, backup, 'test', interactive=True)
			self.assertNotIn('TESTD_HOST_TLD', launch.call_args.kwargs['env'])
			self.assertNotIn('TESTD_TOKEN', launch.call_args.kwargs['env'])
			self.assertEqual(launch.call_args.kwargs['env']['TESTD_TUNNEL'], str(run.output))
			self.assertTrue(run.metadata['incomplete'])

	def test_desktop_refuses_existing_user_data_before_system_snapshot(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			config = pathlib.Path(directory) / 'testd'
			config.mkdir()
			(config / 'config.toml').write_text('existing data', encoding='utf-8')
			terminal = Mock()
			terminal.isatty.return_value = True
			with patch.object(runner, 'require_owned_product_integration'), \
				patch.object(runner, 'SYSTEM', 'Windows'), patch.dict(os.environ, {'APPDATA': directory}), \
				patch.object(runner.sys, 'stdin', terminal), \
				patch.object(runner, 'system_snapshot', side_effect=AssertionError('snapshot ran too early')) as snapshot:
				with self.assertRaisesRegex(RuntimeError, 'existing testd user data'):
					runner.desktop(run)
			snapshot.assert_not_called()
			self.assertEqual((config / 'config.toml').read_text(encoding='utf-8'), 'existing data')

	def test_desktop_requires_a_disposable_host_with_a_persisted_backup(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			terminal = Mock()
			terminal.isatty.return_value = True
			with patch.object(runner, 'require_owned_product_integration'), \
				patch.object(runner, 'SYSTEM', 'Windows'), patch.dict(os.environ, {'APPDATA': directory}), \
				patch.object(runner.sys, 'stdin', terminal), patch.object(runner, 'ask', return_value='n'), \
				patch.object(runner, 'system_snapshot') as snapshot:
				with self.assertRaisesRegex(RuntimeError, 'disposable host'):
					runner.desktop(run)
			snapshot.assert_not_called()

	def test_desktop_defers_restore_without_shutdown_confirmation(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			terminal = Mock()
			terminal.isatty.return_value = True
			with patch.object(runner, 'require_owned_product_integration'), \
				patch.object(runner, 'SYSTEM', 'Windows'), patch.dict(os.environ, {'APPDATA': directory}), \
				patch.object(runner.sys, 'stdin', terminal), \
				patch.object(runner, 'system_snapshot', return_value=pathlib.Path(directory) / 'system-before'), \
				patch.object(runner, 'system_restore') as restore, patch.object(runner.subprocess, 'Popen'), \
				patch.object(runner, 'checklist_items', return_value=['fixture']), \
				patch.object(runner, 'ask', side_effect=['y', 'q', 'n']), redirect_stdout(io.StringIO()):
				runner.desktop(run)
			restore.assert_not_called()
			self.assertTrue(run.metadata['incomplete'])
			deferred = next(result for result in run.results if result['name'] == 'system-restore')
			self.assertEqual(deferred['status'], 'skip')
			self.assertIn('--restore-report', deferred['detail'])


class BrowserTests(unittest.TestCase):
	def create_run(self, directory, tld='test'):
		args = SimpleNamespace(report=pathlib.Path(directory) / 'report', suite='browser', tld=tld,
			port=19080, edge_port=443, intake_port=7737)
		with redirect_stdout(io.StringIO()):
			return runner.Run(args)

	def test_playwright_report_requires_exact_candidate_and_browser_evidence(self):
		certificate = {'subjectName': 'app.releasecheck.test', 'issuer': 'testd intermediate',
			'validFrom': time.time() - 60, 'validTo': time.time() + 86400}
		result = {'status': 'pass', 'engine': 'chromium', 'cleanupComplete': True,
			'origin': 'https://app.releasecheck.test:8443',
			'commit': 'fixture-commit', 'candidate': 'a' * 64, 'rootSha256': 'b' * 64,
			'checks': list(runner.PLAYWRIGHT_CHECKS), 'firstFingerprint': 'c' * 64,
			'secondFingerprint': 'd' * 64, 'firstCertificate': certificate, 'secondCertificate': certificate,
			'userAgent': 'fixture browser'}
		arguments = ('chromium', 8443, 'fixture-commit', 'a' * 64, 'b' * 64)
		self.assertIsNone(runner.playwright_report_error(result, *arguments))
		for change in ({'candidate': 'e' * 64}, {'rootSha256': 'e' * 64}, {'origin': 'https://other.test'},
				{'checks': result['checks'][:-1]}, {'checks': [result['checks'][0]] * len(result['checks'])},
				{'secondFingerprint': result['firstFingerprint']}, {'firstCertificate': None},
				{'secondCertificate': {**certificate, 'validTo': float('nan')}}, {'cleanupComplete': False},
				{'userAgent': ''}, {'status': 'fail'}):
			with self.subTest(change=change):
				self.assertIsNotNone(runner.playwright_report_error({**result, **change}, *arguments))

	def test_browser_system_tls_evidence_must_match_each_browser_leaf(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			result = {'firstFingerprint': 'a' * 64, 'secondFingerprint': 'b' * 64}
			for stage, fingerprint in (('before', result['firstFingerprint']), ('after', result['secondFingerprint'])):
				evidence = {'host': 'app.releasecheck.test', 'port': 443, 'addresses': ['127.0.0.1'],
					'leafSha256': fingerprint, 'openssl': 'fixture TLS'}
				(run.output / f'browser-system-tls-{stage}.json').write_text(json.dumps(evidence), encoding='utf-8')
			self.assertIsNone(runner.browser_system_tls_error(run, result))
			path = run.output / 'browser-system-tls-after.json'
			evidence['addresses'] = ['192.0.2.1']
			path.write_text(json.dumps(evidence), encoding='utf-8')
			self.assertIn('non-loopback', runner.browser_system_tls_error(run, result))
			evidence['addresses'] = ['127.0.0.1']
			evidence['leafSha256'] = 'c' * 64
			path.write_text(json.dumps(evidence), encoding='utf-8')
			self.assertIn('does not match', runner.browser_system_tls_error(run, result))

	def test_missing_playwright_blocks_before_starting_any_candidate(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			run.args.browser_engine = 'chromium'
			result = SimpleNamespace(returncode=2, stdout=b'', stderr=b'install Playwright')
			with patch.object(runner, 'SYSTEM', 'Windows'), patch.object(runner, 'require', return_value='bun'), \
					patch.object(runner.subprocess, 'run', return_value=result), patch.object(runner, 'binary') as binary, \
					patch.object(run, 'serve') as serve, redirect_stdout(io.StringIO()):
				runner.browser(run)
			binary.assert_not_called()
			serve.assert_not_called()
			self.assertTrue(run.metadata['incomplete'])
			self.assertEqual(run.results[-1]['status'], 'skip')

	def test_playwright_prerequisite_timeout_retains_partial_output(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			error = subprocess.TimeoutExpired(['bun'], 30, output=b'partial output', stderr=b'partial error')
			with patch.object(runner, 'SYSTEM', 'Windows'), patch.object(runner, 'require', return_value='bun'), \
					patch.object(runner.subprocess, 'run', side_effect=error), redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'prerequisite check timed out'):
					runner.playwright_available(run, 'chromium')
			self.assertEqual(run.results[-1]['status'], 'fail')
			self.assertEqual(next(run.output.glob('*playwright-prerequisite.log')).read_bytes(),
				b'partial outputpartial error')

	def test_playwright_requires_network_isolation_before_starting_a_candidate(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			run.args.browser_engine = 'chromium'
			terminal = Mock()
			terminal.isatty.return_value = True
			with patch.object(runner, 'require'), patch.object(runner, 'playwright_available', return_value=True), \
					patch.object(runner.sys, 'stdin', terminal), patch.object(runner, 'ask', return_value='n'), \
					patch.object(runner, 'binary') as binary, redirect_stdout(io.StringIO()):
				runner.browser(run)
			binary.assert_not_called()
			self.assertTrue(run.metadata['incomplete'])
			self.assertIn('isolated network egress', run.results[-1]['detail'])

	def test_system_browser_refuses_unowned_platforms_before_starting_a_candidate(self):
		for system in ('Darwin', 'Windows'):
			with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
				run = self.create_run(directory)
				run.args.system = True
				with patch.object(runner, 'SYSTEM', system), patch.object(runner, 'require'), \
						patch.object(runner, 'binary') as binary, patch.object(runner, 'system_snapshot') as snapshot, \
						self.assertRaisesRegex(RuntimeError, 'ownership is enforced'):
					runner.browser(run)
				binary.assert_not_called()
				snapshot.assert_not_called()

	@unittest.skipIf(os.name == 'nt', 'not applicable: Linux browser integration uses Unix file operations')
	def test_system_browser_initializes_a_private_isolated_home(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			home = run.output / 'browser-home'
			home.mkdir()
			config = home / '.config/testd/config.toml'
			def initialize(name, command, timeout, env=None):
				self.assertEqual(name, 'browser-init')
				self.assertEqual(env['HOME'], str(home))
				self.assertNotIn('TESTD_TOKEN', env)
				config.parent.mkdir(parents=True)
				config.write_text('[host]\nsecret = "fixture"\n', encoding='utf-8')
			with patch.dict(os.environ, {'TESTD_TOKEN': 'operator-secret'}), \
					patch.object(run, 'command', side_effect=initialize):
				env = runner.initialize_browser_home(run, pathlib.Path('candidate'), home)
			table = runner.tomllib.loads(config.read_text(encoding='utf-8'))
			self.assertEqual(table['host']['listen_addr'], '127.0.0.1:7737')
			self.assertEqual(table['host']['edge_addr'], '127.0.0.1:443')
			self.assertEqual(table['host']['http_addr'], '127.0.0.1:7740')
			self.assertEqual(table['host']['secret'], 'fixture')
			self.assertEqual(config.stat().st_mode & 0o777, 0o600)
			self.assertTrue((run.output / 'browser-config-before.toml').is_file())
			self.assertEqual(env['TESTD_TUNNEL'], str(run.output))

	@unittest.skipIf(os.name == 'nt', 'not applicable: Linux browser integration uses Unix file operations')
	def test_system_browser_does_not_replace_a_changed_fixture_config(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			home = run.output / 'browser-home'
			home.mkdir()
			config = home / '.config/testd/config.toml'
			def initialize(*args, **kwargs):
				config.parent.mkdir(parents=True)
				config.write_text('[host]\nsecret = "fixture"\n', encoding='utf-8')
			with patch.object(run, 'command', side_effect=initialize), \
					patch.object(runner, 'file_digest', return_value='changed'):
				with self.assertRaisesRegex(RuntimeError, 'config changed'):
					runner.initialize_browser_home(run, pathlib.Path('candidate'), home)
			self.assertEqual(config.read_text(encoding='utf-8'), '[host]\nsecret = "fixture"\n')
			self.assertTrue((run.output / 'browser-config-before.toml').is_file())

	def test_system_browser_cleans_owned_state_after_a_failed_session(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			run.args.system = True
			run.args.browser_engine = 'chromium'
			cli = pathlib.Path(directory) / 'candidate'
			cli.write_bytes(b'candidate fixture')
			terminal = Mock()
			terminal.isatty.return_value = True
			backup = pathlib.Path(directory) / 'snapshot'
			events = []
			def snapshot(*args, **kwargs):
				events.append('snapshot')
				return backup
			def initialize(*args):
				events.append('initialize')
				return {'HOME': str(args[2])}
			def session(*args):
				events.append('browser')
				raise RuntimeError('fixture browser failed')
			with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner, 'require'), \
					patch.object(runner, 'playwright_available', return_value=True), \
					patch.object(runner.sys, 'stdin', terminal), patch.object(runner, 'ask', return_value='y'), \
					patch.object(runner, 'check_ports'), patch.object(runner, 'wait_for_fixture_ports'), \
					patch.object(runner, 'binary', return_value=cli), \
					patch.object(runner, 'system_snapshot', side_effect=snapshot), \
					patch.object(runner, 'initialize_browser_home', side_effect=initialize), \
					patch.object(runner, 'browser_session', side_effect=session), \
					patch.object(runner, 'cleanup_owned_linux_integration', side_effect=lambda *a, **k: events.append('cleanup')), \
					patch.object(runner, 'system_restore', side_effect=lambda *a, **k: events.append('restore')), \
					redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'fixture browser failed'):
					runner.browser(run)
			self.assertEqual(events, ['snapshot', 'initialize', 'browser', 'cleanup', 'restore'])
			self.assertEqual(run.results[-1]['name'], 'fixture-shutdown')
			self.assertEqual(run.results[-1]['status'], 'pass')

	def test_browser_cleanup_defers_when_restart_watcher_is_active(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			run.metadata['browser_watcher_active'] = True
			with patch.object(runner, 'cleanup_owned_linux_integration') as cleanup, \
					patch.object(runner, 'system_restore') as restore, redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'watcher is still running'):
					runner.cleanup_browser_system(run, pathlib.Path('candidate'), pathlib.Path('home'),
						pathlib.Path('snapshot'), [7737], [7753], 'fixture')
			cleanup.assert_not_called()
			restore.assert_not_called()
			self.assertEqual(run.results[-2]['name'], 'fixture-shutdown')
			self.assertEqual(run.results[-2]['status'], 'fail')
			self.assertEqual(run.results[-1]['status'], 'skip')

	def test_browser_cleanup_defers_when_playwright_cleanup_is_unverified(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			run.metadata['browser_cleanup_unverified'] = True
			with patch.object(runner, 'cleanup_owned_linux_integration') as cleanup, \
					patch.object(runner, 'system_restore') as restore, redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'browser process cleanup is unverified'):
					runner.cleanup_browser_system(run, pathlib.Path('candidate'), pathlib.Path('home'),
						pathlib.Path('snapshot'), [7737], [7753], 'fixture')
			cleanup.assert_not_called()
			restore.assert_not_called()
			self.assertEqual(run.results[-2]['status'], 'fail')
			self.assertEqual(run.results[-1]['status'], 'skip')

	def test_interrupted_playwright_without_cleanup_evidence_is_not_assumed_stopped(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			cli = pathlib.Path(directory) / 'candidate'
			run.metadata['binaries'] = {str(cli): 'a' * 64}
			thread = Mock()
			thread.is_alive.return_value = False
			@contextlib.contextmanager
			def serve(*args, **kwargs):
				yield Mock(), Mock()
			with patch.object(runner.threading, 'Thread', return_value=thread), \
					patch.object(run, 'serve', side_effect=serve), patch.object(runner, 'browser_system_tls'), \
					patch.object(run, 'command', side_effect=RuntimeError('driver interrupted')):
				with self.assertRaisesRegex(RuntimeError, 'driver interrupted'):
					runner.browser_fixture(run, cli, Mock(), 'chromium', pathlib.Path('root.crt'), None)
			self.assertTrue(run.metadata['browser_cleanup_unverified'])

	def test_playwright_uses_scoped_fixtures_and_retains_real_evidence(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			run.args.browser_engine = 'chromium'
			config = pathlib.Path(directory) / 'config'
			root = config / 'pki/root.crt'
			root.parent.mkdir(parents=True)
			root.write_bytes(b'public fixture root')
			root_digest = runner.file_digest(root)
			cli = pathlib.Path(directory) / 'candidate'
			candidate = 'a' * 64
			run.metadata['binaries'] = {str(cli): candidate}
			host = SimpleNamespace(status={'tld': 'test'}, started=True)
			process = Mock()
			terminal = Mock()
			terminal.isatty.return_value = True
			thread = Mock()
			thread.is_alive.return_value = False
			@contextlib.contextmanager
			def serve(*args, **kwargs):
				yield process, Mock()
			def system_tls(run, stage, env):
				value = {'host': 'app.releasecheck.test', 'port': 443, 'addresses': ['127.0.0.1'],
					'leafSha256': ('b' if stage == 'before' else 'c') * 64, 'openssl': 'fixture TLS'}
				(run.output / f'browser-system-tls-{stage}.json').write_text(json.dumps(value), encoding='utf-8')
			def command(name, argv, timeout, env, **kwargs):
				self.assertEqual(name, 'playwright-browser')
				self.assertEqual(env['TESTD_BROWSER_ROOT'], str(root))
				self.assertEqual(env['TESTD_BROWSER_CANDIDATE'], candidate)
				for name in ('TESTD_TOKEN', 'HTTPS_PROXY', 'http_proxy', 'SSL_CERT_FILE', 'NODE_TLS_REJECT_UNAUTHORIZED'):
					self.assertNotIn(name, env)
				certificate = {'subjectName': 'app.releasecheck.test', 'issuer': 'testd intermediate',
					'validFrom': time.time() - 60, 'validTo': time.time() + 86400}
				result = {'status': 'pass', 'engine': 'chromium', 'cleanupComplete': True,
					'origin': 'https://app.releasecheck.test:443',
					'commit': run.metadata['commit'], 'candidate': candidate, 'rootSha256': root_digest,
					'checks': list(runner.PLAYWRIGHT_CHECKS), 'firstFingerprint': 'b' * 64,
					'secondFingerprint': 'c' * 64, 'firstCertificate': certificate,
					'secondCertificate': certificate, 'userAgent': 'fixture browser'}
				(run.output / 'playwright-chromium.json').write_text(json.dumps(result), encoding='utf-8')
				return ''
			with patch.dict(os.environ, {'TESTD_TOKEN': 'secret', 'HTTPS_PROXY': 'https://proxy.invalid',
					'http_proxy': 'http://proxy.invalid', 'SSL_CERT_FILE': '/untrusted',
					'NODE_TLS_REJECT_UNAUTHORIZED': '0'}), patch.object(runner, 'require'), \
					patch.object(runner, 'playwright_available', return_value=True), \
					patch.object(runner.sys, 'stdin', terminal), patch.object(runner, 'ask', return_value='y'), \
					patch.object(runner, 'desktop_config_dir', return_value=config), \
					patch.object(runner, 'check_ports'), patch.object(runner, 'binary', return_value=cli), \
					patch.object(runner, 'HostFixture', return_value=contextlib.nullcontext(host)), \
					patch.object(runner, 'require_host_resolution', return_value={'certificate': {'ok': True}}), \
					patch.object(runner.threading, 'Thread', return_value=thread), \
					patch.object(runner, 'browser_system_tls', side_effect=system_tls), \
					patch.object(run, 'serve', side_effect=serve) as started, \
					patch.object(run, 'command', side_effect=command), redirect_stdout(io.StringIO()):
				runner.browser(run)
			started.assert_called_once()
			self.assertEqual(run.results[-1]['name'], 'browser-results')
			self.assertEqual(run.results[-1]['status'], 'pass')

	def test_missing_host_is_started_for_the_fixture(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			events = []
			binary_path = pathlib.Path('/bin/true')

			@contextlib.contextmanager
			def start_host(*args, **kwargs):
				events.append('start')
				try:
					yield 'process', 'output'
				finally:
					events.append('stop')

			with patch.dict(os.environ, {'TESTD_TOKEN': 'real-secret', 'TESTD_HOSTS': 'remote.example'}), \
				patch.object(runner, 'require'), \
				patch.object(runner, 'check_ports'), \
				patch.object(runner, 'wait_for_host', return_value={'tld': 'test'}) as wait, \
				patch.object(runner, 'binary', return_value=binary_path), \
				patch.object(runner, 'require_host_resolution'), \
				patch.object(run, 'serve', side_effect=start_host) as serve, \
				patch.object(run, 'command', return_value='') as command, \
				redirect_stdout(io.StringIO()):
				runner.browser(run)
			self.assertEqual(events, ['start', 'stop'])
			self.assertEqual(serve.call_args.args, ('host-fixture', [str(binary_path), 'host']))
			self.assertEqual(serve.call_args.kwargs['stop_signal'], signal.SIGINT)
			self.assertEqual(serve.call_args.kwargs['env']['TESTD_TUNNEL'], str(run.output))
			self.assertNotIn('TESTD_TOKEN', serve.call_args.kwargs['env'])
			self.assertNotIn('TESTD_HOSTS', serve.call_args.kwargs['env'])
			wait.assert_called_once_with(7737, 'process', 'output')
			command.assert_called_once()
			self.assertNotIn('TESTD_TOKEN', command.call_args.args[3])
			self.assertNotIn('TESTD_HOSTS', command.call_args.args[3])

	def test_browser_refuses_an_existing_listener_without_contacting_it(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			def check(ports, udp=()):
				if ports == [7737]:
					raise RuntimeError('fixture port 7737 is unavailable')
			with patch.object(runner, 'require'), patch.object(runner, 'check_ports', side_effect=check), \
				patch.object(runner, 'local_host_status') as status, \
				patch.object(runner, 'binary', return_value=pathlib.Path('candidate')), \
				patch.object(runner, 'require_host_resolution') as resolution, \
				patch.object(run, 'serve') as serve, patch.object(run, 'command') as command, \
				redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'port 7737'):
					runner.browser(run)
			status.assert_not_called()
			resolution.assert_not_called()
			serve.assert_not_called()
			command.assert_not_called()

	def test_browser_preflight_does_not_connect_to_an_unrelated_local_service(self):
		with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
			listener.bind(('127.0.0.1', 0))
			listener.listen()
			listener.settimeout(0.1)
			run = self.create_run(directory)
			with patch.object(runner, 'local_host_status') as status, patch.object(run, 'serve') as serve:
				with self.assertRaisesRegex(RuntimeError, 'unavailable'):
					with runner.HostFixture(run, pathlib.Path('candidate'), listener.getsockname()[1]):
						self.fail('an occupied listener was accepted')
			status.assert_not_called()
			serve.assert_not_called()
			with self.assertRaises(TimeoutError):
				listener.accept()

	def test_expected_browser_checks_match_the_page(self):
		page = (ROOT / 'tests/release/browser.html').read_text(encoding='utf-8')
		names = re.findall(r"await check\('([^']+)'", page)
		self.assertEqual(len(names), len(runner.BROWSER_CHECKS))
		self.assertEqual(set(names), runner.BROWSER_CHECKS)

	def test_browser_report_requires_all_evidence_and_expected_checks(self):
		valid = {'browser': 'fixture browser', 'notes': 'fixture OS', 'fingerprint': 'a' * 64,
			'manualConfirmed': True, 'commit': 'fixture-commit', 'origin': 'https://app.releasecheck.test',
			'checks': [{'name': name, 'status': 'pass'} for name in sorted(runner.BROWSER_CHECKS)]}
		self.assertIsNone(runner.browser_report_error(valid, 'fixture-commit', 443))
		for change in ('manual', 'browser', 'notes', 'fingerprint', 'commit', 'origin', 'missing', 'duplicate',
			'unknown', 'malformed', 'failed'):
			with self.subTest(change=change):
				result = json.loads(json.dumps(valid))
				if change == 'manual': result['manualConfirmed'] = 'true'
				if change == 'browser': result['browser'] = ''
				if change == 'notes': result['notes'] = '  '
				if change == 'fingerprint': result['fingerprint'] = 'bad'
				if change == 'commit': result['commit'] = 'different'
				if change == 'origin': result['origin'] = 'https://different.example'
				if change == 'missing': result['checks'].pop()
				if change == 'duplicate': result['checks'][0] = result['checks'][1]
				if change == 'unknown': result['checks'][0]['name'] = 'not a browser check'
				if change == 'malformed': result['checks'][0] = None
				if change == 'failed': result['checks'][0]['status'] = 'fail'
				self.assertIsNotNone(runner.browser_report_error(result, 'fixture-commit', 443))
		valid['origin'] = 'https://app.releasecheck.test:8443'
		self.assertIsNone(runner.browser_report_error(valid, 'fixture-commit', 8443))
		self.assertIsNotNone(runner.browser_report_error(None, 'fixture-commit', 443))

	@unittest.skipUnless(shutil.which('bun'), 'Bun is not installed')
	def test_absolute_fixture_path_excludes_nested_checkouts(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory)
			for prefix, name in [(root, 'current checkout'), (root / 'worktrees/other', 'nested checkout')]:
				path = prefix / 'tests/release/browser.test.ts'
				path.parent.mkdir(parents=True)
				path.write_text("import { test, expect } from 'bun:test';\n"
					f"test('{name}', () => expect(true).toBe(true));\n", encoding='utf-8')
			result = subprocess.run(['bun', 'test', str(root / 'tests/release/browser.test.ts')], cwd=root,
				capture_output=True, text=True, timeout=15, check=True)
			output = result.stdout + result.stderr
			self.assertIn('current checkout', output)
			self.assertNotIn('nested checkout', output)

	@unittest.skipUnless(shutil.which('bun'), 'Bun is not installed')
	def test_fixture_reports_match_the_release_runner_contract(self):
		with tempfile.TemporaryDirectory() as directory:
			root = pathlib.Path(directory)
			(root / 'report.json').write_text(json.dumps({'commit': 'fixture-commit'}), encoding='utf-8')
			env = {**os.environ, 'TESTD_BROWSER_REPORT': directory, 'TESTD_BROWSER_PORT': '0',
				'TESTD_BROWSER_TLD': 'test', 'TESTD_BROWSER_EDGE_PORT': '8443'}
			process = subprocess.Popen(['bun', 'tests/release/browser-server.ts'], cwd=ROOT, env=env,
				stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			try:
				port_file = root / 'listener-port'
				deadline = time.monotonic() + 5
				port = None
				while time.monotonic() < deadline and process.poll() is None:
					if port_file.exists():
						value = port_file.read_text().strip()
						if value.isdecimal() and 0 < int(value) <= 65535:
							port = int(value)
							break
					time.sleep(0.02)
				self.assertIsNotNone(port, 'browser fixture did not report its port')
				connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
				result = {'browser': 'fixture browser', 'notes': 'fixture OS', 'fingerprint': 'a' * 64,
					'manualConfirmed': True,
					'checks': [{'name': name, 'status': 'pass'} for name in sorted(runner.BROWSER_CHECKS)]}
				connection.request('POST', '/report', json.dumps(result),
					{'Origin': 'https://app.releasecheck.test:8443', 'X-Testd-Browser-Report': '1'})
				response = connection.getresponse()
				self.assertEqual(response.status, 200)
				saved = pathlib.Path(json.loads(response.read())['saved'])
				connection.close()
				report = json.loads(saved.read_text(encoding='utf-8'))
				self.assertIsNone(runner.browser_report_error(report, 'fixture-commit', 8443))
			finally:
				if process.poll() is None:
					process.terminate()
				try:
					process.communicate(timeout=5)
				except subprocess.TimeoutExpired:
					process.kill()
					process.communicate(timeout=5)

	def test_duplicate_browser_checks_cannot_pass_the_release_report(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			result = {'browser': 'fixture browser', 'notes': 'fixture OS', 'fingerprint': 'a' * 64,
				'manualConfirmed': True, 'commit': run.metadata['commit'], 'origin': 'https://app.releasecheck.test',
				'checks': [{'name': 'HTTPS and secure context', 'status': 'pass'} for _ in range(4)]}

			def write_report(*args, **kwargs):
				(run.output / 'browser-duplicate.json').write_text(json.dumps(result), encoding='utf-8')
				return ''

			host = SimpleNamespace(status={'tld': 'test'}, started=True)
			with patch.object(runner, 'require'), patch.object(runner, 'check_ports'), \
				patch.object(runner, 'HostFixture', return_value=contextlib.nullcontext(host)), \
				patch.object(runner, 'binary', return_value=pathlib.Path('/bin/true')), \
				patch.object(runner, 'require_host_resolution'), patch.object(run, 'command', side_effect=write_report), \
				redirect_stdout(io.StringIO()):
				runner.browser(run)
			self.assertEqual(run.results[-1]['name'], 'browser-results')
			self.assertEqual(run.results[-1]['status'], 'fail')

	def test_a_managed_host_can_be_restarted(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			events = []

			@contextlib.contextmanager
			def serve(*args, **kwargs):
				events.append(('start', args[0]))
				try:
					yield 'process', 'output'
				finally:
					events.append(('stop', args[0]))

			with patch.object(runner, 'check_ports'), \
				patch.object(runner, 'wait_for_host', return_value={'tld': 'test'}), \
				patch.object(run, 'serve', side_effect=serve) as serve_mock, \
				redirect_stdout(io.StringIO()):
				with runner.HostFixture(run, pathlib.Path('/bin/true'), 7737) as host:
					host.restart()
			self.assertEqual(events, [('start', 'host-fixture'), ('stop', 'host-fixture'),
				('start', 'host-fixture-restart-1'), ('stop', 'host-fixture-restart-1')])
			self.assertEqual(serve_mock.call_count, 2)

	def test_restart_requests_restart_a_managed_host(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			request_id = '00000000-0000-4000-8000-000000000000'
			(run.output / f'restart-request-{request_id}.json').write_text('')
			host = Mock()
			errors = []
			stop = Mock()
			stop.wait = Mock(side_effect=[False, True])
			stop.is_set.return_value = False
			runner.watch_restart_requests(run, host, stop, errors)
			host.restart.assert_called_once_with()
			self.assertEqual(errors, [])
			self.assertEqual((run.output / f'restart-result-{request_id}.json').read_text(),
				'{"status": "ok"}\n')
			self.assertFalse((run.output / f'restart-request-{request_id}.json').exists())

	def test_restart_requests_fail_when_the_suite_did_not_start_the_host(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			request_id = '00000000-0000-4000-8000-000000000000'
			(run.output / f'restart-request-{request_id}.json').write_text('')
			host = Mock()
			host.restart.side_effect = RuntimeError('the suite did not start this host; restart it manually')
			stop = Mock()
			stop.wait = Mock(side_effect=[False, True])
			stop.is_set.return_value = False
			runner.watch_restart_requests(run, host, stop, [])
			self.assertEqual(json.loads((run.output / f'restart-result-{request_id}.json').read_text()),
				{'status': 'failed', 'detail': 'the suite did not start this host; restart it manually'})

	def test_restart_watcher_does_not_start_new_work_after_shutdown(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			request = run.output / 'restart-request-00000000-0000-4000-8000-000000000000.json'
			request.write_text('', encoding='utf-8')
			host = Mock()
			stop = Mock()
			stop.wait.return_value = False
			stop.is_set.return_value = True
			runner.watch_restart_requests(run, host, stop, [])
			host.restart.assert_not_called()
			self.assertTrue(request.exists())

	def test_a_host_that_exits_while_starting_reports_its_log(self):
		process = SimpleNamespace(poll=lambda: 1, returncode=1)
		output = SimpleNamespace(text=lambda: 'failed to load config')
		with self.assertRaisesRegex(RuntimeError, 'is it initialized with `testd init`'):
			runner.wait_for_host(7737, process, output)

	def test_a_different_managed_host_tld_is_refused_before_the_fixture_starts(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			host = SimpleNamespace(status={'tld': 'localhost'}, started=True)
			with patch.object(runner, 'require'), \
				patch.object(runner, 'check_ports'), \
				patch.object(runner, 'HostFixture', return_value=contextlib.nullcontext(host)), \
				patch.object(runner, 'binary', return_value=pathlib.Path('/bin/true')), \
				patch.object(runner, 'require_host_resolution') as resolution, \
				patch.object(run, 'command') as command:
				with self.assertRaisesRegex(RuntimeError, r'serves \.localhost'):
					runner.browser(run)
			resolution.assert_not_called()
			command.assert_not_called()

	def test_a_managed_host_starts_the_fixture(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			host = SimpleNamespace(status={'tld': 'test'}, started=True)
			with patch.object(runner, 'require'), \
				patch.object(runner, 'check_ports'), \
				patch.object(runner, 'HostFixture', return_value=contextlib.nullcontext(host)), \
				patch.object(runner, 'binary', return_value=pathlib.Path('/bin/true')), \
				patch.object(runner, 'require_host_resolution'), \
				patch.object(run, 'command', return_value='') as command, \
				redirect_stdout(io.StringIO()):
				runner.browser(run)
			command.assert_called_once()
			self.assertIn('app.othercheck:19080', command.call_args.args[1])
			self.assertTrue(run.metadata['incomplete'])

	def test_a_missing_os_resolver_fails_before_the_browser_opens(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			doctor = json.dumps({'checks': [
				{'name': 'resolver', 'ok': False, 'detail': 'not configured',
					'fix': 'run `testd doctor --fix` or `testd init --resolver-now`'},
				{'name': 'resolution', 'ok': False, 'detail': 'testd.test does not resolve',
					'fix': 'run `testd doctor --fix`'},
			]}).encode()
			result = SimpleNamespace(stdout=doctor, stderr=b'')
			with patch.object(runner.subprocess, 'run', return_value=result), \
				redirect_stdout(io.StringIO()):
				with self.assertRaisesRegex(RuntimeError, 'resolver: not configured; run `testd doctor --fix`'):
					runner.require_host_resolution(run, pathlib.Path('/bin/true'))
			self.assertIn('not configured', (run.output / '00-host-doctor.log').read_text())

	def test_browser_doctor_does_not_inherit_operator_overrides(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			doctor = json.dumps({'checks': [{'name': 'resolver', 'ok': True},
				{'name': 'resolution', 'ok': True}]}).encode()
			result = SimpleNamespace(stdout=doctor, stderr=b'')
			with patch.dict(os.environ, {'TESTD_TOKEN': 'secret', 'TESTD_HOSTS': 'remote.example'}), \
					patch.object(runner.subprocess, 'run', return_value=result) as command, \
					redirect_stdout(io.StringIO()):
				runner.require_host_resolution(run, pathlib.Path('candidate'))
			env = command.call_args.kwargs['env']
			self.assertNotIn('TESTD_TOKEN', env)
			self.assertNotIn('TESTD_HOSTS', env)
			self.assertEqual(env['PYTHONUTF8'], '1')

	def test_a_configured_os_resolver_passes(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			doctor = json.dumps({'checks': [
				{'name': 'resolver', 'ok': True, 'detail': 'configured', 'fix': None},
				{'name': 'resolution', 'ok': True, 'detail': 'testd.test resolves', 'fix': None},
			]}).encode()
			result = SimpleNamespace(stdout=doctor, stderr=b'')
			with patch.object(runner.subprocess, 'run', return_value=result), \
				redirect_stdout(io.StringIO()):
				runner.require_host_resolution(run, pathlib.Path('/bin/true'))
			self.assertEqual(run.results[-1]['name'], 'host-resolution')
			self.assertEqual(run.results[-1]['status'], 'pass')

	def test_a_refused_connection_is_reported_as_a_missing_host(self):
		with patch.object(runner.http.client, 'HTTPConnection') as connection:
			connection.return_value.getresponse.side_effect = ConnectionRefusedError(111, 'Connection refused')
			with self.assertRaisesRegex(runner.HostUnavailable, 'no testd host is listening'):
				runner.local_host_status(7737)


class TranscriptTests(unittest.TestCase):
	def create_run(self, directory):
		args = SimpleNamespace(report=pathlib.Path(directory) / 'report', suite='fixture')
		with redirect_stdout(io.StringIO()):
			return runner.Run(args)

	def test_transcript_retains_runner_messages_and_both_child_streams(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			stdout, stderr = io.StringIO(), io.StringIO()
			code = "import os; os.write(1, b'child-out\\n'); os.write(2, b'child-err\\n')"
			with redirect_stdout(stdout), redirect_stderr(stderr):
				with runner.run_transcript(run):
					print('stage begin')
					run.command('fixture', [sys.executable, '-c', code])
					print('stage end')
			text = (run.output / 'run.log').read_text(encoding='utf-8')
			for value in ('Report:', 'stage begin', 'Running:', 'child-out', 'child-err', 'pass', 'stage end'):
				self.assertIn(value, text)
			self.assertIn('child-out\n', stdout.getvalue())
			self.assertNotIn('\nchild-err\n', stdout.getvalue())
			self.assertIn('child-err\n', stderr.getvalue())
			self.assertEqual(run.metadata['transcript'], str(run.output / 'run.log'))

	def test_transcript_does_not_replace_an_existing_log(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			path = run.output / 'run.log'
			path.write_text('existing evidence', encoding='utf-8')
			with self.assertRaises(FileExistsError):
				with runner.run_transcript(run):
					pass
			self.assertEqual(path.read_text(encoding='utf-8'), 'existing evidence')

	def test_transcript_retains_non_utf8_paths_as_escapes(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
				with runner.run_transcript(run):
					print('path-\udcff')
			self.assertIn('path-\\udcff', (run.output / 'run.log').read_text(encoding='utf-8'))

	def test_transcript_flushes_before_terminal_output_and_restores_streams_on_exception(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			class Terminal(io.StringIO):
				def write(self, text):
					if text == 'live output':
						self.assert_in_log()
					return super().write(text)
				def assert_in_log(self):
					if 'live output' not in (run.output / 'run.log').read_text(encoding='utf-8'):
						raise AssertionError('transcript was not flushed before mirroring')
			terminal, error_terminal = Terminal(), io.StringIO()
			with redirect_stdout(terminal), redirect_stderr(error_terminal):
				with self.assertRaisesRegex(RuntimeError, 'fixture'):
					with runner.run_transcript(run):
						print('live output')
						raise RuntimeError('fixture')
				self.assertIs(sys.stdout, terminal)
				self.assertIs(sys.stderr, error_terminal)
			self.assertIn('live output', (run.output / 'run.log').read_text(encoding='utf-8'))


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

	def test_serve_stops_a_long_running_fixture(self):
		with tempfile.TemporaryDirectory() as directory:
			run = self.create_run(directory)
			with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
				with run.serve('server', [sys.executable, '-c', 'import time; time.sleep(60)']):
					pass
			self.assertEqual(run.results[-1]['status'], 'pass')
			self.assertIn('exit', run.results[-1]['detail'])

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

	@unittest.skipUnless(hasattr(os, 'getpgid'), 'not applicable: process groups are POSIX-only')
	def test_a_detached_child_is_signalled_alone(self):
		process = Mock(pid=4321)
		with patch.object(runner, 'SYSTEM', 'Linux'), patch.object(runner.os, 'getpgid', return_value=1), \
			patch.object(runner.os, 'killpg') as killpg:
			runner.stop_command(process, signal.SIGTERM)
		process.send_signal.assert_called_once_with(signal.SIGTERM)
		killpg.assert_not_called()

	@unittest.skipUnless(hasattr(os, 'getpgid'), 'not applicable: process groups are POSIX-only')
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


def powershell_skip_reason(system):
	if system == 'Windows':
		return 'PowerShell is required on Windows'
	return 'not applicable: PowerShell fixtures are required only on Windows'


POWERSHELLS = [engine for engine in (shutil.which('powershell'), shutil.which('pwsh')) if engine]
POWERSHELL_SKIP = powershell_skip_reason(runner.SYSTEM)
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


# Exercise the PowerShell snapshot against fake rules and stores, never the OS.
SNAPSHOT_PROBE = r'''
$live = [pscustomobject]@{
	Name = 'fixture-rule'
	Namespace = @('.testdcheck', '.testdcheck')
	NameServers = @('127.0.0.1', '127.0.0.1')
	DisplayName = ''
	Comment = ''
}
$script:live = $live
$script:roots = @()
function Get-NamespaceRules { @($script:live) }
function Get-RootThumbprints { @($script:roots) }
function Assert-Administrator { }
function Remove-DnsClientNrptRule { throw 'must not remove any rule' }
function Add-DnsClientNrptRule { throw 'must not recreate any rule' }
function certutil.exe { throw 'must not change the root store' }
$existing = Join-Path $Destination 'existing-evidence'
[IO.File]::WriteAllText($existing, 'keep')
try { Write-NewBytes $existing ([Text.Encoding]::UTF8.GetBytes('replace')); throw 'existing evidence was overwritten' } catch {
	if ($_ -match 'existing evidence was overwritten') { throw }
}
if ([IO.File]::ReadAllText($existing) -ne 'keep') { throw 'existing evidence changed' }
$legacy = @([pscustomobject]@{
	Signature = [pscustomobject]@{
		Namespace = @('.testdcheck', '.testdcheck')
		NameServers = '127.0.0.1,127.0.0.1'
		DisplayName = ''
		Comment = ''
	}
	Properties = Get-RuleProperties $live
})
Set-Content -LiteralPath $NrptFile -Value (ConvertTo-Json -InputObject $legacy -Depth 10) -Encoding utf8
New-Item -ItemType Directory -Path $RootDirectory | Out-Null
$snapshot = Read-Snapshot
$signature = $snapshot.Rules[0].Signature
if ($signature.Namespace -ne '.testdcheck') { throw "namespace is not canonical: $($signature.Namespace)" }
if ($signature.NameServers -ne '127.0.0.1') { throw "name servers are not canonical: $($signature.NameServers)" }
if ((@(Get-PropertyDifferences $snapshot)).Count -ne 0) {
	throw 'a matching multi-entry rule was reported as missing'
}
Restore-Snapshot
$script:live.Name = 'replacement-rule'
if ((@(Get-PropertyDifferences $snapshot)).Count -eq 0) { throw 'a replacement rule was not reported' }
try { Restore-Snapshot; throw 'changed rule was accepted' } catch {
	if ($_ -match 'changed rule was accepted|must not remove|must not recreate|must not change') { throw }
}
$script:live = $live
$script:live.Name = 'fixture-rule'
$script:roots = @('0123456789012345678901234567890123456789')
try { Restore-Snapshot; throw 'unknown root was accepted' } catch {
	if ($_ -match 'unknown root was accepted|must not remove|must not recreate|must not change') { throw }
}
Remove-Item -LiteralPath $Destination -Recurse -Force
'''


def snapshot_probe(engine):
	script = state.powershell_quote(str(ROOT / 'tests/release/windows-system-state.ps1'))
	command = (
		"$Tld = 'testdcheck';"
		"$Destination = Join-Path ([IO.Path]::GetTempPath()) ('testd-snapshot-' + [guid]::NewGuid().ToString('N'));"
		'New-Item -ItemType Directory -Path $Destination | Out-Null;'
		'$tokens = $null; $errors = $null;'
		f'$ast = [System.Management.Automation.Language.Parser]::ParseFile({script}, [ref]$tokens, [ref]$errors);'
		'foreach ($statement in $ast.FindAll({ $args[0] -is '
		'[System.Management.Automation.Language.AssignmentStatementAst] }, $false)) {'
		' . ([scriptblock]::Create($statement.Extent.Text)) };'
		'foreach ($function in $ast.FindAll({ $args[0] -is '
		'[System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {'
		' . ([scriptblock]::Create($function.Extent.Text)) };'
		+ SNAPSHOT_PROBE)
	result = subprocess.run([engine, '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True)
	return result.returncode, (result.stdout + result.stderr).decode('utf-8', errors='replace').strip()


@unittest.skipUnless(POWERSHELLS, POWERSHELL_SKIP)
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

	def test_windows_system_scripts_refuse_before_touching_the_host(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			marker = root / 'keep'
			marker.write_text('existing data', encoding='utf-8')
			env = {**os.environ, 'TESTD_HOST_TEST_SYSTEM': '1', 'TESTD_HOST_OUTPUT_DIR': str(root / 'output')}
			for engine in POWERSHELLS:
				for script in ('tests/host/windows.ps1', 'tests/release/windows-system-fixture.ps1'):
					with self.subTest(engine=pathlib.Path(engine).name, script=script):
						result = subprocess.run([engine, '-NoProfile', '-NonInteractive', '-File', str(ROOT / script)],
							env=env, capture_output=True, encoding='utf-8', timeout=30)
						self.assertNotEqual(result.returncode, 0)
						self.assertIn('blocked', result.stderr.lower())
						self.assertEqual(marker.read_text(encoding='utf-8'), 'existing data')
						self.assertFalse((root / 'output').exists())

	def test_windows_cleanup_uses_fixture_process_objects_and_a_finally_block(self):
		script = state.powershell_quote(ROOT / 'tests/host/windows.ps1')
		command = (
			'$tokens = $null; $errors = $null;'
			f'$ast = [System.Management.Automation.Language.Parser]::ParseFile({script}, [ref]$tokens, [ref]$errors);'
			'$definition = $ast.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] '
			"-and $args[0].Name -eq 'Stop-FixtureProcess' }, $true);"
			'. ([scriptblock]::Create($definition.Extent.Text));'
			"$cleanup = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TryStatementAst] "
			"-and $null -ne $args[0].Finally -and $args[0].Finally.Extent.Text -match \"Section 'cleanup'\" }, $true));"
			"if ($cleanup.Count -ne 1) { throw 'missing cleanup finally' };"
			'$process = [pscustomobject]@{ HasExited = $false; Calls = 0 };'
			"$process | Add-Member ScriptMethod Kill { $this.Calls++; $this.HasExited = $true };"
			"$process | Add-Member ScriptMethod WaitForExit { param($timeout) return $true };"
			'Stop-FixtureProcess $process; Stop-FixtureProcess $process;'
			"if ($process.Calls -ne 1) { throw 'incorrect process cleanup' };"
			"$failed = [pscustomobject]@{ HasExited = $false };"
			"$failed | Add-Member ScriptMethod Kill { throw 'fixture kill failed' };"
			"try { Stop-FixtureProcess $failed; throw 'error was swallowed' } catch { "
			"if ($_ -match 'error was swallowed') { throw } }; exit 0;"
		)
		for engine in POWERSHELLS:
			with self.subTest(engine=pathlib.Path(engine).name):
				result = subprocess.run([engine, '-NoProfile', '-NonInteractive', '-Command', command],
					capture_output=True, encoding='utf-8', timeout=30)
				self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
		self.assertNotIn('Stop-Process -Id', (ROOT / 'tests/host/windows.ps1').read_text(encoding='utf-8'))

	def test_windows_login_entry_does_not_count_as_candidate_evidence(self):
		script = state.powershell_quote(ROOT / 'tests/host/windows.ps1')
		command = (
			'[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false);'
			'$tokens = $null; $errors = $null;'
			f'$ast = [System.Management.Automation.Language.Parser]::ParseFile({script}, [ref]$tokens, [ref]$errors);'
			'$definition = $ast.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] '
			"-and $args[0].Name -eq 'Report-LaunchAtLogin' }, $true);"
			'. ([scriptblock]::Create($definition.Extent.Text));'
			'$script:records = @();'
			'function global:Skip([string]$message) { $script:records += $message };'
			"function global:Pass { throw 'unvalidated login entry was counted as a pass' };"
			"function global:Fail { throw 'an unrelated login entry was counted as a failure' };"
			"Report-LaunchAtLogin 'C:\\work\\target\\debug\\testd-gui.exe';"
			"Report-LaunchAtLogin 'C:\\other\\unrelated.exe';"
			"Report-LaunchAtLogin '';"
			'$script:records | ConvertTo-Json -Compress'
		)
		for engine in POWERSHELLS:
			with self.subTest(engine=pathlib.Path(engine).name):
				result = subprocess.run([engine, '-NoProfile', '-NonInteractive', '-Command', command],
					capture_output=True, encoding='utf-8', timeout=30)
				self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
				records = json.loads(result.stdout)
				self.assertEqual(len(records), 3)
				self.assertIn('not validated against the candidate', records[0])
				self.assertIn('not validated against the candidate', records[1])
				self.assertIn('not configured', records[2])

	def test_windows_host_fixture_disables_real_providers(self):
		with tempfile.TemporaryDirectory() as temporary:
			home = pathlib.Path(temporary) / 'fixture-home'
			script = state.powershell_quote(ROOT / 'tests/host/windows.ps1')
			path = state.powershell_quote(home)
			command = (
				'[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false);'
				'$tokens = $null; $errors = $null;'
				f'$ast = [System.Management.Automation.Language.Parser]::ParseFile({script}, [ref]$tokens, [ref]$errors);'
				'$definition = $ast.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] '
				"-and $args[0].Name -eq 'Set-TestEnvironment' }, $true);"
				'. ([scriptblock]::Create($definition.Extent.Text));'
				"$env:TESTD_TUNNEL = 'real-provider'; $env:TESTD_TOKEN = 'real-secret';"
				"$env:TESTD_HOSTS = 'remote.example'; $env:TESTD_HOST_TLD = 'testdcheck';"
				f'$appData = Set-TestEnvironment {path};'
				'@{ home = $env:HOME; appdata = $env:APPDATA; tunnel = $env:TESTD_TUNNEL; '
				'leaked = [bool]($env:TESTD_TOKEN -or $env:TESTD_HOSTS); allowed = $env:TESTD_HOST_TLD; '
				'created = (Test-Path -LiteralPath $appData -PathType Container) } | ConvertTo-Json -Compress'
			)
			for engine in POWERSHELLS:
				with self.subTest(engine=pathlib.Path(engine).name):
					result = subprocess.run([engine, '-NoProfile', '-NonInteractive', '-Command', command],
						capture_output=True, encoding='utf-8', timeout=30)
					self.assertEqual(result.returncode, 0, result.stderr)
					value = json.loads(result.stdout)
					self.assertEqual(value['home'], str(home))
					self.assertEqual(value['tunnel'], str(home))
					self.assertFalse(value['leaked'])
					self.assertEqual(value['allowed'], 'testdcheck')
					self.assertTrue(value['created'])
					self.assertEqual(pathlib.Path(value['appdata']), home / 'AppData/Roaming')

	def test_windows_disconnect_requires_router_and_live_dns_evidence(self):
		script = state.powershell_quote(ROOT / 'tests/host/windows.ps1')
		command = (
			'[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false);'
			'$tokens = $null; $errors = $null;'
			f'$ast = [System.Management.Automation.Language.Parser]::ParseFile({script}, [ref]$tokens, [ref]$errors);'
			"foreach ($name in @('Router-Status', 'Test-NameRemoved')) {"
			'$definition = $ast.Find({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] '
			'-and $args[0].Name -eq $name }, $true); . ([scriptblock]::Create($definition.Extent.Text)) };'
			"$Tld = 'testdcheck'; $router = '404'; $stale = $false; $dns = $true;"
			'function global:curl.exe { $global:curlArgs = @($args); return $global:router };'
			'function global:Resolve-DnsName { [CmdletBinding()] param($Name, $Server, $Type, [switch]$DnsOnly);'
			"if ($Name -eq 'testd.testdcheck') { if ($global:dns) { return @{ IPAddress = '127.0.0.1' } }; "
			"throw 'DNS unavailable' }; if ($global:stale) { return @{ IPAddress = '127.0.0.1' } }; throw 'NXDOMAIN' };"
			"$good = Test-NameRemoved 'app.testdproj.testdcheck';"
			"$router = '200'; $routed = Test-NameRemoved 'app.testdproj.testdcheck';"
			"$router = '000'; $unreachable = Test-NameRemoved 'app.testdproj.testdcheck';"
			"$router = '404'; $stale = $true; $staleName = Test-NameRemoved 'app.testdproj.testdcheck';"
			"$stale = $false; $dns = $false; $noDns = Test-NameRemoved 'app.testdproj.testdcheck';"
			'@{ good = $good; routed = $routed; unreachable = $unreachable; stale = $staleName; '
			'noDns = $noDns; curlArgs = $global:curlArgs } | ConvertTo-Json -Depth 4 -Compress'
		)
		for engine in POWERSHELLS:
			with self.subTest(engine=pathlib.Path(engine).name):
				result = subprocess.run([engine, '-NoProfile', '-NonInteractive', '-Command', command],
					capture_output=True, encoding='utf-8', timeout=30)
				self.assertEqual(result.returncode, 0, result.stderr)
				value = json.loads(result.stdout)
				self.assertTrue(value['good'])
				for field in ('routed', 'unreachable', 'stale', 'noDns'):
					self.assertFalse(value[field], field)
				self.assertIn('Host: app.testdproj.testdcheck', value['curlArgs'])
				self.assertIn('http://127.0.0.1:7740/', value['curlArgs'])

	def test_nrpt_snapshot_detects_replacements_without_mutating_rules_or_roots(self):
		"""Compare multi-entry rules without deleting a replacement or unknown root."""
		for engine in POWERSHELLS:
			with self.subTest(engine=pathlib.Path(engine).name):
				code, output = snapshot_probe(engine)
				self.assertEqual(code, 0, output)


if __name__ == '__main__':
	unittest.main()
