import argparse
import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load(name, path):
	spec = importlib.util.spec_from_file_location(name, path)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


checks = load('testd_all_checks', ROOT / 'tests/release/all_checks.py')
doctest_output = load('testd_doctest_output', ROOT / 'tests/release/doctest_output.py')
runner = load('testd_all_runner', ROOT / 'tests/release/run.py')


def arguments(**overrides):
	values = dict(suite='all', report=None, bin=None, app=None, artifacts=None, previous_bin=None,
		no_previous_release=False, interactive=False, system=False, plan=False, gui=False, strict=False,
		host=False, service=False, require_checksums=False, port=19080, edge_port=443, intake_port=7737)
	values.update(overrides)
	return SimpleNamespace(**values)


class FakeRun:
	def __init__(self, args, output, commands=None, failures=(), outputs=None):
		self.args = args
		self.output = output
		self.output.mkdir(parents=True, exist_ok=True)
		self.metadata = {}
		self.results = []
		self.commands = commands if commands is not None else []
		self.failures = failures
		self.outputs = outputs or {}

	def save(self):
		pass

	def record(self, name, status, detail=''):
		self.results.append({'name': name, 'status': status, 'detail': detail})

	def command(self, name, command, timeout=300, env=None, **options):
		self.commands.append((name, command, timeout, env, options))
		if name in self.failures:
			self.record(name, 'fail', 'fixture failure')
			raise RuntimeError(f'{name} failed')
		self.record(name, 'pass', 'fixture success')
		return self.outputs.get(name, '')


def fixture(directory, *, args=None, system='Linux', failures=(), outputs=None):
	root = pathlib.Path(directory)
	args = args or arguments()
	commands = []
	outputs = {'release-script-fixtures': 'Ran 1 test in 0.1s\n\nOK\n',
		'system-restore-self-test': 'ok       scoped fixture state was restored and verified\n', **(outputs or {})}
	parent = FakeRun(args, root / 'report', commands, failures, outputs)
	def child(child_args):
		return FakeRun(child_args, child_args.report, commands, failures, outputs)
	api = SimpleNamespace(Run=child, SYSTEM=system, HOST_TLD='testdcheck', DESKTOP_TLD='test',
		NEXTEST_OUTPUT_OPTIONS=runner.NEXTEST_OUTPUT_OPTIONS,
		prepare_doctests=Mock(side_effect=lambda project, report, env: (dict(env), None, None)),
		replay_doctests=Mock(), binary=Mock(return_value=root / 'candidate'), file_digest=Mock(return_value='a' * 64),
		host=Mock(), service=Mock(), artifacts=Mock(), desktop=Mock(), browser=Mock(),
		system_snapshot=Mock(return_value=root / 'snapshot'), system_restore=Mock(),
		check_ports=Mock(), checklist_items=runner.checklist_items)
	return parent, api, commands


def outcome(run, name):
	return next(item for item in run.metadata['stages'] if item['name'] == name)


class AllChecksTests(unittest.TestCase):
	def test_all_stages_have_boundaries_and_continue_after_a_failure(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, commands = fixture(temporary, failures=('contracts-msrv',))
			output = io.StringIO()
			with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(output):
				checks.execute(parent, api)
			stages = parent.metadata['stages']
			self.assertEqual(len(stages), 31)
			self.assertEqual(outcome(parent, 'contracts-msrv')['status'], 'fail')
			self.assertEqual(outcome(parent, 'site-links')['status'], 'pass')
			self.assertEqual(outcome(parent, 'host-system')['status'], 'blocked')
			self.assertTrue(parent.metadata['incomplete'])
			for index, stage in enumerate(stages, 1):
				start = f'BEGIN [{index:02d}/{len(stages):02d}] {stage["name"]}'
				end = f'END [{index:02d}/{len(stages):02d}] {stage["name"]}: {stage["status"].upper()}'
				self.assertIn(start, output.getvalue())
				self.assertIn(end, output.getvalue())
			self.assertIn('ALL TESTS: SUMMARY', (parent.output / 'boundaries.log').read_text())
			self.assertLess(output.getvalue().index('END [06/31] contracts-msrv: FAIL'),
				output.getvalue().index('BEGIN [07/31] cli-stable'))
			api.host.assert_called_once()
			self.assertFalse(api.host.call_args.args[0].args.system)
			api.service.assert_not_called()
			api.browser.assert_not_called()
			api.desktop.assert_not_called()
			by_name = {name: command for name, command, _, _, _ in commands}
			for name in ('contracts-msrv', 'cli-stable', 'workspace-stable'):
				command = by_name[name]
				self.assertEqual(command[command.index('--success-output') + 1], 'immediate')
				self.assertEqual(command[command.index('--failure-output') + 1], 'immediate')
				self.assertEqual(command[command.index('--status-level') + 1], 'all')
			self.assertIn('--run-ignored', by_name['contracts-msrv'])
			self.assertIn('--no-fail-fast', by_name['contracts-msrv'])
			self.assertIn('--all-features', by_name['cli-stable'])
			self.assertIn('--all-features', by_name['workspace-stable'])
			for name in ('rustdoc-msrv', 'rustdoc-cli-stable', 'rustdoc-workspace'):
				self.assertIn('--include-ignored', by_name[name])
				self.assertIn('--show-output', by_name[name])
			self.assertEqual(api.prepare_doctests.call_count, 3)
			self.assertIn('testd-gui', by_name['msrv-gui'])
			self.assertIn('deny', by_name['dependency-audit'])
			self.assertEqual(by_name['browser-server-fixtures'][-1], str(ROOT / 'tests/release/browser.test.ts'))
			site_env = next(env for name, _, _, env, _ in commands if name == 'site-build')
			self.assertEqual(site_env['TESTD_SITE_OUT_DIR'], str(parent.output / 'site-dist'))
			self.assertEqual(site_env['TESTD_DOCS_CACHE_DIR'], str(parent.output / 'site-cache'))

	def test_missing_tools_block_only_the_affected_stages(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, commands = fixture(temporary)
			def which(name, path=None):
				return None if name == 'bun' else 'installed'
			with patch.object(checks.shutil, 'which', side_effect=which), contextlib.redirect_stdout(io.StringIO()):
				checks.execute(parent, api)
			for name in ('browser-server-fixtures', 'site-check', 'site-build', 'site-links'):
				self.assertEqual(outcome(parent, name)['status'], 'blocked')
			self.assertEqual(outcome(parent, 'rustdoc-msrv')['status'], 'pass')
			api.host.assert_called_once()
			self.assertNotIn('site-build', [name for name, *_ in commands])

	def test_missing_site_dependencies_are_reported_without_installing_them(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, commands = fixture(temporary)
			def which(name, path=None):
				return None if path and name == 'vite' else 'installed'
			with patch.object(checks.shutil, 'which', side_effect=which), contextlib.redirect_stdout(io.StringIO()):
				checks.execute(parent, api)
			self.assertEqual(outcome(parent, 'site-check')['status'], 'blocked')
			self.assertEqual(outcome(parent, 'site-build')['status'], 'blocked')
			self.assertIn('bun install --frozen-lockfile', outcome(parent, 'site-build')['detail'])
			self.assertEqual(outcome(parent, 'browser-server-fixtures')['status'], 'pass')
			self.assertFalse(any('install' == argument for _, command, *_ in commands for argument in command))

	def test_failed_site_build_cannot_reuse_a_stale_link_tree(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, commands = fixture(temporary, failures=('site-build',))
			with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				checks.execute(parent, api)
			self.assertEqual(outcome(parent, 'site-build')['status'], 'fail')
			self.assertEqual(outcome(parent, 'site-links')['status'], 'blocked')
			self.assertNotIn('site-links', [name for name, *_ in commands])
			api.host.assert_called_once()

	def test_failed_candidate_blocks_host_checks_without_stopping_the_sequence(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, _ = fixture(temporary)
			api.binary.side_effect = RuntimeError('candidate build failed')
			with patch.object(checks.shutil, 'which', return_value='installed'), \
				contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				checks.execute(parent, api)
			self.assertEqual(outcome(parent, 'cli-candidate')['status'], 'fail')
			self.assertEqual(outcome(parent, 'host-unprivileged')['status'], 'blocked')
			self.assertEqual(outcome(parent, 'platform-resolver-probe')['status'], 'not-applicable')
			api.host.assert_not_called()

	def test_interruption_marks_remaining_stages_blocked_with_boundaries(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, _ = fixture(temporary)
			run = checks.AllChecks(parent, api, parent.args)
			later = Mock()
			def interrupt(child):
				raise KeyboardInterrupt()
			stages = [checks.Stage('first', interrupt), checks.Stage('second', later)]
			output = io.StringIO()
			with patch.object(run, 'stages', return_value=stages), contextlib.redirect_stdout(output):
				run.execute()
			self.assertTrue(parent.metadata['incomplete'])
			self.assertEqual(outcome(parent, 'first')['status'], 'blocked')
			self.assertEqual(outcome(parent, 'second')['status'], 'blocked')
			self.assertIn('END [01/02] first: BLOCKED', output.getvalue())
			self.assertIn('END [02/02] second: BLOCKED', output.getvalue())
			later.assert_not_called()

	def test_doctest_logging_conflict_is_incomplete_but_does_not_skip_the_tests(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, commands = fixture(temporary)
			api.prepare_doctests.side_effect = lambda project, report, env: (dict(env), None, 'custom runtool')
			run = checks.AllChecks(parent, api, parent.args)
			run.boundary_log = io.StringIO()
			stage = next(item for item in run.stages() if item.name == 'rustdoc-msrv')
			with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'rustdoc-msrv')['status'], 'blocked')
			self.assertIn('rustdoc-msrv', [name for name, *_ in commands])
			api.replay_doctests.assert_not_called()

	def test_doctest_output_is_replayed_after_a_failed_command(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, _ = fixture(temporary, failures=('rustdoc-msrv',))
			directory = pathlib.Path(temporary) / 'doctest-output'
			api.prepare_doctests.side_effect = lambda project, report, env: (dict(env), directory, None)
			run = checks.AllChecks(parent, api, parent.args)
			run.boundary_log = io.StringIO()
			stage = next(item for item in run.stages() if item.name == 'rustdoc-msrv')
			with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'rustdoc-msrv')['status'], 'fail')
			api.replay_doctests.assert_called_once_with(directory)

	def test_fixture_skips_are_incomplete_not_a_pass(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, _ = fixture(temporary, outputs={'release-script-fixtures': 'OK (skipped=2)'})
			with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				checks.execute(parent, api)
			self.assertEqual(outcome(parent, 'release-script-fixtures')['status'], 'blocked')
			self.assertTrue(parent.metadata['incomplete'])

	def test_source_diff_is_captured_only_by_the_parent_report(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(include_git_diff=True)
			parent, api, _ = fixture(temporary, args=args)
			run = checks.AllChecks(parent, api, args)
			stage = next(item for item in run.stages() if item.name == 'format')
			child = run.child_run(1, stage)
			self.assertTrue(parent.args.include_git_diff)
			self.assertFalse(child.args.include_git_diff)

	def test_platform_fixture_skips_are_not_confused_with_missing_evidence(self):
		cases = (
			('Ran 2 tests in 0.1s\n\nOK (skipped=0)\n', 'pass'),
			("test_a ... skipped 'not applicable: Unix only'\nRan 2 tests in 0.1s\n\nOK (skipped=1)\n", 'pass'),
			("test_a ... skipped 'not applicable: PowerShell fixtures are required only on Windows'\n"
				"Ran 2 tests in 0.1s\n\nOK (skipped=1)\n", 'pass'),
			("test_a ... skipped 'PowerShell is required on Windows'\nRan 2 tests in 0.1s\n\nOK (skipped=1)\n", 'blocked'),
			("test_a ... skipped 'not applicable: Unix only'\nRan 2 tests in 0.1s\n\nOK (skipped=2)\n", 'blocked'),
			("test_a ... skipped 'not applicable: Unix only'\nRan 2 tests in 0.1s\n\nOK\n", 'blocked'),
			('Ran 0 tests in 0.1s\n\nOK\n', 'blocked'),
			('no result summary', 'blocked'),
		)
		for output, expected in cases:
			with self.subTest(output=output), tempfile.TemporaryDirectory() as temporary:
				parent, api, _ = fixture(temporary, outputs={'release-script-fixtures': output})
				run = checks.AllChecks(parent, api, parent.args)
				run.boundary_log = io.StringIO()
				stage = next(item for item in run.stages() if item.name == 'release-script-fixtures')
				with contextlib.redirect_stdout(io.StringIO()):
					run.stage(1, 1, stage)
				self.assertEqual(outcome(parent, 'release-script-fixtures')['status'], expected)

	def test_artifact_checks_distinguish_missing_and_inapplicable_prior_releases(self):
		for no_previous, expected in [(False, 'blocked'), (True, 'pass')]:
			with self.subTest(no_previous=no_previous), tempfile.TemporaryDirectory() as temporary:
				args = arguments(system=True, artifacts=pathlib.Path(temporary), no_previous_release=no_previous)
				parent, api, _ = fixture(temporary, args=args)
				run = checks.AllChecks(parent, api, args)
				run.system_confirmed = True
				run.boundary_log = io.StringIO()
				stage = next(item for item in run.stages() if item.name == 'artifacts')
				with patch.object(run, 'confirm', return_value=True), contextlib.redirect_stdout(io.StringIO()):
					run.stage(1, 1, stage)
				self.assertEqual(outcome(parent, 'artifacts')['status'], expected)
				api.artifacts.assert_called_once()
				self.assertTrue(api.artifacts.call_args.args[0].args.require_checksums)
				self.assertTrue(api.artifacts.call_args.args[0].args.host)

	def test_blocked_artifact_uninstall_blocks_later_system_stages(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, artifacts=pathlib.Path(temporary), no_previous_release=True)
			parent, api, _ = fixture(temporary, args=args)
			api.artifacts.side_effect = lambda child: child.record('uninstall', 'skip', 'blocked: real cleanup not run')
			run = checks.AllChecks(parent, api, args)
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			artifact = next(item for item in run.stages() if item.name == 'artifacts')
			later = next(item for item in run.stages() if item.name == 'system-restore-self-test')
			with patch.object(run, 'confirm', return_value=True), contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 2, artifact)
				run.stage(2, 2, later)
			self.assertEqual(outcome(parent, 'artifacts')['status'], 'blocked')
			self.assertEqual(outcome(parent, 'system-restore-self-test')['status'], 'blocked')
			self.assertTrue(run.system_unsafe)

	def test_artifacts_never_execute_without_disposable_host_confirmation(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(artifacts=pathlib.Path(temporary))
			parent, api, _ = fixture(temporary, args=args)
			run = checks.AllChecks(parent, api, args)
			run.boundary_log = io.StringIO()
			stage = next(item for item in run.stages() if item.name == 'artifacts')
			with contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'artifacts')['status'], 'blocked')
			api.artifacts.assert_not_called()

	def test_declined_system_confirmation_never_starts_sensitive_operations(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, interactive=True, app=pathlib.Path('app'))
			parent, api, _ = fixture(temporary, args=args)
			run = checks.AllChecks(parent, api, args)
			with patch.object(run, 'confirm', return_value=False), \
				patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				run.execute()
			self.assertEqual(outcome(parent, 'system-restore-self-test')['status'], 'blocked')
			self.assertEqual(outcome(parent, 'desktop')['status'], 'blocked')
			api.host.assert_called_once()
			api.service.assert_not_called()
			api.desktop.assert_not_called()
			api.browser.assert_not_called()

	def test_failed_system_stage_blocks_later_system_changes(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, interactive=True, app=pathlib.Path('app'))
			parent, api, commands = fixture(temporary, args=args, failures=('system-restore-self-test',))
			run = checks.AllChecks(parent, api, args)
			with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
				patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				run.execute()
			self.assertEqual(outcome(parent, 'system-restore-self-test')['status'], 'fail')
			self.assertEqual(outcome(parent, 'host-system')['status'], 'blocked')
			self.assertIn('earlier system stage failed', outcome(parent, 'desktop')['detail'])
			api.host.assert_called_once()
			api.service.assert_not_called()
			api.desktop.assert_not_called()
			api.browser.assert_not_called()
			self_test = next(command for name, command, *_ in commands if name == 'system-restore-self-test')
			self.assertIn('--workdir', self_test)
			self.assertTrue(pathlib.Path(self_test[-1]).is_relative_to(parent.output))

	def test_unverified_shared_trust_effects_block_later_system_stages(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, interactive=True, app=pathlib.Path('app'))
			parent, api, _ = fixture(temporary, args=args)
			run = checks.AllChecks(parent, api, args)
			with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
					patch.object(checks.shutil, 'which', return_value='installed'), \
					contextlib.redirect_stdout(io.StringIO()):
				run.execute()
			self.assertEqual(outcome(parent, 'system-restore-self-test')['status'], 'blocked')
			self.assertEqual(outcome(parent, 'host-system')['status'], 'blocked')
			self.assertIn('earlier system stage failed', outcome(parent, 'host-system')['detail'])
			api.host.assert_called_once()
			api.desktop.assert_not_called()

	def test_self_test_exit_two_without_success_evidence_is_a_failure(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True)
			parent, api, _ = fixture(temporary, args=args,
				outputs={'system-restore-self-test': 'usage: invalid arguments\n'})
			run = checks.AllChecks(parent, api, args)
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			stage = next(item for item in run.stages() if item.name == 'system-restore-self-test')
			with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
					contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'system-restore-self-test')['status'], 'fail')
			self.assertTrue(run.system_unsafe)

	def test_system_host_checks_reject_non_throwaway_tlds(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True)
			parent, api, _ = fixture(temporary, args=args)
			api.HOST_TLD = 'test'
			run = checks.AllChecks(parent, api, args)
			run.cli = pathlib.Path('candidate')
			child = FakeRun(arguments(), pathlib.Path(temporary) / 'child')
			with patch.object(run, 'authorize') as authorize, self.assertRaises(checks.Blocked):
				run.host_system(child)
			authorize.assert_not_called()
			api.host.assert_not_called()

	def test_host_skips_do_not_block_later_checks_when_host_and_restore_succeeded(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True)
			parent, api, _ = fixture(temporary, args=args)
			run = checks.AllChecks(parent, api, args)
			run.cli = pathlib.Path('candidate')
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			def host(child):
				child.record('host-checks', 'pass', 'fixture checks')
				child.record('host-coverage', 'skip', 'blocked: login not tested')
				child.record('fixture-shutdown', 'pass', 'fixture stopped')
				child.record('system-restore', 'pass', 'fixture restore')
			api.host.side_effect = host
			stage = next(item for item in run.stages() if item.name == 'host-system')
			with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
				contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'host-system')['status'], 'blocked')
			self.assertFalse(run.system_unsafe)

	def test_desktop_failures_do_not_block_later_checks_when_restore_succeeded(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, interactive=True, app=pathlib.Path('app'))
			parent, api, _ = fixture(temporary, args=args)
			run = checks.AllChecks(parent, api, args)
			run.cli = pathlib.Path('candidate')
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			def desktop(child):
				child.record('GUI-01', 'fail', 'fixture observation')
				child.record('fixture-shutdown', 'pass', 'fixture stopped')
				child.record('system-restore', 'pass', 'fixture restore')
			api.desktop.side_effect = desktop
			stage = next(item for item in run.stages() if item.name == 'desktop')
			with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
				contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'desktop')['status'], 'fail')
			self.assertFalse(run.system_unsafe)

	def test_failed_or_unverified_shutdown_blocks_later_system_changes(self):
		for name, shutdown in (('host-system', 'missing'), ('host-system', 'fail'), ('desktop', 'missing'),
				('desktop', 'fail')):
			with self.subTest(stage=name, shutdown=shutdown), tempfile.TemporaryDirectory() as temporary:
				args = arguments(system=True, interactive=True, app=pathlib.Path('app'))
				parent, api, _ = fixture(temporary, args=args)
				run = checks.AllChecks(parent, api, args)
				run.cli = pathlib.Path('candidate')
				run.system_confirmed = True
				run.boundary_log = io.StringIO()
				def action(child):
					child.record('host-checks', 'pass', 'fixture checks')
					child.record('system-restore', 'pass', 'scoped fixture restore')
					if shutdown == 'fail':
						child.record('fixture-shutdown', 'fail', 'a listener is still occupied')
					else:
						child.record('coverage', 'skip', 'blocked: shutdown was not verified')
				api.host.side_effect = action
				api.desktop.side_effect = action
				stage = next(item for item in run.stages() if item.name == name)
				with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
						contextlib.redirect_stdout(io.StringIO()):
					run.stage(1, 1, stage)
				self.assertIn(outcome(parent, name)['status'], ('fail', 'blocked'))
				self.assertTrue(run.system_unsafe)

	def test_browser_refuses_to_attach_to_an_existing_listener(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, interactive=True)
			parent, api, _ = fixture(temporary, args=args)
			run = checks.AllChecks(parent, api, args)
			run.cli = pathlib.Path('candidate')
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			api.check_ports.side_effect = RuntimeError('fixture port is in use')
			stage = next(item for item in run.stages() if item.name == 'browser')
			with patch.object(run, 'confirm', return_value=True), contextlib.redirect_stdout(io.StringIO()), \
				contextlib.redirect_stderr(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'browser')['status'], 'fail')
			api.browser.assert_not_called()

	def test_unowned_platform_integration_is_blocked_before_any_side_effect(self):
		for system in ('Darwin', 'Windows'):
			for name in ('host-system', 'desktop', 'platform-resolver-probe'):
				with self.subTest(system=system, stage=name), tempfile.TemporaryDirectory() as temporary:
					args = arguments(system=True, interactive=True, app=pathlib.Path('app'))
					parent, api, commands = fixture(temporary, args=args, system=system)
					run = checks.AllChecks(parent, api, args)
					run.cli = pathlib.Path('candidate')
					run.system_confirmed = True
					run.boundary_log = io.StringIO()
					stage = next(item for item in run.stages() if item.name == name)
					with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize') as authorize, \
							contextlib.redirect_stdout(io.StringIO()):
						run.stage(1, 1, stage)
					self.assertEqual(outcome(parent, name)['status'], 'blocked')
					self.assertFalse(commands)
					authorize.assert_not_called()
					api.system_snapshot.assert_not_called()
					api.host.assert_not_called()
					api.desktop.assert_not_called()

	def test_windows_self_test_is_blocked_before_authorization(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True)
			parent, api, commands = fixture(temporary, args=args, system='Windows')
			run = checks.AllChecks(parent, api, args)
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			stage = next(item for item in run.stages() if item.name == 'system-restore-self-test')
			with patch.object(run, 'authorize') as authorize, contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'system-restore-self-test')['status'], 'blocked')
			self.assertFalse(commands)
			authorize.assert_not_called()

	def test_browser_failures_do_not_block_later_checks_after_owned_fixtures_stop(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, interactive=True)
			parent, api, _ = fixture(temporary, args=args)
			run = checks.AllChecks(parent, api, args)
			run.cli = pathlib.Path('candidate')
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			def browser(child):
				child.record('browser-fixture', 'pass', 'stopped')
				child.record('host-fixture', 'pass', 'stopped')
				child.record('browser-results', 'fail', 'fixture observation')
			api.browser.side_effect = browser
			stage = next(item for item in run.stages() if item.name == 'browser')
			with patch.object(run, 'confirm', return_value=True), contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'browser')['status'], 'fail')
			self.assertFalse(run.system_unsafe)

	def test_windows_service_is_inapplicable_and_unsafe_probe_is_blocked(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, _ = fixture(temporary, system='Windows')
			with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				checks.execute(parent, api)
			self.assertEqual(outcome(parent, 'service-supervision')['status'], 'not-applicable')
			self.assertEqual(outcome(parent, 'platform-resolver-probe')['status'], 'blocked')
			self.assertIn('unrelated matching rules', outcome(parent, 'platform-resolver-probe')['detail'])
			api.service.assert_not_called()

	def test_manual_checklist_requires_evidence_and_preserves_blocked_status(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			path = root / 'manual.md'
			path.write_text('- [ ] First check\n- [ ] Second check\n', encoding='utf-8')
			parent, api, _ = fixture(temporary)
			run = checks.AllChecks(parent, api, parent.args)
			child = FakeRun(arguments(), root / 'child')
			with patch.object(checks, 'ROOT', root), \
				patch('builtins.input', side_effect=['p', '', 'evidence', 'b', 'not implemented']), \
				contextlib.redirect_stdout(io.StringIO()):
				run.manual('manual.md')(child)
			self.assertEqual(child.results[0]['status'], 'pass')
			self.assertEqual(child.results[0]['detail'], 'evidence')
			self.assertEqual(child.results[1]['status'], 'skip')
			self.assertEqual(child.results[1]['detail'], 'blocked: not implemented')
			self.assertEqual(run.classify(child)[0], 'blocked')

	def test_all_run_writes_one_transcript_even_when_a_stage_fails(self):
		with tempfile.TemporaryDirectory() as temporary:
			report = pathlib.Path(temporary).resolve() / 'report'
			def command(name, code):
				return lambda child: child.command(name, [sys.executable, '-c', code])
			def blocked(child):
				raise checks.Blocked('missing fixture')
			stages = [
				checks.Stage('passing', command('passing', "print('passed output')")),
				checks.Stage('failing', command('failing', "import sys; print('failure output', file=sys.stderr); sys.exit(7)")),
				checks.Stage('blocked', blocked),
				checks.Stage('later', command('later', "print('later output')")),
			]
			modules = {'all_checks': checks, 'doctest_output': doctest_output}
			with patch.object(runner, 'helper', side_effect=lambda name: modules[name]), \
				patch.object(checks, 'is_ephemeral', return_value=False), \
				patch.object(checks.AllChecks, 'stages', return_value=stages), patch.object(runner.signal, 'signal'), \
				contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
				self.assertEqual(runner.main(['all', '--report', str(report)]), 1)
			text = (report / 'run.log').read_text(encoding='utf-8')
			for value in ('BEGIN [01/04] passing', 'passed output', 'END [01/04] passing: PASS',
				'BEGIN [02/04] failing', 'failure output', 'END [02/04] failing: FAIL',
				'END [03/04] blocked: BLOCKED', 'later output', 'ALL TESTS: SUMMARY'):
				self.assertIn(value, text)
			self.assertEqual((report / '01-passing/00-passing.log').read_text(), 'passed output\n')
			self.assertIn('failure output', (report / '02-failing/00-failing.log').read_text())

	def test_main_returns_failure_before_incomplete_and_never_treats_incomplete_as_success(self):
		for failed, incomplete, expected in [(False, False, 0), (False, True, 2), (True, True, 1)]:
			with self.subTest(failed=failed, incomplete=incomplete):
				run = Mock(metadata={'incomplete': incomplete},
					results=[{'status': 'fail' if failed else 'pass'}])
				module = Mock()
				with patch.object(runner, 'Run', return_value=run), patch.object(runner, 'helper', return_value=module), \
					patch.object(runner, 'all_suites'), patch.object(runner, 'run_transcript', return_value=contextlib.nullcontext()), \
					patch.object(runner.signal, 'signal'), patch.object(runner, 'match_redirected_encoding'):
					self.assertEqual(runner.main(['all']), expected)

	def test_plan_lists_all_stages_without_executing_them(self):
		output = io.StringIO()
		with contextlib.redirect_stdout(output):
			checks.print_plan(arguments())
		self.assertIn('01. format', output.getvalue())
		self.assertIn('contracts-msrv', output.getvalue())
		self.assertIn('desktop [disposable host] [interactive]', output.getvalue())
		self.assertIn('platform-resolver-probe', output.getvalue())

	def test_validation_never_reuses_a_report_and_resolves_candidate_paths(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			candidate = root / 'candidate'
			candidate.write_text('fixture', encoding='utf-8')
			existing = root / 'existing'
			existing.mkdir()
			marker = existing / 'keep'
			marker.write_text('original', encoding='utf-8')
			parser = argparse.ArgumentParser()
			with patch.object(checks, 'is_ephemeral', return_value=False), contextlib.redirect_stderr(io.StringIO()):
				with self.assertRaises(SystemExit):
					checks.validate(parser, arguments(report=existing, bin=candidate))
				args = arguments(report=root / 'new', bin=candidate)
				checks.validate(parser, args)
			self.assertEqual(args.bin, candidate)
			self.assertEqual(args.report, root / 'new')
			self.assertEqual(marker.read_text(encoding='utf-8'), 'original')

	def test_system_validation_requires_terminal_persisted_report_and_explicit_scope(self):
		parser = argparse.ArgumentParser()
		terminal = Mock()
		terminal.isatty.return_value = False
		with patch.object(checks.sys, 'stdin', terminal), contextlib.redirect_stderr(io.StringIO()):
			with self.assertRaises(SystemExit):
				checks.validate(parser, arguments(system=True, report=pathlib.Path('/home/fixture/report')))
			with self.assertRaises(SystemExit):
				checks.validate(parser, arguments(interactive=True))
			checks.validate(parser, arguments(system=True, interactive=True, plan=True))
		with tempfile.TemporaryDirectory() as temporary:
			terminal.isatty.return_value = True
			with patch.object(checks.sys, 'stdin', terminal), contextlib.redirect_stderr(io.StringIO()):
				with self.assertRaises(SystemExit):
					checks.validate(parser, arguments(system=True, report=pathlib.Path(temporary) / 'report'))


if __name__ == '__main__':
	unittest.main()
