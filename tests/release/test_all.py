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
	parent = FakeRun(args, root / 'report', commands, failures, outputs)
	def child(child_args):
		return FakeRun(child_args, child_args.report, commands, failures, outputs)
	api = SimpleNamespace(Run=child, SYSTEM=system, HOST_TLD='testdcheck', DESKTOP_TLD='test',
		binary=Mock(return_value=root / 'candidate'), file_digest=Mock(return_value='a' * 64),
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
			self.assertIn('--run-ignored', by_name['contracts-msrv'])
			self.assertIn('--no-fail-fast', by_name['contracts-msrv'])
			self.assertIn('--all-features', by_name['cli-stable'])
			self.assertIn('--all-features', by_name['workspace-stable'])
			self.assertIn('--include-ignored', by_name['rustdoc-msrv'])
			self.assertIn('--include-ignored', by_name['rustdoc-cli-stable'])
			self.assertIn('--include-ignored', by_name['rustdoc-workspace'])
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
			with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
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

	def test_fixture_skips_are_incomplete_not_a_pass(self):
		with tempfile.TemporaryDirectory() as temporary:
			parent, api, _ = fixture(temporary, outputs={'release-script-fixtures': 'OK (skipped=2)'})
			with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				checks.execute(parent, api)
			self.assertEqual(outcome(parent, 'release-script-fixtures')['status'], 'blocked')
			self.assertTrue(parent.metadata['incomplete'])

	def test_artifact_checks_distinguish_missing_and_inapplicable_prior_releases(self):
		for no_previous, expected in [(False, 'blocked'), (True, 'pass')]:
			with self.subTest(no_previous=no_previous), tempfile.TemporaryDirectory() as temporary:
				args = arguments(artifacts=pathlib.Path(temporary), no_previous_release=no_previous)
				parent, api, _ = fixture(temporary, args=args)
				with patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
					checks.execute(parent, api)
				self.assertEqual(outcome(parent, 'artifacts')['status'], expected)
				api.artifacts.assert_called_once()
				self.assertTrue(api.artifacts.call_args.args[0].args.require_checksums)
				self.assertTrue(api.artifacts.call_args.args[0].args.host)

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
				child.record('system-restore', 'pass', 'fixture restore')
			api.desktop.side_effect = desktop
			stage = next(item for item in run.stages() if item.name == 'desktop')
			with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
				contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'desktop')['status'], 'fail')
			self.assertFalse(run.system_unsafe)

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
			with patch.object(run, 'confirm', return_value=True), contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'browser')['status'], 'fail')
			api.browser.assert_not_called()

	def test_macos_probe_refuses_preexisting_integration_before_running(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, interactive=True)
			parent, api, commands = fixture(temporary, args=args, system='Darwin')
			api.system_snapshot.side_effect = RuntimeError('pre-existing integration')
			run = checks.AllChecks(parent, api, args)
			run.cli = pathlib.Path('candidate')
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			stage = next(item for item in run.stages() if item.name == 'platform-resolver-probe')
			with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
				patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'platform-resolver-probe')['status'], 'fail')
			self.assertFalse(commands)
			api.system_restore.assert_not_called()

	def test_macos_probe_restores_the_scoped_snapshot_after_failure(self):
		with tempfile.TemporaryDirectory() as temporary:
			args = arguments(system=True, interactive=True)
			parent, api, commands = fixture(temporary, args=args, system='Darwin', failures=('macos-resolver-probe',))
			run = checks.AllChecks(parent, api, args)
			run.cli = pathlib.Path('candidate')
			run.system_confirmed = True
			run.boundary_log = io.StringIO()
			stage = next(item for item in run.stages() if item.name == 'platform-resolver-probe')
			with patch.object(run, 'confirm', return_value=True), patch.object(run, 'authorize'), \
				patch.object(checks.shutil, 'which', return_value='installed'), contextlib.redirect_stdout(io.StringIO()):
				run.stage(1, 1, stage)
			self.assertEqual(outcome(parent, 'platform-resolver-probe')['status'], 'fail')
			self.assertEqual([name for name, *_ in commands], ['macos-resolver-probe'])
			api.system_snapshot.assert_called_once()
			api.system_restore.assert_called_once_with(api.system_snapshot.call_args.args[0],
				api.system_snapshot.return_value, 'test', interactive=True)

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

	def test_main_returns_failure_before_incomplete_and_never_treats_incomplete_as_success(self):
		for failed, incomplete, expected in [(False, False, 0), (False, True, 2), (True, True, 1)]:
			with self.subTest(failed=failed, incomplete=incomplete):
				run = Mock(metadata={'incomplete': incomplete},
					results=[{'status': 'fail' if failed else 'pass'}])
				module = Mock()
				with patch.object(runner, 'Run', return_value=run), patch.object(runner, 'helper', return_value=module), \
					patch.object(runner, 'all_suites'), patch.object(runner.signal, 'signal'), \
					patch.object(runner, 'match_redirected_encoding'):
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
