"""One coordinated, explicitly scoped run of the platform test suites."""

import copy
import ctypes
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]


class Blocked(RuntimeError):
	"""A check could not run, so it must not be reported as a pass."""


class NotApplicable(RuntimeError):
	"""The current platform does not ship the feature being tested."""


class Stage:
	def __init__(self, name, action, *, system=False, interactive=False, checkpoint='', precondition=None,
			stop_on_failure=True):
		self.name = name
		self.action = action
		self.system = system
		self.interactive = interactive
		self.checkpoint = checkpoint
		self.precondition = precondition
		self.stop_on_failure = stop_on_failure


def is_ephemeral(path):
	roots = [pathlib.Path(tempfile.gettempdir())]
	roots.extend(pathlib.Path(value) for name in ('TMPDIR', 'TMP', 'TEMP') if (value := os.environ.get(name)))
	if os.name != 'nt':
		roots.extend(pathlib.Path(value) for value in ('/tmp', '/run', '/dev/shm'))
	resolved = path.expanduser().resolve()
	return any(resolved.is_relative_to(root.resolve()) for root in roots)


def validate(parser, args):
	if platform.system() not in ('Linux', 'Darwin', 'Windows'):
		parser.error('all supports Linux, macOS, and Windows')
	for name, port, maximum in [('port', args.port, 65534), ('edge-port', args.edge_port, 65535),
			('intake-port', args.intake_port, 65535)]:
		if not 1 <= port <= maximum:
			parser.error(f'--{name} must be between 1 and {maximum}')
	if args.interactive and not args.system:
		parser.error('all --interactive requires --system and a disposable, backed-up host')
	if args.app and not args.interactive:
		parser.error('all --app requires --interactive')
	if args.previous_bin and not args.artifacts:
		parser.error('--previous-bin requires --artifacts in the all suite')
	if args.plan:
		return
	if args.system and (args.report is None or not sys.stdin.isatty()):
		parser.error('all --system requires an interactive terminal and a new persisted --report')
	base = args.report or pathlib.Path(os.environ.get('LOCALAPPDATA', pathlib.Path.home() / '.local/share'))
	if is_ephemeral(base):
		parser.error('all needs a persisted report outside temporary directories')
	if args.report:
		args.report = args.report.expanduser().absolute()
		if args.report.exists() or args.report.is_symlink():
			parser.error(f'report path already exists: {args.report}')
	for field, kind in [('bin', 'candidate CLI'), ('previous_bin', 'previous CLI')]:
		path = getattr(args, field)
		if path:
			path = path.expanduser().resolve()
			if not path.is_file():
				parser.error(f'{kind} is not a file: {path}')
			setattr(args, field, path)
	if args.app and not args.app.expanduser().exists():
		parser.error(f'candidate app does not exist: {args.app}')
	if args.artifacts and not args.artifacts.expanduser().is_dir():
		parser.error(f'artifact directory does not exist: {args.artifacts}')


def print_plan(args):
	checks = AllChecks(None, None, args)
	for index, stage in enumerate(checks.stages(), 1):
		kind = ' [disposable host]' if stage.system else ''
		kind += ' [interactive]' if stage.interactive else ''
		print(f'{index:02d}. {stage.name}{kind}')


def execute(run, api):
	checks = AllChecks(run, api, run.args)
	checks.execute()


class AllChecks:
	def __init__(self, run, api, args):
		self.run = run
		self.api = api
		self.args = args
		self.cli = None
		self.site_ready = False
		self.system_confirmed = False
		self.system_unsafe = False
		self.interrupted = False
		self.outcomes = []
		self.boundary_log = None

	def stages(self):
		cargo = ('cargo', 'rustup')
		nextest = (*cargo, 'cargo-nextest')
		return [
			Stage('format', self.command('format', ['cargo', '+stable', 'fmt', '--all', '--', '--check'], cargo)),
			Stage('clippy-cli', self.command('clippy-cli', ['cargo', '+stable', 'clippy', '--workspace',
				'--all-targets', '--exclude', 'testd-gui', '--locked', '--', '-D', 'warnings'], cargo)),
			Stage('clippy-workspace', self.command('clippy-workspace', ['cargo', '+stable', 'clippy', '--workspace',
				'--all-targets', '--all-features', '--locked', '--', '-D', 'warnings'], cargo)),
			Stage('msrv-cli', self.command('msrv-cli', ['cargo', '+1.89.0', 'check', '--workspace', '--exclude',
				'testd-gui', '--locked'], cargo)),
			Stage('msrv-gui', self.command('msrv-gui', ['cargo', '+1.90.0', 'check', '-p', 'testd-gui', '--locked'], cargo)),
			Stage('contracts-msrv', self.command('contracts-msrv', ['cargo', '+1.89.0', 'nextest', 'run',
				'--workspace', '--exclude', 'testd-gui', '--locked', '--run-ignored', 'all', '--no-fail-fast'], nextest,
				skip_pattern=r'\b(\d+) skipped\b')),
			Stage('cli-stable', self.command('cli-stable', ['cargo', '+stable', 'nextest', 'run', '--workspace',
				'--exclude', 'testd-gui', '--all-features', '--locked', '--run-ignored', 'all', '--no-fail-fast'], nextest,
				skip_pattern=r'\b(\d+) skipped\b')),
			Stage('workspace-stable', self.command('workspace-stable', ['cargo', '+stable', 'nextest', 'run',
				'--workspace', '--all-features', '--locked', '--run-ignored', 'all', '--no-fail-fast'], nextest,
				skip_pattern=r'\b(\d+) skipped\b')),
			Stage('rustdoc-msrv', self.command('rustdoc-msrv', ['cargo', '+1.89.0', 'test', '--workspace',
				'--exclude', 'testd-gui', '--doc', '--locked', '--', '--include-ignored'], cargo,
				skip_pattern=r'\b(\d+) ignored\b')),
			Stage('rustdoc-cli-stable', self.command('rustdoc-cli-stable', ['cargo', '+stable', 'test', '--workspace',
				'--exclude', 'testd-gui', '--all-features', '--doc', '--locked', '--', '--include-ignored'], cargo,
				skip_pattern=r'\b(\d+) ignored\b')),
			Stage('rustdoc-workspace', self.command('rustdoc-workspace', ['cargo', '+stable', 'test', '--workspace',
				'--all-features', '--doc', '--locked', '--', '--include-ignored'], cargo,
				skip_pattern=r'\b(\d+) ignored\b')),
			Stage('release-script-fixtures', self.command('release-script-fixtures', [sys.executable, '-m', 'unittest',
				'discover', '-s', 'tests/release', '-p', 'test_*.py', '-v'], (), 300,
				skip_pattern=r'\bskipped=(\d+)')),
			Stage('browser-server-fixtures', self.command('browser-server-fixtures', ['bun', '--no-install', 'test',
				str(ROOT / 'tests/release/browser.test.ts')], ('bun',), 300, skip_pattern=r'(?m)^\s*(\d+) skip\b')),
			Stage('dependency-audit', self.command('dependency-audit', ['cargo', '+stable', 'deny', '--workspace',
				'--locked', 'check'], (*cargo, 'cargo-deny'))),
			Stage('release-version', self.command('release-version', [sys.executable, 'scripts/release.py',
				'verify-version'], (), 300)),
			Stage('site-check', self.site_check),
			Stage('site-build', self.site_build),
			Stage('site-links', self.site_links),
			Stage('cli-candidate', self.candidate),
			Stage('host-unprivileged', self.host),
			Stage('artifacts', self.artifacts),
			Stage('system-restore-self-test', self.system_self_test, system=True,
				checkpoint='Use a clean disposable host. This writes real resolver and trust fixtures.'),
			Stage('host-system', self.host_system, system=True, precondition=self.require_candidate,
				checkpoint='Use a clean disposable host with no existing testd integration.'),
			Stage('service-supervision', self.service, system=True, precondition=self.service_available,
				checkpoint='Use a disposable user session; this starts and stops a test service.'),
			Stage('desktop', self.desktop, system=True, interactive=True, precondition=self.desktop_available,
				checkpoint='Use a fresh disposable user and the actual candidate app.'),
			Stage('browser', self.browser, system=True, interactive=True, precondition=self.require_candidate,
				checkpoint='Configure the candidate OS DNS and trust on a disposable host before continuing.'),
			Stage('manual-browser', self.manual('tests/manual/browser.md'), system=True, interactive=True,
				stop_on_failure=False, checkpoint='Complete the real-browser checks on the selected browser and host.'),
			Stage('manual-system', self.manual('tests/manual/system-integration.md'), system=True, interactive=True,
				stop_on_failure=False, checkpoint='Use the separately restored, synthetic system states required by the checklist.'),
			Stage('manual-installation', self.manual('tests/manual/installation.md'), system=True, interactive=True,
				stop_on_failure=False, checkpoint='Use disposable snapshots for the actual package and upgrade paths.'),
			Stage('manual-network-sharing', self.manual('tests/manual/network-and-sharing.md'),
				system=True, interactive=True, stop_on_failure=False,
				checkpoint='Do not expose a listener or use a real provider without approval.'),
			Stage('platform-resolver-probe', self.platform_probe, system=True, interactive=True,
				precondition=self.probe_available,
				checkpoint='Use a separate, clean disposable host; the macOS probe changes resolver and trust state.'),
		]

	def command(self, name, argv, tools, timeout=1200, environment=None, skip_pattern=None):
		def action(child):
			self.require(*tools)
			env = environment() if environment else None
			output = child.command(name, argv, timeout, env=env)
			if skip_pattern and any(int(value) for value in re.findall(skip_pattern, output)):
				child.record('coverage', 'skip', 'blocked: checks were skipped; inspect the command log')
		return action

	def require(self, *tools):
		missing = [tool for tool in tools if not shutil.which(tool)]
		if missing:
			raise Blocked(f'please install: {", ".join(missing)}')

	def site_environment(self):
		return {**os.environ, 'TESTD_SITE_OUT_DIR': str(self.run.output / 'site-dist'),
			'TESTD_DOCS_CACHE_DIR': str(self.run.output / 'site-cache')}

	def require_site_dependencies(self):
		self.require('bun')
		bin_dir = str(ROOT / 'node_modules/.bin')
		if any(not shutil.which(tool, path=bin_dir) for tool in ('tsc', 'vite', 'vitepress')):
			raise Blocked('website dependencies are missing; run bun install --frozen-lockfile first')

	def site_check(self, child):
		self.require_site_dependencies()
		self.command('site-check', ['bun', '--no-install', 'run', 'check'], (), 600, self.site_environment)(child)

	def site_build(self, child):
		self.require_site_dependencies()
		self.command('site-build', ['bun', '--no-install', 'run', 'build'], (), 600, self.site_environment)(child)
		self.site_ready = True

	def site_links(self, child):
		if not self.site_ready:
			raise Blocked('the isolated site build did not complete')
		self.command('site-links', ['bun', '--no-install', 'run', 'check:links'], ('bun',), 600,
			self.site_environment)(child)

	def candidate(self, child):
		if self.args.bin is None:
			self.require('cargo', 'rustup')
		self.cli = self.api.binary(child)
		self.run.metadata['candidate'] = {'path': str(self.cli), 'sha256': self.api.file_digest(self.cli)}
		self.run.save()

	def require_candidate(self):
		if self.cli is None:
			raise Blocked('the candidate CLI was not available')
		return self.cli

	def host(self, child):
		child.args.bin = self.require_candidate()
		child.args.system = False
		child.args.service = False
		self.api.host(child)

	def artifacts(self, child):
		if not self.args.artifacts:
			raise Blocked('provide --artifacts with the candidate assets and SHA256SUMS')
		child.args.artifacts = self.args.artifacts.expanduser().resolve()
		child.args.previous_bin = self.args.previous_bin.expanduser().resolve() if self.args.previous_bin else None
		child.args.require_checksums = True
		child.args.host = True
		child.args.system = False
		child.args.service = False
		self.api.artifacts(child)
		if not child.args.previous_bin:
			if self.args.no_previous_release:
				child.record('upgrade-rollback', 'skip', 'not applicable: no previous release')
			else:
				child.record('upgrade-rollback', 'skip', 'blocked: provide --previous-bin or --no-previous-release')

	def authorize(self, child):
		if self.api.SYSTEM == 'Windows':
			if not ctypes.windll.shell32.IsUserAnAdmin():
				raise Blocked('run the system checks from an elevated PowerShell')
		else:
			self.require('sudo')
			print('Validating sudo in the current terminal.', flush=True)
			result = subprocess.run(['sudo', '-v'], cwd=ROOT, timeout=300)
			if result.returncode:
				raise Blocked('sudo authorization was not granted')
		child.record('authorization', 'pass', 'system test authorization is available')

	def system_self_test(self, child):
		self.authorize(child)
		child.command('system-restore-self-test', [sys.executable, 'tests/release/system_state.py', '--self-test',
			'--workdir', str(child.output / 'self-test-state')], 600, terminal=True)

	def host_system(self, child):
		child.args.bin = self.require_candidate()
		if self.api.HOST_TLD != 'testdcheck':
			raise Blocked('unset TESTD_HOST_TLD; all system host checks use the throwaway .testdcheck zone')
		self.authorize(child)
		child.args.system = True
		child.args.service = False
		self.api.host(child)

	def service_available(self):
		if self.api.SYSTEM == 'Windows':
			raise NotApplicable('no Windows CLI service is shipped; test launch at login in the desktop checklist')
		self.require_candidate()

	def service(self, child):
		child.args.bin = self.require_candidate()
		self.api.service(child)

	def desktop_available(self):
		self.require_candidate()
		if not self.args.app:
			raise Blocked('provide --app with the actual candidate')

	def desktop(self, child):
		self.authorize(child)
		child.args.app = self.args.app.expanduser().resolve()
		self.api.desktop(child)

	def browser(self, child):
		child.args.bin = self.require_candidate()
		child.args.require_managed_host = True
		self.api.check_ports([child.args.intake_port])
		self.api.browser(child)

	def manual(self, path):
		def action(child):
			items = self.api.checklist_items((ROOT / path).read_text(encoding='utf-8'))
			if not items:
				raise RuntimeError(f'no checklist items in {path}')
			print(f'Record evidence for {path}; do not include credentials or private keys.', flush=True)
			for item in items:
				print(f'\n{item}', flush=True)
				answer = input('[p]ass / [f]ail / [b]locked / [n]ot applicable / [q]uit: ').strip().lower()
				while answer not in ('p', 'f', 'b', 'n', 'q'):
					answer = input('Enter p, f, b, n, or q: ').strip().lower()
				if answer == 'q':
					child.metadata['incomplete'] = True
					child.record('manual-checklist', 'skip', 'blocked: unanswered items')
					return
				evidence = input('Evidence or reason (required): ').strip()
				while not evidence:
					evidence = input('Evidence or reason is required: ').strip()
				status = {'p': 'pass', 'f': 'fail', 'b': 'skip', 'n': 'skip'}[answer]
				prefix = {'b': 'blocked: ', 'n': 'not applicable: '}.get(answer, '')
				child.record(item, status, prefix + evidence)
		return action

	def probe_available(self):
		if self.api.SYSTEM == 'Linux':
			raise NotApplicable('the additional resolver probes are macOS- and Windows-specific')
		if self.api.SYSTEM == 'Windows':
			raise Blocked('the local NRPT probe is not tracked and can remove unrelated matching rules; '
				'review its cleanup before running it')
		self.require_candidate()

	def platform_probe(self, child):
		cli = self.require_candidate()
		self.require('bash')
		self.authorize(child)
		backup = self.api.system_snapshot(child, self.api.DESKTOP_TLD, interactive=True)
		try:
			output = child.command('macos-resolver-probe', ['bash', 'tests/release/macos-resolver-probe.sh',
				'--bin', str(cli), '--backup-root', str(child.output / 'probe-backups')], 900, terminal=True)
			for label in ('configure file', 'configure doctor exit', 'unconfigure file', 'restored'):
				match = re.search(rf'(?m)^{re.escape(label)}:\s+(\w+)', output)
				if not match or match.group(1) != 'pass':
					child.record('probe-result', 'fail', f'{label} did not pass; inspect the probe log')
			for label in ('configure resolution', 'unconfigure resolution'):
				match = re.search(rf'(?m)^{re.escape(label)}:\s+(\w+)', output)
				if not match or match.group(1) != 'pass':
					child.record('probe-coverage', 'skip', f'blocked: {label} was not verified')
		finally:
			self.api.system_restore(child, backup, self.api.DESKTOP_TLD, interactive=True)

	def confirm(self, message):
		print(message, flush=True)
		try:
			return input('Type yes to continue; anything else marks this stage blocked: ').strip().lower() == 'yes'
		except EOFError:
			return False

	def check_stage(self, stage):
		if self.interrupted:
			raise Blocked('run interrupted by the operator')
		if stage.precondition:
			stage.precondition()
		if stage.system:
			if not self.args.system or not self.system_confirmed:
				raise Blocked('requires --system and confirmation of a disposable host and persisted full-system snapshot')
			if self.system_unsafe:
				raise Blocked('an earlier system stage failed or was incomplete; inspect recovery before continuing')
		if stage.interactive and not self.args.interactive:
			raise Blocked('requires --interactive and actual operator observations')
		if stage.checkpoint and not self.confirm(stage.checkpoint):
			raise Blocked('operator did not confirm this stage')

	def child_run(self, index, stage):
		args = copy.copy(self.args)
		args.suite = stage.name
		args.report = self.run.output / f'{index:02d}-{stage.name}'
		return self.api.Run(args)

	def classify(self, child):
		if any(item['status'] == 'fail' for item in child.results):
			return 'fail', 'one or more checks failed'
		if child.metadata.get('incomplete') or any(item['status'] == 'skip' and
			not item.get('detail', '').startswith('not applicable:') for item in child.results):
			return 'blocked', 'one or more checks were skipped or incomplete'
		return 'pass', ''

	def boundary(self, text):
		print(text, flush=True)
		self.boundary_log.write(text + '\n')
		self.boundary_log.flush()

	def cleanup_verified(self, stage, child):
		passed = {item['name'] for item in child.results if item['status'] == 'pass'}
		if stage.name == 'host-system':
			return 'host-checks' in passed and 'system-restore' in passed
		if stage.name in ('desktop', 'platform-resolver-probe'):
			return 'system-restore' in passed
		if stage.name == 'browser':
			fixtures = [item for item in child.results if item['name'].startswith('host-fixture')]
			return bool(fixtures) and all(item['status'] == 'pass' for item in fixtures) and 'browser-fixture' in passed
		return False

	def stage(self, index, total, stage):
		self.boundary(f'\n========== BEGIN [{index:02d}/{total:02d}] {stage.name} ==========')
		started = time.monotonic()
		child = None
		status, detail = 'pass', ''
		try:
			self.check_stage(stage)
			child = self.child_run(index, stage)
			stage.action(child)
			status, detail = self.classify(child)
		except NotApplicable as error:
			status, detail = 'not-applicable', str(error)
		except Blocked as error:
			status, detail = 'blocked', str(error)
		except (KeyboardInterrupt, EOFError):
			self.interrupted = True
			status, detail = 'blocked', 'interrupted by the operator or input closed'
		except Exception as error:
			status, detail = 'fail', str(error)
		if child is not None:
			try:
				child.save()
			except Exception as error:
				status, detail = 'fail', f'could not save stage report: {error}'
			detail = '; '.join(filter(None, [detail, f'report: {child.output / "report.json"}']))
		if stage.system and stage.stop_on_failure and child is not None and status in ('fail', 'blocked'):
			if not self.cleanup_verified(stage, child):
				self.system_unsafe = True
		elapsed = time.monotonic() - started
		self.outcomes.append({'name': stage.name, 'status': status, 'detail': detail, 'seconds': round(elapsed, 2)})
		self.run.metadata['stages'] = self.outcomes
		if status == 'blocked':
			self.run.metadata['incomplete'] = True
		result = 'fail' if status == 'fail' else 'skip' if status in ('blocked', 'not-applicable') else 'pass'
		try:
			self.run.record(stage.name, result, detail)
		finally:
			self.boundary(f'========== END [{index:02d}/{total:02d}] {stage.name}: {status.upper()} ==========')

	def summary(self):
		self.boundary('\n========== ALL TESTS: SUMMARY ==========')
		for outcome in self.outcomes:
			self.boundary(f'{outcome["status"].upper():14} {outcome["name"]}: {outcome["detail"]}')
		self.boundary(f'Report: {self.run.output / "report.json"}')

	def execute(self):
		with (self.run.output / 'boundaries.log').open('x', encoding='utf-8') as self.boundary_log:
			if self.args.system:
				try:
					self.system_confirmed = self.confirm('Confirm a disposable host with a persisted full-system snapshot. '
						'Scoped runner snapshots do not replace the full backup.')
				except KeyboardInterrupt:
					self.interrupted = True
			stages = self.stages()
			for index, stage in enumerate(stages, 1):
				self.stage(index, len(stages), stage)
			self.summary()
