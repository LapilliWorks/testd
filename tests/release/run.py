#!/usr/bin/env python3
"""Free-release validation: core, host, service, artifacts, browser, or desktop."""

import argparse
import codecs
import datetime
import hashlib
import json
import locale
import os
import pathlib
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
import tomllib
import uuid
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SYSTEM = platform.system()


def require(tool):
	path = shutil.which(tool)
	if not path:
		raise RuntimeError(f'please install {tool} before running this suite')
	return path


def file_digest(path):
	with path.open('rb') as source:
		return hashlib.file_digest(source, 'sha256').hexdigest()


def safe_members(names):
	for name in names:
		path = pathlib.PurePosixPath(name.replace('\\', '/'))
		if path.is_absolute() or '..' in path.parts or ':' in name:
			raise ValueError(f'unsafe archive path: {name}')


class CommandOutput:
	"""Drain both child streams live, preserving their terminal destinations."""

	def __init__(self, process, log):
		self.process = process
		self.log = log
		self.data = bytearray()
		self.errors = []
		self.lock = threading.Lock()
		self.encoding = locale.getpreferredencoding(False)
		self.threads = []
		for pipe, terminal in [(process.stdout, sys.stdout), (process.stderr, sys.stderr)]:
			thread = threading.Thread(target=self.copy, args=(pipe, terminal), daemon=True)
			thread.start()
			self.threads.append(thread)

	def copy(self, pipe, terminal):
		binary_terminal = getattr(terminal, 'buffer', None)
		decoder = codecs.getincrementaldecoder(self.encoding)(errors='replace')
		try:
			while chunk := pipe.read1(64 * 1024):
				with self.lock:
					self.data.extend(chunk)
					self.log.write(chunk)
					self.log.flush()
				if binary_terminal is not None:
					binary_terminal.write(chunk)
					binary_terminal.flush()
				else:
					terminal.write(decoder.decode(chunk))
					terminal.flush()
			if binary_terminal is None:
				terminal.write(decoder.decode(b'', final=True))
				terminal.flush()
		except Exception as error:
			with self.lock:
				self.errors.append(error)
		finally:
			pipe.close()

	def wait(self, timeout):
		deadline = time.monotonic() + timeout
		self.process.wait(timeout=timeout)
		for thread in self.threads:
			thread.join(timeout=max(0, deadline - time.monotonic()))
			if thread.is_alive():
				raise subprocess.TimeoutExpired(self.process.args, timeout)
		if self.errors:
			raise RuntimeError('failed to mirror command output to the terminal or log') from self.errors[0]
		return self.data.decode(self.encoding, errors='replace')


def stop_command(process, signal_number):
	if SYSTEM == 'Windows':
		if process.poll() is None:
			subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], check=True, capture_output=True)
	else:
		try:
			os.killpg(process.pid, signal_number)
		except ProcessLookupError:
			# The group can exit between the timeout and cleanup.
			return


class Run:
	def __init__(self, args):
		self.args = args
		base = pathlib.Path(os.environ.get('LOCALAPPDATA', pathlib.Path.home() / '.local/share'))
		stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
		self.output = (args.report or base / 'testd/release-checks' / f'{stamp}-{uuid.uuid4().hex[:8]}').resolve()
		self.output.mkdir(parents=True, exist_ok=False, mode=0o700)
		self.results = []
		self.metadata = {'os': platform.platform(), 'python': sys.version, 'suite': args.suite}
		git = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True)
		self.metadata['commit'] = git.stdout.strip()
		status = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True, text=True, check=True)
		self.metadata['dirty'] = bool(status.stdout.strip())
		self.save()
		print(f'Report: {self.output}', flush=True)

	def save(self):
		(self.output / 'report.json').write_text(json.dumps({**self.metadata, 'checks': self.results}, indent=2) + '\n')

	def record(self, name, status, detail=''):
		self.results.append({'name': name, 'status': status, 'detail': detail})
		self.save()
		print(f'{status:8} {name}: {detail}', flush=True)

	def command(self, name, command, timeout=300, env=None, expected=0, interrupt_ok=False):
		log = self.output / f'{len(self.results):02d}-{re.sub(r"[^a-zA-Z0-9-]", "-", name)}.log'
		print(f'Running: {" ".join(map(str, command))}', flush=True)
		with log.open('xb') as log_file:
			process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
				stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=SYSTEM != 'Windows')
			output = CommandOutput(process, log_file)
			try:
				text = output.wait(timeout)
			except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
				stop_command(process, signal.SIGTERM)
				try:
					text = output.wait(10)
				except subprocess.TimeoutExpired:
					stop_command(process, signal.SIGKILL if SYSTEM != 'Windows' else signal.SIGTERM)
					text = output.wait(10)
				if interrupt_ok and isinstance(error, KeyboardInterrupt):
					self.record(name, 'pass', f'fixture stopped by operator; {log}')
					return text
				self.record(name, 'fail', f'timed out or interrupted; {log}')
				raise
		status = 'pass' if process.returncode == expected else 'fail'
		self.record(name, status, f'exit {process.returncode}; {log}')
		if status == 'fail':
			raise RuntimeError(f'{name} failed; inspect {log}')
		return text


def core(run):
	require('cargo')
	run.command('format', ['cargo', 'fmt', '--check'])
	packages = ['--workspace'] + ([] if run.args.gui else ['--exclude', 'testd-gui'])
	run.command('clippy', ['cargo', 'clippy', *packages, '--all-targets', '--locked', '--', '-D', 'warnings'], 1200)
	if shutil.which('cargo-nextest'):
		command = ['cargo', 'nextest', 'run', *packages, '--locked']
	else:
		command = ['cargo', 'test', *packages, '--locked']
	run.command('rust-tests', command, 1200)
	run.command('release-script-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/release'])
	if shutil.which('bun'):
		run.command('browser-fixture-tests', ['bun', 'test', 'tests/release/browser.test.ts'])
	elif run.args.strict:
		raise RuntimeError('please install Bun to test the browser fixtures')
	else:
		run.record('browser-fixture-tests', 'skip', 'Bun is not installed')
	for tool, name, command in [
		('cargo-deny', 'dependencies', ['cargo', 'deny', 'check']),
		('rustup', 'msrv-cli', ['cargo', '+1.88.0', 'check', '--workspace', '--exclude', 'testd-gui', '--locked']),
	]:
		if shutil.which(tool):
			run.command(name, command, 1200)
		elif run.args.strict:
			raise RuntimeError(f'please install {tool} to complete {name}')
		else:
			run.record(name, 'skip', f'{tool} is not installed')
	if run.args.gui:
		run.command('msrv-tray', ['cargo', '+1.90.0', 'check', '-p', 'testd-gui', '--locked'], 1200)


def binary(run):
	if run.args.bin:
		path = run.args.bin.resolve()
	else:
		run.command('build-cli', ['cargo', 'build', '--release', '--bin', 'testd', '--locked'], 1200)
		base = pathlib.Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
		if not base.is_absolute():
			base = ROOT / base
		path = (base / 'release' / ('testd.exe' if SYSTEM == 'Windows' else 'testd')).resolve()
	run.metadata.setdefault('binaries', {})[str(path)] = file_digest(path)
	run.save()
	return path


def system_snapshot(run):
	"""Save inventories before changes; refuse to overwrite any existing testd integration."""
	backup = run.output / 'system-before'
	backup.mkdir(mode=0o700)
	if SYSTEM == 'Windows':
		script = ROOT / 'tests/release/snapshot-windows.ps1'
		command = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(script),
			'-Destination', str(backup)]
		if run.args.system:
			command.append('-RequireAdministrator')
		run.command('system-snapshot', command)
		return
	require('sudo')
	run.command('sudo-ready', ['sudo', '-n', 'true'])
	paths = ['/usr/local/share/ca-certificates/testd-root.crt', '/etc/systemd/resolved.conf.d/90-testd.conf']
	if SYSTEM == 'Darwin':
		paths = ['/etc/resolver/testdcheck']
		text = run.command('root-inventory', ['security', 'find-certificate', '-a', '-p',
			'/Library/Keychains/System.keychain'])
		(backup / 'roots.pem').write_text(text)
		query = subprocess.run(['security', 'find-certificate', '-c', 'testd root', '-p',
			'/Library/Keychains/System.keychain'], capture_output=True, text=True)
		if query.returncode == 0:
			raise RuntimeError('an existing testd root would be replaced; use a clean disposable VM')
	for name in paths:
		path = pathlib.Path(name)
		if path.exists():
			shutil.copy2(path, backup / path.name)
			raise RuntimeError(f'{path} already exists; backed up, but refusing replacement: use a clean VM')
	(backup / 'absent.json').write_text(json.dumps(paths))
	run.record('system-snapshot', 'pass', str(backup))


def host(run):
	cli = binary(run)
	if run.args.system:
		system_snapshot(run)
	ports = [7737, 7740, int(os.environ.get('TESTD_HOST_EDGE_PORT', '8443')),
		int(os.environ.get('TESTD_HOST_APP_PORT', '18080')), int(os.environ.get('TESTD_HOST_LAUNCH_PORT', '18081'))]
	check_ports(ports, [53 if SYSTEM == 'Windows' else 7753])
	state = run.output / 'host-state'
	state.mkdir(mode=0o700)
	env = dict(os.environ, TESTD_HOST_OUTPUT_DIR=str(state),
		TESTD_HOST_SNAPSHOT=str(run.output / 'system-before'), TESTD_BIN=str(cli),
		TESTD_HOST_TEST_SYSTEM='1' if run.args.system else '0',
		TESTD_HOST_TEST_CLEANUP='1', TESTD_HOST_TLD='testdcheck')
	if SYSTEM == 'Windows':
		command = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tests/host/windows.ps1']
	else:
		require('python3')
		command = ['bash', f'tests/host/{"macos" if SYSTEM == "Darwin" else "linux"}.sh']
	text = run.command('host-checks', command, 600, env)
	if 'skip' in text:
		run.record('host-coverage', 'skip', 'see host log for unchecked system/autostart sections')
	if run.args.system:
		if 'ok    doctor --fix' not in text:
			raise RuntimeError('requested system checks did not run successfully')
		run.record('system-checks', 'pass', 'resolver and trust checks ran; inspect cleanup output in host log')
	if run.args.service:
		run.args.bin = cli
		service(run)


def check_ports(tcp, udp=()):
	for kind, ports in [(socket.SOCK_STREAM, tcp), (socket.SOCK_DGRAM, udp)]:
		for port in ports:
			with socket.socket(socket.AF_INET, kind) as probe:
				try:
					probe.bind(('127.0.0.1', port))
				except OSError as error:
					raise RuntimeError(f'fixture port {port} is unavailable; stop the existing service first') from error


def extract_archive(path, destination):
	destination.mkdir(parents=True, mode=0o700)
	if path.suffix == '.zip':
		with zipfile.ZipFile(path) as archive:
			safe_members(archive.namelist())
			if sum(item.file_size for item in archive.infolist()) > 512 * 1024 * 1024:
				raise ValueError('archive is too large')
			archive.extractall(destination)
	else:
		with tarfile.open(path) as archive:
			members = archive.getmembers()
			safe_members(item.name for item in members)
			if any(not (item.isfile() or item.isdir()) for item in members):
				raise ValueError('CLI archives must contain only regular files and directories')
			if sum(item.size for item in members) > 512 * 1024 * 1024:
				raise ValueError('archive is too large')
			archive.extractall(destination, filter='data')


def verify_checksums(directory):
	listed = set()
	for line in (directory / 'SHA256SUMS').read_text().splitlines():
		expected, name = line.split('  ', 1)
		safe_members([name])
		path = directory / name
		if name in listed or not path.resolve().is_relative_to(directory.resolve()):
			raise ValueError(f'unsafe or duplicate checksum entry: {name}')
		listed.add(name)
		if not re.fullmatch('[a-f0-9]{64}', expected):
			raise ValueError(f'invalid digest: {name}')
		if path.exists() and file_digest(path) != expected:
			raise ValueError(f'checksum mismatch: {name}')
	actual = {file.relative_to(directory).as_posix() for file in directory.rglob('*')
		if file.is_file() and file.name != 'SHA256SUMS'}
	if not actual.issubset(listed):
		raise ValueError(f'unlisted downloads: {actual - listed}')


def artifacts(run):
	directory = run.args.artifacts.resolve()
	if (directory / 'SHA256SUMS').exists():
		verify_checksums(directory)
		run.record('checksums', 'pass', 'all downloaded files verified; other platform assets may be absent')
	elif run.args.require_checksums:
		raise RuntimeError('SHA256SUMS is required for downloaded releases')
	else:
		run.record('checksums', 'skip', 'local bundle smoke test; release checksums have not been generated yet')
	target = {'Windows': 'x86_64-pc-windows-msvc', 'Linux': 'x86_64-unknown-linux-gnu',
		'Darwin': 'aarch64-apple-darwin' if platform.machine() == 'arm64' else 'x86_64-apple-darwin'}[SYSTEM]
	archives = sorted(directory.glob(f'testd-*-{target}.*'))
	if not archives:
		raise RuntimeError(f'no CLI archive for {target} in {directory}')
	for index, archive in enumerate(archives):
		extracted = run.output / f'archive-{index}'
		extract_archive(archive, extracted)
		cli = next(extracted.rglob('testd.exe' if SYSTEM == 'Windows' else 'testd'))
		if not cli.is_file():
			raise RuntimeError('no regular CLI binary in archive')
		version = archive.name.removeprefix('testd-').split(f'-{target}', 1)[0]
		fresh_install(run, cli, index, version)
		run.args.bin = cli
		if run.args.host:
			host(run)
		elif run.args.service:
			service(run)
	for image in sorted(directory.glob('*.AppImage')):
		run.command('appimage-runtime', [str(image), '--appimage-version'])
	for image in sorted(directory.glob('*.dmg')):
		if SYSTEM == 'Darwin':
			run.command('dmg-metadata', ['hdiutil', 'imageinfo', str(image)])
	for package in sorted(directory.glob('*.deb')):
		run.command('deb-metadata', [require('dpkg-deb'), '-I', str(package)])
		run.command('deb-contents', ['dpkg-deb', '-c', str(package)])


def fresh_install(run, cli, index, expected_version):
	home = run.output / f'fresh-home-{index}'
	home.mkdir(mode=0o700)
	env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / 'AppData/Roaming'))
	for key in list(env):
		if key.startswith('TESTD_'):
			del env[key]
	run.metadata.setdefault('binaries', {})[str(cli)] = file_digest(cli)
	version = run.command('archive-version', [str(cli), '--version'], env=env).strip()
	if version != f'testd {expected_version}':
		raise RuntimeError(f'invalid version output: {version}')
	self_config = home / ('AppData/Roaming/testd' if SYSTEM == 'Windows' else '.config/testd')
	initial = run.args.previous_bin.resolve() if run.args.previous_bin else cli
	run.command('upgrade-base-init' if run.args.previous_bin else 'fresh-init',
		[str(initial), 'init', '--caddyfile', '', '--tld', 'localhost'], env=env)
	root_before = file_digest(self_config / 'pki/root.crt')
	before = tomllib.loads((self_config / 'config.toml').read_text())
	run.command('re-init', [str(cli), 'init', '--caddyfile', '', '--tld', 'localhost'], env=env)
	after = tomllib.loads((self_config / 'config.toml').read_text())
	assert_preserved_config(before, after)
	if file_digest(self_config / 'pki/root.crt') != root_before:
		raise RuntimeError('re-init or upgrade changed root trust')
	with tarfile.open(run.output / f'fresh-state-before-purge-{index}.tar.gz', 'w:gz') as backup:
		backup.add(self_config, arcname='testd')
	run.command('uninstall-local-state',
		[str(cli), 'uninstall', '--purge', '--keep-resolver', '--keep-certificate'], env=env)
	if self_config.exists():
		raise RuntimeError('purge left the local config directory')
	run.record('fresh-install-and-uninstall', 'pass', version)


def assert_preserved_config(before, after, section=''):
	for key, value in before.items():
		path = f'{section}.{key}' if section else key
		if isinstance(value, dict) and isinstance(after.get(key), dict):
			assert_preserved_config(value, after[key], path)
		elif key not in after or after[key] != value:
			raise RuntimeError(f'configuration value changed during upgrade: {path}')


def service(run):
	import service as service_checks
	service_checks.run_service(run, binary(run), SYSTEM)


def browser(run):
	require('bun')
	check_ports([run.args.port, run.args.port + 1])
	cli = binary(run)
	url = f'https://app.releasecheck.{run.args.tld}:{run.args.edge_port}/'
	print(f'Open {url} in each browser. Do not bypass certificate warnings.\n'
		'Run the checks and save the JSON report using the page. Ctrl+C stops only the fixtures.', flush=True)
	env = dict(os.environ, TESTD_BROWSER_REPORT=str(run.output), TESTD_BROWSER_PORT=str(run.args.port),
		TESTD_BROWSER_TLD=run.args.tld, TESTD_BROWSER_EDGE_PORT=str(run.args.edge_port))
	command = [str(cli), 'run', '--host', f'127.0.0.1:{run.args.intake_port}',
		f'app.releasecheck:{run.args.port}', f'api.releasecheck:{run.args.port}',
		f'dead.releasecheck:{run.args.port + 1}', '--', 'bun', 'tests/release/browser-server.ts']
	try:
		run.command('browser-fixture', command, 3600, env, interrupt_ok=True)
	except KeyboardInterrupt:
		pass
	reports = list(run.output.glob('browser-*.json'))
	if not reports:
		run.metadata['incomplete'] = True
		run.record('browser-results', 'skip', 'no browser report was saved')
	for report in reports:
		result = json.loads(report.read_text())
		has_passed = result.get('manualConfirmed') and all(item['status'] == 'pass' for item in result['checks'])
		status = 'pass' if has_passed else 'fail'
		run.record('browser-results', status, str(report))


def desktop(run):
	if not run.args.app:
		raise RuntimeError('provide --app with the candidate .app, .AppImage, or NSIS installer')
	system_snapshot(run)
	print('Use a clean disposable VM/user session. This suite requires actual desktop interaction.', flush=True)
	app = run.args.app.resolve()
	command = ['open', str(app)] if SYSTEM == 'Darwin' else [str(app)]
	subprocess.Popen(command)
	items = checklist_items((ROOT / 'tests/host/gui-checklist.md').read_text())
	for item in items:
		print(f'\n{item}')
		answer = input('[p]ass / [f]ail / [n]ot applicable / [q]uit: ').strip().lower()
		while answer not in ['p', 'f', 'n', 'q']:
			answer = input('Enter p, f, n, or q: ').strip().lower()
		if answer == 'q':
			run.metadata['incomplete'] = True
			run.record('desktop-checklist', 'skip', 'interrupted; unanswered checks are not passed')
			return
		detail = input('Evidence or reason (required for fail/not applicable): ').strip()
		if answer in ['f', 'n'] and not detail:
			raise RuntimeError('a reason is required')
		run.record(item, {'p': 'pass', 'f': 'fail', 'n': 'skip'}[answer], detail)


def checklist_items(text):
	items = []
	for line in text.splitlines():
		if line.startswith('- [ ] '):
			items.append(line[6:])
		elif items and line.startswith('      '):
			items[-1] += ' ' + line.strip()
	return items


def main():
	if sys.version_info < (3, 12):
		raise SystemExit('Please install Python 3.12 or newer for release validation')
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('suite', choices=['core', 'host', 'artifacts', 'browser', 'desktop', 'service'])
	parser.add_argument('--report', type=pathlib.Path, help='new persisted report directory')
	parser.add_argument('--bin', type=pathlib.Path, help='candidate CLI; otherwise build from source')
	parser.add_argument('--gui', action='store_true', help='include Tauri in core checks')
	parser.add_argument('--strict', action='store_true', help='fail rather than skip missing dependency/MSRV tools')
	parser.add_argument('--system', action='store_true', help='test and clean up resolver/trust changes on a clean VM')
	parser.add_argument('--artifacts', type=pathlib.Path)
	parser.add_argument('--require-checksums', action='store_true')
	parser.add_argument('--host', action='store_true', help='run host suite against the extracted CLI')
	parser.add_argument('--service', action='store_true', help='also test launchd/systemd supervision')
	parser.add_argument('--app', type=pathlib.Path)
	parser.add_argument('--previous-bin', type=pathlib.Path, help='previous CLI for artifact upgrade checks')
	parser.add_argument('--tld', choices=['test', 'localhost'], default='test')
	parser.add_argument('--port', type=int, default=19080)
	parser.add_argument('--edge-port', type=int, default=443)
	parser.add_argument('--intake-port', type=int, default=7737)
	args = parser.parse_args()
	if args.suite == 'artifacts' and not args.artifacts:
		parser.error('artifacts requires --artifacts')
	run = Run(args)
	try:
		globals()[args.suite](run)
	except Exception as error:
		run.record(args.suite, 'fail', str(error))
		return 1
	finally:
		run.save()
	if any(check['status'] == 'fail' for check in run.results):
		return 1
	return 2 if run.metadata.get('incomplete') else 0


if __name__ == '__main__':
	sys.exit(main())
