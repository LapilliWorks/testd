#!/usr/bin/env python3
"""Free-release validation: core, host, service, artifacts, browser, or desktop."""

import argparse
import codecs
import contextlib
import ctypes
import datetime
import functools
import hashlib
import http.client
import importlib.util
import json
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
# Every tool the suites drive writes UTF-8, and the host scripts switch PowerShell
# to it. The locale encoding is the ANSI code page on non-English Windows, so
# decoding with it corrupts cargo trees and any non-ASCII path or message.
ENCODING = 'utf-8'
# Throwaway TLD for the host suite, so it never collides with a real .test setup.
HOST_TLD = os.environ.get('TESTD_HOST_TLD', 'testdcheck')
# The desktop setup wizard always configures the product TLD.
DESKTOP_TLD = 'test'


def require(tool):
	path = shutil.which(tool)
	if not path:
		raise RuntimeError(f'please install {tool} before running this suite')
	return path


def console_code_page():
	"""The console output code page, or zero when no console is attached."""
	kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
	return kernel32.GetConsoleOutputCP()


def console_encoding():
	"""The encoding the shell capturing our redirected output will decode with.

	PowerShell 7 decodes a child's output with [Console]::OutputEncoding, which
	follows the console code page (cp936 on a Chinese system), but this runner
	writes redirected streams as UTF-8. A captured run would then show the
	report and every localized error as mojibake even though the bytes are
	right. Writing the console code page instead keeps the mirror readable; a
	UTF-8 console (65001) needs nothing, and the console itself is written
	through the Windows console API whatever we choose here.
	"""
	if SYSTEM != 'Windows':
		return None
	code_page = console_code_page()
	if not code_page or code_page == 65001:
		return None
	return f'cp{code_page}'


def match_redirected_encoding():
	"""Print redirected streams in the code page the console expects."""
	encoding = console_encoding()
	if not encoding:
		return
	for stream in (sys.stdout, sys.stderr):
		try:
			if stream is not None and not stream.isatty():
				stream.reconfigure(encoding=encoding, errors='replace')
		except (AttributeError, ValueError):
			continue


@functools.cache
def helper(name):
	"""Load a sibling module from tests/release, which is not an installed package."""
	spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(f'{name}.py'))
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


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
		self.threads = []
		for pipe, terminal in [(process.stdout, sys.stdout), (process.stderr, sys.stderr)]:
			thread = threading.Thread(target=self.copy, args=(pipe, terminal), daemon=True)
			thread.start()
			self.threads.append(thread)

	def copy(self, pipe, terminal):
		decoder = codecs.getincrementaldecoder(ENCODING)(errors='replace')
		try:
			while chunk := pipe.read1(64 * 1024):
				with self.lock:
					self.data.extend(chunk)
					self.log.write(chunk)
					self.log.flush()
				terminal.write(decoder.decode(chunk))
				terminal.flush()
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
		return self.text()

	def text(self):
		with self.lock:
			return self.data.decode(ENCODING, errors='replace')


def stop_command(process, signal_number):
	if SYSTEM == 'Windows':
		if process.poll() is None:
			subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], check=True, capture_output=True)
		return
	try:
		# A child started in its own session leads its process group; one that kept
		# the operator's terminal does not, and must not signal the runner's group.
		if os.getpgid(process.pid) == process.pid:
			os.killpg(process.pid, signal_number)
		else:
			process.send_signal(signal_number)
	except ProcessLookupError:
		# The child can exit between the timeout and cleanup.
		return


class Run:
	def __init__(self, args):
		self.args = args
		base = pathlib.Path(os.environ.get('LOCALAPPDATA', pathlib.Path.home() / '.local/share'))
		stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
		self.output = (args.report or base / 'testd/release-checks' / f'{stamp}-{uuid.uuid4().hex[:8]}').resolve()
		self.output.mkdir(parents=True, exist_ok=False, mode=0o700)
		self.results = []
		self.log_count = 0
		self.lock = threading.RLock()
		self.metadata = {'os': platform.platform(), 'python': sys.version, 'suite': args.suite}
		git = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True,
			encoding=ENCODING, errors='replace', check=True)
		self.metadata['commit'] = git.stdout.strip()
		status = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT, capture_output=True,
			encoding=ENCODING, errors='replace', check=True)
		self.metadata['dirty'] = bool(status.stdout.strip())
		self.save()
		print(f'Report: {self.output}', flush=True)

	def save(self):
		with self.lock:
			(self.output / 'report.json').write_text(
				json.dumps({**self.metadata, 'checks': self.results}, indent=2) + '\n', encoding=ENCODING)

	def record(self, name, status, detail=''):
		with self.lock:
			self.results.append({'name': name, 'status': status, 'detail': detail})
			self.save()
			print(f'{status:8} {name}: {detail}', flush=True)

	def log_path(self, name):
		with self.lock:
			path = self.output / f'{self.log_count:02d}-{re.sub(r"[^a-zA-Z0-9-]", "-", name)}.log'
			self.log_count += 1
			return path

	def command(self, name, command, timeout=300, env=None, expected=0, interrupt_ok=False, terminal=False):
		"""Run a command and mirror its output.

		`terminal` keeps the operator's terminal attached, stdin and session
		alike. sudo keys its cached credential to that terminal, so a detached
		check asks for a password even right after `sudo -v` succeeded in the
		same shell. The child still leads its own process group, so a timeout can
		stop the processes it started.
		"""
		log = self.log_path(name)
		print(f'Running: {" ".join(map(str, command))}', flush=True)
		# Nested Python tools would otherwise write the ANSI code page on Windows.
		env = {**(os.environ if env is None else env), 'PYTHONUTF8': '1'}
		with log.open('xb') as log_file:
			process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
				stderr=subprocess.PIPE, stdin=None if terminal else subprocess.DEVNULL,
				start_new_session=SYSTEM != 'Windows' and not terminal,
				**({'process_group': 0} if terminal and SYSTEM != 'Windows' else {}))
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

	@contextlib.contextmanager
	def serve(self, name, command, env=None, stop_signal=signal.SIGTERM):
		"""Run a long-lived fixture and stop it when the block exits."""
		log = self.log_path(name)
		print(f'Running: {" ".join(map(str, command))}', flush=True)
		env = {**(os.environ if env is None else env), 'PYTHONUTF8': '1'}
		with log.open('xb') as log_file:
			process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
				stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=SYSTEM != 'Windows')
			output = CommandOutput(process, log_file)
			try:
				yield process, output
			finally:
				was_running = process.poll() is None
				if was_running:
					stop_command(process, stop_signal)
				try:
					output.wait(10)
				except subprocess.TimeoutExpired:
					stop_command(process, signal.SIGKILL if SYSTEM != 'Windows' else signal.SIGTERM)
					output.wait(10)
				status = 'pass' if was_running or process.returncode == 0 else 'fail'
				self.record(name, status, f'exit {process.returncode}; {log}')


def automated(run):
	for tool in ('cargo', 'rustup', 'cargo-nextest', 'bun'):
		require(tool)
	print('The default Rust suite skips ignored contracts; run the contracts suite for the release gate.', flush=True)
	run.command('format', ['cargo', '+stable', 'fmt', '--all', '--', '--check'], 300)
	run.command('clippy', ['cargo', '+stable', 'clippy', '--workspace', '--all-targets', '--exclude',
		'testd-gui', '--locked', '--', '-D', 'warnings'], 1200)
	run.command('rust-tests', ['cargo', '+1.89.0', 'nextest', 'run', '--workspace', '--exclude',
		'testd-gui', '--locked'], 1200)
	run.command('release-script-tests', [sys.executable, '-m', 'unittest', 'discover',
		'-s', 'tests/release', '-p', 'test_*.py'], 300)
	fixture = ROOT / 'tests/release/browser.test.ts'
	run.command('browser-fixture-tests', ['bun', 'test', str(fixture)], 300)
	if run.args.gui:
		run.command('msrv-tray', ['cargo', '+1.90.0', 'check', '-p', 'testd-gui', '--locked'], 1200)
		run.command('gui-workspace-tests', ['cargo', '+stable', 'nextest', 'run', '--workspace', '--locked'], 1200)


def contracts(run):
	for tool in ('cargo', 'rustup', 'cargo-nextest'):
		require(tool)
	if run.args.gui:
		raise RuntimeError('the Rust 1.89 contract gate excludes the GUI; run the GUI checks separately')
	run.command('release-contracts', ['cargo', '+1.89.0', 'nextest', 'run', '--workspace', '--exclude',
		'testd-gui', '--locked', '--run-ignored', 'all', '--no-fail-fast'], 1200)


def audit(run):
	for tool in ('cargo', 'rustup', 'cargo-deny'):
		require(tool)
	run.command('workspace-dependencies', ['cargo', '+stable', 'deny', '--workspace', '--locked', 'check'], 1200)


def core(run):
	require('cargo')
	run.command('format', ['cargo', 'fmt', '--check'])
	packages = ['--workspace'] + ([] if run.args.gui else ['--exclude', 'testd-gui'])
	run.command('clippy', ['cargo', 'clippy', *packages, '--all-targets', '--locked', '--', '-D', 'warnings'], 1200)
	if shutil.which('cargo-nextest'):
		command = ['cargo', 'nextest', 'run', *packages, '--locked', '--run-ignored', 'all']
	else:
		command = ['cargo', 'test', *packages, '--locked', '--', '--include-ignored']
	run.command('rust-tests', command, 1200)
	run.command('release-script-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/release'])
	if shutil.which('bun'):
		fixture = ROOT / 'tests/release/browser.test.ts'
		run.command('browser-fixture-tests', ['bun', 'test', str(fixture)])
	elif run.args.strict:
		raise RuntimeError('please install Bun to test the browser fixtures')
	else:
		run.record('browser-fixture-tests', 'skip', 'Bun is not installed')
	for tool, name, command in [
		('cargo-deny', 'dependencies', ['cargo', 'deny', 'check']),
		('rustup', 'msrv-cli', ['cargo', '+1.89.0', 'check', '--workspace', '--exclude', 'testd-gui', '--locked']),
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


def system_snapshot(run, tld, interactive=False):
	"""Snapshot OS integration and refuse pre-existing state before system checks."""
	state = helper('system_state')
	if SYSTEM != 'Windows' and not interactive:
		require('sudo')
		run.command('sudo-ready', ['sudo', '-n', 'true'], terminal=True)
	backup = run.output / 'system-before'
	index = 2
	# Every snapshot stays on disk; a later run must not overwrite the state an
	# earlier, possibly failed, restore would need.
	while backup.exists():
		backup = run.output / f'system-before-{index}'
		index += 1
	backup.mkdir(mode=0o700)
	manifest = state.snapshot(state.Host(SYSTEM, tld, interactive), backup)
	occupied = state.occupied(backup)
	if occupied:
		detail = f'pre-existing integration: {", ".join(occupied)}; snapshot kept at {backup}'
		run.record('system-snapshot', 'fail', detail)
		raise RuntimeError(f'system checks require a clean disposable host; {detail}')
	run.record('system-snapshot', 'pass', str(manifest))
	return backup


def system_restore(run, backup, tld, interactive=False):
	"""Put the recorded integration back and verify it against the snapshot."""
	state = helper('system_state')
	problems = state.restore(state.Host(SYSTEM, tld, interactive), backup)
	if problems:
		run.record('system-restore', 'fail', '; '.join(problems))
		raise RuntimeError('the host was not fully restored; fix the cause and rerun with '
			f'--restore-report {run.output}')
	run.record('system-restore', 'pass', f'{backup}; integration matches the snapshot')


def host(run):
	cli = binary(run)
	ports = [7737, 7740, int(os.environ.get('TESTD_HOST_EDGE_PORT', '8443')),
		int(os.environ.get('TESTD_HOST_APP_PORT', '18080')), int(os.environ.get('TESTD_HOST_LAUNCH_PORT', '18081'))]
	# Refuse a busy fixture port before any system state is touched.
	check_ports(ports, [53 if SYSTEM == 'Windows' else 7753])
	state = run.output / 'host-state'
	state.mkdir(mode=0o700)
	env = dict(os.environ, TESTD_HOST_OUTPUT_DIR=str(state), TESTD_BIN=str(cli),
		TESTD_HOST_TEST_SYSTEM='1' if run.args.system else '0', TESTD_HOST_TLD=HOST_TLD)
	snapshot = system_snapshot(run, HOST_TLD) if run.args.system else None
	if snapshot:
		env['TESTD_HOST_SNAPSHOT'] = str(snapshot)
	if SYSTEM == 'Windows':
		command = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tests/host/windows.ps1']
	else:
		require('python3')
		command = ['bash', f'tests/host/{"macos" if SYSTEM == "Darwin" else "linux"}.sh']
	try:
		# With --system the script runs sudo itself, which needs the terminal the
		# credential was validated on. Plain runs keep fixtures off the operator's
		# stdin.
		text = run.command('host-checks', command, 600, env, terminal=run.args.system)
		if 'skip' in text:
			run.record('host-coverage', 'skip', 'see host log for unchecked system/autostart sections')
		if run.args.system:
			if 'ok    doctor --fix' not in text:
				raise RuntimeError('requested system checks did not run successfully')
			run.record('system-checks', 'pass', 'resolver and trust checks ran')
		if run.args.service:
			run.args.bin = cli
			service(run)
	finally:
		if snapshot:
			system_restore(run, snapshot, HOST_TLD)


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
	for line in (directory / 'SHA256SUMS').read_text(encoding=ENCODING).splitlines():
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
		[str(initial), 'init', '--caddyfile', ''], env=env)
	pki = self_config / 'pki'
	root_before = {name: file_digest(pki / name) for name in ('root.crt', 'root.key')}
	before = tomllib.loads((self_config / 'config.toml').read_text(encoding=ENCODING))
	backup_fresh_state(run, self_config, index, 'upgrade')
	run.command('re-init', [str(cli), 'init', '--caddyfile', ''], env=env)
	after = tomllib.loads((self_config / 'config.toml').read_text(encoding=ENCODING))
	assert_preserved_config(before, after)
	assert_root_unchanged(pki, root_before, 'upgrade')
	if run.args.previous_bin:
		backup_fresh_state(run, self_config, index, 'rollback')
		run.command('rollback-init', [str(initial), 'init', '--caddyfile', ''], env=env)
		rolled_back = tomllib.loads((self_config / 'config.toml').read_text(encoding=ENCODING))
		try:
			assert_preserved_config(after, rolled_back)
		except RuntimeError as error:
			raise RuntimeError(f'rollback changed configuration: {error}') from error
		assert_root_unchanged(pki, root_before, 'rollback')
		run.record('rollback', 'pass', 'configuration and root material preserved')
	backup_fresh_state(run, self_config, index, 'purge')
	run.command('uninstall-local-state',
		[str(cli), 'uninstall', '--purge', '--keep-resolver', '--keep-certificate'], env=env)
	if self_config.exists():
		raise RuntimeError('purge left the local config directory')
	run.record('fresh-install-and-uninstall', 'pass', version)


def backup_fresh_state(run, directory, index, step):
	path = run.output / f'fresh-state-before-{step}-{index}.tar.gz'
	with tarfile.open(path, 'x:gz') as backup:
		backup.add(directory, arcname='testd')


def assert_root_unchanged(pki, expected, phase):
	for name, digest in expected.items():
		path = pki / name
		if not path.is_file() or file_digest(path) != digest:
			raise RuntimeError(f'{phase} changed {name}')


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


class HostUnavailable(RuntimeError):
	"""The intake endpoint did not answer like a running testd host."""


def local_host_status(port):
	"""Read the running host's status."""
	connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
	try:
		connection.request('GET', '/api/status')
		response = connection.getresponse()
		body = response.read()
	except OSError as error:
		raise HostUnavailable(f'no testd host is listening at 127.0.0.1:{port}') from error
	finally:
		connection.close()
	if response.status != 200:
		raise RuntimeError(f'the service at 127.0.0.1:{port} returned {response.status} for /api/status; '
			'is a testd host running there?')
	try:
		return json.loads(body)
	except (UnicodeDecodeError, ValueError) as error:
		raise RuntimeError(f'the host at 127.0.0.1:{port} returned an invalid /api/status document') from error


def wait_for_host(port, process, output, timeout=30):
	"""Wait for a host this suite started to accept connections."""
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		if process.poll() is not None:
			detail = output.text().strip()
			raise RuntimeError(f'the host exited with {process.returncode} before listening on 127.0.0.1:{port}; '
				f'is it initialized with `testd init`?\n{detail[-4000:]}')
		try:
			return local_host_status(port)
		except HostUnavailable:
			time.sleep(0.25)
	raise RuntimeError(f'the host did not listen on 127.0.0.1:{port} within {timeout} seconds')


def require_host_resolution(run, cli):
	"""Fail before a browser opens if the OS resolver does not reach the host TLD."""
	log = run.log_path('host-doctor')
	print(f'Running: {cli} doctor --json', flush=True)
	try:
		result = subprocess.run([str(cli), 'doctor', '--json'], cwd=ROOT,
			env={**os.environ, 'PYTHONUTF8': '1'}, capture_output=True, timeout=60)
	except subprocess.TimeoutExpired as error:
		raise RuntimeError(f'`testd doctor --json` timed out; inspect {log}') from error
	log.write_bytes(result.stdout + result.stderr)
	try:
		checks = {item['name']: item for item in json.loads(result.stdout)['checks']}
	except (KeyError, TypeError, ValueError) as error:
		raise RuntimeError(f'could not read `testd doctor --json`; inspect {log}') from error
	for name in ('resolver', 'resolution'):
		check = checks.get(name)
		if not check or not check.get('ok'):
			detail = check.get('detail', 'missing check') if check else 'missing check'
			fix = (check.get('fix') if check else None) or 'run `testd doctor --fix` on the host'
			raise RuntimeError(f'{name}: {detail}; {fix}')
	run.record('host-resolution', 'pass', 'the OS resolver resolves the host TLD')


class HostFixture:
	"""A host the browser suite owns. An already-running host is left untouched."""

	def __init__(self, run, cli, port):
		self.run = run
		self.cli = cli
		self.port = port
		self.started = False
		self.starts = 0
		self.status = None
		self.process = None
		self.output = None
		self.context = None

	def __enter__(self):
		try:
			self.status = local_host_status(self.port)
		except HostUnavailable:
			self.started = True
			self.start()
		return self

	def start(self):
		name = 'host-fixture' if self.starts == 0 else f'host-fixture-restart-{self.starts}'
		self.starts += 1
		self.context = self.run.serve(name, [str(self.cli), 'host'], stop_signal=signal.SIGINT)
		self.process, self.output = self.context.__enter__()
		try:
			self.status = wait_for_host(self.port, self.process, self.output)
		except BaseException:
			self.stop()
			raise

	def stop(self):
		context = self.context
		if context is None:
			return
		self.context = None
		self.process = self.output = None
		context.__exit__(None, None, None)

	def restart(self):
		if not self.started:
			raise RuntimeError('the suite did not start this host; restart it manually')
		self.stop()
		self.start()

	def __exit__(self, *exc_info):
		self.stop()


def write_restart_result(run, request_id, result):
	path = run.output / f'restart-result-{request_id}.json'
	temporary = path.with_name(f'{path.name}.tmp')
	temporary.write_text(json.dumps(result) + '\n', encoding=ENCODING)
	temporary.replace(path)


def watch_restart_requests(run, host, stop, errors):
	"""Answer restart requests from the browser page while the fixture runs."""
	handled = set()
	try:
		while not stop.wait(0.25):
			for request in sorted(run.output.glob('restart-request-*.json')):
				if request.name in handled:
					continue
				handled.add(request.name)
				request_id = request.name.removeprefix('restart-request-').removesuffix('.json')
				try:
					host.restart()
					result = {'status': 'ok'}
				except Exception as error:
					result = {'status': 'failed', 'detail': str(error)}
				write_restart_result(run, request_id, result)
				request.unlink(missing_ok=True)
	except Exception as error:
		errors.append(error)
		raise


BROWSER_CHECKS = frozenset({
	'HTTPS and secure context',
	'WebSocket, including 60 seconds idle',
	'Streaming SSE and 100 MiB upload',
	'Cookie sharing and project isolation',
})


def browser_report_error(result, commit, edge_port):
	if not isinstance(result, dict) or result.get('manualConfirmed') is not True:
		return 'manual browser observations are incomplete'
	for field in ('browser', 'notes'):
		if not isinstance(result.get(field), str) or not result[field].strip():
			return f'missing browser evidence: {field}'
	fingerprint = result.get('fingerprint')
	if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint.lower()):
		return 'missing or invalid leaf fingerprint'
	origin = 'https://app.releasecheck.test' + (f':{edge_port}' if edge_port != 443 else '')
	if result.get('commit') != commit or result.get('origin') != origin:
		return 'browser report does not match the candidate commit and origin'
	checks = result.get('checks')
	if not isinstance(checks, list) or len(checks) != len(BROWSER_CHECKS):
		return 'browser report is missing checks'
	if any(not isinstance(check, dict) or not isinstance(check.get('name'), str) for check in checks):
		return 'browser report has malformed checks'
	if {check['name'] for check in checks} != BROWSER_CHECKS:
		return 'browser report has duplicate, missing, or unknown checks'
	if any(check.get('status') != 'pass' for check in checks):
		return 'a browser check did not pass'
	return None


def browser(run):
	require('bun')
	check_ports([run.args.port, run.args.port + 1])
	cli = binary(run)
	with HostFixture(run, cli, run.args.intake_port) as host:
		status = host.status
		if status.get('tld') != 'test':
			raise RuntimeError(f'the host at 127.0.0.1:{run.args.intake_port} serves .{status.get("tld")}, '
				'but testd serves .test; run `testd init` and restart the host')
		require_host_resolution(run, cli)
		run.metadata['browser_host_managed'] = host.started
		run.save()
		url = f'https://app.releasecheck.test:{run.args.edge_port}/'
		print(f'Open {url} in each browser. Do not bypass certificate warnings.\n'
			'Run the checks and save the JSON report using the page. Ctrl+C stops only the fixtures.', flush=True)
		env = dict(os.environ, TESTD_BROWSER_REPORT=str(run.output), TESTD_BROWSER_PORT=str(run.args.port),
			TESTD_BROWSER_TLD='test', TESTD_BROWSER_EDGE_PORT=str(run.args.edge_port))
		command = [str(cli), 'run', '--host', f'127.0.0.1:{run.args.intake_port}',
			f'app.releasecheck:{run.args.port}', f'api.releasecheck:{run.args.port}',
			f'app.othercheck:{run.args.port}', f'dead.releasecheck:{run.args.port + 1}',
			'--', 'bun', 'tests/release/browser-server.ts']
		stop = threading.Event()
		errors = []
		watcher = threading.Thread(target=watch_restart_requests, args=(run, host, stop, errors), daemon=True)
		watcher.start()
		try:
			run.command('browser-fixture', command, 3600, env, interrupt_ok=True)
		except KeyboardInterrupt:
			pass
		finally:
			stop.set()
			watcher.join(40)
			if watcher.is_alive():
				raise RuntimeError('the host restart watcher did not stop')
			if errors:
				raise RuntimeError('the host restart watcher failed') from errors[0]
	reports = list(run.output.glob('browser-*.json'))
	if not reports:
		run.metadata['incomplete'] = True
		run.record('browser-results', 'skip', 'no browser report was saved')
	for report in reports:
		result = json.loads(report.read_text(encoding=ENCODING))
		error = browser_report_error(result, run.metadata['commit'], run.args.edge_port)
		status = 'fail' if error else 'pass'
		run.record('browser-results', status, f'{report}; {error}' if error else str(report))


def desktop_config_dir():
	if SYSTEM == 'Windows':
		appdata = os.environ.get('APPDATA')
		if appdata:
			return pathlib.Path(appdata) / 'testd'
		profile = os.environ.get('USERPROFILE')
		if not profile:
			raise RuntimeError('USERPROFILE or APPDATA is required for the desktop suite')
		return pathlib.Path(profile) / 'AppData/Roaming/testd'
	home = os.environ.get('HOME')
	if not home:
		raise RuntimeError('HOME is required for the desktop suite')
	return pathlib.Path(home) / '.config/testd'


def require_fresh_desktop_user():
	config = desktop_config_dir()
	try:
		config.lstat()
	except FileNotFoundError:
		return
	raise RuntimeError(f'existing testd user data at {config}; use a fresh disposable user and retain a backup')


def desktop(run):
	if not run.args.app:
		raise RuntimeError('provide --app with the candidate .app, .AppImage, or NSIS installer')
	if not sys.stdin.isatty():
		raise RuntimeError('the desktop suite needs an interactive terminal; run it directly, '
			'not through a pipe or with stdin redirected')
	app = run.args.app.resolve()
	if not app.exists():
		raise RuntimeError(f'candidate app does not exist: {app}')
	require_fresh_desktop_user()
	items = checklist_items((ROOT / 'tests/host/gui-checklist.md').read_text(encoding=ENCODING))
	if not items:
		raise RuntimeError('no desktop checklist items were found')
	if ask('Confirm this is a disposable host with a persisted full-system backup [y/N]: ') != 'y':
		raise RuntimeError('desktop validation requires a disposable host and persisted full-system backup')
	snapshot = system_snapshot(run, DESKTOP_TLD, interactive=True)
	print('This suite requires a real desktop session and actual interaction. '
		'The scoped integration snapshot is restored after the candidate is stopped.', flush=True)
	command = ['open', str(app)] if SYSTEM == 'Darwin' else [str(app)]
	app_log = run.log_path('desktop-app')
	app_process = None
	try:
		# The app must not inherit the checklist's stdin. Its daemon logs belong
		# in the report, not on top of the next prompt.
		with app_log.open('xb') as sink:
			env = dict(os.environ)
			env.pop('TESTD_HOST_TLD', None)
			app_process = subprocess.Popen(
				command, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT, env=env)
		print(f'Candidate app output: {app_log}', flush=True)
		if SYSTEM == 'Linux':
			time.sleep(1.5)
			if app_process.poll() is not None:
				raise RuntimeError(
					f'the candidate app exited immediately; see {app_log}. '
					'Check display/port privileges before rerunning the checklist')
			watch = threading.Thread(target=note_app_exit, args=(app_process, app_log), daemon=True)
			watch.start()
		for item in items:
			print(f'\n{item}')
			answer = ask('[p]ass / [f]ail / [n]ot applicable / [q]uit: ')
			while answer not in ['p', 'f', 'n', 'q']:
				answer = ask('Enter p, f, n, or q: ')
			if answer == 'q':
				run.metadata['incomplete'] = True
				run.record('desktop-checklist', 'skip', 'interrupted; unanswered checks are not passed')
				return
			detail = ask('Evidence or reason (required for fail/not applicable): ')
			if answer in ['f', 'n'] and not detail:
				raise RuntimeError('a reason is required')
			run.record(item, {'p': 'pass', 'f': 'fail', 'n': 'skip'}[answer], detail)
	finally:
		if app_process is not None and SYSTEM == 'Linux' and app_process.poll() is None:
			app_process.terminate()
			try:
				app_process.wait(timeout=5)
			except subprocess.TimeoutExpired:
				app_process.kill()
				app_process.wait(timeout=5)
		try:
			stopped = ask('Confirm all candidate apps, daemons, and providers are stopped before restore [y/N]: ') == 'y'
		except (KeyboardInterrupt, RuntimeError):
			run.metadata['incomplete'] = True
			run.record('system-restore', 'skip', f'shutdown not confirmed; stop processes and use --restore-report {run.output}')
			raise
		if stopped:
			system_restore(run, snapshot, DESKTOP_TLD, interactive=True)
		else:
			run.metadata['incomplete'] = True
			run.record('system-restore', 'skip', f'shutdown not confirmed; stop processes and use --restore-report {run.output}')


def ask(prompt):
	print(prompt, flush=True)
	answer = sys.stdin.readline()
	if answer == '':
		raise RuntimeError('desktop checklist input closed; run in an interactive terminal')
	return answer.strip().lower()


def note_app_exit(process, log):
	try:
		code = process.wait()
	except Exception:
		return
	print(f'\n[desktop] candidate app exited with {code}; see {log}\n', flush=True)


def checklist_items(text):
	items = []
	for line in text.splitlines():
		if line.startswith('- [ ] '):
			items.append(line[6:])
		elif items and line.startswith('      '):
			items[-1] += ' ' + line.strip()
	return items


def restore_report(directory):
	"""Recover a host after a run that could not restore its own integration."""
	directory = directory.resolve()
	state = helper('system_state')
	snapshots = []
	for path in directory.glob('system-before*'):
		if (path / 'manifest.json').is_file():
			manifest = state.load(path)
			snapshots.append((manifest['created'], path, manifest))
	if not snapshots:
		raise SystemExit(f'no system snapshot in {directory}; system checks are only run by '
			'tests/release/run.py host --system')
	status = 0
	# Newest first: each snapshot describes the state before its own run, so the
	# oldest one restores last and wins.
	for created, path, manifest in sorted(snapshots, key=lambda item: item[0], reverse=True):
		if manifest['system'] != SYSTEM:
			raise SystemExit(f'the snapshot at {path} belongs to {manifest["system"]}; run this on that host')
		print(f'Restoring integration recorded at {created} (tld {manifest["tld"]})', flush=True)
		try:
			problems = state.restore(state.Host(SYSTEM, manifest['tld']), path)
		except state.HostError as error:
			problems = [str(error)]
		for problem in problems:
			print(f'fail     {problem}', flush=True)
		if problems:
			status = 1
	if status:
		print('\nThe host is not fully restored. Fix the cause and rerun this command.', flush=True)
	else:
		print(f'Restored and verified against every snapshot in {directory}', flush=True)
	return status


def interrupt(signum, frame):
	raise KeyboardInterrupt(f'signal {signum}')


def main(argv=None):
	if sys.version_info < (3, 12):
		raise SystemExit('Please install Python 3.12 or newer for release validation')
	# Start from UTF-8 so argparse and non-Windows captures never use the locale
	# encoding; match_redirected_encoding then narrows a Windows capture to the
	# code page its shell decodes with.
	for stream in (sys.stdout, sys.stderr):
		if hasattr(stream, 'reconfigure'):
			stream.reconfigure(encoding=ENCODING)
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('suite', nargs='?', choices=['automated', 'contracts', 'audit', 'core', 'host',
		'artifacts', 'browser', 'desktop', 'service'])
	parser.add_argument('--report', type=pathlib.Path, help='new persisted report directory')
	parser.add_argument('--restore-report', type=pathlib.Path,
		help='restore the system integration recorded in an existing report directory, then exit')
	parser.add_argument('--bin', type=pathlib.Path, help='candidate CLI; otherwise build from source')
	parser.add_argument('--gui', action='store_true', help='include Tauri in automated or core checks')
	parser.add_argument('--strict', action='store_true', help='fail rather than skip missing dependency/MSRV tools')
	parser.add_argument('--system', action='store_true',
		help='test resolver/trust changes; integration is snapshotted and restored')
	parser.add_argument('--artifacts', type=pathlib.Path)
	parser.add_argument('--require-checksums', action='store_true')
	parser.add_argument('--host', action='store_true', help='run host suite against the extracted CLI')
	parser.add_argument('--service', action='store_true', help='also test launchd/systemd supervision')
	parser.add_argument('--app', type=pathlib.Path)
	parser.add_argument('--previous-bin', type=pathlib.Path, help='previous CLI for artifact upgrade checks')
	parser.add_argument('--port', type=int, default=19080)
	parser.add_argument('--edge-port', type=int, default=443)
	parser.add_argument('--intake-port', type=int, default=7737)
	args = parser.parse_args(argv)
	match_redirected_encoding()
	if args.restore_report:
		return restore_report(args.restore_report)
	if not args.suite:
		parser.error('a suite is required unless --restore-report is given')
	if args.suite == 'artifacts' and not args.artifacts:
		parser.error('artifacts requires --artifacts')
	# A supervisor restarting or an operator stopping the run must still restore.
	for number in ('SIGTERM', 'SIGHUP'):
		if hasattr(signal, number):
			signal.signal(getattr(signal, number), interrupt)
	run = Run(args)
	try:
		globals()[args.suite](run)
	except KeyboardInterrupt:
		run.metadata['incomplete'] = True
		run.record(args.suite, 'skip', 'interrupted; check system-restore and use --restore-report if needed')
		return 2
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
