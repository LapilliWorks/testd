"""Exercise real user-session supervision without changing resolver or trust state."""

import contextlib
import hashlib
import http.client
import json
import os
import pathlib
import shutil
import socket
import stat
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]


def fingerprint(metadata):
	return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
		stat.S_IMODE(metadata.st_mode), metadata.st_ctime_ns)


def create_owned_file(path, content):
	directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
	try:
		flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
		descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
		try:
			with os.fdopen(descriptor, 'wb', closefd=False) as output:
				output.write(content)
				output.flush()
			os.fsync(descriptor)
			return fingerprint(os.fstat(descriptor)), hashlib.sha256(content).hexdigest()
		finally:
			os.close(descriptor)
	finally:
		os.close(directory)


@contextlib.contextmanager
def verified_owned_file(path, proof):
	directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
	try:
		descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
		try:
			metadata = os.fstat(descriptor)
			if not stat.S_ISREG(metadata.st_mode) or fingerprint(metadata) != proof[0]:
				raise RuntimeError(f'service unit identity changed: {path}')
			with os.fdopen(descriptor, 'rb', closefd=False) as source:
				digest = hashlib.file_digest(source, 'sha256').hexdigest()
			current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
			if digest != proof[1] or fingerprint(os.fstat(descriptor)) != proof[0] or fingerprint(current) != proof[0]:
				raise RuntimeError(f'service unit was changed or replaced: {path}')
			yield directory
		finally:
			os.close(descriptor)
	finally:
		os.close(directory)


def remove_owned_file(path, proof):
	with verified_owned_file(path, proof) as directory:
		os.unlink(path.name, dir_fd=directory)


def prepare_directories(home):
	if home.is_symlink() or not home.is_dir():
		raise RuntimeError(f'the user home is not an ordinary directory: {home}')
	created = []
	try:
		for path in (home / '.config', home / '.config/systemd', home / '.config/systemd/user'):
			if path.is_symlink():
				raise RuntimeError(f'service directory is a symlink: {path}')
			try:
				path.mkdir(mode=0o700)
			except FileExistsError:
				if not path.is_dir():
					raise
			else:
				created.append((path, fingerprint(path.lstat())[:-1]))
		return created
	except Exception as error:
		problems = prune_directories(created)
		if problems:
			raise RuntimeError(f'{error}; fixture directory cleanup incomplete: {"; ".join(problems)}') from error
		raise


def prune_directories(created):
	problems = []
	for path, proof in reversed(created):
		try:
			if path.is_symlink() or fingerprint(path.lstat())[:-1] != proof:
				problems.append(f'directory changed: {path}')
				continue
			path.rmdir()
		except FileNotFoundError:
			continue
		except OSError as error:
			problems.append(f'{path}: {error}')
	return problems


def systemd_argument(value):
	value = str(value)
	if any(ord(char) < 32 or char in '\\"%$' for char in value):
		raise RuntimeError(f'path cannot be safely represented in a systemd unit: {value!r}')
	return f'"{value}"'


def free_ports(count):
	with contextlib.ExitStack() as stack:
		probes = [stack.enter_context(socket.socket()) for _ in range(count)]
		for probe in probes:
			probe.bind(('127.0.0.1', 0))
		return [probe.getsockname()[1] for probe in probes]


def wait_dashboard(port):
	for _ in range(100):
		connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
		try:
			connection.request('GET', '/api/status')
			response = connection.getresponse()
			value = json.loads(response.read())
			is_running = response.status == 200 and value['tld'] == 'test'
		except (OSError, ValueError):
			is_running = False
		finally:
			connection.close()
		if is_running:
			return
		time.sleep(0.1)
	raise RuntimeError('service did not become ready')


def wait_stopped(port):
	for _ in range(100):
		with socket.socket() as probe:
			probe.settimeout(0.1)
			if probe.connect_ex(('127.0.0.1', port)) != 0:
				return
		time.sleep(0.1)
	raise RuntimeError('service listener did not stop')


def service_home(run, cli):
	home = run.output / 'service-home'
	home.mkdir(mode=0o700)
	env = dict(os.environ, HOME=str(home))
	for key in list(env):
		if key.startswith('TESTD_'):
			del env[key]
	run.command('service-init', [str(cli), 'init', '--caddyfile', ''], env=env)
	ports = free_ports(3)
	config = home / '.config/testd/config.toml'
	text = config.read_text().replace('[host]', '[host]\n' + '\n'.join([
		f'listen_addr = "127.0.0.1:{ports[0]}"', f'edge_addr = "127.0.0.1:{ports[1]}"',
		f'http_addr = "127.0.0.1:{ports[2]}"',
	]))
	shutil.copy2(config, run.output / 'service-config-before.toml')
	config.write_text(text)
	provider = config.parent / 'fake-service-tunnel'
	provider.write_text('#!/bin/sh\nprintf \'{"Web":{}}\\n\'\n', encoding='utf-8')
	provider.chmod(0o700)
	return home, ports, provider


def pid(run, name):
	text = run.command('service-pid', ['systemctl', '--user', 'show', name, '-p', 'MainPID', '--value'])
	value = int(text.strip())
	if value <= 1:
		raise RuntimeError(f'no live PID for the test service: {value}')
	return value


def supervise(run, name, unit, proof, port, tls_port, root):
	wait_dashboard(port)
	run.command('service-tls', ['curl', '--silent', '--show-error', '--max-time', '10', '--noproxy', '*',
		'--cacert', str(root), '--resolve', f'testd.test:{tls_port}:127.0.0.1',
		f'https://testd.test:{tls_port}/'])
	original = pid(run, name)
	with verified_owned_file(unit, proof):
		run.command('service-kill', ['systemctl', '--user', 'kill', '--kill-whom=main', '--signal=SIGKILL', name])
	for _ in range(60):
		time.sleep(0.5)
		try:
			current = pid(run, name)
		except RuntimeError:
			continue
		if current != original:
			break
	else:
		raise RuntimeError('the supervisor did not restart the killed daemon')
	wait_dashboard(port)
	run.record('service-restart', 'pass', f'{original} -> {current}')


def service_unit(cli, home, provider):
	text = (ROOT / 'packaging/systemd/testd.service').read_text()
	exec_marker = 'ExecStart=/usr/bin/env testd host'
	write_marker = 'ReadWritePaths=%h/.config/testd'
	if text.count(exec_marker) != 1 or text.count(write_marker) != 1:
		raise RuntimeError('the packaged service template changed; review it before running this fixture')
	environment = (f'HOME={home}', 'PATH=/usr/local/bin:/usr/bin:/bin', 'TESTD_TLD=test', f'TESTD_TUNNEL={provider}')
	command = ' '.join(systemd_argument(value) for value in (*environment, cli))
	text = text.replace(exec_marker, f'ExecStart=/usr/bin/env -i {command} host')
	return text.replace(write_marker, f'ReadWritePaths={systemd_argument(home / ".config/testd")}')


def run_service(run, cli, system):
	if system == 'Windows':
		run.record('service', 'skip', 'not applicable: no Windows CLI service is shipped')
		return
	if system != 'Linux':
		run.metadata['incomplete'] = True
		run.record('service', 'skip', 'blocked: launchd service ownership is not yet verified')
		return
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
		probe.bind(('127.0.0.1', 7753))
	home, ports, provider = service_home(run, cli)
	text = service_unit(cli.resolve(), home, provider)
	(run.output / 'service-unit.service').write_text(text, encoding='utf-8')
	name = f'dev.testd.releasecheck.{uuid.uuid4().hex}.service'
	loaded = run.command('service-preflight', ['systemctl', '--user', 'show', name, '-p', 'LoadState', '--value'])
	if loaded.strip() != 'not-found':
		raise RuntimeError(f'the service name is already loaded: {name}')
	created = prepare_directories(pathlib.Path.home())
	unit = pathlib.Path.home() / '.config/systemd/user' / name
	try:
		proof = create_owned_file(unit, text.encode('utf-8'))
		attempted_start = False
		try:
			run.command('service-reload', ['systemctl', '--user', 'daemon-reload'])
			attempted_start = True
			run.command('service-start', ['systemctl', '--user', 'start', name])
			supervise(run, name, unit, proof, ports[0], ports[1], home / '.config/testd/pki/root.crt')
		finally:
			if attempted_start:
				with verified_owned_file(unit, proof):
					run.command('service-stop', ['systemctl', '--user', 'stop', name])
				wait_stopped(ports[0])
			remove_owned_file(unit, proof)
			run.command('service-reload', ['systemctl', '--user', 'daemon-reload'])
	finally:
		problems = prune_directories(created)
		if problems:
			run.metadata['incomplete'] = True
			run.record('service-directories', 'skip', 'blocked: ' + '; '.join(problems))
	run.record('service-stop-check', 'pass', 'listener stopped; generated unit retained in the report')
