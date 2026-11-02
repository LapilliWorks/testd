"""Exercise real user-session supervision without changing resolver or trust state."""

import http.client
import json
import os
import pathlib
import plistlib
import re
import shutil
import signal
import socket
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]


def free_port():
	with socket.socket() as probe:
		probe.bind(('127.0.0.1', 0))
		return probe.getsockname()[1]


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
	ports = [free_port() for _ in range(3)]
	config = home / '.config/testd/config.toml'
	text = config.read_text().replace('[host]', '[host]\n' + '\n'.join([
		f'listen_addr = "127.0.0.1:{ports[0]}"', f'edge_addr = "127.0.0.1:{ports[1]}"',
		f'http_addr = "127.0.0.1:{ports[2]}"',
	]))
	shutil.copy2(config, run.output / 'service-config-before.toml')
	config.write_text(text)
	return home, ports


def pid(run, system, name):
	if system == 'Linux':
		text = run.command('service-pid', ['systemctl', '--user', 'show', name, '-p', 'MainPID', '--value'])
		value = int(text.strip())
	else:
		text = run.command('service-pid', ['launchctl', 'print', name])
		match = re.search(r'\bpid = (\d+)', text)
		value = int(match[1]) if match else 0
	if value <= 1:
		raise RuntimeError(f'no live PID for the test service: {value}')
	return value


def supervise(run, system, name, port, tls_port, root):
	wait_dashboard(port)
	run.command('service-tls', ['curl', '--silent', '--show-error', '--max-time', '10', '--noproxy', '*',
		'--cacert', str(root), '--resolve', f'testd.test:{tls_port}:127.0.0.1',
		f'https://testd.test:{tls_port}/'])
	original = pid(run, system, name)
	os.kill(original, signal.SIGKILL)
	for _ in range(60):
		time.sleep(0.5)
		try:
			current = pid(run, system, name)
		except RuntimeError:
			continue
		if current != original:
			break
	else:
		raise RuntimeError('the supervisor did not restart the killed daemon')
	wait_dashboard(port)
	run.record('service-restart', 'pass', f'{original} -> {current}')


def run_service(run, cli, system):
	if system == 'Windows':
		run.record('service', 'skip', 'no Windows CLI service is shipped; run the desktop launch-at-login checks')
		return
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
		probe.bind(('127.0.0.1', 7753))
	home, ports = service_home(run, cli)
	label = 'dev.testd.releasecheck.' + re.sub('[^a-z0-9.-]', '-', run.output.name.lower())
	root = home / '.config/testd/pki/root.crt'
	if system == 'Linux':
		directory = pathlib.Path.home() / '.config/systemd/user'
		directory.mkdir(parents=True, exist_ok=True)
		unit = directory / (label + '.service')
		if unit.exists():
			raise FileExistsError(unit)
		text = (ROOT / 'packaging/systemd/testd.service').read_text()
		text = text.replace('ExecStart=/usr/bin/env testd host', f'Environment="HOME={home}"\nExecStart="{cli}" host')
		text = text.replace('ReadWritePaths=%h/.config/testd', f'ReadWritePaths="{home}/.config/testd"')
		(run.output / 'service-unit.service').write_text(text)
		unit.write_text(text)
		name = unit.name
		try:
			run.command('service-reload', ['systemctl', '--user', 'daemon-reload'])
			run.command('service-start', ['systemctl', '--user', 'start', name])
			supervise(run, system, name, ports[0], ports[1], root)
		finally:
			run.command('service-stop', ['systemctl', '--user', 'stop', name])
			unit.unlink()
			run.command('service-reload', ['systemctl', '--user', 'daemon-reload'])
	else:
		value = plistlib.loads((ROOT / 'packaging/launchd/dev.testd.host.plist').read_bytes())
		value.update(Label=label, ProgramArguments=[str(cli), 'host'], EnvironmentVariables={'HOME': str(home)},
			StandardOutPath=str(run.output / 'launchd.out'), StandardErrorPath=str(run.output / 'launchd.err'))
		plist = run.output / 'service.plist'
		plist.write_bytes(plistlib.dumps(value))
		name = f'gui/{os.getuid()}/{label}'
		run.command('service-start', ['launchctl', 'bootstrap', f'gui/{os.getuid()}', str(plist)])
		try:
			supervise(run, system, name, ports[0], ports[1], root)
		finally:
			run.command('service-stop', ['launchctl', 'bootout', name])
	wait_stopped(ports[0])
	run.record('service-stop', 'pass', 'listener stopped; generated unit/plist retained in the report')
