"""Snapshot and restore the OS integration that `testd doctor --fix` installs.

The host suite assumes no testd daemon is running while it holds this state, and
that the pre-run integration comes back afterwards. Every artifact `doctor --fix`
writes is either a plain file or a store entry scoped to the throwaway TLD or to
the `testd root` name, so a byte-exact backup plus a manifest restores a host
exactly. Restores are idempotent, so a report can be restored again after a hard
kill.

Unix files and the macOS keychain are handled here. Windows NRPT rules and the
machine root store are delegated to `windows-system-state.ps1`, which keeps the
privileged PowerShell in one audited place.
"""

import base64
import datetime
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile

MANIFEST = 'manifest.json'
BLOBS = 'blobs'
RESTORED = 'restored.json'
KEYCHAIN = '/Library/Keychains/System.keychain'
KEYCHAIN_NAME = 'testd root'
WINDOWS_SCRIPT = pathlib.Path(__file__).resolve().with_name('windows-system-state.ps1')


class HostError(RuntimeError):
	"""A command or file operation the suite needs did not succeed."""


class Host:
	"""The host operations the restore logic needs.

	Tests subclass this with an in-memory filesystem so the manifest format and
	the restore rules can be exercised without root or a real OS store.
	"""

	def __init__(self, system, tld, interactive=False):
		self.system = system
		self.tld = tld
		# Interactive hosts may prompt for sudo; unattended runs must have it cached.
		self.interactive = interactive

	def command(self, argv, privileged=False):
		"""Run a command and return its stdout, failing loudly on any error."""
		return self._run(self.argv(argv, privileged)).decode(errors='replace')

	def read(self, path):
		try:
			return pathlib.Path(path).read_bytes()
		except PermissionError:
			return self._run(self.argv(['cat', str(path)], True))

	def exists(self, path):
		return pathlib.Path(path).exists()

	def mode(self, path):
		return stat.S_IMODE(pathlib.Path(path).stat().st_mode)

	def write(self, path, data, mode=0o644):
		"""Replace a path through a staged copy, so a failure cannot truncate it."""
		with tempfile.NamedTemporaryFile(delete=False) as staged:
			staged.write(data)
		try:
			parent = str(pathlib.Path(path).parent)
			self.command(['mkdir', '-p', parent], True)
			self.command(['install', '-m', f'{mode:o}', staged.name, str(path)], True)
		finally:
			os.unlink(staged.name)

	def remove(self, path):
		self.command(['rm', '-f', str(path)], True)

	def argv(self, argv, privileged=False):
		if not privileged or self.system == 'Windows':
			return list(argv)
		if self.interactive:
			return ['sudo', '--', *argv]
		self.require_sudo()
		return ['sudo', '-n', '--', *argv]

	def require_sudo(self):
		result = subprocess.run(['sudo', '-n', '-v'], capture_output=True)
		if result.returncode != 0:
			raise HostError('sudo credentials are not cached; run `sudo -v` before the system checks')

	def _run(self, argv):
		result = subprocess.run(argv, capture_output=True)
		if result.returncode != 0:
			detail = result.stderr.decode(errors='replace').strip() or f'exit {result.returncode}'
			raise HostError(f'{" ".join(argv)}: {detail}')
		return result.stdout


def files(host):
	"""Plain files `doctor --fix` writes, plus the command that reloads each consumer."""
	if host.system == 'Linux':
		return [
			{'path': '/etc/systemd/resolved.conf.d/90-testd.conf',
				'reload': ['systemctl', 'reload', 'systemd-resolved']},
			{'path': '/usr/local/share/ca-certificates/testd-root.crt',
				'reload': ['update-ca-certificates', '--fresh']},
		]
	if host.system == 'Darwin':
		return [{'path': f'/etc/resolver/{host.tld}'}]
	return []


def digest(data):
	return hashlib.sha256(data).hexdigest()


def encode_pem(der):
	body = base64.b64encode(der).decode()
	lines = [body[index:index + 64] for index in range(0, len(body), 64)]
	return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(lines) + '\n-----END CERTIFICATE-----\n'


def decode_pem(text):
	"""Return the DER bytes of every certificate in a PEM stream."""
	blocks = text.split('-----BEGIN CERTIFICATE-----')[1:]
	return [base64.b64decode(block.split('-----END CERTIFICATE-----')[0].strip())
		for block in blocks if block.strip()]


def keychain_certificates(host):
	"""Map SHA-1 to DER for every `testd root` in the macOS system keychain."""
	command = ['security', 'find-certificate', '-a', '-c', KEYCHAIN_NAME, '-p', KEYCHAIN]
	if not host.exists(KEYCHAIN):
		return {}
	text = host.command(command, privileged=True)
	return {hashlib.sha1(der).hexdigest(): der for der in decode_pem(text)}


def snapshot(host, directory):
	"""Record the current integration; the run restores it when the suite finishes."""
	directory = pathlib.Path(directory)
	(directory / BLOBS).mkdir(parents=True, exist_ok=True)
	manifest = {'system': host.system, 'tld': host.tld, 'created':
		datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
		'files': [], 'certificates': []}
	for index, item in enumerate(files(host)):
		entry = {'path': item['path'], 'reload': item.get('reload'), 'exists': host.exists(item['path'])}
		if entry['exists']:
			data = host.read(item['path'])
			entry['blob'] = f'{BLOBS}/file-{index}.bin'
			entry['mode'] = host.mode(item['path'])
			entry['sha256'] = digest(data)
			(directory / entry['blob']).write_bytes(data)
		manifest['files'].append(entry)
	if host.system == 'Darwin':
		for index, (sha1, der) in enumerate(keychain_certificates(host).items()):
			blob = f'{BLOBS}/cert-{index}.der'
			(directory / blob).write_bytes(der)
			manifest['certificates'].append({'sha1': sha1, 'blob': blob})
	if host.system == 'Windows':
		host.command(windows_command('Snapshot', directory, host.tld), privileged=True)
	(directory / MANIFEST).write_text(json.dumps(manifest, indent='\t') + '\n')
	return directory / MANIFEST


def windows_command(action, directory, tld):
	return ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(WINDOWS_SCRIPT),
		'-Action', action, '-Destination', str(directory), '-Tld', tld]


def load(directory):
	path = pathlib.Path(directory) / MANIFEST
	if not path.is_file():
		raise HostError(f'no system snapshot at {path}; system checks are only run by '
			'tests/release/run.py host --system')
	return json.loads(path.read_text())


def restore(host, directory):
	"""Put the host back the way it was, then verify it. Returns every problem found."""
	directory = pathlib.Path(directory)
	manifest = load(directory)
	if manifest['system'] != host.system:
		raise HostError(f'the snapshot belongs to {manifest["system"]}, not {host.system}')
	record = directory / RESTORED
	# A completed restore that still verifies needs no second round of privileged
	# reloads; a drifted host does, so the record is not a licence to skip checks.
	if record.is_file() and not verify(host, directory, manifest):
		return []
	problems = []
	for entry in manifest['files']:
		problems += restore_file(host, directory, entry)
	if manifest['system'] == 'Darwin':
		problems += restore_keychain(host, directory, manifest)
	if manifest['system'] == 'Windows':
		try:
			host.command(windows_command('Restore', directory, host.tld), privileged=True)
		except HostError as error:
			problems.append(str(error))
	problems += verify(host, directory, manifest)
	if not problems:
		stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
		record.write_text(json.dumps({'restored': stamp}, indent='\t') + '\n')
	return problems


def restore_file(host, directory, entry):
	path = entry['path']
	try:
		if entry['exists']:
			data = (directory / entry['blob']).read_bytes()
			if digest(data) != entry['sha256']:
				return [f'{path}: the backed-up copy was modified']
			host.write(path, data, entry.get('mode', 0o644))
		else:
			host.remove(path)
		if entry.get('reload'):
			host.command(entry['reload'], privileged=True)
	except HostError as error:
		return [str(error)]
	return []


def restore_keychain(host, directory, manifest):
	expected = {entry['sha1']: entry for entry in manifest['certificates']}
	try:
		current = keychain_certificates(host)
		for sha1 in current:
			if sha1 not in expected:
				host.command(['security', 'delete-certificate', '-Z', sha1, KEYCHAIN], privileged=True)
		for sha1, entry in expected.items():
			if sha1 in current:
				continue
			der = (directory / entry['blob']).read_bytes()
			if hashlib.sha1(der).hexdigest() != sha1:
				return [f'{KEYCHAIN}: the backed-up certificate {sha1} was modified']
			staged = directory / f'restore-{sha1}.pem'
			staged.write_text(encode_pem(der))
			try:
				host.command(['security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', KEYCHAIN,
					str(staged)], privileged=True)
			finally:
				staged.unlink()
	except HostError as error:
		return [str(error)]
	return []


def verify(host, directory, manifest=None):
	"""Compare the host against the manifest; an empty list means it is back."""
	manifest = manifest or load(directory)
	problems = []
	for entry in manifest['files']:
		path = entry['path']
		if host.exists(path) != entry['exists']:
			condition = 'missing' if entry['exists'] else 'still present'
			problems.append(f'{path}: {condition} after restore')
		elif entry['exists'] and digest(host.read(path)) != entry['sha256']:
			problems.append(f'{path}: content differs from the snapshot')
	if manifest['system'] == 'Darwin':
		expected = {entry['sha1'] for entry in manifest['certificates']}
		current = set(keychain_certificates(host))
		if current != expected:
			problems.append(f'{KEYCHAIN}: testd root certificates differ from the snapshot')
	if manifest['system'] == 'Windows':
		try:
			host.command(windows_command('Verify', directory, host.tld), privileged=True)
		except HostError as error:
			problems.append(str(error))
	return problems
