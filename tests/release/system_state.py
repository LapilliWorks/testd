"""Snapshot and restore the OS integration that `testd doctor --fix` installs.

The host suite assumes no testd daemon is running while it holds this state, and
that the pre-run integration comes back afterwards. Every artifact `doctor --fix`
writes is either a plain file or a store entry scoped to the throwaway TLD or to
the `testd root` prefix and the separate `testd root testing` fixture name, so a
byte-exact backup plus a manifest restores a host exactly. Restores are idempotent, so a report can be restored again after a hard
kill.

Unix files and the macOS keychain are handled here. Windows NRPT rules and the
machine root store are delegated to `windows-system-state.ps1`, which keeps the
privileged PowerShell in one audited place.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile

MANIFEST = 'manifest.json'
BLOBS = 'blobs'
RESTORED = 'restored.json'
KEYCHAIN = '/Library/Keychains/System.keychain'
KEYCHAIN_PREFIX = 'testd root'
FIXTURE_KEYCHAIN_NAME = 'testd root testing'
WINDOWS_SCRIPT = pathlib.Path(__file__).resolve().with_name('windows-system-state.ps1')
WINDOWS_FIXTURE = pathlib.Path(__file__).resolve().with_name('windows-system-fixture.ps1')
SELF_TEST_TLD = 'testdrestore'
SELF_TEST_RESOLVER = b'# testd restore self-test fixture\n'


class HostError(RuntimeError):
	"""A command or file operation the suite needs did not succeed."""


def is_root():
	"""True where privileged commands need no sudo, including root containers."""
	return getattr(os, 'geteuid', lambda: 1)() == 0


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
		if not privileged or self.system == 'Windows' or is_root():
			return list(argv)
		if self.interactive:
			return ['sudo', '--', *argv]
		self.require_sudo()
		return ['sudo', '-n', '--', *argv]

	def require_sudo(self):
		if self.system == 'Windows' or is_root():
			return
		result = subprocess.run(['sudo', '-n', '-v'], capture_output=True)
		if result.returncode != 0:
			raise HostError('sudo credentials are not cached; run `sudo -v` before the system checks')

	def certificate_common_name(self, der):
		"""Read the CN from DER with the platform openssl tool."""
		with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as staged:
			staged.write(der)
			path = staged.name
		try:
			text = self.command(['openssl', 'x509', '-inform', 'DER', '-noout', '-subject', path])
		finally:
			pathlib.Path(path).unlink(missing_ok=True)
		match = re.search(r'CN\s*=\s*([^,/\n]+)', text)
		return match.group(1).strip() if match else None

	def _run(self, argv):
		# A hung privileged command must fail the restore, not stall it silently.
		try:
			result = subprocess.run(argv, capture_output=True, timeout=300 if self.interactive else 120)
		except subprocess.TimeoutExpired:
			raise HostError(f'{" ".join(argv)}: timed out') from None
		if result.returncode != 0:
			# windows_command makes the PowerShell child emit UTF-8 whatever the
			# console code page is, so this decode is exact rather than lossy.
			detail = result.stderr.decode('utf-8', errors='replace').strip() or f'exit {result.returncode}'
			raise HostError(f'{" ".join(argv)}: {detail}')
		return result.stdout


# Debian and Ubuntu ship update-ca-certificates and read anchors from the local
# directory; Fedora and RHEL ship update-ca-trust and read the pki anchors. This
# mirrors the layout testd-setup picks.
CA_ANCHOR_TOOLS = ('/usr/sbin/update-ca-certificates', '/usr/bin/update-ca-certificates')
FEDORA_TRUST_TOOL = '/usr/bin/update-ca-trust'
FEDORA_ANCHOR_DIR = '/etc/pki/ca-trust/source/anchors'


def linux_trust(has_update_ca_certificates=None, has_fedora_anchors=None):
	if has_update_ca_certificates is None:
		has_update_ca_certificates = any(pathlib.Path(tool).exists() for tool in CA_ANCHOR_TOOLS)
	if has_fedora_anchors is None:
		has_fedora_anchors = (pathlib.Path(FEDORA_TRUST_TOOL).exists()
			and pathlib.Path(FEDORA_ANCHOR_DIR).is_dir())
	if has_fedora_anchors and not has_update_ca_certificates:
		return f'{FEDORA_ANCHOR_DIR}/testd-root.crt', ['update-ca-trust', 'extract']
	return '/usr/local/share/ca-certificates/testd-root.crt', ['update-ca-certificates']


def files(host):
	"""Plain files `doctor --fix` writes, plus the command that reloads each consumer."""
	if host.system == 'Linux':
		anchor, reload = linux_trust()
		return [
			{'path': '/etc/systemd/resolved.conf.d/90-testd.conf',
				'reload': ['systemctl', 'reload', 'systemd-resolved']},
			{'path': anchor, 'reload': reload},
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


def is_testd_root_name(common_name):
	"""Match legacy, serial-suffixed, and fixture testd root names."""
	if common_name == KEYCHAIN_PREFIX:
		return True
	if common_name == FIXTURE_KEYCHAIN_NAME:
		return False
	suffix = common_name[len(KEYCHAIN_PREFIX):]
	if not suffix.startswith(' '):
		return False
	suffix = suffix[1:]
	return len(suffix) == 8 and all(character in '0123456789abcdefABCDEF' for character in suffix)


def is_snapshot_root_name(common_name):
	"""Snapshot fixture roots too, so their restore can remove them."""
	return common_name == FIXTURE_KEYCHAIN_NAME or is_testd_root_name(common_name)


def keychain_certificates(host):
	"""Map SHA-1 to DER for every testd root in the macOS system keychain."""
	if not host.exists(KEYCHAIN):
		return {}
	text = host.command(['security', 'find-certificate', '-a', '-Z', '-p', KEYCHAIN], privileged=True)
	certificates = {}
	for der in decode_pem(text):
		name = host.certificate_common_name(der)
		if name and is_snapshot_root_name(name):
			certificates[hashlib.sha1(der).hexdigest()] = der
	return certificates


def snapshot(host, directory, artifacts=None):
	"""Record the current integration; the run restores it when the suite finishes."""
	directory = pathlib.Path(directory)
	(directory / BLOBS).mkdir(parents=True, exist_ok=True)
	manifest = {'system': host.system, 'tld': host.tld, 'created':
		datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
		'files': [], 'certificates': []}
	for index, item in enumerate(files(host) if artifacts is None else artifacts):
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


def powershell_quote(value):
	"""Quote one PowerShell literal; inside single quotes a quote is doubled."""
	return "'" + str(value).replace("'", "''") + "'"


def windows_script(script, parameters):
	"""Run a .ps1 with UTF-8 messages, whatever code page the console uses.

	Windows PowerShell 5.1 writes the messages it generates itself in the
	console code page (cp936 on a Chinese system), so a localized parse error
	reached this suite as GBK bytes, was decoded as UTF-8 with replacement
	characters, and rendered as unreadable garbage. Setting the encoding inside
	the child makes 5.1 and 7 emit the same bytes. `-File` cannot do this,
	because a parse error is printed before any of the script has run.
	"""
	arguments = ' '.join(f'-{name} {powershell_quote(value)}' for name, value in parameters)
	return (f'[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); '
		f'& {powershell_quote(script)} {arguments}')


def windows_command(action, directory, tld):
	return ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
		windows_script(WINDOWS_SCRIPT, [('Action', action), ('Destination', directory), ('Tld', tld)])]


def windows_fixture_command(tld):
	return ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
		windows_script(WINDOWS_FIXTURE, [('Tld', tld)])]


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
		changed = False
		if entry['exists']:
			data = (directory / entry['blob']).read_bytes()
			if digest(data) != entry['sha256']:
				return [f'{path}: the backed-up copy was modified']
			host.write(path, data, entry.get('mode', 0o644))
			changed = True
		elif host.exists(path):
			host.remove(path)
			changed = True
		# Only reload a consumer whose file changed: restore also runs when
		# doctor --fix never got as far as installing it, and the reload tool may
		# not exist on this distro.
		if changed and entry.get('reload'):
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


def occupied(directory):
	"""Return the integration a snapshot found; the self-test needs a host with none."""
	directory = pathlib.Path(directory)
	manifest = load(directory)
	found = [entry['path'] for entry in manifest['files'] if entry['exists']]
	found += [f'{KEYCHAIN} {entry["sha1"]}' for entry in manifest['certificates']]
	if manifest['system'] == 'Windows':
		nrpt = directory / 'nrpt.json'
		# The host script writes UTF-8, with a BOM on PowerShell 5.1.
		rules = json.loads(nrpt.read_text(encoding='utf-8-sig')) if nrpt.is_file() else []
		found += [f'NRPT rule for {rule["Signature"]["Namespace"]}' for rule in rules]
		roots = directory / 'roots'
		if roots.is_dir():
			found += [f'machine root {path.stem}' for path in sorted(roots.glob('*.cer'))]
	return found


def self_test_artifacts(host):
	"""The real artifact paths, minus the reload that needs a running resolver.

	The trust reload is kept: it is the one that proves the certificate store,
	and it only needs the distro tool. The resolver reload belongs to the full
	`host --system` run, which is why the resolver drop-in is exercised as a file.
	"""
	artifacts = []
	for entry in files(host):
		reload = entry.get('reload')
		if reload and (reload[0] == 'systemctl' or not shutil.which(reload[0])):
			reload = None
		artifacts.append({'path': entry['path'], 'reload': reload})
	return artifacts


def install_fixture(host, directory, workdir):
	"""Install what `doctor --fix` would, through the same privileged operations."""
	if host.system == 'Windows':
		try:
			host.command(windows_fixture_command(host.tld), privileged=True)
		except HostError as error:
			return [str(error)]
		return []
	certificate = pathlib.Path(workdir) / 'fixture.pem'
	try:
		host.command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
			'-subj', f'/CN={FIXTURE_KEYCHAIN_NAME}', '-keyout', str(pathlib.Path(workdir) / 'fixture.key'),
			'-out', str(certificate)])
	except HostError as error:
		return [f'openssl cannot build the fixture certificate: {error}']
	problems = []
	for entry in load(directory)['files']:
		is_certificate = entry['path'].endswith('.crt')
		try:
			host.write(entry['path'], certificate.read_bytes() if is_certificate else SELF_TEST_RESOLVER, 0o644)
			if entry.get('reload'):
				host.command(entry['reload'], privileged=True)
		except HostError as error:
			# Later steps cannot work either, and the caller still restores.
			return [str(error)]
	if host.system == 'Darwin':
		try:
			host.command(['security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', KEYCHAIN,
				str(certificate)], privileged=True)
		except HostError as error:
			problems.append(str(error))
	return problems


def fixture_present(host, directory):
	"""Assert the fixture landed, so the restore is not a no-op round trip."""
	manifest = load(directory)
	missing = [entry['path'] for entry in manifest['files'] if not host.exists(entry['path'])]
	if missing:
		return [f'the fixture did not install {path}' for path in missing]
	if manifest['system'] == 'Darwin' and not keychain_certificates(host):
		return [f'the fixture did not reach {KEYCHAIN}']
	if manifest['system'] == 'Windows':
		# Verify fails exactly while the machine differs from the snapshot, so a
		# passing verify here means the fixture never landed.
		try:
			host.command(windows_command('Verify', directory, host.tld), privileged=True)
		except HostError:
			return []
		return ['the fixture did not change the machine']
	return []


def self_test(system=None, tld=SELF_TEST_TLD):
	"""Snapshot, install a fixture, restore, verify on a host with no integration.

	This is the check CI runs on disposable runners: it exercises the real
	privileged writes and stores, which unit tests replace with an in-memory host.
	It refuses to run where testd integration already exists, because the fixture
	would replace a live root or route for the duration of the round trip.
	"""
	host = Host(system or platform.system(), tld)
	with tempfile.TemporaryDirectory(prefix='testd-restore-') as temporary:
		workdir = pathlib.Path(temporary)
		directory = workdir / 'system-before'
		print(f'host: {host.system}, snapshot: {directory}', flush=True)
		snapshot(host, directory, self_test_artifacts(host))
		present = occupied(directory)
		if present:
			return [f'{item} is already installed; the self-test needs a host without testd integration'
				for item in present]
		problems = install_fixture(host, directory, workdir)
		if not problems:
			problems = fixture_present(host, directory)
		if problems:
			# A fixture that only partly landed still has to be taken back out.
			return list(dict.fromkeys(problems + restore(host, directory)))
		print('fixture installed; restoring', flush=True)
		return restore(host, directory)


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--self-test', action='store_true',
		help='snapshot, fixture, restore, and verify the real integration paths')
	args = parser.parse_args(argv)
	if not args.self_test:
		parser.error('nothing to do; pass --self-test')
	problems = self_test()
	for problem in problems:
		print(f'fail     {problem}', flush=True)
	if problems:
		return 1
	print('ok       snapshot, fixture, restore, and verify', flush=True)
	return 0


if __name__ == '__main__':
	sys.exit(main())
