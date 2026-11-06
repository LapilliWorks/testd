"""Snapshot selected OS integration and remove only proven test-owned fixtures.

System tests require a clean disposable host and a persisted full-system snapshot.
Changed pre-existing files and unowned additions are reported without modification.
The scoped snapshot cannot restore shared trust-store output or other system state.

Windows NRPT and machine-root snapshots are verify-only until their ownership
can be proven; they are delegated to `windows-system-state.ps1`.
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
OWNED_FILES = 'owned-files'
OWNED_CERTIFICATES = 'owned-certificates'
SAFE_TLDS = frozenset({'test', 'testdcheck', 'testdrestore'})
KEYCHAIN = '/Library/Keychains/System.keychain'
KEYCHAIN_PREFIX = 'testd root'
FIXTURE_KEYCHAIN_NAME = 'testd root testing'
WINDOWS_SCRIPT = pathlib.Path(__file__).resolve().with_name('windows-system-state.ps1')
SELF_TEST_TLD = 'testdrestore'
SELF_TEST_RESOLVER = b'# testd restore self-test fixture\n'

EXCLUSIVE_CREATE = r'''
import json, os, shutil, sys
path, mode, source = sys.argv[1:]
parent, name = os.path.split(path)
directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(name, flags, int(mode, 8), dir_fd=directory)
    try:
        with open(source, 'rb') as incoming, os.fdopen(descriptor, 'wb', closefd=False) as outgoing:
            shutil.copyfileobj(incoming, outgoing)
            outgoing.flush()
        os.fchmod(descriptor, int(mode, 8))
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        print(json.dumps([metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
                          metadata.st_mode & 0o7777, metadata.st_ctime_ns]))
    finally:
        os.close(descriptor)
finally:
    os.close(directory)
'''

REMOVE_OWNED = r'''
import hashlib, json, os, stat, sys
path, encoded = sys.argv[1:]
proof = json.loads(encoded)
parent, name = os.path.split(path)
def fingerprint(value):
    return [value.st_dev, value.st_ino, value.st_uid, value.st_gid,
            stat.S_IMODE(value.st_mode), value.st_ctime_ns]
directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or fingerprint(metadata) != proof['fingerprint']:
            raise SystemExit('fixture identity changed; refusing removal')
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            actual = hashlib.file_digest(source, 'sha256').hexdigest()
        if actual != proof['sha256'] or fingerprint(os.fstat(descriptor)) != proof['fingerprint']:
            raise SystemExit('fixture content changed; refusing removal')
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if fingerprint(current) != proof['fingerprint']:
            raise SystemExit('fixture was replaced; refusing removal')
        os.unlink(name, dir_fd=directory)
    finally:
        os.close(descriptor)
finally:
    os.close(directory)
'''


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
		path = pathlib.Path(path)
		return path.exists() or path.is_symlink()

	def regular(self, path):
		return stat.S_ISREG(pathlib.Path(path).lstat().st_mode)

	def directory(self, path):
		path = pathlib.Path(path)
		return not path.is_symlink() and path.is_dir()

	def mode(self, path):
		return stat.S_IMODE(pathlib.Path(path).lstat().st_mode)

	def identity(self, path):
		metadata = pathlib.Path(path).lstat()
		return [metadata.st_dev, metadata.st_ino]

	def fingerprint(self, path):
		metadata = pathlib.Path(path).lstat()
		return [metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
			stat.S_IMODE(metadata.st_mode), metadata.st_ctime_ns]

	def create(self, path, data, mode=0o644):
		"""Create a fixture without replacing a pre-existing path or symlink."""
		with tempfile.NamedTemporaryFile(delete=False) as staged:
			staged.write(data)
		try:
			output = self.command([sys.executable, '-c', EXCLUSIVE_CREATE, str(path), f'{mode:o}', staged.name], True)
			return json.loads(output)
		finally:
			os.unlink(staged.name)

	def remove_owned(self, path, proof):
		"""Recheck a fixture's identity and bytes in the privileged removal process."""
		self.command([sys.executable, '-c', REMOVE_OWNED, str(path), json.dumps(proof)], True)

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
			text = self.command(['openssl', 'x509', '-inform', 'DER', '-noout', '-subject', '-in', path])
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
			{'path': f'{anchor}.owner'},
			{'path': '/etc/systemd/resolved.conf.d/90-testd.conf.owner'},
		]
	if host.system == 'Darwin':
		return [{'path': f'/etc/resolver/{host.tld}'}]
	return []


def digest(data):
	return hashlib.sha256(data).hexdigest()


def owned_file_path(directory, path):
	return pathlib.Path(directory) / OWNED_FILES / f'{digest(str(path).encode())}.json'


def record_owned_file(host, directory, path, fingerprint, expected_sha256):
	manifest = load(directory)
	entry = next((item for item in manifest['files'] if item['path'] == str(path)), None)
	if not entry or entry['exists'] or not host.regular(path) or host.fingerprint(path) != fingerprint or \
			digest(host.read(path)) != expected_sha256:
		raise HostError(f'{path}: cannot prove that the fixture created this file')
	proof = {'path': str(path), 'fingerprint': fingerprint, 'sha256': expected_sha256}
	ledger = owned_file_path(directory, path)
	if ledger.parent.is_symlink():
		raise HostError('the fixture ownership ledger is a symlink')
	ledger.parent.mkdir(mode=0o700, exist_ok=True)
	with ledger.open('x', encoding='utf-8') as output:
		json.dump(proof, output, indent='\t')
		output.write('\n')
		output.flush()
		os.fsync(output.fileno())


def record_owned_certificate(directory, der):
	sha1 = hashlib.sha1(der).hexdigest()
	manifest = load(directory)
	if any(entry['sha1'] == sha1 for entry in manifest['certificates']):
		raise HostError('the certificate was already present before the fixture')
	ledger = pathlib.Path(directory) / OWNED_CERTIFICATES / f'{sha1}.der'
	if ledger.parent.is_symlink():
		raise HostError('the fixture certificate ledger is a symlink')
	ledger.parent.mkdir(mode=0o700, exist_ok=True)
	with ledger.open('xb') as output:
		output.write(der)
		output.flush()
		os.fsync(output.fileno())
	return sha1


def encode_pem(der):
	body = base64.b64encode(der).decode()
	lines = [body[index:index + 64] for index in range(0, len(body), 64)]
	return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(lines) + '\n-----END CERTIFICATE-----\n'


def decode_pem(text):
	"""Return the DER bytes of every certificate in a PEM stream."""
	blocks = text.split('-----BEGIN CERTIFICATE-----')[1:]
	return [base64.b64decode(block.split('-----END CERTIFICATE-----')[0].strip())
		for block in blocks if block.strip()]


COVO_SUFFIX = re.compile(r'^[bcdfghjklmnprstvaiou]+(?:-[bcdfghjklmnprstvaiou]+)*$')


def is_testd_root_name(common_name):
	"""Match legacy and pronounceable testd root names, not the fixture."""
	if common_name == KEYCHAIN_PREFIX:
		return True
	if common_name == FIXTURE_KEYCHAIN_NAME:
		return False
	suffix = common_name[len(KEYCHAIN_PREFIX):]
	if not suffix.startswith(' '):
		return False
	return COVO_SUFFIX.fullmatch(suffix[1:]) is not None


def is_snapshot_root_name(common_name):
	"""Snapshot fixture roots too, so their restore can remove them."""
	return common_name == FIXTURE_KEYCHAIN_NAME or is_testd_root_name(common_name)


def keychain_certificates(host):
	"""Map SHA-1 to DER for every testd root in the macOS system keychain."""
	if not host.exists(KEYCHAIN):
		return {}
	text = host.command(['security', 'find-certificate', '-a', '-Z', '-p', KEYCHAIN], privileged=True)
	certificates = {}
	seen = set()
	duplicates = set()
	for der in decode_pem(text):
		sha1 = hashlib.sha1(der).hexdigest()
		if sha1 in seen:
			duplicates.add(sha1)
		seen.add(sha1)
		name = host.certificate_common_name(der)
		if name and is_snapshot_root_name(name):
			certificates[sha1] = der
	conflicts = duplicates & certificates.keys()
	if conflicts:
		raise HostError(f'{KEYCHAIN}: duplicate certificate SHA-1 {sorted(conflicts)[0]}; left untouched')
	return certificates


def snapshot(host, directory, artifacts=None):
	"""Record selected integration without changing existing system state."""
	directory = pathlib.Path(directory)
	if host.tld not in SAFE_TLDS:
		raise HostError(f'unsafe test TLD: {host.tld}')
	artifacts = files(host) if artifacts is None else artifacts
	for item in artifacts:
		parent = str(pathlib.Path(item['path']).parent)
		if not host.directory(parent):
			raise HostError(f'{parent}: system fixture parent is missing or a symlink; left untouched')
	(directory / BLOBS).mkdir(parents=True, exist_ok=False)
	manifest = {'system': host.system, 'tld': host.tld, 'created':
		datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
		'files': [], 'certificates': []}
	for index, item in enumerate(artifacts):
		entry = {'path': item['path'], 'reload': item.get('reload'), 'exists': host.exists(item['path'])}
		if entry['exists']:
			if not host.regular(item['path']):
				raise HostError(f'{item["path"]}: not a regular file; left untouched')
			data = host.read(item['path'])
			entry['blob'] = f'{BLOBS}/file-{index}.bin'
			entry['mode'] = host.mode(item['path'])
			entry['identity'] = host.identity(item['path'])
			entry['fingerprint'] = host.fingerprint(item['path'])
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
	with (directory / MANIFEST).open('x', encoding='utf-8') as output:
		json.dump(manifest, output, indent='\t')
		output.write('\n')
		output.flush()
		os.fsync(output.fileno())
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


def load(directory):
	path = pathlib.Path(directory) / MANIFEST
	if path.is_symlink() or not path.is_file():
		raise HostError(f'no regular system snapshot at {path}; system checks are only run by '
			'tests/release/run.py host --system')
	return json.loads(path.read_text())


def validate_manifest(host, directory, manifest):
	if directory.is_symlink() or (directory / BLOBS).is_symlink():
		raise HostError('the snapshot or its blobs directory is a symlink')
	if manifest.get('system') != host.system or manifest.get('tld') != host.tld or host.tld not in SAFE_TLDS:
		raise HostError('the snapshot platform or TLD does not match this host')
	entries = manifest.get('files')
	expected = files(host)
	if not isinstance(entries, list) or [item.get('path') for item in entries] != [item['path'] for item in expected]:
		raise HostError('the snapshot contains unexpected system paths')
	for index, (entry, allowed) in enumerate(zip(entries, expected)):
		if type(entry.get('exists')) is not bool:
			raise HostError(f'{entry["path"]}: invalid existence flag in the snapshot')
		if entry.get('reload') not in (None, allowed.get('reload')):
			raise HostError(f'{entry["path"]}: unexpected reload command in the snapshot')
		if entry.get('exists'):
			blob = f'{BLOBS}/file-{index}.bin'
			path = directory / blob
			if entry.get('blob') != blob or path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != entry.get('sha256'):
				raise HostError(f'{entry["path"]}: the backed-up copy is missing or modified')
	for index, entry in enumerate(manifest.get('certificates', [])):
		blob = f'{BLOBS}/cert-{index}.der'
		path = directory / blob
		if entry.get('blob') != blob or path.is_symlink() or not path.is_file() or \
				hashlib.sha1(path.read_bytes()).hexdigest() != entry.get('sha1'):
			raise HostError('the backed-up certificate is missing or modified')


def restore(host, directory):
	"""Remove only proven test fixtures and verify the scoped snapshot."""
	directory = pathlib.Path(directory)
	manifest = load(directory)
	validate_manifest(host, directory, manifest)
	record = directory / RESTORED
	if record.is_symlink() or record.exists() and not record.is_file():
		raise HostError(f'{record}: restore record is not a regular file')
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
	if not problems and not record.exists():
		stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
		with record.open('x', encoding='utf-8') as output:
			json.dump({'restored': stamp}, output, indent='\t')
			output.write('\n')
	return problems


def restore_file(host, directory, entry):
	path = entry['path']
	try:
		if entry['exists']:
			if not host.exists(path) or not host.regular(path) or host.fingerprint(path) != entry.get('fingerprint') or \
					digest(host.read(path)) != entry['sha256']:
				return [f'{path}: pre-existing state changed; left untouched']
			return []
		if not host.exists(path):
			return []
		ledger = owned_file_path(directory, path)
		if ledger.parent.is_symlink() or ledger.is_symlink() or not ledger.is_file() or not host.regular(path):
			return [f'{path}: no proof of test ownership; left untouched']
		proof = json.loads(ledger.read_text(encoding='utf-8'))
		if proof.get('path') != path or proof.get('fingerprint') != host.fingerprint(path) or \
				proof.get('sha256') != digest(host.read(path)):
			return [f'{path}: test ownership no longer matches; left untouched']
		host.remove_owned(path, proof)
		if entry.get('reload'):
			host.command(entry['reload'], privileged=True)
	except (HostError, OSError, ValueError) as error:
		return [f'{path}: {error}']
	return []


def restore_keychain(host, directory, manifest):
	expected = {entry['sha1'] for entry in manifest['certificates']}
	problems = []
	try:
		current = keychain_certificates(host)
		for sha1, der in current.items():
			if sha1 in expected:
				continue
			proof = directory / OWNED_CERTIFICATES / f'{sha1}.der'
			if proof.parent.is_symlink() or proof.is_symlink() or not proof.is_file() or proof.read_bytes() != der:
				problems.append(f'{KEYCHAIN}: certificate {sha1} has no test ownership proof; left untouched')
				continue
			host.command(['security', 'delete-certificate', '-Z', sha1, KEYCHAIN], privileged=True)
		for sha1 in expected - current.keys():
			problems.append(f'{KEYCHAIN}: pre-existing certificate {sha1} is missing; not reinstalled')
	except (HostError, OSError) as error:
		problems.append(str(error))
	return problems


def verify(host, directory, manifest=None):
	"""Compare the host against the manifest; an empty list means it is back."""
	manifest = manifest or load(directory)
	problems = []
	for entry in manifest['files']:
		path = entry['path']
		if host.exists(path) != entry['exists']:
			condition = 'missing' if entry['exists'] else 'still present'
			problems.append(f'{path}: {condition} after restore')
		elif entry['exists'] and not host.regular(path):
			problems.append(f'{path}: not a regular file after restore')
		elif entry['exists'] and digest(host.read(path)) != entry['sha256']:
			problems.append(f'{path}: content differs from the snapshot')
		elif entry['exists'] and host.fingerprint(path) != entry.get('fingerprint'):
			problems.append(f'{path}: identity, ownership, or mode differs from the snapshot')
	if manifest['system'] == 'Darwin':
		expected = {entry['sha1'] for entry in manifest['certificates']}
		current = set(keychain_certificates(host))
		if current != expected:
			problems.append(f'{KEYCHAIN}: testd root certificates differ from the snapshot')
		if expected:
			problems.append(f'{KEYCHAIN}: pre-existing trust settings were not captured; use the full-system snapshot')
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
		roots = directory / 'roots'
		if nrpt.is_symlink() or not nrpt.is_file() or roots.is_symlink() or not roots.is_dir():
			raise HostError('the Windows rule or root-store snapshot is incomplete')
		# The host script writes UTF-8, with a BOM on PowerShell 5.1.
		try:
			rules = json.loads(nrpt.read_text(encoding='utf-8-sig'))
		except (OSError, ValueError) as error:
			raise HostError(f'the Windows rule snapshot is unreadable: {error}') from error
		if not isinstance(rules, list) or any(not isinstance(rule, dict) or
				not isinstance(rule.get('Signature'), dict) or 'Namespace' not in rule['Signature'] for rule in rules):
			raise HostError('the Windows rule snapshot has an invalid shape')
		found += [f'NRPT rule for {rule["Signature"]["Namespace"]}' for rule in rules]
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
			mode = 0o600 if entry['path'].endswith('.owner') else 0o644
			contents = certificate.read_bytes() if is_certificate else SELF_TEST_RESOLVER
			fingerprint = host.create(entry['path'], contents, mode)
			record_owned_file(host, directory, entry['path'], fingerprint, digest(contents))
			if entry.get('reload'):
				host.command(entry['reload'], privileged=True)
		except (HostError, OSError, ValueError) as error:
			# Later steps cannot work either, and the caller still restores.
			return [str(error)]
	if host.system == 'Darwin':
		try:
			certificates = decode_pem(certificate.read_text(encoding='utf-8'))
			if len(certificates) != 1:
				raise HostError('the fixture must contain exactly one certificate')
			record_owned_certificate(directory, certificates[0])
			host.command(['security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', KEYCHAIN,
				str(certificate)], privileged=True)
		except (HostError, OSError, ValueError) as error:
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
	return []


def self_test_in_workdir(host, workdir):
	"""Keep the snapshot available even when a fixture or restore fails."""
	directory = workdir / 'system-before'
	print(f'host: {host.system}, snapshot: {directory}', flush=True)
	snapshot(host, directory, self_test_artifacts(host))
	present = occupied(directory)
	if present:
		return [f'{item} is already installed; the self-test needs a host without testd integration'
			for item in present]
	problems = []
	try:
		problems = install_fixture(host, directory, workdir)
		if not problems:
			problems = fixture_present(host, directory)
	finally:
		print('restoring the self-test snapshot', flush=True)
		restore_problems = restore(host, directory)
		for problem in restore_problems:
			print(f'fail     restore: {problem}; snapshot: {directory}', flush=True)
	return list(dict.fromkeys(problems + restore_problems))


def self_test(system=None, tld=SELF_TEST_TLD, workdir=None):
	"""Snapshot, install a fixture, restore, verify on a host with no integration.

	This is the check CI runs on disposable runners: it exercises the real
	privileged writes and stores, which unit tests replace with an in-memory host.
	It refuses to run where testd integration already exists, because the fixture
	would replace a live root or route for the duration of the round trip.
	"""
	if workdir is None:
		raise HostError('the self-test requires a new persisted work directory')
	system = system or platform.system()
	if system == 'Windows':
		raise HostError('the Windows self-test is blocked until NRPT ownership can be proven')
	host = Host(system, tld)
	workdir = pathlib.Path(workdir)
	workdir.mkdir(parents=True, mode=0o700, exist_ok=False)
	return self_test_in_workdir(host, workdir)


def temporary_path(path):
	roots = [pathlib.Path(tempfile.gettempdir())]
	roots.extend(pathlib.Path(value) for name in ('TMPDIR', 'TMP', 'TEMP') if (value := os.environ.get(name)))
	if os.name != 'nt':
		roots.extend(pathlib.Path(value) for value in ('/tmp', '/run', '/dev/shm'))
	return any(path.expanduser().resolve().is_relative_to(root.resolve()) for root in roots)


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--self-test', action='store_true',
		help='snapshot, fixture, restore, and verify the real integration paths')
	parser.add_argument('--workdir', type=pathlib.Path,
		help='new persisted directory in which to retain the self-test snapshot and fixtures')
	args = parser.parse_args(argv)
	if not args.self_test:
		parser.error('nothing to do; pass --self-test')
	if args.workdir is None or temporary_path(args.workdir):
		parser.error('--self-test requires a new persisted --workdir outside temporary directories')
	if args.workdir.exists() or args.workdir.is_symlink():
		parser.error(f'work directory already exists: {args.workdir}')
	if not sys.stdin.isatty():
		parser.error('the system self-test requires an interactive terminal')
	try:
		answer = input('Confirm a disposable host with a persisted full-system snapshot; type yes: ')
	except (EOFError, KeyboardInterrupt):
		parser.error('the system self-test was not confirmed')
	if answer.strip().lower() != 'yes':
		parser.error('the system self-test was not confirmed')
	try:
		problems = self_test(workdir=args.workdir)
	except HostError as error:
		print(f'fail     {error}', flush=True)
		return 1
	for problem in problems:
		print(f'fail     {problem}', flush=True)
	if problems:
		return 1
	print('ok       scoped fixture state was restored and verified', flush=True)
	print('blocked  shared trust-store output and hooks need comparison with the full-system snapshot', flush=True)
	return 2


if __name__ == '__main__':
	sys.exit(main())
