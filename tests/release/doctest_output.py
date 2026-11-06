"""Retain output from doctest executables without changing rustdoc's result handling."""

import codecs
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import tomllib
import uuid

LOG_DIRECTORY = '_TESTD_DOCTEST_OUTPUT_DIR'
ENCODING = 'utf-8'


def cargo_config_paths(project, env):
	project = pathlib.Path(project).resolve()
	paths = []
	for parent in (project, *project.parents):
		paths.extend(parent / '.cargo' / name for name in ('config', 'config.toml'))
	home = env.get('USERPROFILE') if os.name == 'nt' else env.get('HOME')
	cargo_home = pathlib.Path(
		env.get('CARGO_HOME') or pathlib.Path(home or pathlib.Path.home()) / '.cargo'
	).expanduser()
	paths.extend(cargo_home / name for name in ('config', 'config.toml'))
	return list(dict.fromkeys(paths))


def configured_flags_reason(project, env, inspect_flags):
	if env.get('CARGO_BUILD_TARGET'):
		return 'CARGO_BUILD_TARGET may select a test runner; preserve it rather than replace it'
	for name in env:
		upper = name.upper()
		if upper.startswith('CARGO_TARGET_') and upper.endswith('_RUNNER'):
			return f'{name} defines a test runner; preserve it rather than replace it'
		if inspect_flags and (upper == 'CARGO_BUILD_RUSTDOCFLAGS' or
				upper.startswith('CARGO_TARGET_') and upper.endswith('_RUSTDOCFLAGS')):
			return f'{name} may define rustdoc flags; preserve it rather than override it'
	for path in cargo_config_paths(project, env):
		if not path.is_file():
			continue
		try:
			config = tomllib.loads(path.read_text(encoding=ENCODING))
		except (OSError, ValueError) as error:
			return f'could not inspect Cargo configuration {path}: {error}'
		build = config.get('build')
		if isinstance(build, dict):
			if 'target' in build:
				return f'{path} defines build.target; preserve its test runner rather than replace it'
			if inspect_flags and 'rustdocflags' in build:
				return f'{path} defines build.rustdocflags; preserve it rather than override it'
		targets = config.get('target')
		if isinstance(targets, dict):
			for value in targets.values():
				if isinstance(value, dict) and 'runner' in value:
					return f'{path} defines a target runner; preserve it rather than replace it'
				if inspect_flags and isinstance(value, dict) and 'rustdocflags' in value:
					return f'{path} defines target rustdocflags; preserve them rather than override them'
	return None


def existing_flags(project, env):
	has_environment_flags = 'CARGO_ENCODED_RUSTDOCFLAGS' in env or 'RUSTDOCFLAGS' in env
	reason = configured_flags_reason(project, env, inspect_flags=not has_environment_flags)
	if reason:
		return [], reason
	if 'CARGO_ENCODED_RUSTDOCFLAGS' in env:
		flags = env['CARGO_ENCODED_RUSTDOCFLAGS'].split('\x1f') if env['CARGO_ENCODED_RUSTDOCFLAGS'] else []
	elif 'RUSTDOCFLAGS' in env:
		flags = env['RUSTDOCFLAGS'].split()
	else:
		flags = []
	if any(flag in ('--test-runtool', '--test-runtool-arg') or flag.startswith('--test-runtool=') or
			flag.startswith('--test-runtool-arg=') for flag in flags):
		return [], 'an existing rustdoc test runtool cannot be replaced without changing test behavior'
	return flags, None


def prepare(project, report, environment):
	"""Enable a per-doctest logger only when Cargo's existing flags can be preserved."""
	env = dict(environment)
	flags, reason = existing_flags(project, env)
	if reason:
		return env, None, reason
	executable = sys.executable
	wrapper = str(pathlib.Path(__file__).resolve())
	if not executable or any('\x1f' in value for value in (executable, wrapper)):
		return env, None, 'the Python or logger path cannot be encoded for Cargo'
	directory = pathlib.Path(report) / 'doctest-output'
	directory.mkdir(mode=0o700, exist_ok=False)
	env[LOG_DIRECTORY] = str(directory.resolve())
	env['CARGO_ENCODED_RUSTDOCFLAGS'] = '\x1f'.join([
		*flags, '--test-runtool', executable, '--test-runtool-arg', wrapper,
	])
	return env, directory, None


def replay(directory):
	"""Place each raw doctest stream in the shared transcript after rustdoc exits."""
	for case in sorted(pathlib.Path(directory).iterdir()):
		if case.is_symlink() or not case.is_dir():
			raise RuntimeError(f'unexpected doctest output entry: {case}')
		print(f'\n----- BEGIN DOCTEST OUTPUT {case.name} -----', flush=True)
		for name in ('started.json', 'stdout.log', 'stderr.log', 'result.json'):
			path = case / name
			print(f'[{name}]', flush=True)
			if path.is_symlink():
				raise RuntimeError(f'doctest output is a symlink: {path}')
			if not path.is_file():
				print('(not available; the doctest may have been interrupted)', flush=True)
				continue
			decoder = codecs.getincrementaldecoder(ENCODING)(errors='replace')
			with path.open('rb') as source:
				while chunk := source.read(64 * 1024):
					sys.stdout.write(decoder.decode(chunk))
				sys.stdout.write(decoder.decode(b'', final=True))
			print('', flush=True)
		print(f'----- END DOCTEST OUTPUT {case.name} -----', flush=True)


def transfer(pipe, terminal, log, process, errors):
	try:
		while chunk := pipe.read1(64 * 1024):
			log.write(chunk)
			log.flush()
			terminal.write(chunk)
			terminal.flush()
	except Exception as error:
		errors.append(f'{type(error).__name__}: {error}')
		try:
			process.terminate()
		except ProcessLookupError:
			pass
		except OSError as stop_error:
			errors.append(f'could not stop doctest: {stop_error}')
	finally:
		pipe.close()


def capture(command, directory):
	case = pathlib.Path(directory) / f'{time.time_ns():020d}-{uuid.uuid4().hex}'
	case.mkdir(mode=0o700, exist_ok=False)
	(case / 'started.json').write_text(json.dumps({'command': command}) + '\n', encoding=ENCODING)
	errors = []
	with (case / 'stdout.log').open('xb') as stdout_log, (case / 'stderr.log').open('xb') as stderr_log:
		try:
			process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		except OSError as error:
			(case / 'result.json').write_text(json.dumps({'error': str(error)}) + '\n', encoding=ENCODING)
			print(f'could not start doctest: {error}', file=sys.stderr, flush=True)
			return 1
		threads = [
			threading.Thread(target=transfer, args=(process.stdout, sys.stdout.buffer, stdout_log, process, errors)),
			threading.Thread(target=transfer, args=(process.stderr, sys.stderr.buffer, stderr_log, process, errors)),
		]
		for thread in threads:
			thread.start()
		status = process.wait()
		for thread in threads:
			thread.join()
	result = {'exit': status, 'errors': errors}
	(case / 'result.json').write_text(json.dumps(result) + '\n', encoding=ENCODING)
	if errors:
		print('could not retain or forward doctest output: ' + '; '.join(errors), file=sys.stderr, flush=True)
		return 1
	if status < 0 and os.name != 'nt':
		os.kill(os.getpid(), -status)
	return status


def main(argv=None):
	command = sys.argv[1:] if argv is None else argv
	directory = os.environ.get(LOG_DIRECTORY)
	if not command or not directory:
		print('doctest output capture requires an executable and a report directory', file=sys.stderr)
		return 2
	return capture(command, directory)


if __name__ == '__main__':
	sys.exit(main())
