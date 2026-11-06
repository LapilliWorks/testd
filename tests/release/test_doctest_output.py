import contextlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'tests/release/doctest_output.py'
SPEC = importlib.util.spec_from_file_location('testd_doctest_output', SCRIPT)
doctests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(doctests)


class DoctestOutputTests(unittest.TestCase):
	def environment(self, root):
		env = dict(os.environ, HOME=str(root / 'home'), USERPROFILE=str(root / 'home'), CARGO_HOME=str(root / 'cargo'))
		env.setdefault('RUSTUP_HOME', str(pathlib.Path.home() / '.rustup'))
		for name in list(env):
			upper = name.upper()
			if upper in ('CARGO_ENCODED_RUSTDOCFLAGS', 'RUSTDOCFLAGS', 'CARGO_BUILD_RUSTDOCFLAGS',
					'CARGO_BUILD_TARGET') or upper.startswith('CARGO_TARGET_') and \
					upper.endswith(('_RUSTDOCFLAGS', '_RUNNER')):
				del env[name]
		return env

	def test_wrapper_retains_and_forwards_both_streams_and_exit_status(self):
		for exit_code in (0, 7):
			with self.subTest(exit=exit_code), tempfile.TemporaryDirectory() as temporary:
				root = pathlib.Path(temporary).resolve()
				logs = root / 'logs'
				logs.mkdir()
				env = {**os.environ, doctests.LOG_DIRECTORY: str(logs)}
				code = f"import os,sys; os.write(1,b'out-\\xff'); os.write(2,b'err-\\xfe'); sys.exit({exit_code})"
				result = subprocess.run([sys.executable, str(SCRIPT), sys.executable, '-c', code], env=env,
					capture_output=True, timeout=15)
				self.assertEqual(result.returncode, exit_code, result.stderr)
				self.assertEqual(result.stdout, b'out-\xff')
				self.assertEqual(result.stderr, b'err-\xfe')
				case, = logs.iterdir()
				self.assertEqual((case / 'stdout.log').read_bytes(), result.stdout)
				self.assertEqual((case / 'stderr.log').read_bytes(), result.stderr)
				self.assertEqual(json.loads((case / 'result.json').read_text())['exit'], exit_code)
				self.assertEqual(json.loads((case / 'started.json').read_text())['command'][0], sys.executable)

	def test_an_abnormal_doctest_exit_keeps_its_output_and_status(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			logs = root / 'logs'
			logs.mkdir()
			env = {**os.environ, doctests.LOG_DIRECTORY: str(logs)}
			if os.name == 'nt':
				code = "import os,sys; os.write(2,b'before-exit'); sys.exit(7)"
				expected = 7
			else:
				code = "import os,signal; os.write(2,b'before-exit'); os.kill(os.getpid(),signal.SIGTERM)"
				expected = -signal.SIGTERM
			result = subprocess.run([sys.executable, str(SCRIPT), sys.executable, '-c', code], env=env,
				capture_output=True, timeout=15)
			self.assertEqual(result.returncode, expected)
			case, = logs.iterdir()
			self.assertEqual((case / 'stderr.log').read_bytes(), b'before-exit')
			self.assertEqual(json.loads((case / 'result.json').read_text())['exit'], expected)

	def test_large_concurrent_streams_are_not_truncated(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			logs = root / 'logs'
			logs.mkdir()
			env = {**os.environ, doctests.LOG_DIRECTORY: str(logs)}
			code = ("import sys; sys.stdout.buffer.write(b'a'*262144); sys.stdout.buffer.flush(); "
				"sys.stderr.buffer.write(b'b'*262144); sys.stderr.buffer.flush()")
			result = subprocess.run([sys.executable, str(SCRIPT), sys.executable, '-c', code], env=env,
				capture_output=True, timeout=30)
			self.assertEqual(result.returncode, 0, result.stderr[-1000:])
			case, = logs.iterdir()
			self.assertEqual(result.stdout, b'a' * 262144)
			self.assertEqual(result.stderr, b'b' * 262144)
			self.assertEqual((case / 'stdout.log').read_bytes(), result.stdout)
			self.assertEqual((case / 'stderr.log').read_bytes(), result.stderr)

	def test_output_is_flushed_while_a_doctest_is_still_running(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			logs = root / 'logs'
			logs.mkdir()
			ack = root / 'ack'
			env = {**os.environ, doctests.LOG_DIRECTORY: str(logs)}
			code = ("import os,pathlib,sys,time; os.write(1,b'ready'); "
				"p=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+5; "
				"exec('while not p.exists() and time.monotonic()<deadline: time.sleep(0.01)'); "
				"sys.exit(0 if p.exists() else 1)")
			process = subprocess.Popen([sys.executable, str(SCRIPT), sys.executable, '-c', code, str(ack)],
				env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			try:
				self.assertEqual(process.stdout.read(5), b'ready')
				case, = logs.iterdir()
				self.assertEqual((case / 'stdout.log').read_bytes(), b'ready')
				ack.touch()
				_, errors = process.communicate(timeout=10)
				self.assertEqual(process.returncode, 0, errors)
			finally:
				if process.poll() is None:
					process.kill()
					process.wait(timeout=5)

	def test_concurrent_doctests_have_distinct_logs(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			logs = root / 'logs'
			logs.mkdir()
			env = {**os.environ, doctests.LOG_DIRECTORY: str(logs)}
			processes = [subprocess.Popen([sys.executable, str(SCRIPT), sys.executable, '-c',
				f"import time; print('case-{index}'); time.sleep(0.1)"], env=env,
				stdout=subprocess.PIPE, stderr=subprocess.PIPE) for index in range(3)]
			try:
				for process in processes:
					_, errors = process.communicate(timeout=15)
					self.assertEqual(process.returncode, 0, errors)
			finally:
				for process in processes:
					if process.poll() is None:
						process.kill()
						process.wait(timeout=5)
			cases = list(logs.iterdir())
			self.assertEqual(len(cases), 3)
			self.assertEqual({(case / 'stdout.log').read_text().strip() for case in cases},
				{'case-0', 'case-1', 'case-2'})

	def test_prepare_preserves_environment_flags_and_encodes_paths(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			report = root / 'report with spaces'
			report.mkdir()
			env = self.environment(root)
			env['RUSTDOCFLAGS'] = '--cfg example --cfg second'
			prepared, directory, reason = doctests.prepare(root, report, env)
			self.assertIsNone(reason)
			self.assertEqual(directory, report / 'doctest-output')
			flags = prepared['CARGO_ENCODED_RUSTDOCFLAGS'].split('\x1f')
			self.assertEqual(flags[:4], ['--cfg', 'example', '--cfg', 'second'])
			self.assertEqual(flags[-4:], ['--test-runtool', sys.executable, '--test-runtool-arg', str(SCRIPT)])
			self.assertEqual(prepared[doctests.LOG_DIRECTORY], str(directory))
			self.assertNotIn(doctests.LOG_DIRECTORY, env)

	def test_encoded_rustdoc_flags_keep_arguments_with_spaces(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			report = root / 'report'
			report.mkdir()
			env = self.environment(root)
			env['CARGO_ENCODED_RUSTDOCFLAGS'] = '--html-in-header\x1fheader with spaces.html'
			env['RUSTDOCFLAGS'] = '--cfg ignored-by-cargo'
			prepared, _, reason = doctests.prepare(root, report, env)
			self.assertIsNone(reason)
			self.assertEqual(prepared['CARGO_ENCODED_RUSTDOCFLAGS'].split('\x1f')[:2],
				['--html-in-header', 'header with spaces.html'])
			self.assertEqual(prepared['RUSTDOCFLAGS'], env['RUSTDOCFLAGS'])

	def test_prepare_refuses_to_replace_existing_doctest_evidence(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			report = root / 'report'
			directory = report / 'doctest-output'
			directory.mkdir(parents=True)
			marker = directory / 'existing'
			marker.write_text('keep', encoding='utf-8')
			with self.assertRaises(FileExistsError):
				doctests.prepare(root, report, self.environment(root))
			self.assertEqual(marker.read_text(encoding='utf-8'), 'keep')

	def test_existing_configured_flags_and_runtools_are_never_overridden(self):
		for kind in ('build-config', 'target-config', 'target-env', 'custom-runtool', 'bad-config',
				'build-target', 'build-target-env', 'target-runner', 'target-runner-env'):
			with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
				root = pathlib.Path(temporary).resolve()
				report = root / 'report'
				report.mkdir()
				env = self.environment(root)
				config = root / '.cargo/config.toml'
				if kind in ('build-config', 'target-config', 'bad-config', 'build-target', 'target-runner'):
					config.parent.mkdir()
					text = {'build-config': '[build]\nrustdocflags = ["--cfg", "custom"]\n',
						'target-config': '[target.example]\nrustdocflags = ["--cfg", "custom"]\n',
						'bad-config': '[invalid', 'build-target': '[build]\ntarget = "example"\n',
						'target-runner': '[target.example]\nrunner = "custom"\n'}[kind]
					config.write_text(text, encoding='utf-8')
				if kind == 'target-env':
					env['CARGO_TARGET_EXAMPLE_RUSTDOCFLAGS'] = '--cfg custom'
				if kind == 'build-target-env':
					env['CARGO_BUILD_TARGET'] = 'another-target'
				if kind == 'target-runner-env':
					env['CARGO_TARGET_EXAMPLE_RUNNER'] = 'custom'
				if kind == 'custom-runtool':
					env['CARGO_ENCODED_RUSTDOCFLAGS'] = '--test-runtool\x1fcustom'
				prepared, directory, reason = doctests.prepare(root, report, env)
				self.assertIsNotNone(reason)
				self.assertIsNone(directory)
				self.assertEqual(prepared, env)
				self.assertFalse((report / 'doctest-output').exists())

	def test_environment_flags_already_take_precedence_over_cargo_config(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			(root / '.cargo').mkdir()
			(root / '.cargo/config.toml').write_text('[build]\nrustdocflags = ["--cfg", "ignored"]\n')
			report = root / 'report'
			report.mkdir()
			env = self.environment(root)
			env['RUSTDOCFLAGS'] = '--cfg chosen'
			prepared, directory, reason = doctests.prepare(root, report, env)
			self.assertIsNone(reason)
			self.assertIsNotNone(directory)
			self.assertEqual(prepared['CARGO_ENCODED_RUSTDOCFLAGS'].split('\x1f')[:2], ['--cfg', 'chosen'])

	def test_replay_labels_streams_and_keeps_raw_bytes(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			case = root / 'case'
			case.mkdir()
			(case / 'started.json').write_text('{}\n', encoding='utf-8')
			(case / 'stdout.log').write_bytes(b'out\xff')
			(case / 'stderr.log').write_bytes(b'error')
			output = io.StringIO()
			with contextlib.redirect_stdout(output):
				doctests.replay(root)
			for value in ('BEGIN DOCTEST OUTPUT case', '[stdout.log]', 'out\ufffd', '[stderr.log]',
				'error', 'not available', 'END DOCTEST OUTPUT case'):
				self.assertIn(value, output.getvalue())
			self.assertEqual((case / 'stdout.log').read_bytes(), b'out\xff')

	@unittest.skipUnless(shutil.which('rustdoc'), 'rustdoc is not installed')
	def test_real_rustdoc_retains_passing_ignored_and_should_panic_output(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary).resolve()
			source = root / 'examples.rs'
			source.write_text('/// ```\n/// println!("ordinary-output");\n/// ```\n'
				'/// ```ignore\n/// eprintln!("ignored-output");\n/// ```\n'
				'/// ```should_panic\n/// panic!("expected-panic-output");\n/// ```\n'
				'pub fn example() {}\n', encoding='utf-8')
			report = root / 'report'
			report.mkdir()
			env, directory, reason = doctests.prepare(root, report, self.environment(root))
			self.assertIsNone(reason)
			env['RUSTUP_DIST_SERVER'] = (root / 'no-distribution').as_uri()
			env['RUSTUP_UPDATE_ROOT'] = (root / 'no-updates').as_uri()
			flags = env['CARGO_ENCODED_RUSTDOCFLAGS'].split('\x1f')
			command = ['rustdoc', '--test', str(source), *flags, '--test-args=--include-ignored --show-output']
			result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
			self.assertEqual(result.returncode, 0, result.stderr)
			cases = list(directory.iterdir())
			self.assertEqual(len(cases), 3)
			stdout = b''.join((case / 'stdout.log').read_bytes() for case in cases)
			stderr = b''.join((case / 'stderr.log').read_bytes() for case in cases)
			self.assertIn(b'ordinary-output', stdout)
			self.assertIn(b'ignored-output', stderr)
			self.assertIn(b'expected-panic-output', stderr)


if __name__ == '__main__':
	unittest.main()
