import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('service_fixtures', ROOT / 'tests/release/service.py')
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class FakeRun:
	def __init__(self, output, loaded='not-found'):
		self.output = output
		self.loaded = loaded
		self.metadata = {}
		self.commands = []
		self.records = []

	def command(self, name, command, **options):
		self.commands.append((name, command, options))
		if name == 'service-preflight':
			return self.loaded
		if name == 'service-init':
			config = pathlib.Path(options['env']['HOME']) / '.config/testd/config.toml'
			config.parent.mkdir(parents=True)
			config.write_text('[host]\n', encoding='utf-8')
		return ''

	def record(self, name, status, detail):
		self.records.append((name, status, detail))


@unittest.skipIf(os.name != 'posix', 'not applicable: Linux service fixtures require Unix file operations')
class ServiceSafetyTests(unittest.TestCase):
	def fixture(self, root):
		root = pathlib.Path(root)
		output = root / 'report'
		output.mkdir()
		user = root / 'user'
		user.mkdir()
		home = output / 'service-home'
		home.mkdir()
		provider = home / 'fake-provider'
		provider.write_text('fixture', encoding='utf-8')
		return FakeRun(output), user, home, provider

	def test_owned_unit_creation_is_exclusive_and_removal_checks_identity_and_bytes(self):
		for change in ('unchanged', 'changed', 'replaced', 'symlink'):
			with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
				root = pathlib.Path(temporary)
				unit = root / 'fixture.service'
				proof = service.create_owned_file(unit, b'owned unit')
				with self.assertRaises(FileExistsError):
					service.create_owned_file(unit, b'cannot overwrite')
				if change == 'changed':
					unit.write_bytes(b'other contents')
				elif change == 'replaced':
					unit.unlink()
					unit.write_bytes(b'owned unit')
				elif change == 'symlink':
					unit.unlink()
					target = root / 'unrelated'
					target.write_bytes(b'preserve')
					unit.symlink_to(target)
				if change == 'unchanged':
					service.remove_owned_file(unit, proof)
					self.assertFalse(unit.exists())
				else:
					with self.assertRaises((RuntimeError, OSError)):
						service.remove_owned_file(unit, proof)
					self.assertTrue(unit.exists())
					if change == 'symlink':
						self.assertEqual(target.read_bytes(), b'preserve')

	def test_directory_cleanup_removes_only_created_empty_directories(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			created = service.prepare_directories(root)
			self.assertEqual(len(created), 3)
			self.assertEqual(service.prune_directories(created), [])
			self.assertFalse((root / '.config').exists())
			created = service.prepare_directories(root)
			keep = root / '.config/systemd/user/other.service'
			keep.write_text('preserve', encoding='utf-8')
			self.assertTrue(service.prune_directories(created))
			self.assertEqual(keep.read_text(encoding='utf-8'), 'preserve')

	def test_linked_service_directory_is_never_followed(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			user = root / 'user'
			user.mkdir()
			target = root / 'other'
			target.mkdir()
			(target / 'keep').write_text('existing data', encoding='utf-8')
			(user / '.config').symlink_to(target, target_is_directory=True)
			with self.assertRaisesRegex(RuntimeError, 'symlink'):
				service.prepare_directories(user)
			self.assertEqual((target / 'keep').read_text(encoding='utf-8'), 'existing data')
			self.assertEqual([path.name for path in target.iterdir()], ['keep'])

	def test_unit_clears_inherited_environment_and_selects_fake_provider(self):
		text = service.service_unit(pathlib.Path('/candidate cli'), pathlib.Path('/fixture home'),
			pathlib.Path('/fixture home/fake-provider'))
		self.assertIn('ExecStart=/usr/bin/env -i ', text)
		self.assertIn('"HOME=/fixture home"', text)
		self.assertIn('"TESTD_TLD=test"', text)
		self.assertIn('"TESTD_TUNNEL=/fixture home/fake-provider"', text)
		self.assertIn('"/candidate cli" host', text)
		for unsafe in ('/bad%path', '/bad$path', '/bad"path', '/bad\\path', '/bad\npath'):
			with self.subTest(path=unsafe), self.assertRaisesRegex(RuntimeError, 'cannot be safely represented'):
				service.systemd_argument(unsafe)

	def test_init_strips_all_inherited_testd_settings_and_installs_a_fake_provider(self):
		with tempfile.TemporaryDirectory() as temporary:
			root = pathlib.Path(temporary)
			run = FakeRun(root)
			with patch.dict(os.environ, {'TESTD_YES': '1', 'TESTD_TOKEN': 'secret', 'TESTD_TUNNEL': 'real-provider'}):
				home, ports, provider = service.service_home(run, pathlib.Path('/candidate'))
			env = run.commands[0][2]['env']
			self.assertFalse(any(key.startswith('TESTD_') for key in env))
			self.assertEqual(env['HOME'], str(home))
			self.assertEqual(len(ports), 3)
			self.assertTrue(provider.is_file())
			self.assertIn('{"Web":{}}', provider.read_text(encoding='utf-8'))

	def test_existing_loaded_unit_or_file_is_never_overwritten(self):
		for conflict in ('loaded', 'file'):
			with self.subTest(conflict=conflict), tempfile.TemporaryDirectory() as temporary:
				run, user, home, provider = self.fixture(temporary)
				name = 'dev.testd.releasecheck.' + 'a' * 32 + '.service'
				unit = user / '.config/systemd/user' / name
				if conflict == 'loaded':
					run.loaded = 'loaded'
				else:
					unit.parent.mkdir(parents=True)
					unit.write_text('preserve', encoding='utf-8')
				with patch.object(service.socket, 'socket'), patch.object(service.pathlib.Path, 'home', return_value=user), \
						patch.object(service, 'service_home', return_value=(home, [1, 2, 3], provider)), \
						patch.object(service.uuid, 'uuid4', return_value=type('Id', (), {'hex': 'a' * 32})()):
					with self.assertRaises((RuntimeError, FileExistsError)):
						service.run_service(run, pathlib.Path('/candidate'), 'Linux')
				self.assertNotIn('service-start', [item[0] for item in run.commands])
				if conflict == 'file':
					self.assertEqual(unit.read_text(encoding='utf-8'), 'preserve')
				else:
					self.assertFalse(unit.parent.exists())

	def test_completed_fixture_removes_its_unit_and_preserves_existing_units(self):
		with tempfile.TemporaryDirectory() as temporary:
			run, user, home, provider = self.fixture(temporary)
			other = user / '.config/systemd/user/keep.service'
			other.parent.mkdir(parents=True)
			other.write_text('preserve', encoding='utf-8')
			with patch.object(service.socket, 'socket'), patch.object(service.pathlib.Path, 'home', return_value=user), \
					patch.object(service, 'service_home', return_value=(home, [1, 2, 3], provider)), \
					patch.object(service, 'supervise') as supervise, patch.object(service, 'wait_stopped') as stopped:
				service.run_service(run, pathlib.Path('/candidate'), 'Linux')
			supervise.assert_called_once()
			stopped.assert_called_once_with(1)
			self.assertEqual([path.name for path in other.parent.iterdir()], ['keep.service'])
			self.assertEqual(other.read_text(encoding='utf-8'), 'preserve')
			self.assertEqual([item[0] for item in run.commands],
				['service-preflight', 'service-reload', 'service-start', 'service-stop', 'service-reload'])
			self.assertTrue(any(name == 'service-stop-check' and status == 'pass' for name, status, _ in run.records))

	def test_replaced_unit_is_not_stopped_or_removed(self):
		with tempfile.TemporaryDirectory() as temporary:
			run, user, home, provider = self.fixture(temporary)
			other = user / '.config/systemd/user/keep.service'
			other.parent.mkdir(parents=True)
			other.write_text('preserve', encoding='utf-8')
			def replace(run, name, unit, proof, *args):
				unit.unlink()
				unit.write_text('replacement', encoding='utf-8')
			with patch.object(service.socket, 'socket'), patch.object(service.pathlib.Path, 'home', return_value=user), \
					patch.object(service, 'service_home', return_value=(home, [1, 2, 3], provider)), \
					patch.object(service, 'supervise', side_effect=replace):
				with self.assertRaisesRegex(RuntimeError, 'identity changed'):
					service.run_service(run, pathlib.Path('/candidate'), 'Linux')
			self.assertNotIn('service-stop', [item[0] for item in run.commands])
			units = sorted(path.read_text(encoding='utf-8') for path in other.parent.iterdir())
			self.assertEqual(units, ['preserve', 'replacement'])

	def test_supervision_signals_only_the_validated_manager_unit(self):
		with tempfile.TemporaryDirectory() as temporary:
			unit = pathlib.Path(temporary) / 'fixture.service'
			proof = service.create_owned_file(unit, b'fixture')
			run = FakeRun(pathlib.Path(temporary))
			with patch.object(service, 'wait_dashboard'), patch.object(service.time, 'sleep'), \
					patch.object(service, 'pid', side_effect=[100, 101]), patch.object(os, 'kill') as kill:
				service.supervise(run, 'fixture.service', unit, proof, 1, 2, pathlib.Path('/fixture-root'))
			kill.assert_not_called()
			commands = {name: command for name, command, _ in run.commands}
			self.assertEqual(commands['service-kill'], ['systemctl', '--user', 'kill', '--kill-whom=main',
				'--signal=SIGKILL', 'fixture.service'])

	def test_macos_service_checks_block_before_touching_the_host(self):
		with tempfile.TemporaryDirectory() as temporary:
			run = FakeRun(pathlib.Path(temporary))
			with patch.object(service.socket, 'socket') as listener:
				service.run_service(run, pathlib.Path('/candidate'), 'Darwin')
			listener.assert_not_called()
			self.assertTrue(run.metadata['incomplete'])
			self.assertEqual(run.records[0][1], 'skip')


if __name__ == '__main__':
	unittest.main()
