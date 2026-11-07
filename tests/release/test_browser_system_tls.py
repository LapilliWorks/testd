import importlib.util
import pathlib
import socket
import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

PATH = pathlib.Path(__file__).with_name('browser_system_tls.py')
spec = importlib.util.spec_from_file_location('browser_system_tls', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SystemTlsTests(unittest.TestCase):
	def test_resolver_refuses_any_non_loopback_address(self):
		loopback = (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 8443))
		external = (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.0.2.1', 8443))
		with patch.object(module.socket, 'getaddrinfo', return_value=[loopback, external]):
			with self.assertRaisesRegex(RuntimeError, 'non-loopback'):
				module.loopback_addresses(module.HOST, 8443)

	def test_connects_only_to_the_verified_os_address_and_checks_the_hostname(self):
		connection = Mock()
		connection.__enter__ = Mock(return_value=connection)
		connection.__exit__ = Mock(return_value=False)
		secure = Mock()
		secure.__enter__ = Mock(return_value=secure)
		secure.__exit__ = Mock(return_value=False)
		secure.getpeercert.return_value = b'synthetic leaf'
		context = Mock()
		context.wrap_socket.return_value = secure
		entry = (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 8443))
		with patch.object(module.socket, 'socket', return_value=connection):
			fingerprint = module.verify_connection(context, [entry], module.HOST)
		connection.connect.assert_called_once_with(('127.0.0.1', 8443))
		context.wrap_socket.assert_called_once_with(connection, server_hostname=module.HOST)
		self.assertEqual(fingerprint, module.hashlib.sha256(b'synthetic leaf').hexdigest())

	def test_requires_unmodified_default_certificate_and_hostname_verification(self):
		for context in (SimpleNamespace(check_hostname=False, verify_mode=ssl.CERT_REQUIRED),
				SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_NONE)):
			with self.subTest(context=context), patch.object(module.ssl, 'create_default_context', return_value=context):
				with self.assertRaisesRegex(RuntimeError, 'not verifying'):
					module.verify(8443)

	def test_returns_os_resolution_and_verified_leaf_evidence(self):
		context = SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
		entries = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 8443))]
		with patch.object(module.ssl, 'create_default_context', return_value=context), \
				patch.object(module, 'loopback_addresses', return_value=entries), \
				patch.object(module, 'verify_connection', return_value='a' * 64) as verify:
			result = module.verify(8443)
		verify.assert_called_once_with(context, entries, module.HOST)
		self.assertEqual(result['addresses'], ['127.0.0.1'])
		self.assertEqual(result['leafSha256'], 'a' * 64)


if __name__ == '__main__':
	unittest.main()
