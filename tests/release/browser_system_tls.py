"""Verify fixture HTTPS with Python's unmodified default platform trust store."""

import argparse
import hashlib
import ipaddress
import json
import pathlib
import socket
import ssl
import sys
import time

HOST = 'app.releasecheck.test'


def loopback_addresses(host, port):
	entries = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
	if not entries:
		raise RuntimeError('the OS resolver returned no addresses')
	for _, _, _, _, address in entries:
		if not ipaddress.ip_address(address[0].split('%', 1)[0]).is_loopback:
			raise RuntimeError(f'the OS resolver returned a non-loopback address: {address[0]}')
	return entries


def verify_connection(context, entries, host):
	last_error = None
	for family, kind, protocol, _, address in entries:
		try:
			with socket.socket(family, kind, protocol) as connection:
				connection.settimeout(5)
				connection.connect(address)
				with context.wrap_socket(connection, server_hostname=host) as secure:
					certificate = secure.getpeercert(binary_form=True)
					if not certificate:
						raise RuntimeError('the server did not present a leaf certificate')
					return hashlib.sha256(certificate).hexdigest()
		except (OSError, ssl.SSLError) as error:
			last_error = error
	if last_error is None:
		raise RuntimeError('the OS resolver returned no usable addresses')
	raise last_error


def verify(port, timeout=30):
	if not 1 <= port <= 65535:
		raise ValueError('invalid fixture edge port')
	context = ssl.create_default_context()
	if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
		raise RuntimeError('the platform TLS context is not verifying certificates and hostnames')
	deadline = time.monotonic() + timeout
	while True:
		try:
			entries = loopback_addresses(HOST, port)
			fingerprint = verify_connection(context, entries, HOST)
			return {'host': HOST, 'port': port, 'addresses': sorted({entry[4][0] for entry in entries}),
				'leafSha256': fingerprint, 'openssl': ssl.OPENSSL_VERSION}
		except (OSError, ssl.SSLError) as error:
			if time.monotonic() >= deadline:
				raise RuntimeError(f'OS DNS or TLS trust was not ready: {error}') from error
			time.sleep(0.25)


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--port', required=True, type=int)
	parser.add_argument('--output', required=True, type=pathlib.Path)
	args = parser.parse_args(argv)
	result = verify(args.port)
	with args.output.open('x', encoding='utf-8') as output:
		json.dump(result, output, indent='\t')
		output.write('\n')
	print(f'OS DNS and default TLS trust verified; evidence: {args.output}')


if __name__ == '__main__':
	try:
		main()
	except Exception as error:
		print(f'OS DNS and TLS trust check failed: {error}', file=sys.stderr)
		sys.exit(1)
