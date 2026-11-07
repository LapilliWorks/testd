"""Loopback HTTP fixture without OS reverse-DNS lookups during startup."""

import http.server
import socketserver
import sys


class LoopbackHTTPServer(http.server.ThreadingHTTPServer):
	def server_bind(self):
		# Reverse DNS is unnecessary for the fixture and can stall macOS startup.
		socketserver.TCPServer.server_bind(self)
		self.server_name = 'localhost'
		self.server_port = self.server_address[1]


if __name__ == '__main__':
	with LoopbackHTTPServer(('127.0.0.1', int(sys.argv[1])), http.server.SimpleHTTPRequestHandler) as server:
		print(f'Fixture HTTP server: http://127.0.0.1:{server.server_port}', flush=True)
		server.serve_forever()
