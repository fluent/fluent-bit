#!/usr/bin/env python3
"""TLS and redirect regressions; only Python's standard library and OpenSSL are needed."""

from contextlib import ExitStack
from http.client import HTTPConnection, HTTPSConnection
import socket
import json
import ssl
import tempfile
import threading
import unittest

from browser_server import (certificate_host, create_redirect_server, create_server,
                            development_certificate, server_tls_context)
from browser_receiver import ReceiverState


class BrowserTLSTest(unittest.TestCase):
    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.directory = self.resources.enter_context(tempfile.TemporaryDirectory(prefix="flb-tls-test-"))
        self.cert, self.key = development_certificate(self.directory, ["localhost", "127.0.0.1"])
        self.server = self.resources.enter_context(create_server(
            self.directory, 0, tls_context=server_tls_context(self.cert, self.key)))
        self.redirect = self.resources.enter_context(create_redirect_server(
            "127.0.0.1", 0, self.server.server_port, ["localhost", "127.0.0.1"]))
        for server in (self.server, self.redirect):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.resources.callback(thread.join)
            self.resources.callback(server.shutdown)

    def test_verified_https_and_headers(self):
        context = ssl.create_default_context(cafile=str(self.cert))
        connection = HTTPSConnection("127.0.0.1", self.server.server_port, context=context, timeout=5)
        self.addCleanup(connection.close)
        connection.request("GET", "/")
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Cross-Origin-Opener-Policy"), "same-origin")
        self.assertEqual(response.getheader("Cross-Origin-Embedder-Policy"), "require-corp")
        self.assertIn(b"WASM test bench", response.read())

    def test_untrusted_certificate_rejected(self):
        connection = HTTPSConnection("localhost", self.server.server_port, timeout=5)
        self.addCleanup(connection.close)
        with self.assertRaises(ssl.SSLCertVerificationError):
            connection.request("GET", "/")

    def test_sdk_allowlist_does_not_expose_arbitrary_build_files(self):
        context = ssl.create_default_context(cafile=str(self.cert))
        connection = HTTPSConnection("127.0.0.1", self.server.server_port, context=context, timeout=5)
        self.addCleanup(connection.close)
        for path in ("/sdk/../../CMakeCache.txt", "/sdk/CMakeCache.txt", "/sdk/package.json"):
            connection.request("GET", path)
            response = connection.getresponse()
            self.assertEqual(response.status, 404)
            response.read()

    def test_hostname_mismatch_rejected(self):
        context = ssl.create_default_context(cafile=str(self.cert))
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5) as connection:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(connection, server_hostname="wrong.example")

    def test_redirect_preserves_path_and_query(self):
        for method in ("GET", "HEAD", "POST"):
            connection = HTTPConnection("127.0.0.1", self.redirect.server_port, timeout=5)
            self.addCleanup(connection.close)
            connection.request(method, "/runner.html?target=flb-wasm-yaml")
            response = connection.getresponse()
            self.assertEqual(response.status, 307)
            self.assertEqual(response.getheader("Location"),
                             f"https://127.0.0.1:{self.server.server_port}/runner.html?target=flb-wasm-yaml")
            self.assertEqual(response.read(), b"")

    def test_redirect_rejects_unrecognized_authority(self):
        for host in ("evil.example", "localhost@evil.example", "localhost/path", "localhost:bad"):
            connection = HTTPConnection("127.0.0.1", self.redirect.server_port, timeout=5)
            self.addCleanup(connection.close)
            connection.request("GET", "/", headers={"Host": host})
            self.assertEqual(connection.getresponse().status, 400)

    def test_certificate_reused_and_key_private(self):
        original = self.key.read_bytes()
        cert, key = development_certificate(self.directory, ["127.0.0.1", "localhost"])
        self.assertEqual(cert, self.cert)
        self.assertEqual(key.read_bytes(), original)
        self.assertEqual(key.stat().st_mode & 0o077, 0)
        context = ssl.create_default_context(cafile=str(self.cert))
        connection = HTTPSConnection("127.0.0.1", self.server.server_port, context=context, timeout=5)
        self.addCleanup(connection.close)
        connection.request("GET", "/" + str(key.relative_to(self.directory)))
        self.assertEqual(connection.getresponse().status, 404)

    def test_stalled_tls_connection_does_not_block_listener(self):
        stalled = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5)
        self.addCleanup(stalled.close)
        self.test_verified_https_and_headers()

    def test_invalid_certificate_hosts(self):
        for host in ("", "https://localhost", "localhost,IP:1.2.3.4", "bad\nname", "-host"):
            with self.assertRaises(ValueError):
                certificate_host(host)

    def receiver_request(self, method, path, body=None, headers=None):
        context = ssl.create_default_context(cafile=str(self.cert))
        connection = HTTPSConnection('127.0.0.1', self.server.server_port, context=context, timeout=5)
        self.addCleanup(connection.close)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()

    def test_receiver_delivery_retry_and_capture(self):
        token = '00000000-0000-0000-0000-000000000001'
        for expected in (503, 200):
            status, _, _ = self.receiver_request('PUT', '/collect/' + token + '?fail=1', b'{"a":1}',
                                                {'Authorization': 'Bearer private', 'X-Demo': 'test'})
            self.assertEqual(status, expected)
        status, _, data = self.receiver_request('GET', '/received/' + token)
        capture = json.loads(data)
        self.assertEqual(status, 200)
        self.assertEqual(capture['attempts'], 2)
        self.assertEqual(capture['requests'][0]['body'], '{"a":1}')
        self.assertTrue(capture['requests'][0]['authorization_present'])
        self.assertNotIn(b'private', data)

    def test_receiver_cors(self):
        path = '/collect/00000000-0000-0000-0000-000000000002'
        origin = 'https://allowed.example'
        self.assertEqual(self.receiver_request('OPTIONS', path, headers={'Origin': origin})[0], 403)
        self.assertEqual(self.receiver_request('POST', path, b'x', {'Origin': origin})[0], 403)
        self.server.receiver.cors_origins = frozenset([origin])
        status, headers, _ = self.receiver_request('OPTIONS', path, headers={'Origin': origin})
        self.assertEqual(status, 204)
        self.assertEqual(headers['Access-Control-Allow-Origin'], origin)
        self.assertNotIn('Access-Control-Allow-Credentials', headers)

    def test_receiver_invalid_lengths_routes_and_parameters(self):
        path = '/collect/00000000-0000-0000-0000-000000000003'
        for length, status in (('-1', 400), ('1048577', 413), ('9' * 5000, 413)):
            self.assertEqual(self.receiver_request('POST', path, b'', {'Content-Length': length})[0], status)
        self.assertEqual(self.receiver_request('POST', path, b'', {'Transfer-Encoding': 'chunked'})[0], 400)
        for query in ('?delay=nan', '?delay=3', '?fail=4', '?status=307'):
            self.assertEqual(self.receiver_request('POST', path + query, b'')[0], 400)
        self.assertEqual(self.receiver_request('POST', '/collect/invalid', b'')[0], 404)


class ReceiverBoundsTest(unittest.TestCase):
    def test_retention_bounds(self):
        state = ReceiverState()
        for index in range(17):
            for attempt in range(25):
                state.record(str(index), {'body': 'test'}, 0, 200)
        self.assertEqual(len(state.entries), 16)
        self.assertEqual(state.read('0')['attempts'], 0)
        self.assertEqual(state.read('16')['attempts'], 25)
        self.assertEqual(len(state.read('16')['requests']), 20)
        state.entries['16']['time'] -= 601
        self.assertEqual(state.read('16')['attempts'], 0)


if __name__ == "__main__":
    unittest.main()
