import http.server
import os
import socket
import ssl
import threading

import pytest

from utils.test_service import FluentBitTestService


class IPv6ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True


class TLSReceiver:
    def __init__(self, port, cert_file, key_file):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.server = None
        self.thread = None
        self.requests = []
        self.sni_values = []

    def start(self):
        receiver = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)
                receiver.requests.append(
                    {
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body,
                    }
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, fmt, *args):
                pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_file, self.key_file)

        def record_sni(_socket, server_name, _context):
            self.sni_values.append(server_name)

        context.set_servername_callback(
            record_sni
        )

        self.server = IPv6ThreadingHTTPServer(("::1", self.port), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

        if self.thread is not None:
            self.thread.join(timeout=5)
            self.thread = None


class Service:
    def __init__(self):
        config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                  "../config"))
        cert_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                "../../in_splunk/certificate"))
        self.config_file = os.path.join(config_dir, "out_http_tls_ipv6_literal.yaml")
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.receiver = None
        self.service = FluentBitTestService(
            self.config_file,
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.receiver = TLSReceiver(service.test_suite_http_port,
                                    self.tls_crt_file,
                                    self.tls_key_file)
        self.receiver.start()

    def _stop_receiver(self, service):
        if self.receiver is not None:
            self.receiver.stop()

    def start(self):
        self.service.start()

    def stop(self):
        self.service.stop()

    def wait_for_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: self.receiver.requests
            if len(self.receiver.requests) >= minimum_count
            else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} outbound HTTPS requests",
        )


def ipv6_loopback_available():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.bind(("::1", 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def test_tls_sni_omits_ipv6_literals():
    if not ipv6_loopback_available():
        pytest.skip("IPv6 loopback is not available")

    service = Service()
    try:
        service.start()
        service.wait_for_requests(1, timeout=30)
    finally:
        service.stop()

    assert service.receiver.sni_values
    assert service.receiver.sni_values[0] is None
