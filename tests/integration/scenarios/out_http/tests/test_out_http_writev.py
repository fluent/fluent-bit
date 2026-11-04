import http.server
import json
from pathlib import Path
import ssl
import threading

import pytest
import yaml

from utils.memory_check import memory_check_enabled
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("use_tls", [False, True], ids=["tcp", "tls"])
@pytest.mark.parametrize("payload_size", [1024, 65536, 131079])
def test_out_http_vector_payload(tmp_path, use_tls, payload_size):
    """Verify headers and bodies across batching boundaries on reused connections."""
    message = ("0123456789abcdef" * ((payload_size + 15) // 16))[:payload_size]
    received = []
    server = None
    server_thread = None

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            body = self.rfile.read(length)
            received.append((self.path, dict(self.headers), body, self.client_address))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    def start_receiver(service):
        nonlocal server, server_thread
        server = http.server.ThreadingHTTPServer(("127.0.0.1", service.test_suite_http_port), Handler)
        if use_tls:
            cert_dir = Path(__file__).resolve().parents[2] / "in_splunk" / "certificate"
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_dir / "certificate.pem", cert_dir / "private_key.pem")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

    def stop_receiver(service):
        if server is not None:
            server.shutdown()
            server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=5)

    output = {
        "name": "http", "match": "*", "host": "127.0.0.1",
        "port": "${TEST_SUITE_HTTP_PORT}", "uri": "/vectors",
        "format": "json", "json_date_key": False, "workers": 0,
        "net.keepalive": True,
    }
    if use_tls:
        output.update({"tls": True, "tls.verify": False})
    config = {
        "service": {
            "flush": 0.1, "grace": 1, "http_server": True,
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{"name": "dummy", "samples": 2,
                        "dummy": json.dumps({"message": message})}],
            "outputs": [output],
        },
    }
    config_path = tmp_path / "out_http_writev.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path), pre_start=start_receiver, post_stop=stop_receiver)
    try:
        service.start()
        service.wait_for_condition(lambda: len(received) >= 2,
                                   timeout=60 if memory_check_enabled() else 15,
                                   description="two complete vector HTTP requests")
    finally:
        service.stop()

    assert len(received) == 2
    assert received[0][3] == received[1][3], "the connection should be reused"
    for path, headers, body, _ in received:
        assert path == "/vectors"
        assert len(body) == int(headers["Content-Length"])
        assert json.loads(body) == [{"message": message}]
