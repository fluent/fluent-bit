"""Record-derived headers preserve valid pairs and reject unsafe characters."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest
import requests
import yaml

from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("invalid", ["line\r\nX-Injected: yes", "embedded\0null"])
def test_record_header_validation(tmp_path, invalid):
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((dict(self.headers), body))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "headers.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "http", "listen": "127.0.0.1",
                        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}],
            "outputs": [{"name": "http", "match": "*", "host": "127.0.0.1",
                         "port": server.server_port, "body_key": "$body", "headers_key": "$headers"}],
        },
    }))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/test", json={
            "body": "header-regression", "headers": {
                "X-Valid-First": "first", "X-Invalid": invalid,
                invalid: "bad-name", "X-Valid-Last": "last",
            },
        }, timeout=5)
        assert response.status_code == 201
        service.wait_for_condition(lambda: received, timeout=20, description="validated HTTP headers")
    finally:
        service.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert len(received) == 1
    headers, body = received[0]
    assert headers["X-Valid-First"] == "first"
    assert headers["X-Valid-Last"] == "last"
    assert "X-Invalid" not in headers
    assert "X-Injected" not in headers
    assert body == b"header-regression"
