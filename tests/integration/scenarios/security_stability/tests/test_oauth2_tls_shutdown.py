"""Keep a local OAuth2 TLS session alive until Fluent Bit teardown."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import sys

import pytest
import threading

import yaml

from utils.test_service import FluentBitTestService


def test_oauth2_tls_connection_shutdown(tmp_path):
    if sys.platform != "linux":
        pytest.skip("local OAuth2 trust fixture requires Linux LD_PRELOAD")
    fixture = Path(__file__).with_name("oauth2_test_ca.c")
    library = tmp_path / "oauth2-ca.so"
    subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-o", str(library),
                    str(fixture), "-ldl"], check=True)
    received = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, self.headers.get("Authorization")))
            payload = json.dumps({"access_token": "local-regression-token", "expires_in": 300,
                                  "token_type": "Bearer"}).encode() if self.path == "/oauth/token" else b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    certificates = Path(__file__).resolve().parents[2] / "in_splunk/certificate"
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificates / "certificate.pem", certificates / "private_key.pem")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "oauth2.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "samples": 1, "dummy": '{"message":"tls-shutdown"}'}],
            "outputs": [{"name": "http", "match": "*", "host": "localhost", "port": server.server_port,
                         "uri": "/data", "format": "json", "tls": True,
                         "tls.ca_file": str(certificates / "certificate.pem"),
                         "oauth2.enable": True,
                         "oauth2.token_url": f"https://localhost:{server.server_port}/oauth/token",
                         "oauth2.client_id": "local-client", "oauth2.client_secret": "local-secret"}],
        },
    }))
    service = FluentBitTestService(str(config), extra_env={
        "LD_PRELOAD": str(library),
        "OAUTH2_TEST_CA": str(certificates / "certificate.pem"),
    })
    try:
        service.start()
        service.wait_for_condition(
            lambda: any(path == "/data" for path, _ in received),
            timeout=30, description="delivery using the local TLS token endpoint")
    finally:
        try:
            service.stop()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    assert [path for path, _ in received] == ["/oauth/token", "/data"]
    assert received[0][1].startswith("Basic ")
    assert received[1][1] == "Bearer local-regression-token"
