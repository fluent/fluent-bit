"""Opt-in Google token exchange; log entries stay on a local TLS receiver.

Set STACKDRIVER_TEST_CREDENTIALS to a service-account JSON key path to run.
The private key and access token are never copied into test artifacts.
"""

import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("credential_source", ["config", "environment"])
def test_service_account_token_exchange(tmp_path, monkeypatch, credential_source):
    credentials = os.environ.get("STACKDRIVER_TEST_CREDENTIALS")
    if not credentials:
        pytest.skip("set STACKDRIVER_TEST_CREDENTIALS to run the live Google token exchange")
    credentials = str(Path(credentials).resolve(strict=True))
    for name in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_SERVICE_CREDENTIALS",
                 "SERVICE_ACCOUNT_EMAIL", "SERVICE_ACCOUNT_SECRET"):
        monkeypatch.delenv(name, raising=False)

    delivered = threading.Event()
    metadata_requests = []
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status):
            self.send_response(status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def do_GET(self):
            metadata_requests.append(self.path)
            self.reply(500)

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            # Keep only the presence of authentication, never the token itself.
            authenticated = self.headers.get("Authorization", "").startswith("Bearer ")
            received.append((self.path, authenticated, payload))
            self.reply(200)
            delivered.set()

    metadata = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    logging = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    certificates = Path(__file__).resolve().parents[2] / "in_splunk/certificate"
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificates / "certificate.pem", certificates / "private_key.pem")
    logging.socket = tls.wrap_socket(logging.socket, server_side=True)
    servers = [metadata, logging]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()

    output = {"name": "stackdriver", "match": "*", "resource": "global",
              "metadata_server": f"http://127.0.0.1:{metadata.server_port}",
              "cloud_logging_base_url": f"https://127.0.0.1:{logging.server_port}",
              "tls": "on", "tls.verify": "off"}
    if credential_source == "config":
        output["google_service_credentials"] = credentials
        # Explicit configuration must take precedence over the environment.
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "missing.json"))
    else:
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", credentials)
    config = {
        "service": {"flush": 0.2, "grace": 1, "log_level": "info", "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "samples": 1,
                        "dummy": '{"message":"service-account-regression"}'}],
            "outputs": [output],
        },
    }
    config_path = tmp_path / "stackdriver-service-account.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path), shutdown_timeout=30)
    try:
        service.start()
        service.wait_for_condition(delivered.is_set, timeout=30, interval=0.1,
                                   description="authenticated Stackdriver log delivery")
    finally:
        try:
            service.stop()
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)

    assert not metadata_requests, "service-account authentication must bypass metadata"
    assert len(received) == 1
    path, authenticated, payload = received[0]
    assert path == "/v2/entries:write"
    assert authenticated
    assert payload["entries"][0]["jsonPayload"]["message"] == "service-account-regression"
