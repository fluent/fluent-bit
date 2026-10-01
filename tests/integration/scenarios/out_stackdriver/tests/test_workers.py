import json
import ssl
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("workers", [2, 4])
def test_token_refresh_worker_connections(tmp_path, workers):
    """Exercise short-lived tokens and a failed refresh using real keepalive sockets."""
    lock = threading.Lock()
    token_peers = []
    entries = []
    authorizations = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def reply(self, status, body):
            payload = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path.endswith("/project/project-id"):
                self.reply(200, "worker-test-project")
                return
            if not self.path.endswith("/service-accounts/default/token"):
                self.reply(404, {})
                return
            with lock:
                token_peers.append(self.client_address)
                sequence = len(token_peers)
            # Keep a refresh in flight while other workers contend for the token.
            time.sleep(0.05)
            if sequence == 2:
                self.reply(503, {"error": "temporary token failure"})
            else:
                # After the OAuth safety margins, the legacy token expires after 62 seconds.
                self.reply(200, {"access_token": f"token-{sequence}",
                                 "token_type": "Bearer", "expires_in": 68})

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path != "/v2/entries:write":
                self.reply(404, {})
                return
            with lock:
                entries.extend(payload["entries"])
                authorizations.append(self.headers.get("Authorization"))
            self.reply(200, {})

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

    config = {
        "service": {"flush": 0.2, "grace": 1, "log_level": "info", "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
                    "scheduler.base": 1, "scheduler.cap": 1},
        "pipeline": {
            "inputs": [{"name": "dummy", "tag": f"worker.{i}", "rate": 1, "samples": 66,
                        "dummy": json.dumps({"message": f"worker-{i}"})} for i in range(6)],
            "outputs": [{"name": "stackdriver", "match": "*", "workers": workers,
                         "resource": "generic_node", "location": "test", "namespace": "test",
                         "node_id": "test-node", "retry_limit": 3,
                         "metadata_server": f"http://127.0.0.1:{metadata.server_port}",
                         "cloud_logging_base_url": f"https://127.0.0.1:{logging.server_port}",
                         "tls": "on", "tls.verify": "off"}],
        },
    }
    config_path = tmp_path / "stackdriver-workers.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path), shutdown_timeout=30)

    def all_delivered():
        assert service.flb.process.poll() is None, "Fluent Bit exited during token refresh"
        with lock:
            return len(entries) >= 396

    try:
        service.start()
        service.wait_for_condition(all_delivered, timeout=100, interval=0.1,
                                   description="all Stackdriver records after token refresh failure")
    finally:
        try:
            service.stop()
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)

    assert Counter(entry["jsonPayload"]["message"] for entry in entries) == {
        f"worker-{i}": 66 for i in range(6)
    }
    assert len(token_peers) >= 3, "token expiration and failure must trigger refreshes"
    assert all(value and value.startswith("Bearer token-") for value in authorizations)
    assert "Bearer token-2" not in authorizations
    if workers:
        # The initialization thread's connection must never migrate to a worker.
        assert token_peers[0] not in token_peers[1:]
