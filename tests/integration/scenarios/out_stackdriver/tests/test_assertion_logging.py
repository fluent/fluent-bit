"""JWT generation must not expose replayable assertions in diagnostic logs."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("plugin", ["stackdriver", "bigquery", "chronicle"])
@pytest.mark.parametrize("log_level", ["debug", "trace"])
def test_assertion_not_logged(tmp_path, monkeypatch, plugin, log_level):
    # Reuse a public test key, never an operator's service-account credentials.
    key = Path(__file__).resolve().parents[2] / "in_splunk/certificate/private_key.pem"
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({
        "type": "service_account", "project_id": "assertion-test",
        "private_key_id": "test-key", "private_key": key.read_text(),
        "client_email": "test@assertion-test.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
    }))
    for name in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_SERVICE_CREDENTIALS",
                 "SERVICE_ACCOUNT_EMAIL", "SERVICE_ACCOUNT_SECRET"):
        monkeypatch.delenv(name, raising=False)

    connections = []

    class RejectingProxy(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_CONNECT(self):
            connections.append(self.path)
            # No external connection is opened and no credential leaves the host.
            self.send_error(502)

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), RejectingProxy)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    proxy_url = f"http://127.0.0.1:{proxy.server_port}"
    for name in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(name, proxy_url)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost")

    output = {"name": plugin, "match": "*", "log_level": log_level,
              "google_service_credentials": str(credentials)}
    if plugin == "stackdriver":
        output["resource"] = "global"
    elif plugin == "bigquery":
        output.update(dataset_id="test", table_id="test")
    else:
        output.update(customer_id="test", log_type="BIND_DNS")
    config = {
        # Plugin-level debug alone must be safe with the default service level.
        "service": {"flush": 1, "grace": 1, "log_level": "info",
                    "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [{"name": "dummy", "samples": 1}], "outputs": [output]},
    }
    config_path = tmp_path / "assertion-logging.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path), shutdown_timeout=30)
    try:
        try:
            service.start()
        except FluentBitStartupError:
            # Chronicle validates its log type during startup, which also needs
            # authentication. The rejecting proxy makes that validation fail.
            if plugin != "chronicle":
                raise
    finally:
        try:
            service.stop()
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=5)

    logs = Path(service.flb.log_file).read_text()
    assert not re.search(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{20,}", logs)
    assert "assertion=" not in logs
    assert "JWT assertion generated" in logs
    assert "JWT signature generation failed" not in logs
    assert "oauth2.googleapis.com:443" in connections
