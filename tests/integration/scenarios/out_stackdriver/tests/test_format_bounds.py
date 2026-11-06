"""Record-controlled names must never serialize bytes beyond formatter buffers."""

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from utils.test_service import FluentBitTestService


def test_format_buffer_boundaries(tmp_path, monkeypatch):
    for name in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_SERVICE_CREDENTIALS",
                 "SERVICE_ACCOUNT_EMAIL", "SERVICE_ACCOUNT_SECRET"):
        monkeypatch.delenv(name, raising=False)

    received = []
    expected = {}
    inputs = []
    project = "bounds-project"
    # snprintf receives sizeof(buffer) - 1, leaving capacities of 254 and 1022.
    for field in ("trace", "log", "project", "tag"):
        limit = 254 if field == "trace" else 1022
        prefix = f"projects/{project}/{'traces' if field == 'trace' else 'logs'}/"
        overhead = len("projects//logs/test") if field == "project" else len(prefix)
        for length in (0, limit - overhead - 1, limit - overhead,
                       limit - overhead + 1, 8192):
            value = "x" * length
            key = f"{field}-{length}"
            record = {"case": key, "trace": "trace-id"}
            tag = "test"
            if field == "tag":
                # Empty tags are normalized by the engine; cover empty record fields instead.
                if not value:
                    continue
                tag = value
            else:
                record[field] = value
            trace = f"projects/{project}/traces/{record['trace']}"[:254]
            log_name = f"projects/{record.get('project', project)}/logs/{record.get('log', tag)}"[:1022]
            expected[key] = (trace, log_name)
            inputs.append({"name": "dummy", "tag": tag, "samples": 1,
                           "dummy": json.dumps(record)})

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, body):
            payload = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path.endswith("/project/project-id"):
                self.reply(project)
            elif self.path.endswith("/instance/zone"):
                self.reply("projects/123/zones/us-central1-a")
            elif self.path.endswith("/instance/id"):
                self.reply("123")
            else:
                self.reply({"access_token": "local-token", "token_type": "Bearer",
                            "expires_in": 3600})

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.extend(payload["entries"])
            self.reply({})

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
        "service": {"flush": 0.2, "grace": 1, "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": inputs,
            "outputs": [{"name": "stackdriver", "match": "*", "resource": "global",
                         "trace_key": "trace", "autoformat_stackdriver_trace": "true",
                         "log_name_key": "log", "project_id_key": "project",
                         "metadata_server": f"http://127.0.0.1:{metadata.server_port}",
                         "cloud_logging_base_url": f"https://127.0.0.1:{logging.server_port}",
                         "tls": "on", "tls.verify": "off"}],
        },
    }
    config_path = tmp_path / "stackdriver-bounds.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path), shutdown_timeout=30)
    try:
        service.start()
        service.wait_for_condition(
            lambda: expected.keys() <= {entry["jsonPayload"]["case"] for entry in received},
            timeout=30, interval=0.1, description="all boundary records delivered")
    finally:
        try:
            service.stop()
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)

    actual = {entry["jsonPayload"]["case"]: (entry["trace"], entry["logName"])
              for entry in received}
    assert actual == expected
