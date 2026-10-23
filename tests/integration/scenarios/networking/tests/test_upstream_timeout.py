"""Exercise upstream timeout logging and retry completion against a silent peer."""

from pathlib import Path
import socketserver
import threading

import pytest
import yaml

from utils.test_service import FluentBitTestService


class SilentPeer(socketserver.BaseRequestHandler):
    def handle(self):
        # Accept TCP but never answer the TLS handshake.
        self.server.release.wait(30)


class SilentServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.mark.parametrize("log_error", [True, False])
def test_timeout_logs_configured_host_and_port(tmp_path, log_error):
    server = SilentServer(("127.0.0.1", 0), SilentPeer)
    server.release = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    config = {
        "service": {
            "flush": 0.2,
            "grace": 1,
            "log_level": "debug",
            "http_server": "on",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{"name": "dummy", "samples": 1, "tag": "timeout"}],
            "outputs": [{
                "name": "http",
                "match": "*",
                "host": "localhost",
                "port": port,
                "tls": "on",
                "tls.verify": "off",
                "net.dns.resolver": "LEGACY",
                "net.connect_timeout": 2,
                "net.connect_timeout_log_error": "on" if log_error else "off",
                "retry_limit": "no_retries",
            }],
        },
    }
    config_path = tmp_path / "timeout.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    service = FluentBitTestService(str(config_path))
    try:
        service.start()

        def completed():
            logs = Path(service.flb.log_file).read_text(encoding="utf-8", errors="replace")
            return logs if "is not retried (no retry config)" in logs else None

        logs = service.wait_for_condition(completed, timeout=30, description="timed-out flush")
        timeout_lines = [line for line in logs.splitlines()
                         if "[upstream]" in line and "timed out" in line]
        assert timeout_lines, logs
        assert any(f"to localhost:{port} timed out" in line for line in timeout_lines), logs
        assert any(("[error]" if log_error else "[debug]") in line
                   for line in timeout_lines), logs
        assert "unavailable:0" not in logs
    finally:
        try:
            service.stop()
        finally:
            server.release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
