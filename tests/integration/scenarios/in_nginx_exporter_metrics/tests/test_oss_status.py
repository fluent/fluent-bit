"""Validate OSS stub_status metrics using the public schema and an optional real NGINX."""

import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import yaml

from utils.network import find_available_port
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("backend", ["public-spec", "nginx"])
def test_oss_stub_status_metrics(tmp_path, backend):
    """Preserve OSS counters and gauges through ingestion and Prometheus export."""
    nginx_binary = os.environ.get("NGINX_BINARY")
    if backend == "nginx" and not nginx_binary:
        pytest.skip("set NGINX_BINARY to validate a real OSS NGINX server")
    port = find_available_port()
    exporter_port = find_available_port()
    server = None
    process = None
    thread = None
    state = {"requests": 31, "healthy": True}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                healthy = state["healthy"]
                state["requests"] += 1
                count = state["requests"]
            body = (f"Active connections: 7\n server accepts handled requests\n"
                    f" 19 19 {count}\nReading: 1 Writing: 2 Waiting: 4\n").encode()
            self.send_response(200 if healthy else 503)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    config = tmp_path / "fluent-bit.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.1, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "nginx_metrics", "host": "127.0.0.1", "port": port,
                        "status_url": "/status", "nginx_plus": False,
                        "scrape_interval": "1s", "tag": "nginx"}],
            "outputs": [{"name": "prometheus_exporter", "match": "*",
                         "host": "127.0.0.1", "port": exporter_port}],
        },
    }))
    service = FluentBitTestService(str(config))

    def scrape(check):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert service.flb.process.poll() is None, "Fluent Bit crashed during OSS scrape"
            try:
                response = requests.get(f"http://127.0.0.1:{exporter_port}/metrics", timeout=1)
                metrics = {name: float(value) for name, value in re.findall(
                    r"^(nginx_\w+) ([^\s]+)", response.text, re.MULTILINE
                )}
                if check(metrics):
                    return metrics
            except requests.RequestException:
                pass
            time.sleep(0.1)
        pytest.fail("OSS metric assertions did not become true")

    try:
        if backend == "nginx":
            nginx_config = tmp_path / "nginx.conf"
            nginx_config.write_text(
                f"daemon off;\nmaster_process off;\npid {tmp_path}/nginx.pid;\n"
                f"error_log {tmp_path}/nginx-error.log;\nevents {{ worker_connections 64; }}\n"
                f"http {{ access_log off; client_body_temp_path {tmp_path}/body;\n"
                f"proxy_temp_path {tmp_path}/proxy; fastcgi_temp_path {tmp_path}/fastcgi;\n"
                f"uwsgi_temp_path {tmp_path}/uwsgi; scgi_temp_path {tmp_path}/scgi;\n"
                f"server {{ listen 127.0.0.1:{port}; location = /status {{ stub_status; }} }} }}\n"
            )
            process = subprocess.Popen([nginx_binary, "-p", str(tmp_path), "-c", str(nginx_config)])
        else:
            server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
        service.start()
        names = {"nginx_up", "nginx_connections_accepted", "nginx_connections_handled",
                 "nginx_connections_active", "nginx_connections_reading",
                 "nginx_connections_writing", "nginx_connections_waiting",
                 "nginx_http_requests_total"}
        first = scrape(lambda m: names <= m.keys() and m["nginx_up"] == 1)
        assert first["nginx_connections_active"] == sum(
            first[f"nginx_connections_{name}"] for name in ["reading", "writing", "waiting"]
        )
        assert first["nginx_connections_accepted"] == first["nginx_connections_handled"]
        if backend == "public-spec":
            for name, value in {"active": 7, "reading": 1, "writing": 2,
                                "waiting": 4, "accepted": 19, "handled": 19}.items():
                assert first[f"nginx_connections_{name}"] == value
        for _ in range(5):
            requests.get(f"http://127.0.0.1:{port}/status", timeout=2).raise_for_status()
        scrape(lambda m: m.get("nginx_http_requests_total", 0) > first["nginx_http_requests_total"])
        if backend == "public-spec":
            with lock:
                state["healthy"] = False
            scrape(lambda m: m.get("nginx_up") == 0)
            with lock:
                state["healthy"] = True
            scrape(lambda m: m.get("nginx_up") == 1)
    finally:
        try:
            service.stop()
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=10)
            if server is not None:
                server.shutdown()
                server.server_close()
                thread.join()
