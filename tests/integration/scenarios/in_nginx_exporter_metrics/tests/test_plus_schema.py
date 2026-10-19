"""Untrusted NGINX Plus responses must fail safely and allow later scrapes."""

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import yaml

from utils.network import find_available_port
from utils.test_service import FluentBitTestService


TABLES = [
    "http/server_zones", "http/location_zones", "http/upstreams",
    "stream/server_zones", "stream/upstreams",
]


def invalid_tables(endpoint):
    # Cover each union alternative, including empty containers and null.
    wrong_maps = [5, "value", None, True, [], [1]]
    yield from wrong_maps
    for value in wrong_maps:
        yield {"zone": value}
    if endpoint.endswith("upstreams"):
        for value in [5, "value", None, True, {}]:
            yield {"zone": {"peers": value}}
        for value in wrong_maps:
            yield {"zone": {"peers": [value]}}
        for value in [5, 2**63, -1, None, True, [], {}]:
            yield {"zone": {"peers": [{"server": value}]}}
        yield {"zone": {"peers": [{}]}}
        if endpoint.startswith("http/"):
            for value in wrong_maps:
                yield {"zone": {"peers": [{"server": "127.0.0.1:80", "responses": value}]}}
    else:
        field = "sessions" if endpoint.startswith("stream/") else "responses"
        for value in wrong_maps:
            yield {"zone": {field: value}}


@pytest.mark.parametrize("endpoint", TABLES)
def test_plus_rejects_malformed_tables_and_recovers(tmp_path, endpoint):
    state = {"payload": {}, "requests": 0}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                if self.path == "/status/":
                    payload = [5]
                elif self.path == f"/status/5/{endpoint}":
                    payload = state["payload"]
                    state["requests"] += 1
                else:
                    payload = {}
                body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    exporter_port = find_available_port()
    config = tmp_path / "nginx.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.1, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "nginx_metrics", "host": "127.0.0.1",
                        "port": server.server_port, "status_url": "/status",
                        "nginx_plus": True, "scrape_interval": "1s", "tag": "nginx"}],
            "outputs": [{"name": "prometheus_exporter", "match": "*",
                         "host": "127.0.0.1", "port": exporter_port}],
        },
    }))
    service = FluentBitTestService(str(config))

    def wait_status(value, minimum_requests):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert service.flb.process.poll() is None, "Fluent Bit crashed during scrape"
            with lock:
                count = state["requests"]
            try:
                text = requests.get(f"http://127.0.0.1:{exporter_port}/metrics", timeout=1).text
                if count >= minimum_requests and re.search(
                    rf"^nginxplus_up {value}(?:\.0)?(?: |$)", text, re.MULTILINE
                ):
                    return text
            except requests.RequestException:
                pass
            time.sleep(0.1)
        pytest.fail(f"scrape status did not become {value}; endpoint={endpoint}")

    try:
        service.start()
        wait_status(1, 1)
        for payload in invalid_tables(endpoint):
            with lock:
                state["payload"] = payload
                minimum = state["requests"] + 1
            wait_status(0, minimum)
            # Exercise successful recovery and both label allocations after every rejection.
            with lock:
                if endpoint.endswith("upstreams"):
                    state["payload"] = {"zone": {"peers": [{
                        "server": "127.0.0.1:80", "active": 7, "responses": {"2xx": 3},
                    }]}}
                else:
                    state["payload"] = {"zone": {"requests": 3, "connections": 3,
                                                 "responses": {"2xx": 3}, "sessions": {"2xx": 3}}}
                minimum = state["requests"] + 1
            metrics = wait_status(1, minimum)
            assert 'zone' in metrics
            if endpoint.endswith("upstreams"):
                assert re.search(r'server="127.0.0.1:80"[^\n]*\} 7(?: |$)', metrics, re.MULTILINE)
    finally:
        try:
            service.stop()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
