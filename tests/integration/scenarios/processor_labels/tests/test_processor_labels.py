import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import yaml

from utils.test_service import FluentBitTestService


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'# TYPE test_metric gauge\ntest_metric{original="value"} 1\n'
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.mark.parametrize(
    "second_processor, expected_labels",
    [
        ({"upsert": "second two"}, {"original": "value", "first": "one", "second": "two"}),
        ({"update": "original changed"}, {"original": "changed", "first": "one"}),
    ],
    ids=["chained_upsert", "unrelated_update"],
)
def test_static_labels_survive_chain(tmp_path, second_processor, expected_labels):
    source = ThreadingHTTPServer(("127.0.0.1", 0), MetricsHandler)
    thread = threading.Thread(target=source.serve_forever, daemon=True)
    thread.start()
    config = {
        "service": {
            "flush": 0.2,
            "grace": 1,
            "http_server": "on",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{
                "name": "prometheus_scrape",
                "tag": "test",
                "host": "127.0.0.1",
                "port": source.server_port,
                "scrape_interval": "5s",
                "processors": {"metrics": [
                    {"name": "labels", "upsert": "first one"},
                    {"name": "labels", **second_processor},
                ]},
            }],
            "outputs": [{
                "name": "prometheus_exporter",
                "match": "test",
                "host": "127.0.0.1",
                "port": "${EXPORTER_PORT}",
            }],
        },
    }
    config_file = tmp_path / "labels.yaml"
    config_file.write_text(yaml.safe_dump(config))
    exporter_port = None

    def prepare(service):
        nonlocal exporter_port
        exporter_port = service.allocate_port_env("EXPORTER_PORT")

    service = FluentBitTestService(str(config_file), pre_start=prepare)

    def get_sample():
        try:
            response = requests.get(f"http://127.0.0.1:{exporter_port}/metrics", timeout=1)
            response.raise_for_status()
        except requests.RequestException:
            return None
        return next(
            (line for line in response.text.splitlines() if line.startswith("test_metric{")),
            None,
        )

    try:
        service.start()
        sample = service.wait_for_condition(
            get_sample, timeout=30, interval=0.1, description="processed test metric"
        )
        labels_text, value = sample.removeprefix("test_metric{").split("}", 1)
        pairs = [label.split("=", 1) for label in labels_text.split(",")]
        labels = {key: label_value.strip('"') for key, label_value in pairs}
        assert len(pairs) == len(expected_labels), sample
        assert labels == expected_labels, sample
        assert float(value.split()[0]) == 1
    finally:
        try:
            service.stop()
        finally:
            source.shutdown()
            source.server_close()
            thread.join(timeout=5)
