import os
import re
import time
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
import pytest
import yaml

from utils.test_service import FluentBitTestService


def test_scrape_preserves_all_files_and_removes_deleted_series(tmp_path):
    metrics_dir = tmp_path / "metrics"
    metrics_dir.mkdir()
    stable_dir = tmp_path / "stable"
    stable_dir.mkdir()
    (stable_dir / "stable.prom").write_text(
        "# TYPE other_input_marker gauge\nother_input_marker 1\n", encoding="utf-8"
    )
    expected = {"f0", "f1", "f2"}
    for marker in expected:
        lines = [
            "# HELP file_marker Identifies a file in the scrape.",
            "# TYPE file_marker gauge",
            f'file_marker{{file="{marker}"}} 1',
            "# HELP filler_total A counter shared by several files.",
            "# TYPE filler_total counter",
        ]
        lines.extend(
            f'filler_total{{file="{marker}",i="{index}"}} {index}'
            for index in range(2)
        )
        (metrics_dir / f"{marker}.prom").write_text("\n".join(lines) + "\n", encoding="utf-8")

    (metrics_dir / "invalid.prom").write_text("invalid_metric{broken\n", encoding="utf-8")
    (metrics_dir / "empty.prom").write_text("", encoding="utf-8")
    config = {
        "service": {
            "flush": 0.2,
            "grace": 1,
            "http_server": "on",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{
                "name": "prometheus_textfile",
                "path": str(metrics_dir / "*.prom"),
                "scrape_interval": "2s",
            }, {
                "name": "prometheus_textfile",
                "path": str(stable_dir / "*.prom"),
                "scrape_interval": "1s",
            }],
            "outputs": [{
                "name": "prometheus_exporter",
                "match": "*",
                "host": "127.0.0.1",
                "port": "${EXPORTER_PORT}",
            }],
        },
    }
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    service = FluentBitTestService(
        str(config_path),
        pre_start=lambda instance: instance.allocate_port_env("EXPORTER_PORT"),
    )
    service.start()
    url = f"http://127.0.0.1:{os.environ['EXPORTER_PORT']}/metrics"

    def snapshot():
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        # Shared families must emit metadata only once across files and inputs.
        for directive in ("HELP", "TYPE"):
            names = re.findall(rf"^# {directive} (\S+)", response.text, re.MULTILINE)
            assert len(names) == len(set(names)), f"Repeated {directive} directives"
        assert re.search(r"^other_input_marker 1(?: \d+)?$", response.text, re.MULTILINE)
        markers = re.findall(r'^file_marker\{file="([^"]+)"\} 1(?: \d+)?$',
                             response.text, re.MULTILINE)
        assert len(markers) == len(set(markers))
        error_samples = re.findall(
            r'^fluentbit_textfile_scrape_error\{input="([^"]+)"\} ([01])(?: \d+)?$',
            response.text, re.MULTILINE,
        )
        errors = {name: int(value) for name, value in error_samples}
        assert len(errors) == len(error_samples)
        return set(markers), errors

    def wait_for_snapshot(wanted, scrape_error=1):
        expected_snapshot = (wanted, {"prometheus_textfile.0": scrape_error,
                                      "prometheus_textfile.1": 0})
        service.wait_for_condition(
            lambda: snapshot() == expected_snapshot,
            timeout=30,
            interval=0.2,
            description="complete textfile scrape",
        )
        # Poll across further scrapes: no intermediate partial snapshot or duplicates.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            assert snapshot() == expected_snapshot
            time.sleep(0.1)

    try:
        wait_for_snapshot(expected)
        (metrics_dir / "f0.prom").unlink()
        wait_for_snapshot(expected - {"f0"})
        for marker in expected - {"f0"}:
            (metrics_dir / f"{marker}.prom").unlink()
        # Invalid and empty files must not keep the previous snapshot alive.
        wait_for_snapshot(set())
        # Recover after an empty scrape, then delete the very last matching file.
        for path in metrics_dir.glob("*.prom"):
            path.unlink()
        (metrics_dir / "last.prom").write_text(
            '# HELP file_marker Identifies a file in the scrape.\n'
            '# TYPE file_marker gauge\nfile_marker{file="last"} 1\n', encoding="utf-8"
        )
        wait_for_snapshot({"last"}, scrape_error=0)
        (metrics_dir / "last.prom").unlink()
        wait_for_snapshot(set(), scrape_error=0)
    finally:
        service.stop()


@pytest.mark.parametrize("output_name", ["file", "influxdb"])
def test_single_context_outputs_receive_all_files(tmp_path, output_name):
    payloads = queue.Queue()

    class InfluxHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            payloads.put(self.rfile.read(int(self.headers["Content-Length"])).decode())
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), InfluxHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for name in ("first", "second"):
        (tmp_path / f"{name}.prom").write_text(
            f'# HELP file_marker File identifier.\n# TYPE file_marker gauge\n'
            f'file_marker{{file="{name}"}} 1\n', encoding="utf-8"
        )
    config = {
        "service": {
            "flush": 0.2,
            "grace": 1,
            "http_server": "on",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{
                "name": "prometheus_textfile",
                "path": str(tmp_path / "*.prom"),
                "scrape_interval": "1s",
            }],
            "outputs": [{
                "name": "file", "match": "*", "path": str(tmp_path), "file": "metrics.txt",
            }, {
                "name": "influxdb", "match": "*", "host": "127.0.0.1",
                "port": server.server_port, "database": "test",
            }],
        },
    }
    config["pipeline"]["outputs"] = [
        output for output in config["pipeline"]["outputs"] if output["name"] == output_name
    ]
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    service = FluentBitTestService(str(config_path))
    try:
        service.start()
        if output_name == "influxdb":
            for _ in range(2):
                body = payloads.get(timeout=30)
                markers = re.findall(r"^file,file=(\w+) marker=1 ", body, re.MULTILINE)
                assert sorted(markers) == ["first", "second"], body
            return

        def file_has_all_series():
            path = tmp_path / "metrics.txt"
            if not path.exists():
                return False
            content = path.read_text(encoding="utf-8")
            return 'file="first"' in content and 'file="second"' in content

        service.wait_for_condition(file_has_all_series, timeout=30, interval=0.2,
                                   description="both textfile series in file output")
    finally:
        try:
            service.stop()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
