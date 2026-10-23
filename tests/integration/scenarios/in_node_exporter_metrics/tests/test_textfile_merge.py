"""A rejected textfile merge must report an error and keep the collector alive."""
from pathlib import Path
import sys

import pytest
import requests
import yaml

from utils.test_service import FluentBitTestService


@pytest.mark.skipif(sys.platform != "linux", reason="textfile collector requires Linux")
def test_textfile_merge_failure_preserves_context(tmp_path):
    metrics_dir = tmp_path / "metrics"
    metrics_dir.mkdir()

    def summary(quantile, value):
        return ("# TYPE textfile_summary summary\n"
                f'textfile_summary{{quantile="{quantile}"}} {value}\n'
                "textfile_summary_sum 10\ntextfile_summary_count 2\n")

    first = metrics_dir / "a.prom"
    first.write_text(summary("0.5", 5))
    (metrics_dir / "b.prom").write_text(summary("0.9", 9))
    config = tmp_path / "textfile.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "node_exporter_metrics", "tag": "textfile",
                        "metrics": "textfile", "scrape_interval": "1s",
                        "collector.textfile.path": str(metrics_dir)}],
            "outputs": [{"name": "prometheus_exporter", "match": "*",
                         "host": "127.0.0.1", "port": "${EXPORTER_PORT}"}],
        },
    }))
    exporter_port = None

    def prepare(service):
        nonlocal exporter_port
        exporter_port = service.allocate_port_env("EXPORTER_PORT")

    service = FluentBitTestService(str(config), pre_start=prepare)

    def scrape(expected):
        try:
            response = requests.get(f"http://127.0.0.1:{exporter_port}/metrics", timeout=1)
            response.raise_for_status()
        except requests.RequestException:
            return None
        text = response.text
        return text if all(item in text for item in expected) else None

    try:
        service.start()
        expected = ['textfile_summary{quantile="0.5"} 5', 'reason="merge error"']
        service.wait_for_condition(lambda: scrape(expected), timeout=30,
                                   description="textfile merge failure metric")
        assert "could not merge textfile metrics" in Path(service.flb.log_file).read_text()

        # The shared context and its error counter must survive later scrapes.
        first.write_text(summary("0.5", 7))
        expected[0] = 'textfile_summary{quantile="0.5"} 7'
        service.wait_for_condition(lambda: scrape(expected), timeout=30,
                                   description="textfile update after merge failure")
    finally:
        service.stop()
