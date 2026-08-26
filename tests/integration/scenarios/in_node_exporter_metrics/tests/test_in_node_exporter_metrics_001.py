import os
import sys

import pytest

from utils.http_matrix import run_curl_request
from utils.test_service import FluentBitTestService


EXPECTED_METRICS = {
    "node_disk_reads_completed_total": 1.0,
    "node_disk_reads_merged_total": 2.0,
    "node_disk_read_bytes_total": 1536.0,
    "node_disk_read_time_seconds_total": 4.0,
    "node_disk_writes_completed_total": 5.0,
    "node_disk_writes_merged_total": 6.0,
    "node_disk_written_bytes_total": 3584.0,
    "node_disk_write_time_seconds_total": 8.0,
    "node_disk_io_now": 9.0,
    "node_disk_io_time_seconds_total": 10.0,
    "node_disk_io_time_weighted_seconds_total": 11.0,
}


def _metric_value(metrics_text, metric_name):
    prefix = f'{metric_name}{{device="sda"}} '
    for line in metrics_text.splitlines():
        if line.startswith(prefix):
            return float(line[len(prefix):].split()[0])
    return None


@pytest.mark.skipif(sys.platform != "linux", reason="procfs diskstats are Linux-only")
def test_node_exporter_diskstats_metric_cache(tmp_path):
    procfs_path = tmp_path / "proc"
    procfs_path.mkdir()
    (procfs_path / "diskstats").write_text(
        "8 0 sda 1 2 3 4000 5 6 7 8000 9 10000 11000 "
        "12 13 14 15000 16 17000\n",
        encoding="utf-8",
    )

    config_file = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "../config/in_node_exporter_metrics_diskstats.yaml",
        )
    )

    def pre_start(service):
        service.allocate_port_env("NODE_EXPORTER_EXPORTER_PORT")

    service = FluentBitTestService(
        config_file,
        extra_env={"NODE_EXPORTER_PROCFS": procfs_path},
        pre_start=pre_start,
    )
    service.start()
    exporter_port = os.environ["NODE_EXPORTER_EXPORTER_PORT"]

    try:
        response = service.wait_for_condition(
            lambda: (
                result
                if result["status_code"] == 200
                and all(
                    _metric_value(result["body"], name) == value
                    for name, value in EXPECTED_METRICS.items()
                )
                else None
            )
            if (
                result := run_curl_request(
                    f"http://127.0.0.1:{exporter_port}/metrics",
                    method="GET",
                    http_mode="http1.1",
                )
            )
            else None,
            timeout=15,
            interval=1,
            description="diskstats metrics with correct cache values",
        )
    finally:
        service.stop()

    for metric_name, expected_value in EXPECTED_METRICS.items():
        assert _metric_value(response["body"], metric_name) == expected_value
