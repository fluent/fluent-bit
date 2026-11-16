"""End-to-end coverage for the service memory monitor (memory.limit)."""

import platform
import socket
import time

import pytest
import requests
import yaml

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port

pytestmark = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="process memory usage is only sampled on Linux",
)

STATE_NORMAL = 0
STATE_THROTTLE = 2
STATE_REFUSE = 3


def wait_until(predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    pytest.fail(f"Timed out waiting for {description}")


def write_config(tmp_path, tcp_port, service=None):
    config = {
        "service": {
            "flush": 0.2,
            "grace": 1,
            "log_level": "info",
            "http_server": True,
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [
                {"name": "dummy", "tag": "local", "rate": 20},
                {"name": "tcp", "tag": "server", "listen": "127.0.0.1",
                 "port": tcp_port, "format": "none"},
            ],
            "outputs": [{"name": "null", "match": "*"}],
        },
    }
    config["service"].update(service or {})

    path = tmp_path / "fluent-bit.yaml"
    path.write_text(yaml.safe_dump(config))
    return str(path)


def read_metrics(manager):
    """Return the internal metrics as a {'name{labels}': value} dictionary."""
    response = requests.get(
        f"http://127.0.0.1:{manager.http_monitoring_port}/api/v2/metrics/prometheus",
        timeout=5,
    )
    response.raise_for_status()

    metrics = {}
    for line in response.text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.rsplit(" ", 1)
        metrics[fields[0]] = float(fields[1])
    return metrics


def metric(manager, name, default=None):
    return read_metrics(manager).get(name, default)


def input_records(manager, name):
    return metric(manager, f'fluentbit_input_records_total{{name="{name}"}}', 0)


def input_paused(manager, name):
    return metric(manager, f'fluentbit_input_ingestion_paused{{name="{name}"}}', 0)


def send_tcp_line(port, line=b"hello\n"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(line)


def test_no_limit_reports_usage_only(tmp_path):
    tcp_port = find_available_port()
    manager = FluentBitManager(write_config(tmp_path, tcp_port))

    try:
        manager.start()
        wait_until(lambda: input_records(manager, "dummy.0") > 0,
                   "the dummy input to ingest records")

        metrics = read_metrics(manager)
        assert metrics["fluentbit_memory_usage_bytes"] > 0
        assert metrics["fluentbit_memory_limit_bytes"] == 0
        assert metrics["fluentbit_memory_pressure"] == 0
        assert metrics["fluentbit_memory_state"] == STATE_NORMAL
        assert metrics["fluentbit_memory_paused_inputs"] == 0
    finally:
        manager.stop()


@pytest.mark.parametrize("limit", ["64G", "100%"], ids=["bytes", "percent"])
def test_usage_below_limit_keeps_ingesting(tmp_path, limit):
    tcp_port = find_available_port()
    manager = FluentBitManager(
        write_config(tmp_path, tcp_port,
                     {"memory.limit": limit, "memory.check_interval": 0.1}))

    try:
        manager.start()
        wait_until(lambda: input_records(manager, "dummy.0") > 0,
                   "the dummy input to ingest records")

        send_tcp_line(tcp_port)
        wait_until(lambda: input_records(manager, "tcp.1") > 0,
                   "the tcp input to ingest records")

        metrics = read_metrics(manager)
        assert metrics["fluentbit_memory_limit_bytes"] > 0
        assert 0 < metrics["fluentbit_memory_pressure"] < 0.5
        assert metrics["fluentbit_memory_state"] == STATE_NORMAL
        assert metrics["fluentbit_memory_paused_inputs"] == 0
    finally:
        manager.stop()


def test_usage_over_limit_pauses_every_input(tmp_path):
    tcp_port = find_available_port()
    manager = FluentBitManager(
        write_config(tmp_path, tcp_port,
                     {"memory.limit": "1M", "memory.check_interval": 0.1}))

    try:
        manager.start()
        wait_until(lambda: metric(manager, "fluentbit_memory_state") == STATE_REFUSE,
                   "the monitor to reach the refuse state")
        wait_until(lambda: metric(manager, "fluentbit_memory_paused_inputs") == 2,
                   "both inputs to be paused")

        assert input_paused(manager, "dummy.0") == 1
        assert input_paused(manager, "tcp.1") == 1
        assert metric(manager, "fluentbit_memory_pressure") > 1
        assert metric(manager, "fluentbit_memory_reclaims_total") >= 1

        # Paused inputs do not ingest: the counter must not move anymore.
        before = input_records(manager, "dummy.0")
        time.sleep(1)
        assert input_records(manager, "dummy.0") == before
    finally:
        manager.stop()


def test_throttle_pauses_local_inputs_before_network_servers(tmp_path):
    tcp_port = find_available_port()

    # First run: learn how much memory this pipeline uses on this host.
    manager = FluentBitManager(write_config(tmp_path, tcp_port))
    try:
        manager.start()
        wait_until(lambda: input_records(manager, "dummy.0") > 0,
                   "the dummy input to ingest records")
        time.sleep(1)
        usage = metric(manager, "fluentbit_memory_usage_bytes")
    finally:
        manager.stop()

    assert usage > 0

    # With a 50% reserve the monitor throttles at 50% of the limit and
    # refuses at 87.5%: place the measured usage in the middle of that band.
    limit = int(usage / 0.68)
    manager = FluentBitManager(
        write_config(tmp_path, tcp_port,
                     {"memory.limit": str(limit), "memory.spike_reserve": "50%",
                      "memory.check_interval": 0.1}))
    try:
        manager.start()
        wait_until(lambda: metric(manager, "fluentbit_memory_state") == STATE_THROTTLE,
                   "the monitor to reach the throttle state")
        wait_until(lambda: input_paused(manager, "dummy.0") == 1,
                   "the dummy input to be paused")

        assert metric(manager, "fluentbit_memory_paused_inputs") == 1
        assert input_paused(manager, "tcp.1") == 0

        # The network server keeps receiving data while throttled.
        send_tcp_line(tcp_port)
        wait_until(lambda: input_records(manager, "tcp.1") > 0,
                   "the tcp input to ingest records")
        assert metric(manager, "fluentbit_memory_state") == STATE_THROTTLE
    finally:
        manager.stop()
