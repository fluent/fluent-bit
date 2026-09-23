"""Reject malformed bulk payloads while keeping ingestion failures retryable."""
import contextlib
import http.client
import json
from pathlib import Path
import socket
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager


def wait_for(predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    assert predicate(), "Timed out waiting for Fluent Bit output"


@contextlib.contextmanager
def daemon(tmp_path, mode, input_options=None):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    input_config = {"name": mode, "listen": "127.0.0.1", "port": port}
    if input_options:
        input_config.update(input_options)
    config = {
        "service": {
            "flush": 0.1,
            "grace": 1,
            "http_server": "on",
            "http_listen": "127.0.0.1",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [input_config],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}],
        },
    }
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(json.dumps(config))
    manager = FluentBitManager(str(config_path))
    try:
        manager.start()
        log = Path(manager.log_file)
        yield ("127.0.0.1", port), manager.process, log
    finally:
        manager.stop()


def send(mode, address, payload):
    conn = http.client.HTTPConnection(*address, timeout=10)
    try:
        payload = b'{"index":{}}\n' + payload + b"\n"
        conn.request("POST", "/_bulk", payload, {"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


@pytest.mark.parametrize("mode", ["elasticsearch"])
@pytest.mark.parametrize("kind", ["array", "map", "mixed"])
def test_nested_json_recovery(tmp_path, mode, kind):
    # Bounded regression data, with no process-crash or exploit-chain behavior.
    value = b"0"
    for index in range(65):
        value = (b'{"k":' + value + b"}") if kind == "map" or (
            kind == "mixed" and index % 2) else b"[" + value + b"]"
    nested = b'{"nested":' + value + b"}"
    with daemon(tmp_path, mode) as (address, process, log):
        send(mode, address, b'{"marker":"before"}')
        wait_for(lambda: '"marker":"before"' in log.read_text())
        assert send(mode, address, nested) == 400
        send(mode, address, b'{"marker":"after"}')
        wait_for(lambda: '"marker":"after"' in log.read_text())
        assert process.poll() is None
        assert '"nested":' not in log.read_text()


@pytest.mark.parametrize("payload", [b'{"broken":', b'not-json', b'[]', b'42'])
def test_malformed_bulk_recovery(tmp_path, payload):
    with daemon(tmp_path, "elasticsearch") as (address, process, log):
        assert send("elasticsearch", address, payload) == 400
        assert send("elasticsearch", address, b'{"marker":"after"}') == 200
        wait_for(lambda: '"marker":"after"' in log.read_text())
        assert process.poll() is None


def test_busy_ingress_is_retryable(tmp_path):
    options = {"http_server.workers": 2, "http_server.ingress_queue_byte_limit": "128"}
    with daemon(tmp_path, "elasticsearch", options) as (address, process, log):
        assert send("elasticsearch", address, json.dumps({"large": "x" * 1024}).encode()) == 503
        assert send("elasticsearch", address, b'{"marker":"after"}') == 200
        wait_for(lambda: '"marker":"after"' in log.read_text())
        assert process.poll() is None
