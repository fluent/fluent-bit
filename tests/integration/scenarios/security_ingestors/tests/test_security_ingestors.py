"""Bounded nesting and recovery checks for network ingestion."""
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
    assert predicate(), "Timed out waiting for Fluent Bit"


@contextlib.contextmanager
def daemon(tmp_path, mode):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    plugin = mode.split("-")[0]
    address = str(tmp_path / "input.sock") if plugin == "unix_socket" else ("127.0.0.1", port)
    parser = tmp_path / "parsers.conf"
    parser.write_text("[PARSER]\n    Name json\n    Format json\n")
    input_config = {"name": plugin}
    if plugin == "unix_socket":
        input_config["socket_path"] = address
    else:
        input_config.update({"listen": "127.0.0.1", "port": port})
    if mode.endswith("-parser"):
        input_config.update({"format": "none", "parser": "json"})
    if plugin == "syslog":
        input_config.update({"mode": "tcp", "parser": "json"})
    config = {
        "service": {
            "flush": 0.1,
            "grace": 1,
            "parsers_file": str(parser),
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
        yield address, manager.process, log
    finally:
        manager.stop()


def send(mode, address, payload):
    plugin = mode.split("-")[0]
    if plugin in ("http", "splunk", "elasticsearch"):
        conn = http.client.HTTPConnection(*address, timeout=10)
        try:
            path = "/test"
            if plugin == "splunk":
                path = "/services/collector/event"
                payload = b'{"event":' + payload + b"}"
            elif plugin == "elasticsearch":
                path = "/_bulk"
                payload = b'{"index":{}}\n' + payload + b"\n"
            conn.request("POST", path, payload, {"Content-Type": "application/json"})
            response = conn.getresponse()
            response.read()
        finally:
            conn.close()
        return
    if plugin == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload + b"\n", address)
        return
    family = socket.AF_UNIX if plugin == "unix_socket" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(address)
        if plugin == "mqtt":
            # A regular MQTT CONNECT followed by a QoS 0 JSON publication.
            sock.sendall(b"\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04test")
            assert sock.recv(4)[0] == 0x20
            body = b"\x00\x01a" + payload
            length = len(body)
            encoded = bytearray()
            while True:
                digit = length % 128
                length //= 128
                encoded.append(digit | (0x80 if length else 0))
                if not length:
                    break
            sock.sendall(b"\x30" + bytes(encoded) + body)
        else:
            sock.sendall(payload if plugin == "forward" else payload + b"\n")


@pytest.mark.parametrize("mode", ["mqtt", "tcp-parser", "udp-parser", "tcp", "udp", "http",
                                 "splunk"])
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
        send(mode, address, nested)
        send(mode, address, b'{"marker":"after"}')
        wait_for(lambda: '"marker":"after"' in log.read_text())
        assert process.poll() is None
        # Parser inputs may preserve rejected JSON as a raw log string.
        assert '"nested":' not in log.read_text()


@pytest.mark.parametrize("kind", ["array", "map"])
def test_forward_log_depth_recovery(tmp_path, kind):
    def message(record):
        return b"\x93\xa4test\x01" + record
    def marker(value):
        return b"\x81\xa6marker" + bytes([0xa0 | len(value)]) + value
    nested = b"\x00"
    for _ in range(65):
        nested = (b"\x81\xa1k" if kind == "map" else b"\x91") + nested
    with daemon(tmp_path, "forward") as (address, process, log):
        send("forward", address, message(marker(b"before")))
        wait_for(lambda: '"marker":"before"' in log.read_text())
        send("forward", address, message(b"\x81\xa6nested" + nested))
        send("forward", address, message(marker(b"after")))
        wait_for(lambda: '"marker":"after"' in log.read_text())
        assert process.poll() is None
        assert '"nested":' not in log.read_text()
