"""Reject short collectd value parts and continue receiving valid datagrams."""
from pathlib import Path
import socket
import struct

import pytest
import yaml

from utils.test_service import FluentBitTestService


def part(kind, value):
    return struct.pack("!HH", kind, len(value) + 4) + value


@pytest.mark.parametrize("value", [b"", b"\x00"])
def test_collectd_short_value_part(tmp_path, value):
    types = tmp_path / "types.db"
    types.write_text("counter value:COUNTER:0:U\n")
    config = tmp_path / "collectd.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "collectd", "listen": "127.0.0.1",
                        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "typesdb": str(types)}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}],
        },
    }))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            address = ("127.0.0.1", service.flb_listener_port)
            sock.sendto(part(4, b"counter\0") + part(6, value), address)
            service.wait_for_condition(
                lambda: "data truncated" in Path(service.flb.log_file).read_text(),
                timeout=20, description="short value part rejected before reading count")
            payload = (part(0, b"test-host\0") + part(2, b"test-plugin\0") +
                       part(4, b"counter\0") + part(6, struct.pack("!HBQ", 1, 0, 42)))
            sock.sendto(payload, address)
            service.wait_for_condition(
                lambda: '"value":42' in Path(service.flb.log_file).read_text(),
                timeout=20, description="valid collectd record after short value part")
        assert service.flb.process.poll() is None
    finally:
        service.stop()
