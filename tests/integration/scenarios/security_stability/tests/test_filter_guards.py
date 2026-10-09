"""Small malformed records exercise filter bounds and recovery over Forward."""
from pathlib import Path
import socket
import struct

import pytest
import yaml

from utils.test_service import FluentBitTestService


def pack(value):
    """Encode only the small MessagePack fixture types used by these tests."""
    if value is None:
        return b"\xc0"
    if value is True:
        return b"\xc3"
    if value is False:
        return b"\xc2"
    if isinstance(value, int):
        return b"\xd3" + struct.pack("!q", value)
    if isinstance(value, str):
        data = value.encode()
        return b"\xd9" + bytes([len(data)]) + data
    if isinstance(value, bytes):
        return b"\xc4" + bytes([len(value)]) + value
    if isinstance(value, list):
        return bytes([0x90 + len(value)]) + b"".join(pack(item) for item in value)
    return bytes([0x80 + len(value)]) + b"".join(
        pack(key) + pack(item) for key, item in value.items())


@pytest.mark.parametrize("name,options,records", [
    ("modify", {"remove_wildcard": "prefix"},
     [{"": 1}, {"pre": 1}, {"prefix.match": 1}, {b"": 1}]),
    ("nest", {"operation": "lift", "nested_under": "nested", "add_prefix": "p."},
     [{"nested": {None: 1, 0: 2, "": 3, "valid": 4}}]),
    ("nest", {"operation": "lift", "nested_under": "nested", "remove_prefix": "prefix"},
     [{"nested": {"": 1, "pre": 2, "prefix.valid": 3, None: 4}}]),
    ("multiline", {"mode": "partial_message", "multiline.key_content": "log"},
     [{"log": "invalid-value", "partial_message": value, "partial_last": value,
       "partial_id": value} for value in [None, False, 1, {}, [], "", "t", "true-extra"]]),
])
def test_filter_malformed_keys_and_values(tmp_path, name, options, records):
    config = tmp_path / "guards.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "forward", "listen": "127.0.0.1",
                        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}],
            "filters": [{"name": name, "match": "test", **options}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}],
        },
    }))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        for record in [{"marker": "before"}, *records, {"marker": "after"}]:
            with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
                sock.sendall(pack(["test", 1700000000, record]))
            if "marker" in record:
                service.wait_for_condition(
                    lambda: record["marker"] in Path(service.flb.log_file).read_text(),
                    timeout=20, description="control record after malformed filter data")
        assert service.flb.process.poll() is None
    finally:
        service.stop()
