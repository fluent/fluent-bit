import json
from pathlib import Path
import socket
import struct

import pytest

from utils.test_service import FluentBitTestService
from utils.fluent_bit_manager import fluent_bit_input_supports_config_property


@pytest.fixture(autouse=True, scope="module")
def require_collectd_input():
    if not fluent_bit_input_supports_config_property("collectd", "typesdb"):
        pytest.skip("This Fluent Bit build does not include the collectd input")


def part(kind, payload):
    return struct.pack("!HH", kind, len(payload) + 4) + payload


def packet(padding, high_resolution):
    timestamp = 1700000000
    interval = 10
    scale = 1 << 30 if high_resolution else 1
    return b"".join([
        part(0xFFFF, bytes(padding)),
        part(0, b"hi\0"),
        part(8 if high_resolution else 1, struct.pack("!Q", timestamp * scale)),
        part(9 if high_resolution else 7, struct.pack("!Q", interval * scale)),
        part(4, b"mixed\0"),
        part(5, str(padding).encode() + b"\0"),
        part(6, struct.pack("!H", 4) + bytes([0, 1, 2, 3]) +
             struct.pack("!Q", 0x0102030405060708) +
             struct.pack("<d", 42.25) + struct.pack("!qQ", -42, 0xFEDCBA9876543210)),
    ])


@pytest.mark.parametrize("high_resolution", [False, True])
def test_unaligned_collectd_datagrams(tmp_path, high_resolution):
    typesdb = tmp_path / "types.db"
    typesdb.write_text("mixed counter:COUNTER:0:U, gauge:GAUGE:U:U, "
                       "derive:DERIVE:U:U, absolute:ABSOLUTE:0:U\n")
    output = tmp_path / "records.jsonl"
    config = tmp_path / "collectd.conf"
    service = FluentBitTestService(str(config))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config.write_text(f"""
[SERVICE]
    Flush 0.2
    Grace 1
    HTTP_Server On
    HTTP_Listen 127.0.0.1
    HTTP_Port ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
[INPUT]
    Name collectd
    Listen 127.0.0.1
    Port {port}
    TypesDB {typesdb}
    Tag collectd.test
[OUTPUT]
    Name file
    Match *
    Path {tmp_path}
    File {output.name}
    Format plain
""")

    def read_records():
        if not output.exists():
            return []
        # A flush may still be writing the final line.
        lines = output.read_bytes().split(b"\n")[:-1]
        return [json.loads(line) for line in lines]

    try:
        service.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            # Reject malformed lengths and value counts, then accept valid packets.
            malformed = [
                part(0, b"hi\0") + struct.pack("!HHQ", 1, 12, 1)[:-1],
                part(0, b"hi\0") + part(1, b"\0" * 7),
                part(0, b"hi\0") + struct.pack("!HH", 1, 3),
                part(4, b"mixed\0") + part(6, b"\0\x04\0"),
            ]
            for data in malformed:
                sender.sendto(data, ("127.0.0.1", port))
            for padding in range(8):
                sender.sendto(packet(padding, high_resolution), ("127.0.0.1", port))
        service.wait_for_condition(lambda: len(read_records()) == 8,
                                   timeout=20, interval=0.1,
                                   description="eight collectd records after malformed packets")
        assert service.flb.process.poll() is None
    finally:
        service.stop()

    records = read_records()
    assert len(records) == 8
    assert {record["type_instance"] for record in records} == {str(i) for i in range(8)}
    for record in records:
        assert record["type"] == "mixed"
        assert record["host"] == "hi"
        assert record["time"] == 1700000000
        assert record["interval"] == 10
        assert record["counter"] == 0x0102030405060708
        assert record["gauge"] == 42.25
        assert record["derive"] == -42
        assert record["absolute"] == 0xFEDCBA9876543210
    assert "netprot_to_msgpack fails" in Path(service.flb.log_file).read_text()
