import gzip
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

import pytest

from utils.test_service import FluentBitTestService


@pytest.fixture(scope="module")
def disconnect_library(tmp_path_factory):
    if sys.platform != "linux":
        pytest.skip("UDP disconnection injection requires Linux LD_PRELOAD")
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("UDP disconnection injection requires a C compiler")
    library = tmp_path_factory.mktemp("gelf-disconnect") / "disconnect.so"
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-Wall", "-Wextra", "-o", str(library),
         str(Path(__file__).with_name("disconnect_udp.c")), "-ldl"],
        check=True,
    )
    return library


@pytest.mark.parametrize("workers", [0, 2])
@pytest.mark.parametrize("compress,packet_size,fail_at,fail_reconnect", [
    (False, 1420, 0, 0),
    (False, 1420, 1, 0),
    (True, 1420, 0, 0),
    (True, 1420, 1, 0),
    (True, 32, 0, 0),
    (True, 32, 2, 0),
    (True, 32, 1, 0),
    (True, 32, 2, 1),
])
def test_udp_delivery_after_disconnect(tmp_path, disconnect_library,
                                       compress, packet_size, fail_at, fail_reconnect, workers):
    # Distinct input tags create separate flushes for the output workers.
    message = "gelf UDP recovery regression"
    expected_records = 8 if workers else 1
    inputs = "".join(f"""
[INPUT]
    Name dummy
    Tag test.{index}
    Samples 1
    Dummy {{"host":"test-host","short_message":"{message}","sequence":{index}}}
""" for index in range(expected_records))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(0.5)
        port = receiver.getsockname()[1]
        config = tmp_path / "gelf.conf"
        config.write_text(f"""
[SERVICE]
    Flush 0.2
    Grace 1
    HTTP_Server On
    HTTP_Listen 127.0.0.1
    HTTP_Port ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
    Scheduler.Base 1
    Scheduler.Cap 1
{inputs}
[OUTPUT]
    Name gelf
    Match *
    Host 127.0.0.1
    Port {port}
    Mode udp
    Workers {workers}
    Compress {str(compress).lower()}
    Packet_Size {packet_size}
    Retry_Limit False
""")
        preload = str(disconnect_library)
        if os.environ.get("LD_PRELOAD"):
            preload += ":" + os.environ["LD_PRELOAD"]
        service = FluentBitTestService(str(config), extra_env={
            "LD_PRELOAD": preload,
            "GELF_TEST_PORT": port,
            "GELF_TEST_FAIL_AT": fail_at,
            "GELF_TEST_FAIL_RECONNECT": fail_reconnect,
        })
        if workers:
            service.extra_env["GELF_TEST_SERIALIZE"] = "1"
        groups = {}
        delivered = set()
        payload = None
        try:
            service.start()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    packet, _ = receiver.recvfrom(65535)
                except socket.timeout:
                    continue
                if packet.startswith(b"\x1e\x0f"):
                    assert len(packet) > 12
                    message_id = packet[2:10]
                    sequence, count = packet[10:12]
                    assert sequence < count <= 128
                    parts = groups.setdefault(message_id, {})
                    parts[sequence] = packet[12:]
                    if len(parts) != count:
                        continue
                    payload = b"".join(parts[index] for index in range(count))
                else:
                    payload = packet
                if compress:
                    payload = gzip.decompress(payload)
                record = json.loads(payload)
                assert record["short_message"] == message
                assert record["host"] == "test-host"
                delivered.add(record["_sequence"])
                if len(delivered) == expected_records:
                    break
            assert delivered == set(range(expected_records))
        finally:
            service.stop()
        logs = Path(service.flb.log_file).read_text()
        assert logs.count("GELF test: disconnected UDP socket") == bool(fail_at)
        assert logs.count("GELF test: failed reconnect") == fail_reconnect
        if fail_at:
            assert "failed to flush chunk" in logs


def test_udp_skips_oversized_record(tmp_path):
    import random
    import string

    import requests

    random_source = random.Random(12345)
    oversized = "".join(random_source.choices(string.ascii_letters, k=20000))
    assert len(gzip.compress(oversized.encode())) > 128 * 32
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(0.5)
        config = tmp_path / "oversized.conf"
        config.write_text(f"""
[SERVICE]
    Flush 0.2
    Grace 1
    HTTP_Server On
    HTTP_Listen 127.0.0.1
    HTTP_Port ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
    Scheduler.Base 1
    Scheduler.Cap 1
[INPUT]
    Name http
    Listen 127.0.0.1
    Port ${{GELF_TEST_HTTP_PORT}}
[OUTPUT]
    Name gelf
    Match *
    Host 127.0.0.1
    Port {receiver.getsockname()[1]}
    Mode udp
    Workers 2
    Compress true
    Packet_Size 32
    Retry_Limit False
""")
        service = FluentBitTestService(
            str(config),
            pre_start=lambda service: service.allocate_port_env("GELF_TEST_HTTP_PORT"),
        )
        groups = {}
        delivered = []
        try:
            service.start()
            response = requests.post(
                f"http://127.0.0.1:{os.environ['GELF_TEST_HTTP_PORT']}/test",
                json=[{"host": "test-host", "short_message": message}
                      for message in ["before oversized", oversized, "after oversized"]],
                timeout=5,
            )
            assert response.status_code in (200, 201)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and len(delivered) < 2:
                try:
                    packet, _ = receiver.recvfrom(65535)
                except socket.timeout:
                    continue
                assert packet[:2] == b"\x1e\x0f"
                parts = groups.setdefault(packet[2:10], {})
                parts[packet[10]] = packet[12:]
                if len(parts) == packet[11]:
                    payload = b"".join(parts[index] for index in range(packet[11]))
                    delivered.append(json.loads(gzip.decompress(payload))["short_message"])
            assert delivered == ["before oversized", "after oversized"]
        finally:
            service.stop()
        logs = Path(service.flb.log_file).read_text()
        assert logs.count("message too big:") == 1
        assert "failed to flush chunk" not in logs
