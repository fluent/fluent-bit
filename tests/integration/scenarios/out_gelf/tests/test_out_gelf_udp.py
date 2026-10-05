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
                                       compress, packet_size, fail_at, fail_reconnect):
    # Emit exactly one record: delivery after a fault must come from a retry.
    message = "gelf UDP recovery regression"
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
[INPUT]
    Name dummy
    Samples 1
    Dummy {{"host":"test-host","short_message":"{message}"}}
[OUTPUT]
    Name gelf
    Match *
    Host 127.0.0.1
    Port {port}
    Mode udp
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
        groups = {}
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
                break
            assert payload is not None, "GELF record was not delivered after retry"
            if compress:
                payload = gzip.decompress(payload)
            record = json.loads(payload)
            assert record["short_message"] == message
            assert record["host"] == "test-host"
        finally:
            service.stop()
        logs = Path(service.flb.log_file).read_text()
        assert logs.count("GELF test: disconnected UDP socket") == bool(fail_at)
        assert logs.count("GELF test: failed reconnect") == fail_reconnect
        if fail_at:
            assert "failed to flush chunk" in logs
