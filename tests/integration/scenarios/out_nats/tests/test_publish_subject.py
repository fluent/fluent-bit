"""Verify publish subjects against a local TCP listener, without a NATS server."""
import json
import os
from pathlib import Path
import socket
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager
from utils.memory_check import memory_check_enabled


@pytest.mark.parametrize("tag,valid,action", [
    ("app.events", True, None), ("app-é", True, None),
    ("app reply", False, None), ("app\t100", False, None),
    ("app\r\nPING\r\n", False, None), ("app\nPING", False, None),
    ("app.*", False, None), ("app.>", False, None), (".app", False, None),
    ("app.", False, None), ("app..events", False, None), ("app\x7f", False, None),
    ("app.events", True, "reject"), ("app reply", False, "reject"),
    ("app.events", True, "encode"), ("app-é", True, "encode"),
    ("a%20b", True, "encode"),
    ("app reply", False, "encode"), ("app\r\nPING\r\nend", False, "encode"),
    ("app é", False, "encode"),
    ("app.*", False, "encode"), ("app..events", False, "encode"),
    ("_flb_encoded.617070", True, "encode"),
    pytest.param("a" * 4000, True, None, id="long-subject"),
    pytest.param("a" * 4096, True, None, id="oversized-subject"),
    pytest.param("a" * 4085, True, None, id="control-line-exact-limit"),
    pytest.param("a" * 4086, True, None, id="control-line-one-over-limit"),
    pytest.param("a" + " " * 1998 + "z", False, "encode", id="long-encoded-subject"),
    pytest.param("a" + " " * 2046 + "z", False, "encode", id="oversized-encoded-subject"),
    pytest.param("a" + " " * 2034 + "z", False, "encode", id="encoded-line-below-limit"),
    pytest.param("a" + " " * 2035 + "z", False, "encode", id="encoded-line-over-limit"),
])
def test_publish_subject(tmp_path, tag, valid, action):
    subject_size = (len("_flb_encoded.") + len(tag.encode()) * 2
                    if action == "encode" and (not valid or tag.startswith("_flb_encoded."))
                    else len(tag.encode()))
    # Large fixtures have a four-digit payload length: PUB + subject + size + CRLF.
    oversized = subject_size + 11 > 4096
    diagnostic_text = ("NATS publish control line exceeds 4096 bytes" if oversized
                       else "invalid NATS publish subject in tag")
    root = Path(__file__).resolve().parents[5]
    binary = os.environ.get("FLUENT_BIT_BINARY", str(root / "build/bin/fluent-bit"))
    if os.name == "nt" and not binary.endswith(".exe"):
        binary += ".exe"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        config = tmp_path / "nats.yaml"
        config.write_text(
            "service:\n  flush: 0.1\n  grace: 1\npipeline:\n  inputs:\n"
            "    - name: dummy\n      samples: 1\n      tag: " + json.dumps(tag) +
            "\n  outputs:\n    - name: nats\n      match: '*'\n"
            "      host: 127.0.0.1\n      port: " + str(listener.getsockname()[1]) + "\n" +
            ("      invalid_subject_action: " + action + "\n" if action else ""),
            encoding="utf-8")
        manager = FluentBitManager(str(config), binary_path=binary)
        try:
            manager.start(wait_for_ready=False)
            received = b""
            connected = False
            deadline = time.monotonic() + (15 if memory_check_enabled() else 5)
            while time.monotonic() < deadline:
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    diagnostic = Path(manager.log_file).read_text()
                    if diagnostic_text in diagnostic:
                        break
                    assert manager.process.poll() is None, diagnostic
                    continue
                connected = True
                with connection:
                    connection.settimeout(2)
                    while not received.endswith(b"]\r\n"):
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        received += chunk
                break
            if not oversized and (valid or action == "encode"):
                assert connected
                connect, publish, payload, end = received.split(b"\r\n")
                assert connect.startswith(b"CONNECT ")
                command, subject, size = publish.split(b" ")
                assert command == b"PUB"
                assert len(publish) + 2 <= 4096
                if action == "encode" and (not valid or tag.startswith("_flb_encoded.")):
                    assert subject == b"_flb_encoded." + tag.encode().hex().upper().encode()
                else:
                    assert subject == tag.encode()
                assert int(size) == len(payload)
                assert json.loads(payload)[0][1]["tag"] == tag
                assert end == b""
            else:
                assert diagnostic_text in Path(manager.log_file).read_text()
                assert not connected
        finally:
            manager.stop()


def test_invalid_subject_action(tmp_path):
    root = Path(__file__).resolve().parents[5]
    binary = os.environ.get("FLUENT_BIT_BINARY", str(root / "build/bin/fluent-bit"))
    if os.name == "nt" and not binary.endswith(".exe"):
        binary += ".exe"
    config = tmp_path / "invalid_action.yaml"
    config.write_text(
        "service:\n  flush: 0.1\npipeline:\n  inputs:\n"
        "    - name: dummy\n      samples: 1\n  outputs:\n"
        "    - name: nats\n      match: '*'\n"
        "      invalid_subject_action: passthrough\n",
        encoding="utf-8")
    manager = FluentBitManager(str(config), binary_path=binary)
    try:
        manager.start(wait_for_ready=False)
        manager.process.wait(timeout=120 if memory_check_enabled() else 30)
        assert "invalid value for invalid_subject_action: passthrough" in Path(manager.log_file).read_text()
        if not memory_check_enabled():
            assert manager.process.returncode != 0
    finally:
        manager.stop()
