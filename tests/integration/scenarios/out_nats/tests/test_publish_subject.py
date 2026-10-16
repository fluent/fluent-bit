"""Verify publish subjects against a local TCP listener, without a NATS server."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time

import pytest


@pytest.mark.parametrize("tag,valid", [
    ("app.events", True), ("app-é", True),
    ("app reply", False), ("app\t100", False),
    ("app\r\nPING\r\n", False), ("app\nPING", False),
    ("app.*", False), ("app.>", False), (".app", False),
    ("app.", False), ("app..events", False), ("app\x7f", False),
])
def test_publish_subject(tmp_path, tag, valid):
    if os.environ.get("VALGRIND") or os.environ.get("LEAKS"):
        pytest.fail("This direct-process scenario does not yet support memory-checker wrapping")
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
            "      host: 127.0.0.1\n      port: " + str(listener.getsockname()[1]) + "\n",
            encoding="utf-8")
        with (tmp_path / "stderr").open("w+") as log:
            process = subprocess.Popen([binary, "-c", str(config)],
                                       stdout=log, stderr=log)
            received = b""
            connected = False
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        log.seek(0)
                        diagnostic = log.read()
                        if "invalid NATS publish subject in tag" in diagnostic:
                            break
                        assert process.poll() is None, diagnostic
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
                if valid:
                    assert connected
                    connect, publish, payload, end = received.split(b"\r\n")
                    assert connect.startswith(b"CONNECT ")
                    command, subject, size = publish.split(b" ")
                    assert command == b"PUB"
                    assert subject == tag.encode()
                    assert int(size) == len(payload)
                    assert json.loads(payload)[0][1]["tag"] == tag
                    assert end == b""
                else:
                    log.seek(0)
                    assert "invalid NATS publish subject in tag" in log.read()
                    assert not connected
            finally:
                process.terminate()
                process.wait(timeout=10)
