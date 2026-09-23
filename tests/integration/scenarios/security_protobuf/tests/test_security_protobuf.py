"""Reject excessive protobuf nesting before allocating decoded requests."""
import contextlib
import http.client
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

import pytest


def wait_for(predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    assert predicate(), "Timed out waiting for Fluent Bit"


@contextlib.contextmanager
def daemon(tmp_path, plugin):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    log = tmp_path / "fluent-bit.log"
    memlog = tmp_path / "valgrind.log"
    binary = os.environ["FLUENT_BIT_BINARY"]
    command = [binary, "-f", "0.1", "-i", plugin, "-p", "listen=127.0.0.1",
               "-p", f"port={port}", "-o", "stdout", "-m", "*"]
    if plugin == "opentelemetry":
        command += ["-p", "format=json"]
    memory = os.environ.get("VALGRIND") == "1"
    if memory:
        command = ["valgrind", "--leak-check=full", "--show-leak-kinds=all",
                   "--errors-for-leak-kinds=definite,indirect", "--error-exitcode=99",
                   f"--log-file={memlog}"] + command
    with log.open("w") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        def ready():
            assert process.poll() is None, log.read_text()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return True
            except OSError:
                return False
        try:
            wait_for(ready)
            yield port, process, log
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                pytest.fail("Fluent Bit did not shut down cleanly")
            assert process.returncode == 0, log.read_text() + (memlog.read_text() if memory else "")
            if memory:
                assert "ERROR SUMMARY: 0 errors" in memlog.read_text(), memlog.read_text()

def field(number, payload):
    def varint(value):
        data = bytearray()
        while value > 127:
            data.append((value & 127) | 128)
            value >>= 7
        data.append(value)
        return bytes(data)
    return varint(number * 8 + 2) + varint(len(payload)) + payload



def request(depth, shape):
    value = field(1, b"leaf")
    for index in range(depth):
        if shape == "map" or (shape == "mixed" and index % 2):
            value = field(6, field(1, field(1, b"k") + field(2, value)))
        else:
            value = field(5, field(1, value))
    return field(1, field(2, field(2, field(5, value))))


@pytest.mark.parametrize("shape", ["array", "map", "mixed"])
def test_protobuf_depth_recovery(tmp_path, shape):
    path = "/v1/logs"
    with daemon(tmp_path, "opentelemetry") as (port, process, log):
        def post(payload):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
            try:
                conn.request("POST", path, payload, {"Content-Type": "application/x-protobuf"})
                response = conn.getresponse()
                response.read()
                return response.status
            finally:
                conn.close()
        assert post(request(3, shape)) in (200, 201)
        assert post(request(55, shape)) >= 400
        assert post(request(3, shape)) in (200, 201)
        assert process.poll() is None
