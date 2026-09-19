"""Bounded nesting and recovery checks for network ingestion."""
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
def daemon(tmp_path, mode):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    plugin = mode.split("-")[0]
    address = str(tmp_path / "input.sock") if plugin == "unix_socket" else ("127.0.0.1", port)
    parser = tmp_path / "parsers.conf"
    parser.write_text("[PARSER]\n    Name json\n    Format json\n")
    command = [os.environ["FLUENT_BIT_BINARY"], "-f", "0.1", "-R", str(parser), "-i", plugin]
    if plugin == "unix_socket":
        command += ["-p", f"socket_path={address}"]
    else:
        command += ["-p", "listen=127.0.0.1", "-p", f"port={port}"]
    if mode.endswith("-parser"):
        command += ["-p", "format=none", "-p", "parser=json"]
    if plugin == "syslog":
        command += ["-p", "mode=tcp", "-p", "parser=json"]
    command += ["-o", "stdout", "-m", "*", "-p", "format=json_lines"]
    log = tmp_path / "fluent-bit.log"
    memlog = tmp_path / "valgrind.log"
    memory = os.environ.get("VALGRIND") == "1"
    if memory:
        command = ["valgrind", "--leak-check=full", "--show-leak-kinds=all",
                   "--errors-for-leak-kinds=definite,indirect", "--error-exitcode=99",
                   f"--log-file={memlog}"] + command
    with log.open("w") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        def ready():
            assert process.poll() is None, log.read_text()
            return "[output:stdout:" in log.read_text()
        try:
            wait_for(ready)
            yield address, process, log
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
            return response.status
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
        # Parser inputs may preserve rejected JSON as a raw log string.
        assert '"nested":' not in log.read_text()
