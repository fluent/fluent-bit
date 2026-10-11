"""Regression coverage for empty stream frames and RFC 6587 length validation."""
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

import pytest


def wait_for(predicate):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    assert predicate(), "Timed out waiting for Fluent Bit"


@contextlib.contextmanager
def daemon(tmp_path, mode, framing):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    address = str(tmp_path / "syslog.sock") if mode == "unix_tcp" else ("127.0.0.1", port)
    parser = tmp_path / "parsers.conf"
    parser.write_text("[PARSER]\n    Name passthrough\n    Format regex\n    Regex ^(?<message>.*)$\n")
    binary = os.environ.get("FLUENT_BIT_BINARY", str(Path(__file__).resolve().parents[5] / "build/bin/fluent-bit"))
    command = [binary, "-f", "0.1", "-R", str(parser), "-i", "syslog",
               "-p", f"mode={mode}", "-p", "parser=passthrough", "-p", f"format={framing}"]
    if mode == "unix_tcp":
        command += ["-p", f"path={address}"]
    else:
        command += ["-p", "listen=127.0.0.1", "-p", f"port={port}"]
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
            yield address, log
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


def connect(mode, address):
    sock = socket.socket(socket.AF_UNIX if mode == "unix_tcp" else socket.AF_INET)
    sock.settimeout(10)
    sock.connect(address)
    return sock


def messages(log):
    return [json.loads(line)["message"] for line in log.read_text().splitlines()
            if line.startswith("{")]


@pytest.mark.parametrize("mode", ["tcp", "unix_tcp"])
@pytest.mark.parametrize("delimiter", [b"\n", b"\0"])
def test_empty_delimiters(tmp_path, mode, delimiter):
    with daemon(tmp_path, mode, "newline") as (address, log):
        with connect(mode, address) as sock:
            sock.sendall(delimiter * 2 + b"first" + delimiter * 3 + b"second" + delimiter + b"par")
            wait_for(lambda: "second" in messages(log))
            sock.sendall(b"tial" + delimiter * 2)
            wait_for(lambda: "partial" in messages(log))
    assert messages(log) == ["first", "second", "partial"]


@pytest.mark.parametrize("mode", ["tcp", "unix_tcp"])
@pytest.mark.parametrize("prefix", [b"0 ", b" ", b"00 ", b"01 "])
def test_invalid_octet_length_closes_connection(tmp_path, mode, prefix):
    with daemon(tmp_path, mode, "octet_counting") as (address, log):
        with connect(mode, address) as sock:
            sock.sendall(b"5 hello" + prefix + b"7 goodbye")
            # A malformed frame must close the stream, not leave a silent sink.
            assert sock.recv(1) == b""
        wait_for(lambda: messages(log) == ["hello"])
        with connect(mode, address) as sock:
            sock.sendall(b"5 world")
            wait_for(lambda: "world" in messages(log))
    assert messages(log) == ["hello", "world"]


@pytest.mark.parametrize("mode", ["tcp", "unix_tcp"])
def test_fragmented_octet_frames(tmp_path, mode):
    with daemon(tmp_path, mode, "octet_counting") as (address, log):
        with connect(mode, address) as sock:
            sock.sendall(b"5 hello1")
            wait_for(lambda: messages(log) == ["hello"])
            sock.sendall(b"1 hello world5 wo")
            wait_for(lambda: "hello world" in messages(log))
            sock.sendall(b"rld")
            wait_for(lambda: "world" in messages(log))
    assert messages(log) == ["hello", "hello world", "world"]
