"""Functional coverage for private Unix socket staging and publication."""
import contextlib
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile

import pytest

from test_unix_socket_decode_status import wait_for
from utils.valgrind import assert_valgrind_clean


def command_for(tmp_path, plugin, address, permissions=True):
    parser = tmp_path / "parsers.conf"
    parser.write_text("[PARSER]\n    Name json\n    Format json\n")
    name = plugin.split("-")[0]
    command = [os.environ["FLUENT_BIT_BINARY"], "-f", "0.1", "-R", str(parser), "-i", name]
    if name == "unix_socket":
        command += ["-p", f"socket_path={address}"]
        if permissions:
            command += ["-p", "socket_permissions=0600"]
    else:
        path_option = "path" if name == "syslog" else "unix_path"
        command += ["-p", f"{path_option}={address}", "-p", "unix_perm=0600"]
    if name == "syslog":
        mode = "unix_udp" if plugin.endswith("dgram") else "unix_tcp"
        command += ["-p", f"mode={mode}", "-p", "parser=json"]
    command += ["-o", "stdout", "-m", "*", "-p", "format=json_lines"]
    if os.environ.get("VALGRIND") == "1":
        # A forked bind helper inherits live parent allocations and exits without cleanup.
        # Preserve its exit status and check the parent report strictly after shutdown.
        command = ["valgrind", "--leak-check=full", "--show-leak-kinds=all",
                   "--errors-for-leak-kinds=definite,indirect,possible",
                   "--child-silent-after-fork=yes", f"--log-file={tmp_path / 'memory.log'}"] + command
    return command


def check_memory(tmp_path):
    if os.environ.get("VALGRIND") == "1":
        log = (tmp_path / "memory.log").read_text()
        assert "ERROR SUMMARY: 0 errors" in log, log
        assert_valgrind_clean(tmp_path / "memory.log")


@contextlib.contextmanager
def running(tmp_path, plugin, address, *, mask=0o022, permissions=True):
    log = tmp_path / "fluent-bit.log"
    with log.open("w") as output:
        process = subprocess.Popen(command_for(tmp_path, plugin, address, permissions),
                                   stdout=output, stderr=subprocess.STDOUT, umask=mask)
        try:
            def ready():
                assert process.poll() is None, log.read_text()
                return "[output:stdout:" in log.read_text()
            wait_for(ready)
            yield log
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                pytest.fail("Fluent Bit did not stop")
            assert process.returncode == 0, log.read_text()
            check_memory(tmp_path)


def deliver(plugin, address, log):
    kind = socket.SOCK_DGRAM if plugin.endswith("dgram") else socket.SOCK_STREAM
    payload = (b"\x93\xa4test\x01\x81\xa6marker\xa8received"
               if plugin == "forward" else b'{"marker":"received"}\n')
    with socket.socket(socket.AF_UNIX, kind) as client:
        client.settimeout(5)
        client.connect(str(address))
        client.sendall(payload)
    wait_for(lambda: '"marker":"received"' in log.read_text())


@pytest.mark.parametrize("plugin", ["forward", "syslog-stream", "syslog-dgram", "unix_socket"])
@pytest.mark.parametrize("case", ["restrictive_umask", "long_path"])
def test_staged_socket_receives_data(tmp_path, plugin, case):
    # Keep the fixture root short so the boundary path fits on Linux and macOS.
    with tempfile.TemporaryDirectory(prefix="fb-", dir="/tmp") as directory:
        parent = Path(directory)
        if case == "long_path":
            limit = 103 if sys.platform == "darwin" else 107
            parent /= "p" * (limit - len(directory) - 3)
            parent.mkdir()
        address = parent / "s"
        with running(tmp_path, plugin, address,
                     mask=0o177 if case == "restrictive_umask" else 0o022) as log:
            assert stat.S_ISSOCK(address.stat().st_mode)
            assert stat.S_IMODE(address.stat().st_mode) == 0o600
            deliver(plugin, address, log)
            assert not list(parent.glob(".fb-*"))
        if plugin == "unix_socket":
            assert not address.exists()


def test_unix_socket_without_permissions(tmp_path):
    address = tmp_path / "s"
    with running(tmp_path, "unix_socket", address, permissions=False) as log:
        deliver("unix_socket", address, log)
    assert not address.exists()


@pytest.mark.parametrize("permissions", [False, True])
@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_unix_socket_preserves_active_listener(tmp_path, permissions, kind):
    address = tmp_path / "s"
    with socket.socket(socket.AF_UNIX, kind) as listener:
        listener.bind(str(address))
        if kind == socket.SOCK_STREAM:
            listener.listen(8)
        original = address.stat()
        command = command_for(tmp_path, "unix_socket", address, permissions)
        # Options following an output apply to that output, so insert before -o.
        index = command.index("-o")
        command[index:index] = ["-p", f"socket_mode={'STREAM' if kind == socket.SOCK_STREAM else 'DGRAM'}"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert result.returncode not in (0, 99), result.stderr
        assert "could not remove existing unix socket" in result.stderr, result.stderr
        assert address.stat().st_ino == original.st_ino
        with socket.socket(socket.AF_UNIX, kind) as client:
            client.settimeout(5)
            client.connect(str(address))
        assert not list(tmp_path.glob(".fb-*"))
        check_memory(tmp_path)


def test_unix_socket_replaces_stale_socket(tmp_path):
    address = tmp_path / "s"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
        stale.bind(str(address))
    with running(tmp_path, "unix_socket", address) as log:
        deliver("unix_socket", address, log)
    assert not address.exists()


def test_unix_socket_teardown_preserves_replacement(tmp_path):
    address = tmp_path / "s"
    with running(tmp_path, "unix_socket", address):
        address.unlink()
        address.write_text("replacement")
    assert address.read_text() == "replacement"
