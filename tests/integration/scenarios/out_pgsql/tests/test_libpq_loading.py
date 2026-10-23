"""Exercise the runtime loader with real libpq and a local PostgreSQL wire peer."""

import ctypes
import ctypes.util
import os
from pathlib import Path
import queue
import re
import shutil
import socketserver
import struct
import subprocess
import sys
import threading

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError


@pytest.fixture(scope="module", autouse=True)
def require_pgsql_output():
    """Skip before starting peers or looking for libpq when the plugin is omitted."""
    binary = FluentBitManager().binary_absolute_path
    result = subprocess.run([binary, "--help"], capture_output=True, text=True,
                            check=True, timeout=10)
    help_text = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + "\n" + result.stderr)
    outputs = re.search(r"(?ms)^Outputs\r?\n(.*?)(?:\n\s*\n|\Z)", help_text)
    assert outputs is not None, f"Cannot find the output plugin list in {binary} --help"
    if not re.search(r"(?m)^\s+pgsql\s", outputs.group(1)):
        pytest.skip("pgsql output is not compiled into the selected Fluent Bit binary")


def packet(kind, payload):
    return kind + struct.pack("!I", len(payload) + 4) + payload


class PostgreSQLPeer(socketserver.StreamRequestHandler):
    def handle(self):
        def read_exact(size):
            data = self.rfile.read(size)
            if len(data) != size:
                raise EOFError
            return data

        try:
            size = struct.unpack("!I", read_exact(4))[0]
            startup = read_exact(size - 4)
            # Decline SSL/GSS negotiation so the test needs no certificates.
            while startup in (struct.pack("!I", 80877103), struct.pack("!I", 80877104)):
                self.wfile.write(b"N")
                size = struct.unpack("!I", read_exact(4))[0]
                startup = read_exact(size - 4)
            self.wfile.write(
                packet(b"R", struct.pack("!I", 0))
                + packet(b"S", b"server_version\x0018.0\x00")
                + packet(b"S", b"client_encoding\x00UTF8\x00")
                + packet(b"S", b"standard_conforming_strings\x00on\x00")
                + packet(b"Z", b"I")
            )
            while True:
                kind = read_exact(1)
                size = struct.unpack("!I", read_exact(4))[0]
                payload = read_exact(size - 4)
                if kind == b"X":
                    return
                assert kind == b"Q"
                query_text = payload.rstrip(b"\0").decode()
                self.server.queries.put(query_text)
                if self.server.reject_create and query_text.startswith("CREATE"):
                    response = packet(b"E", b"SERROR\x00C42501\x00Mpermission denied\x00\x00")
                else:
                    tag = b"CREATE TABLE\0" if query_text.startswith("CREATE") else b"INSERT 0 1\0"
                    response = packet(b"C", tag)
                self.wfile.write(response + packet(b"Z", b"I"))
        except (EOFError, ConnectionResetError, BrokenPipeError):
            pass


@pytest.fixture
def peer():
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), PostgreSQLPeer) as server:
        server.daemon_threads = True
        server.queries = queue.Queue()
        server.reject_create = False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=5)


@pytest.fixture
def libpq_path():
    configured = os.environ.get("TEST_LIBPQ_PATH")
    if configured:
        return str(Path(configured).resolve())
    name = ctypes.util.find_library("pq")
    if not name:
        pytest.fail("Install libpq or set TEST_LIBPQ_PATH to run loader coverage")
    if sys.platform.startswith("linux"):
        # Resolve the real system library independently of the plugin under test.
        handle = ctypes.CDLL(name)
        assert handle.PQstatus
        for line in Path("/proc/self/maps").read_text().splitlines():
            path = line.split()[-1]
            if Path(path).name.startswith("libpq.so") and Path(path).is_file():
                return path
    pytest.fail("Set TEST_LIBPQ_PATH to an absolute libpq path on this platform")


def manager(tmp_path, peer, library=None, asynchronous=False, copies=1):
    output = {"name": "pgsql", "match": "*", "host": "127.0.0.1",
              "port": peer.server_address[1], "user": "test", "database": "test",
              "async": asynchronous}
    if library is not None:
        output["libpq_path"] = str(library)
    config = {
        "service": {"flush": 0.2, "grace": 1, "log_level": "debug",
                    "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "tag": "loader", "samples": 1,
                        "dummy": '{"message":"libpq loader regression"}'}],
            "outputs": [dict(output) for _ in range(copies)],
        },
    }
    path = tmp_path / "pgsql.yaml"
    path.write_text(yaml.safe_dump(config))
    return FluentBitManager(str(path), shutdown_timeout=30)


@pytest.mark.parametrize("mode", ["default", "absolute", "soname", "search_path", "two_outputs"])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_load_and_flush(tmp_path, peer, libpq_path, monkeypatch, mode, asynchronous):
    library = None
    if mode in ("absolute", "two_outputs"):
        library = libpq_path
    elif mode == "soname":
        library = Path(libpq_path).name
    elif mode == "search_path":
        if not sys.platform.startswith("linux"):
            pytest.skip("LD_LIBRARY_PATH coverage is Linux-specific")
        library = "libpq-test-private.so"
        (tmp_path / library).symlink_to(libpq_path)
        monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path) + ":" + os.environ.get("LD_LIBRARY_PATH", ""))
    copies = 2 if mode == "two_outputs" else 1
    flb = manager(tmp_path, peer, library, asynchronous, copies)
    try:
        flb.start()
        queries = [peer.queries.get(timeout=30) for _ in range(2 * copies)]
        inserts = [query for query in queries if query.startswith("INSERT")]
        assert len(inserts) == copies
        assert all("libpq loader regression" in query and "loader" in query for query in inserts)
        assert sum(query.startswith("CREATE TABLE") for query in queries) == copies
    finally:
        flb.stop()
    assert "loaded libpq" in Path(flb.log_file).read_text()


@pytest.mark.parametrize("failure", ["missing", "empty", "invalid", "symbol", "connection", "query"])
def test_loading_failure(tmp_path, peer, libpq_path, failure):
    library = tmp_path / "does-not-exist.so"
    expected = "cannot load libpq"
    if failure == "empty":
        library = ""
        expected = "libpq_path must not be empty"
    elif failure == "invalid":
        library = tmp_path / "invalid.so"
        library.write_text("not a shared object")
    elif failure == "symbol":
        compiler = shutil.which("cc")
        assert compiler, "A C compiler is required for missing-symbol coverage"
        source = tmp_path / "incomplete.c"
        source.write_text("void *PQsetdbLogin(void) { return 0; }\n")
        library = tmp_path / "incomplete.so"
        subprocess.run([compiler, "-shared", "-fPIC", str(source), "-o", str(library)], check=True)
        expected = "is missing symbol PQstatus"
    elif failure == "connection":
        library = libpq_path
        # A listening socket that is closed before initialization refuses connections.
        peer.shutdown()
        peer.server_close()
        expected = "failed connecting"
    elif failure == "query":
        library = libpq_path
        peer.reject_create = True
        expected = "permission denied"
    flb = manager(tmp_path, peer, library)
    try:
        with pytest.raises(FluentBitStartupError, match="exited early"):
            flb.start()
        assert flb.process.returncode != 0
        assert expected in Path(flb.log_file).read_text()
    finally:
        flb.stop()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="ELF and LD_LIBRARY_PATH coverage")
def test_no_link_dependency(tmp_path, peer, monkeypatch):
    # A broken default library must not prevent unrelated pipelines from starting.
    (tmp_path / "libpq.so.5").write_text("not a shared object")
    monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path))
    flb = manager(tmp_path, peer)
    config_path = Path(flb.config_path)
    config = yaml.safe_load(config_path.read_text())
    config["pipeline"]["outputs"] = [{"name": "null", "match": "*"}]
    config_path.write_text(yaml.safe_dump(config))
    try:
        flb.start()
    finally:
        flb.stop()
    assert peer.queries.empty()
    readelf = shutil.which("readelf")
    assert readelf, "readelf is required for dependency regression coverage"
    dynamic = subprocess.check_output([readelf, "-d", flb.binary_absolute_path], text=True)
    assert not any("NEEDED" in line and "libpq" in line for line in dynamic.splitlines())
