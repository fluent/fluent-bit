"""Records accepted into filesystem chunks must survive a restart.

The chunks are written and never flushed: the process is stopped, or killed,
while they are still open for appends. With ``storage.max_chunks_up 1`` all
tags but one append to chunks that are down.
"""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import signal
import threading
import time

import pytest
import requests
import yaml

from utils.fluent_bit_manager import FluentBitManager
from utils.memory_check import memory_check_enabled
from utils.network import find_available_port

TAGS = 3
ROUNDS = 20


def wait_until(predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail(f"Timed out waiting for {description}")


def start_sink(release, received, lock):
    class Sink(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if release.is_set():
                with lock:
                    received.extend(record["id"] for record in json.loads(body))
            self.send_response(200 if release.is_set() else 503)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    return sink, thread


def write_config(path, storage, input_port, sink_port, checksum, max_chunks_up, flush):
    path.write_text(yaml.safe_dump({
        "service": {
            "flush": flush, "grace": 1, "log_level": "debug",
            "storage.path": str(storage), "storage.checksum": checksum,
            "storage.max_chunks_up": max_chunks_up,
            "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{"name": "http", "listen": "127.0.0.1", "port": input_port,
                        "storage.type": "filesystem"}],
            "outputs": [{"name": "http", "match": "*", "host": "127.0.0.1",
                         "port": sink_port, "format": "json", "json_date_key": False,
                         "retry_limit": False}],
        },
    }))


@pytest.mark.parametrize("shutdown", ["graceful", "crash"])
@pytest.mark.parametrize("max_chunks_up", [128, 1], ids=["chunks-up", "chunks-down"])
@pytest.mark.parametrize("checksum", [False, True], ids=["no-checksum", "checksum"])
def test_unflushed_chunks_survive_restart(tmp_path, checksum, max_chunks_up, shutdown):
    if shutdown == "crash" and not hasattr(signal, "SIGKILL"):
        pytest.skip("requires POSIX SIGKILL")
    if shutdown == "crash" and memory_check_enabled():
        pytest.skip("SIGKILL prevents the memory checker from producing its final summary")
    release = threading.Event()
    received = []
    lock = threading.Lock()
    sink, thread = start_sink(release, received, lock)
    storage = tmp_path / "storage"
    config = tmp_path / "fluent-bit.yaml"
    input_port = find_available_port()
    # Nothing is flushed before the process stops: every chunk stays open.
    write_config(config, storage, input_port, sink.server_port, checksum, max_chunks_up, 60)
    manager = FluentBitManager(str(config))
    expected = list(range(TAGS * ROUNDS))
    try:
        manager.start()
        for record_id in expected:
            # The response is sent after the record was appended to its chunk.
            response = requests.post(
                f"http://127.0.0.1:{input_port}/tag.{record_id % TAGS}",
                json={"id": record_id}, timeout=15,
            )
            assert response.status_code == 201, response.text
        if shutdown == "crash":
            manager.send_signal(signal.SIGKILL)
            manager.process.wait(timeout=5)
        manager.stop()
        assert len(list(storage.glob("*/*.flb"))) == TAGS

        release.set()
        write_config(config, storage, input_port, sink.server_port, checksum, max_chunks_up,
                     0.2)
        manager.start()

        def drained():
            with lock:
                return set(expected).issubset(received)

        wait_until(drained, "every accepted record to reach the output")
        wait_until(lambda: not list(storage.glob("*/*.flb")), "chunk deletion after delivery")
        log = Path(manager.log_file).read_text()
        assert "invalid crc32" not in log, log
        assert "format check failed" not in log, log
        with lock:
            assert all(count == 1 for count in Counter(received).values())
            assert sorted(received) == expected
    finally:
        manager.stop()
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=5)
