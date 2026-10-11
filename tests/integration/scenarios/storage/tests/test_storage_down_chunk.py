"""Regression coverage for filesystem chunk placement at max_chunks_up (#12402)."""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mmap
from pathlib import Path
import threading
import time

import pytest
import requests
import yaml

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port


def wait_until(predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail(f"Timed out waiting for {description}")


@pytest.mark.parametrize("limit", [None, 1024 * 1024, 4 * mmap.PAGESIZE],
                         ids=["unlimited", "below-limit", "eviction"])
@pytest.mark.parametrize("routes", [1, 2], ids=["single-route", "fan-out"])
def test_down_chunk_placement(tmp_path, limit, routes):
    release = threading.Event()
    entered = [threading.Event() for _ in range(routes)]
    received = [[] for _ in range(routes)]
    lock = threading.Lock()

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            records = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            route = int(self.path[1:])
            entered[route].set()
            if not release.wait(90):
                return
            with lock:
                received[route].extend(record["id"] for record in records)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    input_port = find_available_port()
    storage = tmp_path / "storage"
    output = {
        "name": "http", "match": "*", "host": "127.0.0.1",
        "port": sink.server_port, "format": "json", "json_date_key": False,
        "workers": 1, "retry_limit": False, "net.io_timeout": 120,
    }
    if limit is not None:
        output["storage.total_limit_size"] = limit
    config = {
        "service": {
            "flush": 0.1, "grace": 1, "log_level": "debug",
            "storage.path": str(storage), "storage.max_chunks_up": 1,
            "storage.metrics": True, "http_server": True,
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{"name": "http", "listen": "127.0.0.1",
                        "port": input_port, "storage.type": "filesystem"}],
            "outputs": [dict(output, uri=f"/{route}") for route in range(routes)],
        },
    }
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config))
    manager = FluentBitManager(str(config_path))

    def send(record_id, tag_id=None):
        if tag_id is None:
            tag_id = record_id
        # A distinct tag forces a new chunk; the response synchronizes ingestion.
        response = requests.post(
            f"http://127.0.0.1:{input_port}/chunk.{tag_id}",
            json={"id": record_id}, timeout=15,
        )
        assert response.status_code == 201, response.text

    try:
        manager.start()
        send(0)
        for event in entered:
            assert event.wait(30), "The sink never received the first chunk"
        # The first HTTP request keeps the only permitted up chunk busy.
        for record_id in range(1, 7):
            send(record_id)
        # Reuse the newest down chunk as well as creating down chunks.
        send(7, tag_id=6)

        def has_down_chunks():
            response = requests.get(
                f"http://127.0.0.1:{manager.http_monitoring_port}/api/v1/storage",
                timeout=5,
            )
            if response.status_code != 200:
                return False
            chunks = response.json()["storage_layer"]["chunks"]
            return chunks["fs_chunks_up"] == 1 and chunks["fs_chunks_down"] > 0

        wait_until(has_down_chunks, "the up quota to remain saturated with down chunks")
        log = Path(manager.log_file).read_text()
        assert "cannot mmap/read chunk" not in log, log
        assert "no available chunk" not in log, log
        if limit == 4 * mmap.PAGESIZE:
            assert "evicted" in log, log
            assert sum(p.stat().st_size for p in storage.glob("*/*.flb")) <= limit
        else:
            assert "evicted" not in log, log
            assert len(list(storage.glob("*/*.flb"))) == 7

        release.set()
        expected = {0, 6, 7} if limit == 4 * mmap.PAGESIZE else set(range(8))

        def drained():
            with lock:
                return all(expected.issubset(records) for records in received)

        wait_until(drained, "buffered records to drain on every route")
        wait_until(lambda: not list(storage.glob("*/*.flb")), "chunks to be released")
        with lock:
            for records in received:
                assert all(count == 1 for count in Counter(records).values())
                if limit != 4 * mmap.PAGESIZE:
                    assert set(records) == expected
    finally:
        release.set()
        try:
            manager.stop()
        finally:
            sink.shutdown()
            sink.server_close()
            thread.join(timeout=5)
