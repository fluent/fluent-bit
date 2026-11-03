"""Filesystem allocation must follow the append and the final filtered payload."""

import json
import mmap
from pathlib import Path

import pytest
import requests
import yaml

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port


@pytest.fixture
def storage_pipeline(tmp_path):
    managers = []

    def start(filters=None, limit=None):
        port = find_available_port()
        storage = tmp_path / "storage"
        output = {"name": "null", "match": "*"}
        if limit is not None:
            output["storage.total_limit_size"] = limit
        config = {
            "service": {"flush": 60, "grace": 1, "log_level": "debug",
                        "storage.path": str(storage), "http_server": True,
                        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
            "pipeline": {
                "inputs": [{"name": "http", "listen": "127.0.0.1", "port": port,
                            "buffer_max_size": "4M", "storage.type": "filesystem"}],
                "filters": filters or [], "outputs": [output],
            },
        }
        path = tmp_path / "fluent-bit.yaml"
        path.write_text(yaml.safe_dump(config))
        manager = FluentBitManager(str(path))
        managers.append(manager)
        manager.start()

        def send(tag, record):
            response = requests.post(f"http://127.0.0.1:{port}/{tag}", json=record, timeout=30)
            assert response.status_code == 201, response.text

        return storage, manager, send

    yield start
    for manager in managers:
        manager.stop()


@pytest.mark.parametrize("payload_size", [256, 16384, 1024 * 1024])
def test_append_sized_creation(storage_pipeline, payload_size):
    storage, _, send = storage_pipeline()
    record = {"padding": "x" * payload_size}
    send("sized", record)
    chunks = list(storage.glob("*/*.flb"))
    assert len(chunks) == 1
    # JSON plus 128 bytes bounds MessagePack, timestamp and both headers here.
    upper_bound = ((len(json.dumps(record)) + 128 + mmap.PAGESIZE - 1)
                   // mmap.PAGESIZE) * mmap.PAGESIZE
    assert payload_size < chunks[0].stat().st_size <= upper_bound


def test_filter_expansion_respects_quota(storage_pipeline):
    storage, manager, send = storage_pipeline(
        [{"name": "modify", "match": "*", "add": "padding " + "x" * 5000}],
        10 * mmap.PAGESIZE,
    )
    send("first", {"id": 0})
    first = set(storage.glob("*/*.flb"))
    assert len(first) == 1
    send("second", {"id": 1})
    chunks = set(storage.glob("*/*.flb"))
    assert len(chunks) == 1
    assert not first.intersection(chunks), "The oldest chunk must make room for expanded data"
    assert sum(p.stat().st_size for p in chunks) <= 10 * mmap.PAGESIZE
    assert "evicted" in Path(manager.log_file).read_text()


@pytest.mark.parametrize("action", ["drop", "shrink"])
def test_filtered_payload_does_not_evict(storage_pipeline, action):
    following = ({"name": "grep", "exclude": "discard ^yes$"} if action == "drop"
                 else {"name": "modify", "remove": "padding"})
    storage, manager, send = storage_pipeline([dict(following, match="second")],
                                              10 * mmap.PAGESIZE)
    send("first", {"id": 0})
    first = set(storage.glob("*/*.flb"))
    assert len(first) == 1
    send("second", {"id": 1, "discard": "yes", "padding": "x" * 200000})
    chunks = set(storage.glob("*/*.flb"))
    assert first.issubset(chunks), "Filtering must happen before destructive quota placement"
    assert len(chunks) == (1 if action == "drop" else 2)
    assert "evicted" not in Path(manager.log_file).read_text()


def test_reused_chunk_budgets_adaptive_growth(storage_pipeline):
    if mmap.PAGESIZE != 4096:
        pytest.skip("This boundary case requires 4 KiB pages")
    storage, manager, send = storage_pipeline(limit=672 * 1024)
    send("target", {"padding": "x" * (256 * 1024 - 256)})
    target = next(storage.glob("*/*.flb"))
    assert target.stat().st_size == 256 * 1024
    send("filler", {"padding": "x" * (300 * 1024 - 256)})
    assert len(list(storage.glob("*/*.flb"))) == 2
    # Fixed prediction adds 32 KiB; adaptive growth actually adds 128 KiB.
    # The filler must be evicted even though the fixed prediction would fit.
    send("target", {"padding": "x" * 3000})
    chunks = set(storage.glob("*/*.flb"))
    assert chunks == {target}
    assert target.stat().st_size == 384 * 1024
    assert "evicted" in Path(manager.log_file).read_text()
