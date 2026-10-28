"""Destination admission is bounded across workers, including failed opens."""

import json
from pathlib import Path
import time

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitManager


DESTINATIONS = 40
LIMIT = 8


def create_file_output(tmp_path, mode, limit, action, failed_opens=False):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    inputs = []
    for index in range(DESTINATIONS):
        destination = f"dest{index}"
        if failed_opens:
            destination += "x" * 300
        elif mode == "tag":
            destination += "/events"
        inputs.append({
            "name": "dummy", "tag": destination,
            "samples": 1 if failed_opens or action != "fallback" else 2,
            "dummy": json.dumps({"id": index, "dest": destination}),
        })
    output = {
        "name": "file", "match": "*", "path": str(output_dir),
        "format": "plain", "mkdir": True, "rotate": True, "workers": 4,
        "on_limit_reached": action, "fallback_path": str(output_dir),
        "fallback_file": "overflow.log",
    }
    if limit is not None:
        output["max_dynamic_files"] = limit
    if mode == "accessor":
        output["file"] = "$dest"
    config = tmp_path / "fluent-bit.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": inputs, "outputs": [output]},
    }))
    manager = FluentBitManager(str(config))
    return manager, output_dir


def wait_until(predicate, manager):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    pytest.fail(Path(manager.log_file).read_text())


def record_count(directory):
    return sum(path.read_bytes().count(b"\n") for path in directory.rglob("*") if path.is_file())


@pytest.mark.parametrize("mode,limit,action", [
    ("tag", LIMIT, "fallback"),
    ("tag", LIMIT, "error"),
    ("tag", LIMIT, "drop"),
    ("tag", 0, "fallback"),
    ("tag", None, "fallback"),
    ("accessor", LIMIT, "fallback"),
])
def test_destination_limit_workers(tmp_path, mode, limit, action):
    manager, output_dir = create_file_output(tmp_path, mode, limit, action)
    capped = limit == LIMIT
    destination_count = LIMIT if capped else DESTINATIONS
    samples = 2 if action == "fallback" else 1
    expected_records = samples * (destination_count if action != "fallback" else DESTINATIONS)
    try:
        manager.start()
        wait_until(lambda: record_count(output_dir) == expected_records, manager)
        if capped and action != "fallback":
            wait_until(lambda: Path(manager.log_file).read_text().count(
                "max_dynamic_files limit reached") == DESTINATIONS - LIMIT, manager)
    finally:
        manager.stop()

    files = [path for path in output_dir.rglob("*") if path.is_file()]
    destinations = [path for path in files if path.name != "overflow.log"]
    assert len(destinations) == destination_count
    # Reusing admitted destinations remains possible after the cap is reached.
    assert all(len(path.read_text().splitlines()) == samples for path in destinations)
    if mode == "tag":
        assert len(list(output_dir.iterdir())) == len(files)
    overflow = output_dir / "overflow.log"
    if capped and action == "fallback":
        assert len(overflow.read_text().splitlines()) == 2 * (DESTINATIONS - LIMIT)
    else:
        assert not overflow.exists()
    if action == "fallback":
        ids = sorted(json.loads(line)["id"] for path in files for line in path.read_text().splitlines())
        assert ids == sorted(list(range(DESTINATIONS)) * 2)


@pytest.mark.parametrize("mode", ["tag", "accessor"])
def test_failed_opens_consume_destination_slots(tmp_path, mode):
    manager, output_dir = create_file_output(tmp_path, mode, LIMIT, "error", failed_opens=True)
    try:
        manager.start()
        wait_until(lambda: Path(manager.log_file).read_text().count("error opening:") +
                   Path(manager.log_file).read_text().count("max_dynamic_files limit reached")
                   == DESTINATIONS, manager)
    finally:
        manager.stop()
    log = Path(manager.log_file).read_text()
    assert log.count("error opening:") == LIMIT
    assert log.count("max_dynamic_files limit reached") == DESTINATIONS - LIMIT
    assert not list(output_dir.iterdir())
