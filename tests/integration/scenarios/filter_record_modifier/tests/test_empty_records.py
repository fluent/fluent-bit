"""Removing all fields must never forward the original record."""

import json
from pathlib import Path
from uuid import UUID

import pytest
import requests
import yaml

from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("rule", ["allowlist_key", "remove_key"])
@pytest.mark.parametrize("case", [
    "empty_single", "empty_batch", "mixed", "control", "unchanged", "record", "uuid",
])
def test_empty_records(tmp_path, rule, case):
    if rule == "allowlist_key":
        key = "message"
        empty = {"ssn": "222-22-2222"}
        control = {"message": "hello", "ssn": "222-22-2222"}
        retained = {"message": "hello"}
    else:
        key = "token"
        empty = {"token": "SECRET-SUBJECT"}
        control = {"keep": "visible", "token": "SECRET-CONTROL"}
        retained = {"keep": "visible"}

    modifier = {"name": "record_modifier", "match": "*", rule: key}
    records = [empty]
    expected = []
    if case == "empty_batch":
        records = [empty, empty]
    elif case == "mixed":
        records = [empty, control, empty]
        expected = [retained]
    elif case == "control":
        records = [control]
        expected = [retained]
    elif case == "unchanged":
        records = [retained]
        expected = [retained]
    elif case == "record":
        modifier["record"] = "added visible"
        expected = [{"added": "visible"}]
    elif case == "uuid":
        modifier["uuid_key"] = "uuid"
        expected = [{}]

    config = {
        "service": {
            "flush": 0.1, "grace": 1, "log_level": "error",
            "http_server": True, "http_listen": "127.0.0.1",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{
                "name": "dummy", "tag": "test", "samples": 1,
                "interval_sec": 0, "interval_nsec": 100000000,
                # Concatenated objects are encoded in one dummy append.
                "dummy": " ".join(json.dumps(record) for record in records),
            }],
            "filters": [modifier],
            "outputs": [{
                "name": "stdout", "match": "*", "format": "json_lines",
                "json_date_key": False, "workers": 0,
            }],
        },
    }
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    try:
        service.start()

        def filtered():
            response = requests.get(
                f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics",
                timeout=5,
            )
            response.raise_for_status()
            metrics = response.json().get("filter", {}).get("record_modifier.0", {})
            return metrics.get("records", 0) == len(records)

        # Wait for ingestion even when no record should reach the output.
        service.wait_for_condition(filtered, timeout=30, interval=0.1,
                                   description="record_modifier to process the batch")
    finally:
        # Graceful shutdown flushes any surviving records before inspection.
        service.stop()

    actual = []
    for line in Path(service.flb.log_file).read_text().splitlines():
        if line.startswith("{"):
            actual.append(json.loads(line))
    if case == "uuid":
        assert len(actual) == 1
        assert UUID(actual[0].pop("uuid")).version == 4
    assert actual == expected
