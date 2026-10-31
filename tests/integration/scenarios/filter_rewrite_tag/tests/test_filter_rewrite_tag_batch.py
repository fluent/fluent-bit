import json
from collections import Counter
from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


def read_records(service):
    records = []
    for line in Path(service.flb.log_file).read_text().splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and "id" in record:
            records.append(record)
    return records


@pytest.mark.parametrize("batch_size", [0, 2, 256])
@pytest.mark.parametrize("keep", [False, True])
def test_batch_routes_stages_and_invalid_tags(tmp_path, batch_size, keep):
    # Alternating tags exercise grouping and per-tag order. Missing/empty tags
    # must preserve the original even when other records emit successfully.
    messages = [
        {"id": i, "kind": "emit", "destination": f"routed.{'a' if i % 2 == 0 else 'b'}"}
        for i in range(6)
    ]
    messages.extend([{"id": 6, "kind": "emit", "destination": ""}, {"id": 7, "kind": "emit"}])
    script = tmp_path / "stages.lua"
    script.write_text('''
function before(tag, ts, record)
    record.before = (record.before or 0) + 1
    return 1, ts, record
end
function after(tag, ts, record)
    record.after = (record.after or 0) + 1
    record.after_tag = tag
    return 1, ts, record
end
''')
    config = {
        "service": {
            "flush": 0.2, "grace": 1, "log_level": "error",
            "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{
                "name": "dummy", "tag": "source", "samples": 1,
                "dummy": " ".join(json.dumps(message) for message in messages),
                "processors": {"logs": [
                    {"name": "lua", "script": str(script), "call": "before"},
                    {"name": "rewrite_tag", "rule": f"$kind ^emit$ $destination {str(keep).lower()}",
                     "batch_size": batch_size},
                    {"name": "lua", "script": str(script), "call": "after"},
                ]},
            }],
            "filters": [
                {"name": "record_modifier", "match": tag, "record": f"route {tag}"}
                for tag in ["source", "routed.a", "routed.b"]
            ],
            # Both outputs must receive all records independently.
            "outputs": [
                {"name": "stdout", "match": "*", "format": "json_lines", "workers": 0},
                {"name": "stdout", "match": "*", "format": "json_lines", "workers": 0},
            ],
        },
    }
    config_path = tmp_path / "batch.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    expected = Counter()
    for message in messages:
        if message.get("destination"):
            expected[(message["id"], message["destination"])] += 2
            if keep:
                expected[(message["id"], "source")] += 2
        else:
            expected[(message["id"], "source")] += 2
    try:
        service.start()
        service.wait_for_condition(
            lambda: len(read_records(service)) >= expected.total(),
            timeout=30, description="rewritten and retained records on both outputs",
        )
    finally:
        service.stop()
    records = read_records(service)
    assert Counter((record["id"], record["route"]) for record in records) == expected
    for record in records:
        assert record["before"] == 1
        assert record["after"] == 1
        assert record["after_tag"] == record["route"]
    for route in ["routed.a", "routed.b"]:
        # Two outputs each retain the source order within this destination.
        ids = [record["id"] for record in records if record["route"] == route]
        expected_ids = [message["id"] for message in messages if message.get("destination") == route]
        assert ids == expected_ids + expected_ids


def test_output_processor_is_rejected(tmp_path):
    config = {
        "service": {"log_level": "error", "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "tag": "source", "samples": 1}],
            "outputs": [{"name": "null", "match": "*", "processors": {"logs": [
                {"name": "rewrite_tag", "rule": "$log .* routed false"},
            ]}}],
        },
    }
    config_path = tmp_path / "output.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    with pytest.raises(FluentBitStartupError, match="exited early"):
        service.start()
    assert "rewrite_tag only supports input processors" in Path(service.flb.log_file).read_text()


@pytest.mark.parametrize("chain", ["single", "forward", "reverse"])
def test_pending_emitter_records_drain_at_eof(tmp_path, chain):
    source = tmp_path / "source.log"
    source.write_text("hello\n" * 1000)
    filters = [{"name": "rewrite_tag", "match": "source",
                "rule": f"$log ^hello$ {'routed' if chain == 'single' else 'middle'} false"}]
    if chain != "single":
        filters.append({"name": "rewrite_tag", "match": "middle",
                        "rule": "$log ^hello$ routed false"})
        if chain == "reverse":
            filters.reverse()
    config = {
        "service": {"flush": 0.2, "grace": 1, "log_level": "error",
                    "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "tail", "tag": "source", "path": str(source),
                        "read_from_head": True, "exit_on_eof": True}],
            "filters": filters,
            "outputs": [{"name": "counter", "match": "routed", "workers": 0}],
        },
    }
    config_path = tmp_path / "eof.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    # EOF intentionally stops this finite input before the health check completes.
    with pytest.raises(FluentBitStartupError, match="exited early with code 0"):
        service.start()
    delivered = 0
    for line in Path(service.flb.log_file).read_text().splitlines():
        try:
            delivered += json.loads(line).get("log_records", 0)
        except (ValueError, AttributeError):
            pass
    assert delivered == 1000
