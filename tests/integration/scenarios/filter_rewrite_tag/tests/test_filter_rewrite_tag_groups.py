import copy
import json
from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService


def exported_records(log_file):
    records = []
    for line in Path(log_file).read_text().splitlines():
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        for resource in payload.get("resourceLogs", []):
            attributes = {
                item["key"]: item["value"]["stringValue"]
                for item in resource.get("resource", {}).get("attributes", [])
            }
            for scope in resource.get("scopeLogs", []):
                for record in scope.get("logRecords", []):
                    records.append((record["body"]["stringValue"], attributes))
    return records


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("mode", ["split", "same", "keep", "unmatched"])
def test_rewrite_tag_preserves_group_context(tmp_path, reverse, mode):
    messages = [
        {"level": "info", "message": "order accepted"},
        {"level": "error", "message": "payment authorization failed"},
    ]
    if reverse:
        messages.reverse()
    destination = "routed.same" if mode == "same" else "routed.$level"
    pattern = "^info$" if mode == "unmatched" else "^(info|error)$"
    keep = "true" if mode == "keep" else "false"
    attributes = {
        "service.name": "checkout",
        "deployment.environment.name": "production",
    }
    processors = [{"name": "opentelemetry_envelope"}]
    processors.extend(
        {
            "name": "content_modifier",
            "context": "otel_resource_attributes",
            "action": "upsert",
            "key": key,
            "value": value,
        }
        for key, value in attributes.items()
    )
    config = {
        "service": {
            "flush": 0.2, "grace": 1, "log_level": "error",
            "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{
                "name": "dummy", "tag": "source", "samples": 1,
                "dummy": " ".join(json.dumps(message) for message in messages),
                "fixed_timestamp": True, "start_time_sec": 1700000000,
                "processors": {"logs": processors},
            }],
            "filters": [{
                "name": "rewrite_tag", "match": "source",
                "rule": f"$level {pattern} {destination} {keep}",
            }],
            "outputs": [{
                "name": "stdout", "match": "*", "format": "otlp_json", "workers": 0,
            }],
        },
    }
    # A second resource and an ungrouped record share the destination tags.
    # Neither may inherit the first group's attributes.
    second_input = copy.deepcopy(config["pipeline"]["inputs"][0])
    second_input["dummy"] = json.dumps({"level": "info", "message": "billing event"})
    second_input["processors"]["logs"][1]["value"] = "billing"
    config["pipeline"]["inputs"].extend([
        second_input,
        {
            "name": "dummy", "tag": "source", "samples": 1,
            "dummy": json.dumps({"level": "info", "message": "ungrouped event"}),
        },
    ])
    config_path = tmp_path / "rewrite_tag.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    expected_count = 8 if mode == "keep" else 4
    try:
        service.start()
        service.wait_for_condition(
            lambda: len(exported_records(service.flb.log_file)) >= expected_count,
            timeout=30,
            description="all original and retagged records",
        )
    finally:
        service.stop()
    records = exported_records(service.flb.log_file)
    assert len(records) == expected_count
    for message in messages:
        copies = [attrs for body, attrs in records if body == message["message"]]
        assert len(copies) == (2 if mode == "keep" else 1)
        assert all(attrs == attributes for attrs in copies)
    for body, expected in [
        ("billing event", dict(attributes, **{"service.name": "billing"})),
        ("ungrouped event", {}),
    ]:
        copies = [attrs for message, attrs in records if message == body]
        assert len(copies) == (2 if mode == "keep" else 1)
        assert all(attrs == expected for attrs in copies)
