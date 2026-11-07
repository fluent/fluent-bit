"""Regressions for preservation, read-only context access and timestamp writes."""
import json
from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port
from utils.test_service import FluentBitTestService
from test_fts_policies import PolicyRunner, attributes, scalar


@pytest.fixture(scope="module", params=["input", "output"])
def audit_runner(request, tmp_path_factory):
    port = find_available_port()
    source = {"name": "opentelemetry", "port": port}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    code = '''function process(log)
      local action = log.body:get_string("text")
      if action == "edit" then log.body:set("edited", true)
      elseif action == "read" then
        assert(log.resource.attributes:len() >= 0)
        assert(log.scope.attributes:len() >= 0)
      elseif action == "marker" then
        log.timestamp.sec = 4294967295; log.timestamp.nsec = 1
      end
    end'''
    (source if request.param == "input" else output)["processors"] = {
        "logs": [{"name": "fts", "code": code, "error_mode": "drop"}]}
    config = tmp_path_factory.mktemp("fts-audits") / "audit.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    manager = FluentBitManager(str(config))
    try:
        manager.start()
        yield PolicyRunner(manager, port)
    finally:
        manager.stop()


@pytest.mark.parametrize("action", ["noop", "edit", "read"])
def test_untouched_otel_fields_and_context_survive(audit_runner, action):
    request = f"audit-{action}"
    payload = audit_runner.payload("unused", request)
    source = payload["resourceLogs"][0]
    source["scopeLogs"][0]["scope"].pop("attributes")
    logs = source["scopeLogs"][0]["logRecords"]
    for index, record in enumerate(logs):
        record["traceId"] = "0" * 32
        record["spanId"] = "0" * 16
        record["severityNumber"] = 30
        if index < 2:
            record["body"]["kvlistValue"]["values"][0]["value"]["stringValue"] = action
    audit_runner.send(payload)
    resources = audit_runner.wait_for_condition(lambda: audit_runner.collect(request))
    assert len(resources) == 1
    assert len(resources[0]["scopeLogs"]) == 1
    exported = resources[0]["scopeLogs"][0]["logRecords"]
    assert len(exported) == 3
    for index, record in enumerate(exported):
        assert record["traceId"] == "0" * 32 and record["spanId"] == "0" * 16
        assert record["severityNumber"] == 30
        assert ("edited" in scalar(record["body"])) == (action == "edit" and index < 2)
    assert "edits rolled back" not in Path(audit_runner.manager.log_file).read_text()


def test_reserved_timestamp_drops_only_changed_record(audit_runner):
    request = "audit-marker"
    payload = audit_runner.payload("unused", request)
    payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["kvlistValue"]["values"][0]["value"]["stringValue"] = "marker"
    audit_runner.send(payload)
    resources = audit_runner.wait_for_condition(lambda: audit_runner.collect(request))
    records = [record for resource in resources for scope in resource["scopeLogs"]
               for record in scope["logRecords"]]
    assert [scalar(record["body"])["text"] for record in records] == ["operationB", "control"]


def test_plain_metadata_does_not_gain_otlp_fields(tmp_path):
    config = tmp_path / "plain.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}, "pipeline": {
        "inputs": [{"name": "dummy", "dummy": json.dumps({"message": "plain"}),
                    "metadata": json.dumps({"trace_flags": 1, "event_name": "ordinary.metadata"}), "rate": 4}],
        "outputs": [{"name": "stdout", "match": "*", "format": "otlp_json"}]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        batches = service.wait_for_condition(lambda: [json.loads(line) for line in
            Path(service.flb.log_file).read_text().splitlines() if line.startswith("{")], timeout=30)
        records = [record for batch in batches for resource in batch["resourceLogs"]
                   for scope in resource["scopeLogs"] for record in scope["logRecords"]]
        assert records
        assert all("flags" not in record and "eventName" not in record for record in records)
    finally:
        service.stop()
