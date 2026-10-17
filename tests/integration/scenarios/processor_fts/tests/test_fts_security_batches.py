"""Privacy policies must execute for every item, despite malformed siblings."""
import base64
import copy
import json
import re
import time
from pathlib import Path

import pytest
import requests
import yaml
from google.protobuf.json_format import ParseDict
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port
from test_fts_signals import attr, metric, span
from test_fts_policies import attributes, scalar

POLICY = '''
local fb = require("fluentbit")
if type(getmetatable("")) ~= "string" then error("string metatable exposed") end
assert = function() end
require = function() return {} end
fb._attach = function() return function() end end
fb._validate = function() end
fb._fts_wrap = function() return {} end
fb._fts_validate_telemetry = function() end
fb._fts_equal = function() return true end
math.huge = 0
string.match = function() return true end
function process(record)
  if record.body ~= nil then
    fb.redact(record.body, {"password", "secret"})
    if record.body:get_string("action") == "bad" then record.metadata:ensure_map("otlp"):set("severity_number", fb.int64(999)) end
  elseif record.signal == "metrics" then
    for i=1,record.datapoints:len() do
      fb.redact(record.datapoints:get(i):get("attributes"), {"secret", "password"})
    end
    if record.name == "bad" then record.datapoints:get(1):set("time_unix_nano", fb.uint64(0)) end
  else
    fb.redact(record.attributes, {"secret", "password"})
    if record.name == "bad" then record.status:set("code", fb.int64(7)) end
  end
end
'''


class BatchRunner:
    def __init__(self, manager, port, signal):
        self.manager, self.port, self.signal = manager, port, signal
        self.sequence = 0
        self.log_offset = 0
        self.keys = {"logs": ("resourceLogs", "scopeLogs", "logRecords"),
                     "metrics": ("resourceMetrics", "scopeMetrics", "metrics"),
                     "traces": ("resourceSpans", "scopeSpans", "spans")}[signal]

    def send(self, items, transport="protobuf", scopes=None, resource_attributes=None):
        self.log_offset = len(Path(self.manager.log_file).read_text())
        self.sequence += 1
        request = str(self.sequence)
        resource_key, scope_key, item_key = self.keys
        payload = {resource_key: [{"resource": {"attributes": [attr("test.request", request)] + (resource_attributes or [])},
                                  scope_key: scopes or [{"scope": {"name": "audit"}, item_key: items}]}]}
        if transport == "protobuf":
            def convert(value):
                if isinstance(value, dict):
                    return {k: base64.b64encode(bytes.fromhex(v)).decode() if k in
                            ("traceId", "spanId", "parentSpanId") else convert(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [convert(v) for v in value]
                return value
            message = {"logs": ExportLogsServiceRequest, "metrics": ExportMetricsServiceRequest,
                       "traces": ExportTraceServiceRequest}[self.signal]()
            ParseDict(convert(payload), message)
            response = requests.post(f"http://127.0.0.1:{self.port}/v1/{self.signal}",
                data=message.SerializeToString(), headers={"Content-Type": "application/x-protobuf"}, timeout=30)
        else:
            response = requests.post(f"http://127.0.0.1:{self.port}/v1/{self.signal}", json=payload, timeout=30)
        assert response.status_code in (200, 201), response.text
        expected = sum(len(s[item_key]) for s in scopes) if scopes else len(items)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            resources = []
            text = Path(self.manager.log_file).read_text()
            # Diagnostics can interrupt a large stdout write. Remove complete log
            # messages before reconstructing the JSON artifact, retaining partial writes.
            text = re.sub(r"\[\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+\] "
                          r"\[\s*(?:error|warn|info|debug|trace)\][^\n]*\n", "", text)
            for line in text.splitlines(keepends=True):
                if not line.startswith("{") or not line.endswith("\n"):
                    continue
                try:
                    batch = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for resource in batch.get(resource_key, []):
                    if attributes(resource.get("resource", {}).get("attributes", [])).get("test.request") == request:
                        resources.append(resource)
            rows = [item for r in resources for s in r[scope_key] for item in s[item_key]]
            if len(rows) >= expected:
                return resources, rows
            time.sleep(0.1)
        raise AssertionError(Path(self.manager.log_file).read_text()[-5000:])


    def recent_log(self):
        return Path(self.manager.log_file).read_text()[self.log_offset:]


@pytest.fixture(scope="module", params=[(s, p) for s in ("logs", "metrics", "traces")
                                       for p in ("input", "output")])
def batch_runner(request, tmp_path_factory):
    signal, placement = request.param
    port = find_available_port()
    source = {"name": "opentelemetry", "port": port, "buffer_max_size": "8M"}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    (source if placement == "input" else output)["processors"] = {
        signal: [{"name": "fts", "code": POLICY, "error_mode": "keep", "memory_limit": "4M"}]}
    config = tmp_path_factory.mktemp("fts-security-batches") / "config.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}, "pipeline": {"inputs": [source], "outputs": [output]}}))
    manager = FluentBitManager(str(config))
    try:
        manager.start()
        yield BatchRunner(manager, port, signal)
    finally:
        manager.stop()


@pytest.mark.parametrize("transport", ["json", "protobuf"])
def test_duplicate_parent_redaction(batch_runner, transport):
    if batch_runner.signal == "metrics":
        item = metric("gauge", "privacy")
        values = item["gauge"]["dataPoints"][0]["attributes"]
    elif batch_runner.signal == "traces":
        item = span("privacy")
        values = item["attributes"]
    else:
        item = {"timeUnixNano": "2147483648123456789", "body": {"kvlistValue": {"values": []}}}
        values = item["body"]["kvlistValue"]["values"]
    values.extend([{"key": "a", "value": {"kvlistValue": {"values": [attr("password", text)]}}}
                   for text in ("first-secret", "second-secret")])
    _, rows = batch_runner.send([item], transport)
    rendered = json.dumps(rows)
    assert "first-secret" not in rendered and "second-secret" not in rendered
    assert rendered.count("[REDACTED]") >= 2
    assert "cannot construct FTS" not in batch_runner.recent_log()


def test_validation_is_private_and_item_local(batch_runner):
    if batch_runner.signal == "metrics":
        items = [metric("gauge", "bad"), metric("gauge", "good")]
    elif batch_runner.signal == "traces":
        items = [span("bad"), span("good")]
    else:
        items = [{"severityNumber": 2, "body": {"kvlistValue": {"values": [attr("action", action),
                  attr("secret", "sensitive")]}}} for action in ("bad", "good")]
    _, rows = batch_runner.send(items)
    assert len(rows) == 2
    if batch_runner.signal == "metrics":
        points = [row["gauge"]["dataPoints"][0] for row in rows]
        assert points[0]["timeUnixNano"] == "2147483648123456789"
        assert attributes(points[0]["attributes"])["secret"] == "sensitive"
        assert attributes(points[1]["attributes"])["secret"] == "[REDACTED]"
    elif batch_runner.signal == "traces":
        assert rows[0]["status"]["code"] == 1
        assert attributes(rows[0]["attributes"])["secret"] == "sensitive"
        assert attributes(rows[1]["attributes"])["secret"] == "[REDACTED]"
    else:
        assert rows[0]["severityNumber"] == 2
        assert scalar(rows[0]["body"])["secret"] == "sensitive"
        assert scalar(rows[1]["body"])["secret"] == "[REDACTED]"
    log = batch_runner.recent_log()
    assert "edits rolled back" in log and "cannot construct FTS" not in log


def test_unknown_inherited_kind_does_not_bypass_privacy(batch_runner):
    if batch_runner.signal != "traces":
        pytest.skip("trace enum preservation")
    items = [span("unknown"), span("good")]
    items[0]["kind"] = 9
    items[0]["parentSpanId"] = "0" * 16
    items[0]["endTimeUnixNano"] = "1"
    _, rows = batch_runner.send(items)
    # the span is kept; stored traces record an unknown kind as unspecified
    assert len(rows) == 2 and rows[0].get("kind", 0) == 0
    assert all(attributes(r["attributes"])["secret"] == "[REDACTED]" for r in rows)
    assert "edits rolled back" not in batch_runner.recent_log()


def test_large_trace_batch_is_redacted(batch_runner):
    if batch_runner.signal != "traces":
        pytest.skip("trace batch memory accounting")
    items = [span(f"span-{i}") for i in range(4000)]
    for item in items:
        item["attributes"] += [attr(f"extra-{i}", "value") for i in range(3)]
    resources, rows = batch_runner.send(items, resource_attributes=[attr("bulk", "b" * 32768)])
    assert len(rows) == 4000 and len(resources) == 1
    assert len(resources[0]["scopeSpans"]) == 1
    assert all(attributes(r["attributes"])["secret"] == "[REDACTED]" for r in rows)
    assert "cannot construct FTS" not in batch_runner.recent_log()


@pytest.mark.parametrize("separate_scopes", [False, True])
@pytest.mark.parametrize("transport", ["json", "protobuf"])
def test_repeated_metric_names_are_preserved(batch_runner, separate_scopes, transport):
    if batch_runner.signal != "metrics":
        pytest.skip("metric family identity")
    items = [metric("gauge", "same"), metric("gauge", "same")]
    items[1]["gauge"]["dataPoints"][0]["asInt"] = "42"
    items[0]["metadata"] = [attr("family.id", "first")]
    items[1]["metadata"] = [attr("family.id", "second")]
    scopes = [{"scope": {"name": name}, "metrics": [item]} for name, item in zip(("one", "two"), items)]
    resources, rows = batch_runner.send(items, transport, scopes=scopes if separate_scopes else None)
    assert len(rows) == 2
    assert [int(r["gauge"]["dataPoints"][0]["asInt"]) for r in rows] == [8, 42]
    assert [attributes(r["metadata"])["family.id"] for r in rows] == ["first", "second"]
    assert all(attributes(r["gauge"]["dataPoints"][0]["attributes"])["secret"] == "[REDACTED]" for r in rows)
    if separate_scopes:
        assert [s["scope"]["name"] for r in resources for s in r["scopeMetrics"]] == ["one", "two"]
    assert "cannot construct FTS" not in batch_runner.recent_log()


def test_snapshot_limit_is_item_local(batch_runner):
    if batch_runner.signal != "traces":
        pytest.skip("trace snapshot isolation")
    items = [span("oversized"), span("good")]
    items[0]["attributes"] += [attr(f"field-{i}", "value") for i in range(9000)]
    _, rows = batch_runner.send(items)
    assert len(rows) == 2
    assert attributes(rows[0]["attributes"])["secret"] == "sensitive"
    assert attributes(rows[1]["attributes"])["secret"] == "[REDACTED]"
    text = batch_runner.recent_log()
    assert "snapshot limits" in text and "cannot construct FTS" not in text


@pytest.mark.parametrize("transport", ["json", "protobuf"])
def test_untouched_invalid_metric_does_not_skip_redaction(batch_runner, transport):
    if batch_runner.signal != "metrics":
        pytest.skip("metric field validation")
    item = metric("gauge", "invalid-inherited-time")
    point = item["gauge"]["dataPoints"][0]
    point["startTimeUnixNano"] = "2147483648999999999"
    point["timeUnixNano"] = "2147483648000000000"
    _, rows = batch_runner.send([item], transport)
    result = rows[0]["gauge"]["dataPoints"][0]
    assert result["startTimeUnixNano"] == point["startTimeUnixNano"]
    assert result["timeUnixNano"] == point["timeUnixNano"]
    assert attributes(result["attributes"])["secret"] == "[REDACTED]"
    assert "policy failed" not in batch_runner.recent_log()
    assert "cannot construct FTS" not in batch_runner.recent_log()
