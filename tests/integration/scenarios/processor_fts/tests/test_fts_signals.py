"""FTS metrics and traces policies based on OTTL transformation workflows."""
import base64
import copy
import json
import time
from pathlib import Path

import pytest
import requests
import yaml
from google.protobuf.json_format import ParseDict
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port
from test_fts_policies import attributes


POLICY = r'''
local fb = require("fluentbit")
function process(record)
    local case = record.name
    if case == "control" or case == "noop" then return end
    if case == "rename" then
        record.name = "normalized"; record.resource.attributes:set("service.name", "normalized")
        record.scope.name = "normalized.scope"; record.scope.version = "2"
        record.resource.schema_url = "https://example.com/resource"
        record.scope.schema_url = "https://example.com/scope"
    elseif case == "resource" then
        record.resource.attributes:set("deployment.environment.name", "production")
        record.resource.attributes:remove("secret")
        record.scope.attributes:set("policy.version", fb.int64(2))
    elseif case == "tag" then
        assert(type(record.tag) == "string" and #record.tag > 0)
        record.resource.attributes:set("source.tag", record.tag)
    elseif case == "module_guard" then
        assert(module == nil and os == nil and debug == nil and package == nil)
        assert(not pcall(function() module("os") end))
        assert(not pcall(require, "debug"))
        record.name = "restricted"
    elseif case == "drop" then return fb.DROP
    elseif case == "rollback" then
        record.name = "partial"; record.resource.attributes:set("secret", "partial")
        error("rollback-test")
    elseif case == "bad_name" then record.name = fb.map()
    elseif case == "bad_utf8" then record.name = string.char(255)
    elseif case == "bad_nul" then record.name = "a\0b"
    elseif case == "bad_resource" then record.resource.attributes:set("invalid", fb.uint64("18446744073709551615"))
    elseif case == "bad_scope" then record.scope.attributes = fb.array()
    elseif case == "bad_return" then return true
    elseif case == "budget" then while true do end
    elseif record.signal == "metrics" then
        if case == "metadata" then
            record.description = "normalized description"; record.unit = "s"
        elseif case == "labels" then
            for i=1,record.datapoints:len() do
                local attrs = record.datapoints:get(i):get("attributes")
                attrs:set("region", "west"); attrs:remove("secret")
            end
        elseif case == "values" then
            fb.set_metric_value(record.datapoints:get(1), fb.int64("-9223372036854775808"))
        elseif case == "scale" then fb.scale_metric(record, 2, "s")
        elseif case == "scale_fraction" then fb.scale_metric(record, 0.5, "s")
        elseif case == "to_sum" then
            record.type = "sum"; record.aggregation_temporality = "delta"; record.is_monotonic = false
        elseif case == "to_gauge" then record.type = "gauge"
        elseif case == "copy" then
            local derived = fb.copy_metric(record, "derived", "copy", "ms")
            derived.resource.attributes:set("service.name", "derived")
        elseif case == "extract_count" then fb.extract_metric(record, "count", "derived")
        elseif case == "extract_sum" then fb.extract_metric(record, "sum", "derived")
        elseif case == "extract_avg" then fb.extract_metric(record, "avg", "derived")
        elseif case:match("^aggregate_") then
            fb.aggregate_metric(record, {"region"}, case:sub(11))
        elseif case == "merge_buckets" then
            local bounds = fb.array(); bounds:append(2.0)
            fb.merge_histogram_buckets(record, bounds)
        elseif case == "bad_value" then fb.set_metric_value(record.datapoints:get(1), fb.map())
        elseif case == "typed_labels" then
            local attrs = record.datapoints:get(1):get("attributes")
            attrs:set("typed", fb.int64("9223372036854775807")); attrs:set("enabled", true)
            attrs:set("binary", fb.bytes("\0\255"))
            local nested = fb.map(); nested:set("count", fb.int64(2)); attrs:set("nested", nested)
        elseif case == "bad_label" then
            record.datapoints:get(1):get("attributes"):set("typed", fb.uint64("18446744073709551615"))
        elseif case == "bad_time" then record.datapoints:get(1):set("time_unix_nano", fb.uint64(0))
        end
    else
        if case == "redact" then
            fb.redact(record.attributes, {"secret"})
            fb.redact(record.events, {"secret"}); fb.redact(record.links, {"secret"})
        elseif case == "status" then record.status:set("code", fb.int64(2)); record.status:set("message", "failed")
        elseif case == "kind" then record.kind = 3
        elseif case == "correlation" then
            record.trace_id = "1234567890abcdef1234567890abcdef"
            record.span_id = "1234567890abcdef"; record.parent_span_id = ""
        elseif case == "time" then record.end_time_unix_nano = fb.uint64("2147483648999999999")
        elseif case == "events" then
            local events = fb.array(); local event = fb.map()
            event:set("name", "normalized.event")
            event:set("time_unix_nano", fb.uint64("2147483648123456789"))
            event:set("attributes", fb.map()); event:set("dropped_attributes_count", fb.uint64(0))
            events:append(event); record.events = events
        elseif case == "bad_id" then record.trace_id = "00000000000000000000000000000000"
        elseif case == "bad_time" then record.end_time_unix_nano = fb.uint64(0)
        elseif case == "bad_status" then record.status:set("code", fb.int64("9223372036854775807"))
        end
    end
end
'''


def attr(key, value):
    return {"key": key, "value": {"stringValue": value}}


def number_point(value=8):
    return {"attributes": [attr("region", "east"), attr("secret", "sensitive")],
            "startTimeUnixNano": "2147483648000000000", "timeUnixNano": "2147483648123456789",
            "asInt": str(value), "flags": 1}


def metric(kind, name):
    point = number_point()
    if kind == "histogram":
        point.pop("asInt")
        point.update(count="3", sum=4.0, bucketCounts=["1", "1", "1"], explicitBounds=[1.0, 2.0],
                     min=0.5, max=2.5)
    elif kind == "exponentialHistogram":
        point.pop("asInt")
        point.update(count="3", sum=2.0, scale=0, zeroCount="1", zeroThreshold=0.0,
                     positive={"offset": 0, "bucketCounts": ["1"]},
                     negative={"offset": 0, "bucketCounts": ["1"]}, min=-1.0, max=2.0)
    elif kind == "summary":
        point.pop("asInt")
        point.update(count="3", sum=4.0, quantileValues=[{"quantile": 0.5, "value": 1.5},
                                                       {"quantile": 0.9, "value": 2.5}])
        point.pop("flags")
    data = {"dataPoints": [point]}
    if kind in ("sum", "histogram", "exponentialHistogram"):
        data["aggregationTemporality"] = 2
    if kind == "sum":
        data["isMonotonic"] = True
    return {"name": name, "description": "original description", "unit": "ms", kind: data}


def span(name):
    return {"name": name, "traceId": "0102030405060708090a0b0c0d0e0f10",
            "spanId": "0102030405060708" if name != "control" else "0807060504030201",
            "parentSpanId": "1112131415161718", "traceState": "vendor=value", "kind": 2,
            "startTimeUnixNano": "2147483648000000000", "endTimeUnixNano": "2147483648123456789",
            "attributes": [attr("secret", "sensitive"), {"key": "exact", "value": {"intValue": "9223372036854775807"}}],
            "events": [{"timeUnixNano": "2147483648123456789", "name": "original.event",
                        "attributes": [attr("secret", "sensitive")], "droppedAttributesCount": 4}],
            "links": [{"traceId": "0102030405060708090a0b0c0d0e0f10", "spanId": "1112131415161718",
                       "traceState": "vendor=link", "attributes": [attr("secret", "sensitive")],
                       "droppedAttributesCount": 5}],
            "status": {"code": 1, "message": "ok"}, "droppedAttributesCount": 1,
            "droppedEventsCount": 2, "droppedLinksCount": 3}


class SignalRunner:
    def __init__(self, manager, port, signal):
        self.manager, self.port, self.signal = manager, port, signal
        self.sequence = 0

    def run(self, case, kind="gauge", transport="protobuf", points=None, temporality=None,
            extra_resource=None):
        self.log_offset = len(Path(self.manager.log_file).read_text())
        self.sequence += 1
        request_id = f"{case}-{self.sequence}"
        metrics = self.signal == "metrics"
        resource_key, scope_key, item_key = (("resourceMetrics", "scopeMetrics", "metrics") if metrics else
                                            ("resourceSpans", "scopeSpans", "spans"))
        items = [metric(kind, case), metric(kind, "control")] if metrics else [span(case), span("control")]
        if points is not None:
            items[0][kind]["dataPoints"] = points
        if temporality is not None:
            items[0][kind]["aggregationTemporality"] = temporality
        payload = {resource_key: [{"resource": {"attributes": [attr("test.request", request_id),
                    attr("secret", "sensitive"), attr("service.name", "original")] + (extra_resource or []),
                    "droppedAttributesCount": 7},
                    "schemaUrl": "https://example.com/original-resource",
                    scope_key: [{"scope": {"name": "original.scope", "version": "1",
                        "attributes": [{"key": "exact", "value": {"intValue": "9223372036854775807"}}],
                        "droppedAttributesCount": 6}, "schemaUrl": "https://example.com/original-scope",
                        item_key: items}]}]}
        if transport == "json":
            response = requests.post(f"http://127.0.0.1:{self.port}/v1/{self.signal}", json=payload, timeout=10)
        else:
            def convert(value):
                if isinstance(value, dict):
                    return {k: base64.b64encode(bytes.fromhex(v)).decode() if k in
                            ("traceId", "spanId", "parentSpanId") else convert(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [convert(v) for v in value]
                return value
            message = ExportMetricsServiceRequest() if metrics else ExportTraceServiceRequest()
            ParseDict(convert(payload), message)
            response = requests.post(f"http://127.0.0.1:{self.port}/v1/{self.signal}",
                data=message.SerializeToString(), headers={"Content-Type": "application/x-protobuf"}, timeout=10)
        assert response.status_code in (200, 201), response.text
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            rows = []
            for line in Path(self.manager.log_file).read_text().splitlines(keepends=True):
                if not line.startswith("{") or not line.endswith("\n"):
                    continue
                batch = json.loads(line)
                for resource in batch.get(resource_key, []):
                    if attributes(resource.get("resource", {}).get("attributes", [])).get("test.request") != request_id:
                        continue
                    for scope in resource.get(scope_key, []):
                        rows += [(resource, scope, item) for item in scope.get(item_key, [])]
            if rows:
                if not case.startswith("bad_") and case not in ("rollback", "budget"):
                    diagnostics = Path(self.manager.log_file).read_text()[self.log_offset:]
                    assert "cannot construct" not in diagnostics
                    assert "policy failed" not in diagnostics
                return items[0], rows
            time.sleep(0.1)
        raise AssertionError(f"no {self.signal} output for {case}: {Path(self.manager.log_file).read_text()[-5000:]}")


@pytest.fixture(scope="module", params=[("metrics", "input"), ("metrics", "output"),
                                       ("traces", "input"), ("traces", "output")])
def signal_runner(request, tmp_path_factory):
    signal, placement = request.param
    config = tmp_path_factory.mktemp(f"fts-{signal}-{placement}") / "signals.yaml"
    port = find_available_port()
    source = {"name": "opentelemetry", "port": port}
    output = {"name": "stdout", "match": "*", "format": "otlp_json", "workers": 2}
    (source if placement == "input" else output)["processors"] = {
        signal: [{"name": "fts", "code": POLICY, "error_mode": "keep"}]}
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
                                               "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
                                    "pipeline": {"inputs": [source], "outputs": [output]}}))
    manager = FluentBitManager(str(config))
    try:
        manager.start()
        yield SignalRunner(manager, port, signal)
    finally:
        manager.stop()


COMMON_CASES = ["noop", "rename", "resource", "tag", "module_guard", "drop", "rollback", "bad_name", "bad_utf8", "bad_nul",
                "bad_resource", "bad_scope", "bad_return", "budget"]
METRIC_CASES = ["metadata", "labels", "typed_labels", "values", "scale", "scale_fraction", "to_sum", "to_gauge", "copy",
               "extract_count", "extract_sum", "extract_avg", "bad_value", "bad_label", "bad_time"]
TRACE_CASES = ["redact", "status", "kind", "correlation", "time", "events", "bad_id", "bad_time", "bad_status"]


@pytest.mark.parametrize("case", list(dict.fromkeys(COMMON_CASES + METRIC_CASES + TRACE_CASES)))
def test_signal_policy_matrix(signal_runner, case):
    signal = signal_runner.signal
    if case not in COMMON_CASES and case not in (METRIC_CASES if signal == "metrics" else TRACE_CASES):
        pytest.skip("case belongs to the other signal")
    kind = "sum" if case == "to_gauge" else "histogram" if case.startswith("extract_") else "gauge"
    original, rows = signal_runner.run(case, kind)
    control = [(r, s, item) for r, s, item in rows if item["name"] == "control"]
    assert len(control) == 1
    resource, scope, item = control[0]
    assert attributes(resource["resource"]["attributes"])["service.name"] == "original"
    assert scope["scope"]["name"] == "original.scope"
    assert scope["scope"]["droppedAttributesCount"] == 6
    targets = [(r, s, item) for r, s, item in rows if item["name"] != "control"]
    if case == "drop":
        assert not targets
        return
    assert targets
    resource, scope, item = targets[0]
    if case.startswith("bad_") or case in ("rollback", "budget", "noop"):
        assert item["name"] == case
        assert attributes(resource["resource"]["attributes"])["service.name"] == "original"
        assert scope["scope"]["name"] == "original.scope"
    elif case == "rename":
        assert item["name"] == "normalized"
        assert attributes(resource["resource"]["attributes"])["service.name"] == "normalized"
        assert scope["scope"]["name"] == "normalized.scope" and scope["scope"]["version"] == "2"
        assert resource["schemaUrl"] == "https://example.com/resource"
        assert scope["schemaUrl"] == "https://example.com/scope"
    elif case == "resource":
        attrs = attributes(resource["resource"]["attributes"])
        assert "secret" not in attrs and attrs["deployment.environment.name"] == "production"
        assert attributes(scope["scope"]["attributes"])["policy.version"] == 2
    elif case == "tag":
        assert attributes(resource["resource"]["attributes"])["source.tag"]
    elif case == "module_guard":
        assert item["name"] == "restricted"
    elif signal == "metrics":
        data = item.get("gauge") or item.get("sum") or item.get("histogram")
        point = data["dataPoints"][0]
        if case == "metadata":
            assert item["description"] == "normalized description" and item["unit"] == "s"
        elif case == "labels":
            assert attributes(point["attributes"])["region"] == "west"
            assert "secret" not in attributes(point["attributes"])
        elif case == "values":
            assert int(point["asInt"]) == -(2**63)
        elif case == "typed_labels":
            attrs = attributes(point["attributes"])
            assert attrs["typed"] == 2**63-1 and attrs["enabled"] is True
            assert attrs["nested"] == {"count": 2}
            assert any(a["key"] == "binary" and a["value"]["bytesValue"] == "AP8="
                       for a in point["attributes"])
        elif case in ("scale", "scale_fraction"):
            assert float(point.get("asInt", point.get("asDouble"))) == (16 if case == "scale" else 4)
            assert item["unit"] == "s"
        elif case == "to_sum":
            assert "sum" in item and item["sum"]["aggregationTemporality"] == 1
            assert not item["sum"]["isMonotonic"]
        elif case == "to_gauge":
            assert "gauge" in item and "sum" not in item
        elif case == "copy" or case.startswith("extract_"):
            derived = [(r, s, m) for r, s, m in targets if m["name"] == "derived"]
            assert len(derived) == 1
            r, _, m = derived[0]
            if case == "copy":
                assert attributes(r["resource"]["attributes"])["service.name"] == "derived"
                assert m["description"] == "copy" and m["unit"] == "ms"
            else:
                p = (m.get("gauge") or m.get("sum"))["dataPoints"][0]
                assert float(p.get("asInt", p.get("asDouble"))) == {"extract_count": 3, "extract_sum": 4,
                                                                       "extract_avg": 4/3}[case]
    else:
        assert attributes(item["attributes"])["exact"] == 2**63-1
        if case == "redact":
            assert attributes(item["attributes"])["secret"] == "[REDACTED]"
            assert attributes(item["events"][0]["attributes"])["secret"] == "[REDACTED]"
            assert attributes(item["links"][0]["attributes"])["secret"] == "[REDACTED]"
        elif case == "status":
            assert item["status"] == {"code": 2, "message": "failed"}
        elif case == "kind":
            assert item["kind"] == 3
        elif case == "correlation":
            assert item["traceId"] == "1234567890abcdef1234567890abcdef"
            assert item["spanId"] == "1234567890abcdef"
            assert item.get("parentSpanId", "") == ""
        elif case == "time":
            assert int(item["endTimeUnixNano"]) == 2147483648999999999
        elif case == "events":
            assert len(item["events"]) == 1 and item["events"][0]["name"] == "normalized.event"


@pytest.mark.parametrize("kind", ["gauge", "sum", "histogram", "exponentialHistogram", "summary"])
@pytest.mark.parametrize("transport", ["json", "protobuf"])
def test_metric_types_round_trip(signal_runner, kind, transport):
    if signal_runner.signal != "metrics":
        pytest.skip("metrics case")
    _, rows = signal_runner.run("noop", kind, transport)
    target = next(item for _, _, item in rows if item["name"] == "noop")
    point = target[kind]["dataPoints"][0]
    assert int(point["timeUnixNano"]) == 2147483648123456789
    assert int(point["startTimeUnixNano"]) == 2147483648000000000
    if kind in ("gauge", "sum"):
        assert int(point["asInt"]) == 8
    else:
        assert int(point["count"]) == 3
        assert point["sum"] == (2.0 if kind == "exponentialHistogram" else 4.0)


@pytest.mark.parametrize("kind", ["gauge", "sum", "histogram", "exponentialHistogram", "summary"])
# OTLP JSON input merges repeated series by labels before FTS runs, like 5.1.
@pytest.mark.parametrize("transport", ["protobuf"])
@pytest.mark.parametrize("distinct_windows", [False, True],
                         ids=["ambiguous-native-points", "distinct-windows"])
def test_typed_series_keep_independent_metadata(signal_runner, kind, transport, distinct_windows):
    if signal_runner.signal != "metrics":
        pytest.skip("metric datapoint semantics")
    points = [copy.deepcopy(metric(kind, "noop")[kind]["dataPoints"][0]) for _ in range(2)]
    points[0]["attributes"].append({"key": "typed", "value": {"intValue": "1"}})
    points[1]["attributes"].append(attr("typed", "1"))
    if distinct_windows:
        points[1]["timeUnixNano"] = str(int(points[0]["timeUnixNano"]) + 1)
    if kind != "summary":
        points[0]["flags"], points[1]["flags"] = 7, 3
    _, rows = signal_runner.run("noop", kind, transport, points)
    target = next(item for _, _, item in rows if item["name"] == "noop")
    exported = target[kind]["dataPoints"]
    assert len(exported) == 2
    # cmetrics 2.3.1 binds sidecars to native identities. Identical native
    # points cannot safely retain metadata that differs only in attribute type.
    expected_types = [1, "1"] if distinct_windows else ["1", "1"]
    assert [attributes(point["attributes"])["typed"] for point in exported] == expected_types
    if kind != "summary":
        assert [point.get("flags", 0) for point in exported] == ([7, 3] if distinct_windows else [0, 0])
    assert not any(entry["key"] in {"resource_index", "scope_index", "scope_flat_index"}
                   for entry in target.get("metadata", []))


@pytest.mark.parametrize("transport", ["json", "protobuf"])
def test_bytes_context_attributes_round_trip(signal_runner, transport):
    raw = {"key": "binary", "value": {"bytesValue": base64.b64encode(b"\x00\x01\xff").decode()}}
    _, rows = signal_runner.run("noop", "gauge", transport, extra_resource=[raw])
    resource = rows[0][0]["resource"]["attributes"]
    exported = next(entry["value"] for entry in resource if entry["key"] == "binary")
    assert base64.b64decode(exported["bytesValue"]) == b"\x00\x01\xff"


@pytest.mark.parametrize("transport", ["json", "protobuf"])
def test_repeated_unlabeled_points_keep_last_value(signal_runner, transport):
    """Like 5.1, a repeated label-less series keeps its last value."""
    if signal_runner.signal != "metrics":
        pytest.skip("metric datapoint semantics")
    points = [number_point(1), number_point(2)]
    for index, point in enumerate(points):
        point["attributes"] = []
        point["timeUnixNano"] = str(2147483648123456789 + index)
    _, rows = signal_runner.run("noop", "gauge", transport, points)
    target = next(item for _, _, item in rows if item["name"] == "noop")
    assert [int(point["asInt"]) for point in target["gauge"]["dataPoints"]] == [2]


@pytest.mark.parametrize("operation,expected", [("sum", 20), ("min", 8), ("max", 12),
                                               ("mean", 10), ("count", 2)])
def test_metric_cardinality_aggregation(signal_runner, operation, expected):
    if signal_runner.signal != "metrics":
        pytest.skip("metric aggregation")
    points = [number_point(8), number_point(12)]
    for index, point in enumerate(points):
        point["attributes"].append(attr("method", ["GET", "POST"][index]))
    _, rows = signal_runner.run(f"aggregate_{operation}", "gauge", points=points)
    target = next(item for _, _, item in rows if item["name"] != "control")
    exported = target["gauge"]["dataPoints"]
    assert len(exported) == 1
    assert float(exported[0].get("asInt", exported[0].get("asDouble"))) == expected
    assert attributes(exported[0]["attributes"]) == {"region": "east"}


def test_histogram_bucket_merge(signal_runner):
    if signal_runner.signal != "metrics":
        pytest.skip("metric bucket semantics")
    _, rows = signal_runner.run("merge_buckets", "histogram")
    target = next(item for _, _, item in rows if item["name"] != "control")
    point = target["histogram"]["dataPoints"][0]
    assert point["explicitBounds"] == [2.0]
    assert [int(value) for value in point["bucketCounts"]] == [2, 1]
    assert int(point["count"]) == 3 and point["sum"] == 4.0


@pytest.mark.parametrize("transport", ["json", "protobuf"])
def test_scaling_includes_exemplars(signal_runner, transport):
    if signal_runner.signal != "metrics":
        pytest.skip("metric scaling")
    point = number_point()
    point["exemplars"] = [{"asDouble": 3.0, "timeUnixNano": point["timeUnixNano"]}]
    _, rows = signal_runner.run("scale", transport=transport, points=[point])
    target = next(item for _, _, item in rows if item["name"] == "scale")
    result = target["gauge"]["dataPoints"][0]
    assert int(result["asInt"]) == 16
    assert result["exemplars"][0]["asDouble"] == 6.0


# OTLP JSON input merges repeated series by labels before FTS runs, like 5.1.
@pytest.mark.parametrize("transport", ["protobuf"])
def test_aggregation_preserves_distinct_start_times(signal_runner, transport):
    if signal_runner.signal != "metrics":
        pytest.skip("metric windows")
    points = [number_point(8), number_point(42)]
    points[0]["startTimeUnixNano"] = "2147483647000000000"
    _, rows = signal_runner.run("aggregate_sum", transport=transport, points=points)
    target = next(item for _, _, item in rows if item["name"] == "aggregate_sum")
    result = target["gauge"]["dataPoints"]
    assert len(result) == 2
    assert [p["startTimeUnixNano"] for p in result] == [p["startTimeUnixNano"] for p in points]
    assert [int(p["asInt"]) for p in result] == [8, 42]
    assert all(attributes(p["attributes"]) == {"region": "east"} for p in result)


@pytest.mark.parametrize("transport", ["json", "protobuf"])
def test_extraction_preserves_unspecified_temporality(signal_runner, transport):
    if signal_runner.signal != "metrics":
        pytest.skip("metric extraction")
    _, rows = signal_runner.run("extract_sum", "histogram", transport=transport, temporality=0)
    target = next(item for _, _, item in rows if item["name"] == "derived")
    assert target["sum"].get("aggregationTemporality", 0) == 0
    assert target["sum"]["dataPoints"][0]["asDouble"] == 4.0
