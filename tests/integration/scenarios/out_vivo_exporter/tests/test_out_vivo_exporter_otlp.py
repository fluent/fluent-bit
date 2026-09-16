"""OTLP JSON schema, numeric fidelity, and browser HTTP compression contract."""
import base64
import copy
import gzip
import json
import math
import os
import socket

import pytest
import requests
from google.protobuf.json_format import ParseDict
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from test_out_vivo_exporter_audit import exporter, pack_forward, poll
from utils.http_matrix import curl_supports_http2, run_curl_request


NANOSECONDS = 1789516800123456789


def decode_otlp(payload, message_type):
    """The Protobuf JSON parser uses base64; OTLP overrides trace/span IDs with hex."""
    def normalize(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ("traceId", "spanId", "parentSpanId"):
                    assert isinstance(child, str)
                    expected = 32 if key == "traceId" else 16
                    assert len(child) in (0, expected)
                    value[key] = base64.b64encode(bytes.fromhex(child)).decode()
                else:
                    normalize(child)
        elif isinstance(value, list):
            for child in value:
                normalize(child)
    normalized = copy.deepcopy(payload)
    normalize(normalized)
    return ParseDict(normalized, message_type())


def submit(urls, signal, request):
    response = requests.post(urls["OTEL"] + f"/v1/{signal}", data=request.SerializeToString(),
                             headers={"Content-Type": "application/x-protobuf"}, timeout=5)
    assert response.ok, response.text


def test_otlp_log_types_and_metadata(exporter):
    service, urls = exporter
    request = ExportLogsServiceRequest()
    resource = request.resource_logs.add(schema_url="https://example.test/resource")
    resource.resource.attributes.add(key="service.name").value.string_value = "typed-service"
    resource.resource.dropped_attributes_count = 2
    scope = resource.scope_logs.add(schema_url="https://example.test/scope")
    scope.scope.name = "typed-scope"
    scope.scope.version = "1.2.3"
    scope.scope.attributes.add(key="enabled").value.bool_value = True
    record = scope.log_records.add(time_unix_nano=NANOSECONDS, observed_time_unix_nano=NANOSECONDS + 1,
                                   severity_number=9, severity_text="INFO", dropped_attributes_count=3,
                                   flags=1, trace_id=bytes.fromhex("ab" * 16), span_id=bytes.fromhex("cd" * 8))
    record.attributes.add(key="attempt").value.int_value = 42
    for key, field, value in (("integer", "int_value", 2147483647),
                              ("text", "string_value", "9007199254740993"),
                              ("bytes", "bytes_value", b"\x00\xff\x12"),
                              ("boolean", "bool_value", False),
                              ("double", "double_value", 0.12345678901234566),
                              ("unicode", "string_value", '雪\n"\\')):
        setattr(record.body.kvlist_value.values.add(key=key).value, field, value)
    array = record.body.kvlist_value.values.add(key="nested").value.array_value
    array.values.add().int_value = -2147483648
    array.values.add().string_value = "NaN"
    submit(urls, "logs", request)
    response = poll(service, urls["EXPORTER"] + "/api/v2/logs", lambda r: "typed-service" in r.text)
    page = response.json()
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-encoding"] == "gzip"
    assert page["signal"] == "logs"
    entry = page["entries"][0]
    assert entry["id"] == "0"
    assert entry["source"]["type"] == "opentelemetry"
    decoded = decode_otlp(entry["payload"], ExportLogsServiceRequest)
    exported_resource = decoded.resource_logs[0]
    exported_scope = exported_resource.scope_logs[0]
    exported = exported_scope.log_records[0]
    assert exported_resource.schema_url == resource.schema_url
    assert exported_resource.resource == resource.resource
    assert exported_scope.schema_url == scope.schema_url
    assert exported_scope.scope == scope.scope
    assert exported == record


def test_otlp_trace_structure(exporter):
    service, urls = exporter
    request = ExportTraceServiceRequest()
    resource = request.resource_spans.add(schema_url="https://example.test/resource")
    resource.resource.attributes.add(key="service.name").value.string_value = "trace-service"
    scope = resource.scope_spans.add(schema_url="https://example.test/scope")
    scope.scope.name = "trace-scope"
    span = scope.spans.add(name="typed-span", kind=2, trace_id=bytes.fromhex("12" * 16),
                           span_id=bytes.fromhex("34" * 8), parent_span_id=bytes.fromhex("56" * 8),
                           start_time_unix_nano=NANOSECONDS, end_time_unix_nano=NANOSECONDS + 1000001)
    span.status.code = 1
    span.attributes.add(key="integer").value.int_value = 9007199254740993
    span.attributes.add(key="text").value.string_value = "9007199254740993"
    event = span.events.add(name="an event", time_unix_nano=NANOSECONDS + 1)
    event.attributes.add(key="detail").value.string_value = "event detail"
    span.links.add(trace_id=bytes.fromhex("78" * 16), span_id=bytes.fromhex("90" * 8))
    submit(urls, "traces", request)
    response = poll(service, urls["EXPORTER"] + "/api/v2/traces", lambda r: "typed-span" in r.text)
    entry = response.json()["entries"][0]
    assert entry["source"]["type"] == "opentelemetry"
    payload = entry["payload"]
    exported = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert exported["kind"] == 2
    assert exported["status"]["code"] == 1
    assert exported["startTimeUnixNano"] == str(NANOSECONDS)
    assert exported["endTimeUnixNano"] == str(NANOSECONDS + 1000001)
    assert exported["traceId"] == "12" * 16
    assert exported["spanId"] == "34" * 8
    decoded = decode_otlp(payload, ExportTraceServiceRequest)
    assert decoded.resource_spans[0].scope_spans[0].spans[0] == span
    assert decoded.resource_spans[0].schema_url == resource.schema_url


def test_otlp_metric_types_and_snapshot(exporter):
    service, urls = exporter
    request = ExportMetricsServiceRequest()
    resource = request.resource_metrics.add(schema_url="https://example.test/metrics")
    resource.resource.attributes.add(key="service.name").value.string_value = "metric-service"
    scope = resource.scope_metrics.add()
    scope.scope.name = "metric-scope"
    metric = scope.metrics.add(name="exact_counter", unit="requests", description="Counter")
    metric.sum.aggregation_temporality = 2
    metric.sum.is_monotonic = True
    point = metric.sum.data_points.add(time_unix_nano=NANOSECONDS, start_time_unix_nano=NANOSECONDS - 1,
                                       as_int=9007199254740993)
    point.attributes.add(key="route").value.string_value = "/"
    exemplar = point.exemplars.add(time_unix_nano=NANOSECONDS, as_int=42,
                                   trace_id=bytes.fromhex("aa" * 16), span_id=bytes.fromhex("bb" * 8))
    for name, value in (("nan", math.nan), ("positive", math.inf), ("negative", -math.inf),
                        ("precise", 0.12345678901234566), ("negative_zero", -0.0)):
        scope.metrics.add(name=name).gauge.data_points.add(time_unix_nano=NANOSECONDS, as_double=value)
    histogram = scope.metrics.add(name="latency").histogram
    histogram.aggregation_temporality = 2
    histogram.data_points.add(time_unix_nano=NANOSECONDS, count=3, sum=4.5,
                              bucket_counts=[1, 2], explicit_bounds=[1.0], min=0.5, max=2.0)
    summary = scope.metrics.add(name="summary").summary.data_points.add(time_unix_nano=NANOSECONDS,
                                                                       count=3, sum=4.5)
    summary.quantile_values.add(quantile=0.5, value=1.5)
    submit(urls, "metrics", request)
    response = poll(service, urls["EXPORTER"] + "/api/v2/metrics", lambda r: "exact_counter" in r.text)
    decoded = decode_otlp(response.json()["entries"][0]["payload"], ExportMetricsServiceRequest)
    metrics = {metric.name: metric for resource in decoded.resource_metrics
               for scope in resource.scope_metrics for metric in scope.metrics}
    assert metrics["exact_counter"].sum.data_points[0].as_int == 9007199254740993
    assert metrics["exact_counter"].sum.aggregation_temporality == 2
    assert metrics["exact_counter"].sum.is_monotonic
    assert metrics["exact_counter"].sum.data_points[0].exemplars[0] == exemplar
    assert math.isnan(metrics["nan"].gauge.data_points[0].as_double)
    assert metrics["positive"].gauge.data_points[0].as_double == math.inf
    assert metrics["negative"].gauge.data_points[0].as_double == -math.inf
    assert metrics["precise"].gauge.data_points[0].as_double == 0.12345678901234566
    assert math.copysign(1, metrics["negative_zero"].gauge.data_points[0].as_double) == -1
    assert metrics["latency"].histogram.data_points[0] == histogram.data_points[0]
    assert metrics["summary"].summary.data_points[0] == summary
    snapshot = requests.get(urls["EXPORTER"] + "/api/v2/internal/metrics", timeout=5)
    assert snapshot.headers["content-encoding"] == "gzip"
    decoded = decode_otlp(snapshot.json(), ExportMetricsServiceRequest)
    assert any(metric.name == "fluentbit_output_proc_records_total"
               for resource in decoded.resource_metrics for scope in resource.scope_metrics
               for metric in scope.metrics)


@pytest.mark.parametrize("mode", ["http1.1", "http2-prior-knowledge"])
def test_browser_compression_and_v2_pages(exporter, mode):
    if mode.startswith("http2") and not curl_supports_http2():
        pytest.skip("curl lacks HTTP/2")
    service, urls = exporter
    base = urls["EXPORTER"]
    for index in range(3):
        assert requests.post(urls["INPUT"] + "/audit", json={"index": index, "message": "x" * 4096},
                             timeout=5).ok
        poll(service, base + "/api/v2/logs", lambda r: r.json()["tailCursor"] == str(index + 1))
    # curl --compressed exercises browser-style transparent decoding over both protocols.
    response = run_curl_request(base + "/api/v2/logs?limit=1", method="GET", http_mode=mode,
                                include_headers=True, extra_args=["--compressed"])
    assert response["status_code"] == 200
    assert "content-encoding: gzip" in response["headers_raw"].lower()
    first = json.loads(response["body"])
    assert first["entries"][0]["id"] == "0"
    assert first["nextCursor"] == "1"
    for cursor in (1, 2):
        response = run_curl_request(base + f"/api/v2/logs?from={cursor}&limit=1", method="GET",
                                    http_mode=mode, extra_args=["--compressed"])
        page = json.loads(response["body"])
        assert [entry["id"] for entry in page["entries"]] == [str(cursor)]
        assert page["nextCursor"] == str(cursor + 1)
    empty = requests.get(base + "/api/v2/logs?from=999", timeout=5).json()
    assert empty["entries"] == [] and empty["gap"] is True and empty["nextCursor"] == "3"
    identity = requests.get(base + "/api/v2/logs", headers={"Accept-Encoding": "identity"}, timeout=5)
    assert "Content-Encoding" not in identity.headers
    compressed = requests.get(base + "/api/v2/logs", headers={"Accept-Encoding": "gzip"},
                              stream=True, timeout=5)
    with compressed:
        raw = compressed.raw.read(decode_content=False)
        assert raw[:2] == b"\x1f\x8b"
        assert len(raw) == int(compressed.headers["Content-Length"])
        assert gzip.decompress(raw) == identity.content
        assert len(raw) < len(identity.content)
        assert compressed.headers["Vary"] == "Accept-Encoding"
    for encoding, expected in (("gzip;q=0", None), ("br", None), ("notgzip", None),
                               ("gzip;q=0, *;q=1", None), ("*", "gzip"),
                               ("br, GZip; q=0.5", "gzip"), ("gzip;q=bogus", None),
                               ("gzip;q=1.5", None), ("identity;q=1,gzip;q=0.5", None)):
        response = requests.get(base + "/api/v2/logs", headers={"Accept-Encoding": encoding}, timeout=5)
        assert response.status_code == 200
        assert response.headers.get("Content-Encoding") == expected
        assert response.json() == identity.json()
    for encoding in ("gzip;q=0,identity;q=0", "*;q=0"):
        response = requests.get(base + "/api/v2/logs", headers={"Accept-Encoding": encoding}, timeout=5)
        assert response.status_code == 406
    for method, status in (("HEAD", 200), ("OPTIONS", 204)):
        response = requests.request(method, base + "/api/v2/logs", timeout=5)
        assert response.status_code == status
        assert response.content == b""
        assert "Content-Encoding" not in response.headers


@pytest.mark.parametrize("exporter", [{"compress": False}], indirect=True)
def test_disable_compression(exporter):
    service, urls = exporter
    response = requests.get(urls["EXPORTER"] + "/api/v2/logs", headers={"Accept-Encoding": "gzip"}, timeout=5)
    assert response.status_code == 200
    assert "Content-Encoding" not in response.headers
    assert response.json()["entries"] == []
    response = requests.get(urls["EXPORTER"] + "/api/v2/logs",
                            headers={"Accept-Encoding": "gzip,identity;q=0"}, timeout=5)
    assert response.status_code == 406


def test_forward_log_anyvalue_uint64_and_bytes(exporter):
    service, urls = exporter
    # Forward isolates exporter fidelity from OTLP intake integer conversion.
    body = {"int64": 9007199254740993, "minimum": -9223372036854775808, "uint64": 18446744073709551615, "int": 42, "str": "42", "bytes": b"\x00\xff", "nil": None, "unicode": '雪\n"\\\x00'}
    forwarded = pack_forward(["typed", [[1789516800, body]], {}])
    with socket.create_connection(("127.0.0.1", int(os.environ["AUDIT_FORWARD_PORT"])), timeout=5) as conn:
        conn.sendall(forwarded)
    response = poll(service, urls["EXPORTER"] + "/api/v2/logs", lambda r: bool(r.json()["entries"]))
    decoded = decode_otlp(response.json()["entries"][0]["payload"], ExportLogsServiceRequest)
    values = {pair.key: pair.value for pair in decoded.resource_logs[0].scope_logs[0].log_records[0].body.kvlist_value.values}
    assert values["int"].WhichOneof("value") == "int_value" and values["int"].int_value == 42
    assert values["str"].WhichOneof("value") == "string_value" and values["str"].string_value == "42"
    assert values["int64"].int_value == 9007199254740993
    assert values["minimum"].int_value == -9223372036854775808
    assert values["bytes"].bytes_value == b"\x00\xff"
    assert values["nil"].WhichOneof("value") is None
    assert values["unicode"].string_value == '雪\n"\\\x00'
    tagged = {pair.key: pair.value.string_value for pair in values["uint64"].kvlist_value.values}
    assert tagged == {"fluentbit.type": "uint64", "fluentbit.value": "18446744073709551615"}
