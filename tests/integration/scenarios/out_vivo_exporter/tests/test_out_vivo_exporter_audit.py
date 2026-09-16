"""Producer/consumer regressions for the September 2026 VIVO audit."""
import json
import os
import socket

import struct
import pytest
import requests
import yaml

from utils.http_matrix import curl_supports_http2, run_curl_request
from utils.test_service import FluentBitTestService


@pytest.fixture
def exporter(tmp_path, request):
    config = {
        "service": {"flush": 1, "grace": 1, "log_level": "info",
                    "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [
                {"name": "http", "listen": "127.0.0.1", "port": "${AUDIT_INPUT_PORT}"},
                {"name": "forward", "listen": "127.0.0.1", "port": "${AUDIT_FORWARD_PORT}"},
                {"name": "opentelemetry", "listen": "127.0.0.1", "port": "${AUDIT_OTEL_PORT}"},
            ],
            "outputs": [{"name": "vivo_exporter", "match": "*", "host": "127.0.0.1",
                         "port": "${AUDIT_EXPORTER_PORT}", "http_cors_allow_origin": "*",
                         "stream_queue_size": "512K", "stream_page_size": "512K"}],
        },
    }
    config["pipeline"]["outputs"][0].update(getattr(request, "param", {}))
    path = tmp_path / "audit.yaml"
    path.write_text(yaml.safe_dump(config))
    ports = {}

    def prepare(service):
        for name in ("INPUT", "OTEL", "EXPORTER", "FORWARD"):
            ports[name] = service.allocate_port_env(f"AUDIT_{name}_PORT")

    service = FluentBitTestService(str(path), pre_start=prepare)
    service.start()
    try:
        yield service, {name: f"http://127.0.0.1:{port}" for name, port in ports.items()}
    finally:
        service.stop()


def headers(response):
    return {key.strip().lower(): value.strip()
            for line in response["headers_raw"].splitlines() if ":" in line
            for key, value in [line.split(":", 1)]}


def poll(service, url, predicate):
    def attempt():
        response = requests.get(url, timeout=5)
        assert response.status_code == 200
        return response if predicate(response) else None
    return service.wait_for_condition(attempt, timeout=15, interval=0.2, description=url)


@pytest.mark.parametrize("mode", ["http1.1", "http2-prior-knowledge"])
def test_pagination_methods_and_recovery(exporter, mode):
    if mode.startswith("http2") and not curl_supports_http2():
        pytest.skip("curl lacks HTTP/2")
    service, urls = exporter
    for index in range(3):
        assert requests.post(urls["INPUT"] + "/audit", json={"index": index}, timeout=5).ok
        poll(service, urls["EXPORTER"] + "/api/v1/logs",
             lambda r: f'"index":{index}' in r.text)
    url = urls["EXPORTER"] + "/api/v1/logs"

    def read(query="", method="GET"):
        return run_curl_request(url + query, payload="" if method == "POST" else None,
                                method=method, http_mode=mode, include_headers=True)

    first = read("?from=0&limit=1")
    meta = headers(first)
    assert len(first["body"].splitlines()) == 1
    assert meta["content-type"].startswith("application/x-ndjson")
    assert meta["vivo-stream-next-id"] == "1"
    assert meta["vivo-stream-end-id"] == "0"
    assert meta["cache-control"] == "no-store"
    assert len(meta["vivo-stream-generation"]) == 36
    assert len(read("?from=1")["body"].splitlines()) == 2
    assert len(read("?to=0")["body"].splitlines()) == 1
    for query in ("?from=abc", "?notfrom=3", "?from=-1", "?from=9223372036854775808",
                  "?from=1&from=2", "?limit=0", "?from=2&to=1"):
        assert read(query)["status_code"] == 400
    for method, status in (("HEAD", 200), ("OPTIONS", 204), ("POST", 405)):
        response = read(method=method)
        assert response["status_code"] == status
        assert response["body"] == ""
    assert len(read()["body"].splitlines()) == 3
    empty = read("?from=999")
    assert empty["body"] == ""
    assert headers(empty)["vivo-stream-gap"] == "true"
    assert headers(empty)["vivo-stream-tail-id"] == "3"
    assert headers(empty)["vivo-stream-generation"] == meta["vivo-stream-generation"]
    health = requests.get(urls["EXPORTER"] + "/api/v2/health", timeout=5)
    assert health.json()["versions"] == [1, 2]
    v2 = requests.get(urls["EXPORTER"] + "/api/v2/logs?limit=1", timeout=5)
    page = v2.json()
    assert page["schemaVersion"] == 2
    assert page["nextCursor"] == "1"
    record = page["entries"][0]["payload"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert isinstance(record["timeUnixNano"], str)
    assert record["body"]["kvlistValue"]["values"][0]["value"] == {"intValue": "0"}


def test_log_group_identity_and_large_payload(exporter):
    service, urls = exporter
    resources = []
    for index in range(2):
        resources.append({"schemaUrl": f"resource-schema-{index}",
                          "resource": {"attributes": [{"key": "service.name",
                              "value": {"stringValue": f"service-{index}"}}]},
                          "scopeLogs": [{"schemaUrl": f"scope-schema-{index}",
                              "scope": {"name": f"scope-{index}"},
                              "logRecords": [{"timeUnixNano": "1789516800123456789",
                                  "body": {"stringValue": f"message-{index}" + "x" * 1100}}]}]})
    response = requests.post(urls["OTEL"] + "/v1/logs", json={"resourceLogs": resources}, timeout=5)
    assert response.ok
    response = poll(service, urls["EXPORTER"] + "/api/v2/logs", lambda r: "message-1" in r.text)
    records = []
    for entry in response.json()["entries"]:
        for resource in entry["payload"]["resourceLogs"]:
            for scope in resource["scopeLogs"]:
                for record in scope["logRecords"]:
                    records.append(record)
                    index = 0 if "message-0" in json.dumps(record) else 1
                    assert f"service-{index}" in json.dumps(resource["resource"])
                    assert scope["scope"]["name"] == f"scope-{index}"
                    assert resource["schemaUrl"] == f"resource-schema-{index}"
                    assert scope["schemaUrl"] == f"scope-schema-{index}"
                    assert record["timeUnixNano"] == "1789516800123456789"
    assert len(records) == 2


def test_batched_trace_contexts(exporter):
    service, urls = exporter
    for index in range(100):
        payload = {"resourceSpans": [{"resource": {}, "scopeSpans": [{"scope": {}, "spans": [{
            "traceId": f"{index + 1:032x}", "spanId": f"{index + 1:016x}",
            "name": f"audit-span-{index:03}", "kind": 1,
            "startTimeUnixNano": "1789516800123456789", "endTimeUnixNano": "1789516800124456790"
        }]}]}]}
        assert requests.post(urls["OTEL"] + "/v1/traces", json=payload, timeout=5).ok
    response = poll(service, urls["EXPORTER"] + "/api/v1/traces",
                    lambda r: "audit-span-099" in r.text)
    # Each context is a complete NDJSON object; retention is tested separately.
    for line in response.text.splitlines():
        json.loads(line)
    for index in range(100):
        assert f'"audit-span-{index:03}"' in response.text


def test_oversized_entry_keeps_history(exporter):
    service, urls = exporter
    assert requests.post(urls["INPUT"] + "/audit", json={"message": "retained"}, timeout=5).ok
    before = poll(service, urls["EXPORTER"] + "/api/v1/logs", lambda r: "retained" in r.text)
    assert requests.post(urls["INPUT"] + "/audit", json={"message": "x" * 600000}, timeout=5).ok
    after = poll(service, urls["EXPORTER"] + "/api/v1/logs",
                 lambda r: int(r.headers["vivo-stream-rejected-entries"]) > 0)
    assert before.text == after.text
    assert int(after.headers["vivo-stream-retained-bytes"]) <= 524288


def test_metrics_special_values(exporter):
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest

    service, urls = exporter
    payload = ExportMetricsServiceRequest()
    scope = payload.resource_metrics.add().scope_metrics.add()
    for name, value in (("finite", 1.5), ("nan", float("nan")),
                        ("positive", float("inf")), ("negative", -float("inf"))):
        metric = scope.metrics.add(name=name)
        point = metric.gauge.data_points.add(time_unix_nano=1789516800123456789)
        point.as_double = value
    metric = scope.metrics.add(name="large_counter")
    metric.sum.aggregation_temporality = 2
    metric.sum.is_monotonic = True
    metric.sum.data_points.add(time_unix_nano=1789516800123456789, as_int=9007199254740993)
    assert requests.post(urls["OTEL"] + "/v1/metrics", data=payload.SerializeToString(),
                         headers={"Content-Type": "application/x-protobuf"}, timeout=5).ok
    response = poll(service, urls["EXPORTER"] + "/api/v1/metrics", lambda r: "large_counter" in r.text)
    for line in response.text.splitlines():
        json.loads(line, parse_constant=lambda value: pytest.fail(f"Invalid JSON: {value}"))
    for special in ("NaN", "Infinity", "-Infinity"):
        assert f'"{special}"' in response.text
    v2 = requests.get(urls["EXPORTER"] + "/api/v2/metrics", timeout=5)
    assert v2.ok
    assert '"1789516800123456789"' in v2.text


def test_protobuf_trace_contexts(exporter):
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    service, urls = exporter
    for index in range(100):
        payload = ExportTraceServiceRequest()
        resource = payload.resource_spans.add()
        resource.resource.attributes.add(key="service.name").value.string_value = "audit"
        scope = resource.scope_spans.add()
        scope.scope.name = "audit"
        span = scope.spans.add()
        span.trace_id = (index + 1).to_bytes(16, "big")
        span.span_id = (index + 1).to_bytes(8, "big")
        span.name = f"protobuf-span-{index:03}"
        span.start_time_unix_nano = 1789516800123456789
        span.end_time_unix_nano = 1789516800124456790
        assert requests.post(urls["OTEL"] + "/v1/traces", data=payload.SerializeToString(),
                             headers={"Content-Type": "application/x-protobuf"}, timeout=5).ok
    response = poll(service, urls["EXPORTER"] + "/api/v2/traces", lambda r: "protobuf-span-099" in r.text)
    for line in response.text.splitlines():
        json.loads(line)
    for index in range(100):
        assert f'"protobuf-span-{index:03}"' in response.text
    assert '"1789516800123456789"' in response.text
    assert '"1789516800124456790"' in response.text


@pytest.mark.parametrize("exporter", [{"stream_queue_size": "4000", "stream_page_size": "2048"}],
                         indirect=True)
def test_eviction_and_byte_limited_pages(exporter):
    service, urls = exporter
    url = urls["EXPORTER"] + "/api/v1/logs"
    lengths = []
    for index in range(7):
        assert requests.post(urls["INPUT"] + "/audit", json={"index": index, "text": "x" * 150},
                             timeout=5).ok
        page = poll(service, url + f"?from={index}", lambda r: f'"index":{index}' in r.text)
        v2 = requests.get(urls["EXPORTER"] + f"/api/v2/logs?from={index}", timeout=5)
        stored = v2.json()["entries"][0]
        del stored["id"]
        lengths.append(len(page.content) + len(json.dumps(stored, separators=(",", ":")).encode()))
        assert len(v2.content) <= 2048
        assert len(page.content) <= 2048
        assert int(page.headers["vivo-stream-retained-bytes"]) <= 4000
        assert int(page.headers["vivo-stream-tail-id"]) == index + 1
    expected_oldest = 0
    while sum(lengths[expected_oldest:]) > 4000:
        expected_oldest += 1
    first = requests.get(url + "?from=0", timeout=5)
    assert int(first.headers["vivo-stream-oldest-id"]) == expected_oldest
    assert int(first.headers["vivo-stream-evicted-entries"]) == expected_oldest
    assert first.headers["vivo-stream-gap"] == "true"
    assert len(first.content) <= 2048
    for version in (1, 2):
        cursor = expected_oldest
        seen = []
        while cursor < len(lengths):
            page = requests.get(url.replace("/v1/", f"/v{version}/") + f"?from={cursor}", timeout=5)
            assert len(page.content) <= 2048
            if version == 1:
                for line in page.text.splitlines():
                    seen.extend(record[1]["index"] for record in json.loads(line)["records"])
            else:
                seen.extend(int(entry["id"]) for entry in page.json()["entries"])
            next_cursor = int(page.headers["vivo-stream-next-id"])
            assert next_cursor > cursor
            cursor = next_cursor
        assert seen == list(range(expected_oldest, len(lengths)))



def test_restart_generation_and_empty_recovery(exporter):
    service, urls = exporter
    before = requests.get(urls["EXPORTER"] + "/api/v1/logs", timeout=5)
    assert before.text == ""
    assert before.headers["vivo-stream-oldest-id"] == "0"
    assert before.headers["vivo-stream-tail-id"] == "0"
    service.stop()
    service.start()
    url = f"http://127.0.0.1:{os.environ['AUDIT_EXPORTER_PORT']}/api/v1/logs?from=50"
    after = requests.get(url, timeout=5)
    assert after.text == ""
    assert after.headers["vivo-stream-generation"] != before.headers["vivo-stream-generation"]
    assert after.headers["vivo-stream-gap"] == "true"
    assert after.headers["vivo-stream-next-id"] == "0"



def test_forward_bulk_metrics_contexts(exporter):
    from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest

    service, urls = exporter
    for index in range(2):
        payload = ExportMetricsServiceRequest()
        metric = payload.resource_metrics.add().scope_metrics.add().metrics.add(name=f"bulk_{index}")
        metric.gauge.data_points.add(time_unix_nano=1789516800123456789, as_double=1.0)
        assert requests.post(urls["OTEL"] + "/v1/metrics", data=payload.SerializeToString(),
                             headers={"Content-Type": "application/x-protobuf"}, timeout=5).ok
    response = poll(service, urls["EXPORTER"] + "/api/v1/metrics", lambda r: "bulk_1" in r.text)
    contexts = [json.loads(line) for line in response.text.splitlines()]
    assert len(contexts) == 2
    cursor = response.headers["vivo-stream-tail-id"]
    packed_contexts = b"".join(pack_forward(context) for context in contexts)
    forwarded = pack_forward(["bulk", packed_contexts, {"fluent_signal": 1}])
    with socket.create_connection(("127.0.0.1", int(os.environ["AUDIT_FORWARD_PORT"])), timeout=5) as conn:
        conn.sendall(forwarded)
    response = poll(service, urls["EXPORTER"] + f"/api/v1/metrics?from={cursor}",
                    lambda r: "bulk_0" in r.text and "bulk_1" in r.text)
    assert len(response.text.splitlines()) == 2
    response = requests.get(urls["EXPORTER"] + f"/api/v2/metrics?from={cursor}", timeout=5)
    entries = response.json()["entries"]
    assert entries[0]["source"]["type"] == "forward"
    names = [metric["name"] for entry in entries for resource in entry["payload"]["resourceMetrics"]
             for scope in resource["scopeMetrics"] for metric in scope["metrics"]]
    assert sorted(names) == ["bulk_0", "bulk_1"]



def pack_forward(value):
    """Encode the primitive MessagePack types used by these Forward fixtures."""
    if value is None:
        return b"\xc0"
    if isinstance(value, bool):
        return b"\xc3" if value else b"\xc2"
    if isinstance(value, int):
        return b"\xcf" + struct.pack(">Q", value) if value >= 0 else b"\xd3" + struct.pack(">q", value)
    if isinstance(value, float):
        return b"\xcb" + struct.pack(">d", value)
    if isinstance(value, str):
        encoded = value.encode()
        return b"\xdb" + struct.pack(">I", len(encoded)) + encoded
    if isinstance(value, bytes):
        return b"\xc6" + struct.pack(">I", len(value)) + value
    if isinstance(value, list):
        return b"\xdd" + struct.pack(">I", len(value)) + b"".join(map(pack_forward, value))
    if isinstance(value, dict):
        return (b"\xdf" + struct.pack(">I", len(value)) +
                b"".join(pack_forward(k) + pack_forward(v) for k, v in value.items()))
    raise TypeError(type(value))
