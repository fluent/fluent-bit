"""FTS extensions must preserve metric label processors and non-FTS exports."""
import json
import os
import socket
from pathlib import Path

import pytest
import requests
import yaml

from utils.network import find_available_port
from utils.test_service import FluentBitTestService
from utils.fluent_bit_manager import FluentBitManager
from test_fts_signals import attr, metric, number_point
from google.protobuf.json_format import ParseDict
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from test_fts_policies import attributes


@pytest.mark.parametrize("fts", [False, True])
@pytest.mark.parametrize("unlabeled", [False, True])
def test_labels_and_static_labels_survive_otlp_export(tmp_path, fts, unlabeled):
    source_port, destination_port = find_available_port(), find_available_port()
    processors = ([{"name": "fts", "code": "function process(metric) end"}] if fts else [])
    processors.append({"name": "labels", "insert": "environment production", "update": "region west",
                       "delete": "secret"})
    config = tmp_path / "labels.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}, "pipeline": {
        "inputs": [{"name": "opentelemetry", "port": source_port, "tag": "original",
                    "processors": {"metrics": processors}},
                   {"name": "opentelemetry", "port": destination_port, "tag": "converted"}],
        "outputs": [{"name": "opentelemetry", "match": "original", "host": "127.0.0.1",
                     "port": destination_port, "tls": "off", "add_label": "cluster test"},
                    {"name": "stdout", "match": "converted", "format": "otlp_json"}]}}))
    item = metric("gauge", "series")
    points = [number_point(8), number_point(42)]
    points[1]["startTimeUnixNano"] = "2147483649000000000"
    points[1]["timeUnixNano"] = "2147483649123456789"
    points[1]["flags"] = 3
    if unlabeled:
        for point in points:
            point["attributes"] = []
    item["gauge"]["dataPoints"] = points
    payload = {"resourceMetrics": [{"scopeMetrics": [{"metrics": [item]}]}]}
    service = FluentBitTestService(str(config))
    try:
        service.start()
        response = requests.post(f"http://127.0.0.1:{source_port}/v1/metrics", json=payload, timeout=10)
        response.raise_for_status()
        batches = service.wait_for_condition(lambda: [json.loads(line) for line in
            Path(service.flb.log_file).read_text().splitlines() if line.startswith("{")], timeout=30)
        exported = [p for b in batches for r in b.get("resourceMetrics", []) for s in r["scopeMetrics"]
                    for m in s["metrics"] for p in m["gauge"]["dataPoints"]]
        # OTLP JSON input merges repeated series by labels, so the last point wins.
        expected = [(42, "2147483649000000000", "2147483649123456789", 3)]
        assert [(int(p["asInt"]), p["startTimeUnixNano"], p["timeUnixNano"], p["flags"])
                for p in exported] == expected
        for point in exported:
            values = attributes(point["attributes"])
            assert values["environment"] == "production" and values["cluster"] == "test"
            assert "secret" not in values
            if not unlabeled:
                assert values["region"] == "west"
        assert "cannot construct FTS" not in Path(service.flb.log_file).read_text()
    finally:
        service.stop()


@pytest.mark.parametrize("fts", [False, True])
def test_metric_chunk_compatibility(tmp_path, fts):
    if not os.environ.get("FTS_COMPAT_BINARY"):
        # Always exercise an actual 5.1.0 chunk when that binary is unavailable.
        test_5_1_0_histogram_fixture_survives_forward(tmp_path, fts)
        return
    forward_port, source_port = find_available_port(), find_available_port()
    receiver_config = tmp_path / "receiver.yaml"
    sender_config = tmp_path / "sender.yaml"
    service = {"flush": 0.2, "grace": 1, "http_server": True,
               "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}
    receiver_config.write_text(yaml.safe_dump({"service": service, "pipeline": {
        "inputs": [{"name": "forward", "listen": "127.0.0.1", "port": forward_port}],
        "outputs": [{"name": "stdout", "match": "*"}]}}))
    source = {"name": "opentelemetry", "port": source_port, "tag": "compat"}
    if fts:
        source["processors"] = {"metrics": [{"name": "fts", "code": "function process(metric) end"}]}
    sender_config.write_text(yaml.safe_dump({"service": service, "pipeline": {
        "inputs": [source], "outputs": [{"name": "forward", "match": "*", "host": "127.0.0.1",
                                         "port": forward_port}]}}))
    receiver = FluentBitManager(str(receiver_config), binary_path=os.environ["FTS_COMPAT_BINARY"])
    sender = FluentBitTestService(str(sender_config))
    items = [metric("gauge", "compat_gauge"), metric("sum", "compat_sum"),
             metric("histogram", "compat_histogram")]
    histogram = items[2]["histogram"]["dataPoints"][0]
    histogram.update(bucketCounts=["5", "1", "3"], count="9", sum=12.0)
    items[1]["sum"]["isMonotonic"] = False
    value = {"stringValue": "nested"}
    for _ in range(25):
        value = {"kvlistValue": {"values": [{"key": "child", "value": value}]}}
    items[0]["gauge"]["dataPoints"][0]["attributes"].append({"key": "deep", "value": value})
    payload = {"resourceMetrics": [{"scopeMetrics": [{"metrics": items}]}]}
    try:
        receiver.start()
        sender.start()
        message = ParseDict(payload, ExportMetricsServiceRequest())
        response = requests.post(f"http://127.0.0.1:{source_port}/v1/metrics", data=message.SerializeToString(),
                                 headers={"Content-Type": "application/x-protobuf"}, timeout=10)
        response.raise_for_status()
        text = sender.wait_for_condition(lambda: (text if all(name in text for name in ("compat_gauge", "compat_sum", "compat_histogram")) else None)
            if (text := Path(receiver.log_file).read_text()) else None, timeout=30)
        assert "cmt_decode_msgpack_create failed" not in text
        assert " 8" in text or "=8" in text or "= 8" in text
        histogram_line = next(line for line in text.splitlines() if "compat_histogram" in line)
        # The internal wire format keeps cumulative buckets, as 5.1 expects.
        assert "buckets = { 1=5, 2=6, +Inf=9 }, sum=12, count=9" in histogram_line
        diagnostics = Path(sender.flb.log_file).read_text()
        assert "cannot construct" not in diagnostics and "policy failed" not in diagnostics
    finally:
        sender.stop()
        receiver.stop()


@pytest.mark.parametrize("fts", [False, True])
def test_5_1_0_histogram_fixture_survives_forward(tmp_path, fts):
    port = find_available_port()
    source = {"name": "forward", "listen": "127.0.0.1", "port": port}
    if fts:
        source["processors"] = {"metrics": [{"name": "fts", "code": "function process(metric) end"}]}
    config = tmp_path / "legacy-histogram.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}, "pipeline": {"inputs": [source],
        "outputs": [{"name": "stdout", "match": "*", "format": "otlp_json"}]}}))
    fixture = Path(__file__).resolve().parents[5] / "lib/cmetrics/tests/data/histogram-v5.1.0.msgpack"
    assert fixture.is_file(), "the vendored 5.1.0 compatibility fixture is required"
    data = fixture.read_bytes()
    # PackedForward frame: [tag, binary chunk, {fluent_signal: metrics}].
    message = b"\x93\xa6legacy\xc6" + len(data).to_bytes(4, "big") + data + b"\x81\xadfluent_signal\x01"
    service = FluentBitTestService(str(config))
    try:
        service.start()
        with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
            connection.sendall(message)
        batches = service.wait_for_condition(lambda: [json.loads(line) for line in
            Path(service.flb.log_file).read_text().splitlines() if line.startswith("{")], timeout=30)
        rows = [m for b in batches for r in b.get("resourceMetrics", []) for s in r["scopeMetrics"]
                for m in s["metrics"]]
        assert len(rows) == 1 and rows[0]["name"] == "legacy_histogram"
        point = rows[0]["histogram"]["dataPoints"][0]
        assert [int(count) for count in point["bucketCounts"]] == [5, 1, 3]
        assert int(point["count"]) == 9
        assert point["sum"] == 12.0
        diagnostics = Path(service.flb.log_file).read_text()
        assert "cannot construct" not in diagnostics and "policy failed" not in diagnostics
    finally:
        service.stop()


@pytest.mark.parametrize("signal", ["metrics", "traces"])
@pytest.mark.parametrize("export", ["stdout", "otlp"])
def test_without_fts_json_anyvalue_preservation(tmp_path, signal, export):
    from test_fts_signals import span

    source_port, destination_port = find_available_port(), find_available_port()
    source = {"name": "opentelemetry", "port": source_port, "tag": "source"}
    inputs = [source]
    outputs = [{"name": "stdout", "match": "source", "format": "otlp_json"}]
    if export == "otlp":
        inputs.append({"name": "opentelemetry", "port": destination_port, "tag": "exported"})
        outputs = [{"name": "opentelemetry", "match": "source", "host": "127.0.0.1",
                    "port": destination_port},
                   {"name": "stdout", "match": "exported", "format": "otlp_json"}]
    config = tmp_path / "native-anyvalue.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}, "pipeline": {"inputs": inputs, "outputs": outputs}}))
    values = [attr("healthy", "kept"),
              {"key": "negative", "value": {"intValue": "-9223372036854775808"}},
              {"key": "positive", "value": {"intValue": "9223372036854775807"}},
              {"key": "bytes", "value": {"bytesValue": "AAH/"}},
              {"key": "overflow", "value": {"intValue": "18446744073709551615"}},
              {"key": "invalid", "value": {"boolValue": "wrong"}}]
    if signal == "metrics":
        item = metric("gauge", "native-values")
        item["gauge"]["dataPoints"][0]["attributes"] = values
        resource_key, scope_key, item_key = "resourceMetrics", "scopeMetrics", "metrics"
    else:
        item = span("native-values")
        item["attributes"] = values
        resource_key, scope_key, item_key = "resourceSpans", "scopeSpans", "spans"
    payload = {resource_key: [{scope_key: [{item_key: [item]}]}]}
    service = FluentBitTestService(str(config))
    try:
        service.start()
        response = requests.post(f"http://127.0.0.1:{source_port}/v1/{signal}", json=payload, timeout=10)
        response.raise_for_status()
        batches = service.wait_for_condition(lambda: [json.loads(line) for line in
            Path(service.flb.log_file).read_text().splitlines() if line.startswith("{")], timeout=30)
        rows = [m for b in batches for r in b.get(resource_key, []) for s in r[scope_key] for m in s[item_key]]
        assert len(rows) == 1
        entries = rows[0]["gauge"]["dataPoints"][0]["attributes"] if signal == "metrics" else rows[0]["attributes"]
        fields = {entry["key"]: entry["value"] for entry in entries}
        assert fields["healthy"] == {"stringValue": "kept"}
        assert int(fields["negative"]["intValue"]) == -(2**63)
        assert int(fields["positive"]["intValue"]) == 2**63-1
        assert fields["bytes"] == {"bytesValue": "AAH/"}
        assert "overflow" not in fields and "invalid" not in fields
        diagnostics = Path(service.flb.log_file).read_text()
        assert "could not decode" not in diagnostics and "could not convert" not in diagnostics
    finally:
        service.stop()


@pytest.mark.parametrize("export", ["stdout", "otlp"])
def test_without_fts_unknown_signed_span_kind_keeps_siblings(tmp_path, export):
    from test_fts_signals import span
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
    import base64

    source_port, destination_port = find_available_port(), find_available_port()
    inputs = [{"name": "opentelemetry", "port": source_port, "tag": "source"}]
    outputs = [{"name": "stdout", "match": "source", "format": "otlp_json"}]
    if export == "otlp":
        inputs.append({"name": "opentelemetry", "port": destination_port, "tag": "exported"})
        outputs = [{"name": "opentelemetry", "match": "source", "host": "127.0.0.1", "port": destination_port},
                   {"name": "stdout", "match": "exported", "format": "otlp_json"}]
    config = tmp_path / "signed-kind.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}, "pipeline": {"inputs": inputs, "outputs": outputs}}))
    items = [span("negative-kind"), span("healthy")]
    items[0]["kind"] = -1
    for item in items:
        for key in ("traceId", "spanId", "parentSpanId"):
            item[key] = base64.b64encode(bytes.fromhex(item[key])).decode()
        for link in item["links"]:
            for key in ("traceId", "spanId"):
                link[key] = base64.b64encode(bytes.fromhex(link[key])).decode()
    request = ParseDict({"resourceSpans": [{"resource": {}, "scopeSpans": [{"scope": {}, "spans": items}]}]},
                        ExportTraceServiceRequest())
    service = FluentBitTestService(str(config))
    try:
        service.start()
        response = requests.post(f"http://127.0.0.1:{source_port}/v1/traces", data=request.SerializeToString(),
                                 headers={"Content-Type": "application/x-protobuf"}, timeout=10)
        response.raise_for_status()
        batches = service.wait_for_condition(lambda: [json.loads(line) for line in
            Path(service.flb.log_file).read_text().splitlines() if line.startswith("{")], timeout=30)
        rows = [span for batch in batches for resource in batch.get("resourceSpans", [])
                for scope in resource["scopeSpans"] for span in scope["spans"]]
        # stored traces keep the span; an unknown kind is stored as unspecified
        assert [(row["name"], row.get("kind", 0)) for row in rows] == [("negative-kind", 0), ("healthy", 2)]
        diagnostics = Path(service.flb.log_file).read_text()
        assert "could not decode" not in diagnostics and "could not convert" not in diagnostics
    finally:
        service.stop()


@pytest.mark.parametrize("transport", ["json", "protobuf"])
@pytest.mark.parametrize("fts", [False, True])
def test_log_trace_flags_preserve_the_low_eight_bits(tmp_path, transport, fts):
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

    port = find_available_port()
    source = {"name": "opentelemetry", "port": port}
    if fts:
        source["processors"] = {"logs": [{"name": "fts", "code": "function process(log) end"}]}
    config = tmp_path / "flags.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}, "pipeline": {"inputs": [source],
        "outputs": [{"name": "stdout", "match": "*", "format": "otlp_json"}]}}))
    payload = {"resourceLogs": [{"scopeLogs": [{"logRecords": [{"flags": 300,
        "timeUnixNano": "2147483648123456789", "body": {"kvlistValue": {"values": [attr("marker", "flags")]}}}]}]}]}
    service = FluentBitTestService(str(config))
    try:
        service.start()
        if transport == "protobuf":
            message = ParseDict(payload, ExportLogsServiceRequest())
            response = requests.post(f"http://127.0.0.1:{port}/v1/logs", data=message.SerializeToString(),
                                     headers={"Content-Type": "application/x-protobuf"}, timeout=10)
        else:
            response = requests.post(f"http://127.0.0.1:{port}/v1/logs", json=payload, timeout=10)
        response.raise_for_status()
        batches = service.wait_for_condition(lambda: [json.loads(line) for line in
            Path(service.flb.log_file).read_text().splitlines() if line.startswith("{")], timeout=30)
        rows = [log for batch in batches for resource in batch.get("resourceLogs", [])
                for scope in resource["scopeLogs"] for log in scope["logRecords"]]
        assert len(rows) == 1 and rows[0]["flags"] == 44
        diagnostics = Path(service.flb.log_file).read_text()
        assert "cannot construct" not in diagnostics and "policy failed" not in diagnostics
    finally:
        service.stop()
