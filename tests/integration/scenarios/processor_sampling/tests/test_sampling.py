"""Sampling contracts through OTLP ingestion, processing and protobuf export."""
from collections import Counter
from copy import deepcopy
from pathlib import Path
import threading
import subprocess

import pytest
import requests
import yaml
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError
from utils.memory_check import valgrind_enabled, leaks_enabled
from utils.valgrind import assert_valgrind_clean
from utils.leaks import assert_leaks_clean
from utils.test_service import FluentBitTestService


SIGNALS = {
    "logs": (ExportLogsServiceRequest, "resource_logs", "scope_logs", "log_records"),
    "metrics": (ExportMetricsServiceRequest, "resource_metrics", "scope_metrics", "metrics"),
    "traces": (ExportTraceServiceRequest, "resource_spans", "scope_spans", "spans"),
}


def rows(messages, signal):
    _, resource_key, scope_key, item_key = SIGNALS[signal]
    return [(resource, scope, item) for message in messages
            for resource in getattr(message, resource_key)
            for scope in getattr(resource, scope_key) for item in getattr(scope, item_key)]


def fnv_hash(data):
    h = 14695981039346656037
    for b in data:
        h = ((h ^ b) * 1099511628211) & (2**64 - 1)
    return h


def keep(data, percentage, labels=()):
    """Independent reference for the documented stable hash contract."""
    mask = 2**64 - 1
    h = fnv_hash(data)
    for key, value in labels:
        h ^= fnv_hash(key.encode() + b"\0" + value.encode())
    h ^= h >> 33
    h = h * 0xff51afd7ed558ccd & mask
    h ^= h >> 33
    h = h * 0xc4ceb9fe1a85ec53 & mask
    h ^= h >> 33
    return (h >> 11) / 2**53 < percentage / 100


def source_payloads(count=128):
    payloads = {}
    for signal, (message_type, resource_key, scope_key, item_key) in SIGNALS.items():
        message = message_type()
        for group in range(2):
            resource = getattr(message, resource_key).add(schema_url="https://example.com/resource")
            resource.resource.attributes.add(key="service.name").value.string_value = f"svc-{group}"
            scope = getattr(resource, scope_key).add(schema_url="https://example.com/scope")
            scope.scope.name = f"scope-{group}"
            for i in range(count):
                item = getattr(scope, item_key).add()
                # Only the lower eight bytes vary; the original implementation kept everything.
                trace_id = bytes.fromhex("0102030405060708") + (i + 1).to_bytes(8, "big")
                if signal == "logs":
                    item.body.string_value = f"event-{i}"
                    item.trace_id = trace_id
                    item.span_id = (i + 1).to_bytes(8, "big")
                    item.time_unix_nano = 1700000000000000000 + i
                elif signal == "traces":
                    item.name = f"span-{i}"
                    item.status.SetInParent()
                    item.trace_id = trace_id
                    item.span_id = (i + 1).to_bytes(8, "big")
                    item.start_time_unix_nano = 1700000000000000000
                    item.end_time_unix_nano = 1700000000001000000
                else:
                    item.name = f"metric_{i}"
                    item.description = "-"
                    kind = ["gauge", "sum", "histogram", "exponential_histogram", "summary"][i % 5]
                    data = getattr(item, kind)
                    point = data.data_points.add(time_unix_nano=1700000000000000000)
                    if kind in ("gauge", "sum"):
                        point.as_int = 42
                    else:
                        point.count = 3
                        point.sum = 9
                        if kind == "histogram":
                            point.explicit_bounds.extend([1, 5])
                            point.bucket_counts.extend([1, 1, 1])
                        elif kind == "exponential_histogram":
                            point.scale = 1
                            point.positive.bucket_counts.extend([1, 2])
                        else:
                            point.quantile_values.add(quantile=0.5, value=3)
                    if kind in ("sum", "histogram", "exponential_histogram"):
                        data.aggregation_temporality = 2
        payloads[signal] = message
    return payloads


class Pipeline:
    def __init__(self, tmp_path, processors, location="input"):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        self.received = {signal: [[], []] for signal in SIGNALS}
        received = self.received

        class Sink(BaseHTTPRequestHandler):
            def do_POST(self):
                signal, route = self.path.strip("/").split("/")
                message = SIGNALS[signal][0].FromString(
                    self.rfile.read(int(self.headers["Content-Length"])))
                received[signal][int(route)].append(message)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        source = {"name": "opentelemetry", "tag": "sampling.test",
                  "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}
        outputs = [{"name": "opentelemetry", "match": "*", "host": "127.0.0.1",
                    "port": self.server.server_port,
                    **{f"{signal}_uri": f"/{signal}/{route}" for signal in SIGNALS}}
                   for route in range(2)]
        if location == "input":
            source["processors"] = processors
        else:
            outputs[0]["processors"] = processors
        config = {"service": {"flush": 0.1, "grace": 1, "http_server": True,
                              "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
                  "pipeline": {"inputs": [source], "outputs": outputs}}
        path = tmp_path / "sampling.yaml"
        path.write_text(yaml.safe_dump(config))
        self.service = FluentBitTestService(str(path))

    def send(self, signal, message):
        response = requests.post(f"http://127.0.0.1:{self.service.flb_listener_port}/v1/{signal}",
                                 data=message.SerializeToString(), timeout=30,
                                 headers={"Content-Type": "application/x-protobuf"})
        assert response.status_code in (200, 201), response.text

    def close(self):
        try:
            self.service.stop()
        finally:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("percentage", [0, 12.5, 100])
def test_kubernetes_log_selection_preserves_unmatched_records(tmp_path, location, percentage):
    """Sample only the selected namespace/app, preserving other and unenriched logs."""
    processor = {
        "name": "sampling", "type": "probabilistic",
        "condition": {"op": "and", "rules": [
            {"field": "$kubernetes['namespace_name']", "op": "eq", "value": "staging"},
            {"field": "$kubernetes['labels']['app']", "op": "eq", "value": "checkout"},
        ]},
        "sampling_settings": {"sampling_percentage": percentage},
    }
    source = source_payloads(count=128)["logs"]
    source_count = len(rows([source], "logs"))
    selected_ids = set()
    for index, (_, _, item) in enumerate(rows([source], "logs")):
        item.body.Clear()
        fields = item.body.kvlist_value.values
        fields.add(key="event").value.string_value = f"event-{index}"
        category = index % 4
        if category == 3:
            continue
        kubernetes = fields.add(key="kubernetes").value.kvlist_value.values
        namespace = "production" if category == 1 else "staging"
        app = "payments" if category == 2 else "checkout"
        kubernetes.add(key="namespace_name").value.string_value = namespace
        labels = kubernetes.add(key="labels").value.kvlist_value.values
        labels.add(key="app").value.string_value = app
        if category == 0:
            selected_ids.add(item.trace_id)

    expected = [item.SerializeToString() for _, _, item in rows([source], "logs")
                if item.trace_id not in selected_ids or keep(item.trace_id, percentage)]
    pipeline = Pipeline(tmp_path, {"logs": [processor]}, location)
    try:
        pipeline.service.start()
        for _ in range(2):
            pipeline.send("logs", source)
        pipeline.service.wait_for_condition(
            lambda: all(len(rows(pipeline.received["logs"][route], "logs")) >=
                        2 * (len(expected) if location == "input" or route == 0 else source_count)
                        for route in range(2)),
            timeout=45, description="selected and bypassed Kubernetes logs")
        pipeline.service.stop()
        for route in range(2):
            route_expected = expected if location == "input" or route == 0 else [
                item.SerializeToString() for _, _, item in rows([source], "logs")]
            actual_rows = rows(pipeline.received["logs"][route], "logs")
            assert Counter(item.SerializeToString() for _, _, item in actual_rows) == Counter(
                route_expected * 2)
            assert all(resource.schema_url == "https://example.com/resource" and
                       scope.schema_url == "https://example.com/scope"
                       for resource, scope, _ in actual_rows)
    finally:
        pipeline.close()


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("percentage", [0, 100, 12.5, None], ids=["drop", "keep", "fraction", "default"])
def test_all_signals_and_route_isolation(tmp_path, location, percentage):
    processor = {"name": "sampling", "type": "probabilistic", "debug": True}
    if percentage is not None:
        processor["sampling_settings"] = {"sampling_percentage": percentage}
    rate = 10 if percentage is None else percentage
    pipeline = Pipeline(tmp_path, {signal: [deepcopy(processor)] for signal in SIGNALS}, location)
    source = source_payloads()
    try:
        pipeline.service.start()
        # Repeat across requests to check stable series and trace decisions.
        for _ in range(2):
            for signal, message in source.items():
                pipeline.send(signal, message)
        def all_outputs_arrived():
            for signal, payload in source.items():
                for route in range(2):
                    route_rate = 100 if location == "output" and route == 1 else rate
                    expected_count = sum(keep(item.name.encode() if signal == "metrics"
                                              else item.trace_id, route_rate)
                                         for _, _, item in rows([payload], signal)) * 2
                    if len(rows(pipeline.received[signal][route], signal)) < expected_count:
                        return False
            return True

        if rate == 0 and location == "input":
            def all_zero_rate_requests_processed():
                response = requests.get(
                    f"http://127.0.0.1:{pipeline.service.flb.http_monitoring_port}"
                    "/api/v2/metrics/prometheus", timeout=5)
                response.raise_for_status()
                counts = {signal: 0 for signal in SIGNALS}
                for line in response.text.splitlines():
                    if not line.startswith("fluentbit_processor_invocations_total{"):
                        continue
                    if 'scope="input"' not in line or 'processor="sampling"' not in line:
                        continue
                    for signal in SIGNALS:
                        if f'signal="{signal}"' in line:
                            counts[signal] += float(line.split("}", 1)[1].split()[0])
                # Logs and traces have one invocation per request. Metrics have
                # one per scope; wait for both scopes of both requests as well.
                return (counts["logs"] == 2 and counts["traces"] == 2 and
                        counts["metrics"] == 2 * sum(len(resource.scope_metrics)
                                                    for resource in source["metrics"].resource_metrics))

            pipeline.service.wait_for_condition(all_zero_rate_requests_processed, timeout=30,
                                                 description="all zero-rate input requests processed")

        pipeline.service.wait_for_condition(all_outputs_arrived, timeout=45,
                                             description="all sampled output requests")
        pipeline.service.stop()
        for signal, payload in source.items():
            for route in range(2):
                route_rate = 100 if location == "output" and route == 1 else rate
                expected = []
                for resource, scope, item in rows([payload], signal):
                    key = item.name.encode() if signal == "metrics" else item.trace_id
                    if keep(key, route_rate):
                        expected.append(item.SerializeToString())
                actual_rows = rows(pipeline.received[signal][route], signal)
                actual = [item.SerializeToString() for _, _, item in actual_rows]
                assert Counter(actual) == Counter(expected * 2), (signal, route)
                for resource, scope, _ in actual_rows:
                    assert resource.schema_url == "https://example.com/resource"
                    assert scope.schema_url == "https://example.com/scope"
                    assert scope.scope.name in ("scope-0", "scope-1")
            if 0 < rate < 100:
                assert 0 < len(rows(pipeline.received[signal][0], signal)) < 512
    finally:
        pipeline.close()


@pytest.mark.parametrize("processor,signal,location", [
    ({"type": "probabilistic", "sampling_settings": {"sampling_percentage": rate}}, "traces", "input")
    for rate in [-1, 101, "nan", "inf", "10junk", "", "1" * 2048]
] + [
    ({"type": "probabilistic", "sampling_settings": {"unknown": 1}}, "traces", "input"),
    ({"type": "probabilistic", "sampling_settings": {"sampling_key": ""}}, "logs", "input"),
    ({"type": "probabilistic", "conditions": []}, "traces", "input"),
    ({"type": "tail", "sampling_settings": {"decision_wait": "0s"}}, "traces", "input"),
    ({"type": "tail", "sampling_settings": {"max_traces": -1}}, "traces", "input"),
    ({"type": "tail"}, "logs", "input"),
    ({"type": "tail"}, "metrics", "input"),
    ({"type": "tail"}, "traces", "output"),
])
def test_invalid_configuration_fails_cleanly(tmp_path, processor, signal, location):
    pipeline = Pipeline(tmp_path, {signal: [{"name": "sampling", **processor}]}, location)
    try:
        with pytest.raises(FluentBitStartupError):
            pipeline.service.start()
        diagnostics = Path(pipeline.service.flb.log_file).read_text()
        assert "caught signal" not in diagnostics.lower(), diagnostics
    finally:
        pipeline.close()


def test_tail_wait_and_condition(tmp_path):
    pipeline = Pipeline(tmp_path, {"traces": [{"name": "sampling", "type": "tail", "debug": True,
                        "sampling_settings": {"decision_wait": "1s", "max_traces": 128},
                        "conditions": [{"type": "status_code", "status_codes": ["ERROR"]}]}]})
    message = source_payloads(8)["traces"]
    for _, _, span in rows([message], "traces"):
        span.status.code = 2 if int(span.name.split("-")[1]) % 2 else 1
    try:
        pipeline.service.start()
        pipeline.send("traces", message)
        pipeline.service.wait_for_condition(
            lambda: len(rows(pipeline.received["traces"][0], "traces")) == 8,
            timeout=30, description="tail decisions to arrive")
        pipeline.service.stop()
        for route in range(2):
            actual = rows(pipeline.received["traces"][route], "traces")
            assert len(actual) == 8
            assert all(span.status.code == 2 for _, _, span in actual)
    finally:
        pipeline.close()


@pytest.mark.parametrize("key", ["trace_id", "customer"])
def test_logs_without_trace_and_custom_key(tmp_path, key):
    pipeline = Pipeline(tmp_path, {"logs": [{"name": "sampling", "type": "probabilistic",
                        "sampling_settings": {"sampling_percentage": 50, "sampling_key": key}}]})
    message = ExportLogsServiceRequest()
    scope = message.resource_logs.add().scope_logs.add()
    for i in range(256):
        record = scope.log_records.add(time_unix_nano=1700000000000000000)
        # Equal keyless bodies must still receive independent decisions.
        if key == "trace_id":
            record.body.string_value = "identical event"
        else:
            record.body.kvlist_value.values.add(key="customer").value.string_value = f"tenant-{i}"
    try:
        pipeline.service.start()
        pipeline.send("logs", message)
        pipeline.service.stop()
        result = rows(pipeline.received["logs"][0], "logs")
        if key == "trace_id":
            assert 40 < len(result) < 216
        else:
            actual = {record.body.kvlist_value.values[0].value.string_value for _, _, record in result}
            expected = {f"tenant-{i}" for i in range(256) if keep(f"tenant-{i}".encode(), 50)}
            assert actual == expected
    finally:
        pipeline.close()


def test_metric_series_identity_ignores_label_order(tmp_path):
    pipeline = Pipeline(tmp_path, {"metrics": [{"name": "sampling", "type": "probabilistic",
                        "sampling_settings": {"sampling_percentage": 50}}]})
    payload = ExportMetricsServiceRequest()
    scope = payload.resource_metrics.add().scope_metrics.add()
    metric = scope.metrics.add(name="requests", description="requests")
    for region in ["east", "west"]:
        for i in range(128):
            point = metric.sum.data_points.add(time_unix_nano=1700000000000000000, as_int=42)
            point.attributes.add(key="tenant").value.string_value = f"tenant-{i}"
            point.attributes.add(key="region").value.string_value = region
    metric.sum.aggregation_temporality = 2
    metric.sum.is_monotonic = True
    reordered = deepcopy(payload)
    for point in reordered.resource_metrics[0].scope_metrics[0].metrics[0].sum.data_points:
        point.time_unix_nano += 1
        point.attributes.reverse()
    try:
        pipeline.service.start()
        pipeline.send("metrics", payload)
        pipeline.send("metrics", reordered)
        pipeline.service.stop()
        cohorts = {}
        for _, _, metric in rows(pipeline.received["metrics"][0], "metrics"):
            for point in metric.sum.data_points:
                attrs = {attr.key: attr.value.string_value for attr in point.attributes}
                cohorts.setdefault((point.time_unix_nano, attrs["region"]), set()).add(attrs["tenant"])
                assert point.as_int == 42
            assert metric.sum.is_monotonic
            assert metric.sum.aggregation_temporality == 2
        assert len(cohorts) == 4
        for region in ["east", "west"]:
            first = cohorts[(1700000000000000000, region)]
            second = cohorts[(1700000000000000001, region)]
            expected = {f"tenant-{i}" for i in range(128)
                        if keep(b"requests", 50, [("tenant", f"tenant-{i}"), ("region", region)])}
            assert 0 < len(first) < 128
            assert first == second == expected
        assert cohorts[(1700000000000000000, "east")] != cohorts[(1700000000000000000, "west")]
    finally:
        pipeline.close()


def test_invalid_trace_ids_are_dropped(tmp_path):
    pipeline = Pipeline(tmp_path, {"traces": [{"name": "sampling", "type": "probabilistic",
                        "sampling_settings": {"sampling_percentage": 100}}]})
    message = source_payloads(4)["traces"]
    for resource in message.resource_spans:
        spans = resource.scope_spans[0].spans
        spans[0].trace_id = b"\0" * 16
        spans[1].trace_id = b""
        spans[2].trace_id = b"short-id"
    try:
        pipeline.service.start()
        pipeline.send("traces", message)
        pipeline.service.wait_for_condition(
            lambda: len(rows(pipeline.received["traces"][0], "traces")) >= 2, timeout=30)
        pipeline.service.stop()
        for route in range(2):
            assert [span.name for _, _, span in rows(pipeline.received["traces"][route], "traces")] == [
                "span-3", "span-3"]
    finally:
        pipeline.close()


def test_tail_defaults_discard_pending_spans_at_shutdown(tmp_path):
    pipeline = Pipeline(tmp_path, {"traces": [{"name": "sampling", "type": "tail"}]})
    try:
        pipeline.service.start()
        pipeline.send("traces", source_payloads(8)["traces"])
        pipeline.service.stop()
        assert not rows(pipeline.received["traces"][0], "traces")
    finally:
        pipeline.close()



def test_metric_series_identity_ignores_absent_labels(tmp_path):
    processor = {"name": "sampling", "type": "probabilistic",
                 "sampling_settings": {"sampling_percentage": 10}}
    pipeline = Pipeline(tmp_path, {"metrics": [processor]}, "output")
    payloads = []
    for batch, extra in enumerate([None, "east", "east", ""]):
        payload = ExportMetricsServiceRequest()
        metric = payload.resource_metrics.add().scope_metrics.add().metrics.add(
            name="requests", description="requests")
        for i in range(128):
            point = metric.gauge.data_points.add(time_unix_nano=1700000000000000000 + batch,
                                                as_int=42)
            point.attributes.add(key="tenant").value.string_value = f"tenant-{i}"
        if extra is not None:
            point = metric.gauge.data_points.add(time_unix_nano=1700000000000000000 + batch,
                                                as_int=42)
            point.attributes.add(key="region").value.string_value = extra
            point.attributes.add(key="tenant").value.string_value = "extra"
        if batch == 1:
            metric.gauge.data_points.reverse()
        payloads.append(payload)
    expected = {f"tenant-{i}" for i in range(128)
                if keep(b"requests", 10, [("tenant", f"tenant-{i}")])}
    assert 0 < len(expected) < 128
    try:
        pipeline.service.start()
        for payload in payloads:
            pipeline.send("metrics", payload)
        pipeline.service.wait_for_condition(
            lambda: sum(len(metric.gauge.data_points)
                        for _, _, metric in rows(pipeline.received["metrics"][1], "metrics")) == 515,
            timeout=30, description="all metric batches on the control route")
        pipeline.service.stop()
        cohorts = {}
        for _, _, metric in rows(pipeline.received["metrics"][0], "metrics"):
            for point in metric.gauge.data_points:
                attrs = {attr.key: attr.value.string_value for attr in point.attributes}
                if attrs["tenant"] != "extra":
                    cohorts.setdefault(point.time_unix_nano, set()).add(attrs["tenant"])
        assert len(cohorts) == 4
        assert all(cohort == expected for cohort in cohorts.values())
    finally:
        pipeline.close()


@pytest.mark.parametrize("storage", ["context", "point"])
def test_metric_series_identity_includes_all_exported_labels(tmp_path, storage):
    processors = [{"name": "sampling", "type": "probabilistic",
                   "sampling_settings": {"sampling_percentage": 25}}]
    if storage == "context":
        processors.insert(0, {"name": "labels", "upsert": "region east"})
    pipeline = Pipeline(tmp_path, {"metrics": processors})
    payload = source_payloads()["metrics"]
    expected = Counter()
    for _, _, metric in rows([payload], "metrics"):
        if storage == "point":
            data = getattr(metric, metric.WhichOneof("data"))
            data.data_points[0].attributes.add(key="region").value.string_value = "east"
        if keep(metric.name.encode(), 25, [("region", "east")]):
            expected[metric.name] += 1
    assert 0 < sum(expected.values()) < 256
    try:
        pipeline.service.start()
        pipeline.send("metrics", payload)
        pipeline.service.stop()
        for route in range(2):
            result = rows(pipeline.received["metrics"][route], "metrics")
            assert Counter(metric.name for _, _, metric in result) == expected
            for _, _, metric in result:
                data = getattr(metric, metric.WhichOneof("data"))
                labels = {attr.key: attr.value.string_value for attr in data.data_points[0].attributes}
                assert labels == {"region": "east"}
    finally:
        pipeline.close()



def test_tail_without_conditions_retains_traces_after_wait(tmp_path):
    pipeline = Pipeline(tmp_path, {"traces": [{"name": "sampling", "type": "tail",
                        "sampling_settings": {"decision_wait": "1s", "max_traces": 128}}]})
    payload = source_payloads(8)["traces"]
    expected = Counter(span.SerializeToString() for _, _, span in rows([payload], "traces"))
    try:
        pipeline.service.start()
        pipeline.send("traces", payload)
        pipeline.service.wait_for_condition(
            lambda: all(len(rows(pipeline.received["traces"][route], "traces")) == 16
                        for route in range(2)),
            timeout=30, description="tail decisions without conditions on both routes")
        pipeline.service.stop()
        for route in range(2):
            actual = Counter(span.SerializeToString()
                             for _, _, span in rows(pipeline.received["traces"][route], "traces"))
            assert actual == expected
    finally:
        pipeline.close()



@pytest.mark.parametrize("match_type", ["strict", "regex"])
@pytest.mark.parametrize("legacy", [False, True])
def test_tail_attribute_selection_preserves_scope_schema(tmp_path, match_type, legacy):
    values = ["^svc-[01]$"] if match_type == "regex" else ["svc-0", "svc-1"]
    processor = {"name": "sampling", "type": "tail",
                 "sampling_settings": {"decision_wait": "1s", "legacy_reconcile": legacy},
                 "conditions": [{"type": "string_attribute", "key": "service.name",
                                 "match_type": match_type, "values": values}]}
    pipeline = Pipeline(tmp_path, {"traces": [processor]})
    payload = source_payloads(2)["traces"]
    try:
        pipeline.service.start()
        pipeline.send("traces", payload)
        pipeline.service.wait_for_condition(
            lambda: all(len(rows(pipeline.received["traces"][route], "traces")) == 4
                        for route in range(2)), timeout=15, description="tail attribute decisions")
        pipeline.service.stop()
        for route in range(2):
            for resource, scope, span in rows(pipeline.received["traces"][route], "traces"):
                assert resource.schema_url == "https://example.com/resource"
                assert scope.schema_url == "https://example.com/scope"
                assert scope.scope.name in ("scope-0", "scope-1")
    finally:
        pipeline.close()


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("percentage", [0, 12.5, 100])
@pytest.mark.parametrize("key_type", ["string_value", "bytes_value"])
def test_otlp_log_attribute_sampling_key(tmp_path, location, percentage, key_type):
    processor = {"name": "sampling", "type": "probabilistic",
                 "sampling_settings": {"sampling_percentage": percentage, "sampling_key": "customer"}}
    pipeline = Pipeline(tmp_path, {"logs": [processor]}, location)
    payload = source_payloads()["logs"]
    for index, (_, _, record) in enumerate(rows([payload], "logs")):
        key = f"tenant-{index}"
        value = record.attributes.add(key="customer").value
        setattr(value, key_type, key.encode() if key_type == "bytes_value" else key)
        if index % 2:
            record.body.Clear()
            record.body.kvlist_value.values.add(key="customer").value.string_value = "body-fallback"
    selected = [record.SerializeToString() for index, (_, _, record) in enumerate(rows([payload], "logs"))
                if keep(f"tenant-{index}".encode(), percentage)]
    try:
        pipeline.service.start()
        for _ in range(2):
            pipeline.send("logs", payload)
        pipeline.service.wait_for_condition(
            lambda: all(len(rows(pipeline.received["logs"][route], "logs")) >=
                        2 * (len(rows([payload], "logs")) if location == "output" and route == 1
                             else len(selected)) for route in range(2)),
            timeout=30, description="OTLP attribute sampling decisions")
        pipeline.service.stop()
        for route in range(2):
            expected = ([record.SerializeToString() for _, _, record in rows([payload], "logs")]
                        if location == "output" and route == 1 else selected)
            assert Counter(record.SerializeToString() for _, _, record in
                           rows(pipeline.received["logs"][route], "logs")) == Counter(expected * 2)
    finally:
        pipeline.close()


@pytest.mark.parametrize("signal,location", [(signal, location) for signal in SIGNALS
                                            for location in ["input", "output"]] + [("tail", "input")])
def test_sampling_configuration_dry_run(tmp_path, signal, location):
    processor = {"name": "sampling", "type": "probabilistic",
                 "sampling_settings": {"sampling_percentage": 12.5}}
    if signal == "tail":
        signal = "traces"
        processor.update(type="tail", sampling_settings={"decision_wait": "1s"},
                         conditions=[{"type": "status_code", "status_codes": ["ERROR"]}])
    source = {"name": "opentelemetry"}
    output = {"name": "null", "match": "*"}
    (source if location == "input" else output)["processors"] = {signal: [processor]}
    config = tmp_path / "dry-run.yaml"
    config.write_text(yaml.safe_dump({"pipeline": {"inputs": [source], "outputs": [output]}}))
    command = [FluentBitManager(str(config)).binary_absolute_path, "--dry-run", "-c", str(config)]
    memory_log = tmp_path / "memory.log"
    if valgrind_enabled():
        command = ["valgrind", "--error-exitcode=97", "--leak-check=full",
                   f"--log-file={memory_log}", *command]
    elif leaks_enabled():
        command = ["leaks", "--atExit", "--", *command]
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=60)
    diagnostic = result.stdout + result.stderr
    (tmp_path / "dry-run.log").write_text(diagnostic)
    if valgrind_enabled():
        assert_valgrind_clean(memory_log)
    elif leaks_enabled():
        memory_log.write_text(diagnostic)
        assert_leaks_clean(result.returncode, memory_log)
    assert result.returncode == 0, diagnostic
    assert "configuration test is successful" in diagnostic
