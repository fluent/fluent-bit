"""Grouped OTLP fallback must preserve envelope data and logical-record accounting."""

from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest
import requests
import yaml
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from utils.test_service import FluentBitTestService
from test_content_modifier import processor_metrics


def grouped_payload():
    payload = ExportLogsServiceRequest()
    for group in range(2):
        resource = payload.resource_logs.add()
        resource.schema_url = f"https://schemas.example/resource/{group}"
        attribute = resource.resource.attributes.add(key="service.name")
        attribute.value.string_value = f"service-{group}"
        scope = resource.scope_logs.add()
        scope.schema_url = f"https://schemas.example/scope/{group}"
        scope.scope.name = f"scope-{group}"
        scope.scope.version = "1.2.3"
        scope.scope.attributes.add(key="scope-key").value.string_value = "scope-value"
        for index in range(2):
            record_id = group * 2 + index + 1
            record = scope.log_records.add()
            record.time_unix_nano = 1700000000000000000 + record_id
            record.observed_time_unix_nano = 1700000001000000000 + record_id
            record.severity_number = 9
            record.severity_text = "INFO"
            record.trace_id = bytes([record_id]) * 16
            record.span_id = bytes([record_id]) * 8
            record.flags = record_id
            record.attributes.add(key="original-attribute").value.string_value = "preserved"
            record.body.kvlist_value.values.add(key="id").value.int_value = record_id
            record.body.kvlist_value.values.add(key="target").value.string_value = "original"
    return payload


def flatten(payloads):
    """Associate every log with its complete resource and scope envelopes."""
    result = []
    for payload in payloads:
        for resource in payload.resource_logs:
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    result.append((resource.schema_url, resource.resource,
                                   scope.schema_url, scope.scope, record))
    return sorted(result, key=lambda entry: next(
        item.value.int_value for item in entry[4].body.kvlist_value.values if item.key == "id"
    ))


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("mixed", [False, True], ids=["group-fallback", "mixed-native-fallback"])
def test_grouped_fallback_envelopes_and_accounting(tmp_path, location, mixed):
    source = grouped_payload()
    expected = deepcopy(source)
    for resource in expected.resource_logs:
        for scope in resource.scope_logs:
            for record in scope.log_records:
                for item in record.body.kvlist_value.values:
                    if item.key == "target":
                        item.key = "renamed"
                        item.value.string_value = (hashlib.sha256(b"updated").hexdigest()
                                                   if mixed else "updated")
                record.body.kvlist_value.values.add(key="after").value.string_value = "yes"
    remaining = 4
    processors = [
        {"name": "content_modifier", "action": "upsert", "key": "target", "value": "updated"},
        {"name": "content_modifier", "action": "rename", "key": "target", "value": "renamed"},
    ]
    counts = [(4, 4), (4, 4)]
    if mixed:
        processors.append({"name": "content_modifier", "action": "hash", "key": "renamed"})
        counts.append((4, 4))
    processors.append({"name": "content_modifier", "action": "insert", "key": "after",
                       "value": "yes"})
    counts.append((remaining, remaining))
    received = [[], []]
    lock = threading.Lock()

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = ExportLogsServiceRequest()
            payload.ParseFromString(self.rfile.read(int(self.headers["Content-Length"])))
            with lock:
                received[int(self.path[-1])].append(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    input_config = {"name": "opentelemetry", "listen": "127.0.0.1",
                    "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "tag": "test",
                    "storage.type": "filesystem"}
    outputs = [{"name": "opentelemetry", "match": "*", "host": "127.0.0.1",
                "port": sink.server_port, "logs_uri": f"/logs/{route}"}
               for route in range(2)]
    if location == "input":
        input_config["processors"] = {"logs": processors}
    else:
        outputs[0]["processors"] = {"logs": processors}
    config = {
        "service": {"flush": 0.1, "grace": 1, "log_level": "error",
                    "storage.path": str(tmp_path / "storage"), "http_server": True,
                    "http_listen": "127.0.0.1",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [input_config], "outputs": outputs},
    }
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    try:
        service.start()
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",
                                 data=source.SerializeToString(),
                                 headers={"Content-Type": "application/x-protobuf"}, timeout=30)
        assert response.status_code == 201, response.text
        control_count = remaining if location == "input" else 4
        service.wait_for_condition(
            lambda: len(flatten(received[0])) >= remaining and
                    len(flatten(received[1])) >= control_count,
            timeout=30, interval=0.1, description="both grouped output routes to finish",
        )
        for route, payloads in enumerate(received):
            (tmp_path / f"route-{route}.txt").write_text("\n".join(str(p) for p in payloads))

        def metrics_ready():
            response = requests.get(
                f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus",
                timeout=10,
            )
            response.raise_for_status()
            values = processor_metrics(response.text, location, owner="opentelemetry.0")
            for stage, (before, after) in enumerate(counts):
                if values.get(("fluentbit_processor_items_in_total", stage), 0) != before:
                    return None
                if values.get(("fluentbit_processor_items_out_total", stage), 0) != after:
                    return None
            return values

        values = service.wait_for_condition(metrics_ready, timeout=30, interval=0.2,
                                             description="group markers excluded from accounting")
        for stage, (before, after) in enumerate(counts):
            assert values[("fluentbit_processor_invocations_total", stage)] == 1
            assert values.get(("fluentbit_processor_errors_total", stage), 0) == 0
            assert values.get(("fluentbit_processor_items_drop_total", stage), 0) == before - after
            assert values.get(("fluentbit_processor_items_add_total", stage), 0) == 0
    finally:
        try:
            service.stop()
        finally:
            sink.shutdown()
            sink.server_close()
            thread.join(timeout=5)
    assert flatten(received[0]) == flatten([expected])
    assert flatten(received[1]) == flatten([expected if location == "input" else source])
    # Group envelopes must remain paired with their logical records.
    for route in received:
        for payload in route:
            for resource in payload.resource_logs:
                assert resource.scope_logs
                assert all(scope.log_records for scope in resource.scope_logs)
