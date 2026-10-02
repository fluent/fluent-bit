"""OTLP round trips preserve dropped-attribute counts at every log envelope level."""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest
import requests
import yaml
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from utils.test_service import FluentBitTestService


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


@pytest.mark.parametrize("count", [0, 7, 4294967295], ids=["zero", "nonzero", "uint32-max"])
@pytest.mark.parametrize("processed", [False, True], ids=["direct", "with-body-processor"])
def test_dropped_attribute_counts_round_trip(tmp_path, count, processed):
    source = grouped_payload()
    for resource in source.resource_logs:
        resource.resource.dropped_attributes_count = count
        for scope in resource.scope_logs:
            scope.scope.dropped_attributes_count = count
            for record in scope.log_records:
                record.dropped_attributes_count = count
    expected = deepcopy(source)
    if processed:
        for resource in expected.resource_logs:
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    record.body.kvlist_value.values.add(key="processed").value.string_value = "yes"
    processors = [{"name": "content_modifier", "action": "insert", "key": "processed",
                   "value": "yes"}]
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
    if processed:
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
        service.wait_for_condition(
            lambda: len(flatten(received[0])) >= 4 and
                    len(flatten(received[1])) >= 4,
            timeout=30, interval=0.1, description="both grouped output routes to finish",
        )
        for route, payloads in enumerate(received):
            (tmp_path / f"route-{route}.txt").write_text("\n".join(str(p) for p in payloads))

    finally:
        try:
            service.stop()
        finally:
            sink.shutdown()
            sink.server_close()
            thread.join(timeout=5)
    assert flatten(received[0]) == flatten([expected])
    assert flatten(received[1]) == flatten([source])
    # Group envelopes must remain paired with their logical records.
    for route in received:
        for payload in route:
            for resource in payload.resource_logs:
                assert resource.scope_logs
                assert all(scope.log_records for scope in resource.scope_logs)
