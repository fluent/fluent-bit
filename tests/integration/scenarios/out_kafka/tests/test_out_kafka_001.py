import json
import os
import struct
from copy import deepcopy

import requests
import pytest
from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from server.kafka_server import data_storage, kafka_server_run, kafka_server_stop
from utils.data_utils import read_json_file
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["connections", "requests", "messages"],
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.kafka_port = service.allocate_port_env("TEST_SUITE_KAFKA_PORT")
        kafka_server_run(self.kafka_port)

    def _stop_receiver(self, service):
        kafka_server_stop()

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def wait_for_messages(self, minimum_count=1, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["messages"] if len(data_storage["messages"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} Kafka messages",
        )

    def send_json_logs_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "logs")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/logs",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_json_metrics_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "metrics")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/metrics",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_json_traces_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "traces")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/traces",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_payload_dict(self, payload_dict, signal_type):
        payload = self._build_signal_payload_from_dict(payload_dict, signal_type)
        endpoints = {
            "logs": "/v1/logs",
            "metrics": "/v1/metrics",
            "traces": "/v1/traces",
        }
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}{endpoints[signal_type]}",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def _resolve_json_fixture(self, json_file):
        return os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "../../in_opentelemetry/tests/data_files",
                json_file,
            )
        )

    def _build_signal_payload(self, json_file, signal_type):
        messages = {
            "logs": ExportLogsServiceRequest(),
            "metrics": ExportMetricsServiceRequest(),
            "traces": ExportTraceServiceRequest(),
        }
        return json_format.Parse(
            json.dumps(read_json_file(self._resolve_json_fixture(json_file))),
            messages[signal_type],
        )

    def _build_signal_payload_from_dict(self, payload_dict, signal_type):
        messages = {
            "logs": ExportLogsServiceRequest(),
            "metrics": ExportMetricsServiceRequest(),
            "traces": ExportTraceServiceRequest(),
        }
        return json_format.Parse(json.dumps(payload_dict), messages[signal_type])


def _decode_simple_msgpack(data, offset=0):
    first = data[offset]
    offset += 1

    if first <= 0x7F:
        return first, offset
    if 0xA0 <= first <= 0xBF:
        size = first & 0x1F
        end = offset + size
        return data[offset:end].decode("utf-8"), end
    if 0x80 <= first <= 0x8F:
        size = first & 0x0F
        mapping = {}
        for _ in range(size):
            key, offset = _decode_simple_msgpack(data, offset)
            value, offset = _decode_simple_msgpack(data, offset)
            mapping[key] = value
        return mapping, offset
    if first == 0xC0:
        return None, offset
    if first == 0xC2:
        return False, offset
    if first == 0xC3:
        return True, offset
    if first == 0xCC:
        return data[offset], offset + 1
    if first == 0xCD:
        return int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    if first == 0xCE:
        return int.from_bytes(data[offset:offset + 4], "big"), offset + 4
    if first == 0xCA:
        return struct.unpack(">f", data[offset:offset + 4])[0], offset + 4
    if first == 0xCB:
        return struct.unpack(">d", data[offset:offset + 8])[0], offset + 8
    if first == 0xD9:
        size = data[offset]
        offset += 1
        end = offset + size
        return data[offset:end].decode("utf-8"), end

    raise ValueError(f"Unsupported MessagePack type 0x{first:02x}")


def _decode_otlp_proto(data, signal_type):
    messages = {
        "logs": ExportLogsServiceRequest(),
        "metrics": ExportMetricsServiceRequest(),
        "traces": ExportTraceServiceRequest(),
    }
    message = messages[signal_type]
    message.ParseFromString(data)
    return json.loads(json_format.MessageToJson(message))


def _resource_key(signal_type):
    return {
        "logs": "resource_logs",
        "metrics": "resource_metrics",
        "traces": "resource_spans",
    }[signal_type]


def _resource_key_camel(signal_type):
    return {
        "logs": "resourceLogs",
        "metrics": "resourceMetrics",
        "traces": "resourceSpans",
    }[signal_type]


def _load_signal_fixture(service, json_file):
    return read_json_file(service._resolve_json_fixture(json_file))


def _build_multi_resource_payload(service, signal_type, json_file):
    payload = _load_signal_fixture(service, json_file)
    key = _resource_key(signal_type)
    resources = payload[key]
    base = resources[0]

    clone = deepcopy(base)
    if signal_type == "logs":
        clone["resource"]["attributes"][0]["value"]["string_value"] = "example-service-bulk"
        clone["scope_logs"][0]["log_records"][0]["body"]["string_value"] = "bulk log resource"
    elif signal_type == "metrics":
        clone["resource"]["attributes"][0]["value"]["string_value"] = "instance-bulk"
        clone["scope_metrics"][0]["metrics"][0]["name"] = "requests_total_bulk"
    else:
        clone["resource"]["attributes"][0]["value"]["string_value"] = "checkout-bulk"
        clone["scope_spans"][0]["spans"][0]["name"] = "bulk-trace-span"

    resources.append(clone)
    return payload


def _decode_kafka_payload(message, format_name, signal_type):
    if format_name == "otlp_json":
        return json.loads(message["value"].decode("utf-8"))
    return _decode_otlp_proto(message["value"], signal_type)


def _collect_resources(messages, format_name, signal_type):
    resource_key = _resource_key_camel(signal_type)
    resources = []

    for message in messages:
        payload = _decode_kafka_payload(message, format_name, signal_type)
        resources.extend(payload[resource_key])

    return resources


def test_out_kafka_sends_json_payload():
    service = Service("out_kafka_basic.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["topic"] == "test"
    assert message["partition"] == 0
    assert message["key"] is None

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "hello from out_kafka"
    assert payload["source"] == "dummy"
    assert any(request["api_key"] == 3 for request in data_storage["requests"])
    assert any(request["api_key"] == 0 for request in data_storage["requests"])


def test_out_kafka_raw_format_uses_selected_field():
    service = Service("out_kafka_raw.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["topic"] == "test"
    assert message["value"] == b"raw value"


def test_out_kafka_message_key_field_sets_kafka_key():
    service = Service("out_kafka_message_key_field.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["topic"] == "test"
    assert message["key"] == b"key-123"

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "hello with key"
    assert payload["message_key"] == "key-123"


def test_out_kafka_dynamic_topic_routes_to_record_topic():
    service = Service("out_kafka_dynamic_topic.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["topic"] == "topic-dynamic"

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "hello dynamic topic"
    assert payload["topic_name"] == "topic-dynamic"


def test_out_kafka_msgpack_format_sends_msgpack_payload():
    service = Service("out_kafka_msgpack.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["topic"] == "test"
    assert message["key"] is None

    payload, offset = _decode_simple_msgpack(message["value"])
    assert offset == len(message["value"])
    assert payload["message"] == "hello msgpack"
    assert payload["count"] == 7
    assert payload["source"] == "dummy"


def test_out_kafka_otlp_json_logs():
    service = Service("out_kafka_otlp_json.yaml")
    service.start()
    service.send_json_logs_payload("test_logs_001.in.json")

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    payload = json.loads(message["value"].decode("utf-8"))
    record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]

    assert message["topic"] == "otlp-topic"
    assert message["key"] == b"static-otlp-key"
    assert payload["resourceLogs"]
    assert record["body"]["stringValue"] == "This is an example log message."
    assert payload["resourceLogs"][0]["resource"]["attributes"][0]["key"] == "service.name"


def test_out_kafka_otlp_json_metrics():
    service = Service("out_kafka_otlp_json.yaml")
    service.start()
    service.send_json_metrics_payload("test_metrics_001.in.json")

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    payload = json.loads(message["value"].decode("utf-8"))
    metric = payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
    data_point = metric["sum"]["dataPoints"][0]

    assert message["topic"] == "otlp-topic"
    assert message["key"] == b"static-otlp-key"
    assert payload["resourceMetrics"]
    assert metric["name"] == "requests_total"
    assert data_point["attributes"][0]["key"] == "service.name"
    assert data_point["attributes"][0]["value"]["stringValue"] == "checkout"


def test_out_kafka_otlp_json_traces():
    service = Service("out_kafka_otlp_json.yaml")
    service.start()
    service.send_json_traces_payload("test_traces_001.in.json")

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    payload = json.loads(message["value"].decode("utf-8"))
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]

    assert message["topic"] == "otlp-topic"
    assert message["key"] == b"static-otlp-key"
    assert payload["resourceSpans"]
    assert span["name"] == "checkout-span"


def test_out_kafka_otlp_proto_logs():
    service = Service("out_kafka_otlp_proto.yaml")
    service.start()
    service.send_json_logs_payload("test_logs_001.in.json")

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    payload = _decode_otlp_proto(message["value"], "logs")
    record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]

    assert message["topic"] == "otlp-topic"
    assert message["key"] == b"static-otlp-key"
    assert payload["resourceLogs"]
    assert record["body"]["stringValue"] == "This is an example log message."
    assert payload["resourceLogs"][0]["resource"]["attributes"][0]["key"] == "service.name"


def test_out_kafka_otlp_proto_metrics():
    service = Service("out_kafka_otlp_proto.yaml")
    service.start()
    service.send_json_metrics_payload("test_metrics_001.in.json")

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    payload = _decode_otlp_proto(message["value"], "metrics")
    metric = payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
    data_point = metric["sum"]["dataPoints"][0]

    assert message["topic"] == "otlp-topic"
    assert message["key"] == b"static-otlp-key"
    assert payload["resourceMetrics"]
    assert metric["name"] == "requests_total"
    assert data_point["attributes"][0]["key"] == "service.name"
    assert data_point["attributes"][0]["value"]["stringValue"] == "checkout"


def test_out_kafka_otlp_proto_traces():
    service = Service("out_kafka_otlp_proto.yaml")
    service.start()
    service.send_json_traces_payload("test_traces_001.in.json")

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    payload = _decode_otlp_proto(message["value"], "traces")
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]

    assert message["topic"] == "otlp-topic"
    assert message["key"] == b"static-otlp-key"
    assert payload["resourceSpans"]
    assert span["name"] == "checkout-span"


@pytest.mark.parametrize(
    "format_name,config_file,signal_type,json_file",
    [
        ("otlp_json", "out_kafka_otlp_json.yaml", "logs", "test_logs_001.in.json"),
        ("otlp_json", "out_kafka_otlp_json.yaml", "metrics", "test_metrics_001.in.json"),
        ("otlp_json", "out_kafka_otlp_json.yaml", "traces", "test_traces_001.in.json"),
        ("otlp_proto", "out_kafka_otlp_proto.yaml", "logs", "test_logs_001.in.json"),
        ("otlp_proto", "out_kafka_otlp_proto.yaml", "metrics", "test_metrics_001.in.json"),
        ("otlp_proto", "out_kafka_otlp_proto.yaml", "traces", "test_traces_001.in.json"),
    ],
    ids=[
        "otlp_json_logs",
        "otlp_json_metrics",
        "otlp_json_traces",
        "otlp_proto_logs",
        "otlp_proto_metrics",
        "otlp_proto_traces",
    ],
)
def test_out_kafka_otlp_formats_preserve_multiple_resources(
    format_name,
    config_file,
    signal_type,
    json_file,
):
    service = Service(config_file)
    service.start()
    payload_dict = _build_multi_resource_payload(service, signal_type, json_file)
    service.send_payload_dict(payload_dict, signal_type)

    expected_message_count = 2 if signal_type == "metrics" else 1
    messages = service.wait_for_messages(expected_message_count)
    service.stop()

    resources = _collect_resources(messages, format_name, signal_type)

    for message in messages:
        assert message["topic"] == "otlp-topic"
        assert message["key"] == b"static-otlp-key"

    assert len(resources) >= 2

    if signal_type == "logs":
        bodies = [
            record["body"]["stringValue"]
            for resource in resources
            for scope in resource["scopeLogs"]
            for record in scope["logRecords"]
        ]
        resource_names = [
            attribute["value"]["stringValue"]
            for resource in resources
            for attribute in resource["resource"]["attributes"]
            if attribute["key"] == "service.name"
        ]
        assert "This is an example log message." in bodies
        assert "bulk log resource" in bodies
        assert "example-service-bulk" in resource_names
    elif signal_type == "metrics":
        metric_names = [
            metric["name"]
            for resource in resources
            for scope in resource["scopeMetrics"]
            for metric in scope["metrics"]
        ]
        assert "requests_total" in metric_names
        assert "requests_total_bulk" in metric_names
        if format_name == "otlp_json":
            instance_ids = [
                attribute["value"]["stringValue"]
                for resource in resources
                for attribute in resource["resource"]["attributes"]
                if attribute["key"] == "service.instance.id"
            ]
            assert "instance-bulk" in instance_ids
    else:
        span_names = [
            span["name"]
            for resource in resources
            for scope in resource["scopeSpans"]
            for span in scope["spans"]
        ]
        service_names = [
            attribute["value"]["stringValue"]
            for resource in resources
            for attribute in resource["resource"]["attributes"]
            if attribute["key"] == "service.name"
        ]
        assert "checkout-span" in span_names
        assert "bulk-trace-span" in span_names
        assert "checkout-bulk" in service_names
