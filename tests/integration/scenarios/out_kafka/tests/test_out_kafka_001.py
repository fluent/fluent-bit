import json
import os
import socket
import struct
import time
from copy import deepcopy

import requests
import pytest
from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from server.kafka_server import data_storage, kafka_server_run, kafka_server_stop
from server.schema_registry_server import (
    SCHEMA_ID,
    SCHEMA_SUBJECT,
    data_storage as schema_registry_data_storage,
    schema_registry_server_run,
    schema_registry_server_stop,
)
from utils.data_utils import read_json_file
from utils.memory_check import memory_check_enabled
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


EMPTY_MAP_RECORD_ID = "97789a11215b54828d2c3f50b864afed42543ff8"


class Service:
    def __init__(
        self,
        config_file,
        *,
        extra_env=None,
        use_schema_registry=False,
        kafka_response_delay=0,
    ):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.use_schema_registry = use_schema_registry
        self.kafka_response_delay = kafka_response_delay
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["connections", "requests", "messages"],
            extra_env=extra_env,
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.kafka_port = service.allocate_port_env("TEST_SUITE_KAFKA_PORT")
        self.forward_port = service.allocate_port_env("TEST_SUITE_FORWARD_PORT")
        kafka_server_run(
            self.kafka_port,
            response_delay=self.kafka_response_delay,
        )
        if self.use_schema_registry:
            self.schema_registry_port = service.allocate_port_env("TEST_SUITE_SCHEMA_REGISTRY_PORT")
            schema_registry_server_run(self.schema_registry_port)

    def _stop_receiver(self, service):
        if self.use_schema_registry:
            schema_registry_server_stop()
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

    def send_forward_record(self, payload):
        with socket.create_connection(("127.0.0.1", self.forward_port), timeout=5) as sock:
            sock.sendall(payload)

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


def _decode_avro_long(data, offset=0):
    encoded = 0
    shift = 0

    while True:
        if offset >= len(data):
            raise ValueError("Truncated Avro long")

        byte = data[offset]
        offset += 1

        if shift == 63 and byte & 0x7E:
            raise ValueError("Invalid Avro long")

        encoded |= (byte & 0x7F) << shift

        if byte & 0x80 == 0:
            break

        shift += 7
        if shift >= 64:
            raise ValueError("Invalid Avro long")

    return (encoded >> 1) ^ -(encoded & 1), offset


def _decode_avro_string(data, offset=0):
    size, offset = _decode_avro_long(data, offset)
    end = offset + size

    if size < 0 or end > len(data):
        raise ValueError("Invalid Avro string")

    return data[offset:end].decode("utf-8"), end


def _encode_msgpack_string(value):
    encoded = value.encode("utf-8")
    size = len(encoded)

    if size < 32:
        return bytes([0xA0 | size]) + encoded
    if size <= 0xFF:
        return b"\xd9" + bytes([size]) + encoded
    if size <= 0xFFFF:
        return b"\xda" + size.to_bytes(2, "big") + encoded
    if size <= 0xFFFFFFFF:
        return b"\xdb" + size.to_bytes(4, "big") + encoded

    raise ValueError("Test MessagePack string exceeds uint32")


def _encode_msgpack_binary(value):
    size = len(value)

    if size <= 0xFF:
        return b"\xc4" + bytes([size]) + value
    if size <= 0xFFFF:
        return b"\xc5" + size.to_bytes(2, "big") + value
    if size <= 0xFFFFFFFF:
        return b"\xc6" + size.to_bytes(4, "big") + value

    raise ValueError("Test MessagePack binary value exceeds uint32")


def _encode_msgpack_map(entries):
    if len(entries) >= 16:
        raise ValueError("Test MessagePack maps must fit in fixmap")

    return bytes([0x80 | len(entries)]) + b"".join(
        encoded_key + encoded_value for encoded_key, encoded_value in entries
    )


def _encode_forward_record_entries(entries, timestamp=1):
    record = _encode_msgpack_map(entries)
    return (
        b"\x93"
        + _encode_msgpack_string("out_kafka")
        + bytes([timestamp])
        + record
    )


def _encode_forward_record_with_binary_headers():
    headers = b"".join(
        [
            b"\x85",
            _encode_msgpack_string("x-binary"),
            b"\xc4\x03\x00\xffA",
            _encode_msgpack_string("x-repeat"),
            _encode_msgpack_string("first"),
            _encode_msgpack_string("x-repeat"),
            _encode_msgpack_string("second"),
            b"\x01",
            _encode_msgpack_string("invalid-name"),
            _encode_msgpack_string("x-invalid"),
            b"\x2a",
        ]
    )
    record = b"".join(
        [
            b"\x82",
            _encode_msgpack_string("message"),
            _encode_msgpack_string("binary headers"),
            _encode_msgpack_string("headers"),
            headers,
        ]
    )
    return b"\x93" + _encode_msgpack_string("out_kafka") + b"\x01" + record


def _encode_forward_record_with_binary_header(value, name="x-large"):
    headers = _encode_msgpack_map(
        [
            (_encode_msgpack_string(name), _encode_msgpack_binary(value)),
        ]
    )
    return _encode_forward_record_entries(
        [
            (_encode_msgpack_string("message"), _encode_msgpack_string("large header")),
            (_encode_msgpack_string("headers"), headers),
        ]
    )


def _encode_forward_records_with_headers():
    entries = []

    for timestamp, message in [(1, "batch one"), (2, "batch two")]:
        headers = (
            b"\x81"
            + _encode_msgpack_string("x-batch")
            + _encode_msgpack_string("value")
        )
        record = b"".join(
            [
                b"\x82",
                _encode_msgpack_string("message"),
                _encode_msgpack_string(message),
                _encode_msgpack_string("headers"),
                headers,
            ]
        )
        entries.append(b"\x92" + bytes([timestamp]) + record)

    return b"".join(
        [
            b"\x92",
            _encode_msgpack_string("out_kafka"),
            b"\x92",
            *entries,
        ]
    )


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


def _build_resource_collision_payload(user_id, body, schema_url=None):
    payload = {
        "resource_logs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "user.id",
                            "value": {
                                "string_value": user_id,
                            },
                        }
                    ],
                },
                "scope_logs": [
                    {
                        "scope": {},
                        "log_records": [
                            {
                                "time_unix_nano": "1640995200000000000",
                                "body": {
                                    "string_value": body,
                                },
                            }
                        ],
                    }
                ],
            }
        ],
    }

    if schema_url is not None:
        payload["resource_logs"][0]["schema_url"] = schema_url

    return payload


def _build_monolithic_logs_payload(record_count):
    body_padding = "x" * 256
    current_time_ns = 1640995200000000000

    resource_log = {
        "resource": {
            "attributes": [
                {
                    "key": "service.name",
                    "value": {
                        "string_value": "monolithic-payment-backend",
                    },
                },
                {
                    "key": "deployment.environment",
                    "value": {
                        "string_value": "production",
                    },
                },
                {
                    "key": "k8s.namespace.name",
                    "value": {
                        "string_value": "transactions",
                    },
                },
                {
                    "key": "cloud.region",
                    "value": {
                        "string_value": "eastus2",
                    },
                },
            ],
        },
        "scope_logs": [
            {
                "scope": {
                    "name": "io.opentelemetry.contrib.mongodb",
                    "version": "1.0.0",
                },
                "log_records": [],
            }
        ],
    }

    for index in range(record_count):
        resource_log["scope_logs"][0]["log_records"].append(
            {
                "time_unix_nano": str(current_time_ns - (index * 100000)),
                "observed_time_unix_nano": str(current_time_ns),
                "severity_number": 13,
                "severity_text": "WARN",
                "body": {
                    "string_value": (
                        "Database transaction query execution took longer than "
                        f"expected threshold. Execution time: {120 + index}ms. "
                        f"{body_padding}"
                    ),
                },
                "attributes": [
                    {
                        "key": "component",
                        "value": {
                            "string_value": "database-proxy",
                        },
                    },
                    {
                        "key": "db.system",
                        "value": {
                            "string_value": "mongodb",
                        },
                    },
                    {
                        "key": "db.operation",
                        "value": {
                            "string_value": "findAndModify",
                        },
                    },
                    {
                        "key": "exception.type",
                        "value": {
                            "string_value": "com.mongodb.MongoTimeoutException",
                        },
                    },
                ],
                "dropped_attributes_count": 0,
            }
        )

    return {
        "resource_logs": [
            resource_log,
        ],
    }


def _build_logs_payload_with_unset_attribute_values():
    return {
        "resource_logs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {
                                "string_value": "unset-any-value-service",
                            },
                        },
                        {
                            "key": "resource.unset",
                            "value": {},
                        },
                    ],
                },
                "scope_logs": [
                    {
                        "scope": {
                            "name": "unset-any-value-scope",
                            "attributes": [
                                {
                                    "key": "scope.unset",
                                    "value": {},
                                },
                            ],
                        },
                        "log_records": [
                            {
                                "time_unix_nano": "1640995200000000000",
                                "body": {
                                    "string_value": "log with unset attribute values",
                                },
                                "attributes": [
                                    {
                                        "key": "record.unset",
                                        "value": {},
                                    },
                                    {
                                        "key": "record.ok",
                                        "value": {
                                            "string_value": "ok",
                                        },
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
        ],
    }


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


def _wait_for_log_text(log_file, pattern, timeout=10):
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            with open(log_file, "r", encoding="utf-8") as log:
                text = log.read()
        except FileNotFoundError:
            text = ""

        if pattern in text:
            return text

        time.sleep(0.25)

    raise TimeoutError(f"Timed out waiting for log pattern {pattern!r}")


def _read_fluent_bit_log(service):
    if not service.service.flb or not service.service.flb.log_file:
        return ""

    try:
        with open(service.service.flb.log_file, "r", encoding="utf-8", errors="replace") as log:
            return log.read()
    except FileNotFoundError:
        return ""


def _start_or_skip_without_avro_encoder(service):
    try:
        service.start()
    except FluentBitStartupError as error:
        log_contents = _read_fluent_bit_log(service)
        error_message = str(error)
        unsupported_markers = [
            "unknown configuration property 'schema_str'",
            "unknown configuration property 'schema_id'",
            "unknown configuration property 'schema_registry_url'",
            "unknown configuration property 'schema_registry_subject'",
            "unknown configuration property 'schema_registry_version'",
        ]

        if any(marker in log_contents or marker in error_message
               for marker in unsupported_markers):
            try:
                service.stop()
            except Exception:
                pass
            pytest.skip("Kafka Avro Schema Registry requires FLB_AVRO_ENCODER=On")

        try:
            service.stop()
        except Exception:
            pass
        raise


def test_decode_avro_long_rejects_out_of_range_terminal_bits():
    payload = b"\x80" * 9 + b"\x02"

    with pytest.raises(ValueError, match="Invalid Avro long"):
        _decode_avro_long(payload)


def _create_shutdown_grace_service(ensure_thread_safe_reload):
    config_file = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "../config",
            "out_kafka_shutdown_grace.yaml",
        )
    )
    service = FluentBitTestService(
        config_file,
        extra_env={
            "TEST_HOT_RELOAD_ENSURE_THREAD_SAFETY": (
                "on" if ensure_thread_safe_reload else "off"
            ),
        },
    )
    service.allocate_port_env("TEST_SUITE_KAFKA_PORT")
    return service


def _send_shutdown_grace_record(service):
    response = requests.post(
        f"http://127.0.0.1:{service.flb_listener_port}/",
        json={"message": "pending during reload"},
        timeout=5,
    )
    response.raise_for_status()


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


def test_out_kafka_hot_reload_waits_for_pending_delivery_with_infinite_grace():
    service = _create_shutdown_grace_service(ensure_thread_safe_reload=True)
    service.start()

    try:
        _send_shutdown_grace_record(service)
        _wait_for_log_text(service.flb.log_file, "enqueued message")
        service.flb.trigger_http_reload()
        service.flb.wait_for_hot_reload_count(
            1,
            timeout=30 if memory_check_enabled() else 10,
        )
        log_text = _wait_for_log_text(
            service.flb.log_file,
            "[reload] start everything",
            timeout=30 if memory_check_enabled() else 10,
        )

        delivery_failure = "message delivery failed: Local: Message timed out"
        reload_start = "[reload] start everything"
        assert delivery_failure in log_text
        assert "Failed to force flush" not in log_text
        assert log_text.index(delivery_failure) < log_text.index(reload_start)
    finally:
        service.stop()


def test_out_kafka_hot_reload_times_out_pending_delivery_with_finite_grace():
    service = _create_shutdown_grace_service(ensure_thread_safe_reload=False)
    service.start()

    try:
        _send_shutdown_grace_record(service)
        _wait_for_log_text(service.flb.log_file, "enqueued message")
        reload_started_at = time.monotonic()
        service.flb.trigger_http_reload()
        service.flb.wait_for_hot_reload_count(
            1,
            timeout=30 if memory_check_enabled() else 10,
        )
        log_text = _wait_for_log_text(
            service.flb.log_file,
            "Failed to force flush: Local: Timed out",
        )

        reload_elapsed_seconds = time.monotonic() - reload_started_at
        force_flush_failure = "Failed to force flush: Local: Timed out"
        reload_start = "[reload] start everything"

        # Allow scheduling margin around the configured two-second grace.
        assert reload_elapsed_seconds >= 1.5
        assert reload_start in log_text
        assert log_text.index(force_flush_failure) < log_text.index(reload_start)
    finally:
        service.stop()


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


def test_out_kafka_dynamic_headers_sets_kafka_headers_and_excludes_field():
    service = Service("out_kafka_dynamic_headers.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["topic"] == "test"
    assert message["headers"] == [
        ("x-test", b"value"),
        ("x-empty", b""),
        ("x-null", None),
    ]

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "hello with headers"
    assert "headers" not in payload


@pytest.mark.parametrize("headers_key", ["", "   "])
def test_out_kafka_dynamic_headers_blank_key_disables_feature(headers_key):
    service = Service(
        "out_kafka_dynamic_headers_blank.yaml",
        extra_env={"TEST_HEADERS_KEY": headers_key},
    )
    service.start()

    messages = service.wait_for_messages(1)

    if headers_key:
        log_text = _wait_for_log_text(
            service.service.flb.log_file,
            "headers_key is blank; record-derived Kafka headers are disabled",
        )

    service.stop()

    message = messages[0]
    assert message["headers"] == []

    if headers_key:
        assert "record-derived Kafka headers are disabled" in log_text

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "blank headers key"
    assert payload["headers"] == {"x-test": "value"}


def test_out_kafka_dynamic_headers_blank_key_allows_otlp_format():
    service = Service(
        "out_kafka_dynamic_headers_blank_otlp_json.yaml",
        extra_env={"TEST_HEADERS_KEY": "\t \r"},
    )
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    assert messages[0]["headers"] == []


def test_out_kafka_dynamic_headers_preserves_source_map_when_enabled():
    service = Service("out_kafka_dynamic_headers_preserve.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    log_text = _wait_for_log_text(
        service.service.flb.log_file,
        "value must be a string, binary, or null",
    )
    service.stop()

    message = messages[0]
    assert message["headers"] == [
        ("x-test", b"value"),
        ("x-empty", b""),
        ("x-null", None),
    ]
    assert "value must be a string, binary, or null" in log_text

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "preserved headers"
    assert payload["headers"] == {
        "x-test": "value",
        "x-empty": "",
        "x-null": None,
        "x-invalid": 42,
    }


def test_out_kafka_dynamic_headers_preserves_source_map_in_msgpack():
    service = Service("out_kafka_dynamic_headers_preserve_msgpack.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["headers"] == [
        ("x-test", b"value"),
        ("x-empty", b""),
        ("x-null", None),
    ]

    payload, offset = _decode_simple_msgpack(message["value"])
    assert offset == len(message["value"])
    assert payload["message"] == "preserved msgpack headers"
    assert payload["headers"] == {
        "x-test": "value",
        "x-empty": "",
        "x-null": None,
    }


def test_out_kafka_dynamic_headers_preserves_empty_source_map():
    service = Service("out_kafka_dynamic_headers_preserve_empty.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["headers"] == []

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "preserved empty headers"
    assert payload["headers"] == {}


def test_out_kafka_dynamic_headers_keeps_non_map_field_in_payload():
    service = Service("out_kafka_dynamic_headers_non_map.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["topic"] == "test"
    assert message["headers"] == []

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "hello without a header map"
    assert payload["headers"] == "not-a-map"


def test_out_kafka_dynamic_headers_msgpack_excludes_field():
    service = Service("out_kafka_dynamic_headers_msgpack.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["headers"] == [
        ("x-test", b"value"),
        ("x-empty", b""),
        ("x-null", None),
    ]

    payload, offset = _decode_simple_msgpack(message["value"])
    assert offset == len(message["value"])
    assert payload["message"] == "hello msgpack headers"
    assert "headers" not in payload


def test_out_kafka_dynamic_headers_supports_binary_and_duplicate_values():
    service = Service("out_kafka_dynamic_headers_forward.yaml")
    service.start()
    service.send_forward_record(_encode_forward_record_with_binary_headers())

    messages = service.wait_for_messages(1)
    name_log_text = _wait_for_log_text(
        service.service.flb.log_file,
        "skipping Kafka header with a non-string name",
    )
    value_log_text = _wait_for_log_text(
        service.service.flb.log_file,
        "value must be a string, binary, or null",
    )
    service.stop()

    message = messages[0]
    assert message["headers"] == [
        ("x-binary", b"\x00\xffA"),
        ("x-repeat", b"first"),
        ("x-repeat", b"second"),
    ]

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "binary headers"
    assert "headers" not in payload
    assert "skipping Kafka header with a non-string name" in name_log_text
    assert "value must be a string, binary, or null" in value_log_text


def test_out_kafka_dynamic_headers_supports_large_binary_value():
    service = Service("out_kafka_dynamic_headers_forward.yaml")
    service.start()
    value = b"x" * 65536
    service.send_forward_record(_encode_forward_record_with_binary_header(value))

    messages = service.wait_for_messages(1)
    service.stop()

    assert messages[0]["headers"] == [("x-large", value)]


def test_out_kafka_dynamic_headers_supports_large_name():
    service = Service("out_kafka_dynamic_headers_forward.yaml")
    service.start()
    name = "x" * 65536
    service.send_forward_record(_encode_forward_record_with_binary_header(b"value", name))

    messages = service.wait_for_messages(1)
    service.stop()

    assert messages[0]["headers"] == [(name, b"value")]


def test_out_kafka_dynamic_headers_rejects_message_over_client_limit():
    service = Service("out_kafka_dynamic_headers_too_large.yaml")
    service.start()
    value = b"x" * 2048
    service.send_forward_record(_encode_forward_record_with_binary_header(value))

    log_text = _wait_for_log_text(
        service.service.flb.log_file,
        "Message size too large",
    )
    service.stop()

    assert data_storage["messages"] == []
    assert "Message size too large" in log_text


def test_out_kafka_dynamic_headers_preserves_non_map_value_types():
    service = Service("out_kafka_dynamic_headers_forward.yaml")
    service.start()

    records = [
        ("string", _encode_msgpack_string("not-a-map"), "not-a-map"),
        ("null", b"\xc0", None),
        ("boolean", b"\xc3", True),
        ("array", b"\x91" + _encode_msgpack_string("value"), ["value"]),
    ]

    for timestamp, (name, encoded_value, _) in enumerate(records, start=1):
        service.send_forward_record(
            _encode_forward_record_entries(
                [
                    (_encode_msgpack_string("message"), _encode_msgpack_string(name)),
                    (_encode_msgpack_string("headers"), encoded_value),
                ],
                timestamp=timestamp,
            )
        )

    messages = service.wait_for_messages(len(records))
    service.stop()

    payloads = {
        payload["message"]: payload
        for payload in (
            json.loads(message["value"].decode("utf-8")) for message in messages
        )
    }

    for name, _, expected_value in records:
        assert payloads[name]["headers"] == expected_value

    assert all(message["headers"] == [] for message in messages)


def test_out_kafka_dynamic_headers_all_invalid_map_is_removed():
    service = Service("out_kafka_dynamic_headers_forward.yaml")
    service.start()

    headers = _encode_msgpack_map(
        [
            (b"\x01", _encode_msgpack_string("invalid-name")),
            (_encode_msgpack_string("x-array"), b"\x91\x01"),
            (_encode_msgpack_string("x-map"), b"\x81\xa1k\xa1v"),
        ]
    )
    service.send_forward_record(
        _encode_forward_record_entries(
            [
                (_encode_msgpack_string("message"), _encode_msgpack_string("invalid map")),
                (_encode_msgpack_string("headers"), headers),
            ]
        )
    )

    messages = service.wait_for_messages(1)
    name_log_text = _wait_for_log_text(
        service.service.flb.log_file,
        "skipping Kafka header with a non-string name",
    )
    value_log_text = _wait_for_log_text(
        service.service.flb.log_file,
        "value must be a string, binary, or null",
    )
    service.stop()

    message = messages[0]
    assert message["headers"] == []
    assert "skipping Kafka header with a non-string name" in name_log_text
    assert "value must be a string, binary, or null" in value_log_text

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] == "invalid map"
    assert "headers" not in payload


def test_out_kafka_dynamic_headers_uses_first_duplicate_source_field():
    service = Service("out_kafka_dynamic_headers_forward.yaml")
    service.start()

    first_headers = _encode_msgpack_map(
        [
            (_encode_msgpack_string(""), _encode_msgpack_string("empty name")),
            (_encode_msgpack_string("x-first"), _encode_msgpack_string("first")),
        ]
    )
    second_headers = _encode_msgpack_map(
        [
            (_encode_msgpack_string("x-second"), _encode_msgpack_string("second")),
        ]
    )
    service.send_forward_record(
        _encode_forward_record_entries(
            [
                (_encode_msgpack_string("message"), _encode_msgpack_string("duplicates")),
                (_encode_msgpack_string("headers"), first_headers),
                (_encode_msgpack_string("headers"), second_headers),
            ]
        )
    )

    messages = service.wait_for_messages(1)
    log_text = _wait_for_log_text(
        service.service.flb.log_file,
        "multiple map-valued fields match headers_key; using the first one",
    )
    service.stop()

    message = messages[0]
    assert message["headers"] == [
        ("", b"empty name"),
        ("x-first", b"first"),
    ]
    assert "using the first one" in log_text

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["headers"] == {"x-second": "second"}


def test_out_kafka_dynamic_headers_batches_multiple_records():
    service = Service("out_kafka_dynamic_headers_batch.yaml")
    service.start()
    service.send_forward_record(_encode_forward_records_with_headers())

    messages = service.wait_for_messages(2)
    service.stop()

    assert len(messages) == 2
    assert all(message["headers"] == [("x-batch", b"value")] for message in messages)
    assert messages[0]["produce_correlation_id"] == messages[1]["produce_correlation_id"]
    assert messages[0]["batch_index"] == messages[1]["batch_index"]

    for message in messages:
        payload = json.loads(message["value"].decode("utf-8"))
        assert payload["message"] in {"batch one", "batch two"}
        assert "headers" not in payload


def test_out_kafka_dynamic_headers_survive_queue_full_retry():
    service = Service(
        "out_kafka_dynamic_headers_queue_full.yaml",
        kafka_response_delay=0.5,
    )
    service.start()
    service.send_forward_record(_encode_forward_records_with_headers())

    messages = service.wait_for_messages(2)
    log_text = _wait_for_log_text(
        service.service.flb.log_file,
        "internal queue is full, retrying in one second",
    )
    service.stop()

    assert len(messages) == 2
    assert all(message["headers"] == [("x-batch", b"value")] for message in messages)
    assert "internal queue is full, retrying in one second" in log_text


def test_out_kafka_dynamic_headers_supports_raw_format():
    service = Service("out_kafka_dynamic_headers_raw.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["headers"] == [("x-format", b"raw")]
    assert message["value"] == b"raw value"


def test_out_kafka_dynamic_headers_supports_gelf_format():
    service = Service("out_kafka_dynamic_headers_gelf.yaml")
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["headers"] == [("x-format", b"gelf")]

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["short_message"] == "hello gelf"
    assert payload["_source"] == "dummy"
    assert "_headers" not in payload


def test_out_kafka_dynamic_headers_supports_avro_format():
    service = Service(
        "out_kafka_dynamic_headers_avro.yaml",
        use_schema_registry=True,
    )
    _start_or_skip_without_avro_encoder(service)

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    value = message["value"]

    assert message["headers"] == [("x-format", b"avro")]
    assert value[0] == 0
    assert int.from_bytes(value[1:5], "big") == SCHEMA_ID
    assert len(value) > 5


@pytest.mark.parametrize(
    "config_file",
    [
        "out_kafka_dynamic_headers_missing.yaml",
        "out_kafka_dynamic_headers_empty.yaml",
    ],
)
def test_out_kafka_dynamic_headers_handles_missing_and_empty_maps(config_file):
    service = Service(config_file)
    service.start()

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    assert message["headers"] == []

    payload = json.loads(message["value"].decode("utf-8"))
    assert payload["message"] in {"missing headers", "empty headers"}
    assert "headers" not in payload


@pytest.mark.parametrize(
    "config_file",
    [
        "out_kafka_dynamic_headers_otlp_json_invalid.yaml",
        "out_kafka_dynamic_headers_otlp_proto_invalid.yaml",
    ],
)
def test_out_kafka_dynamic_headers_rejects_otlp_formats(config_file):
    service = Service(config_file)

    with pytest.raises(FluentBitStartupError):
        service.start()

    service.stop()


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


def test_out_kafka_avro_resolves_schema_registry_subject():
    service = Service("out_kafka_avro_schema_registry.yaml", use_schema_registry=True)
    _start_or_skip_without_avro_encoder(service)

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    value = message["value"]

    assert message["topic"] == "test"
    assert value[0] == 0
    assert int.from_bytes(value[1:5], "big") == SCHEMA_ID
    assert len(value) > 5

    requests_seen = schema_registry_data_storage["requests"]
    assert len(requests_seen) == 1
    assert requests_seen[0]["method"] == "GET"
    assert requests_seen[0]["path"] == f"/subjects/{SCHEMA_SUBJECT}/versions/latest"
    assert "application/vnd.schemaregistry.v1+json" in requests_seen[0]["headers"]["Accept"]


def test_out_kafka_avro_encodes_empty_map():
    service = Service("out_kafka_avro_empty_map.yaml")
    _start_or_skip_without_avro_encoder(service)

    messages = service.wait_for_messages(1)
    service.stop()

    message = messages[0]
    value = message["value"]

    assert message["topic"] == "test"
    assert value[0] == 0
    assert int.from_bytes(value[1:5], "big") == SCHEMA_ID

    record_id, offset = _decode_avro_string(value, 5)
    map_size, offset = _decode_avro_long(value, offset)

    assert record_id == EMPTY_MAP_RECORD_ID
    assert map_size == 0
    assert offset == len(value)


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


def test_out_kafka_otlp_json_logs_preserves_unset_attribute_values():
    service = Service("out_kafka_otlp_json.yaml")
    service.start()
    service.send_payload_dict(_build_logs_payload_with_unset_attribute_values(), "logs")

    messages = service.wait_for_messages(1)
    service.stop()

    payload = json.loads(messages[0]["value"].decode("utf-8"))
    resource_log = payload["resourceLogs"][0]
    scope_log = resource_log["scopeLogs"][0]
    record = scope_log["logRecords"][0]

    resource_attrs = {
        attr["key"]: attr["value"]
        for attr in resource_log["resource"]["attributes"]
    }
    scope_attrs = {
        attr["key"]: attr["value"]
        for attr in scope_log["scope"]["attributes"]
    }
    record_attrs = {
        attr["key"]: attr["value"]
        for attr in record["attributes"]
    }

    assert resource_attrs["resource.unset"] == {}
    assert scope_attrs["scope.unset"] == {}
    assert record_attrs["record.unset"] == {}
    assert record_attrs["record.ok"]["stringValue"] == "ok"
    assert record["body"]["stringValue"] == "log with unset attribute values"


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


@pytest.mark.parametrize(
    "format_name,config_file",
    [
        ("otlp_json", "out_kafka_otlp_json_slow_flush.yaml"),
        ("otlp_proto", "out_kafka_otlp_proto_slow_flush.yaml"),
    ],
)
def test_out_kafka_otlp_logs_preserve_resources_across_requests_in_same_chunk(
    format_name,
    config_file,
):
    service = Service(config_file)
    service.start()
    service.send_payload_dict(
        _build_resource_collision_payload("user-a", "event-a"),
        "logs",
    )
    service.send_payload_dict(
        _build_resource_collision_payload("user-b", "event-b"),
        "logs",
    )

    messages = service.wait_for_messages(1, timeout=10)
    service.stop()

    assert len(messages) == 1

    resources = _collect_resources(messages[:1], format_name, "logs")
    body_to_user = {
        record["body"]["stringValue"]: next(
            attribute["value"]["stringValue"]
            for attribute in resource["resource"]["attributes"]
            if attribute["key"] == "user.id"
        )
        for resource in resources
        for scope in resource["scopeLogs"]
        for record in scope["logRecords"]
    }

    assert "event-a" in body_to_user
    assert "event-b" in body_to_user
    assert body_to_user["event-a"] == "user-a"
    assert body_to_user["event-b"] == "user-b"
    assert len(resources) == 2


@pytest.mark.parametrize(
    "format_name,config_file",
    [
        ("otlp_json", "out_kafka_otlp_json_slow_flush.yaml"),
        ("otlp_proto", "out_kafka_otlp_proto_slow_flush.yaml"),
    ],
)
def test_out_kafka_otlp_logs_preserve_resource_schema_urls_across_requests(
    format_name,
    config_file,
):
    service = Service(config_file)
    service.start()
    service.send_payload_dict(
        _build_resource_collision_payload("same-user", "event-a", "schema-a"),
        "logs",
    )
    service.send_payload_dict(
        _build_resource_collision_payload("same-user", "event-b", "schema-b"),
        "logs",
    )

    messages = service.wait_for_messages(1, timeout=10)
    service.stop()

    assert len(messages) == 1

    resources = _collect_resources(messages[:1], format_name, "logs")
    body_to_schema_url = {
        record["body"]["stringValue"]: resource["schemaUrl"]
        for resource in resources
        for scope in resource["scopeLogs"]
        for record in scope["logRecords"]
    }

    assert body_to_schema_url["event-a"] == "schema-a"
    assert body_to_schema_url["event-b"] == "schema-b"
    assert len(resources) == 2


@pytest.mark.parametrize(
    "format_name,config_file",
    [
        ("otlp_json", "out_kafka_otlp_json_partition_by_resource.yaml"),
        ("otlp_proto", "out_kafka_otlp_proto_partition_by_resource.yaml"),
    ],
)
def test_out_kafka_otlp_logs_partition_by_resource(format_name, config_file):
    service = Service(config_file)
    service.start()
    service.send_payload_dict(
        _build_resource_collision_payload("user-a", "event-a"),
        "logs",
    )
    service.send_payload_dict(
        _build_resource_collision_payload("user-b", "event-b"),
        "logs",
    )

    messages = service.wait_for_messages(2, timeout=10)
    service.stop()

    assert len(messages) == 2

    keys = {message["key"] for message in messages}
    assert len(keys) == 2
    assert b"static-otlp-key" not in keys

    body_to_user = {}
    for message in messages:
        assert message["topic"] == "otlp-topic"
        assert message["key"]

        payload = _decode_kafka_payload(message, format_name, "logs")
        resources = payload["resourceLogs"]
        assert len(resources) == 1

        resource = resources[0]
        user_id = next(
            attribute["value"]["stringValue"]
            for attribute in resource["resource"]["attributes"]
            if attribute["key"] == "user.id"
        )

        for scope in resource["scopeLogs"]:
            for record in scope["logRecords"]:
                body_to_user[record["body"]["stringValue"]] = user_id

    assert body_to_user == {
        "event-a": "user-a",
        "event-b": "user-b",
    }


def test_out_kafka_otlp_json_partition_by_resource_keeps_monolithic_resource_valid():
    record_count = 512
    service = Service("out_kafka_otlp_json_partition_by_resource.yaml")
    service.start()
    service.send_payload_dict(_build_monolithic_logs_payload(record_count), "logs")

    messages = service.wait_for_messages(1, timeout=10)
    service.stop()

    assert len(messages) == 1
    message = messages[0]
    payload = json.loads(message["value"].decode("utf-8"))
    resource_logs = payload["resourceLogs"]

    assert message["topic"] == "otlp-topic"
    assert len(resource_logs) == 1
    assert len(resource_logs[0]["scopeLogs"]) == 1
    assert len(resource_logs[0]["scopeLogs"][0]["logRecords"]) == record_count
    assert len(message["value"]) > 100000


def test_out_kafka_otlp_json_partition_by_resource_rejects_oversized_message():
    service = Service("out_kafka_otlp_json_partition_by_resource_small_message_max.yaml")
    service.start()
    service.send_payload_dict(_build_monolithic_logs_payload(512), "logs")

    timeout = 30 if memory_check_enabled() else 10
    log_text = _wait_for_log_text(
        service.flb.log_file,
        "Broker: Message size too large",
        timeout=timeout,
    )
    service.stop()

    assert data_storage["messages"] == []
    assert "could not convert partitioned OTLP logs" not in log_text
