#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2026 The Fluent Bit Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Regression tests for in_opentelemetry bugs.

These cases assert the intended behavior. They fail against the unpatched
plugin and become regression coverage after the fixes land.
"""

import json
import logging
import os
import socket
import sys
import time
from pathlib import Path

import h2.config
import h2.connection
import h2.events
import opentelemetry
import opentelemetry.proto
import opentelemetry.proto.collector
import pytest
import requests
from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from server.otlp_server import data_storage

VENDORED_OTEL_PROTO_ROOT = Path(__file__).resolve().parents[3] / "vendor"
VENDORED_OTEL_PACKAGE_ROOT = VENDORED_OTEL_PROTO_ROOT / "opentelemetry"
VENDORED_OTEL_PROTO_PACKAGE_ROOT = VENDORED_OTEL_PACKAGE_ROOT / "proto"
VENDORED_OTEL_COLLECTOR_PACKAGE_ROOT = VENDORED_OTEL_PROTO_PACKAGE_ROOT / "collector"

if str(VENDORED_OTEL_PACKAGE_ROOT) not in opentelemetry.__path__:
    opentelemetry.__path__.append(str(VENDORED_OTEL_PACKAGE_ROOT))

if str(VENDORED_OTEL_PROTO_PACKAGE_ROOT) not in opentelemetry.proto.__path__:
    opentelemetry.proto.__path__.append(str(VENDORED_OTEL_PROTO_PACKAGE_ROOT))

if str(VENDORED_OTEL_COLLECTOR_PACKAGE_ROOT) not in opentelemetry.proto.collector.__path__:
    opentelemetry.proto.collector.__path__.append(str(VENDORED_OTEL_COLLECTOR_PACKAGE_ROOT))

from opentelemetry.proto.collector.profiles.v1development.profiles_service_pb2 import (  # noqa: E402
    ExportProfilesServiceRequest,
)

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

from test_in_opentelemetry_001 import (  # noqa: E402
    IN_OPENTELEMETRY_WORKER_PROTOCOL_CONFIGS,
    Service,
    iter_log_records,
)

logger = logging.getLogger(__name__)

GRPC_LOGS_PATH = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"
INT64_ATTRIBUTE_VALUE = (2 ** 40) + 123
HTTP11_NO_HOST_TIMEOUT = 2.0


def _assert_process_alive(service, extra=None):
    assert service.flb.process is not None
    exit_code = service.flb.process.poll()
    message = "fluent-bit process exited unexpectedly"
    if extra is not None:
        message = f"{message}: {extra}"
    assert exit_code is None, message


def _build_log_request(*, body_text=None, body_kv=None, attributes=None, include_empty_resource=False):
    payload = {"resourceLogs": []}

    if include_empty_resource:
        payload["resourceLogs"].append({})
        return payload

    record = {
        "timeUnixNano": "1640995200000000000",
    }
    if body_text is not None:
        record["body"] = {"stringValue": body_text}
    if body_kv is not None:
        record["body"] = {
            "kvlistValue": {
                "values": [
                    {"key": key, "value": {"stringValue": value}}
                    for key, value in body_kv
                ],
            }
        }
    if attributes is not None:
        record["attributes"] = attributes

    payload["resourceLogs"].append({
        "scopeLogs": [
            {
                "logRecords": [record],
            }
        ],
    })
    return payload


def _protobuf_logs(payload):
    return json_format.Parse(json.dumps(payload), ExportLogsServiceRequest()).SerializeToString()


def _grpc_frame(message):
    return b"\x00" + len(message).to_bytes(4, "big") + message


def _send_http11_without_host(port, path, body, content_type, timeout=HTTP11_NO_HOST_TIMEOUT):
    payload = body if isinstance(body, bytes) else body.encode("utf-8")
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii") + payload

    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        chunks = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)

    return b"".join(chunks)


def _parse_http_status(raw_response):
    if not raw_response:
        return None
    first_line = raw_response.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
    parts = first_line.split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _send_grpc_http2(port, path, body, timeout=5):
    connection = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    )
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.settimeout(timeout)
    connection.initiate_connection()
    sock.sendall(connection.data_to_send())

    stream_id = connection.get_next_available_stream_id()
    connection.send_headers(
        stream_id,
        [
            (":method", "POST"),
            (":authority", f"127.0.0.1:{port}"),
            (":scheme", "http"),
            (":path", path),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ],
        end_stream=False,
    )
    connection.send_data(stream_id, body, end_stream=True)
    sock.sendall(connection.data_to_send())

    headers = {}
    trailers = {}
    response_body = b""
    ended = False
    deadline = time.time() + timeout

    try:
        while time.time() < deadline and not ended:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                break
            if not data:
                break

            for event in connection.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    headers.update(event.headers)
                elif isinstance(event, h2.events.TrailersReceived):
                    trailers.update(event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    response_body += event.data
                    connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    ended = True
            sock.sendall(connection.data_to_send())
    finally:
        sock.close()

    def header_value(table, name):
        for key, value in table.items():
            if key.decode("utf-8") == name if isinstance(key, bytes) else key == name:
                return value.decode("utf-8") if isinstance(value, bytes) else value
        return None

    status = header_value(headers, ":status")
    grpc_status = header_value(trailers, "grpc-status")
    if grpc_status is None:
        grpc_status = header_value(headers, "grpc-status")

    return {
        "http_status": int(status) if status else None,
        "grpc_status": int(grpc_status) if grpc_status is not None else None,
        "body": response_body,
        "headers": headers,
        "trailers": trailers,
    }


def _post_without_content_type(url, payload):
    session = requests.Session()
    request = requests.Request("POST", url, data=payload)
    prepared = session.prepare_request(request)
    prepared.headers.pop("Content-Type", None)
    return session.send(prepared, timeout=5)


def _build_minimal_profiles_request():
    request = ExportProfilesServiceRequest()
    request.dictionary.string_table.append("")
    resource_profile = request.resource_profiles.add()
    scope_profile = resource_profile.scope_profiles.add()
    profile = scope_profile.profiles.add()
    profile.time_unix_nano = 1000
    profile.duration_nano = 100
    return request


def test_in_opentelemetry_preserves_protobuf_int64_attributes():
    """Protobuf AnyValue int_value must keep the full int64, not a 32-bit cast."""
    payload = _build_log_request(
        body_text="int64-attribute",
        attributes=[
            {
                "key": "big_int",
                "value": {
                    "intValue": str(INT64_ATTRIBUTE_VALUE),
                },
            }
        ],
    )

    service = Service("001-fluent-bit.yaml")
    service.start()
    try:
        response = service.send_raw_request("/v1/logs", _protobuf_logs(payload))
        assert response.status_code == 201
        output = service.read_response("logs")
    finally:
        service.stop()

    records = list(iter_log_records(output))
    assert len(records) == 1
    assert records[0]["record_attributes"]["big_int"] == str(INT64_ATTRIBUTE_VALUE)


def test_in_opentelemetry_http11_missing_host_returns_response():
    """HTTP/1.1 OTLP/HTTP requests without Host must still receive a response."""
    payload = json.dumps(_build_log_request(body_text="missing-host")).encode("utf-8")

    service = Service("otlp_http1_cleartext.yaml")
    service.start()
    try:
        raw = _send_http11_without_host(
            service.flb_listener_port,
            "/v1/logs",
            payload,
            "application/json",
        )
        status = _parse_http_status(raw)
        _assert_process_alive(service)
    finally:
        service.stop()

    assert raw, "server sent no HTTP response for an HTTP/1.1 request without Host"
    assert status is not None, f"could not parse HTTP status from {raw!r}"
    assert 200 <= status < 600


@pytest.mark.parametrize(
    "config_file",
    [
        "001-fluent-bit.yaml",
        IN_OPENTELEMETRY_WORKER_PROTOCOL_CONFIGS["http1_cleartext"],
    ],
    ids=["single-worker", "multi-worker"],
)
def test_in_opentelemetry_accepts_empty_logs_export(config_file):
    """A valid ExportLogsServiceRequest with no records must succeed."""
    payload = _protobuf_logs(_build_log_request(include_empty_resource=True))
    assert payload, "empty resourceLogs still has to produce a non-zero protobuf"

    service = Service(config_file)
    service.start()
    try:
        response = service.send_raw_request("/v1/logs", payload)
        _assert_process_alive(service)
    finally:
        service.stop()

    assert 200 <= response.status_code < 300


def test_in_opentelemetry_missing_attribute_key_does_not_crash():
    """Omitted protobuf KeyValue.key must not crash the process."""
    request = ExportLogsServiceRequest()
    log_record = request.resource_logs.add().scope_logs.add().log_records.add()
    log_record.body.string_value = "missing-attribute-key"
    attribute = log_record.attributes.add()
    attribute.value.string_value = "orphan"

    service = Service("001-fluent-bit.yaml")
    service.start()
    crash_error = None
    status = None
    try:
        try:
            response = service.send_raw_request("/v1/logs", request.SerializeToString())
            status = response.status_code
        except requests.RequestException as exc:
            crash_error = exc
        _assert_process_alive(service, extra=crash_error)
    finally:
        service.stop()

    assert status is not None, f"no HTTP response after omitted attribute key: {crash_error}"
    assert 200 <= status < 600


def test_in_opentelemetry_grpc_export_returns_success_response():
    """A successful unary gRPC Export must return HTTP 200 and grpc-status 0."""
    payload = _protobuf_logs(_build_log_request(body_text="grpc-success"))

    service = Service("otlp_http2_cleartext.yaml")
    service.start()
    try:
        result = _send_grpc_http2(
            service.flb_listener_port,
            GRPC_LOGS_PATH,
            _grpc_frame(payload),
        )
        _assert_process_alive(service)
        service.read_response("logs")
    finally:
        service.stop()

    assert result["http_status"] == 200
    assert result["grpc_status"] == 0


def test_in_opentelemetry_grpc_batched_invalid_then_valid_is_rejected():
    """A batched gRPC body must not report OK when an earlier message failed."""
    valid = _protobuf_logs(_build_log_request(body_text="batched-valid"))
    body = _grpc_frame(b"not-a-valid-otlp-protobuf") + _grpc_frame(valid)

    service = Service("otlp_http2_cleartext.yaml")
    service.start()
    try:
        result = _send_grpc_http2(service.flb_listener_port, GRPC_LOGS_PATH, body)
        _assert_process_alive(service)
    finally:
        service.stop()

    assert result["http_status"] == 200
    assert result["grpc_status"] not in (None, 0)


def test_in_opentelemetry_grpc_batched_valid_messages_are_all_ingested():
    """Every valid gRPC message in one HTTP body must be ingested."""
    first = _protobuf_logs(_build_log_request(body_text="batch-one"))
    second = _protobuf_logs(_build_log_request(body_text="batch-two"))
    body = _grpc_frame(first) + _grpc_frame(second)

    service = Service("otlp_http2_cleartext.yaml")
    service.start()
    try:
        result = _send_grpc_http2(service.flb_listener_port, GRPC_LOGS_PATH, body)
        _assert_process_alive(service)
        service.wait_for_signal_count("logs", 1, timeout=10)
        bodies = {
            record["body"]
            for received in data_storage["logs"]
            for record in iter_log_records(json.loads(json_format.MessageToJson(received)))
        }
    finally:
        service.stop()

    assert result["http_status"] == 200
    assert result["grpc_status"] == 0
    assert bodies >= {"batch-one", "batch-two"}


def test_in_opentelemetry_tag_key_routes_from_record():
    """tag_key must extract the record tag instead of being ignored."""
    payload = json.dumps(
        _build_log_request(body_kv=[("route_tag", "from_record"), ("message", "tagged")])
    ).encode("utf-8")

    service = Service("tag_key.yaml")
    service.start()
    try:
        response = service.send_raw_request(
            "/v1/logs",
            payload,
            content_type="application/json",
        )
        assert 200 <= response.status_code < 300
        service.wait_for_log_message("from_record:", timeout=10)
        with open(service.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
            content = log_file.read()
    finally:
        service.stop()

    assert "[0] from_record:" in content
    assert "tagged" in content


def test_in_opentelemetry_json_logs_honor_logs_metadata_key():
    """JSON log ingest must store metadata under logs_metadata_key."""
    payload = json.dumps(
        _build_log_request(body_text="custom-metadata-key")
    ).encode("utf-8")
    payload = json.loads(payload)
    payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["severityText"] = "INFO"
    payload = json.dumps(payload).encode("utf-8")

    service = Service("logs_metadata_key.yaml")
    service.start()
    try:
        response = service.send_raw_request(
            "/v1/logs",
            payload,
            content_type="application/json",
        )
        assert 200 <= response.status_code < 300
        service.wait_for_log_message("custom_meta", timeout=10)
        with open(service.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
            content = log_file.read()
    finally:
        service.stop()

    assert '{"custom_meta"=>' in content
    assert "severity_text" in content or "severityText" in content


def test_in_opentelemetry_accepts_http_profiles_uri():
    """OTLP/HTTP profiles must be accepted at /v1development/profiles."""
    payload = _build_minimal_profiles_request().SerializeToString()

    service = Service("profiles_http.yaml")
    service.start()
    try:
        response = service.send_raw_request("/v1development/profiles", payload)
        _assert_process_alive(service)
        if 200 <= response.status_code < 300:
            service.wait_for_signal_count("logs", 1, timeout=10)
    finally:
        service.stop()

    assert 200 <= response.status_code < 300, (
        f"OTLP/HTTP profiles URI was rejected: {response.status_code} {response.text!r}"
    )
    assert len(data_storage["logs"]) >= 1


def test_in_opentelemetry_metrics_missing_content_type_does_not_crash():
    """A metrics export without Content-Type must not crash the process."""
    payload = {
        "resourceMetrics": [
            {
                "scopeMetrics": [
                    {
                        "metrics": [
                            {
                                "name": "requests_total",
                                "sum": {
                                    "aggregationTemporality": 2,
                                    "dataPoints": [
                                        {
                                            "asInt": "1",
                                            "timeUnixNano": "1",
                                        }
                                    ],
                                },
                            }
                        ],
                    }
                ],
            }
        ],
    }

    service = Service("001-fluent-bit.yaml")
    service.start()
    crash_error = None
    status = None
    try:
        url = f"http://localhost:{service.flb_listener_port}/v1/metrics"
        try:
            response = _post_without_content_type(url, json.dumps(payload).encode("utf-8"))
            status = response.status_code
        except requests.RequestException as exc:
            crash_error = exc
        _assert_process_alive(service, extra=crash_error)
    finally:
        service.stop()

    assert status is not None, f"no HTTP response after metrics request without Content-Type: {crash_error}"
    assert 200 <= status < 600
