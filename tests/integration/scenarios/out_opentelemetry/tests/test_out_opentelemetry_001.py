import base64
import json
import logging
import os
import re
import shutil
import socket
import ssl
import threading
import time
from collections import Counter

import requests
import pytest
import yaml
from google.protobuf import json_format
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from server.http_server import (
    configure_oauth_token_response,
    data_storage as http_data_storage,
    http_server_run,
)
from server.otlp_server import (
    configure_otlp_grpc_methods,
    configure_otlp_response,
    data_storage,
    otlp_server_run,
    stop_otlp_server,
)
from utils.data_utils import read_json_file
from utils.test_service import FluentBitTestService

logger = logging.getLogger(__name__)


def _repo_relative(*parts):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), *parts))


def _attributes_to_dict(attributes):
    return {
        item["key"]: next(iter(item["value"].values()))
        for item in attributes
    }


def iter_log_records(output):
    for resource_log in output.get("resourceLogs", []):
        resource_attributes = _attributes_to_dict(
            resource_log.get("resource", {}).get("attributes", [])
        )
        for scope_log in resource_log.get("scopeLogs", []):
            for record in scope_log.get("logRecords", []):
                attributes = _attributes_to_dict(record.get("attributes", []))
                yield record, attributes, resource_attributes


def iter_metric_attributes(output):
    for resource_metric in output.get("resourceMetrics", []):
        for scope_metric in resource_metric.get("scopeMetrics", []):
            for metric in scope_metric.get("metrics", []):
                if "sum" in metric:
                    points = metric["sum"].get("dataPoints", [])
                elif "gauge" in metric:
                    points = metric["gauge"].get("dataPoints", [])
                else:
                    points = metric.get("histogram", {}).get("dataPoints", [])
                for point in points:
                    yield {
                        item["key"]: next(iter(item["value"].values()))
                        for item in point.get("attributes", [])
                    }


class Service:
    def __init__(
        self,
        config_file,
        *,
        receiver_mode="http",
        use_tls=False,
        grpc_methods=None,
        use_oauth_server=False,
        response_timeout=10,
    ):
        self.config_file = _repo_relative("../config", config_file)
        cert_dir = _repo_relative("../../in_splunk/certificate")
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.receiver_mode = receiver_mode
        self.use_tls = use_tls
        self.grpc_methods = grpc_methods or {}
        self.use_oauth_server = use_oauth_server
        self.oauth_server_port = None
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["logs", "metrics", "traces", "requests"],
            extra_env={
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
                "TEST_SUITE_HTTP_CLIENT_RESPONSE_TIMEOUT": response_timeout,
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _wait_for_tcp_port(self, port, timeout=10):
        def _ready():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                return sock.connect_ex(("127.0.0.1", port)) == 0

        self.service.wait_for_condition(
            _ready,
            timeout=timeout,
            interval=0.25,
            description=f"OTLP receiver port {port}",
        )

    def _start_receiver(self, service):
        if self.use_oauth_server:
            self.oauth_server_port = service.allocate_port_env("TEST_SUITE_OAUTH_PORT")
            http_server_run(self.oauth_server_port)
            self.service.wait_for_http_endpoint(
                f"http://127.0.0.1:{self.oauth_server_port}/ping",
                timeout=10,
                interval=0.5,
            )

        configure_otlp_grpc_methods(**self.grpc_methods)
        otlp_server_run(
            service.test_suite_http_port,
            use_tls=self.use_tls,
            tls_crt_file=self.tls_crt_file,
            tls_key_file=self.tls_key_file,
            use_grpc=self.receiver_mode == "grpc",
        )

        if self.receiver_mode == "grpc":
            self._wait_for_tcp_port(service.test_suite_http_port)
            return

        scheme = "https" if self.use_tls else "http"
        url = f"{scheme}://localhost:{service.test_suite_http_port}/ping"

        def _http_ready():
            try:
                response = requests.get(
                    url,
                    timeout=1,
                    verify=self.tls_crt_file if self.use_tls else True,
                )
                return response.status_code == 200
            except requests.RequestException:
                return False

        self.service.wait_for_condition(
            _http_ready,
            timeout=10,
            interval=0.5,
            description=f"OTLP {self.receiver_mode} receiver readiness",
        )

    def _stop_receiver(self, service):
        if self.oauth_server_port is not None:
            try:
                requests.post(f"http://127.0.0.1:{self.oauth_server_port}/shutdown", timeout=2)
            except requests.RequestException:
                pass
        stop_otlp_server()

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.flb_listener_port = self.service.flb_listener_port
        self.test_suite_http_port = self.service.test_suite_http_port

    def stop(self):
        self.service.stop()

    def wait_for_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["requests"] if len(data_storage["requests"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} OTLP requests",
        )

    def wait_for_oauth_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: http_data_storage["requests"] if len(http_data_storage["requests"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} OAuth requests",
        )

    def wait_for_signal(self, signal_type, minimum_count=1, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage[signal_type] if len(data_storage[signal_type]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} OTLP {signal_type} payloads",
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

    def send_json_traces_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "traces")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/traces",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def _resolve_json_fixture(self, json_file):
        scenario_fixture = _repo_relative("../tests/data_files", json_file)
        if os.path.exists(scenario_fixture):
            return scenario_fixture

        return _repo_relative("../../in_opentelemetry/tests/data_files", json_file)

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


class IPv6Http2OtlpReceiver:
    def __init__(self, port, oversized_headers=False, oversized_body=False,
                 fragmented_body=False):
        self.port = port
        self.oversized_headers = oversized_headers
        self.oversized_body = oversized_body
        self.fragmented_body = fragmented_body
        self.server_socket = None
        self.thread = None
        self.requests = []
        self.stop_event = threading.Event()

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("::1", self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(0.5)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()

        if self.server_socket is not None:
            self.server_socket.close()
            self.server_socket = None

        if self.thread is not None:
            self.thread.join(timeout=5)
            self.thread = None

    def _serve(self):
        while not self.stop_event.is_set():
            try:
                client_socket, _ = self.server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with client_socket:
                self._handle_connection(client_socket)

    def _handle_connection(self, client_socket):
        connection = H2Connection(
            config=H2Configuration(client_side=False, header_encoding="utf-8")
        )
        request = {
            "headers": {},
            "path": None,
            "body": b"",
        }

        client_socket.settimeout(2)
        connection.initiate_connection()
        client_socket.sendall(connection.data_to_send())

        while not self.stop_event.is_set():
            try:
                data = client_socket.recv(65535)
            except socket.timeout:
                continue

            if not data:
                break

            for event in connection.receive_data(data):
                if isinstance(event, RequestReceived):
                    request["headers"] = dict(event.headers)
                    request["path"] = request["headers"].get(":path")
                elif isinstance(event, DataReceived):
                    request["body"] += event.data
                    connection.acknowledge_received_data(
                        event.flow_controlled_length,
                        event.stream_id,
                    )
                elif isinstance(event, StreamEnded):
                    self.requests.append(request)
                    self._send_response(connection, event.stream_id)
                    client_socket.sendall(connection.data_to_send())
                    return

            pending = connection.data_to_send()
            if pending:
                client_socket.sendall(pending)

    def _send_response(self, connection, stream_id):
        if self.oversized_body:
            body = b"x" * (32 * 1024)
        elif self.fragmented_body:
            body = b"x" * 8192
        else:
            body = b"{}"

        headers = [
            (":status", "200"),
            ("content-type", "application/json"),
        ]
        if not self.fragmented_body:
            headers.append(("content-length", str(len(body))))
        if self.oversized_headers:
            headers.extend((f"x-extra-{index}", "a" * 1024) for index in range(70))

        connection.send_headers(stream_id, headers)
        if self.oversized_body:
            connection.send_data(stream_id, body[:16384])
            connection.send_data(stream_id, body[16384:], end_stream=True)
        elif self.fragmented_body:
            for offset in range(len(body)):
                connection.send_data(stream_id, body[offset:offset + 1],
                                     end_stream=offset + 1 == len(body))
        else:
            connection.send_data(stream_id, body, end_stream=True)


class Http2IPv6Service:
    def __init__(self, oversized_headers=False, oversized_body=False,
                 fragmented_body=False):
        config_name = (
            "out_otel_http2_ipv6_response_limit.yaml"
            if oversized_body or fragmented_body else "out_otel_http2_ipv6_logs.yaml"
        )
        self.config_file = _repo_relative("../config", config_name)
        self.receiver = None
        self.test_suite_http_port = None
        self.oversized_headers = oversized_headers
        self.oversized_body = oversized_body
        self.fragmented_body = fragmented_body
        self.service = FluentBitTestService(
            self.config_file,
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.test_suite_http_port = service.test_suite_http_port
        self.receiver = IPv6Http2OtlpReceiver(
            service.test_suite_http_port, self.oversized_headers,
            self.oversized_body, self.fragmented_body
        )
        self.receiver.start()

    def _stop_receiver(self, service):
        if self.receiver is not None:
            self.receiver.stop()
            self.receiver = None

    def start(self):
        self.service.start()
        self.flb = self.service.flb

    def stop(self):
        self.service.stop()

    def wait_for_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: self.receiver.requests
            if len(self.receiver.requests) >= minimum_count
            else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} IPv6 HTTP/2 OTLP requests",
        )


class StalledTlsReceiver:
    def __init__(self, port, cert_file, key_file):
        self.port = port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_file, key_file)
        self.context.set_alpn_protocols(["http/1.1"])
        self.accepted = threading.Event()
        self.stop_event = threading.Event()
        self.thread = None
        self.server_socket = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("127.0.0.1", self.port))
        self.server_socket.listen(1)
        self.server_socket.settimeout(0.5)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop_event.is_set():
            try:
                client_socket, _ = self.server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            with client_socket:
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                client_socket.settimeout(5)
                with self.context.wrap_socket(client_socket, server_side=True):
                    self.accepted.set()
                    self.stop_event.wait(15)
            return

    def stop(self):
        self.stop_event.set()
        if self.server_socket is not None:
            self.server_socket.close()
        if self.thread is not None:
            self.thread.join(timeout=5)


def ipv6_loopback_available():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.bind(("::1", 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _build_resource_collision_payload(user_id, body):
    return {
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


def _build_conditional_grouped_logs_payload():
    def resource(route_group, group_id, scopes):
        return {
            "schema_url": f"https://schemas.example/{route_group}",
            "resource": {
                "attributes": [
                    {
                        "key": "route_group",
                        "value": {
                            "string_value": route_group,
                        },
                    },
                    {
                        "key": "group_id",
                        "value": {
                            "string_value": group_id,
                        },
                    },
                    {
                        "key": "service_name",
                        "value": {
                            "string_value": f"service-{route_group}",
                        },
                    },
                ],
            },
            "scope_logs": scopes,
        }

    def scope(scope_name, scope_version, body, flags):
        return {
            "schema_url": f"https://schemas.example/{scope_name}",
            "scope": {
                "name": scope_name,
                "version": scope_version,
                "attributes": [
                    {
                        "key": "scope_marker",
                        "value": {
                            "string_value": f"{scope_name}-marker",
                        },
                    }
                ],
            },
            "log_records": [
                {
                    "time_unix_nano": "1640995200000000000",
                    "body": {
                        "string_value": body,
                    },
                    "flags": flags,
                    "attributes": [
                        {
                            "key": "record_marker",
                            "value": {
                                "string_value": f"{body}-marker",
                            },
                        }
                    ],
                }
            ],
        }

    resource_logs = [
        resource(
            "alpha",
            "group-alpha",
            [
                scope("scope-alpha-a", "1.0.0", "event-alpha-a", 1),
                scope("scope-alpha-b", "1.1.0", "event-alpha-b", 2),
            ],
        ),
        resource("beta", "group-beta", [scope("scope-beta", "2.0.0", "event-beta", 3)]),
        resource(
            "fallback",
            "group-default",
            [scope("scope-default", "3.0.0", "event-default", 4)],
        ),
    ]

    return {"resource_logs": resource_logs}


def _build_batched_metrics_payload():
    def attributes(series_id):
        return [
            {
                "key": "series.id",
                "value": {
                    "string_value": str(series_id),
                },
            }
        ]

    def resource(service_name, metric):
        return {
            "schema_url": f"https://example.com/resource/{service_name}/1.0.0",
            "resource": {
                "attributes": [
                    {
                        "key": "service.name",
                        "value": {
                            "string_value": service_name,
                        },
                    }
                ],
            },
            "scope_metrics": [
                {
                    "scope": {
                        "name": f"batch-test-{service_name}",
                        "version": "1.0.0",
                    },
                    "schema_url": f"https://example.com/scope/{service_name}/1.0.0",
                    "metrics": [metric],
                }
            ],
        }

    gauge_points = [
        {
            "attributes": attributes(series_id),
            "time_unix_nano": str(1704067200000000000 + series_id),
            "as_int": series_id,
        }
        for series_id in range(7)
    ]
    sum_points = [
        {
            "attributes": attributes(series_id),
            "start_time_unix_nano": "1704067200000000000",
            "time_unix_nano": str(1704067200000000000 + series_id),
            "as_int": series_id,
        }
        for series_id in range(7, 11)
    ]

    return {
        "resource_metrics": [
            resource(
                "service-a",
                {
                    "name": "batch.gauge",
                    "gauge": {
                        "data_points": gauge_points,
                    },
                },
            ),
            resource(
                "service-b",
                {
                    "name": "batch.sum",
                    "sum": {
                        "data_points": sum_points,
                        "aggregation_temporality": 2,
                        "is_monotonic": True,
                    },
                },
            ),
        ]
    }


def iter_metric_points_with_resource(output):
    data_keys = ("gauge", "sum", "histogram", "exponentialHistogram", "summary")

    for resource_metric in output.get("resourceMetrics", []):
        resource_attributes = _attributes_to_dict(
            resource_metric.get("resource", {}).get("attributes", [])
        )
        resource_schema_url = resource_metric.get("schemaUrl")
        for scope_metric in resource_metric.get("scopeMetrics", []):
            scope = scope_metric.get("scope", {})
            scope_schema_url = scope_metric.get("schemaUrl")
            for metric in scope_metric.get("metrics", []):
                for data_key in data_keys:
                    if data_key in metric:
                        for point in metric[data_key].get("dataPoints", []):
                            yield (
                                point,
                                resource_attributes,
                                resource_schema_url,
                                scope,
                                scope_schema_url,
                            )
                        break


def _assert_log_resource_attribution(logs_seen):
    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    records = list(iter_log_records(output))
    body_to_user = {
        record["body"]["stringValue"]: resource_attributes["user.id"]
        for record, _, resource_attributes in records
    }

    assert body_to_user["event-a"] == "user-a"
    assert body_to_user["event-b"] == "user-b"
    assert len(output["resourceLogs"]) == 2


def _log_payloads_by_request_path(logs_seen, requests_seen):
    assert len(logs_seen) >= len(requests_seen)

    decoded_by_path = {}
    for log_seen in logs_seen:
        output = json.loads(json_format.MessageToJson(log_seen))
        resource_logs = output.get("resourceLogs", [])
        assert len(resource_logs) == 1

        resource_attributes = _attributes_to_dict(
            resource_logs[0].get("resource", {}).get("attributes", [])
        )
        group_id = resource_attributes.get("group_id")
        assert group_id is not None
        assert group_id.startswith("group-")

        path = f"/conditional/group/{group_id[6:]}"
        assert path not in decoded_by_path
        decoded_by_path[path] = output

    payloads_by_path = {}
    for request_seen in requests_seen:
        path = request_seen["path"]
        assert path in decoded_by_path
        payloads_by_path[path] = decoded_by_path[path]

    return payloads_by_path


def _assert_grouped_resource(output, *, route_group, group_id, scopes):
    resource_logs = output.get("resourceLogs", [])
    assert len(resource_logs) == 1

    resource_log = resource_logs[0]
    assert resource_log["schemaUrl"] == f"https://schemas.example/{route_group}"

    resource_attributes = _attributes_to_dict(
        resource_log.get("resource", {}).get("attributes", [])
    )
    assert resource_attributes["route_group"] == route_group
    assert resource_attributes["group_id"] == group_id
    assert resource_attributes["service_name"] == f"service-{route_group}"

    scope_logs = resource_log.get("scopeLogs", [])
    assert len(scope_logs) == len(scopes)

    for scope_log, expected in zip(scope_logs, scopes):
        scope = scope_log["scope"]
        assert scope_log["schemaUrl"] == f"https://schemas.example/{expected['name']}"
        assert scope["name"] == expected["name"]
        assert scope["version"] == expected["version"]
        assert _attributes_to_dict(scope.get("attributes", []))["scope_marker"] == (
            f"{expected['name']}-marker"
        )

        records = scope_log.get("logRecords", [])
        assert len(records) == 1
        assert records[0]["body"]["stringValue"] == expected["body"]
        assert records[0]["flags"] == expected["flags"]
        assert _attributes_to_dict(records[0].get("attributes", []))["record_marker"] == (
            f"{expected['body']}-marker"
        )


def test_out_opentelemetry_http_logs_uri_headers_and_basic_auth():
    service = Service("out_otel_http_logs.yaml")
    service.start()
    requests_seen = service.wait_for_requests(1)
    logs_seen = service.wait_for_signal("logs")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    record = output["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]

    assert request_seen["transport"] == "http"
    assert request_seen["path"] == "/custom/logs"
    assert request_seen["headers"]["Authorization"] == "Basic " + base64.b64encode(b"otel:secret").decode()
    assert request_seen["headers"]["X-Suite"] == "otel-test"
    assert base64.b64decode(record["traceId"]) == bytes.fromhex("63560bd4d8de74fae7d1e4160f2ee099")
    assert base64.b64decode(record["spanId"]) == bytes.fromhex("251484295a9df731")


@pytest.mark.parametrize(
    "config_file,auth_mode",
    [
        ("out_otel_http_logs_oauth2_basic.yaml", "basic"),
        ("out_otel_http_logs_oauth2_private_key_jwt.yaml", "private_key_jwt"),
    ],
    ids=["oauth2_basic", "oauth2_private_key_jwt"],
)
def test_out_opentelemetry_http_logs_oauth2_auth_matrix(config_file, auth_mode):
    service = Service(config_file, use_oauth_server=True)
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    token_requests = service.wait_for_oauth_requests(1)
    otlp_requests = service.wait_for_requests(1)
    service.stop()

    token_request = next(request for request in token_requests if request["path"] == "/oauth/token")
    data_request = next(request for request in otlp_requests if request["path"] == "/custom/logs")

    assert token_request["method"] == "POST"
    assert "grant_type=client_credentials" in token_request["raw_data"]
    assert data_request["headers"].get("Authorization") == "Bearer oauth-access-token"

    if auth_mode == "basic":
        assert "Basic " in token_request["headers"].get("Authorization", "")
        assert "scope=logs.write" in token_request["raw_data"]
        return

    assert "client_assertion_type=" in token_request["raw_data"]
    assert "client_assertion=" in token_request["raw_data"]
    assert "client_id=client1" in token_request["raw_data"]


@pytest.mark.parametrize(
    "config_file,auth_mode",
    [
        ("out_otel_grpc_logs_oauth2_basic.yaml", "basic"),
        ("out_otel_grpc_logs_oauth2_private_key_jwt.yaml", "private_key_jwt"),
    ],
    ids=["grpc_oauth2_basic", "grpc_oauth2_private_key_jwt"],
)
def test_out_opentelemetry_grpc_logs_oauth2_auth_matrix(config_file, auth_mode):
    service = Service(
        config_file,
        receiver_mode="grpc",
        grpc_methods={"logs": "/custom.logs.v1.Logs/Push"},
        use_oauth_server=True,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    token_requests = service.wait_for_oauth_requests(1)
    otlp_requests = service.wait_for_requests(1)
    service.stop()

    token_request = next(request for request in token_requests if request["path"] == "/oauth/token")
    data_request = next(request for request in otlp_requests if request["path"] == "/custom.logs.v1.Logs/Push")

    assert token_request["method"] == "POST"
    assert "grant_type=client_credentials" in token_request["raw_data"]
    assert data_request["transport"] == "grpc"
    assert data_request["headers"].get("authorization") == "Bearer oauth-access-token"

    if auth_mode == "basic":
        assert "Basic " in token_request["headers"].get("Authorization", "")
        assert "scope=logs.write" in token_request["raw_data"]
        return

    assert "client_assertion_type=" in token_request["raw_data"]
    assert "client_assertion=" in token_request["raw_data"]
    assert "client_id=client1" in token_request["raw_data"]


def test_out_opentelemetry_gzip_and_logs_body_key_attributes():
    service = Service("out_otel_http_logs_gzip.yaml")
    service.start()
    requests_seen = service.wait_for_requests(1)
    logs_seen = service.wait_for_signal("logs")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    record, attributes, _ = next(iter_log_records(output))

    assert request_seen["headers"]["Content-Encoding"] == "gzip"
    assert record["body"]["stringValue"] == "body only"
    assert attributes["source"] == "dummy"
    assert attributes["level"] == "info"
    assert "message" not in attributes


@pytest.mark.skipif(
    shutil.which("zstd") is None,
    reason="zstd executable is required to decode the test payload",
)
def test_out_opentelemetry_zstd_and_logs_body_key_attributes():
    service = Service("out_otel_http_logs_zstd.yaml")
    service.start()
    requests_seen = service.wait_for_requests(1)
    logs_seen = service.wait_for_signal("logs")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    record, attributes, _ = next(iter_log_records(output))

    assert request_seen["headers"]["Content-Encoding"] == "zstd"
    assert record["body"]["stringValue"] == "zstd body"
    assert attributes["source"] == "dummy"
    assert "message" not in attributes


def test_out_opentelemetry_tls_verification_with_vhost():
    service = Service("out_otel_http_logs_tls.yaml", use_tls=True)
    service.start()
    requests_seen = service.wait_for_requests(1)
    logs_seen = service.wait_for_signal("logs")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    record = output["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]

    assert request_seen["transport"] == "http"
    assert request_seen["path"] == "/v1/logs"
    assert record["body"]["stringValue"] == "hello over tls"


def test_out_opentelemetry_grpc_custom_logs_uri():
    service = Service(
        "out_otel_grpc_logs.yaml",
        receiver_mode="grpc",
        grpc_methods={"logs": "/custom.logs.v1.Logs/Push"},
    )
    service.start()
    requests_seen = service.wait_for_requests(1)
    logs_seen = service.wait_for_signal("logs")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    record = output["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]

    assert request_seen["transport"] == "grpc"
    assert request_seen["path"] == "/custom.logs.v1.Logs/Push"
    assert request_seen["headers"]["x-grpc"] == "otlp-test"
    assert record["body"]["stringValue"] == "hello via grpc"


def test_out_opentelemetry_http2_ipv6_authority_header():
    if not ipv6_loopback_available():
        pytest.skip("IPv6 loopback is not available")

    service = Http2IPv6Service()
    try:
        service.start()
        requests_seen = service.wait_for_requests(1, timeout=30)
    finally:
        service.stop()

    request_seen = requests_seen[0]

    assert request_seen["path"] == "/v1/logs"
    assert request_seen["headers"][":authority"] == f"[::1]:{service.test_suite_http_port}"


def test_out_opentelemetry_http1_oversized_response_is_rejected():
    service = Service("out_otel_http2_http1_response_limit.yaml", use_tls=True)
    service.start()
    try:
        configure_otlp_response(body="x" * (128 * 1024))
        service.wait_for_requests(1)
        _wait_for_log_message(service, "HTTP response exceeded configured client limit")
    finally:
        service.stop()


def test_out_opentelemetry_http1_chunk_framing_does_not_count_as_body():
    service = Service("out_otel_http2_http1_response_limit.yaml", use_tls=True)
    service.start()
    try:
        configure_otlp_response(body=(b"x" for _ in range(8192)))
        service.wait_for_requests(1)
        _wait_for_log_message(service, "HTTP status=200")
    finally:
        service.stop()

    with open(service.flb.log_file, encoding="utf-8") as log_file:
        assert "HTTP response exceeded configured client limit" not in log_file.read()


def test_out_opentelemetry_http1_response_deadline():
    service = Service("out_otel_http2_http1_response_limit.yaml", use_tls=True,
                      response_timeout=1)
    service.start()
    try:
        configure_otlp_response(delay_seconds=3)
        service.wait_for_requests(1)
        _wait_for_log_message(service, "timed out after 1 seconds (IO timeout)", timeout=8)
    finally:
        service.stop()


def test_out_opentelemetry_stalled_first_write_hits_deadline():
    cert_dir = _repo_relative("../../in_splunk/certificate")
    cert_file = os.path.join(cert_dir, "certificate.pem")
    key_file = os.path.join(cert_dir, "private_key.pem")
    receiver = None

    def start_receiver(harness):
        nonlocal receiver
        receiver = StalledTlsReceiver(harness.test_suite_http_port, cert_file, key_file)
        receiver.start()

    def stop_receiver(harness):
        if receiver is not None:
            receiver.stop()

    service = FluentBitTestService(
        _repo_relative("../config", "out_otel_http2_http1_stalled_write.yaml"),
        extra_env={"CERTIFICATE_TEST": cert_file},
        pre_start=start_receiver,
        post_stop=stop_receiver,
    )
    service.start()
    try:
        payload = ExportLogsServiceRequest()
        record = payload.resource_logs.add().scope_logs.add().log_records.add()
        record.body.string_value = "x" * (16 * 1024 * 1024)
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=15,
        )
        response.raise_for_status()
        assert receiver.accepted.wait(timeout=10)

        def request_timed_out():
            with open(service.flb.log_file, encoding="utf-8") as log_file:
                return "timed out after 2 seconds (IO timeout)" in log_file.read()

        service.wait_for_condition(
            request_timed_out, timeout=8, description="stalled HTTP request timeout"
        )
    finally:
        service.stop()


def test_out_opentelemetry_http2_oversized_headers_are_rejected():
    if not ipv6_loopback_available():
        pytest.skip("IPv6 loopback is not available")

    service = Http2IPv6Service(oversized_headers=True)
    try:
        service.start()
        service.wait_for_requests(1, timeout=30)
        _wait_for_log_message(service, "HTTP response exceeded configured client limit")
    finally:
        service.stop()


def test_out_opentelemetry_http2_oversized_body_is_rejected():
    if not ipv6_loopback_available():
        pytest.skip("IPv6 loopback is not available")

    service = Http2IPv6Service(oversized_body=True)
    try:
        service.start()
        service.wait_for_requests(1, timeout=30)
        _wait_for_log_message(service, "HTTP response exceeded configured client limit")
    finally:
        service.stop()


def test_out_opentelemetry_http2_frame_overhead_does_not_count_as_body():
    if not ipv6_loopback_available():
        pytest.skip("IPv6 loopback is not available")

    service = Http2IPv6Service(fragmented_body=True)
    try:
        service.start()
        service.wait_for_requests(1, timeout=30)
        _wait_for_log_message(service, "HTTP status=200")
    finally:
        service.stop()

    with open(service.flb.log_file, encoding="utf-8") as log_file:
        assert "HTTP response exceeded configured client limit" not in log_file.read()


@pytest.mark.parametrize(
    "config_file,receiver_mode",
    [
        ("out_otel_http_logs_otlp_input_slow_flush.yaml", "http"),
        ("out_otel_grpc_logs_otlp_input_slow_flush.yaml", "grpc"),
    ],
    ids=["http", "grpc"],
)
def test_out_opentelemetry_logs_preserve_resources_across_otlp_input_requests(
    config_file,
    receiver_mode,
):
    service = Service(config_file, receiver_mode=receiver_mode)
    service.start()
    service.send_payload_dict(
        _build_resource_collision_payload("user-a", "event-a"),
        "logs",
    )
    service.send_payload_dict(
        _build_resource_collision_payload("user-b", "event-b"),
        "logs",
    )
    logs_seen = service.wait_for_signal("logs", minimum_count=1, timeout=10)
    service.stop()

    _assert_log_resource_attribution(logs_seen)


def test_out_opentelemetry_metrics_uri_and_add_label():
    service = Service("out_otel_http_metrics.yaml")
    service.start()
    requests_seen = service.wait_for_requests(1)
    metrics_seen = service.wait_for_signal("metrics")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(metrics_seen[0]))
    point_attributes = list(iter_metric_attributes(output))

    assert request_seen["path"] == "/custom/metrics"
    assert any(attributes.get("cluster") == "ci" for attributes in point_attributes)


def test_out_opentelemetry_grpc_metrics_uri():
    service = Service(
        "out_otel_grpc_metrics.yaml",
        receiver_mode="grpc",
        grpc_methods={"metrics": "/custom.metrics.v1.Metrics/Push"},
    )
    service.start()
    requests_seen = service.wait_for_requests(1)
    metrics_seen = service.wait_for_signal("metrics")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(metrics_seen[0]))

    assert request_seen["transport"] == "grpc"
    assert request_seen["path"] == "/custom.metrics.v1.Metrics/Push"
    assert request_seen["headers"]["x-metrics"] == "grpc"
    assert output["resourceMetrics"]


@pytest.mark.parametrize(
    "config_file,receiver_mode,request_path",
    [
        ("out_otel_http_metrics_max_datapoints.conf", "http", "/batched/metrics"),
        (
            "out_otel_grpc_metrics_max_datapoints.conf",
            "grpc",
            "/batched.metrics.v1.Metrics/Export",
        ),
    ],
    ids=["http", "grpc"],
)
def test_out_opentelemetry_metrics_max_datapoints(
    config_file,
    receiver_mode,
    request_path,
):
    grpc_methods = {"metrics": request_path} if receiver_mode == "grpc" else None
    service = Service(
        config_file,
        receiver_mode=receiver_mode,
        grpc_methods=grpc_methods,
    )
    service.start()
    service.send_payload_dict(_build_batched_metrics_payload(), "metrics")
    metrics_seen = service.wait_for_signal("metrics", minimum_count=3, timeout=15)
    requests_seen = service.wait_for_requests(3, timeout=15)
    service.stop()

    assert len(metrics_seen) == 3
    assert len(requests_seen) == 3
    assert {request["path"] for request in requests_seen} == {request_path}

    batch_sizes = []
    observed_series = {}
    for export_request in metrics_seen:
        output = json.loads(json_format.MessageToJson(export_request))
        points = list(iter_metric_points_with_resource(output))
        batch_sizes.append(len(points))
        assert len(points) <= 4

        for (
            point,
            resource_attributes,
            resource_schema_url,
            scope,
            scope_schema_url,
        ) in points:
            point_attributes = _attributes_to_dict(point.get("attributes", []))
            series_id = int(point_attributes["series.id"])
            assert series_id not in observed_series
            service_name = "service-a" if series_id < 7 else "service-b"
            assert resource_attributes["service.name"] == service_name
            assert resource_schema_url == (
                f"https://example.com/resource/{service_name}/1.0.0"
            )
            assert scope == {
                "name": f"batch-test-{service_name}",
                "version": "1.0.0",
            }
            assert scope_schema_url == (
                f"https://example.com/scope/{service_name}/1.0.0"
            )
            observed_series[series_id] = service_name

    assert sorted(batch_sizes) == [3, 4, 4]
    assert observed_series == {
        **{series_id: "service-a" for series_id in range(7)},
        **{series_id: "service-b" for series_id in range(7, 11)},
    }


def test_out_opentelemetry_metrics_partial_success_is_not_retried():
    payload = _build_batched_metrics_payload()
    resource_metrics = payload["resource_metrics"]
    gauge_points = resource_metrics[0]["scope_metrics"][0]["metrics"][0]["gauge"]
    gauge_points["data_points"].extend(
        resource_metrics[1]["scope_metrics"][0]["metrics"][0]["sum"]["data_points"]
    )
    payload["resource_metrics"] = [resource_metrics[0]]

    service = Service("out_otel_http_metrics_max_datapoints.conf")
    service.start()
    try:
        configure_otlp_response(status_codes=[200, 503, 200])
        service.send_payload_dict(payload, "metrics")
        metrics_seen = service.wait_for_signal("metrics", minimum_count=2, timeout=15)
        _wait_for_log_message(service, "metric payload partially succeeded")
        requests_seen = list(data_storage["requests"])
    finally:
        service.stop()

    assert len(metrics_seen) == 2
    assert len(requests_seen) == 2

    batch_series = []
    for export_request in metrics_seen:
        output = json.loads(json_format.MessageToJson(export_request))
        points = list(iter_metric_points_with_resource(output))
        assert len(points) == 4
        batch_series.append(
            {
                int(_attributes_to_dict(point.get("attributes", []))["series.id"])
                for point, _, _, _, _ in points
            }
        )

    assert batch_series[0] == {0, 1, 2, 3}
    assert batch_series[1] == {4, 5, 6, 7}
    assert {8, 9, 10}.isdisjoint(set().union(*batch_series))


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
@pytest.mark.parametrize("filesystem_storage", [False, True])
def test_out_opentelemetry_trace_status_roundtrip(tmp_path, encoding, filesystem_storage):
    with open(_repo_relative("../config", "out_otel_http_traces.yaml"), encoding="utf-8") as stream:
        config = yaml.safe_load(stream)
    if filesystem_storage:
        config["service"]["storage.path"] = str(tmp_path / "storage")
        config["pipeline"]["inputs"][0]["storage.type"] = "filesystem"
    config_file = tmp_path / "trace-status.yaml"
    with config_file.open("w", encoding="utf-8") as stream:
        yaml.safe_dump(config, stream)

    codes = [0, 1, 2, -2147483648, -1, 3, 2147483647]
    spans = [{
        "traceId": "0123456789abcdef0123456789abcdef",
        "spanId": f"{index + 1:016x}",
        "name": f"status-{code}",
        "startTimeUnixNano": "1700000000000000000",
        "endTimeUnixNano": "1700000000000000001",
        "status": {"code": code, "message": f"message-{code}"},
    } for index, code in enumerate(codes)]
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
    service = Service(str(config_file))
    service.start()
    if encoding == "protobuf":
        request = ExportTraceServiceRequest()
        resource = request.resource_spans.add()
        resource.resource.SetInParent()
        scope = resource.scope_spans.add()
        for source in spans:
            span = scope.spans.add()
            span.trace_id = bytes.fromhex(source["traceId"])
            span.span_id = bytes.fromhex(source["spanId"])
            span.name = source["name"]
            span.start_time_unix_nano = int(source["startTimeUnixNano"])
            span.end_time_unix_nano = int(source["endTimeUnixNano"])
            span.status.code = source["status"]["code"]
            span.status.message = source["status"]["message"]
        body = request.SerializeToString()
        content_type = "application/x-protobuf"
    else:
        body = json.dumps(payload).encode()
        content_type = "application/json"
    response = requests.post(
        f"http://127.0.0.1:{service.flb_listener_port}/v1/traces",
        data=body,
        headers={"Content-Type": content_type},
        timeout=5,
    )
    response.raise_for_status()
    traces_seen = service.wait_for_signal("traces")
    service.stop()
    received = [
        span for request in traces_seen for resource in request.resource_spans
        for scope in resource.scope_spans for span in scope.spans
    ]
    assert len(received) == len(codes)
    assert {span.name: (span.status.code, span.status.message) for span in received} == {
        f"status-{code}": (code, f"message-{code}") for code in codes
    }


def test_out_opentelemetry_traces_uri():
    service = Service("out_otel_http_traces.yaml")
    service.start()
    service.send_json_traces_payload("test_traces_001.in.json")
    requests_seen = service.wait_for_requests(1)
    traces_seen = service.wait_for_signal("traces")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(traces_seen[0]))
    span = output["resourceSpans"][0]["scopeSpans"][0]["spans"][0]

    assert request_seen["path"] == "/custom/traces"
    assert span["name"] == "checkout-span"


def test_out_opentelemetry_batch_size_splits_log_exports():
    service = Service("out_otel_http_logs_batch_size.yaml")
    service.start()
    service.send_json_logs_payload("test_logs_001.in.json")
    logs_seen = service.wait_for_signal("logs", minimum_count=4, timeout=15)
    requests_seen = service.wait_for_requests(4, timeout=15)
    service.stop()

    assert len(requests_seen) == 4
    assert {request["path"] for request in requests_seen} == {"/batched/logs"}

    for export_request in logs_seen:
        output = json.loads(json_format.MessageToJson(export_request))
        record_count = sum(
            len(scope_log.get("logRecords", []))
            for resource_log in output["resourceLogs"]
            for scope_log in resource_log.get("scopeLogs", [])
        )
        assert record_count == 1


@pytest.mark.parametrize(
    "input_name,batch_size,record_count,fail_request,status_code",
    [
        ("http", 1, 2, 0, 429),
        ("http", 1, 2, 1, 429),
        ("http", 1, 2, 2, 429),
        ("http", 2, 5, 1, 429),
        ("http", 2, 5, 2, 429),
        ("http", 2, 5, 3, 429),
        ("http", 2, 1, 1, 429),
        ("http", 2, 2, 1, 429),
        ("http", 1000, 2000, 1, 429),
        ("http", 1000, 2000, 2, 429),
        ("http", 1, 2, 1, 400),
        ("http", 1, 2, 2, 400),
        ("opentelemetry", 1, 2, 0, 429),
        ("opentelemetry", 1, 2, 1, 429),
        ("opentelemetry", 1, 2, 2, 429),
    ],
)
def test_out_opentelemetry_log_batch_retry(
    monkeypatch, input_name, batch_size, record_count, fail_request, status_code
):
    monkeypatch.setenv("TEST_LOG_INPUT", input_name)
    monkeypatch.setenv("TEST_LOG_BATCH_SIZE", str(batch_size))
    service = Service("out_otel_http_logs_batch_retry.yaml")
    expected = [f"event-{index:06d}" for index in range(record_count)]
    expected_batches = [expected[index:index + batch_size] for index in range(0, record_count, batch_size)]
    statuses = [200] * (fail_request - 1) + [status_code] if fail_request else []
    permanent_failure = bool(fail_request and status_code == 400)
    retried = bool(fail_request and not permanent_failure)
    service.start()
    try:
        configure_otlp_response(
            status_codes=statuses,
            body=b"",
            content_type="application/x-protobuf",
        )
        if input_name == "opentelemetry":
            service.send_payload_dict(
                {"resource_logs": [
                    _build_resource_collision_payload(event_id, event_id)["resource_logs"][0]
                    for event_id in expected
                ]},
                "logs",
            )
        else:
            response = requests.post(
                f"http://127.0.0.1:{service.flb_listener_port}/repro",
                json=[{"message": event_id} for event_id in expected],
                timeout=5,
            )
            assert response.status_code == 201

        def completed_metrics():
            try:
                response = requests.get(
                    f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics/prometheus",
                    timeout=2,
                )
            except (requests.ConnectionError, requests.Timeout):
                return None
            response.raise_for_status()
            counters = {
                name: int(value)
                for name, value in re.findall(
                    r'^fluentbit_output_(\w+)\{name="opentelemetry\.0"\} (\d+)',
                    response.text,
                    re.MULTILINE,
                )
            }
            finished = counters.get("proc_records_total", 0) + counters.get("dropped_records_total", 0)
            return counters if finished == record_count else None

        counters = service.service.wait_for_condition(
            completed_metrics,
            timeout=30,
            description="completion of the whole log chunk",
        )
        _wait_for_log_message(service, "[task] destroy task=")
        requests_seen = list(data_storage["logs"])
    finally:
        service.stop()

    accepted = []
    batches = []
    for request_number, export_request in enumerate(requests_seen, start=1):
        batch = [
            record.body.string_value
            for resource in export_request.resource_logs
            for scope in resource.scope_logs
            for record in scope.log_records
        ]
        assert 0 < len(batch) <= batch_size
        batches.append(batch)
        if request_number != fail_request:
            accepted.extend(batch)

    assert counters["proc_records_total"] == (0 if permanent_failure else record_count)
    assert counters["retries_total"] == int(retried)
    assert counters["retried_records_total"] == (record_count if retried else 0)
    assert counters["errors_total"] == int(permanent_failure)
    assert counters["dropped_records_total"] == (record_count if permanent_failure else 0)
    if fail_request:
        assert batches[fail_request - 1] == expected_batches[fail_request - 1]
        attempted = expected_batches[:fail_request]
        expected_accepted = expected[:(fail_request - 1) * batch_size]
        if retried:
            assert batches[fail_request] == expected_batches[0]
            replayed = [event_id for batch in batches[fail_request:] for event_id in batch]
            assert Counter(replayed) == Counter(expected)
            attempted += expected_batches
            expected_accepted += expected
    else:
        attempted = expected_batches
        expected_accepted = expected
    assert Counter(accepted) == Counter(expected_accepted)
    assert Counter(map(tuple, batches)) == Counter(map(tuple, attempted))

    with open(service.flb.log_file, encoding="utf-8") as log_file:
        log = log_file.read()
    created = re.findall(r"\[task\] created task=(\S+)", log)
    destroyed = re.findall(r"\[task\] destroy task=(\S+)", log)
    assert len(created) == 1
    assert destroyed == created


def test_out_opentelemetry_log_severity_message_keys():
    service = Service("out_otel_http_logs_message_keys.yaml")
    service.start()
    requests_seen = service.wait_for_requests(1)
    logs_seen = service.wait_for_signal("logs")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    record = output["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]

    assert request_seen["path"] == "/v1/logs"
    assert record["body"]["stringValue"] == "message-key body"
    assert record["severityText"] == "ERROR"
    assert record["severityNumber"] == "SEVERITY_NUMBER_ERROR"


def test_out_opentelemetry_custom_metadata_key_accessors():
    service = Service("out_otel_http_metadata_keys.yaml")
    service.start()
    service.send_json_logs_payload("test_logs_metadata_001.in.json")
    requests_seen = service.wait_for_requests(1)
    logs_seen = service.wait_for_signal("logs")
    service.stop()

    request_seen = requests_seen[0]
    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    record, attributes, _ = next(iter_log_records(output))

    assert request_seen["path"] == "/metadata/logs"
    assert record["severityText"] == "WARN"
    assert record["severityNumber"] == "SEVERITY_NUMBER_WARN"
    assert record["timeUnixNano"] == "1650917400000000000"
    assert record["observedTimeUnixNano"] == "1650917401000000000"
    assert base64.b64decode(record["traceId"]) == bytes.fromhex("63560bd4d8de74fae7d1e4160f2ee099")
    assert base64.b64decode(record["spanId"]) == bytes.fromhex("251484295a9df731")
    assert record["flags"] == 1
    assert attributes["example_key"] == "example_value"
    assert attributes["custom_attr"] == "custom_value"


@pytest.mark.parametrize(
    "config_file",
    [
        "out_otel_http_conditional_grouped_logs_non_threaded.yaml",
        "out_otel_http_conditional_grouped_logs_threaded.yaml",
    ],
    ids=["non_threaded", "threaded"],
)
def test_out_opentelemetry_conditional_routing_preserves_group_metadata(config_file):
    service = Service(config_file)
    service.start()
    try:
        service.send_payload_dict(_build_conditional_grouped_logs_payload(), "logs")
        logs_seen = list(service.wait_for_signal("logs", minimum_count=3, timeout=15))
        requests_seen = list(service.wait_for_requests(3, timeout=15))
    finally:
        service.stop()

    payloads_by_path = _log_payloads_by_request_path(logs_seen, requests_seen)
    assert set(payloads_by_path) == {
        "/conditional/group/alpha",
        "/conditional/group/beta",
        "/conditional/group/default",
    }

    _assert_grouped_resource(
        payloads_by_path["/conditional/group/alpha"],
        route_group="alpha",
        group_id="group-alpha",
        scopes=[
            {
                "name": "scope-alpha-a",
                "version": "1.0.0",
                "body": "event-alpha-a",
                "flags": 1,
            },
            {
                "name": "scope-alpha-b",
                "version": "1.1.0",
                "body": "event-alpha-b",
                "flags": 2,
            },
        ],
    )
    _assert_grouped_resource(
        payloads_by_path["/conditional/group/beta"],
        route_group="beta",
        group_id="group-beta",
        scopes=[
            {
                "name": "scope-beta",
                "version": "2.0.0",
                "body": "event-beta",
                "flags": 3,
            },
        ],
    )
    _assert_grouped_resource(
        payloads_by_path["/conditional/group/default"],
        route_group="fallback",
        group_id="group-default",
        scopes=[
            {
                "name": "scope-default",
                "version": "3.0.0",
                "body": "event-default",
                "flags": 4,
            },
        ],
    )


def _wait_for_log_message(service, message, timeout=15):
    def _contains_message():
        if not os.path.exists(service.flb.log_file):
            return False
        with open(service.flb.log_file, encoding="utf-8") as log_file:
            return message in log_file.read()

    service.service.wait_for_condition(
        _contains_message,
        timeout=timeout,
        interval=0.5,
        description=message,
    )


def test_out_opentelemetry_logs_max_resources_enforcement():
    service = Service("out_otel_http_limited_logs.yaml")
    service.start()
    service.send_json_logs_payload("test_logs_001.in.json")
    _wait_for_log_message(service, "max resources limit reached")
    service.stop()

    assert data_storage["logs"] == []


def test_out_opentelemetry_logs_max_scopes_enforcement():
    service = Service("out_otel_http_limited_scopes_logs.yaml")
    service.start()
    service.send_json_logs_payload("test_logs_001.in.json")
    logs_seen = service.wait_for_signal("logs", minimum_count=1, timeout=15)
    requests_seen = service.wait_for_requests(1, timeout=15)
    service.stop()

    assert len(requests_seen) == 1

    output = json.loads(json_format.MessageToJson(logs_seen[0]))
    assert len(output["resourceLogs"]) == 4
    assert all(len(resource_log["scopeLogs"]) == 1 for resource_log in output["resourceLogs"])


def _pack(value):
    """Encode forward fixtures without an optional MessagePack dependency."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, int):
        return b"\xcf" + value.to_bytes(8, "big")
    if isinstance(value, str):
        data = value.encode("utf-8")
        return b"\xdb" + len(data).to_bytes(4, "big") + data
    if isinstance(value, list):
        return b"\xdd" + len(value).to_bytes(4, "big") + b"".join(_pack(item) for item in value)
    if isinstance(value, dict):
        return b"\xdf" + len(value).to_bytes(4, "big") + b"".join(
            _pack(key) + _pack(item) for key, item in value.items())
    raise TypeError(type(value))


def _event_time(seconds):
    return b"\xd7\x00" + seconds.to_bytes(4, "big") + bytes(4)


def _group_start(resource_id, name):
    return [[_event_time(0xFFFFFFFF), {"schema": "otlp", "resource_id": resource_id, "scope_id": 0}],
            {"resource": {"attributes": {"service.name": name}}, "scope": {"name": "scope"}}]


def _group_end():
    return [[_event_time(0xFFFFFFFE), {}], {}]


def _log_record(record_id):
    return [[_event_time(1700000000), {"otlp": {}}], {"id": record_id}]


def _send_forward(service, entries):
    with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=10) as connection:
        connection.sendall(_pack(["test", entries]))


def _exported_record_ids():
    ids = []
    for export_request in data_storage["logs"]:
        output = json.loads(json_format.MessageToJson(export_request))
        for record, _, _ in iter_log_records(output):
            for item in record["body"]["kvlistValue"]["values"]:
                if item["key"] == "id":
                    ids.append(int(item["value"]["intValue"]))
    return sorted(ids)


def test_out_opentelemetry_chunk_ending_with_empty_group_exports_its_records():
    """A chunk that ends with a group start and no records still exports the earlier groups."""
    service = Service("out_otel_http_logs_forward_groups.yaml")
    service.start()
    try:
        # the next group starts in this append and receives its records later
        _send_forward(service, [_group_start(0, "first"), _log_record(0), _log_record(1),
                                _group_end(), _group_start(1, "second")])
        service.service.wait_for_condition(
            lambda: _exported_record_ids() == [0, 1] or None,
            timeout=15, interval=0.5, description="records of the first group")

        _send_forward(service, [_log_record(2), _group_end()])
        service.service.wait_for_condition(
            lambda: _exported_record_ids() == [0, 1, 2] or None,
            timeout=15, interval=0.5, description="record appended to the open group")
    finally:
        service.stop()


def test_out_opentelemetry_batch_size_exports_each_record_once():
    """Records of earlier scopes are not sent again by a later batch."""
    service = Service("out_otel_http_logs_forward_batch_size.yaml")
    service.start()
    try:
        entries = [_group_start(0, "first")] + [_log_record(i) for i in range(2)] + [_group_end()]
        entries += [_group_start(1, "second")] + [_log_record(i) for i in range(2, 7)] + [_group_end()]
        _send_forward(service, entries)
        service.service.wait_for_condition(
            lambda: len(_exported_record_ids()) >= 7 or None,
            timeout=15, interval=0.5, description="seven exported records")
        # give a duplicated export time to arrive
        time.sleep(2)
        assert _exported_record_ids() == list(range(7))
    finally:
        service.stop()
