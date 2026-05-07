import base64
import json
import logging
import os
import socket

import requests
import pytest
from google.protobuf import json_format
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
