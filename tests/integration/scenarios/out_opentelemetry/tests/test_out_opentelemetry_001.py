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


def iter_log_records(output):
    for resource_log in output.get("resourceLogs", []):
        for scope_log in resource_log.get("scopeLogs", []):
            for record in scope_log.get("logRecords", []):
                attributes = {
                    item["key"]: next(iter(item["value"].values()))
                    for item in record.get("attributes", [])
                }
                yield record, attributes


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
    record, attributes = next(iter_log_records(output))

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
    record, attributes = next(iter_log_records(output))

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
    record, attributes = next(iter_log_records(output))

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
