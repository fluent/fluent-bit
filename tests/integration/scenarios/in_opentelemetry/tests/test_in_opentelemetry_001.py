#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2024 The Fluent Bit Authors
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

import os
import json
import logging
import time
import base64
from concurrent.futures import ThreadPoolExecutor
import grpc
import requests
import pytest

# OTel imports to convert from JSON to OTLP Protobuf
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceResponse
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceResponse
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse
from google.protobuf import json_format

# local imports
from utils.data_utils import read_json_file
from utils.http_matrix import PROTOCOL_CASES, run_curl_request
from utils.test_service import FluentBitTestService

from server.http_server import http_server_run
from server.otlp_server import configure_otlp_response, otlp_server_run, data_storage

logger = logging.getLogger(__name__)
MOCK_VALID_JWT = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QiLCJ0eXAiOiJKV1QifQ."
    "eyJleHAiOjE4OTM0NTYwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50MSJ9."
    "TqWs06LUpQa0FGLejnOkWAD6v562d5CUh2NwsJ7iAuae9-WNFBKU6mP1zAaoafla6o5npee7RfbSzZNFI4PKhqAj69789JjAYV7IW-GSuMwJejHdVOWmCc5lmcZPH0EVxEkHA6lFQxYQwDCrfQ8Sd4Q3vYCV6sLPENcuNpQi9ytjVjaZs_7ONH2oA-sZ7EUchqJJoIBPfjit2yYsq9NeemxCzYMtngiC-IX12eEfaQ1cVYPIjhhN_NaMvapznp-BW4gnXkNoAZ1S-p1axWWY-6UgRdMYOr0Hy5PHQ9fCuHJ6Z-blYdtuGavCUGHK5ghX-JdH1WJ51F89992dQ5yF_w"
)

IN_OPENTELEMETRY_PROTOCOL_CONFIGS = {
    "http1_cleartext": "otlp_http1_cleartext.yaml",
    "http2_cleartext": "otlp_http2_cleartext.yaml",
    "http1_tls": "otlp_http1_tls.yaml",
    "http2_tls": "otlp_http2_tls.yaml",
}

IN_OPENTELEMETRY_WORKER_PROTOCOL_CONFIGS = {
    "http1_cleartext": "otlp_http1_cleartext_workers.yaml",
    "http2_cleartext": "otlp_http2_cleartext_workers.yaml",
    "http1_tls": "otlp_http1_tls_workers.yaml",
    "http2_tls": "otlp_http2_tls_workers.yaml",
}

IN_OPENTELEMETRY_OAUTH2_PROTOCOL_CONFIGS = {
    "http1_cleartext": "otlp_http1_cleartext_oauth2.yaml",
    "http2_cleartext": "otlp_http2_cleartext_oauth2.yaml",
    "http1_tls": "otlp_http1_tls_oauth2.yaml",
    "http2_tls": "otlp_http2_tls_oauth2.yaml",
}

IN_OPENTELEMETRY_GRPC_OAUTH2_CASES = [
    {
        "id": "grpc_cleartext",
        "config_file": "otlp_http2_cleartext_oauth2.yaml",
        "use_tls": False,
    },
    {
        "id": "grpc_tls",
        "config_file": "otlp_http2_tls_oauth2.yaml",
        "use_tls": True,
    },
]

#  [Fluent Bit Test Suite]
#    - Start Fluent Bit:
#      - a custom configuration file
#      - set 3 environment variables:
#        - FLUENT_BIT_HTTP_MONITORING_PORT: port where Fluent Bit will expose internal metrics
#        - FLUENT_BIT_TEST_LISTENER_PORT: port used by the config file to define where to listen
#          for incoming connections
#        - TEST_SUITE_HTTP_PORT: local port on this suite which is used by Fluent Bit to send the
#          data back
#
#   [Test Suite] --> writes a request --> [Fluent Bit] --> forwards the request --> [Test Suite]
#
#    In the process above, Fluent Bit decode the request, process it and encode it back.


def iter_log_records(output):
    for resource_log in output["resourceLogs"]:
        resource_attributes = {
            item["key"]: next(iter(item["value"].values()))
            for item in resource_log.get("resource", {}).get("attributes", [])
        }
        for scope_log in resource_log.get("scopeLogs", []):
            scope = scope_log.get("scope", {})
            scope_attributes = {
                item["key"]: next(iter(item["value"].values()))
                for item in scope.get("attributes", [])
            }
            for record in scope_log.get("logRecords", []):
                record_attributes = {
                    item["key"]: next(iter(item["value"].values()))
                    for item in record.get("attributes", [])
                }
                yield {
                    "resource_attributes": resource_attributes,
                    "scope_name": scope.get("name"),
                    "scope_version": scope.get("version"),
                    "scope_attributes": scope_attributes,
                    "record": record,
                    "record_attributes": record_attributes,
                    "body": record.get("body", {}).get("stringValue"),
                }


def iter_metric_entries(output):
    for resource_metric in output.get("resourceMetrics", []):
        resource_attributes = {
            item["key"]: next(iter(item["value"].values()))
            for item in resource_metric.get("resource", {}).get("attributes", [])
        }
        for scope_metric in resource_metric.get("scopeMetrics", []):
            scope = scope_metric.get("scope", {})
            for metric in scope_metric.get("metrics", []):
                yield {
                    "resource_attributes": resource_attributes,
                    "scope_name": scope.get("name"),
                    "scope_version": scope.get("version"),
                    "metric": metric,
                }


def iter_spans(output):
    for resource_span in output.get("resourceSpans", []):
        resource_attributes = {
            item["key"]: next(iter(item["value"].values()))
            for item in resource_span.get("resource", {}).get("attributes", [])
        }
        for scope_span in resource_span.get("scopeSpans", []):
            scope = scope_span.get("scope", {})
            for span in scope_span.get("spans", []):
                span_attributes = {
                    item["key"]: next(iter(item["value"].values()))
                    for item in span.get("attributes", [])
                }
                yield {
                    "resource_attributes": resource_attributes,
                    "scope_name": scope.get("name"),
                    "scope_version": scope.get("version"),
                    "span": span,
                    "span_attributes": span_attributes,
                }


def read_stdout_otlp_json(service, root_key, timeout=10, interval=0.25):
    deadline = time.time() + timeout
    decoder = json.JSONDecoder()

    while time.time() < deadline:
        if service.flb and service.flb.log_file and os.path.exists(service.flb.log_file):
            with open(service.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
                content = log_file.read()

            matches = []

            for offset, character in enumerate(content):
                if character != "{":
                    continue

                try:
                    payload, _ = decoder.raw_decode(content[offset:])
                except json.JSONDecodeError:
                    continue

                if isinstance(payload, dict) and root_key in payload:
                    matches.append(payload)

            if matches:
                return matches[-1]

        time.sleep(interval)

    raise TimeoutError(f"Timed out waiting for stdout OTLP JSON payload with root key {root_key}")


def read_stdout_otlp_json_text(service, root_key, timeout=10, interval=0.25):
    deadline = time.time() + timeout
    decoder = json.JSONDecoder()

    while time.time() < deadline:
        if service.flb and service.flb.log_file and os.path.exists(service.flb.log_file):
            with open(service.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
                content = log_file.read()

            matches = []

            for offset, character in enumerate(content):
                if character != "{":
                    continue

                try:
                    payload, end = decoder.raw_decode(content[offset:])
                except json.JSONDecodeError:
                    continue

                if isinstance(payload, dict) and root_key in payload:
                    matches.append(content[offset:offset + end])

            if matches:
                return matches[-1]

        time.sleep(interval)

    raise TimeoutError(f"Timed out waiting for stdout OTLP JSON payload with root key {root_key}")

class Service:
    def __init__(self, config_file, *, use_auth_server=False):
        # Compose the absolute path for the Fluent Bit configuration file
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '../config/', config_file))
        test_path = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.abspath(os.path.join(test_path, "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.use_auth_server = use_auth_server
        self.auth_server_port = None
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

    def _start_receiver(self, service):
        if self.use_auth_server:
            self.auth_server_port = service.allocate_port_env("TEST_SUITE_JWKS_PORT")
            http_server_run(self.auth_server_port)
            self.service.wait_for_http_endpoint(
                f"http://127.0.0.1:{self.auth_server_port}/ping",
                timeout=10,
                interval=0.5,
            )
        otlp_server_run(service.test_suite_http_port)
        url = f'http://127.0.0.1:{service.test_suite_http_port}/ping'
        self.service.wait_for_http_endpoint(url, timeout=10, interval=0.5)

    def _stop_receiver(self, service):
        if self.auth_server_port is not None:
            try:
                requests.post(f"http://127.0.0.1:{self.auth_server_port}/shutdown", timeout=2)
            except requests.RequestException:
                pass
        try:
            requests.post(f'http://localhost:{service.test_suite_http_port}/shutdown', timeout=2)
        except requests.RequestException:
            pass

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.flb_listener_port = self.service.flb_listener_port
        self.test_suite_http_port = self.service.test_suite_http_port
        logger.info(f"Fluent Bit listener port: {self.flb_listener_port}")
        logger.info(f"test suite http port: {self.test_suite_http_port}")

    def wait_for_log_message(self, pattern, timeout=10, interval=0.25):
        deadline = time.time() + timeout

        while time.time() < deadline:
            if self.flb and self.flb.log_file and os.path.exists(self.flb.log_file):
                with open(self.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
                    if pattern in log_file.read():
                        return True

            time.sleep(interval)

        raise TimeoutError(f"Timed out waiting for log pattern: {pattern}")

    def read_response(self, signal_type, timeout=10, interval=0.5):
        deadline = time.time() + timeout
        while len(data_storage[signal_type]) <= 0:
            if time.time() >= deadline:
                raise TimeoutError(f"Timed out waiting for OTLP {signal_type} response")
            time.sleep(0.5)
            logger.info("waiting for %s response...", signal_type)

        json_str = json_format.MessageToJson(data_storage[signal_type][0])
        logger.info(f"{json_str}")
        return json.loads(json_str)

    def send_request(self, endpoint, payload, content_type='application/x-protobuf'):
        # Send the protobuf payload
        url = f'http://localhost:{self.flb_listener_port}{endpoint}'
        headers = {'Content-Type': content_type}
        response = requests.post(url, data=payload.SerializeToString(), headers=headers)
        print(f'Status code: {response.status_code}')
        print(f'Response text: {response.text}')
        return response

    def send_raw_request(self, endpoint, payload, content_type='application/x-protobuf'):
        url = f'http://localhost:{self.flb_listener_port}{endpoint}'
        headers = {'Content-Type': content_type}
        return requests.post(url, data=payload, headers=headers, timeout=5)

    def send_json_as_otel_protobuf(self, json_input, signal_type):
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tests', 'data_files'))
        json_payload_dict = read_json_file(os.path.join(base_path, json_input))
        json_payload_str = json.dumps(json_payload_dict)

        request_map = {
            "logs": (ExportLogsServiceRequest(), "/v1/logs"),
            "metrics": (ExportMetricsServiceRequest(), "/v1/metrics"),
            "traces": (ExportTraceServiceRequest(), "/v1/traces"),
        }
        request_message, endpoint = request_map[signal_type]
        protobuf_payload = json_format.Parse(json_payload_str, request_message)

        self.send_request(endpoint, protobuf_payload)

        return self.read_response(signal_type)

    def send_grpc_request(self, signal_type, payload, *, authorization=None, use_tls=False):
        method_map = {
            "logs": (
                "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
                ExportLogsServiceRequest.SerializeToString,
                ExportLogsServiceResponse.FromString,
            ),
            "metrics": (
                "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
                ExportMetricsServiceRequest.SerializeToString,
                ExportMetricsServiceResponse.FromString,
            ),
            "traces": (
                "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
                ExportTraceServiceRequest.SerializeToString,
                ExportTraceServiceResponse.FromString,
            ),
        }
        method_path, serializer, deserializer = method_map[signal_type]
        target = f"127.0.0.1:{self.flb_listener_port}"

        if use_tls:
            with open(self.tls_crt_file, "rb") as certificate_file:
                channel_credentials = grpc.ssl_channel_credentials(certificate_file.read())
            channel = grpc.secure_channel(target, channel_credentials)
        else:
            channel = grpc.insecure_channel(target)

        metadata = []
        if authorization is not None:
            metadata.append(("authorization", authorization))

        try:
            grpc.channel_ready_future(channel).result(timeout=5)
            rpc = channel.unary_unary(
                method_path,
                request_serializer=serializer,
                response_deserializer=deserializer,
            )
            return rpc(payload, metadata=metadata, timeout=5)
        finally:
            channel.close()

    def build_otel_payload(self, json_input, signal_type):
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tests', 'data_files'))
        json_payload_dict = read_json_file(os.path.join(base_path, json_input))
        json_payload_str = json.dumps(json_payload_dict)

        request_map = {
            "logs": ExportLogsServiceRequest(),
            "metrics": ExportMetricsServiceRequest(),
            "traces": ExportTraceServiceRequest(),
        }
        request_message = request_map[signal_type]
        protobuf_payload = json_format.Parse(json_payload_str, request_message)
        return protobuf_payload.SerializeToString()

    def wait_for_signal_count(self, signal_type, minimum_count, timeout=10, interval=0.25):
        return self.service.wait_for_condition(
            lambda: len(data_storage[signal_type]) if len(data_storage[signal_type]) >= minimum_count else None,
            timeout=timeout,
            interval=interval,
            description=f"{minimum_count} OTLP {signal_type} payloads",
        )

    def stop(self):
        self.service.stop()


# This is a full pipeline test, the file tests_logs_001.in.json, represents an OpenTelemetry Log payload in
# JSON format which gets converted to Protobuf.
#
# Then Fluent Bit is started having an OpenTelemetry listener (input plugin) and OpenTelemetry output plugin
# that sends the data back to the test suite. Note that we instance a dummy OTLP server in this test suite
# so we can check the data that is being sent back.
def test_opentelemetry_to_opentelemetry_basic_log():
    service = Service("001-fluent-bit.yaml")
    service.start()
    output = service.send_json_as_otel_protobuf("test_logs_001.in.json", "logs")
    logger.info(f"response: {output}")
    service.stop()

    records = list(iter_log_records(output))
    assert len(records) >= 2

    expected_bodies = {
        "This is an example log message.",
        "This is another example log message.",
    }
    observed_bodies = {record["body"] for record in records}

    assert observed_bodies == expected_bodies

    for item in records:
        assert item["resource_attributes"]["aaa"] == "bbb"
        assert "service.name" not in item["resource_attributes"]
        assert item["scope_name"] == "new scope name"
        assert item["scope_version"] == "3.1.0"
        assert item["scope_attributes"]["mynewscope"] == "123"
        assert item["record"]["severityText"] == "INFO"
        assert item["record_attributes"]["example_key"] == "example_value"


# Start a Fluent Bit Pipeline with Dummy message and then it gets handle by OpenTelemetry output, the config
# aims to populate traceId and spanId fields with the values from the Dummy message.
#
# issue : https://github.com/fluent/fluent-bit/issues/9071
# fixed : https://github.com/fluent/fluent-bit/pull/9074
def test_dummy_to_opentelemetry_log():
    service = Service("002-fluent-bit.yaml")
    service.start()
    output = service.read_response("logs")
    logger.info(f"response: {output}")
    service.stop()

    # direct reference to the record
    record = output['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0]

    # notes on traceid and spanid: the test case encodes the values as hex strings, Fluent Bit OpenTelemetry
    # output plugin will decode and pack them as bytes. When the data is sent back to the test suite, the values
    # are encoded as base64 strings (Python thing). So we need to decode them back to bytes and compare them.
    assert base64.b64decode(record['traceId']) == bytes.fromhex('63560bd4d8de74fae7d1e4160f2ee099')
    assert base64.b64decode(record['spanId'])  == bytes.fromhex('251484295a9df731')


def test_opentelemetry_to_opentelemetry_basic_metrics():
    service = Service("001-fluent-bit.yaml")
    service.start()
    output = service.send_json_as_otel_protobuf("test_metrics_001.in.json", "metrics")
    logger.info(f"response: {output}")
    service.stop()

    assert len(output["resourceMetrics"]) == 1
    resource_metric = output["resourceMetrics"][0]
    metric = resource_metric["scopeMetrics"][0]["metrics"][0]
    datapoint = metric["sum"]["dataPoints"][0]

    assert metric["name"] == "requests_total"
    assert metric["sum"]["aggregationTemporality"] == "AGGREGATION_TEMPORALITY_CUMULATIVE"
    assert datapoint["asInt"] == "42"
    assert datapoint["attributes"][0]["key"] == "service.name"
    assert datapoint["attributes"][0]["value"]["stringValue"] == "checkout"


def test_opentelemetry_to_opentelemetry_histogram_and_gauge_metrics():
    service = Service("001-fluent-bit.yaml")
    service.start()
    output = service.send_json_as_otel_protobuf("test_metrics_002.in.json", "metrics")
    logger.info(f"response: {output}")
    service.stop()

    metrics = {item["metric"]["name"]: item for item in iter_metric_entries(output)}

    assert set(metrics) == {"request.duration", "cpu.usage"}

    histogram = metrics["request.duration"]["metric"]["histogram"]
    gauge = metrics["cpu.usage"]["metric"]["gauge"]
    histogram_datapoint = histogram["dataPoints"][0]
    gauge_datapoint = gauge["dataPoints"][0]

    assert metrics["request.duration"]["resource_attributes"]["service.name"] == "payments"
    assert metrics["request.duration"]["scope_name"] == "metrics-advanced-scope"
    assert histogram_datapoint["count"] == "3"
    assert histogram_datapoint["sum"] == 245.0
    assert histogram_datapoint["bucketCounts"] == ["1", "2"]
    assert histogram_datapoint["explicitBounds"] == [100.0]
    assert histogram_datapoint["attributes"][0]["key"] == "http.route"
    assert histogram_datapoint["attributes"][0]["value"]["stringValue"] == "/checkout"

    assert metrics["cpu.usage"]["scope_version"] == "2.0.0"
    assert gauge_datapoint["asDouble"] == 0.82
    assert gauge_datapoint["attributes"][0]["key"] == "host.name"
    assert gauge_datapoint["attributes"][0]["value"]["stringValue"] == "node-a"


def test_opentelemetry_to_opentelemetry_basic_traces():
    service = Service("001-fluent-bit.yaml")
    service.start()
    output = service.send_json_as_otel_protobuf("test_traces_001.in.json", "traces")
    logger.info(f"response: {output}")
    service.stop()

    assert len(output["resourceSpans"]) == 1
    resource_span = output["resourceSpans"][0]
    span = resource_span["scopeSpans"][0]["spans"][0]

    assert span["name"] == "checkout-span"
    assert span["kind"] == "SPAN_KIND_SERVER"
    assert span["traceId"] == "5b8efff798038103d269b633813fc60c"
    assert span["spanId"] == "eee19b7ec3c1b174"
    assert span["attributes"][0]["key"] == "http.method"
    assert span["attributes"][0]["value"]["stringValue"] == "GET"


def test_opentelemetry_to_opentelemetry_parent_child_traces():
    service = Service("001-fluent-bit.yaml")
    service.start()
    output = service.send_json_as_otel_protobuf("test_traces_002.in.json", "traces")
    logger.info(f"response: {output}")
    service.stop()

    spans = {item["span"]["name"]: item for item in iter_spans(output)}

    assert set(spans) == {"parent-span", "child-span"}

    parent_span = spans["parent-span"]["span"]
    child_span = spans["child-span"]["span"]

    assert spans["parent-span"]["resource_attributes"]["service.name"] == "checkout"
    assert spans["parent-span"]["scope_name"] == "trace-advanced-scope"
    assert spans["child-span"]["span_attributes"]["db.system"] == "postgresql"

    assert parent_span["traceId"] == child_span["traceId"]
    assert child_span["parentSpanId"] == parent_span["spanId"]
    assert parent_span["events"][0]["name"] == "cache.miss"
    assert parent_span["status"]["message"] == "ok"
    assert child_span["status"]["code"] == "STATUS_CODE_ERROR"


def test_in_opentelemetry_rejects_invalid_logs_payload():
    service = Service("001-fluent-bit.yaml")
    service.start()
    response = service.send_raw_request("/v1/logs", b"not-a-valid-otlp-payload")
    service.stop()

    assert response.status_code >= 400
    assert len(data_storage["logs"]) == 0


def test_in_opentelemetry_rejects_invalid_metrics_payload():
    service = Service("001-fluent-bit.yaml")
    service.start()
    response = service.send_raw_request("/v1/metrics", b"not-a-valid-otlp-payload")
    service.stop()

    assert response.status_code >= 400
    assert len(data_storage["metrics"]) == 0


def test_in_opentelemetry_rejects_invalid_traces_payload():
    service = Service("001-fluent-bit.yaml")
    service.start()
    response = service.send_raw_request("/v1/traces", b"not-a-valid-otlp-payload")
    service.stop()

    assert response.status_code >= 400
    assert len(data_storage["traces"]) == 0


def test_in_opentelemetry_stdout_otlp_json_logs():
    service = Service("003-stdout-otlp-json.yaml")
    service.start()

    payload = service.build_otel_payload("test_logs_001.in.json", "logs")
    response = service.send_raw_request("/v1/logs", payload)
    assert 200 <= response.status_code < 300

    output = read_stdout_otlp_json(service, "resourceLogs")
    service.stop()

    records = list(iter_log_records(output))
    assert len(records) >= 2
    assert records[0]["record"]["severityText"] == "INFO"
    assert records[0]["record"]["timeUnixNano"] == "1650917400000000000"
    assert records[0]["resource_attributes"]["service.name"] == "example-service"


def test_in_opentelemetry_stdout_otlp_json_metrics():
    service = Service("003-stdout-otlp-json.yaml")
    service.start()

    payload = service.build_otel_payload("test_metrics_001.in.json", "metrics")
    response = service.send_raw_request("/v1/metrics", payload)
    assert 200 <= response.status_code < 300

    output = read_stdout_otlp_json(service, "resourceMetrics")
    service.stop()

    metric_entry = list(iter_metric_entries(output))[0]
    metric = metric_entry["metric"]

    assert metric["name"] == "requests_total"
    assert metric["sum"]["dataPoints"][0]["asInt"] == "42"
    assert metric_entry["resource_attributes"]["service.instance.id"] == "instance-1"
    assert metric["sum"]["dataPoints"][0]["attributes"][0]["key"] == "service.name"
    assert metric["sum"]["dataPoints"][0]["attributes"][0]["value"]["stringValue"] == "checkout"


def test_in_opentelemetry_stdout_otlp_json_traces():
    service = Service("003-stdout-otlp-json.yaml")
    service.start()

    payload = service.build_otel_payload("test_traces_001.in.json", "traces")
    response = service.send_raw_request("/v1/traces", payload)
    assert 200 <= response.status_code < 300

    output = read_stdout_otlp_json(service, "resourceSpans")
    service.stop()

    span_entry = list(iter_spans(output))[0]
    span = span_entry["span"]

    assert span["name"] == "checkout-span"
    assert span["traceId"] == "e5bf1e7df7fbf7cd37f35d37776ebd6fadf7f35ddf73ad1c"
    assert span["spanId"] == "79e7b5f5bede7377356f5ef8"
    assert span_entry["resource_attributes"]["service.name"] == "checkout"


def test_in_opentelemetry_stdout_otlp_json_pretty_logs():
    service = Service("004-stdout-otlp-json-pretty.yaml")
    service.start()

    payload = service.build_otel_payload("test_logs_001.in.json", "logs")
    response = service.send_raw_request("/v1/logs", payload)
    assert 200 <= response.status_code < 300

    output = read_stdout_otlp_json(service, "resourceLogs")
    output_text = read_stdout_otlp_json_text(service, "resourceLogs")
    service.stop()

    records = list(iter_log_records(output))
    assert len(records) >= 2
    assert records[0]["record"]["severityText"] == "INFO"
    assert "\n  \"resourceLogs\": [" in output_text
    assert "\n          \"logRecords\": [" in output_text


def test_in_opentelemetry_stdout_otlp_json_pretty_metrics():
    service = Service("004-stdout-otlp-json-pretty.yaml")
    service.start()

    payload = service.build_otel_payload("test_metrics_001.in.json", "metrics")
    response = service.send_raw_request("/v1/metrics", payload)
    assert 200 <= response.status_code < 300

    output = read_stdout_otlp_json(service, "resourceMetrics")
    output_text = read_stdout_otlp_json_text(service, "resourceMetrics")
    service.stop()

    metric_entry = list(iter_metric_entries(output))[0]
    assert metric_entry["metric"]["name"] == "requests_total"
    assert "\n  \"resourceMetrics\": [" in output_text
    assert "\n          \"metrics\": [" in output_text


def test_in_opentelemetry_stdout_otlp_json_pretty_traces():
    service = Service("004-stdout-otlp-json-pretty.yaml")
    service.start()

    payload = service.build_otel_payload("test_traces_001.in.json", "traces")
    response = service.send_raw_request("/v1/traces", payload)
    assert 200 <= response.status_code < 300

    output = read_stdout_otlp_json(service, "resourceSpans")
    output_text = read_stdout_otlp_json_text(service, "resourceSpans")
    service.stop()

    span_entry = list(iter_spans(output))[0]
    assert span_entry["span"]["name"] == "checkout-span"
    assert "\n  \"resourceSpans\": [" in output_text
    assert "\n          \"spans\": [" in output_text


@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[case["id"] for case in PROTOCOL_CASES])
def test_in_opentelemetry_oauth2_requires_bearer_token(case):
    service = Service(
        IN_OPENTELEMETRY_OAUTH2_PROTOCOL_CONFIGS[case["config_key"]],
        use_auth_server=True,
    )
    service.start()

    scheme = "https" if case["use_tls"] else "http"
    payload = service.build_otel_payload("test_logs_001.in.json", "logs")
    result = run_curl_request(
        f"{scheme}://localhost:{service.flb_listener_port}/v1/logs",
        payload,
        headers=["Content-Type: application/x-protobuf"],
        http_mode=case["http_mode"],
        ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
    )

    service.stop()

    assert result["status_code"] == 401
    assert len(data_storage["logs"]) == 0


@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[case["id"] for case in PROTOCOL_CASES])
def test_in_opentelemetry_oauth2_accepts_valid_jwt(case):
    service = Service(
        IN_OPENTELEMETRY_OAUTH2_PROTOCOL_CONFIGS[case["config_key"]],
        use_auth_server=True,
    )
    service.start()

    scheme = "https" if case["use_tls"] else "http"
    payload = service.build_otel_payload("test_logs_001.in.json", "logs")
    result = run_curl_request(
        f"{scheme}://localhost:{service.flb_listener_port}/v1/logs",
        payload,
        headers=[
            "Content-Type: application/x-protobuf",
            f"Authorization: Bearer {MOCK_VALID_JWT}",
        ],
        http_mode=case["http_mode"],
        ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
    )
    response_payload = service.read_response("logs")

    service.stop()

    assert result["status_code"] == 201
    assert result["http_version"] == case["expected_http_version"]
    assert len(response_payload["resourceLogs"]) > 0


@pytest.mark.parametrize("case", IN_OPENTELEMETRY_GRPC_OAUTH2_CASES, ids=[case["id"] for case in IN_OPENTELEMETRY_GRPC_OAUTH2_CASES])
def test_in_opentelemetry_grpc_oauth2_requires_bearer_token(case):
    service = Service(case["config_file"], use_auth_server=True)
    service.start()

    payload = json_format.Parse(
        json.dumps(
            read_json_file(
                os.path.abspath(
                    os.path.join(os.path.dirname(__file__), "../tests/data_files/test_logs_001.in.json")
                )
            )
        ),
        ExportLogsServiceRequest(),
    )

    with pytest.raises(grpc.RpcError) as exc_info:
        service.send_grpc_request("logs", payload, use_tls=case["use_tls"])

    service.stop()

    assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED
    assert len(data_storage["logs"]) == 0


@pytest.mark.parametrize("case", IN_OPENTELEMETRY_GRPC_OAUTH2_CASES, ids=[case["id"] for case in IN_OPENTELEMETRY_GRPC_OAUTH2_CASES])
def test_in_opentelemetry_grpc_oauth2_accepts_valid_jwt(case):
    service = Service(case["config_file"], use_auth_server=True)
    service.start()

    payload = json_format.Parse(
        json.dumps(
            read_json_file(
                os.path.abspath(
                    os.path.join(os.path.dirname(__file__), "../tests/data_files/test_logs_001.in.json")
                )
            )
        ),
        ExportLogsServiceRequest(),
    )
    service.send_grpc_request(
        "logs",
        payload,
        authorization=f"Bearer {MOCK_VALID_JWT}",
        use_tls=case["use_tls"],
    )
    response_payload = service.read_response("logs")

    service.stop()

    assert len(response_payload["resourceLogs"]) > 0


def test_out_opentelemetry_receiver_error_is_observable():
    service = Service("001-fluent-bit.yaml")
    service.start()
    configure_otlp_response(status_code=500, body={"status": "error"})

    service.send_json_as_otel_protobuf("test_logs_001.in.json", "logs")
    requests_seen = service.service.wait_for_condition(
        lambda: data_storage["requests"] if len(data_storage["requests"]) >= 1 else None,
        timeout=10,
        interval=0.5,
        description="at least one OTLP output attempt",
    )
    service.stop()

    assert len(requests_seen) >= 1


@pytest.mark.parametrize("signal_type,json_input,endpoint,storage_key", [
    ("logs", "test_logs_001.in.json", "/v1/logs", "logs"),
    ("metrics", "test_metrics_001.in.json", "/v1/metrics", "metrics"),
    ("traces", "test_traces_001.in.json", "/v1/traces", "traces"),
])
@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[case["id"] for case in PROTOCOL_CASES])
def test_in_opentelemetry_protocol_matrix(case, signal_type, json_input, endpoint, storage_key):
    service = Service(IN_OPENTELEMETRY_PROTOCOL_CONFIGS[case["config_key"]])
    service.start()

    scheme = "https" if case["use_tls"] else "http"
    payload = service.build_otel_payload(json_input, signal_type)
    result = run_curl_request(
        f"{scheme}://localhost:{service.flb_listener_port}{endpoint}",
        payload,
        headers=["Content-Type: application/x-protobuf"],
        http_mode=case["http_mode"],
        ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
    )
    response_payload = service.read_response(storage_key)

    service.stop()

    assert result["status_code"] == 201
    assert result["http_version"] == case["expected_http_version"]
    assert len(response_payload) > 0


# This test is branch-specific coverage for the generic HTTP listener worker mode.
# It does three things:
# 1. enables http_server.workers on the in_opentelemetry listener,
# 2. sends concurrent mixed OTLP requests across representative matrix variants,
# 3. verifies end-to-end delivery for logs, metrics and traces under that load.
#
# The current OTLP input path does not expose the serving worker id back to the
# client or the forwarded payload, so this test validates the multi-worker
# transport path with concurrent mixed traffic and confirms the listener started
# with multiple workers. Once the branch exposes per-worker request identity,
# this should be tightened to assert distinct worker ids directly.
@pytest.mark.parametrize("case", [
    {"id": "http1_cleartext", "config_key": "http1_cleartext", "http_mode": "http1.1", "use_tls": False},
    {"id": "http2_cleartext_prior_knowledge", "config_key": "http2_cleartext", "http_mode": "http2-prior-knowledge", "use_tls": False},
    {"id": "http1_tls", "config_key": "http1_tls", "http_mode": "http1.1", "use_tls": True},
    {"id": "http2_tls_alpn", "config_key": "http2_tls", "http_mode": "http2", "use_tls": True},
], ids=lambda case: case["id"])
def test_in_opentelemetry_http_workers_mixed_signal_matrix(case):
    request_plan = [
        ("logs", "test_logs_001.in.json", "/v1/logs"),
        ("metrics", "test_metrics_001.in.json", "/v1/metrics"),
        ("traces", "test_traces_001.in.json", "/v1/traces"),
    ]
    repeats_per_signal = 4
    total_requests = len(request_plan) * repeats_per_signal

    service = Service(IN_OPENTELEMETRY_WORKER_PROTOCOL_CONFIGS[case["config_key"]])
    service.start()
    service.wait_for_log_message("with 4 workers", timeout=10)

    scheme = "https" if case["use_tls"] else "http"
    request_jobs = []
    for _ in range(repeats_per_signal):
        for signal_type, json_input, endpoint in request_plan:
            request_jobs.append(
                {
                    "signal_type": signal_type,
                    "endpoint": endpoint,
                    "payload": service.build_otel_payload(json_input, signal_type),
                }
            )

    def send_job(job):
        return run_curl_request(
            f"{scheme}://localhost:{service.flb_listener_port}{job['endpoint']}",
            job["payload"],
            headers=["Content-Type: application/x-protobuf", "Connection: close"],
            http_mode=case["http_mode"],
            ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
        )

    with ThreadPoolExecutor(max_workers=total_requests) as executor:
        results = list(executor.map(send_job, request_jobs))

    for result in results:
        assert result["status_code"] == 201

    service.wait_for_signal_count("logs", 1, timeout=20)
    service.wait_for_signal_count("metrics", 1, timeout=20)
    service.wait_for_signal_count("traces", 1, timeout=20)

    requests_seen = service.service.wait_for_condition(
        lambda: list(data_storage["requests"]) if len(data_storage["requests"]) >= 3 else None,
        timeout=20,
        interval=0.25,
        description="mixed OTLP output requests",
    )

    service.stop()

    paths_seen = {request["path"] for request in requests_seen}

    assert len(requests_seen) >= 3
    assert "/v1/logs" in paths_seen
    assert "/v1/metrics" in paths_seen
    assert "/v1/traces" in paths_seen
