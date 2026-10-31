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
import gzip
import http.client
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
from utils.fluent_bit_manager import FluentBitStartupError
from utils.http_matrix import PROTOCOL_CASES, curl_supports_http2, run_curl_request
from utils.oauth2 import duplicate_header_token, track_jwks_requests
from utils.input_pause_resume import (
    assert_pause_resume_cycles,
    assert_shutdown_while_paused,
    open_stalled_tcp_connection,
)
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

IN_OPENTELEMETRY_TINY_INGRESS_QUEUE_CONFIG = "otlp_http1_cleartext_workers_tiny_ingress_queue.yaml"
IN_OPENTELEMETRY_TINY_INGRESS_QUEUE_BYTE_LIMIT_CONFIG = \
    "otlp_http1_cleartext_workers_tiny_ingress_queue_byte_limit.yaml"
IN_OPENTELEMETRY_TINY_INGRESS_QUEUE_BYTE_LIMIT_PROCESSORS_CONFIG = \
    "otlp_http1_cleartext_workers_tiny_ingress_queue_byte_limit_processors.yaml"

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


def read_stdout_otlp_json(service, root_key, timeout=10, interval=0.25, min_entries=None):
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
                if min_entries is None:
                    return matches[-1]
                entries = [entry for match in matches for entry in match[root_key]]
                if len(entries) >= min_entries:
                    return {root_key: entries}

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


def read_fluent_bit_log(service):
    if not service.flb or not service.flb.log_file or not os.path.exists(service.flb.log_file):
        return ""

    with open(service.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
        return log_file.read()


def read_prometheus_metric_value(metrics_text, metric_name, input_name):
    label = f'name="{input_name}"'

    for line in metrics_text.splitlines():
        if not line.startswith(metric_name):
            continue

        if "{" in line and label not in line:
            continue

        return float(line.rsplit(" ", 1)[-1])

    raise AssertionError(f"Metric {metric_name} with {label} not found")


def maybe_read_prometheus_metric_value(metrics_text, metric_name, input_name):
    try:
        return read_prometheus_metric_value(metrics_text, metric_name, input_name)
    except AssertionError:
        return None


def build_resource_collision_logs_payload(user_id, body, schema_url=None):
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "user.id",
                            "value": {
                                "stringValue": user_id,
                            },
                        }
                    ],
                },
                "scopeLogs": [
                    {
                        "scope": {},
                        "logRecords": [
                            {
                                "timeUnixNano": "1640995200000000000",
                                "body": {
                                    "stringValue": body,
                                },
                            }
                        ],
                    }
                ],
            }
        ],
    }

    if schema_url is not None:
        payload["resourceLogs"][0]["schemaUrl"] = schema_url

    return json_format.Parse(json.dumps(payload), ExportLogsServiceRequest()).SerializeToString()


def build_resource_collision_logs_json_payload(user_id, body, schema_url=None):
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "user.id",
                            "value": {
                                "stringValue": user_id,
                            },
                        }
                    ],
                },
                "scopeLogs": [
                    {
                        "scope": {},
                        "logRecords": [
                            {
                                "timeUnixNano": "1640995200000000000",
                                "body": {
                                    "stringValue": body,
                                },
                            }
                        ],
                    }
                ],
            }
        ],
    }

    if schema_url is not None:
        payload["resourceLogs"][0]["schemaUrl"] = schema_url

    return json.dumps(payload).encode("utf-8")


def build_scope_schema_logs_payload():
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {
                                "stringValue": "scope-schema-service",
                            },
                        }
                    ],
                },
                "scopeLogs": [
                    {
                        "schemaUrl": "scope-schema-a",
                        "logRecords": [
                            {
                                "timeUnixNano": "1640995200000000000",
                                "body": {
                                    "stringValue": "event-a",
                                },
                            }
                        ],
                    },
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": "1640995200000000000",
                                "body": {
                                    "stringValue": "event-b",
                                },
                            }
                        ],
                    },
                ],
            }
        ],
    }

    return json_format.Parse(json.dumps(payload), ExportLogsServiceRequest()).SerializeToString()


def build_scope_schema_logs_json_payload():
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {
                                "stringValue": "scope-schema-service",
                            },
                        }
                    ],
                },
                "scopeLogs": [
                    {
                        "schemaUrl": "scope-schema-a",
                        "logRecords": [
                            {
                                "timeUnixNano": "1640995200000000000",
                                "body": {
                                    "stringValue": "event-a",
                                },
                            }
                        ],
                    },
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": "1640995200000000000",
                                "body": {
                                    "stringValue": "event-b",
                                },
                            }
                        ],
                    },
                ],
            }
        ],
    }

    return json.dumps(payload).encode("utf-8")


def build_histogram_json_payload(explicit_bounds, name="histogram_bounds"):
    payload = {
        "resourceMetrics": [
            {
                "resource": {
                    "attributes": [],
                },
                "scopeMetrics": [
                    {
                        "metrics": [
                            {
                                "name": name,
                                "histogram": {
                                    "aggregationTemporality": 2,
                                    "dataPoints": [
                                        {
                                            "count": "3",
                                            "sum": 3.0,
                                            "bucketCounts": ["1", "1", "1"],
                                            "explicitBounds": explicit_bounds,
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

    return json.dumps(payload).encode("utf-8")


def generated_limit_payload(attributes, scopes, records=1, resources=1):
    request = ExportLogsServiceRequest()
    for _ in range(resources):
        resource = request.resource_logs.add()
        for index in range(attributes):
            attribute = resource.resource.attributes.add(key=f"key{index:04d}")
            attribute.value.string_value = "v" * 64
        for _ in range(scopes):
            scope = resource.scope_logs.add()
            for _ in range(records):
                scope.log_records.add().body.string_value = "generated-limit"
    return request


def generated_limit_service(tmp_path, workers, limit="16k"):
    config = tmp_path / "generated-limit.yaml"
    limit_option = f"logs_max_size: {limit}" if limit else ""
    config.write_text(f"""
service:
  flush: 0.2
  grace: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
    - name: opentelemetry
      port: ${{FLUENT_BIT_TEST_LISTENER_PORT}}
      http2: on
      http_server.workers: {workers}
      {limit_option}
  outputs:
    - name: opentelemetry
      match: '*'
      host: 127.0.0.1
      port: ${{TEST_SUITE_HTTP_PORT}}
""", encoding="utf-8")
    return Service(str(config))


@pytest.mark.parametrize("workers", [1, pytest.param(
    2, marks=pytest.mark.skipif(os.name == "nt",
                               reason="HTTP shared listener ports are unavailable on Windows"))])
@pytest.mark.parametrize("encoding", ["json", "protobuf"])
@pytest.mark.parametrize("attributes,scopes,records,resources,accepted", [
    (1, 32, 1, 1, True),
    (64, 1, 1, 1, True),
    (64, 32, 1, 1, False),
    (32, 64, 1, 1, False),
    (64, 2, 1, 2, False),
    (1, 1, 512, 1, False),
    # scopes without records produce nothing, the request is accepted
    (64, 1000, 0, 1, True),
])
def test_in_opentelemetry_generated_limit(tmp_path, workers, encoding, attributes,
                                         scopes, records, resources, accepted):
    service = generated_limit_service(tmp_path, workers)
    request = generated_limit_payload(attributes, scopes, records, resources)
    if encoding == "json":
        payload = json_format.MessageToJson(request).encode()
        content_type = "application/json"
    else:
        payload = request.SerializeToString()
        content_type = "application/x-protobuf"
    # All requests fit the wire limit; rejection must be due to generated bytes.
    assert len(payload) < 4_000_000
    try:
        service.start()
        response = service.send_raw_request("/v1/logs", payload, content_type)
        assert response.status_code == (201 if accepted else 400)
        # Exercise cleanup and ensure a rejected request never appends its prefix.
        small = generated_limit_payload(1, 1)
        small.resource_logs[0].scope_logs[0].log_records[0].body.string_value = "recovery"
        response = service.send_raw_request("/v1/logs", small.SerializeToString())
        assert response.status_code == 201

        def received_records():
            return [record for request in data_storage["logs"]
                    for resource in request.resource_logs
                    for scope in resource.scope_logs for record in scope.log_records]

        expected = scopes * records * resources if accepted else 0
        service.service.wait_for_condition(
            lambda: len(received_records()) >= expected + 1,
            timeout=20, interval=0.1, description="recovery after generated byte limit")
        actual = received_records()
        assert len(actual) == expected + 1
        assert sum(record.body.string_value == "recovery" for record in actual) == 1
        assert sum(record.body.string_value == "generated-limit" for record in actual) == expected
    finally:
        service.stop()


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
@pytest.mark.parametrize("attributes,scopes,expected_status", [
    (64, 1000, 201),
    (512, 3000, 400),
])
def test_in_opentelemetry_generated_limit_default(tmp_path, encoding, attributes,
                                                 scopes, expected_status):
    service = generated_limit_service(tmp_path, 1, limit=None)
    request = generated_limit_payload(attributes, scopes)
    if encoding == "json":
        payload = json_format.MessageToJson(request).encode()
        content_type = "application/json"
    else:
        payload = request.SerializeToString()
        content_type = "application/x-protobuf"
    assert len(payload) < 4_000_000
    # Count only repeated key/value bytes: MessagePack headers add more bytes.
    generated_lower_bound = attributes * scopes * (len("key0000") + 64)
    assert generated_lower_bound > 4_000_000
    if expected_status == 400:
        assert generated_lower_bound > 100_000_000
    try:
        service.start()
        # Expanding over 100 MB of generated data needs more time under Valgrind.
        assert service.send_raw_request("/v1/logs", payload, content_type,
                                        timeout=60).status_code == expected_status
        # Large conversion buffers must be cleaned up without poisoning later requests.
        small = generated_limit_payload(1, 1).SerializeToString()
        assert service.send_raw_request("/v1/logs", small).status_code == 201
    finally:
        service.stop()


@pytest.mark.parametrize("limit", ["invalid", "-1", "-2M", "0"])
def test_in_opentelemetry_generated_limit_invalid_config(tmp_path, limit):
    service = generated_limit_service(tmp_path, 1, limit=limit)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        with open(service.service.flb.log_file, encoding="utf-8", errors="replace") as log:
            assert "logs_max_size must be a valid positive size" in log.read()
    finally:
        service.stop()


def test_in_opentelemetry_generated_limit_grpc_request_budget(tmp_path):
    service = generated_limit_service(tmp_path, 1)
    payload = generated_limit_payload(64, 2).SerializeToString()
    endpoint = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"
    try:
        service.start()
        with grpc.insecure_channel(f"127.0.0.1:{service.flb_listener_port}") as channel:
            export = channel.stream_unary(endpoint)
            # Each message fits alone; two exceed the shared HTTP request budget.
            export(iter([payload]), timeout=10)
            with pytest.raises(grpc.RpcError) as rejected:
                export(iter([payload, payload]), timeout=10)
            assert rejected.value.code() == grpc.StatusCode.UNKNOWN
            export(iter([payload]), timeout=10)
    finally:
        service.stop()


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

    def send_raw_request(self, endpoint, payload, content_type='application/x-protobuf', *, timeout=5):
        url = f'http://localhost:{self.flb_listener_port}{endpoint}'
        headers = {'Content-Type': content_type}
        return requests.post(url, data=payload, headers=headers, timeout=timeout)

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

    def scrape_prometheus_metrics(self):
        url = f"http://127.0.0.1:{self.flb.http_monitoring_port}/api/v2/metrics/prometheus"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.text

    def wait_for_prometheus_metric(self, metric_name, timeout=10, interval=0.25):
        return self.service.wait_for_condition(
            lambda: (
                metrics if metric_name in metrics else None
            ) if (metrics := self.scrape_prometheus_metrics()) else None,
            timeout=timeout,
            interval=interval,
            description=f"prometheus metric {metric_name}",
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


def test_in_opentelemetry_protobuf_log_body_int64():
    service = Service("001-fluent-bit.yaml")
    payload = ExportLogsServiceRequest()
    scope = payload.resource_logs.add().scope_logs.add()
    expected = [-(2**63), -(2**31) - 1, 2**31, 2**53 + 1, 2**63 - 1]
    for value in expected:
        scope.log_records.add(time_unix_nano=1789516800123456789).body.int_value = value

    service.start()
    try:
        before = len(data_storage["logs"])
        response = service.send_raw_request("/v1/logs", payload.SerializeToString())
        assert response.status_code == 201

        def received():
            values = [record.body.int_value
                      for request in data_storage["logs"][before:]
                      for resource in request.resource_logs
                      for scope in resource.scope_logs
                      for record in scope.log_records]
            return values if len(values) >= len(expected) else None

        actual = service.service.wait_for_condition(received, timeout=20, interval=0.25,
                                                    description="64-bit log body values")
        assert actual == expected
    finally:
        service.stop()


def test_in_opentelemetry_large_protobuf_logs():
    service = Service("001-fluent-bit.yaml")
    source = ExportLogsServiceRequest()
    source.ParseFromString(service.build_otel_payload("test_logs_001.in.json", "logs"))

    payload = ExportLogsServiceRequest()
    payload.CopyFrom(source)
    source_records = list(source.resource_logs[0].scope_logs[0].log_records)

    while payload.ByteSize() < 128 * 1024:
        payload.resource_logs[0].scope_logs[0].log_records.extend(source_records)

    expected_record_count = sum(
        len(scope_logs.log_records)
        for resource_logs in payload.resource_logs
        for scope_logs in resource_logs.scope_logs
    )

    service.start()
    try:
        logs_before = len(data_storage["logs"])
        response = service.send_raw_request("/v1/logs", payload.SerializeToString())

        assert response.status_code == 201
        received_record_count = service.service.wait_for_condition(
            lambda: count if (
                count := sum(
                    len(scope_logs.log_records)
                    for received in data_storage["logs"][logs_before:]
                    for resource_logs in received.resource_logs
                    for scope_logs in resource_logs.scope_logs
                )
            ) >= expected_record_count else None,
            timeout=20,
            interval=0.25,
            description="all large protobuf log records",
        )
    finally:
        service.stop()

    assert received_record_count == expected_record_count


def test_in_opentelemetry_batched_protobuf_logs_with_workers():
    service = Service(IN_OPENTELEMETRY_WORKER_PROTOCOL_CONFIGS["http1_cleartext"])
    source = ExportLogsServiceRequest()
    source.ParseFromString(service.build_otel_payload("test_logs_001.in.json", "logs"))

    payload = ExportLogsServiceRequest()
    payload.CopyFrom(source)
    source_records = list(source.resource_logs[0].scope_logs[0].log_records)

    while payload.ByteSize() < 16 * 1024:
        payload.resource_logs[0].scope_logs[0].log_records.extend(source_records)

    assert payload.ByteSize() < 64 * 1024

    expected_record_count = sum(
        len(scope_logs.log_records)
        for resource_logs in payload.resource_logs
        for scope_logs in resource_logs.scope_logs
    )

    service.start()
    try:
        service.wait_for_log_message("with 4 workers", timeout=10)
        logs_before = len(data_storage["logs"])
        response = service.send_raw_request("/v1/logs", payload.SerializeToString())

        assert response.status_code == 201
        received_record_count = service.service.wait_for_condition(
            lambda: count if (
                count := sum(
                    len(scope_logs.log_records)
                    for received in data_storage["logs"][logs_before:]
                    for resource_logs in received.resource_logs
                    for scope_logs in resource_logs.scope_logs
                )
            ) >= expected_record_count else None,
            timeout=20,
            interval=0.25,
            description="all batched protobuf log records",
        )

        metrics_text = service.service.wait_for_condition(
            lambda: (
                metrics if maybe_read_prometheus_metric_value(
                    metrics,
                    "fluentbit_input_records_total",
                    "opentelemetry.0",
                ) is not None and maybe_read_prometheus_metric_value(
                    metrics,
                    "fluentbit_input_records_total",
                    "opentelemetry.0",
                ) >= expected_record_count else None
            ) if (metrics := service.scrape_prometheus_metrics()) else None,
            timeout=10,
            interval=0.25,
            description="protobuf input record accounting",
        )
    finally:
        service.stop()

    assert received_record_count == expected_record_count
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_records_total",
        "opentelemetry.0",
    ) == expected_record_count


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
    try:
        small_response = service.send_raw_request("/v1/logs", b"not-a-valid-otlp-payload")
        large_response = service.send_raw_request("/v1/logs", b"\x80" * (64 * 1024))
    finally:
        service.stop()

    assert small_response.status_code >= 400
    assert large_response.status_code >= 400
    assert len(data_storage["logs"]) == 0


@pytest.mark.parametrize(
    ("body", "expected_status", "expected_body"),
    [
        pytest.param(
            {"arrayValue": {"values": "not-an-array"}},
            400,
            None,
            id="array-value",
        ),
        pytest.param(
            {"arrayValue": {"value": []}},
            400,
            None,
            id="array-value-invalid-values-key",
        ),
        pytest.param(
            {"kvlistValue": {"values": "not-a-kvlist"}},
            400,
            None,
            id="kvlist-value",
        ),
        pytest.param(
            {"kvlistValue": {}},
            201,
            {"kvlistValue": {"values": []}},
            id="map-form-kvlist-value",
        ),
        pytest.param(
            {"arrayValue": {}},
            201,
            {"arrayValue": {"values": []}},
            id="empty-array-value",
        ),
    ],
)
def test_in_opentelemetry_handles_json_logs_with_invalid_any_value_container(
    body, expected_status, expected_body
):
    payload = {
        "resourceLogs": [
            {
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "body": body,
                            }
                        ],
                    }
                ],
            }
        ],
    }

    service = Service("003-stdout-otlp-json.yaml")
    service.start()

    try:
        response = service.send_raw_request(
            "/v1/logs",
            json.dumps(payload).encode("utf-8"),
            content_type="application/json",
        )

        assert response.status_code == expected_status
        assert service.flb.process is not None
        assert service.flb.process.poll() is None

        if expected_body is None:
            with pytest.raises(TimeoutError):
                read_stdout_otlp_json(service, "resourceLogs", timeout=2)
        else:
            output = read_stdout_otlp_json(service, "resourceLogs")
            records = list(iter_log_records(output))

            assert len(records) == 1
            assert records[0]["record"]["body"] == expected_body
    finally:
        service.stop()


def test_in_opentelemetry_rejects_invalid_metrics_payload():
    service = Service("001-fluent-bit.yaml")
    service.start()
    response = service.send_raw_request("/v1/metrics", b"not-a-valid-otlp-payload")
    service.stop()

    assert response.status_code >= 400
    assert len(data_storage["metrics"]) == 0


def test_in_opentelemetry_rejects_json_histogram_with_descending_bounds():
    service = Service("001-fluent-bit.yaml")
    service.start()

    try:
        response = service.send_raw_request(
            "/v1/metrics",
            build_histogram_json_payload([2, 1]),
            content_type="application/json",
        )

        assert response.status_code == 400
        assert service.flb.process is not None
        assert service.flb.process.poll() is None
        assert len(data_storage["metrics"]) == 0

        response = service.send_raw_request(
            "/v1/metrics",
            build_histogram_json_payload([1, 1]),
            content_type="application/json",
        )

        assert response.status_code == 400
        assert service.flb.process is not None
        assert service.flb.process.poll() is None
        assert len(data_storage["metrics"]) == 0

        response = service.send_raw_request(
            "/v1/metrics",
            build_histogram_json_payload([1, 2], name=""),
            content_type="application/json",
        )

        assert response.status_code == 400
        assert service.flb.process is not None
        assert service.flb.process.poll() is None
        assert len(data_storage["metrics"]) == 0

        response = service.send_raw_request(
            "/v1/metrics",
            build_histogram_json_payload([1, 2]),
            content_type="application/json",
        )
        assert 200 <= response.status_code < 300

        output = service.read_response("metrics")
    finally:
        service.stop()

    metrics = {item["metric"]["name"]: item for item in iter_metric_entries(output)}
    histogram = metrics["histogram_bounds"]["metric"]["histogram"]
    histogram_datapoint = histogram["dataPoints"][0]

    assert histogram_datapoint["count"] == "3"
    assert histogram_datapoint["sum"] == 3.0
    assert histogram_datapoint["bucketCounts"] == ["1", "1", "1"]
    assert histogram_datapoint["explicitBounds"] == [1.0, 2.0]


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


def test_in_opentelemetry_stdout_otlp_json_logs_preserve_resources_across_requests():
    service = Service("stdout-otlp-json-slow-flush.yaml")
    service.start()

    response = service.send_raw_request(
        "/v1/logs",
        build_resource_collision_logs_payload("user-a", "event-a"),
    )
    assert 200 <= response.status_code < 300

    response = service.send_raw_request(
        "/v1/logs",
        build_resource_collision_logs_payload("user-b", "event-b"),
    )
    assert 200 <= response.status_code < 300

    # The requests may land on opposite sides of a flush boundary.
    output = read_stdout_otlp_json(service, "resourceLogs", timeout=10, min_entries=2)
    service.stop()

    records = list(iter_log_records(output))
    body_to_user = {
        record["body"]: record["resource_attributes"]["user.id"]
        for record in records
    }

    assert body_to_user["event-a"] == "user-a"
    assert body_to_user["event-b"] == "user-b"
    assert len(output["resourceLogs"]) == 2


@pytest.mark.parametrize(
    "content_type,payload_builder",
    [
        ("application/x-protobuf", build_resource_collision_logs_payload),
        ("application/json", build_resource_collision_logs_json_payload),
    ],
)
def test_in_opentelemetry_stdout_otlp_json_logs_preserve_resource_schema_urls(
    content_type,
    payload_builder,
):
    service = Service("stdout-otlp-json-slow-flush.yaml")
    service.start()

    response = service.send_raw_request(
        "/v1/logs",
        payload_builder("same-user", "event-a", "schema-a"),
        content_type=content_type,
    )
    assert 200 <= response.status_code < 300

    response = service.send_raw_request(
        "/v1/logs",
        payload_builder("same-user", "event-b", "schema-b"),
        content_type=content_type,
    )
    assert 200 <= response.status_code < 300

    output = read_stdout_otlp_json(service, "resourceLogs", timeout=10, min_entries=2)
    service.stop()

    body_to_schema_url = {
        record["body"]["stringValue"]: resource_log["schemaUrl"]
        for resource_log in output["resourceLogs"]
        for scope_log in resource_log["scopeLogs"]
        for record in scope_log["logRecords"]
    }

    assert body_to_schema_url["event-a"] == "schema-a"
    assert body_to_schema_url["event-b"] == "schema-b"
    assert len(output["resourceLogs"]) == 2


@pytest.mark.parametrize(
    "content_type,payload_builder",
    [
        ("application/x-protobuf", build_scope_schema_logs_payload),
        ("application/json", build_scope_schema_logs_json_payload),
    ],
)
def test_in_opentelemetry_stdout_otlp_json_logs_preserve_scope_schema_urls(
    content_type,
    payload_builder,
):
    service = Service("stdout-otlp-json-slow-flush.yaml")
    service.start()
    try:
        response = service.send_raw_request(
            "/v1/logs",
            payload_builder(),
            content_type=content_type,
        )
        assert 200 <= response.status_code < 300

        output = read_stdout_otlp_json(service, "resourceLogs", timeout=10)
    finally:
        service.stop()

    assert len(output["resourceLogs"]) == 1
    scope_by_body = {
        record["body"]["stringValue"]: scope_log
        for resource_log in output["resourceLogs"]
        for scope_log in resource_log["scopeLogs"]
        for record in scope_log["logRecords"]
    }

    assert scope_by_body["event-a"]["schemaUrl"] == "scope-schema-a"
    assert "schemaUrl" not in scope_by_body["event-b"]


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


@pytest.mark.parametrize("config_file", [
    "003-stdout-otlp-json.yaml", "004-stdout-otlp-json-pretty.yaml",
])
@pytest.mark.parametrize("encoding", ["json", "protobuf", "legacy", "canonical"])
def test_in_opentelemetry_trace_status_codes(config_file, encoding):
    service = Service(config_file)
    service.start()
    codes = [0, 1, 2]
    if encoding in ("json", "protobuf"):
        codes += [-2147483648, -1, 3, 2147483647]
    spans = []
    for index, code in enumerate(codes):
        wire_code = code
        if encoding == "legacy":
            wire_code = ["UNSET", "OK", "ERROR"][code]
        elif encoding == "canonical":
            wire_code = ["STATUS_CODE_UNSET", "STATUS_CODE_OK", "STATUS_CODE_ERROR"][code]
        spans.append({
            "traceId": "0123456789abcdef0123456789abcdef",
            "spanId": f"{index + 1:016x}",
            "name": f"status-{code}",
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000000000001",
            "status": {"code": wire_code, "message": f"message-{code}"},
        })
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
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
    response = service.send_raw_request("/v1/traces", body, content_type)
    assert 200 <= response.status_code < 300, response.text
    output = read_stdout_otlp_json(service, "resourceSpans")
    service.stop()
    received = {entry["span"]["name"]: entry["span"] for entry in iter_spans(output)}
    assert len(received) == len(codes)
    for code in codes:
        status = received[f"status-{code}"]["status"]
        assert type(status["code"]) is int
        assert status["code"] == code
        assert status["message"] == f"message-{code}"


def test_in_opentelemetry_trace_status_invalid_codes():
    service = Service("003-stdout-otlp-json.yaml")
    service.start()
    for code in [True, 1.5, [], {}, "INVALID", 2147483648, -2147483649]:
        payload = {"resourceSpans": [{"scopeSpans": [{"spans": [{
            "name": "invalid-status", "status": {"code": code},
        }]}]}]}
        response = service.send_raw_request(
            "/v1/traces", json.dumps(payload).encode(), "application/json")
        assert response.status_code == 400, (code, response.text)
    service.stop()


@pytest.mark.parametrize("status", [
    True, 1, "ERROR", [],
    {"code": 2, "message": True},
    {"code": 2, "message": 1},
    {"code": 2, "message": []},
    {"code": 2, "message": {}},
])
def test_in_opentelemetry_trace_status_invalid_fields_recovery(status):
    service = Service("003-stdout-otlp-json.yaml")
    service.start()
    spans = [
        {"name": "before-invalid", "status": {"code": 2, "message": "valid"}},
        {"name": "invalid-status", "status": status},
    ]
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
    response = service.send_raw_request(
        "/v1/traces", json.dumps(payload).encode(), "application/json")
    assert response.status_code == 400, response.text

    spans = [{"name": "recovered", "status": {"code": 2, "message": "error details"}}]
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
    response = service.send_raw_request(
        "/v1/traces", json.dumps(payload).encode(), "application/json")
    assert 200 <= response.status_code < 300, response.text
    output = read_stdout_otlp_json(service, "resourceSpans")
    log_file = service.flb.log_file
    service.stop()
    received = [entry["span"] for entry in iter_spans(output)]
    assert [span["name"] for span in received] == ["recovered"]
    assert received[0]["status"] == {"code": 2, "message": "error details"}
    with open(log_file, encoding="utf-8") as stream:
        emitted = stream.read()
    assert "before-invalid" not in emitted
    assert "invalid-status" not in emitted


def test_in_opentelemetry_trace_status_default_code():
    service = Service("003-stdout-otlp-json.yaml")
    service.start()
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": [
        {"name": "empty-status", "status": {}},
        {"name": "message-only", "status": {"message": "unset"}},
        {"name": "absent-status"},
        {"name": "null-status", "status": None},
        {"name": "null-message", "status": {"code": 2, "message": None}},
        {"name": "null-code", "status": {"code": None, "message": "unset"}},
    ]}]}]}
    response = service.send_raw_request(
        "/v1/traces", json.dumps(payload).encode(), "application/json")
    assert 200 <= response.status_code < 300, response.text
    output = read_stdout_otlp_json(service, "resourceSpans")
    service.stop()
    received = {entry["span"]["name"]: entry["span"] for entry in iter_spans(output)}
    assert len(received) == 6
    assert received["message-only"]["status"] == {"code": 0, "message": "unset"}
    assert received["null-message"]["status"] == {"code": 2}
    assert received["null-code"]["status"] == {"code": 0, "message": "unset"}
    for name in ["empty-status", "absent-status", "null-status"]:
        assert received[name].get("status", {}).get("code", 0) == 0


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


@pytest.mark.parametrize("field", ["kid", "alg"])
@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[case["id"] for case in PROTOCOL_CASES])
def test_in_opentelemetry_oauth2_rejects_duplicate_header(monkeypatch, case, field):
    jwks_requests = track_jwks_requests(monkeypatch)
    token = duplicate_header_token(MOCK_VALID_JWT, field)
    service = Service(
        IN_OPENTELEMETRY_OAUTH2_PROTOCOL_CONFIGS[case["config_key"]],
        use_auth_server=True,
    )
    service.start()
    try:
        scheme = "https" if case["use_tls"] else "http"
        payload = service.build_otel_payload("test_logs_001.in.json", "logs")
        for _ in range(8):
            result = run_curl_request(
                f"{scheme}://localhost:{service.flb_listener_port}/v1/logs",
                payload,
                headers=["Content-Type: application/x-protobuf", f"Authorization: Bearer {token}"],
                http_mode=case["http_mode"],
                ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
            )
            assert result["status_code"] == 401
        assert jwks_requests == []
        assert data_storage["logs"] == []

        result = run_curl_request(
            f"{scheme}://localhost:{service.flb_listener_port}/v1/logs",
            payload,
            headers=["Content-Type: application/x-protobuf", f"Authorization: Bearer {MOCK_VALID_JWT}"],
            http_mode=case["http_mode"],
            ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
        )
        assert result["status_code"] == 201
        assert service.read_response("logs")["resourceLogs"]
    finally:
        service.stop()


@pytest.mark.parametrize("field", ["kid", "alg"])
@pytest.mark.parametrize(
    "case", IN_OPENTELEMETRY_GRPC_OAUTH2_CASES,
    ids=[case["id"] for case in IN_OPENTELEMETRY_GRPC_OAUTH2_CASES],
)
def test_in_opentelemetry_grpc_oauth2_rejects_duplicate_header(monkeypatch, case, field):
    jwks_requests = track_jwks_requests(monkeypatch)
    token = duplicate_header_token(MOCK_VALID_JWT, field)
    service = Service(case["config_file"], use_auth_server=True)
    service.start()
    try:
        payload = json_format.Parse(
            json.dumps(read_json_file(os.path.join(
                os.path.dirname(__file__), "data_files/test_logs_001.in.json"
            ))),
            ExportLogsServiceRequest(),
        )
        for _ in range(8):
            with pytest.raises(grpc.RpcError) as exc_info:
                service.send_grpc_request(
                    "logs", payload, authorization=f"Bearer {token}", use_tls=case["use_tls"],
                )
            assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED
        assert jwks_requests == []
        assert data_storage["logs"] == []

        service.send_grpc_request(
            "logs", payload, authorization=f"Bearer {MOCK_VALID_JWT}", use_tls=case["use_tls"],
        )
        assert service.read_response("logs")["resourceLogs"]
    finally:
        service.stop()


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


def test_in_opentelemetry_http2_invalid_endpoint_returns_404():
    service = Service(IN_OPENTELEMETRY_PROTOCOL_CONFIGS["http2_cleartext"])
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/v1/invalid",
        b"invalid payload",
        headers=["Content-Type: application/x-protobuf"],
        http_mode="http2-prior-knowledge",
    )

    service.stop()

    assert result["status_code"] == 404
    assert result["http_version"] == "2"
    assert result["body"] == "error: invalid endpoint\n"
    assert len(data_storage["logs"]) == 0
    assert len(data_storage["metrics"]) == 0
    assert len(data_storage["traces"]) == 0


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
    worker_count = 4
    repeats_per_signal = 4
    total_requests = len(request_plan) * repeats_per_signal

    service = Service(IN_OPENTELEMETRY_WORKER_PROTOCOL_CONFIGS[case["config_key"]])
    service.start()
    service.wait_for_log_message(f"with {worker_count} workers", timeout=10)

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

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
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


@pytest.mark.parametrize(
    "config_file,signal_type,json_input,endpoint",
    [
        (config_file, signal_type, json_input, endpoint)
        for config_file in [
            "otlp_pause_resume_single.yaml",
            "otlp_pause_resume_workers.yaml",
        ]
        for signal_type, json_input, endpoint in [
            ("logs", "test_logs_001.in.json", "/v1/logs"),
            ("metrics", "test_metrics_001.in.json", "/v1/metrics"),
            ("traces", "test_traces_001.in.json", "/v1/traces"),
        ]
    ],
    ids=[
        f"{'single_listener' if 'single' in config_file else 'workers_4'}-{signal_type}"
        for config_file in [
            "otlp_pause_resume_single.yaml",
            "otlp_pause_resume_workers.yaml",
        ]
        for signal_type in ["logs", "metrics", "traces"]
    ],
)
def test_in_opentelemetry_pause_resume(config_file, signal_type, json_input, endpoint):
    service = Service(config_file)

    try:
        service.start()
        resume_payload = service.build_otel_payload(json_input, signal_type)

        def open_active_connections():
            return [
                open_stalled_tcp_connection(
                    "127.0.0.1",
                    service.flb_listener_port,
                )
                for _ in range(8)
            ]

        assert_pause_resume_cycles(
            service.flb,
            f"http://localhost:{service.flb_listener_port}{endpoint}",
            resume_payload,
            ["Content-Type: application/x-protobuf"],
            input_name="opentelemetry.0",
            success_status=201,
            cycles=2,
            http_mode="http2-prior-knowledge",
            pause_trigger_requests=64,
            resume_payload=resume_payload,
            active_connection_factory=open_active_connections,
        )
    finally:
        service.stop()


@pytest.mark.parametrize(
    "config_file",
    ["otlp_pause_resume_single.yaml", "otlp_pause_resume_workers.yaml"],
    ids=["single_listener", "workers_4"],
)
def test_in_opentelemetry_shutdown_while_paused(config_file):
    service = Service(config_file)

    try:
        service.start()
        payload = service.build_otel_payload("test_logs_001.in.json", "logs")
        assert_shutdown_while_paused(
            service.flb,
            service.stop,
            "127.0.0.1",
            service.flb_listener_port,
            f"http://localhost:{service.flb_listener_port}/v1/logs",
            payload,
            ["Content-Type: application/x-protobuf"],
            input_name="opentelemetry.0",
            success_status=201,
            connection_factory=open_stalled_tcp_connection,
            pause_trigger_requests=64,
            http_mode="http2-prior-knowledge",
        )
    finally:
        service.stop()


def test_in_opentelemetry_http_workers_export_ingress_queue_metrics():
    service = Service(IN_OPENTELEMETRY_WORKER_PROTOCOL_CONFIGS["http1_cleartext"])
    service.start()
    service.wait_for_log_message("with 4 workers", timeout=10)

    response = service.send_raw_request(
        "/v1/logs",
        service.build_otel_payload("test_logs_001.in.json", "logs"),
    )
    assert response.status_code == 201

    service.wait_for_signal_count("logs", 1, timeout=10)

    metrics_text = service.service.wait_for_condition(
        lambda: (
            metrics
            if "fluentbit_input_http_server_ingress_queue_pending_events" in metrics
            else None
        ) if (metrics := service.scrape_prometheus_metrics()) else None,
        timeout=10,
        interval=0.25,
        description="prometheus ingress queue metrics",
    )

    service.stop()

    assert "fluentbit_input_http_server_ingress_queue_pending_events" in metrics_text
    assert "fluentbit_input_http_server_ingress_queue_pending_bytes" in metrics_text
    assert "fluentbit_input_http_server_ingress_queue_busy_total" in metrics_text

    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_pending_events",
        "opentelemetry.0",
    ) == 0
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_pending_bytes",
        "opentelemetry.0",
    ) == 0
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_busy_total",
        "opentelemetry.0",
    ) == 0


def test_in_opentelemetry_http_workers_respect_tiny_ingress_queue_limits():
    service = Service(IN_OPENTELEMETRY_TINY_INGRESS_QUEUE_CONFIG)
    service.start()
    service.wait_for_log_message("with 4 workers", timeout=10)
    logs_before = len(data_storage["logs"])

    response = service.send_raw_request(
        "/v1/logs",
        service.build_otel_payload("test_logs_001.in.json", "logs"),
    )

    metrics_text = service.service.wait_for_condition(
        lambda: (
            metrics if maybe_read_prometheus_metric_value(
                metrics,
                "fluentbit_input_http_server_ingress_queue_busy_total",
                "opentelemetry.0",
            ) is not None and maybe_read_prometheus_metric_value(
                metrics,
                "fluentbit_input_http_server_ingress_queue_busy_total",
                "opentelemetry.0",
            ) >= 1 else None
        ) if (metrics := service.scrape_prometheus_metrics()) else None,
        timeout=10,
        interval=0.25,
        description="ingress queue busy metric",
    )

    service.stop()

    assert response.status_code == 503
    assert "deferred ingress queue is full" in response.text
    assert len(data_storage["logs"]) == logs_before
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_busy_total",
        "opentelemetry.0",
    ) >= 1
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_pending_events",
        "opentelemetry.0",
    ) == 0
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_pending_bytes",
        "opentelemetry.0",
    ) == 0


@pytest.mark.parametrize(
    "config_file",
    [
        IN_OPENTELEMETRY_TINY_INGRESS_QUEUE_BYTE_LIMIT_CONFIG,
        IN_OPENTELEMETRY_TINY_INGRESS_QUEUE_BYTE_LIMIT_PROCESSORS_CONFIG,
    ],
    ids=["no_processors", "worker_processors"],
)
def test_in_opentelemetry_http_workers_respect_ingress_queue_byte_limit(config_file):
    service = Service(config_file)
    small_payload = service.build_otel_payload("test_logs_001.in.json", "logs")

    small_request = ExportLogsServiceRequest()
    small_request.ParseFromString(small_payload)

    large_request = ExportLogsServiceRequest()
    large_request.resource_logs.extend(small_request.resource_logs)
    large_request.resource_logs.extend(small_request.resource_logs)

    large_payload = large_request.SerializeToString()
    large_json_payload = json_format.MessageToJson(large_request).encode()

    assert len(small_payload) < len(large_payload)

    service.start()
    service.wait_for_log_message("with 4 workers", timeout=10)

    logs_before = len(data_storage["logs"])

    success_response = service.send_raw_request("/v1/logs", small_payload)
    assert success_response.status_code == 201

    service.wait_for_signal_count("logs", logs_before + 1, timeout=10)

    failure_response = service.send_raw_request("/v1/logs", large_payload)
    assert failure_response.status_code == 503
    assert "deferred ingress queue is full" in failure_response.text

    failure_response = service.send_raw_request(
        "/v1/logs", large_json_payload, content_type="application/json"
    )
    assert failure_response.status_code == 503
    assert "deferred ingress queue is full" in failure_response.text

    metrics_text = service.service.wait_for_condition(
        lambda: (
            metrics if maybe_read_prometheus_metric_value(
                metrics,
                "fluentbit_input_http_server_ingress_queue_busy_total",
                "opentelemetry.0",
            ) is not None and maybe_read_prometheus_metric_value(
                metrics,
                "fluentbit_input_http_server_ingress_queue_busy_total",
                "opentelemetry.0",
            ) >= 1 else None
        ) if (metrics := service.scrape_prometheus_metrics()) else None,
        timeout=10,
        interval=0.25,
        description="ingress queue byte-limit busy metric",
    )

    service.stop()

    assert len(data_storage["logs"]) == logs_before + 1
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_busy_total",
        "opentelemetry.0",
    ) >= 1
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_pending_events",
        "opentelemetry.0",
    ) == 0
    assert read_prometheus_metric_value(
        metrics_text,
        "fluentbit_input_http_server_ingress_queue_pending_bytes",
        "opentelemetry.0",
    ) == 0


def test_in_opentelemetry_http_workers_account_metrics_payload_bytes():
    service = Service(IN_OPENTELEMETRY_TINY_INGRESS_QUEUE_BYTE_LIMIT_CONFIG)
    small_payload = service.build_otel_payload("test_metrics_001.in.json", "metrics")

    small_request = ExportMetricsServiceRequest()
    small_request.ParseFromString(small_payload)

    large_request = ExportMetricsServiceRequest()
    for _ in range(16):
        large_request.resource_metrics.extend(small_request.resource_metrics)

    large_payload = large_request.SerializeToString()

    assert len(small_payload) < 2000
    assert len(large_payload) > 2000

    service.start()
    service.wait_for_log_message("with 4 workers", timeout=10)
    metrics_before = len(data_storage["metrics"])

    try:
        success_response = service.send_raw_request("/v1/metrics", small_payload)
        assert success_response.status_code == 201
        service.wait_for_signal_count("metrics", metrics_before + 1, timeout=10)

        failure_response = service.send_raw_request("/v1/metrics", large_payload)
        assert failure_response.status_code == 503
        assert "deferred ingress queue is full" in failure_response.text
    finally:
        service.stop()

    assert len(data_storage["metrics"]) == metrics_before + 1


def test_expect_warn_validates_each_otlp_log_record_in_batch():
    service = Service("expect_batch.yaml")
    payload = read_json_file(
        os.path.join(
            os.path.dirname(__file__),
            "data_files",
            "test_logs_expect_batch.in.json",
        )
    )

    service.start()

    try:
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",
            json=payload,
            timeout=5,
        )
        assert response.status_code == 201

        log_text = service.service.wait_for_condition(
            lambda: (
                content
                if content.count("expect check failed") >= 4
                else None
            ) if (content := read_fluent_bit_log(service)) else None,
            timeout=10,
            interval=0.25,
            description="one expect warning per invalid OTLP log record",
        )
    finally:
        service.stop()

    assert log_text.count("expect check failed") == 4
    for field_name in ("field1", "field2", "field3", "field4"):
        assert log_text.count(f"key '{field_name}' not found") == 1


def test_expect_result_key_preserves_otlp_log_groups():
    service = Service("expect_group_result_key.yaml")
    payload = read_json_file(
        os.path.join(
            os.path.dirname(__file__),
            "data_files",
            "test_logs_expect_batch.in.json",
        )
    )
    scope_logs = payload["resourceLogs"][0]["scopeLogs"][0]
    scope_logs["scope"] = {"name": "issue.scope"}
    scope_logs["logRecords"].append(
        {
            "timeUnixNano": "1784797967000450100",
            "body": {
                "kvlistValue": {
                    "values": [
                        {
                            "key": f"field{index}",
                            "value": {"stringValue": str(index)},
                        }
                        for index in range(1, 5)
                    ]
                }
            },
        }
    )

    service.start()

    try:
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",
            json=payload,
            timeout=5,
        )
        assert response.status_code == 201
        output = service.read_response("logs")
    finally:
        service.stop()

    records = list(iter_log_records(output))
    assert len(records) == 5

    matched_values = []
    for record in records:
        assert record["resource_attributes"] == {"service.name": "my-service"}
        assert record["scope_name"] == "issue.scope"

        values = record["record"]["body"]["kvlistValue"]["values"]
        fields = {
            item["key"]: next(iter(item["value"].values()))
            for item in values
        }
        matched_values.append(fields["matched"])

    assert matched_values == [False, False, False, False, True]


def grpc_limit_payload(service, size, signal_type="logs"):
    """Pad a valid export using an unknown length-delimited protobuf field."""
    payload = service.build_otel_payload(f"test_{signal_type}_001.in.json", signal_type)
    padding_size = size - len(payload) - 6
    # Field 127, with a four-byte varint length (legal even for small lengths).
    length = bytes([
        (padding_size & 0x7f) | 0x80,
        ((padding_size >> 7) & 0x7f) | 0x80,
        ((padding_size >> 14) & 0x7f) | 0x80,
        padding_size >> 21,
    ])
    result = payload + b"\xfa\x07" + length + b"x" * padding_size
    assert len(result) == size
    return result


def send_grpc_limit_frames(service, frames, signal_type="logs", encoding="gzip", suffix=b""):
    body = b""
    for payload, compressed in frames:
        encoded = encode_grpc_limit_payload(payload, encoding) if compressed else payload
        body += bytes([int(compressed)]) + len(encoded).to_bytes(4, "big") + encoded
    service_name = {"logs": "Logs", "metrics": "Metrics", "traces": "Trace"}[signal_type]
    package = "trace" if signal_type == "traces" else signal_type
    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/opentelemetry.proto.collector."
        f"{package}.v1.{service_name}Service/Export",
        body + suffix,
        headers=["Content-Type: application/grpc", f"grpc-encoding: {encoding.split('-')[0]}"],
        http_mode="http2-prior-knowledge",
        include_headers=True,
    )
    assert result["status_code"] == 200
    headers = dict(
        line.split(":", 1) for line in result["headers_raw"].lower().splitlines()
        if ":" in line
    )
    return int(headers["grpc-status"].strip())


@pytest.mark.parametrize("size_delta,expected_status", [(-1, 0), (0, 0), (1, 8)])
def test_in_opentelemetry_grpc_expanded_message_limit(size_delta, expected_status):
    service = Service("otlp_grpc_expanded_limit.yaml")
    try:
        service.start()
        payload = grpc_limit_payload(service, 16 * 1024 * 1024 + size_delta)
        assert send_grpc_limit_frames(service, [(payload, True)]) == expected_status
        # A rejected allocation must not poison subsequent requests.
        small = service.build_otel_payload("test_logs_001.in.json", "logs")
        assert send_grpc_limit_frames(service, [(small, True)]) == 0
    finally:
        service.stop()


@pytest.mark.parametrize("signal_type", ["logs", "metrics", "traces"])
@pytest.mark.parametrize("size_delta,expected_status", [(-1, 0), (0, 0), (1, 8)])
def test_in_opentelemetry_grpc_expanded_http_limit(signal_type, size_delta, expected_status):
    # The listener's default 4M limit uses decimal bytes.
    service = Service("otlp_http2_cleartext.yaml")
    try:
        service.start()
        payload = grpc_limit_payload(service, 4_000_000 + size_delta, signal_type)
        assert send_grpc_limit_frames(service, [(payload, True)], signal_type) == expected_status
    finally:
        service.stop()


@pytest.mark.parametrize("first_compressed", [False, True])
@pytest.mark.parametrize("size_delta,expected_status", [(-1, 0), (0, 0), (1, 8)])
def test_in_opentelemetry_grpc_expanded_request_budget(first_compressed, size_delta, expected_status):
    service = Service("otlp_http2_cleartext.yaml")
    try:
        service.start()
        first = grpc_limit_payload(service, 1024)
        second = grpc_limit_payload(service, 4_000_000 - len(first) + size_delta)
        assert send_grpc_limit_frames(
            service, [(first, first_compressed), (second, True)]
        ) == expected_status
        small = service.build_otel_payload("test_logs_001.in.json", "logs")
        assert send_grpc_limit_frames(service, [(small, False)]) == 0
    finally:
        service.stop()



def encode_test_varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def snappy_test_crc32c(payload):
    # Castagnoli CRC for Snappy framed test data; no optional codec dependencies.
    crc = 0xffffffff
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    crc ^= 0xffffffff
    return (((crc >> 15) | (crc << 17)) + 0xa282ead8) & 0xffffffff


def encode_grpc_limit_payload(payload, encoding):
    if encoding == "gzip":
        return gzip.compress(payload)

    prefix = payload.rstrip(b"x")
    repeated = len(payload) - len(prefix)
    if encoding.startswith("zstd"):
        # Single-segment frames carry content size; streaming frames omit it.
        if encoding == "zstd":
            header = b"\x28\xb5\x2f\xfd\xa0" + len(payload).to_bytes(4, "little")
        elif encoding == "zstd-unknown-large-window":
            # No FCS, with an 8 MiB window exceeding the default request budget.
            header = b"\x28\xb5\x2f\xfd\x00\x68"
        else:
            # No FCS, not single-segment; descriptor 0x38 gives a 128 KiB window.
            header = b"\x28\xb5\x2f\xfd\x00\x38"
        blocks = [(0, prefix[offset:offset + 1024], len(prefix[offset:offset + 1024]))
                  for offset in range(0, len(prefix), 1024)]
        while repeated:
            count = min(repeated, 1024)
            blocks.append((1, b"x", count))
            repeated -= count
        result = header
        for index, (kind, data, size) in enumerate(blocks):
            result += ((size << 3) | (kind << 1) | int(index == len(blocks) - 1)).to_bytes(3, "little")
            result += data
        return result

    if encoding in ("snappy-framed", "snappy-mixed"):
        result = b"\xff\x06\x00\x00sNaPpY"
        # Multiple chunks exercise accounting within a single Snappy stream.
        for offset in range(0, len(payload), 2048):
            chunk = payload[offset:offset + 2048]
            uncompressed = encoding == "snappy-mixed" and offset == 0
            encoded = chunk if uncompressed else encode_grpc_limit_payload(chunk, "snappy")
            result += bytes([int(uncompressed)]) + (len(encoded) + 4).to_bytes(3, "little")
            result += snappy_test_crc32c(chunk).to_bytes(4, "little") + encoded
        return result

    assert encoding == "snappy"
    if repeated:
        prefix += b"x"
        repeated -= 1
    literal_length = len(prefix) - 1
    if literal_length < 60:
        literal = bytes([literal_length << 2])
    else:
        byte_count = (literal_length.bit_length() + 7) // 8
        literal = bytes([(59 + byte_count) << 2]) + literal_length.to_bytes(byte_count, "little")
    result = encode_test_varint(len(payload)) + literal + prefix
    while repeated:
        count = min(repeated, 64)
        result += bytes([((count - 1) << 2) | 2, 1, 0])
        repeated -= count
    return result


def received_grpc_log_records():
    return [record for request in data_storage["logs"]
            for resource in request.resource_logs for scope in resource.scope_logs
            for record in scope.log_records]


@pytest.mark.parametrize("encoding", [
    "gzip", "zstd", "zstd-unknown", "zstd-unknown-large-window",
    "snappy", "snappy-framed", "snappy-mixed",
])
@pytest.mark.parametrize("workers", [1, 4])
def test_in_opentelemetry_grpc_bounded_codecs(encoding, workers):
    service = Service("otlp_grpc_bounded.yaml")
    service.service.extra_env["OTLP_TEST_HTTP_WORKERS"] = workers
    try:
        service.start()
        # Check each boundary and cumulative accounting, including an exhausted budget.
        for sizes, expected in [([4095], 0), ([4096], 0), ([4097], 8),
                                ([1024, 3072], 0), ([1024, 3073], 8),
                                ([4096, 1024], 8)]:
            frames = [(grpc_limit_payload(service, size), True) for size in sizes]
            assert send_grpc_limit_frames(service, frames, encoding=encoding) == expected
    finally:
        service.stop()
    # Every fixture has four records. Only the three accepted requests may ingest.
    assert len(received_grpc_log_records()) == 16


@pytest.mark.parametrize("encoding", [
    "gzip", "zstd", "zstd-unknown", "zstd-unknown-large-window",
    "snappy", "snappy-framed", "snappy-mixed",
])
@pytest.mark.parametrize("first_compressed", [False, True])
def test_in_opentelemetry_grpc_rejected_request_is_not_ingested(encoding, first_compressed):
    service = Service("otlp_grpc_bounded.yaml")
    service.service.extra_env["OTLP_TEST_HTTP_WORKERS"] = 4
    try:
        service.start()
        first = grpc_limit_payload(service, 1024)
        second = grpc_limit_payload(service, 3073)
        # Retry the rejected request to detect duplication of its first frame.
        for _ in range(2):
            assert send_grpc_limit_frames(
                service, [(first, first_compressed), (second, True)], encoding=encoding
            ) == 8
        # A malformed later frame must also reject the entire request.
        assert send_grpc_limit_frames(
            service, [(first, True)], encoding=encoding, suffix=b"\x01\x00"
        ) == 3
        # Corrupt compressed data in a later frame must free every staged frame.
        assert send_grpc_limit_frames(
            service, [(first, True)], encoding=encoding, suffix=b"\x01\x00\x00\x00\x01\xff"
        ) == 13
    finally:
        service.stop()
    assert received_grpc_log_records() == []


@pytest.mark.parametrize("encoding,payload", [
    ("gzip", b"\x1f\x8b\x08\x00" + b"\x00" * 10 + (100_000_000).to_bytes(4, "little")),
    ("zstd", b"\x28\xb5\x2f\xfd\xa0" + (100_000_000).to_bytes(4, "little") + b"\x01\x00\x00"),
    ("snappy", b"\xfe\xff\xff\xff\x0f"),
    ("snappy", b"\xff\x06\x00\x00sNaPpY\x00\x09\x00\x00" + b"\x00" * 4 + b"\xfe\xff\xff\xff\x0f"),
])
def test_in_opentelemetry_grpc_rejects_advertised_size_before_decode(encoding, payload):
    service = Service("otlp_grpc_bounded.yaml")
    service.service.extra_env["OTLP_TEST_HTTP_WORKERS"] = 1
    try:
        service.start()
        # These bodies have no valid compressed data. Size rejection (8), rather
        # than decompression failure (13), proves rejection precedes decoding.
        # Supply the already encoded bytes without modifying the codec header.
        result = run_curl_request(
            f"http://localhost:{service.flb_listener_port}/opentelemetry.proto.collector."
            "logs.v1.LogsService/Export",
            b"\x01" + len(payload).to_bytes(4, "big") + payload,
            headers=["Content-Type: application/grpc", f"grpc-encoding: {encoding}"],
            http_mode="http2-prior-knowledge", include_headers=True,
        )
        assert result["status_code"] == 200
        assert "grpc-status: 8" in result["headers_raw"].lower()
    finally:
        service.stop()
    assert received_grpc_log_records() == []


@pytest.mark.parametrize("encoding", [
    "gzip", "zstd", "zstd-unknown", "zstd-unknown-large-window",
    "snappy", "snappy-framed", "snappy-mixed",
])
def test_in_opentelemetry_grpc_preserves_groups_across_chunks(encoding):
    service = Service("otlp_grpc_grouped.yaml")
    frames = []
    expected = []
    for frame_index in range(2):
        request = ExportLogsServiceRequest()
        for resource_index in range(2):
            resource = request.resource_logs.add()
            resource_id = f"frame-{frame_index}-resource-{resource_index}"
            attribute = resource.resource.attributes.add(key="resource.id")
            attribute.value.string_value = resource_id
            resource.schema_url = f"https://example.com/resource/{resource_id}"
            for scope_index in range(2):
                scope = resource.scope_logs.add()
                scope.scope.name = f"scope-{scope_index}"
                scope.scope.version = "1.2.3"
                scope.schema_url = f"https://example.com/scope/{scope_index}"
                scope.scope.attributes.add(key="scope.id").value.int_value = scope_index
                body = f"{resource_id}-scope-{scope_index}:" + "x" * 300_000
                scope.log_records.add(time_unix_nano=1789516800123456789).body.string_value = body
                expected.append((resource_id, resource.schema_url, scope.scope.name,
                                 scope.scope.version, scope.schema_url, scope_index, body))
        payload = request.SerializeToString()
        assert len(payload) > 1024 * 1000
        frames.append((payload, True))
    try:
        service.start()
        assert send_grpc_limit_frames(service, frames, encoding=encoding) == 0
        service.service.wait_for_condition(
            lambda: len(received_grpc_log_records()) == len(expected), timeout=30,
            description="all grouped records from both gRPC frames",
        )
    finally:
        service.stop()
    actual = []
    for received in data_storage["logs"]:
        for resource in received.resource_logs:
            resource_id = next(item.value.string_value for item in resource.resource.attributes
                               if item.key == "resource.id")
            for scope in resource.scope_logs:
                scope_id = next(item.value.int_value for item in scope.scope.attributes
                                if item.key == "scope.id")
                actual.extend((resource_id, resource.schema_url, scope.scope.name,
                               scope.scope.version, scope.schema_url, scope_id, record.body.string_value)
                              for record in scope.log_records)
    assert sorted(actual) == sorted(expected)


@pytest.mark.parametrize("case", PROTOCOL_CASES[:2], ids=[case["id"] for case in PROTOCOL_CASES[:2]])
@pytest.mark.parametrize("encoding", ["snappy", "snappy-framed", "snappy-mixed"])
def test_in_opentelemetry_http_snappy_content_encoding(case, encoding):
    if case["http_mode"] == "http2-prior-knowledge" and not curl_supports_http2():
        pytest.skip("Installed curl lacks HTTP/2 support")
    service = Service(IN_OPENTELEMETRY_PROTOCOL_CONFIGS[case["config_key"]])
    try:
        service.start()
        payload = ExportLogsServiceRequest()
        scope = payload.resource_logs.add().scope_logs.add()
        expected = "snappy HTTP checksum regression " + "x" * 4096
        scope.log_records.add().body.string_value = expected
        encoded = encode_grpc_limit_payload(payload.SerializeToString(), encoding)
        result = run_curl_request(
            f"http://localhost:{service.flb_listener_port}/v1/logs",
            encoded,
            headers=["Content-Type: application/x-protobuf", "Content-Encoding: snappy"],
            http_mode=case["http_mode"],
        )
        assert result["status_code"] == 201
        records = service.service.wait_for_condition(
            received_grpc_log_records, timeout=20, interval=0.25,
            description="Snappy Content-Encoding log delivery",
        )
        assert [record.body.string_value for record in records] == [expected]
    finally:
        service.stop()


@pytest.mark.parametrize("frame_type", [0, 1])
def test_in_opentelemetry_http_snappy_invalid_checksum(frame_type):
    service = Service("otlp_http1_cleartext.yaml")
    try:
        service.start()
        payload = service.build_otel_payload("test_logs_001.in.json", "logs")
        encoded = payload if frame_type else encode_grpc_limit_payload(payload, "snappy")
        checksum = snappy_test_crc32c(payload) ^ 1
        framed = (b"\xff\x06\x00\x00sNaPpY" + bytes([frame_type])
                  + (len(encoded) + 4).to_bytes(3, "little")
                  + checksum.to_bytes(4, "little") + encoded)
        url = f"http://localhost:{service.flb_listener_port}/v1/logs"
        # Invalid compressed bodies must not produce log records.
        for invalid in [framed, framed[:-1],
                        b"\xff\x06\x00\x00sNaPpY\x01\x04\x00\x00\x00\x00\x00\x00"]:
            response = requests.post(url, data=invalid, timeout=5, headers={
                "Content-Type": "application/x-protobuf", "Content-Encoding": "snappy",
            })
            assert response.status_code == 400
        assert not received_grpc_log_records()
        # The listener must remain usable after malformed compressed requests.
        response = service.send_raw_request("/v1/logs", payload)
        assert response.status_code == 201
        service.wait_for_signal_count("logs", 1)
    finally:
        service.stop()


# Processor chains used to compare the msgpack and the direct CFL logs paths.
# The direct path is only taken when the chain starts with a native processor,
# the filter first chain covers the fallback to the msgpack path.
#
# The msgpack reference runs the same chain behind a filter that keeps every
# record: a filter unit makes the input take the established msgpack path.
MSGPACK_REFERENCE_FILTER = {"name": "grep", "exclude": "msgpack_reference ^never$"}

DIRECT_CFL_PROCESSOR_CHAINS = {
    "content_modifier": [
        {"name": "content_modifier", "context": "otel_resource_attributes",
         "action": "upsert", "key": "aaa", "value": "bbb"},
        {"name": "content_modifier", "context": "otel_resource_attributes",
         "action": "delete", "key": "service.name"},
        {"name": "content_modifier", "context": "otel_scope_name",
         "action": "upsert", "value": "new scope name"},
        {"name": "content_modifier", "context": "attributes",
         "action": "upsert", "key": "added", "value": "yes"},
    ],
    "sql_drop": [
        {"name": "sql", "query": "SELECT * FROM STREAM WHERE keep = 'yes';"},
        {"name": "content_modifier", "context": "otel_scope_version",
         "action": "upsert", "value": "3.1.0"},
    ],
    "native_then_filter": [
        {"name": "content_modifier", "context": "otel_scope_attributes",
         "action": "upsert", "key": "scope_new", "value": "123"},
        {"name": "grep", "regex": "keep ^yes$"},
    ],
    "filter_first": [
        {"name": "grep", "regex": "keep ^yes$"},
        {"name": "content_modifier", "context": "otel_resource_attributes",
         "action": "upsert", "key": "aaa", "value": "bbb"},
    ],
    "hash_once": [
        {"name": "content_modifier", "context": "attributes",
         "action": "hash", "key": "marker"},
    ],
    "rename": [
        {"name": "content_modifier", "context": "body",
         "action": "rename", "key": "marker", "value": "renamed_marker"},
    ],
    "hash_then_sql": [
        {"name": "content_modifier", "context": "attributes",
         "action": "hash", "key": "marker"},
        {"name": "sql", "query": "SELECT * FROM STREAM WHERE keep = 'yes';"},
    ],
    "conditional_safe": [
        {"name": "content_modifier", "context": "attributes",
         "action": "upsert", "key": "condition_matched", "value": "yes",
         "condition": {"op": "and", "rules": [
             {"field": "$keep", "op": "eq", "value": "yes"}
         ]}},
        {"name": "content_modifier", "context": "attributes",
         "action": "upsert", "key": "always", "value": "yes"},
    ],
    "hash_then_filter": [
        {"name": "content_modifier", "context": "attributes",
         "action": "hash", "key": "marker"},
        {"name": "grep", "regex": "keep ^yes$"},
    ],
    "hash_then_unflagged": [
        {"name": "content_modifier", "context": "attributes",
         "action": "hash", "key": "marker"},
        {"name": "opentelemetry_envelope"},
    ],
    "unflagged_then_hash": [
        {"name": "opentelemetry_envelope"},
        {"name": "content_modifier", "context": "attributes",
         "action": "hash", "key": "marker"},
    ],
}


def add_any_value_attributes(attributes):
    attributes.add(key="str").value.string_value = "value"
    attributes.add(key="int_negative").value.int_value = -(2**40)
    attributes.add(key="int_positive").value.int_value = 2**62
    attributes.add(key="double").value.double_value = 3.25
    attributes.add(key="bool").value.bool_value = True
    attributes.add(key="bytes").value.bytes_value = b"\x00\x01binary\xff"
    attributes.add(key="empty")
    array = attributes.add(key="array").value.array_value
    array.values.add().string_value = "one"
    array.values.add().int_value = 2
    array.values.add()
    nested = array.values.add().kvlist_value
    nested.values.add(key="inner").value.bool_value = False
    kvlist = attributes.add(key="kvlist").value.kvlist_value
    kvlist.values.add(key="name").value.string_value = "nested"
    kvlist.values.add(key="list").value.array_value.values.add().double_value = -1.5


def add_kvlist_body(record, keep, marker):
    body = record.body.kvlist_value
    body.values.add(key="keep").value.string_value = keep
    body.values.add(key="marker").value.string_value = marker
    body.values.add(key="count").value.int_value = -5
    add_any_value_attributes(body.values.add(key="nested").value.kvlist_value.values)


def build_direct_cfl_logs_payload():
    request = ExportLogsServiceRequest()
    timestamp = 1789516800123456789

    resource_logs = request.resource_logs.add(schema_url="https://example.com/resource")
    resource_logs.resource.attributes.add(key="service.name").value.string_value = "direct"
    add_any_value_attributes(resource_logs.resource.attributes)
    resource_logs.resource.dropped_attributes_count = 2

    scope_logs = resource_logs.scope_logs.add(schema_url="https://example.com/scope")
    scope_logs.scope.name = "direct-cfl"
    scope_logs.scope.version = "1.0.0"
    scope_logs.scope.dropped_attributes_count = 1
    add_any_value_attributes(scope_logs.scope.attributes)

    record = scope_logs.log_records.add(time_unix_nano=timestamp,
                                        observed_time_unix_nano=timestamp + 1,
                                        severity_number=9, severity_text="INFO",
                                        dropped_attributes_count=3, flags=0x101,
                                        trace_id=bytes(range(16)), span_id=bytes(range(8)))
    add_kvlist_body(record, "yes", "kvlist")
    add_any_value_attributes(record.attributes)

    scope_logs.log_records.add(time_unix_nano=timestamp + 2).body.string_value = "plain"
    scope_logs.log_records.add(observed_time_unix_nano=timestamp + 3).body.int_value = -7
    scope_logs.log_records.add(time_unix_nano=timestamp + 4,
                               severity_number=24).body.bytes_value = b"\xde\xad"
    array = scope_logs.log_records.add(time_unix_nano=timestamp + 5).body.array_value
    array.values.add().double_value = 0.5
    array.values.add().bool_value = False
    scope_logs.log_records.add(time_unix_nano=timestamp + 6, severity_number=99)

    # scopes without records produce no group
    resource_logs.scope_logs.add().scope.name = "empty"

    # resources and scopes without content
    second = request.resource_logs.add()
    second_scope = second.scope_logs.add()
    add_kvlist_body(second_scope.log_records.add(time_unix_nano=timestamp + 7), "yes", "bare")
    add_kvlist_body(second_scope.log_records.add(time_unix_nano=timestamp + 8), "no", "bare")
    second.scope_logs.add(schema_url="https://example.com/only-schema")
    add_kvlist_body(second.scope_logs[1].log_records.add(time_unix_nano=timestamp + 9),
                    "yes", "schema-only")

    return request


def build_direct_cfl_sentinel_payload(keep="yes"):
    request = ExportLogsServiceRequest()
    record = request.resource_logs.add().scope_logs.add().log_records.add(
        time_unix_nano=1789516800000000000)
    add_kvlist_body(record, keep, "sentinel")
    return request


def direct_cfl_service(tmp_path, direct, processors, *, body_key=None, workers=1,
                       logs_max_size=None, threaded=False, conditional_routes=False):
    name = f"direct-cfl-{'on' if direct else 'off'}.yaml"
    if not direct:
        processors = [MSGPACK_REFERENCE_FILTER] + (processors or [])
    options = [f"http_server.workers: {workers}"]
    if body_key:
        options.append(f"logs_body_key: {body_key}")
    if logs_max_size:
        options.append(f"logs_max_size: {logs_max_size}")
    if threaded:
        options.append("threaded: true")
    option_lines = "\n".join(f"      {option}" for option in options)
    processor_lines = ""
    if processors is not None:
        processor_lines = f"      processors: {json.dumps({'logs': processors})}\n"
    route_lines = ""
    output_match = "      match: '*'"
    if conditional_routes:
        route_lines = """      routes:
        logs:
          - name: direct_cfl_default
            condition:
              default: true
            to:
              outputs:
                - direct_cfl_output
"""
        output_match = ""
    config = tmp_path / name
    config.write_text(f"""
service:
  flush: 0.2
  grace: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
    - name: opentelemetry
      port: ${{FLUENT_BIT_TEST_LISTENER_PORT}}
      http2: on
{option_lines}
{processor_lines}{route_lines}  outputs:
    - name: opentelemetry
      alias: direct_cfl_output
{output_match}
      host: 127.0.0.1
      port: ${{TEST_SUITE_HTTP_PORT}}
""", encoding="utf-8")
    return Service(str(config))


def flatten_received_logs(requests_received):
    records = []
    for request in requests_received:
        for resource_logs in request.resource_logs:
            resource = json_format.MessageToDict(resource_logs.resource)
            for scope_logs in resource_logs.scope_logs:
                scope = json_format.MessageToDict(scope_logs.scope)
                for record in scope_logs.log_records:
                    records.append(json.dumps({
                        "resource": resource,
                        "resource_schema_url": resource_logs.schema_url,
                        "scope": scope,
                        "scope_schema_url": scope_logs.schema_url,
                        "record": json_format.MessageToDict(record),
                    }, sort_keys=True))
    return sorted(records)


def is_sentinel(record):
    return '"stringValue": "sentinel"' in record


def run_direct_cfl_case(tmp_path, direct, processors, transport, *, body_key=None,
                        workers=1, sentinel_keep="yes", threaded=False,
                        conditional_routes=False, encoding="protobuf"):
    service = direct_cfl_service(tmp_path, direct, processors, body_key=body_key,
                                 workers=workers, threaded=threaded,
                                 conditional_routes=conditional_routes)
    service.start()
    try:
        before = len(data_storage["logs"])
        payloads = [build_direct_cfl_logs_payload(),
                    build_direct_cfl_sentinel_payload(sentinel_keep)]
        for payload in payloads:
            if transport == "grpc":
                service.send_grpc_request("logs", payload)
            elif encoding == "json":
                # protobuf's generic JSON formatter represents bytes as base64,
                # while OTLP/JSON requires trace and span IDs in hexadecimal.
                for resource_logs in payload.resource_logs:
                    for scope_logs in resource_logs.scope_logs:
                        for record in scope_logs.log_records:
                            record.trace_id = b""
                            record.span_id = b""
                json_payload = json_format.MessageToJson(payload).encode("utf-8")
                response = service.send_raw_request(
                    "/v1/logs", json_payload, content_type="application/json")
                assert response.status_code == 201
            else:
                response = service.send_raw_request("/v1/logs", payload.SerializeToString())
                assert response.status_code == 201

        # The sentinel goes in its own request, after the payload being compared.
        def received():
            records = flatten_received_logs(data_storage["logs"][before:])
            return records if any(is_sentinel(record) for record in records) else None

        return service.service.wait_for_condition(received, timeout=20, interval=0.1,
                                                  description="direct CFL sentinel")
    finally:
        service.stop()


@pytest.mark.parametrize("transport", ["http", "grpc"])
@pytest.mark.parametrize("chain", sorted(DIRECT_CFL_PROCESSOR_CHAINS))
def test_in_opentelemetry_logs_direct_cfl_parity(tmp_path, chain, transport):
    processors = DIRECT_CFL_PROCESSOR_CHAINS[chain]
    msgpack_records = run_direct_cfl_case(tmp_path, False, processors, transport)
    direct_records = run_direct_cfl_case(tmp_path, True, processors, transport)

    # more than the sentinel must reach the output for the comparison to matter
    assert len(msgpack_records) > 1
    assert direct_records == msgpack_records


@pytest.mark.parametrize("chain", sorted(DIRECT_CFL_PROCESSOR_CHAINS))
def test_in_opentelemetry_logs_direct_cfl_json_parity(tmp_path, chain):
    processors = DIRECT_CFL_PROCESSOR_CHAINS[chain]
    msgpack_records = run_direct_cfl_case(
        tmp_path, False, processors, "http", encoding="json")
    direct_records = run_direct_cfl_case(
        tmp_path, True, processors, "http", encoding="json")

    assert len(msgpack_records) > 1
    assert direct_records == msgpack_records


@pytest.mark.parametrize("workers", [1, pytest.param(
    4, marks=pytest.mark.skipif(os.name == "nt",
                                reason="HTTP shared listener ports are unavailable on Windows"))])
def test_in_opentelemetry_logs_direct_cfl_json_without_processors(tmp_path, workers):
    # Without processors JSON uses the single-pass CFL decoder and is encoded
    # once, the records must match the msgpack reference.
    msgpack_records = run_direct_cfl_case(
        tmp_path, False, None, "http", encoding="json", workers=workers)
    direct_records = run_direct_cfl_case(
        tmp_path, True, None, "http", encoding="json", workers=workers)

    assert len(msgpack_records) > 1
    assert direct_records == msgpack_records


@pytest.mark.parametrize("processors", [None, "content_modifier"])
def test_in_opentelemetry_logs_direct_cfl_json_edge_parity(tmp_path, processors):
    if processors is not None:
        processors = DIRECT_CFL_PROCESSOR_CHAINS[processors]
    payload = {
        "resourceLogs": [{
            "resource": {"attributes": [
                {"key": "missing"},
                {"key": "unset", "value": {}},
                {"key": "nested", "value": {
                    "customValue": {"child": [1, True, None]}
                }},
            ]},
            "scopeLogs": [{"logRecords": [
                {"timeUnixNano": "1789516800123456789",
                 "body": {"arrayValue": {"values": [
                    {}, {"stringValue": "value"}
                ]}}},
                {"timeUnixNano": "1789516800123456790", "body": {}},
            ]}],
        }]
    }
    results = []

    for direct in [False, True]:
        service = direct_cfl_service(tmp_path, direct, processors)
        try:
            service.start()
            before = len(data_storage["logs"])
            response = service.send_raw_request(
                "/v1/logs", json.dumps(payload).encode("utf-8"),
                content_type="application/json")
            assert response.status_code == 201

            def received_records():
                records = flatten_received_logs(data_storage["logs"][before:])
                return records if len(records) == 2 else None

            received = service.service.wait_for_condition(
                received_records,
                timeout=20, interval=0.1, description="direct CFL JSON edge records")
            results.append(received)
        finally:
            service.stop()

    assert results[1] == results[0]


@pytest.mark.parametrize("encoding", ["protobuf", "json"])
def test_in_opentelemetry_logs_direct_cfl_empty_request(tmp_path, encoding):
    # A request without log records is valid and accepted on every path.
    if encoding == "json":
        payload = b'{"resourceLogs":[{"scopeLogs":[{"logRecords":[]}]}]}'
        content_type = "application/json"
    else:
        request = ExportLogsServiceRequest()
        request.resource_logs.add().scope_logs.add()
        payload = request.SerializeToString()
        content_type = "application/x-protobuf"

    for direct in [False, True]:
        service = direct_cfl_service(tmp_path, direct,
                                     DIRECT_CFL_PROCESSOR_CHAINS["content_modifier"])
        try:
            service.start()
            response = service.send_raw_request("/v1/logs", payload,
                                                content_type=content_type)
            assert response.status_code == 201
        finally:
            service.stop()


@pytest.mark.parametrize("processors", [None, "content_modifier"])
def test_in_opentelemetry_logs_direct_cfl_json_unsupported_key(tmp_path, processors):
    # CFL maps only hold string keys. A wrapped attribute key is unwrapped,
    # a numeric one makes the request take the msgpack path.
    if processors is not None:
        processors = DIRECT_CFL_PROCESSOR_CHAINS[processors]
    payload = {"resourceLogs": [{"scopeLogs": [{"logRecords": [
        {"timeUnixNano": "1789516800000000000", "body": {"stringValue": "wrapped"},
         "attributes": [{"key": {"stringValue": "name"}, "value": {"intValue": "1"}}]},
        {"timeUnixNano": "1789516800000000001", "body": {"stringValue": "numeric"},
         "attributes": [{"key": 5, "value": {"boolValue": True}}]},
    ]}]}]}
    sentinel = build_direct_cfl_sentinel_payload().SerializeToString()
    results = []

    for direct in [False, True]:
        service = direct_cfl_service(tmp_path, direct, processors)
        try:
            service.start()
            before = len(data_storage["logs"])
            response = service.send_raw_request(
                "/v1/logs", json.dumps(payload).encode("utf-8"),
                content_type="application/json")
            assert response.status_code == 201
            response = service.send_raw_request("/v1/logs", sentinel)
            assert response.status_code == 201

            def received():
                records = flatten_received_logs(data_storage["logs"][before:])
                return records if any(is_sentinel(record) for record in records) else None

            results.append(service.service.wait_for_condition(
                received, timeout=20, interval=0.1, description="sentinel after key test"))
        finally:
            service.stop()

    assert results[1] == results[0]


@pytest.mark.parametrize("encoding", ["protobuf", "json"])
def test_in_opentelemetry_logs_direct_cfl_body_key(tmp_path, encoding):
    processors = DIRECT_CFL_PROCESSOR_CHAINS["content_modifier"]
    msgpack_records = run_direct_cfl_case(tmp_path, False, processors, "http",
                                          body_key="message", encoding=encoding)
    direct_records = run_direct_cfl_case(tmp_path, True, processors, "http",
                                         body_key="message", encoding=encoding)

    assert len(msgpack_records) > 1
    assert direct_records == msgpack_records


@pytest.mark.skipif(os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows")
@pytest.mark.parametrize("encoding", ["protobuf", "json"])
def test_in_opentelemetry_http_workers_balance_keepalive_connections(tmp_path, encoding):
    # Every accepted socket may be handed to another worker. Many concurrent
    # keep-alive connections must all be served and every record delivered.
    connections = 24
    requests_per_connection = 10
    service = direct_cfl_service(tmp_path, True, DIRECT_CFL_PROCESSOR_CHAINS["hash_once"],
                                 workers=4, threaded=True)
    service.start()
    try:
        before = len(data_storage["logs"])
        payload = build_direct_cfl_sentinel_payload("keep")
        if encoding == "json":
            body = json_format.MessageToJson(payload).encode("utf-8")
            content_type = "application/json"
        else:
            body = payload.SerializeToString()
            content_type = "application/x-protobuf"

        def client():
            connection = http.client.HTTPConnection("127.0.0.1", service.flb_listener_port,
                                                    timeout=10)
            try:
                for _ in range(requests_per_connection):
                    connection.request("POST", "/v1/logs", body,
                                       {"Content-Type": content_type})
                    response = connection.getresponse()
                    response.read()
                    assert response.status == 201
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=connections) as pool:
            for future in [pool.submit(client) for _ in range(connections)]:
                future.result()

        expected = connections * requests_per_connection

        def delivered():
            records = flatten_received_logs(data_storage["logs"][before:])
            return records if len(records) >= expected else None

        records = service.service.wait_for_condition(delivered, timeout=30, interval=0.2,
                                                     description="balanced connections")
        assert len(records) == expected
    finally:
        service.stop()


@pytest.mark.skipif(os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows")
def test_in_opentelemetry_logs_direct_cfl_workers(tmp_path):
    # Hashing makes accidental processing in both the worker and collector
    # observable: a double pass would hash the first digest again.
    processors = DIRECT_CFL_PROCESSOR_CHAINS["hash_once"]
    msgpack_records = run_direct_cfl_case(tmp_path, False, processors, "http", workers=4)
    direct_records = run_direct_cfl_case(tmp_path, True, processors, "http", workers=4)

    assert len(msgpack_records) > 1
    assert direct_records == msgpack_records


@pytest.mark.skipif(os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows")
@pytest.mark.parametrize("conditional_routes", [False, True])
def test_in_opentelemetry_logs_direct_cfl_threaded_workers(tmp_path, conditional_routes):
    processors = DIRECT_CFL_PROCESSOR_CHAINS["hash_once"]
    msgpack_records = run_direct_cfl_case(
        tmp_path, False, processors, "http", workers=4, threaded=True,
        conditional_routes=conditional_routes)
    direct_records = run_direct_cfl_case(
        tmp_path, True, processors, "http", workers=4, threaded=True,
        conditional_routes=conditional_routes)

    assert len(msgpack_records) > 1
    assert direct_records == msgpack_records


@pytest.mark.skipif(os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows")
@pytest.mark.parametrize("encoding", ["protobuf", "json"])
@pytest.mark.parametrize("conditional_routes", [False, True])
def test_in_opentelemetry_logs_worker_processing(tmp_path, encoding, conditional_routes):
    # Worker-safe chains run in the HTTP workers, the msgpack reference runs
    # them in the input collector.
    processors = DIRECT_CFL_PROCESSOR_CHAINS["hash_once"]
    collector_records = run_direct_cfl_case(
        tmp_path, False, processors, "http", workers=4, threaded=True,
        conditional_routes=conditional_routes, encoding=encoding)
    worker_records = run_direct_cfl_case(
        tmp_path, True, processors, "http", workers=4, threaded=True,
        conditional_routes=conditional_routes, encoding=encoding)

    assert len(collector_records) > 1
    assert worker_records == collector_records


@pytest.mark.skipif(os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows")
@pytest.mark.parametrize("chain", ["hash_then_filter", "hash_then_unflagged",
                                    "unflagged_then_hash"])
def test_in_opentelemetry_logs_worker_processing_fallback(tmp_path, chain):
    processors = DIRECT_CFL_PROCESSOR_CHAINS[chain]
    collector_records = run_direct_cfl_case(
        tmp_path, False, processors, "http", workers=4, threaded=True,
        conditional_routes=True)
    fallback_records = run_direct_cfl_case(
        tmp_path, True, processors, "http", workers=4, threaded=True,
        conditional_routes=True)

    assert len(collector_records) > 1
    assert fallback_records == collector_records


@pytest.mark.skipif(os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows")
@pytest.mark.parametrize("direct", [False, True])
def test_in_opentelemetry_logs_direct_cfl_threaded_stress(tmp_path, direct):
    request_count = 200
    processors = DIRECT_CFL_PROCESSOR_CHAINS["hash_once"]
    service = direct_cfl_service(
        tmp_path, direct, processors, workers=4, threaded=True,
        conditional_routes=True)
    payload = build_direct_cfl_sentinel_payload().SerializeToString()

    try:
        service.start()
        before = len(data_storage["logs"])

        def send_request(_):
            return service.send_raw_request("/v1/logs", payload).status_code

        with ThreadPoolExecutor(max_workers=16) as executor:
            statuses = list(executor.map(send_request, range(request_count)))

        assert statuses == [201] * request_count

        def received_records():
            records = flatten_received_logs(data_storage["logs"][before:])
            return records if len(records) >= request_count else None

        records = service.service.wait_for_condition(
            received_records, timeout=30, interval=0.1,
            description="threaded direct-CFL stress records")
        assert len(records) == request_count
    finally:
        service.stop()


@pytest.mark.skipif(os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows")
@pytest.mark.parametrize("chain", ["hash_then_filter", "filter_first",
                                    "hash_then_unflagged", "unflagged_then_hash"])
def test_in_opentelemetry_logs_direct_cfl_workers_fallback(tmp_path, chain):
    # Hashing is intentionally non-idempotent. If an eligible prefix ran in a
    # worker before the whole chain fell back, direct-on parity would fail.
    processors = DIRECT_CFL_PROCESSOR_CHAINS[chain]
    msgpack_records = run_direct_cfl_case(tmp_path, False, processors, "http", workers=4)
    direct_records = run_direct_cfl_case(tmp_path, True, processors, "http", workers=4)

    assert len(msgpack_records) > 1
    assert direct_records == msgpack_records


@pytest.mark.skipif(os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows")
@pytest.mark.parametrize("encoding", ["protobuf", "json"])
@pytest.mark.parametrize("chain", ["content_modifier", "sql_drop", "hash_then_sql",
                                    "conditional_safe"])
def test_in_opentelemetry_logs_direct_cfl_threaded_worker_safe_chain(tmp_path, chain,
                                                                    encoding):
    processors = DIRECT_CFL_PROCESSOR_CHAINS[chain]
    msgpack_records = run_direct_cfl_case(
        tmp_path, False, processors, "http", workers=4, threaded=True,
        encoding=encoding)
    direct_records = run_direct_cfl_case(
        tmp_path, True, processors, "http", workers=4, threaded=True,
        encoding=encoding)

    assert len(msgpack_records) > 1
    assert direct_records == msgpack_records


@pytest.mark.parametrize("direct", [False, True])
def test_in_opentelemetry_logs_direct_cfl_drop_all(tmp_path, direct):
    # Every record of the payload is dropped, only the sentinel matches.
    processors = [{"name": "sql", "query": "SELECT * FROM STREAM WHERE keep = 'last';"}]
    records = run_direct_cfl_case(tmp_path, direct, processors, "http", sentinel_keep="last")

    assert len(records) == 1
    assert is_sentinel(records[0])


@pytest.mark.parametrize("attributes,scopes,records,resources,accepted", [
    (1, 32, 1, 1, True),
    (64, 1, 1, 1, True),
    (64, 32, 1, 1, False),
    (1, 1, 512, 1, False),
    # scopes without records produce nothing, the request is accepted
    (64, 1000, 0, 1, True),
])
def test_in_opentelemetry_logs_direct_cfl_generated_limit(tmp_path, attributes, scopes,
                                                          records, resources, accepted):
    processors = DIRECT_CFL_PROCESSOR_CHAINS["content_modifier"]
    service = direct_cfl_service(tmp_path, True, processors, logs_max_size="16k")
    request = generated_limit_payload(attributes, scopes, records, resources)
    try:
        service.start()
        response = service.send_raw_request("/v1/logs", request.SerializeToString())
        assert response.status_code == (201 if accepted else 400)

        # A rejected request never appends a prefix of its records.
        small = generated_limit_payload(1, 1)
        small.resource_logs[0].scope_logs[0].log_records[0].body.string_value = "recovery"
        response = service.send_raw_request("/v1/logs", small.SerializeToString())
        assert response.status_code == 201

        def received_records():
            return [record for request in data_storage["logs"]
                    for resource in request.resource_logs
                    for scope in resource.scope_logs for record in scope.log_records]

        expected = scopes * records * resources if accepted else 0
        service.service.wait_for_condition(
            lambda: len(received_records()) >= expected + 1,
            timeout=20, interval=0.1, description="recovery after direct CFL byte limit")
        actual = received_records()
        assert sum(record.body.string_value == "recovery" for record in actual) == 1
        assert sum(record.body.string_value == "generated-limit" for record in actual) == expected
    finally:
        service.stop()


@pytest.mark.parametrize("encoding", ["protobuf", "json"])
@pytest.mark.parametrize("limit", [512, 1024, 2048, 4096, 8192, 16384])
def test_in_opentelemetry_logs_direct_cfl_limit_parity(tmp_path, limit, encoding):
    processors = DIRECT_CFL_PROCESSOR_CHAINS["content_modifier"]
    request = build_direct_cfl_logs_payload()
    if encoding == "json":
        for resource_logs in request.resource_logs:
            for scope_logs in resource_logs.scope_logs:
                for record in scope_logs.log_records:
                    record.trace_id = b""
                    record.span_id = b""
        payload = json_format.MessageToJson(request).encode("utf-8")
        content_type = "application/json"
    else:
        payload = request.SerializeToString()
        content_type = "application/x-protobuf"
    statuses = []

    for direct in [False, True]:
        service = direct_cfl_service(tmp_path, direct, processors,
                                     logs_max_size=str(limit))
        try:
            service.start()
            response = service.send_raw_request(
                "/v1/logs", payload, content_type=content_type)
            statuses.append(response.status_code)
        finally:
            service.stop()

    assert statuses[1] == statuses[0]
