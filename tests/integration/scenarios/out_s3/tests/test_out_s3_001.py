import gzip
import json
import os

import requests
import pytest
from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from server.s3_server import data_storage, s3_server_run, s3_server_stop
from utils.data_utils import read_json_file
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["requests"],
            extra_env={
                "AWS_ACCESS_KEY_ID": "test-access-key",
                "AWS_SECRET_ACCESS_KEY": "test-secret-key",
                "AWS_EC2_METADATA_DISABLED": "true",
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.s3_port = service.allocate_port_env("TEST_SUITE_HTTP_PORT")
        s3_server_run(self.s3_port)

    def _stop_receiver(self, service):
        s3_server_stop()

    def start(self):
        self.service.start()
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def wait_for_request(self, index=0):
        return self.service.wait_for_condition(
            lambda: data_storage["requests"][index] if len(data_storage["requests"]) > index else None,
            timeout=15,
            interval=0.5,
            description=f"S3 upload request {index}",
        )

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

    def send_logs_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "logs")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/logs",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_metrics_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "metrics")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/metrics",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_traces_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "traces")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/traces",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()


def _parse_json_lines(body):
    lines = [line for line in body.decode("utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _parse_single_json_payload(body):
    return json.loads(body.decode("utf-8").strip())


def _send_otlp_signal(service, signal_type, json_file):
    if signal_type == "logs":
        service.send_logs_payload(json_file)
    elif signal_type == "metrics":
        service.send_metrics_payload(json_file)
    else:
        service.send_traces_payload(json_file)


def _start_or_skip_unsupported_s3_format(service, format_name):
    try:
        service.start()
    except FluentBitStartupError:
        log_contents = ""
        if service.service.flb and service.service.flb.log_file:
            with open(service.service.flb.log_file, "r", encoding="utf-8", errors="replace") as file:
                log_contents = file.read()
        if f"unknown configuration property '{format_name}'" in log_contents:
            pytest.skip(f"s3.{format_name} is not supported by this Fluent Bit binary")
        raise


def test_out_s3_put_object_uploads_json_lines_payload():
    service = Service("out_s3_basic.yaml")
    service.start()
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/out_s3/")
    assert request["headers"]["Content-Type"] == "application/x-ndjson"

    payload = _parse_json_lines(request["body"])
    assert len(payload) == 1
    assert payload[0]["message"] == "hello from out_s3"
    assert payload[0]["source"] == "dummy"
    assert "date" in payload[0]


def test_out_s3_format_json_uploads_logs_only_as_json_lines():
    service = Service("out_s3_format_json.yaml")
    _start_or_skip_unsupported_s3_format(service, "format")
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/out_s3/")
    assert request["headers"]["Content-Type"] == "application/x-ndjson"

    payload = _parse_json_lines(request["body"])
    assert len(payload) == 1
    assert payload[0]["message"] == "hello from out_s3 format json"
    assert payload[0]["source"] == "dummy"
    assert "date" in payload[0]


def test_out_s3_put_object_gzip_upload_sets_encoding_and_compresses_payload():
    service = Service("out_s3_gzip.yaml")
    service.start()
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/out_s3/")
    assert request["headers"]["Content-Type"] == "application/x-ndjson"
    assert request["headers"]["Content-Encoding"] == "gzip"

    payload = _parse_json_lines(gzip.decompress(request["body"]))
    assert len(payload) == 1
    assert payload[0]["message"] == "hello gzip s3"
    assert payload[0]["source"] == "dummy"
    assert "date" in payload[0]


@pytest.mark.parametrize(
    ("signal_type", "json_file", "root_key", "expected_value"),
    [
        ("logs", "test_logs_001.in.json", "resourceLogs", "This is an example log message."),
        ("metrics", "test_metrics_001.in.json", "resourceMetrics", "requests_total"),
        ("traces", "test_traces_001.in.json", "resourceSpans", "checkout-span"),
    ],
)
def test_out_s3_otlp_json_uploads_signal_payloads(signal_type, json_file, root_key, expected_value):
    service = Service("out_s3_otlp_json.yaml")
    _start_or_skip_unsupported_s3_format(service, "format")
    _send_otlp_signal(service, signal_type, json_file)
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/")
    assert request["headers"]["Content-Type"] == "application/json"

    payload = _parse_single_json_payload(request["body"])
    assert root_key in payload

    rendered = json.dumps(payload)
    assert expected_value in rendered
