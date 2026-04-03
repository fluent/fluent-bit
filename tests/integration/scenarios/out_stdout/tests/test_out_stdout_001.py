import json
import os

import requests
from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from utils.data_utils import read_json_file, read_file
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.service = FluentBitTestService(self.config_file)

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def wait_for_log_contains(self, text, timeout=10):
        return self.service.wait_for_condition(
            lambda: read_file(self.flb.log_file) if text in read_file(self.flb.log_file) else None,
            timeout=timeout,
            interval=0.5,
            description=f"log text {text!r}",
        )

    def read_log(self):
        return read_file(self.flb.log_file)

    def _resolve_json_fixture(self, json_file):
        return os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "../../in_opentelemetry/tests/data_files",
                json_file,
            )
        )

    def _build_metrics_payload(self, json_file):
        return json_format.Parse(
            json.dumps(read_json_file(self._resolve_json_fixture(json_file))),
            ExportMetricsServiceRequest(),
        )

    def _build_traces_payload(self, json_file):
        return json_format.Parse(
            json.dumps(read_json_file(self._resolve_json_fixture(json_file))),
            ExportTraceServiceRequest(),
        )

    def _build_logs_payload(self, json_file):
        return json_format.Parse(
            json.dumps(read_json_file(self._resolve_json_fixture(json_file))),
            ExportLogsServiceRequest(),
        )

    def send_json_metrics_payload(self, json_file):
        payload = self._build_metrics_payload(json_file)
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/metrics",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_json_traces_payload(self, json_file):
        payload = self._build_traces_payload(json_file)
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/traces",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_logs_json_payload(self, json_file):
        payload = self._build_logs_payload(json_file)
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/logs",
            data=json_format.MessageToJson(payload),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        response.raise_for_status()

    def send_metrics_json_payload(self, json_file):
        payload = self._build_metrics_payload(json_file)
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/metrics",
            data=json_format.MessageToJson(payload),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        response.raise_for_status()

    def send_traces_json_payload(self, json_file):
        payload = self._build_traces_payload(json_file)
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/traces",
            data=json_format.MessageToJson(payload),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        response.raise_for_status()


def _find_json_line(log_text, needle):
    for line in log_text.splitlines():
        if needle in line and line.lstrip().startswith("{"):
            return json.loads(line)
    raise AssertionError(f"Could not find JSON line containing {needle!r}")


def test_out_stdout_default_format_emits_tagged_log_line():
    service = Service("out_stdout_basic.yaml")
    service.start()
    log_text = service.wait_for_log_contains("hello from out_stdout")
    service.stop()

    assert "[0] stdout.logs:" in log_text
    assert "hello from out_stdout" in log_text
    assert "\"source\"=>\"dummy\"" in log_text or '"source"' in log_text


def test_out_stdout_json_lines_honors_date_key_and_json_format():
    service = Service("out_stdout_json_lines.yaml")
    service.start()
    log_text = service.wait_for_log_contains("hello json lines")
    service.stop()

    payload = _find_json_line(log_text, "hello json lines")
    assert payload["message"] == "hello json lines"
    assert payload["source"] == "dummy"
    assert "timestamp" in payload
    assert "T" in payload["timestamp"]


def test_out_stdout_metrics_emits_text_representation():
    service = Service("out_stdout_metrics.yaml")
    service.start()
    service.send_json_metrics_payload("test_metrics_001.in.json")
    log_text = service.wait_for_log_contains("requests_total")
    service.stop()

    assert "requests_total" in log_text
    assert "service.name=\"checkout\"" in log_text
    assert "= 42" in log_text


def test_out_stdout_traces_emits_text_representation():
    service = Service("out_stdout_traces.yaml")
    service.start()
    service.send_json_traces_payload("test_traces_001.in.json")
    log_text = service.wait_for_log_contains("checkout-span")
    service.stop()

    assert "checkout-span" in log_text
    assert "trace-scope" in log_text
    assert "service.name" in log_text or "checkout" in log_text


def test_out_stdout_logs_accepts_otlp_json_ingestion():
    service = Service("out_stdout_otel.yaml")
    service.start()
    service.send_logs_json_payload("test_logs_001.in.json")
    log_text = service.wait_for_log_contains("This is an example log message.")
    service.stop()

    assert "This is an example log message." in log_text
    assert "This is another example log message." in log_text


def test_out_stdout_metrics_accepts_otlp_json_ingestion():
    service = Service("out_stdout_otel.yaml")
    service.start()
    service.send_metrics_json_payload("test_metrics_001.in.json")
    log_text = service.wait_for_log_contains("requests_total")
    service.stop()

    assert "requests_total" in log_text
    assert "service.name=\"checkout\"" in log_text
    assert "= 42" in log_text


def test_out_stdout_traces_accepts_otlp_json_ingestion():
    service = Service("out_stdout_otel.yaml")
    service.start()
    service.send_traces_json_payload("test_traces_001.in.json")
    log_text = service.wait_for_log_contains("checkout-span")
    service.stop()

    assert "checkout-span" in log_text
    assert "trace-scope" in log_text
