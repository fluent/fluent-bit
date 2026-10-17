"""FTS metric/span policies through protobuf export, fan-out, retries and replay."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests
import yaml
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from utils.test_service import FluentBitTestService
from test_fts_signals import metric, span, attr
from test_fts_policies import attributes


@pytest.mark.parametrize("signal", ["metrics", "traces"])
@pytest.mark.parametrize("filesystem,replay", [(False, False), (True, False), (True, True)])
def test_signal_route_isolation_retry_and_backlog(tmp_path, signal, filesystem, replay):
    message_type = ExportMetricsServiceRequest if signal == "metrics" else ExportTraceServiceRequest
    attempts, received = [], []
    blocked = {"value": replay}

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            attempts.append(data)
            message = message_type.FromString(data)
            status = 503 if blocked["value"] or len(attempts) == 1 else 200
            if status == 200:
                received.append(message)
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    policy = '''local fb = require("fluentbit")
function process(record)
  if record.name == "control" then return end
  record.name = "normalized"
  record.resource.attributes:set("service.name", "normalized")
  record.scope.name = "normalized.scope"
  if record.signal == "metrics" then
    record.datapoints:get(1):get("attributes"):set("exact", fb.int64("9223372036854775807"))
  else
    record.attributes:remove("secret")
    record.attributes:set("exact", fb.int64("9223372036854775807"))
  end
end'''
    source = {"name": "opentelemetry", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}
    service_config = {"flush": 0.2, "grace": 1, "http_server": True,
                      "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
                      "scheduler.base": 1, "scheduler.cap": 1}
    if filesystem:
        source["storage.type"] = "filesystem"
        service_config["storage.path"] = str(tmp_path / "storage")
    config = tmp_path / "pipeline.yaml"
    config.write_text(yaml.safe_dump({"service": service_config, "pipeline": {
        "inputs": [source], "outputs": [
            {"name": "stdout", "match": "*", "format": "otlp_json"},
            {"name": "opentelemetry", "match": "*", "host": "127.0.0.1", "port": server.server_port,
             "retry_limit": False, "processors": {signal: [{"name": "fts", "code": policy}]}}
        ]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        metrics = signal == "metrics"
        resource_key, scope_key, item_key = (("resourceMetrics", "scopeMetrics", "metrics") if metrics else
                                            ("resourceSpans", "scopeSpans", "spans"))
        items = [metric("gauge", "target"), metric("gauge", "control")] if metrics else [span("target"), span("control")]
        payload = {resource_key: [{"resource": {"attributes": [attr("service.name", "original")],
                   "droppedAttributesCount": 7}, scope_key: [{"scope": {"name": "original.scope",
                   "droppedAttributesCount": 6}, item_key: items}]}]}
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/{signal}", json=payload, timeout=15)
        assert response.status_code in (200, 201), response.text
        if replay:
            service.wait_for_condition(lambda: attempts, timeout=30)
            service.stop()
            original_log = Path(service.flb.log_file).read_text()
            assert list((tmp_path / "storage").rglob("*.flb"))
            blocked["value"] = False
            service = FluentBitTestService(str(config))
            service.start()
        service.wait_for_condition(lambda: received, timeout=30)
        service.stop()
        if not replay:
            original_log = Path(service.flb.log_file).read_text()
        assert len(attempts) >= 2 and attempts[0] == attempts[1]
        rows = [(resource, scope, item) for message in received
                for resource in getattr(message, "resource_metrics" if metrics else "resource_spans")
                for scope in getattr(resource, "scope_metrics" if metrics else "scope_spans")
                for item in getattr(scope, "metrics" if metrics else "spans")]
        assert [item.name for _, _, item in rows] == ["normalized", "control"]
        for resource, scope, item in rows:
            values = {entry.key: entry.value.string_value for entry in resource.resource.attributes}
            assert values["service.name"] == ("normalized" if item.name == "normalized" else "original")
            assert scope.scope.name == ("normalized.scope" if item.name == "normalized" else "original.scope")
            assert resource.resource.dropped_attributes_count == 7
            assert scope.scope.dropped_attributes_count == 6
            if item.name == "normalized":
                attrs = item.gauge.data_points[0].attributes if metrics else item.attributes
                assert next(entry.value.int_value for entry in attrs if entry.key == "exact") == 2**63-1
        batches = [json.loads(line) for line in original_log.splitlines() if line.startswith("{")]
        raw = [(resource, scope, item) for batch in batches for resource in batch[resource_key]
               for scope in resource[scope_key] for item in scope[item_key]]
        assert [item["name"] for _, _, item in raw] == ["target", "control"]
        assert all(attributes(resource["resource"]["attributes"])["service.name"] == "original"
                   and scope["scope"]["name"] == "original.scope" for resource, scope, _ in raw)
    finally:
        service.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
