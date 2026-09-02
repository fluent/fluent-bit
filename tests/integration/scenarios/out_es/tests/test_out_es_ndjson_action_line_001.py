import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time

import pytest
import requests

from utils.memory_check import memory_check_enabled
from utils.test_service import FluentBitTestService


FORGED_DELETE_ID = "critical-audit-record-12345"
SAFE_UPDATE_ID = "safe-update-id"


class _BulkCaptureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)

        self.server.requests.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "body": body.decode("utf-8", errors="replace"),
            }
        )

        if self.server.response_factory is None:
            response = b'{"errors":false,"items":[{"create":{"status":201}}]}'
        else:
            response = self.server.response_factory(
                len(self.server.requests), self.server.requests[-1]
            )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class _BulkCaptureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, response_factory=None):
        super().__init__(address, _BulkCaptureHandler)
        self.requests = []
        self.response_factory = response_factory


class Service:
    def __init__(self, config_file, response_factory=None, extra_env=None):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.bulk_server = None
        self.bulk_server_thread = None
        self.response_factory = response_factory
        self.service = FluentBitTestService(
            self.config_file,
            extra_env=extra_env,
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.bulk_server = _BulkCaptureServer(
            ("127.0.0.1", service.test_suite_http_port),
            self.response_factory,
        )
        self.bulk_server_thread = threading.Thread(
            target=self.bulk_server.serve_forever,
            daemon=True,
        )
        self.bulk_server_thread.start()

    def _stop_receiver(self, service):
        if self.bulk_server is None:
            return

        self.bulk_server.shutdown()
        self.bulk_server.server_close()

        if self.bulk_server_thread is not None:
            self.bulk_server_thread.join(timeout=5)

    def start(self):
        self.service.start()

    def stop(self):
        self.service.stop()

    def wait_for_requests(self, minimum_count, timeout=10):
        if memory_check_enabled():
            timeout = max(timeout * 3, 30)

        return self.service.wait_for_condition(
            lambda: self.bulk_server.requests
            if len(self.bulk_server.requests) >= minimum_count
            else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} Elasticsearch bulk requests",
        )

    def wait_for_action_lines(self, minimum_count, timeout=10):
        if memory_check_enabled():
            timeout = max(timeout * 3, 30)

        return self.service.wait_for_condition(
            lambda: self.bulk_server.requests
            if sum(len(_bulk_action_lines(request["body"]))
                   for request in self.bulk_server.requests) >= minimum_count
            else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} Elasticsearch bulk action lines",
        )

    def wait_for_log_text(self, text, timeout=10):
        if memory_check_enabled():
            timeout = max(timeout * 3, 30)

        def matching_log():
            log_path = Path(self.service.flb.log_file)
            if not log_path.exists():
                return None

            log_text = log_path.read_text(encoding="utf-8", errors="replace")
            return log_text if text in log_text else None

        return self.service.wait_for_condition(
            matching_log,
            timeout=timeout,
            interval=0.5,
            description=f"Fluent Bit log text {text!r}",
        )

    def wait_for_bulk_accounting(self, output_name, timeout=10):
        if memory_check_enabled():
            timeout = max(timeout * 3, 30)

        metrics_url = (
            f"http://127.0.0.1:{self.service.flb.http_monitoring_port}"
            "/api/v2/metrics/prometheus"
        )

        def metric_value(metrics, name, labels):
            for line in metrics.splitlines():
                if not line.startswith(f"{name}{{"):
                    continue
                if all(f'{key}="{value}"' in line for key, value in labels.items()):
                    return float(line.rsplit(" ", 1)[-1])
            return None

        def accounting_snapshot():
            response = requests.get(metrics_url, timeout=2)
            response.raise_for_status()
            metrics = response.text
            output_labels = {"name": output_name}
            route_labels = {"input": "dummy.0", "output": output_name}
            snapshot = {
                "processed_records": metric_value(
                    metrics, "fluentbit_output_proc_records_total", output_labels
                ),
                "processed_bytes": metric_value(
                    metrics, "fluentbit_output_proc_bytes_total", output_labels
                ),
                "dropped_records": metric_value(
                    metrics, "fluentbit_output_dropped_records_total", output_labels
                ),
                "routed_records": metric_value(
                    metrics, "fluentbit_routing_logs_records_total", route_labels
                ),
                "routed_bytes": metric_value(
                    metrics, "fluentbit_routing_logs_bytes_total", route_labels
                ),
                "dropped_route_records": metric_value(
                    metrics, "fluentbit_routing_logs_drop_records_total", route_labels
                ),
                "dropped_route_bytes": metric_value(
                    metrics, "fluentbit_routing_logs_drop_bytes_total", route_labels
                ),
            }
            if snapshot["dropped_records"] == 1.0:
                return snapshot
            return None

        return self.service.wait_for_condition(
            accounting_snapshot,
            timeout=timeout,
            interval=0.5,
            description=f"successful and dropped route accounting for {output_name}",
        )


def _bulk_action_lines(body):
    actions = []

    for line in body.splitlines():
        if not line:
            continue

        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(value, dict) and any(
            key in value for key in ("create", "index", "update", "delete")
        ):
            actions.append(value)

    return actions


def _assert_no_forged_delete(body):
    actions = _bulk_action_lines(body)
    deletes = [
        action["delete"]
        for action in actions
        if "delete" in action and action["delete"].get("_id") == FORGED_DELETE_ID
    ]

    assert len(actions) == 1
    assert deletes == []


def _bulk_actions(requests):
    actions = []

    for request in requests:
        actions.extend(_bulk_action_lines(request["body"]))

    return actions


def _partial_bulk_response(request_number, request):
    action_count = len(_bulk_action_lines(request["body"]))

    if request_number == 1:
        assert action_count == 3
        return (
            b'{"errors":true,"items":['
            b'{"create":{"status":201}},'
            b'{"create":{"status":429,"error":{'
            b'"type":"es_rejected_execution_exception",'
            b'"reason":"bulk queue is full"}}},'
            b'{"create":{"status":409}}]}'
        )

    assert action_count == 1
    return b'{"errors":false,"items":[{"create":{"status":201}}]}'


def _unrecoverable_bulk_response(request_number, request):
    action_count = len(_bulk_action_lines(request["body"]))
    reason = "strict mapping conflict " + ("x" * 5000)
    item = {
        "create": {
            "status": 400,
            "error": {
                "type": "mapper_parsing_exception",
                "reason": reason,
            },
        }
    }

    return json.dumps({"errors": True, "items": [item] * action_count}).encode()


@pytest.mark.parametrize(
    "config_file",
    [
        "out_es_logstash_prefix_key_ndjson.yaml",
        "out_es_id_key_ndjson.yaml",
        "out_opensearch_logstash_prefix_key_ndjson.yaml",
        "out_opensearch_index_record_accessor_ndjson.yaml",
        "out_opensearch_id_key_ndjson.yaml",
    ],
)
def test_record_accessor_values_do_not_forge_bulk_action_lines(config_file):
    service = Service(config_file)

    try:
        service.start()
        requests_seen = service.wait_for_requests(1)
    finally:
        service.stop()

    bulk_body = requests_seen[0]["body"]
    assert requests_seen[0]["path"].startswith("/_bulk")
    _assert_no_forged_delete(bulk_body)


@pytest.mark.parametrize(
    "config_file",
    [
        "out_es_id_key_update_ndjson.yaml",
        "out_opensearch_id_key_update_ndjson.yaml",
    ],
)
def test_unsafe_required_id_key_does_not_emit_idless_update(config_file):
    service = Service(config_file)

    try:
        service.start()
        requests_seen = service.wait_for_action_lines(1)
    finally:
        service.stop()

    actions = _bulk_actions(requests_seen)
    updates = [action["update"] for action in actions if "update" in action]

    assert all(request["path"].startswith("/_bulk") for request in requests_seen)
    assert len(actions) == 1
    assert updates == [{"_index": "fluent-bit", "_id": SAFE_UPDATE_ID}]


@pytest.mark.parametrize(
    "config_file",
    [
        "out_es_partial_bulk_retry.yaml",
        "out_opensearch_partial_bulk_retry.yaml",
    ],
)
def test_partial_bulk_retry_sends_only_unresolved_records(config_file):
    service = Service(config_file, response_factory=_partial_bulk_response)

    try:
        service.start()
        requests_seen = service.wait_for_requests(2)
        log_text = service.wait_for_log_text(
            "reason='bulk queue is full'; retrying 1 record(s)"
        )
    finally:
        service.stop()

    assert len(_bulk_action_lines(requests_seen[0]["body"])) == 3
    assert len(_bulk_action_lines(requests_seen[1]["body"])) == 1
    assert "bulk response reported errors: 1/3 items failed" in log_text
    assert "status=429 type='es_rejected_execution_exception'" in log_text
    assert "reason='bulk queue is full'; retrying 1 record(s)" in log_text


@pytest.mark.parametrize(
    "config_file",
    [
        "out_es_drop_unrecoverable_records.yaml",
        "out_opensearch_drop_unrecoverable_records.yaml",
    ],
)
def test_unrecoverable_bulk_errors_are_logged_and_not_retried(config_file):
    output_name = "opensearch.0" if "opensearch" in config_file else "es.0"
    service = Service(
        config_file,
        response_factory=_unrecoverable_bulk_response,
        extra_env={"BULK_TEST_MESSAGE": "y" * 5000},
    )

    try:
        service.start()
        requests_seen = service.wait_for_requests(1)
        log_text = service.wait_for_log_text("dropped 1 unrecoverable record(s)")
        log_text = service.wait_for_log_text("error: Output part 2/2")
        accounting = service.wait_for_bulk_accounting(output_name)
        time.sleep(3)
        request_count = len(service.bulk_server.requests)
    finally:
        service.stop()

    assert len(_bulk_action_lines(requests_seen[0]["body"])) == 1
    assert len(requests_seen[0]["body"]) > 4000
    assert request_count == 1
    assert "bulk response reported errors: 1/1 items failed" in log_text
    assert "status=400 type='mapper_parsing_exception'" in log_text
    assert "retrying 0 record(s), dropped 1 unrecoverable record(s)" in log_text
    assert "error caused by: Input" not in log_text
    assert any(
        "[error]" in line and "error: Output part 2/2" in line
        for line in log_text.splitlines()
    )
    assert accounting["processed_records"] == 0.0
    assert accounting["processed_bytes"] == 0.0
    assert accounting["dropped_records"] == 1.0
    assert accounting["routed_records"] == 0.0
    assert accounting["routed_bytes"] == 0.0
    assert accounting["dropped_route_records"] == 1.0
    assert accounting["dropped_route_bytes"] > 4000
