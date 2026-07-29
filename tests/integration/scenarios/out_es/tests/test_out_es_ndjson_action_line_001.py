import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest

from utils.memory_check import memory_check_enabled
from utils.test_service import FluentBitTestService


FORGED_DELETE_ID = "critical-audit-record-12345"
SAFE_UPDATE_ID = "safe-update-id"


class _BulkCaptureHandler(BaseHTTPRequestHandler):
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

        response = b'{"errors":false,"items":[{"create":{"status":201}}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class _BulkCaptureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address):
        super().__init__(address, _BulkCaptureHandler)
        self.requests = []


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.bulk_server = None
        self.bulk_server_thread = None
        self.service = FluentBitTestService(
            self.config_file,
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.bulk_server = _BulkCaptureServer(("127.0.0.1", service.test_suite_http_port))
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
