import json
import os
import time

import pytest
import requests

from server.http_server import configure_http_response, data_storage, http_server_run
from utils.test_service import FluentBitTestService
from utils.http_matrix import PROTOCOL_CASES, run_curl_request


SUCCESS_BODY = '{"text":"Success","code":0}'


class Service:
    def __init__(self, config_file):
        self.test_path = os.path.dirname(os.path.abspath(__file__))
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.tls_crt_file = f"{self.test_path}/../certificate/certificate.pem"
        self.tls_key_file = f"{self.test_path}/../certificate/private_key.pem"
        self.service = FluentBitTestService(
            self.config_file,
            extra_env={
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
            },
        )

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.flb_listener_port = self.service.flb_listener_port

    def wait_for_log_message(self, pattern, timeout=10, interval=0.25):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.flb and self.flb.log_file and os.path.exists(self.flb.log_file):
                with open(self.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
                    if pattern in log_file.read():
                        return True
            time.sleep(interval)
        raise TimeoutError(f"Timed out waiting for log pattern: {pattern}")

    def stop(self):
        self.service.stop()


class ForwardingService(Service):
    def __init__(self, config_file):
        self.test_path = os.path.dirname(os.path.abspath(__file__))
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.tls_crt_file = f"{self.test_path}/../certificate/certificate.pem"
        self.tls_key_file = f"{self.test_path}/../certificate/private_key.pem"
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            extra_env={
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        http_server_run(service.test_suite_http_port)
        self.service.wait_for_http_endpoint(
            f"http://127.0.0.1:{service.test_suite_http_port}/ping",
            timeout=10,
            interval=0.5,
        )

    def _stop_receiver(self, service):
        try:
            requests.post(f"http://127.0.0.1:{service.test_suite_http_port}/shutdown", timeout=2)
        except requests.RequestException:
            pass

    def start(self):
        super().start()
        self.test_suite_http_port = self.service.test_suite_http_port

    def wait_for_forwarded_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["requests"] if len(data_storage["requests"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} forwarded Splunk requests",
        )


def create_splunk_headers(content_type="application/json"):
    return [
        "Authorization: Splunk secret-token",
        f"Content-Type: {content_type}",
    ]


SPLUNK_PROTOCOL_CONFIGS = {
    False: {
        "http1_cleartext": "splunk_http1_keepalive.yaml",
        "http2_cleartext": "splunk_on_http2_keepalive.yaml",
        "http1_tls": "splunk_http1_tls_keepalive.yaml",
        "http2_tls": "splunk_on_http2_on_keepalive_on_tls_on.yaml",
    },
    True: {
        "http1_cleartext": "splunk_http1_keepalive_workers.yaml",
        "http2_cleartext": "splunk_on_http2_keepalive_workers.yaml",
        "http1_tls": "splunk_http1_tls_keepalive_workers.yaml",
        "http2_tls": "splunk_on_http2_on_keepalive_on_tls_on_workers.yaml",
    },
}


@pytest.mark.parametrize("workers_enabled", [False, True], ids=["single_listener", "workers_4"])
@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[case["id"] for case in PROTOCOL_CASES])
def test_splunk_protocol_matrix(case, workers_enabled):
    service = Service(SPLUNK_PROTOCOL_CONFIGS[workers_enabled][case["config_key"]])
    service.start()
    if workers_enabled:
        service.wait_for_log_message("with 4 workers", timeout=10)

    scheme = "https" if case["use_tls"] else "http"
    url = f"{scheme}://localhost:{service.flb_listener_port}/services/collector"
    result = run_curl_request(
        url,
        json.dumps({"Event": "Some text in the event"}),
        headers=create_splunk_headers(),
        http_mode=case["http_mode"],
        ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
    )

    service.stop()

    assert result["status_code"] == 200
    assert result["body"] == SUCCESS_BODY
    assert result["http_version"] == case["expected_http_version"]


def test_splunk_http1_no_keepalive():
    service = Service("splunk_http1_no_keepalive.yaml")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/services/collector",
        json.dumps({"Event": "Some text in the event"}),
        headers=create_splunk_headers(),
        http_mode="http1.1",
    )

    service.stop()

    assert result["status_code"] == 200
    assert result["body"] == SUCCESS_BODY
    assert result["http_version"] == "1.1"


@pytest.mark.parametrize(
    ("method", "endpoint"),
    [
        ("POST", "/services/collector/unsupported"),
        ("GET", "/services/collector"),
    ],
    ids=["unsupported_uri", "unsupported_method"],
)
def test_in_splunk_rejects_invalid_requests(method, endpoint):
    service = Service("splunk_http1_keepalive.yaml")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}{endpoint}",
        json.dumps({"event": "Some text in the event"}) if method == "POST" else None,
        method=method,
        headers=create_splunk_headers() if method == "POST" else [],
        http_mode="http1.1",
    )

    service.stop()

    assert result["status_code"] >= 400


def test_in_splunk_accepts_missing_authorization_header_by_default():
    service = Service("splunk_http1_keepalive.yaml")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/services/collector",
        json.dumps({"event": "Some text in the event"}),
        headers=["Content-Type: application/json"],
        http_mode="http1.1",
    )

    service.stop()

    assert result["status_code"] == 200


def test_in_splunk_to_out_splunk_prefers_configured_output_token():
    service = ForwardingService("in_splunk_to_out_splunk.yaml")
    service.start()
    configure_http_response(status_code=200, body={"text": "Success", "code": 0})

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/services/collector/event",
        json.dumps({"event": "Some text in the event"}),
        headers=create_splunk_headers(),
        http_mode="http1.1",
    )

    forwarded_requests = service.wait_for_forwarded_requests(1)
    service.stop()

    assert result["status_code"] == 200
    assert result["body"] == SUCCESS_BODY
    assert forwarded_requests[0]["path"] == "/services/collector/event"
    assert forwarded_requests[0]["headers"].get("Authorization") == "Splunk fallback-token"


SPLUNK_URI_CASES = [
    {
        "id": "collector",
        "method": "POST",
        "endpoint": "/services/collector",
        "payload": json.dumps({"Event": "Some text in the event"}),
        "headers": create_splunk_headers(),
    },
    {
        "id": "collector_event",
        "method": "POST",
        "endpoint": "/services/collector/event",
        "payload": json.dumps({"event": "Some text in the event"}),
        "headers": create_splunk_headers(),
    },
    {
        "id": "collector_raw",
        "method": "POST",
        "endpoint": "/services/collector/raw",
        "payload": "1, 2, 3... Hello, world!",
        "headers": create_splunk_headers("application/json"),
    },
    {
        "id": "collector_event_1_0",
        "method": "POST",
        "endpoint": "/services/collector/event/1.0",
        "payload": json.dumps({"event": "Some text in the event"}),
        "headers": create_splunk_headers(),
    },
    {
        "id": "collector_raw_1_0",
        "method": "POST",
        "endpoint": "/services/collector/raw/1.0",
        "payload": "1, 2, 3... Hello, world!",
        "headers": create_splunk_headers("application/json"),
    },
    {
        "id": "collector_health",
        "method": "GET",
        "endpoint": "/services/collector/health",
        "payload": None,
        "headers": [],
        "expected_body": '{"text":"Success","code":200}',
    },
]


@pytest.mark.parametrize("case", SPLUNK_URI_CASES, ids=[case["id"] for case in SPLUNK_URI_CASES])
def test_in_splunk_uri_variants(case):
    service = Service("splunk_http1_keepalive.yaml")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}{case['endpoint']}",
        case["payload"],
        method=case["method"],
        headers=case["headers"],
        http_mode="http1.1",
    )

    service.stop()

    assert result["status_code"] == 200
    assert result["body"] == case.get("expected_body", SUCCESS_BODY)
    assert result["http_version"] == "1.1"
