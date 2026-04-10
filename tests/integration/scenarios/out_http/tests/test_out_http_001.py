import json
import logging
import os

import requests

from server.http_server import (
    configure_http_response,
    configure_oauth_token_response,
    data_storage,
    http_server_run,
)
from utils.test_service import FluentBitTestService

logger = logging.getLogger(__name__)


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        test_path = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.abspath(os.path.join(test_path, "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
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
            description=f"{minimum_count} outbound HTTP requests",
        )


def test_out_http_sends_json_payload():
    service = Service("out_http_basic.yaml")
    service.start()
    configure_http_response(status_code=200, body={"status": "received"})

    requests_seen = service.wait_for_requests(1)
    service.stop()

    first_request = requests_seen[0]
    assert first_request["path"] == "/data"
    assert first_request["method"] == "POST"
    assert "application/json" in first_request["headers"].get("Content-Type", "")

    payload = json.loads(first_request["raw_data"])
    assert isinstance(payload, list)
    assert payload[0]["message"] == "hello from out_http"
    assert payload[0]["source"] == "dummy"


def test_out_http_receiver_error_is_observable():
    service = Service("out_http_retry.yaml")
    service.start()
    configure_http_response(status_code=500, body={"status": "error"})

    requests_seen = service.wait_for_requests(1, timeout=10)
    service.stop()

    assert len(requests_seen) >= 1


def test_out_http_oauth2_basic_adds_bearer_token():
    service = Service("out_http_oauth2_basic.yaml")
    service.start()
    configure_http_response(status_code=200, body={"status": "received"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    requests_seen = service.wait_for_requests(2)
    service.stop()

    token_request = next(request for request in requests_seen if request["path"] == "/oauth/token")
    data_request = next(request for request in requests_seen if request["path"] == "/data")

    assert token_request["method"] == "POST"
    assert "Basic " in token_request["headers"].get("Authorization", "")
    assert "grant_type=client_credentials" in token_request["raw_data"]
    assert "scope=logs.write" in token_request["raw_data"]
    assert data_request["headers"].get("Authorization") == "Bearer oauth-access-token"


def test_out_http_oauth2_private_key_jwt_adds_bearer_token():
    service = Service("out_http_oauth2_private_key_jwt.yaml")
    service.start()
    configure_http_response(status_code=200, body={"status": "received"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    requests_seen = service.wait_for_requests(2)
    service.stop()

    token_request = next(request for request in requests_seen if request["path"] == "/oauth/token")
    data_request = next(request for request in requests_seen if request["path"] == "/data")

    assert token_request["method"] == "POST"
    assert "client_assertion_type=" in token_request["raw_data"]
    assert "client_assertion=" in token_request["raw_data"]
    assert "client_id=client1" in token_request["raw_data"]
    assert data_request["headers"].get("Authorization") == "Bearer oauth-access-token"
