import json
import logging
import os
import time

import requests

from server.http_server import (
    configure_http_response,
    configure_oauth_token_response,
    data_storage,
    http_server_run,
    server_instances,
)
from utils.test_service import FluentBitTestService

logger = logging.getLogger(__name__)

def _wait_for_http_server(port, timeout=5):
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            response = requests.get(f"http://127.0.0.1:{port}/ping", timeout=1)
            if response.status_code == 200:
                return
        except requests.RequestException:
            pass

        time.sleep(0.1)

    raise TimeoutError(f"Timed out waiting for HTTP server on port {port}")


def _wait_for_http_server_port(timeout=5):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if server_instances:
            return server_instances[-1].server_port

        time.sleep(0.1)

    raise TimeoutError("Timed out waiting for HTTP server port assignment")


class Service:
    def __init__(self, config_file, *, response_setup=None, use_tls=False):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        test_path = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.abspath(os.path.join(test_path, "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.response_setup = response_setup
        self.use_tls = use_tls
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
        http_server_run(
            service.test_suite_http_port,
            use_tls=self.use_tls,
            tls_crt_file=self.tls_crt_file,
            tls_key_file=self.tls_key_file,
        )
        if self.response_setup is not None:
            self.response_setup()

        if self.use_tls:
            def _https_ready():
                try:
                    response = requests.get(
                        f"https://localhost:{service.test_suite_http_port}/ping",
                        timeout=1,
                        verify=self.tls_crt_file,
                    )
                    return response.status_code == 200
                except requests.RequestException:
                    return False

            self.service.wait_for_condition(
                _https_ready,
                timeout=10,
                interval=0.5,
                description="HTTPS out_http receiver readiness",
            )
        else:
            self.service.wait_for_http_endpoint(
                f"http://127.0.0.1:{service.test_suite_http_port}/ping",
                timeout=10,
                interval=0.5,
            )

    def _stop_receiver(self, service):
        try:
            if self.use_tls:
                requests.post(
                    f"https://localhost:{service.test_suite_http_port}/shutdown",
                    timeout=2,
                    verify=self.tls_crt_file,
                )
            else:
                requests.post(
                    f"http://127.0.0.1:{service.test_suite_http_port}/shutdown",
                    timeout=2,
                )
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

    def wait_for_log_message(self, pattern, timeout=10):
        def _read_log():
            if not os.path.exists(self.flb.log_file):
                return None

            with open(self.flb.log_file, encoding="utf-8", errors="replace") as log_file:
                contents = log_file.read()

            if pattern in contents:
                return contents

            return None

        return self.service.wait_for_condition(
            _read_log,
            timeout=timeout,
            interval=0.25,
            description=f"log message '{pattern}'",
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


def test_out_http_oauth2_timeout_retries_hung_token_endpoint():
    service = Service(
        "out_http_oauth2_timeout.yaml",
        response_setup=lambda: configure_oauth_token_response(
            hang_before_response=True,
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(2, timeout=15)
    log_text = service.wait_for_log_message("response timeout reached", timeout=15)
    service.stop()

    token_requests = [request for request in requests_seen if request["path"] == "/oauth/token"]
    data_requests = [request for request in requests_seen if request["path"] == "/data"]

    assert len(token_requests) >= 2
    assert len(data_requests) == 0
    assert "response timeout reached" in log_text


def test_out_http_oauth2_read_idle_timeout_retries_partial_token_response():
    service = Service(
        "out_http_oauth2_timeout.yaml",
        response_setup=lambda: configure_oauth_token_response(
            stream_fragments=[
                '{"access_token":"partial',
            ],
            hang_after_fragment_index=0,
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(2, timeout=15)
    log_text = service.wait_for_log_message("response timeout reached", timeout=15)
    service.stop()

    token_requests = [request for request in requests_seen if request["path"] == "/oauth/token"]
    data_requests = [request for request in requests_seen if request["path"] == "/data"]

    assert len(token_requests) >= 2
    assert len(data_requests) == 0
    assert "response timeout reached" in log_text


def test_out_http_tls_response_timeout_retries_hung_server():
    service = Service(
        "out_http_tls_response_timeout.yaml",
        response_setup=lambda: configure_http_response(
            hang_before_response=True,
        ),
        use_tls=True,
    )
    service.start()

    requests_seen = service.wait_for_requests(2, timeout=15)
    log_text = service.wait_for_log_message("response timeout reached", timeout=15)
    service.stop()

    assert len(requests_seen) >= 2
    assert "response timeout reached" in log_text


def test_out_http_tls_read_idle_timeout_retries_partial_response():
    service = Service(
        "out_http_tls_read_idle_timeout.yaml",
        response_setup=lambda: configure_http_response(
            stream_fragments=[
                '{"status":"par',
            ],
            hang_after_fragment_index=0,
        ),
        use_tls=True,
    )
    service.start()

    requests_seen = service.wait_for_requests(2, timeout=15)
    log_text = service.wait_for_log_message("read idle timeout reached", timeout=15)
    service.stop()

    assert len(requests_seen) >= 2
    assert "read idle timeout reached" in log_text


def test_http_server_configure_helpers_allow_clearing_nullable_fields():
    http_server_run(0, reset_state=True)
    port = _wait_for_http_server_port()
    _wait_for_http_server(port)

    try:
        configure_http_response(
            stream_fragments=["part"],
            hang_after_fragment_index=0,
        )
        configure_http_response(
            stream_fragments=None,
            hang_after_fragment_index=None,
        )

        response = requests.post(
            f"http://127.0.0.1:{port}/data",
            json={"test": "clear"},
            timeout=5,
        )

        assert response.status_code == 200
        assert response.json() == {"status": "received"}
    finally:
        try:
            requests.post(f"http://127.0.0.1:{port}/shutdown", timeout=2)
        except requests.RequestException:
            pass


def test_http_server_oauth_token_honors_explicit_content_type_and_raw_body():
    http_server_run(0, reset_state=True)
    port = _wait_for_http_server_port()
    _wait_for_http_server(port)

    try:
        configure_oauth_token_response(
            stream_fragments=["partial-token"],
            hang_after_fragment_index=0,
        )
        configure_oauth_token_response(
            body="not-json",
            content_type="text/plain",
            stream_fragments=None,
            hang_after_fragment_index=None,
        )

        response = requests.post(
            f"http://127.0.0.1:{port}/oauth/token",
            data="grant_type=client_credentials",
            timeout=5,
        )

        assert response.status_code == 200
        assert response.text == "not-json"
        assert response.headers["Content-Type"].startswith("text/plain")
    finally:
        try:
            requests.post(f"http://127.0.0.1:{port}/shutdown", timeout=2)
        except requests.RequestException:
            pass


def test_http_server_oauth_token_honors_explicit_json_content_type():
    http_server_run(0, reset_state=True)
    port = _wait_for_http_server_port()
    _wait_for_http_server(port)

    try:
        configure_oauth_token_response(
            body={"access_token": "json-token", "token_type": "Bearer"},
            content_type="application/json; charset=utf-8",
        )

        response = requests.post(
            f"http://127.0.0.1:{port}/oauth/token",
            data="grant_type=client_credentials",
            timeout=5,
        )

        assert response.status_code == 200
        assert response.json()["access_token"] == "json-token"
        assert "application/json" in response.headers["Content-Type"]
    finally:
        try:
            requests.post(f"http://127.0.0.1:{port}/shutdown", timeout=2)
        except requests.RequestException:
            pass
