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
        cert_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.oauth_server_port = None
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
        self.oauth_server_port = service.allocate_port_env("TEST_SUITE_OAUTH_PORT")
        http_server_run(self.oauth_server_port)
        http_server_run(
            service.test_suite_http_port,
            use_tls=True,
            tls_crt_file=self.tls_crt_file,
            tls_key_file=self.tls_key_file,
            reset_state=False,
        )

        def _http_ready():
            try:
                response = requests.get(
                    f"http://127.0.0.1:{self.oauth_server_port}/ping",
                    timeout=1,
                )
                return response.status_code == 200
            except requests.RequestException:
                return False

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
            _http_ready,
            timeout=10,
            interval=0.5,
            description="azure logs ingestion oauth receiver readiness",
        )

        self.service.wait_for_condition(
            _https_ready,
            timeout=10,
            interval=0.5,
            description="azure logs ingestion receiver readiness",
        )

    def _stop_receiver(self, service):
        try:
            if self.oauth_server_port is not None:
                requests.post(
                    f"http://127.0.0.1:{self.oauth_server_port}/shutdown",
                    timeout=2,
                )
        except requests.RequestException:
            pass

        try:
            requests.post(
                f"https://localhost:{service.test_suite_http_port}/shutdown",
                timeout=2,
                verify=self.tls_crt_file,
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
            description=f"{minimum_count} azure logs ingestion requests",
        )


def test_out_azure_logs_ingestion_legacy_oauth2_and_payload_format():
    service = Service("out_azure_logs_ingestion_oauth2.yaml")
    service.start()
    configure_http_response(status_code=200, body={"status": "received"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    requests_seen = service.wait_for_requests(2, timeout=15)
    service.stop()

    token_request = next(request for request in requests_seen if request["path"] == "/oauth/token")
    data_request = next(
        request
        for request in requests_seen
        if request["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
    )

    assert token_request["method"] == "POST"
    assert "grant_type=client_credentials" in token_request["raw_data"]
    assert "scope=https://monitor.azure.com/.default" in token_request["raw_data"]
    assert "client_id=suite-client" in token_request["raw_data"]
    assert "client_secret=suite-secret" in token_request["raw_data"]

    assert data_request["method"] == "POST"
    assert data_request["query_string"] == "api-version=2021-11-01-preview"
    assert data_request["headers"].get("Authorization") == "Bearer oauth-access-token"
    assert data_request["headers"].get("Content-Encoding") == "gzip"
    assert data_request["headers"].get("Content-Type") == "application/json"

    payload = data_request["json"]
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["message"] == "hello from azure logs ingestion"
    assert payload[0]["source"] == "dummy"
    assert payload[0]["level"] == "info"
    assert isinstance(payload[0]["@timestamp"], (int, float))
