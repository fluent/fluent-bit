import http.client
import json
import os
import logging
import time

import pytest
import requests

from server.http_server import data_storage, http_server_run
from utils.http_matrix import PROTOCOL_CASES, run_curl_request
from utils.test_service import FluentBitTestService

logger = logging.getLogger(__name__)
MOCK_VALID_JWT = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QiLCJ0eXAiOiJKV1QifQ."
    "eyJleHAiOjE4OTM0NTYwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50MSJ9."
    "TqWs06LUpQa0FGLejnOkWAD6v562d5CUh2NwsJ7iAuae9-WNFBKU6mP1zAaoafla6o5npee7RfbSzZNFI4PKhqAj69789JjAYV7IW-GSuMwJejHdVOWmCc5lmcZPH0EVxEkHA6lFQxYQwDCrfQ8Sd4Q3vYCV6sLPENcuNpQi9ytjVjaZs_7ONH2oA-sZ7EUchqJJoIBPfjit2yYsq9NeemxCzYMtngiC-IX12eEfaQ1cVYPIjhhN_NaMvapznp-BW4gnXkNoAZ1S-p1axWWY-6UgRdMYOr0Hy5PHQ9fCuHJ6Z-blYdtuGavCUGHK5ghX-JdH1WJ51F89992dQ5yF_w"
)

IN_HTTP_PROTOCOL_CONFIGS = {
    "http1_cleartext": "in_http_http1_cleartext.yaml",
    "http2_cleartext": "in_http_http2_cleartext.yaml",
    "http1_tls": "in_http_http1_tls.yaml",
    "http2_tls": "in_http_http2_tls.yaml",
}

def create_connection(server, port):
    return http.client.HTTPConnection(server, port)

def create_headers():
    return {
        'Content-Type': 'application/json'
    }

def create_payload(json_filename):
    try:
        file_name = os.path.abspath(os.path.join(os.path.dirname(__file__), './data_files/', json_filename))
        with open(file_name, 'r') as file:
            data = file.read().strip()
            return data
    except FileNotFoundError:
        return json.dumps({"error": "File not found"}, indent=4)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON format"}, indent=4)

def send_requests(conn, num_requests, headers, json_payload):
    responses = []
    for i in range(num_requests):
        conn.request("POST", "/", body=json_payload, headers=headers)
        response = conn.getresponse()
        responses.append({
            'status': response.status,
            'reason': response.reason,
            'data': response.read().decode()
        })
    return responses


def test_send_data():
    try:
        service = Service("in_http_config")
        service.start()
        output = service.runtest_send_data('localhost', service.flb_listener_port, 'sample_data.json')
        forwarded_payloads = service.read_forwarded_payloads()
        logger.info(f"response: {output}")
        service.stop()
        assert len(output) > 0

        # Verify response details if necessary
        for response in output:
            assert response['status'] == 201
            assert response['reason'] == 'Created'

        assert len(forwarded_payloads) == 1
        assert isinstance(forwarded_payloads[0], list)
        assert len(forwarded_payloads[0]) == 1
        record = forwarded_payloads[0][0]
        assert record["message"] == "Este es un mensaje de prueba"
        assert record["level"] == "info"
        assert record["timestamp"] == "2024-07-29T10:00:00Z"
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        if service.flb.process is not None:
            service.stop()
        raise


@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[case["id"] for case in PROTOCOL_CASES])
def test_in_http_protocol_matrix(case):
    service = Service(IN_HTTP_PROTOCOL_CONFIGS[case["config_key"]])
    service.start()

    scheme = "https" if case["use_tls"] else "http"
    result = run_curl_request(
        f"{scheme}://localhost:{service.flb_listener_port}/",
        create_payload("sample_data.json"),
        headers=["Content-Type: application/json"],
        http_mode=case["http_mode"],
        ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
    )
    forwarded_payloads = service.read_forwarded_payloads()

    service.stop()

    assert result["status_code"] == 201
    assert result["http_version"] == case["expected_http_version"]
    assert len(forwarded_payloads) == 1
    assert forwarded_payloads[0][0]["message"] == "Este es un mensaje de prueba"


def test_in_http_rejects_bad_json():
    service = Service("in_http_config")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/",
        '{"message":"broken"',
        headers=["Content-Type: application/json"],
        http_mode="http1.1",
    )

    service.stop()

    assert result["status_code"] == 400


def test_in_http_rejects_get_requests():
    service = Service("in_http_config")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/",
        None,
        method="GET",
        http_mode="http1.1",
    )

    service.stop()

    assert result["status_code"] >= 400


def test_in_http_oauth2_requires_bearer_token():
    service = Service("in_http_oauth2.yaml")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/",
        create_payload("sample_data.json"),
        headers=["Content-Type: application/json"],
        http_mode="http1.1",
    )

    service.stop()

    assert result["status_code"] == 401
    assert data_storage["payloads"] == []


def test_in_http_oauth2_accepts_valid_jwt():
    service = Service("in_http_oauth2.yaml")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/",
        create_payload("sample_data.json"),
        headers=[
            "Content-Type: application/json",
            f"Authorization: Bearer {MOCK_VALID_JWT}",
        ],
        http_mode="http1.1",
    )
    forwarded_payloads = service.read_forwarded_payloads()

    service.stop()

    assert result["status_code"] == 201
    assert len(forwarded_payloads) == 1
    assert forwarded_payloads[0][0]["message"] == "Este es un mensaje de prueba"


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '../config/', config_file))
        test_path = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.abspath(os.path.join(test_path, "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads"],
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
        logger.info(f"Fluent Bit listener port: {self.flb_listener_port}")
        logger.info(f"test suite http port: {self.test_suite_http_port}")

    def runtest_send_data(self, server, port, json_filename):
        conn = create_connection(server, port)
        headers = create_headers()
        json_payload = create_payload(json_filename)
        responses = send_requests(conn, 1, headers, json_payload)
        conn.close()
        return responses

    def read_forwarded_payloads(self, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if data_storage["payloads"]:
                return data_storage["payloads"]
            time.sleep(0.5)
        raise TimeoutError("Timed out waiting for forwarded HTTP payloads")

    def stop(self):
        self.service.stop()
