import http.client
import json
import os
import logging
from pathlib import Path
import re
import socket
import time

import pytest
import requests

from server.http_server import data_storage, http_server_run
from utils.http_matrix import PROTOCOL_CASES, run_curl_request
from utils.input_pause_resume import (
    assert_connection_closed,
    assert_pause_resume_cycles,
    assert_shutdown_while_paused,
    is_valgrind,
    large_json_payload,
    open_partial_http_request,
    open_stalled_tcp_connection,
)
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


def post_json(connection, message):
    body = json.dumps({"message": message})
    connection.request("POST", "/", body=body, headers=create_headers())
    response = connection.getresponse()
    response.read()
    assert response.status == 201


def wait_for_connection_close(connection, timeout=10):
    deadline = time.monotonic() + timeout
    connection.settimeout(0.25)

    while time.monotonic() < deadline:
        try:
            data = connection.recv(1)
        except (ConnectionResetError, BrokenPipeError):
            return
        except socket.timeout:
            continue

        if not data:
            return

        pytest.fail(f"HTTP server sent unexpected data while closing an idle connection: {data!r}")

    pytest.fail("HTTP server did not close the connection after its idle timeout")


def read_fluent_bit_log(service):
    return Path(service.flb.log_file).read_text(encoding="utf-8", errors="replace")


def wait_for_timeout_log(service):
    def read_log_with_timeout():
        log = read_fluent_bit_log(service)
        if "timed out after 2 seconds (IO timeout)" in log:
            return log

    return service.service.wait_for_condition(
        read_log_with_timeout,
        timeout=5,
        interval=0.1,
        description="HTTP connection timeout log",
    )


def timeout_log_pattern(level, peer_port):
    return re.compile(
        rf"\[{level}\].*\[downstream\] connection #\d+ from "
        rf"tcp://127\.0\.0\.1:{peer_port} timed out after 2 seconds \(IO timeout\)"
    )


def assert_connection_open_without_response(connection):
    connection.settimeout(1)

    try:
        data = connection.recv(1)
    except socket.timeout:
        return

    if not data:
        pytest.fail("HTTP server closed the connection while the request was incomplete")

    pytest.fail("HTTP server responded before the request was complete")


def send_raw_http1_request(port, request, split_at=None):
    response = bytearray()

    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(2)

        if split_at is None:
            connection.sendall(request)
        else:
            connection.sendall(request[:split_at])
            assert_connection_open_without_response(connection)
            connection.settimeout(2)
            connection.sendall(request[split_at:])

        while len(response) < 4096 and b"\r\n" not in response:
            try:
                data = connection.recv(4096 - len(response))
            except ConnectionResetError:
                break
            except socket.timeout:
                pytest.fail("HTTP/1 server did not respond or close the connection")

            if not data:
                break
            response.extend(data)

    return bytes(response)


def send_split_http2_preface(port):
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings_frame = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    response = bytearray()

    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(preface[:-2])
        assert_connection_open_without_response(connection)
        connection.settimeout(2)
        connection.sendall(preface[-2:] + settings_frame)

        while len(response) < 9:
            try:
                data = connection.recv(4096)
            except socket.timeout:
                pytest.fail("HTTP/2 server did not respond to a split connection preface")

            if not data:
                break
            response.extend(data)

    return bytes(response)


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


def test_in_http_accepts_split_http2_preface():
    service = Service("in_http_http2_cleartext.yaml")

    try:
        service.start()
        response = send_split_http2_preface(service.flb_listener_port)
    finally:
        service.stop()

    assert len(response) >= 9
    assert response[3] == 0x04
    assert data_storage["payloads"] == []


def test_in_http_accepts_http1_request_split_before_autodetect_boundary():
    service = Service("in_http_http2_cleartext.yaml")
    body = b'{"message":"split-http1"}'
    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n"
        b"\r\n"
        + body
    )

    try:
        service.start()
        response = send_raw_http1_request(service.flb_listener_port, request, split_at=1)
        forwarded_payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    assert b"HTTP/1.1 201" in response
    assert len(forwarded_payloads) == 1
    assert forwarded_payloads[0][0]["message"] == "split-http1"


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


def test_in_http_accepts_post_with_empty_generic_headers():
    service = Service("in_http_config")
    body = b'{"message":"empty-header"}'
    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"X-Empty:\r\n"
        b"X-Empty-Whitespace: \t\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + body
    )

    try:
        service.start()
        response = send_raw_http1_request(service.flb_listener_port, request)
        forwarded_payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    assert b"HTTP/1.1 201" in response
    assert len(forwarded_payloads) == 1
    assert forwarded_payloads[0][0]["message"] == "empty-header"


@pytest.mark.parametrize("workers", [1, 4], ids=["single_listener", "workers_4"])
def test_in_http_idle_timeout_keeps_completed_connections_quiet(workers):
    service = Service(
        "in_http_idle_timeout.yaml",
        extra_env={
            "IN_HTTP_TEST_WORKERS": workers,
            "IN_HTTP_TIMEOUT_LOG_ERROR": "true",
        },
    )
    connection = None
    replacement = None

    try:
        service.start()
        connection = create_connection("127.0.0.1", service.flb_listener_port)
        post_json(connection, "first-request")
        original_socket = connection.sock
        peer_port = original_socket.getsockname()[1]

        time.sleep(0.5)
        post_json(connection, "reused-before-idle-timeout")
        assert connection.sock is original_socket

        wait_for_connection_close(connection.sock)
        if workers == 1:
            timeout_log = wait_for_timeout_log(service)
            assert timeout_log_pattern("debug", peer_port).search(timeout_log), timeout_log
        else:
            timeout_log = read_fluent_bit_log(service)
        assert not re.search(
            r"\[error\].*timed out after 2 seconds \(IO timeout\)",
            timeout_log,
        ), timeout_log

        replacement = create_connection("127.0.0.1", service.flb_listener_port)
        post_json(replacement, "reconnected-after-idle-timeout")
        forwarded_payloads = service.service.wait_for_condition(
            lambda: list(data_storage["payloads"])
            if sum(len(payload) for payload in data_storage["payloads"]) == 3
            else None,
            timeout=10,
            interval=0.1,
            description="three forwarded HTTP records",
        )
    finally:
        if connection is not None:
            connection.close()
        if replacement is not None:
            replacement.close()
        service.stop()

    messages = [record["message"] for payload in forwarded_payloads for record in payload]
    assert messages == [
        "first-request",
        "reused-before-idle-timeout",
        "reconnected-after-idle-timeout",
    ]


@pytest.mark.parametrize("completed_request", [False, True], ids=["new_connection", "keepalive"])
@pytest.mark.parametrize("workers", [1, 4], ids=["single_listener", "workers_4"])
def test_in_http_incomplete_request_timeout_reports_peer(workers, completed_request):
    service = Service(
        "in_http_idle_timeout.yaml",
        extra_env={
            "IN_HTTP_TEST_WORKERS": workers,
            "IN_HTTP_TIMEOUT_LOG_ERROR": "true",
        },
    )
    connection = None

    try:
        service.start()
        connection = socket.create_connection(
            ("127.0.0.1", service.flb_listener_port),
            timeout=2,
        )
        peer_port = connection.getsockname()[1]
        if completed_request:
            body = b'{"message":"completed-before-partial"}'
            connection.sendall(
                b"POST / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"\r\n"
                + body
            )
            response = bytearray()
            connection.settimeout(2)
            while b"\r\n\r\n" not in response:
                response_chunk = connection.recv(4096)
                assert response_chunk, "HTTP server closed the completed request connection"
                response.extend(response_chunk)
            assert b"HTTP/1.1 201" in response

        connection.sendall(
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 100\r\n"
            b"\r\n"
            b'{"message":"incomplete'
        )
        wait_for_connection_close(connection)
        timeout_log = wait_for_timeout_log(service)
        expected_records = 1 if completed_request else 0
        if expected_records:
            forwarded_payloads = service.service.wait_for_condition(
                lambda: list(data_storage["payloads"])
                if sum(len(payload) for payload in data_storage["payloads"]) == expected_records
                else None,
                timeout=5,
                interval=0.1,
                description=f"{expected_records} forwarded HTTP records",
            )
        else:
            service.assert_no_forwarded_payloads_for()
            forwarded_payloads = list(data_storage["payloads"])
    finally:
        if connection is not None:
            connection.close()
        service.stop()

    assert timeout_log_pattern("error", peer_port).search(timeout_log), timeout_log
    assert sum(len(payload) for payload in forwarded_payloads) == expected_records


def test_in_http_timeout_log_error_can_be_disabled():
    service = Service(
        "in_http_idle_timeout.yaml",
        extra_env={
            "IN_HTTP_TEST_WORKERS": 1,
            "IN_HTTP_TIMEOUT_LOG_ERROR": "false",
        },
    )
    connection = None

    try:
        service.start()
        connection = socket.create_connection(
            ("127.0.0.1", service.flb_listener_port),
            timeout=2,
        )
        peer_port = connection.getsockname()[1]
        connection.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\n")
        wait_for_connection_close(connection)
        timeout_log = wait_for_timeout_log(service)
    finally:
        if connection is not None:
            connection.close()
        service.stop()

    assert timeout_log_pattern("debug", peer_port).search(timeout_log), timeout_log
    assert not re.search(
        r"\[error\].*timed out after 2 seconds \(IO timeout\)",
        timeout_log,
    ), timeout_log


def test_in_http_accepts_empty_connection_and_transfer_encoding():
    service = Service("in_http_config")
    body = b'{"message":"empty-semantic-headers"}'
    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection:\r\n"
        b"Transfer-Encoding: \t\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + body
    )

    try:
        service.start()
        response = send_raw_http1_request(service.flb_listener_port, request)
        forwarded_payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    assert b"HTTP/1.1 201" in response
    assert len(forwarded_payloads) == 1
    assert forwarded_payloads[0][0]["message"] == "empty-semantic-headers"


@pytest.mark.parametrize("header_value", [b"", b" \t"], ids=["empty", "whitespace"])
@pytest.mark.parametrize(
    "following_data",
    [b"1-X: value\r\nConnection: close\r\n\r\n1", b"\r\n1"],
    ids=["numeric-header", "numeric-body"],
)
def test_in_http_rejects_empty_content_length(header_value, following_data):
    service = Service("in_http_config")
    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length:" + header_value + b"\r\n"
        + following_data
    )

    try:
        service.start()
        response = send_raw_http1_request(service.flb_listener_port, request)
        service.assert_no_forwarded_payloads_for()
    finally:
        service.stop()

    forwarded_payloads = list(data_storage["payloads"])
    assert response == b"" or b"HTTP/1.1 400" in response
    assert forwarded_payloads == []


@pytest.mark.parametrize(
    "case",
    [
        {
            "id": "http1_cleartext_single_listener",
            "config": "in_http_pause_resume_single.yaml",
            "scheme": "http",
            "http_mode": "http1.1",
            "stalled_connection": open_partial_http_request,
        },
        {
            "id": "http1_cleartext_workers",
            "config": "in_http_pause_resume.yaml",
            "scheme": "http",
            "http_mode": "http1.1",
            "stalled_connection": open_partial_http_request,
        },
        {
            "id": "http2_tls_workers",
            "config": "in_http_pause_resume_http2_tls.yaml",
            "scheme": "https",
            "http_mode": "http2",
            "stalled_connection": open_stalled_tcp_connection,
        },
    ],
    ids=lambda case: case["id"],
)
def test_in_http_pause_resume_cycles(case):
    service = Service(case["config"])

    try:
        service.start()

        def open_active_connections():
            return [
                case["stalled_connection"](
                    "127.0.0.1",
                    service.flb_listener_port,
                )
                for _ in range(8)
            ]

        assert_pause_resume_cycles(
            service.flb,
            f"{case['scheme']}://localhost:{service.flb_listener_port}/",
            large_json_payload(size=6144),
            ["Content-Type: application/json"],
            input_name="http.0",
            success_status=201,
            cycles=3,
            http_mode=case["http_mode"],
            pause_trigger_requests=2,
            ca_cert_path=service.tls_crt_file if case["scheme"] == "https" else None,
            active_connection_factory=open_active_connections,
        )
    finally:
        service.stop()


@pytest.mark.parametrize(
    "config_file",
    ["in_http_pause_resume_single.yaml", "in_http_pause_resume.yaml"],
    ids=["single_listener", "workers_4"],
)
def test_in_http_shutdown_while_paused_with_active_connections(config_file):
    service = Service(config_file)

    try:
        service.start()
        assert_shutdown_while_paused(
            service.flb,
            service.stop,
            "127.0.0.1",
            service.flb_listener_port,
            f"http://localhost:{service.flb_listener_port}/",
            large_json_payload(size=6144),
            ["Content-Type: application/json"],
            input_name="http.0",
            success_status=201,
        )
    finally:
        service.stop()


def test_in_http_async_tls_accept_timeout():
    service = Service("in_http_accept_timeout_tls.yaml")
    service.start()
    stalled_connection = None

    try:
        stalled_connection = open_stalled_tcp_connection(
            "127.0.0.1",
            service.flb_listener_port,
        )
        assert_connection_closed(stalled_connection, timeout=10)

        result = run_curl_request(
            f"https://localhost:{service.flb_listener_port}/",
            '{"message":"accept-timeout-recovered"}',
            headers=["Content-Type: application/json"],
            http_mode="http2",
            ca_cert_path=service.tls_crt_file,
        )
        assert result["status_code"] == 201, result
    finally:
        if stalled_connection is not None:
            stalled_connection.close()
        service.stop()


@pytest.mark.parametrize("case", PROTOCOL_CASES, ids=[case["id"] for case in PROTOCOL_CASES])
def test_in_http_health_endpoint(case):
    service = Service(IN_HTTP_PROTOCOL_CONFIGS[case["config_key"]])
    service.start()

    scheme = "https" if case["use_tls"] else "http"
    result = run_curl_request(
        f"{scheme}://localhost:{service.flb_listener_port}/health",
        None,
        method="GET",
        http_mode=case["http_mode"],
        ca_cert_path=service.tls_crt_file if case["use_tls"] else None,
    )

    service.stop()

    assert data_storage["payloads"] == []

    payload = json.loads(result["body"])

    assert result["status_code"] == 200
    assert result["http_version"] == case["expected_http_version"]
    assert payload["status"] == "ok"
    assert payload["message"] == (
        "I can only show you the door. You're the one that has to walk through it."
    )
    assert payload["timestamp"].endswith("Z")


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


def test_in_http_oauth2_health_endpoint_does_not_require_token():
    service = Service("in_http_oauth2.yaml")
    service.start()

    result = run_curl_request(
        f"http://localhost:{service.flb_listener_port}/health",
        None,
        method="GET",
        http_mode="http1.1",
    )

    service.stop()

    payload = json.loads(result["body"])

    assert result["status_code"] == 200
    assert payload["status"] == "ok"
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
    def __init__(self, config_file, extra_env=None):
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
                **(extra_env or {}),
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

    def assert_no_forwarded_payloads_for(self, quiet_period=1.5):
        deadline = time.time() + quiet_period

        while time.time() < deadline:
            assert data_storage["payloads"] == []
            time.sleep(0.1)

    def stop(self):
        self.service.stop()
