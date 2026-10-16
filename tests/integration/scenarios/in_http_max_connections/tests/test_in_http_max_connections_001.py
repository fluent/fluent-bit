import logging
import os
import socket
import time

import pytest
import requests

from server.http_server import data_storage, http_server_run
from utils.fluent_bit_manager import FluentBitStartupError
from utils.http_matrix import curl_supports_http2, run_curl_request
from utils.test_service import FluentBitTestService


LOGGER = logging.getLogger(__name__)


class Service:
    def __init__(self):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config/in_http_max_connections.yaml")
        )
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads"],
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        http_server_run(service.test_suite_http_port)
        self.service.wait_for_http_endpoint(f"http://127.0.0.1:{service.test_suite_http_port}/ping")

    def _stop_receiver(self, service):
        try:
            requests.post(f"http://127.0.0.1:{service.test_suite_http_port}/shutdown", timeout=2)
        except requests.RequestException:
            pass

    def start(self):
        self.service.start()
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()


def _read_fluent_bit_log(service):
    log_contents = ""

    if service.service.flb and service.service.flb.log_file:
        with open(service.service.flb.log_file, "r", encoding="utf-8", errors="replace") as file:
            log_contents = file.read()

    return log_contents


def _start_service_or_skip(service, required_properties):
    try:
        service.start()
    except FluentBitStartupError as error:
        log_contents = _read_fluent_bit_log(service)
        error_message = str(error)

        for property_name in required_properties:
            unknown_property_error = f"unknown configuration property '{property_name}'"
            if (unknown_property_error in error_message or
                    unknown_property_error in log_contents):
                try:
                    service.stop()
                except Exception:
                    LOGGER.debug("stop after skip failed", exc_info=True)
                pytest.skip(f"{property_name} is not supported by this Fluent Bit binary")

        try:
            service.stop()
        except Exception:
            LOGGER.debug("stop after startup failure failed", exc_info=True)
        raise


def _wait_for_accepted_request(service, payload, http_mode, timeout=10, interval=0.5):
    """Poll until 201, return the last response on timeout, and raise only if none arrived."""
    deadline = time.monotonic() + timeout
    last_error = None
    last_response = None

    while time.monotonic() < deadline:
        try:
            last_response = run_curl_request(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                payload=payload,
                headers=["Content-Type: application/json"],
                http_mode=http_mode,
            )
            if last_response["status_code"] == 201:
                return last_response
        except Exception as error:
            last_error = error

        time.sleep(interval)

    if last_response is not None:
        return last_response

    if last_error is not None:
        raise last_error

    return {"status_code": 0, "http_version": ""}


def _wait_for_rejected_request(service, payload, http_mode, timeout=10, interval=0.05):
    """Wait until the held connection is accepted and consumes the only slot."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            response = run_curl_request(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                payload=payload,
                headers=["Content-Type: application/json"],
                http_mode=http_mode,
            )
            if response["status_code"] != 201:
                return
        except Exception:
            return

        time.sleep(interval)

    raise AssertionError("held connection never occupied the configured connection slot")


def _wait_for_forwarded_message(service, message):
    def find_message():
        for payload in data_storage["payloads"]:
            for record in payload:
                if record.get("message") == message:
                    return record

        return None

    return service.service.wait_for_condition(
        find_message,
        timeout=10,
        interval=0.5,
        description=f"forwarded payload {message}",
    )


def test_in_http_max_connections_blocks_and_recovers():
    service = Service()
    accepted = {"status_code": 0}
    forwarded_payloads = []

    _start_service_or_skip(service, ["http_server.max_connections"])

    held_connection = None
    try:
        try:
            held_connection = socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=2)
            held_connection.settimeout(2)
            held_connection.sendall(b"POST / HTTP/1.1\r\n")

            _wait_for_rejected_request(
                service,
                payload='{"message":"max-connections-probe"}',
                http_mode="http1.1",
            )
        finally:
            if held_connection:
                held_connection.close()

        accepted = run_curl_request(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            payload='{"message":"max-connections"}',
            headers=["Content-Type: application/json"],
            http_mode="http1.1",
        )
        forwarded_payloads = _wait_for_forwarded_message(service, "max-connections")
    finally:
        service.stop()

    assert accepted["status_code"] == 201
    assert forwarded_payloads["message"] == "max-connections"


def test_in_http_idle_timeout_evicts_partial_request_connection():
    service = Service()
    response = {"status_code": 0}
    forwarded_payloads = []

    _start_service_or_skip(service, ["http_server.max_connections", "http_server.idle_timeout"])

    held_connection = None
    try:
        try:
            held_connection = socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=2)
            held_connection.settimeout(5)
            held_connection.sendall(b"POST / HTTP/1.1\r\n")

            _wait_for_rejected_request(
                service,
                payload='{"message":"idle-timeout-blocked"}',
                http_mode="http1.1",
            )

            response = _wait_for_accepted_request(
                service,
                payload='{"message":"idle-timeout-recovered"}',
                http_mode="http1.1",
            )
        finally:
            if held_connection:
                held_connection.close()
                held_connection = None
        forwarded_payloads = _wait_for_forwarded_message(
            service,
            "idle-timeout-recovered",
        )
    finally:
        service.stop()

    assert response["status_code"] == 201
    assert forwarded_payloads["message"] == "idle-timeout-recovered"


def test_in_http_idle_timeout_evicts_partial_http2_preface_connection():
    if not curl_supports_http2():
        pytest.skip("curl was built without HTTP/2 support")

    service = Service()
    response = {"status_code": 0, "http_version": ""}
    forwarded_payloads = []

    _start_service_or_skip(service, ["http_server.max_connections", "http_server.idle_timeout"])

    held_connection = None
    try:
        try:
            held_connection = socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=2)
            held_connection.settimeout(5)
            held_connection.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n")

            _wait_for_rejected_request(
                service,
                payload='{"message":"idle-timeout-http2-blocked"}',
                http_mode="http2-prior-knowledge",
            )

            response = _wait_for_accepted_request(
                service,
                payload='{"message":"idle-timeout-http2-recovered"}',
                http_mode="http2-prior-knowledge",
            )
        finally:
            if held_connection:
                held_connection.close()
                held_connection = None
        forwarded_payloads = _wait_for_forwarded_message(
            service,
            "idle-timeout-http2-recovered",
        )
    finally:
        service.stop()

    assert response["status_code"] == 201
    assert response["http_version"] == "2"
    assert forwarded_payloads["message"] == "idle-timeout-http2-recovered"
