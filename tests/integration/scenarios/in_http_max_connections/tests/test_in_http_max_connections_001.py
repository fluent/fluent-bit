import os
import socket

import pytest
import requests

from server.http_server import data_storage, http_server_run
from utils.fluent_bit_manager import FluentBitStartupError
from utils.http_matrix import run_curl_request
from utils.test_service import FluentBitTestService


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


def test_in_http_max_connections_blocks_and_recovers():
    service = Service()
    try:
        service.start()
    except FluentBitStartupError as error:
        log_contents = ""
        if service.service.flb and service.service.flb.log_file:
            with open(service.service.flb.log_file, "r", encoding="utf-8", errors="replace") as file:
                log_contents = file.read()
        if "http_server.max_connections" in str(error) or "unknown configuration property 'http_server.max_connections'" in log_contents:
            pytest.skip("http_server.max_connections is not supported by this Fluent Bit binary")
        raise

    held_connection = None
    try:
        held_connection = socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=2)
        held_connection.settimeout(2)

        overflow_rejected = False
        try:
            response = run_curl_request(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                payload='{"message":"max-connections"}',
                headers=["Content-Type: application/json"],
                http_mode="http1.1",
            )
            overflow_rejected = response["status_code"] != 201
        except Exception:
            overflow_rejected = True

        assert overflow_rejected
    finally:
        if held_connection:
            held_connection.close()

    accepted = run_curl_request(
        f"http://127.0.0.1:{service.flb_listener_port}/",
        payload='{"message":"max-connections"}',
        headers=["Content-Type: application/json"],
        http_mode="http1.1",
    )
    forwarded_payloads = service.service.wait_for_condition(
        lambda: data_storage["payloads"] if data_storage["payloads"] else None,
        timeout=10,
        interval=0.5,
        description="forwarded max-connections payload",
    )

    service.stop()

    assert accepted["status_code"] == 201
    assert forwarded_payloads[0][0]["message"] == "max-connections"
