import os

import pytest
import requests
from server.http_server import configure_http_response, data_storage, http_server_run
from utils.data_utils import read_file
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file, with_receiver=False):
        if os.path.isabs(config_file):
            self.config_file = config_file
        else:
            self.config_file = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../config", config_file)
            )
        self.with_receiver = with_receiver
        if self.with_receiver:
            self.service = FluentBitTestService(
                self.config_file,
                data_storage=data_storage,
                data_keys=["payloads", "requests"],
                pre_start=self._start_receiver,
                post_stop=self._stop_receiver,
            )
        else:
            self.service = FluentBitTestService(self.config_file)

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

    def stop(self):
        self.service.stop()

    def wait_for_log_contains(self, text, timeout=10):
        return self.service.wait_for_condition(
            lambda: read_file(self.flb.log_file) if text in read_file(self.flb.log_file) else None,
            timeout=timeout,
            interval=0.5,
            description=f"log text {text!r}",
        )

    def wait_for_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["requests"] if len(data_storage["requests"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} outbound HTTP requests",
        )


def test_rate_gate_constructs_input_and_output_pipelines():
    service = Service("config_rate_gate_pipeline.yaml")
    try:
        service.start()
        service.wait_for_log_contains("dummy.0 paused (rate gate limit exceeded)")
        service.wait_for_log_contains("dummy.0 resume (rate gate)")
        service.wait_for_log_contains("hello from config_rate_gate integration")
    finally:
        service.stop()


def test_rate_gate_multi_output_fanout_with_retries():
    configure_http_response(status_code=500, body={"status": "retry"})
    service = Service("config_rate_gate_fanout_retry.yaml", with_receiver=True)
    try:
        service.start()

        requests_seen = service.wait_for_requests(1, timeout=20)
        assert len(requests_seen) >= 1

        service.wait_for_log_contains("dummy.0 paused (rate gate limit exceeded)")
    finally:
        service.stop()


@pytest.mark.parametrize(
    "config_file, expected_message",
    [
        ("config_rate_gate_steady_overrate.yaml", "steady overrate"),
        ("config_rate_gate_burst_recovery.yaml", "burst and recovery"),
        ("config_rate_gate_memrb.yaml", "memrb path"),
        ("config_rate_gate_filesystem.yaml", "filesystem path"),
    ],
)
def test_rate_gate_rollout_scenarios(config_file, expected_message):
    service = Service(config_file)
    try:
        service.start()
    except FluentBitStartupError:
        if config_file == "config_rate_gate_filesystem.yaml":
            pytest.skip("filesystem storage backend is unavailable in this test environment")
        raise

    try:
        service.wait_for_log_contains("dummy.0 paused (rate gate limit exceeded)")
        service.wait_for_log_contains(expected_message)
    finally:
        service.stop()
