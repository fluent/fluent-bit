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
        http_server_run(service.test_suite_http_port, reset_state=False)
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
        service.wait_for_log_contains("retry in", timeout=20)
        service.wait_for_log_contains("dummy.0 resume (rate gate)", timeout=20)
    finally:
        service.stop()


def test_rate_gate_recovers_after_input_becomes_idle():
    service = Service("config_rate_gate_idle_recovery.yaml")
    try:
        service.start()
        service.wait_for_log_contains("dummy.0 paused (rate gate limit exceeded)")
        service.wait_for_log_contains("dummy.0 resume (rate gate)", timeout=10)
    finally:
        service.stop()


def test_rate_gate_observes_throttle_deferred_routes():
    service = Service("config_rate_gate_output_throttle.yaml", with_receiver=True)
    configure_http_response(status_code=429, headers=[("Retry-After", "5")])

    def gauge(metrics, name, input_name):
        series = f'fluentbit_input_rate_gate_{name}{{name="{input_name}"}} '
        return next(float(line.split()[1]) for line in metrics.splitlines()
                    if line.startswith(series))

    def sample():
        response = requests.get(metrics_url, timeout=2)
        response.raise_for_status()
        return response.text

    def deferred_metrics():
        metrics = sample()
        if gauge(metrics, "deferred_routes", "routed") > 0:
            return metrics
        return None

    try:
        service.start()
        metrics_url = (
            f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus"
        )
        service.wait_for_requests(1)
        service.service.wait_for_http_endpoint(metrics_url)
        metrics = service.service.wait_for_condition(
            deferred_metrics, interval=0.1, description="deferred routes for the routed input"
        )
        assert gauge(metrics, "retry_attempts", "routed") == 0
        assert gauge(metrics, "deferred_routes", "independent") == 0
        offset = len(read_file(service.flb.log_file))

        def new_deliveries():
            logs = read_file(service.flb.log_file)[offset:]
            if "independent input" in logs and "fanout during cooldown" in logs:
                return logs
            return None

        logs = service.service.wait_for_condition(
            new_deliveries, interval=0.1, description="both inputs deliver during cooldown",
        )
        assert gauge(sample(), "deferred_routes", "routed") > 0
        assert "independent paused" not in logs
        attempts = list(data_storage["requests"])
        configure_http_response(status_code=200, headers=[])
        service.wait_for_requests(len(attempts) + 1)
        service.service.wait_for_condition(
            lambda: gauge(sample(), "deferred_routes", "routed") == 0,
            interval=0.1,
            description="deferred routes to drain after cooldown",
        )
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
        service.wait_for_log_contains("dummy.0 resume (rate gate)", timeout=20)
        service.wait_for_log_contains(expected_message)
    finally:
        service.stop()
