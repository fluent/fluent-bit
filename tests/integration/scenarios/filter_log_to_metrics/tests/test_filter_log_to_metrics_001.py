import os
import time

from utils.http_matrix import run_curl_request
from utils.test_service import FluentBitTestService


COUNTER_NAME = "nginx_request_nginx_request_status_code_total"
COUNTER_LABELS = (
    'request_method="GET"',
    'status="200"',
    'host="example.com"',
    'endpoint="/"',
    'hostname="host-a"',
)


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.service = FluentBitTestService(self.config_file, pre_start=self._pre_start)

    def _pre_start(self, service):
        self.exporter_port = service.allocate_port_env("EXPORTER_PORT")

    def start(self):
        self.service.start()
        self.base_url = f"http://127.0.0.1:{self.exporter_port}"

    def stop(self):
        self.service.stop()

    def scrape_metrics(self):
        return run_curl_request(f"{self.base_url}/metrics", method="GET", http_mode="http1.1")


def _counter_value(metrics_text):
    for line in metrics_text.splitlines():
        if not line.startswith(f"{COUNTER_NAME}{{"):
            continue
        if all(label in line for label in COUNTER_LABELS):
            return float(line.rsplit(" ", 1)[1])
    return None


def test_log_to_metrics_counter_timer_emits_repeated_metric_chunks():
    service = Service("counter_timer_prometheus.yaml")
    service.start()

    try:
        first_value = service.service.wait_for_condition(
            lambda: _counter_value(service.scrape_metrics()["body"]),
            timeout=15,
            interval=1,
            description="initial log_to_metrics counter scrape",
        )

        second_value = service.service.wait_for_condition(
            lambda: (
                value
                if (value := _counter_value(service.scrape_metrics()["body"])) is not None
                and value > first_value
                else None
            ),
            timeout=15,
            interval=1,
            description="increasing log_to_metrics counter scrape",
        )

        assert second_value > first_value
        time.sleep(3)
    finally:
        service.stop()
