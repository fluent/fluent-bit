import concurrent.futures
import os
import time

from utils.http_matrix import run_curl_request
from utils.test_service import FluentBitTestService


class Service:
    """Run Fluent Bit with an exec input that curls the monitoring server."""

    def __init__(self):
        config_dir = os.path.dirname(__file__)
        self.config_file = os.path.abspath(
            os.path.join(config_dir, "../config/internal_http_server_exec_deadlock.yaml")
        )
        self.service = FluentBitTestService(self.config_file)

    def start(self):
        """Start Fluent Bit and record the monitoring base URL."""
        try:
            self.service.start()
        except Exception:
            self.service.stop()
            raise

        self.flb = self.service.flb
        self.base_url = f"http://127.0.0.1:{self.flb.http_monitoring_port}"

    def stop(self):
        """Stop Fluent Bit and restore the test environment."""
        self.service.stop()

    def request(self, path, *, method="GET", http_mode="http1.1"):
        """Issue a request against the internal monitoring server."""
        return run_curl_request(
            f"{self.base_url}{path}",
            method=method,
            http_mode=http_mode,
        )


def test_http_server_stays_responsive_after_exec_self_request():
    """The monitoring server must not share the blocked exec collector loop."""
    service = Service()
    service.start()

    try:
        result = service.request("/api/v1/uptime")
        assert result["status_code"] == 200
        assert "uptime_sec" in result["body"]

        time.sleep(2)

        endpoints = [
            ("/api/v1/uptime", "uptime_sec"),
            ("/api/v1/health", "ok"),
            ("/api/v1/metrics", "output"),
            ("/api/v1/metrics/prometheus", "fluentbit_uptime"),
            ("/api/v1/storage", "chunks"),
            ("/api/v2/metrics", "fluentbit_uptime"),
            ("/api/v2/metrics/prometheus", "fluentbit_uptime"),
        ]

        for path, pattern in endpoints:
            result = service.service.wait_for_condition(
                lambda: (
                    response
                    if response["status_code"] == 200 and pattern in response["body"]
                    else None
                ) if (response := service.request(path)) else None,
                timeout=10,
                interval=0.5,
                description=f"internal endpoint {path}",
            )
            assert result["status_code"] == 200
            assert pattern in result["body"]

        def fetch(endpoint):
            path, pattern = endpoint
            response = service.request(path)
            assert response["status_code"] == 200
            assert pattern in response["body"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
            futures = [executor.submit(fetch, endpoint) for endpoint in endpoints * 4]
            for future in futures:
                future.result()
    finally:
        service.stop()
