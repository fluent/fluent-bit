import os
import time

from utils.http_matrix import run_curl_request
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config/internal_http_server_exec_deadlock.yaml")
        )
        self.service = FluentBitTestService(self.config_file)

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.base_url = f"http://127.0.0.1:{self.flb.http_monitoring_port}"

    def stop(self):
        self.service.stop()

    def request(self, path, *, method="GET", http_mode="http1.1"):
        return run_curl_request(
            f"{self.base_url}{path}",
            method=method,
            http_mode=http_mode,
        )


def test_http_server_responsive_after_exec_self_request():
    """The built-in HTTP server must remain responsive after the exec input
    plugin makes an HTTP request to it.  Before the fix, the exec child
    process (curl) and the HTTP server shared the same event loop, causing
    a deadlock that made the server permanently unresponsive."""

    service = Service()
    service.start()

    try:
        # Verify the server works before exec fires
        result = service.request("/api/v1/uptime")
        assert result["status_code"] == 200
        assert "uptime_sec" in result["body"]

        # Wait for exec to fire (interval_sec=1) plus a small buffer
        time.sleep(2)

        # Verify the server is still responsive after exec has fired
        result = service.service.wait_for_condition(
            lambda: (
                response
                if response["status_code"] == 200 and "uptime_sec" in response["body"]
                else None
            ) if (response := service.request("/api/v1/uptime")) else None,
            timeout=10,
            interval=1,
            description="HTTP server responsive after exec self-request",
        )
        assert result["status_code"] == 200
        assert "uptime_sec" in result["body"]
    finally:
        service.stop()
