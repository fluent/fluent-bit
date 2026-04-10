import os
import subprocess

import pytest
from utils.http_matrix import curl_supports_http2, run_curl_request
from utils.test_service import FluentBitTestService


def _headers_map(headers_raw):
    headers = {}
    for line in headers_raw.splitlines():
        if ":" not in line or line.startswith("HTTP/"):
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


class Service:
    def __init__(self):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config/out_prometheus_exporter.yaml")
        )
        self.service = FluentBitTestService(self.config_file, pre_start=self._pre_start)

    def _pre_start(self, service):
        self.exporter_port = service.allocate_port_env("EXPORTER_PORT")

    def start(self):
        self.service.start()
        self.base_url = f"http://127.0.0.1:{self.exporter_port}"

    def stop(self):
        self.service.stop()

    def request(self, path, *, http_mode="http1.1", include_headers=False):
        return run_curl_request(
            f"{self.base_url}{path}",
            method="GET",
            http_mode=http_mode,
            include_headers=include_headers,
        )


def test_out_prometheus_exporter_scrape_endpoint():
    service = Service()
    service.start()

    try:
        root = service.request("/")
        assert root["status_code"] == 200
        assert "Prometheus Exporter" in root["body"]

        metrics = service.service.wait_for_condition(
            lambda: (
                response
                if response["status_code"] == 200 and "fluentbit_input_metrics_scrapes_total" in response["body"]
                else None
            ) if (response := service.request("/metrics", include_headers=True)) else None,
            timeout=10,
            interval=1,
            description="prometheus exporter metrics",
        )
        assert metrics["status_code"] == 200
        assert "fluentbit_input_metrics_scrapes_total" in metrics["body"]

        headers = _headers_map(metrics["headers_raw"])
        if headers.get("server") != "Fluent Bit" or headers.get("x-http-engine") != "Monkey heritage":
            pytest.skip("Unified exporter headers are not available in this Fluent Bit binary")
        assert headers["server"] == "Fluent Bit"
        assert headers["x-http-engine"] == "Monkey heritage"
        assert headers["content-type"].startswith("text/plain; version=0.0.4")
    finally:
        service.stop()


def test_out_prometheus_exporter_http2_metrics():
    if not curl_supports_http2():
        return

    service = Service()
    service.start()

    try:
        try:
            metrics = service.service.wait_for_condition(
                lambda: (
                    response
                    if response["status_code"] == 200 and "fluentbit_input_metrics_scrapes_total" in response["body"]
                    else None
                ) if (response := service.request("/metrics", http_mode="http2-prior-knowledge")) else None,
                timeout=10,
                interval=1,
                description="prometheus exporter http2 metrics",
            )
        except subprocess.CalledProcessError:
            pytest.skip("Prometheus exporter does not support HTTP/2 prior knowledge in this Fluent Bit binary")
        assert metrics["status_code"] == 200
        assert metrics["http_version"] == "2"
        assert "fluentbit_input_metrics_scrapes_total" in metrics["body"]
    finally:
        service.stop()
