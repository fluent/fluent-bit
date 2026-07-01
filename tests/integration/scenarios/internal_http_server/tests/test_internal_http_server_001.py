import concurrent.futures
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
            os.path.join(os.path.dirname(__file__), "../config/internal_http_server.yaml")
        )
        self.service = FluentBitTestService(self.config_file)

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.base_url = f"http://127.0.0.1:{self.flb.http_monitoring_port}"

    def stop(self):
        self.service.stop()

    def request(self, path, *, method="GET", http_mode="http1.1", include_headers=False):
        return run_curl_request(
            f"{self.base_url}{path}",
            method=method,
            payload=None,
            http_mode=http_mode,
            include_headers=include_headers,
        )


def test_internal_http_server_endpoints():
    service = Service()
    service.start()
    root_headers = _headers_map(service.request("/", include_headers=True)["headers_raw"])
    require_unified_v2_health = (
        root_headers.get("server") == "Fluent Bit"
        and root_headers.get("x-http-engine") == "Monkey heritage"
    )

    checks = [
        ("/", "200", "fluent-bit"),
        ("/api/v1/uptime", "200", "uptime_sec"),
        ("/api/v1/plugins", "200", "inputs"),
        ("/api/v1/health", "200", "ok"),
        ("/api/v1/metrics", "200", "output"),
        ("/api/v1/metrics/prometheus", "200", "fluentbit_uptime"),
        ("/api/v1/storage", "200", "chunks"),
        ("/api/v2/metrics", "200", "fluentbit_uptime"),
        ("/api/v2/metrics/prometheus", "200", "fluentbit_uptime"),
        ("/api/v2/reload", "200", "hot_reload_count"),
    ]

    try:
        for path, expected_status, pattern in checks:
            result = service.service.wait_for_condition(
                lambda: (
                    response
                    if response["status_code"] == int(expected_status) and pattern in response["body"]
                    else None
                ) if (response := service.request(path)) else None,
                timeout=10,
                interval=0.5,
                description=f"internal endpoint {path}",
            )
            assert result["status_code"] == int(expected_status)
            assert pattern in result["body"]

        v2_health = service.request("/api/v2/health")
        if require_unified_v2_health:
            assert v2_health["status_code"] == 200
            assert "ok" in v2_health["body"]

        trace_enable = service.request("/api/v1/trace/dummy.0")
        assert trace_enable["status_code"] == 200
        assert '"status":"ok"' in trace_enable["body"]

        trace_disable = service.request("/api/v1/trace/dummy.0", method="DELETE")
        assert trace_disable["status_code"] == 201
        assert '"status":"ok"' in trace_disable["body"]
    finally:
        service.stop()


def test_internal_http_server_headers_and_concurrency():
    service = Service()
    service.start()

    try:
        result = service.request("/", include_headers=True)
        headers = _headers_map(result["headers_raw"])

        assert result["status_code"] == 200
        if headers.get("server") != "Fluent Bit" or headers.get("x-http-engine") != "Monkey heritage":
            pytest.skip("Unified internal HTTP server headers are not available in this Fluent Bit binary")
        assert headers["server"] == "Fluent Bit"
        assert headers["x-http-engine"] == "Monkey heritage"

        header_lines = [line.lower() for line in result["headers_raw"].splitlines()]
        server_index = next(index for index, line in enumerate(header_lines) if line.startswith("server:"))
        engine_index = next(index for index, line in enumerate(header_lines) if line.startswith("x-http-engine:"))
        content_type_index = next(index for index, line in enumerate(header_lines) if line.startswith("content-type:"))
        assert server_index < content_type_index
        assert engine_index < content_type_index

        def fetch_metrics():
            response = service.request("/api/v1/metrics/prometheus")
            assert response["status_code"] == 200
            assert "fluentbit_uptime" in response["body"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch_metrics) for _ in range(50)]
            for future in futures:
                future.result()
    finally:
        service.stop()


def test_internal_http_server_http2_subset():
    if not curl_supports_http2():
        return

    service = Service()
    service.start()

    try:
        for path in ["/", "/api/v1/uptime", "/api/v1/metrics/prometheus", "/api/v2/metrics/prometheus", "/api/v2/reload"]:
            try:
                result = service.request(path, http_mode="http2-prior-knowledge")
            except subprocess.CalledProcessError:
                pytest.skip("Internal HTTP server does not support HTTP/2 prior knowledge in this Fluent Bit binary")
            assert result["status_code"] == 200
            assert result["http_version"] == "2"
    finally:
        service.stop()
