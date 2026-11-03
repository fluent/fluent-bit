import concurrent.futures
import json
import os
import socket
import subprocess

import pytest
import yaml
from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError
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
    def __init__(self, config_file=None):
        self.config_file = config_file or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config/internal_http_server.yaml")
        )
        self.service = FluentBitTestService(self.config_file)

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.base_url = f"http://127.0.0.1:{self.flb.http_monitoring_port}"

    def stop(self):
        self.service.stop()

    def request(self, path, *, method="GET", http_mode="http1.1", include_headers=False,
                payload=None):
        headers = None
        if payload is not None:
            headers = ["Content-Type: application/json"]
        return run_curl_request(
            f"{self.base_url}{path}",
            method=method,
            payload=payload,
            headers=headers,
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


def test_internal_http_server_trace_rejects_unsafe_outputs(tmp_path):
    service = Service()
    service.start()

    target_dir = tmp_path / "aws"
    rejected = [
        {
            "output": "file",
            "prefix": "/bin/true ",
            "params": {
                "path": str(target_dir),
                "file": "config",
                "format": "template",
                "template": "credential_process = {trace_id}",
                "mkdir": "true",
            },
        },
        {"output": "s3", "params": {"bucket": "x", "region": "us-east-1"}},
        {"output": "http", "params": {"host": "127.0.0.1", "port": "9"}},
        {"output": "stdout://127.0.0.1"},
        {"output": "CALYPTIA", "params": {"format": "json"}},
        {"output": "Stdout"},
        {"output": "stdout", "params": {"workers": "64"}},
        {"output": "stdout", "params": {"match": "*"}},
    ]

    try:
        for body in rejected:
            result = service.request("/api/v1/trace/dummy.0", method="POST",
                                     payload=json.dumps(body))
            assert result["status_code"] == 403, body
            assert '"status":"error"' in result["body"]

            result = service.request("/api/v1/traces/", method="POST",
                                     payload=json.dumps({"inputs": ["dummy.0"], **body}))
            assert result["status_code"] == 200
            assert '"returncode":403' in result["body"], body

        assert not target_dir.exists()

        result = service.request("/api/v1/trace/dummy.0", method="POST",
                                 payload=json.dumps({"output": "stdout",
                                                     "prefix": "trace.",
                                                     "params": {"format": "json"}}))
        assert result["status_code"] == 200
        assert '"status":"ok"' in result["body"]

        result = service.request("/api/v1/trace/dummy.0", method="DELETE")
        assert result["status_code"] == 201
    finally:
        service.stop()


def test_internal_http_server_trace_rejects_duplicate_and_invalid_options():
    service = Service()
    service.start()
    # Raw JSON preserves duplicate members, including after a populated params map.
    invalid = [
        '"params":{"format":"json"},"params":{}',
        '"params":{"format":"json"},"params":{"json_date_key":"date"}',
        '"params":{"format":"json","FORMAT":"json_lines"}',
        '"prefix":"first","prefix":"second"',
        '"output":"stdout","output":"stdout"',
        '"limit":{"count":1},"limit":{"count":2}',
        '"params":{"format":"json","json_date_key":42}',
        '"params":[]',
        '"prefix":false',
        '"output":null',
        '"output":"stdout\\u0000file"',
        '"params":{"format\\u0000ignored":"json"}',
        '"limit":{"count":2147483648}',
        '"limit":{"count":0}',
        '"limit":{"seconds":0}',
    ]
    try:
        for fields in invalid:
            for path, inputs in [
                ("/api/v1/trace/dummy.0", ""),
                ("/api/v1/traces/", '"inputs":["dummy.0"],'),
            ]:
                result = service.request(path, method="POST", payload="{" + inputs + fields + "}")
                assert result["status_code"] == 400, (fields, result)
                assert json.loads(result["body"])["status"] == "error"
        # The same process must still accept valid options after all error cleanups.
        result = service.request("/api/v1/traces/", method="POST", payload=json.dumps({
            "inputs": ["dummy.0"], "params": {"format": "json"}, "prefix": "trace.",
        }))
        assert result["status_code"] == 200
        assert json.loads(result["body"])["inputs"]["dummy.0"]["status"] == "ok"
        assert service.request("/api/v1/trace/dummy.0", method="DELETE")["status_code"] == 201
    finally:
        service.stop()


def test_internal_http_server_trace_batch_bounds_and_validation():
    service = Service()
    service.start()
    invalid = [
        '{"inputs":["dummy.0","dummy.0"]}',
        '{"inputs":["missing","missing"]}',
        '{"inputs":["dummy.0",42]}',
        '{"inputs":[""]}',
        '{"inputs":["dummy.0\\u0000suffix"]}',
        '{"inputs":[],"inputs":["dummy.0"]}',
        '{"inputs_suffix":["dummy.0"]}',
        json.dumps({"inputs": [f"missing.{i}" for i in range(65)]}),
    ]
    try:
        for payload in invalid:
            result = service.request("/api/v1/traces/", method="POST", payload=payload)
            assert result["status_code"] == 400, (payload, result)
            assert json.loads(result["body"])["status"] == "error"

        names = [f"missing.{i}" for i in range(64)]
        result = service.request("/api/v1/traces/", method="POST", payload=json.dumps({
            "inputs": names, "params": {"format": "json"},
        }))
        assert result["status_code"] == 200
        results = json.loads(result["body"])["inputs"]
        assert set(results) == set(names)
        assert all(item["returncode"] == 404 for item in results.values())
    finally:
        service.stop()


def test_internal_http_server_trace_batch_reuses_options(tmp_path):
    default_service = Service()
    with open(default_service.config_file, encoding="utf-8") as stream:
        config = yaml.safe_load(stream)
    config["pipeline"]["inputs"][0]["alias"] = "source"
    config["pipeline"]["inputs"].append({"name": "dummy", "tag": "second"})
    config_file = tmp_path / "trace-batch.yaml"
    config_file.write_text(yaml.safe_dump(config), encoding="utf-8")
    service = Service(str(config_file))
    service.start()
    try:
        result = service.request("/api/v1/traces/", method="POST", payload=json.dumps({
            "inputs": ["dummy.0", "source"], "params": {"format": "json"},
        }))
        assert result["status_code"] == 400

        for _ in range(3):
            result = service.request("/api/v1/traces/", method="POST", payload=json.dumps({
                "inputs": ["source", "dummy.1"],
                "params": {"format": "json", "json_date_key": "date"},
                "prefix": "batch.",
            }))
            assert result["status_code"] == 200
            results = json.loads(result["body"])["inputs"]
            assert set(results) == {"source", "dummy.1"}
            assert all(item["status"] == "ok" for item in results.values())
            result = service.request("/api/v1/traces/", method="DELETE", payload=json.dumps({
                "inputs": ["source", "dummy.1"],
            }))
            assert result["status_code"] == 200

        # Exercise limit parsing and setup without racing automatic expiration
        # against the explicit DELETE used to clean up this API test.
        for limit in [{"count": 1000}, {"seconds": 60}]:
            result = service.request("/api/v1/trace/source", method="POST", payload=json.dumps({
                "params": {"format": "json"}, "limit": limit,
            }))
            assert result["status_code"] == 200
            assert service.request("/api/v1/trace/source", method="DELETE")["status_code"] == 201
    finally:
        service.stop()


def test_internal_http_server_trace_time_limit_keeps_input_running():
    service = Service()
    service.start()
    try:
        result = service.request("/api/v1/trace/dummy.0", method="POST", payload=json.dumps({
            "prefix": "limit-lock.", "params": {"format": "json"}, "limit": {"seconds": 60},
        }))
        assert result["status_code"] == 200

        def second_chunk_traced():
            with open(service.flb.log_file, encoding="utf-8", errors="replace") as stream:
                return "limit-lock.1" in stream.read()

        # Two traced chunks prove ingestion continues after the first check of
        # a time limit that has not expired. A leaked mutex stalls that path.
        service.service.wait_for_condition(
            second_chunk_traced, timeout=10, interval=0.1,
            description="second chunk traced before time limit expires",
        )
        result = service.request("/api/v1/trace/dummy.0", method="DELETE")
        assert result["status_code"] == 201
        assert service.request("/api/v1/uptime")["status_code"] == 200
    finally:
        service.stop()


def test_internal_http_server_trace_option_byte_bounds():
    service = Service()
    service.start()
    try:
        for path, inputs in [
            ("/api/v1/trace/missing", {}),
            ("/api/v1/traces/", {"inputs": ["missing"]}),
        ]:
            # Include the key bytes in the limit. Missing inputs avoid starting a
            # trace pipeline while still exercising option parsing and cleanup.
            for extra in [0, 1]:
                body = {**inputs, "params": {"json_date_key": "x" * (65536 - 13 + extra)}}
                result = service.request(path, method="POST", payload=json.dumps(body))
                if extra:
                    assert result["status_code"] == 400, result
                elif inputs:
                    assert result["status_code"] == 200
                    assert json.loads(result["body"])["inputs"]["missing"]["returncode"] == 404
                else:
                    assert result["status_code"] == 404, result

            body = {**inputs, "params": {f"key{i}": "value" for i in range(65)}}
            result = service.request(path, method="POST", payload=json.dumps(body))
            assert result["status_code"] == 400, result
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


def test_internal_http_server_bind_failure_fails_startup(monkeypatch):
    config_file = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../config/internal_http_server.yaml")
    )
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    fluent_bit = FluentBitManager(config_file)

    monkeypatch.setenv("FLUENT_BIT_HTTP_MONITORING_PORT", str(port))

    def use_occupied_monitoring_port(_env_var_name, starting_port=0):
        fluent_bit.http_monitoring_port = str(port)

    fluent_bit.set_http_monitoring_port = use_occupied_monitoring_port

    try:
        with pytest.raises(FluentBitStartupError, match="exited early with code"):
            fluent_bit.start()
        assert fluent_bit.process.returncode != 0
    finally:
        holder.close()
        fluent_bit.stop()
