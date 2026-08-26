import contextlib
import http.server
import os
import threading
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port


PROM_RW_CASES = [
    {
        "id": "http1_cleartext",
        "receiver_config": {
            False: "receiver_http1_cleartext.yaml",
            True: "receiver_http1_cleartext_workers.yaml",
        },
        "sender_config": "sender_cleartext.yaml",
    },
    {
        "id": "http2_cleartext",
        "receiver_config": {
            False: "receiver_http2_cleartext.yaml",
            True: "receiver_http2_cleartext_workers.yaml",
        },
        "sender_config": "sender_cleartext.yaml",
    },
    {
        "id": "http1_tls",
        "receiver_config": {
            False: "receiver_http1_tls.yaml",
            True: "receiver_http1_tls_workers.yaml",
        },
        "sender_config": "sender_tls.yaml",
    },
    {
        "id": "http2_tls",
        "receiver_config": {
            False: "receiver_http2_tls.yaml",
            True: "receiver_http2_tls_workers.yaml",
        },
        "sender_config": "sender_tls.yaml",
    },
]

FRESH_METRIC = "backport_fresh_metric"
STALE_METRIC = "backport_stale_metric"


def _read_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as file:
        return file.read()


class Service:
    def __init__(self, receiver_config, sender_config):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))
        self.receiver_config = os.path.join(base_dir, receiver_config)
        self.sender_config = os.path.join(base_dir, sender_config)
        cert_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.receiver = None
        self.sender = None
        self._previous_env = {}

    def _set_env(self, key, value):
        self._previous_env.setdefault(key, os.environ.get(key))
        os.environ[key] = str(value)

    def _restore_env(self):
        for key, value in self._previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._previous_env.clear()

    def start(self):
        self._set_env("PROM_RW_RECEIVER_PORT", find_available_port())
        self._set_env("CERTIFICATE_TEST", self.tls_crt_file)
        self._set_env("PRIVATE_KEY_TEST", self.tls_key_file)

        self.receiver = FluentBitManager(self.receiver_config)
        self.receiver.start()
        self.receiver_port = int(os.environ["PROM_RW_RECEIVER_PORT"])
        self.wait_for_log(self.receiver.log_file, f"listening on 127.0.0.1:{self.receiver_port}")

        self.sender = FluentBitManager(self.sender_config)
        self.sender.start()

    def stop(self):
        try:
            if self.sender:
                self.sender.stop()
            if self.receiver:
                self.receiver.stop()
        finally:
            self._restore_env()

    def wait_for_log(self, path, pattern, *, timeout=20, interval=0.5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            contents = _read_file(path)
            if pattern in contents:
                return contents
            time.sleep(interval)
        raise TimeoutError(f"Timed out waiting for {pattern} in {path}")


class _PrometheusSourceHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        now_ms = int(time.time() * 1000)
        body = (
            f"# TYPE {FRESH_METRIC} gauge\n"
            f"{FRESH_METRIC} 2 {now_ms}\n"
            f"# TYPE {STALE_METRIC} gauge\n"
            f"{STALE_METRIC} 1 {now_ms - 7200000}\n"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


@contextlib.contextmanager
def _run_prometheus_source():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PrometheusSourceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("workers_enabled", [False, True], ids=["single_listener", "workers_4"])
@pytest.mark.parametrize("case", PROM_RW_CASES, ids=[case["id"] for case in PROM_RW_CASES])
def test_in_prometheus_remote_write_matrix(case, workers_enabled):
    service = Service(case["receiver_config"][workers_enabled], case["sender_config"])
    service.start()

    try:
        if workers_enabled:
            service.wait_for_log(
                service.receiver.log_file,
                "with 4 workers",
                timeout=20,
                interval=0.5,
            )
        receiver_log = service.wait_for_log(
            service.receiver.log_file,
            "fluentbit_input_metrics_scrapes_total",
            timeout=40,
            interval=1,
        )
        assert f"listening on 127.0.0.1:{service.receiver_port}" in receiver_log
        assert "fluentbit_input_metrics_scrapes_total" in receiver_log
    finally:
        service.stop()


def test_prometheus_remote_write_expires_stale_metrics():
    with _run_prometheus_source() as source_port:
        previous_source_port = os.environ.get("PROM_SCRAPE_SOURCE_PORT")
        os.environ["PROM_SCRAPE_SOURCE_PORT"] = str(source_port)
        service = Service("receiver_http1_cleartext.yaml", "sender_stale_metrics.yaml")

        try:
            service.start()
            receiver_log = service.wait_for_log(
                service.receiver.log_file,
                FRESH_METRIC,
                timeout=30,
                interval=1,
            )
            assert STALE_METRIC not in receiver_log
        finally:
            service.stop()
            if previous_source_port is None:
                os.environ.pop("PROM_SCRAPE_SOURCE_PORT", None)
            else:
                os.environ["PROM_SCRAPE_SOURCE_PORT"] = previous_source_port
