import os
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager
from utils.input_pause_resume import (
    assert_connection_closed,
    is_valgrind,
    open_partial_http_request,
    open_stalled_tcp_connection,
    wait_for_input_pause_state,
)
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

    def start(self, *, start_sender=True):
        self._set_env("PROM_RW_RECEIVER_PORT", find_available_port())
        self._set_env("CERTIFICATE_TEST", self.tls_crt_file)
        self._set_env("PRIVATE_KEY_TEST", self.tls_key_file)

        self.receiver = FluentBitManager(self.receiver_config)
        self.receiver.start()
        self.receiver_port = int(os.environ["PROM_RW_RECEIVER_PORT"])
        self.wait_for_log(self.receiver.log_file, f"listening on 127.0.0.1:{self.receiver_port}")

        if start_sender:
            self.start_sender()

    def start_sender(self):
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

    def wait_for_log_count(self, path, pattern, minimum, *, timeout=20, interval=0.5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            count = _read_file(path).count(pattern)
            if count >= minimum:
                return count
            time.sleep(interval)
        raise TimeoutError(
            f"Timed out waiting for {minimum} occurrences of {pattern} in {path}"
        )


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


@pytest.mark.parametrize(
    "receiver_config",
    [
        "receiver_pause_resume.yaml",
        "receiver_pause_resume_workers.yaml",
    ],
    ids=["single_listener", "workers_4"],
)
def test_in_prometheus_remote_write_pause_resume_and_shutdown(receiver_config):
    service = Service(
        receiver_config,
        "sender_cleartext.yaml",
    )
    stalled_connections = []
    shutdown_connections = []
    paused_connection = None

    try:
        service.start(start_sender=False)
        for _ in range(8):
            stalled_connections.append(
                open_partial_http_request(
                    "127.0.0.1",
                    service.receiver_port,
                )
            )

        service.start_sender()
        wait_for_input_pause_state(
            service.receiver,
            "prometheus_remote_write.0",
            True,
            timeout=30,
        )

        for connection in stalled_connections:
            assert_connection_closed(connection)

        paused_connection = open_stalled_tcp_connection(
            "127.0.0.1",
            service.receiver_port,
        )
        assert_connection_closed(paused_connection)

        service.sender.stop()
        service.sender = None

        wait_for_input_pause_state(
            service.receiver,
            "prometheus_remote_write.0",
            False,
            timeout=30,
        )
        service.wait_for_log(
            service.receiver.log_file,
            "fluentbit_input_metrics_scrapes_total",
            timeout=30,
            interval=0.5,
        )

        delivered_before_resume = _read_file(service.receiver.log_file).count(
            "fluentbit_input_metrics_scrapes_total"
        )
        for _ in range(8):
            shutdown_connections.append(
                open_partial_http_request(
                    "127.0.0.1",
                    service.receiver_port,
                )
            )

        service.start_sender()
        service.wait_for_log_count(
            service.receiver.log_file,
            "fluentbit_input_metrics_scrapes_total",
            delivered_before_resume + 1,
            timeout=30,
            interval=0.5,
        )
        wait_for_input_pause_state(
            service.receiver,
            "prometheus_remote_write.0",
            True,
            timeout=30,
        )

        for connection in shutdown_connections:
            assert_connection_closed(connection)

        shutdown_started = time.monotonic()
        service.stop()
        shutdown_elapsed = time.monotonic() - shutdown_started
        assert shutdown_elapsed < (30 if is_valgrind() else 8)
    finally:
        for connection in stalled_connections:
            connection.close()
        for connection in shutdown_connections:
            connection.close()
        if paused_connection is not None:
            paused_connection.close()
        service.stop()
