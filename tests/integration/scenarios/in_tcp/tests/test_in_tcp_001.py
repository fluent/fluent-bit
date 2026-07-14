import os
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from server.http_server import data_storage, http_server_run
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        test_path = os.path.dirname(os.path.abspath(__file__))
        self.parsers_file = os.environ.get("FLUENT_BIT_PARSERS_FILE") or os.path.abspath(
            os.path.join(test_path, "../../../../../conf/parsers.conf")
        )
        cert_dir = os.path.abspath(os.path.join(test_path, "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads"],
            extra_env={
                "PARSERS_FILE_TEST": self.parsers_file,
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

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
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def wait_for_single_record(self, timeout=10):
        payloads = self.service.wait_for_condition(
            lambda: data_storage["payloads"] if data_storage["payloads"] else None,
            timeout=timeout,
            interval=0.5,
            description="forwarded TCP payloads",
        )

        assert len(payloads) == 1
        assert isinstance(payloads[0], list)
        assert len(payloads[0]) == 1

        return payloads[0][0]

    def flattened_records(self):
        records = []
        for payload in data_storage["payloads"]:
            if isinstance(payload, list):
                records.extend(payload)
            elif payload is not None:
                records.append(payload)
        return records

    def wait_for_record_count(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: self.flattened_records() if len(self.flattened_records()) >= minimum_count else None,
            timeout=timeout,
            interval=0.2,
            description=f"{minimum_count} forwarded TCP payloads",
        )

    def wait_for_log_message(self, pattern, timeout=10, interval=0.25):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.flb and self.flb.log_file and os.path.exists(self.flb.log_file):
                with open(self.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
                    if pattern in log_file.read():
                        return True
            time.sleep(interval)
        raise TimeoutError(f"Timed out waiting for log pattern: {pattern}")


def _send_line(port, line):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(line.encode("utf-8"))
        sock.shutdown(socket.SHUT_WR)


def _drop_partial_connection(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(payload.encode("utf-8"))


def _send_tls_line(port, line, cafile):
    context = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
            tls_sock.sendall(line.encode("utf-8"))
            tls_sock.shutdown(socket.SHUT_WR)


def _drop_raw_tls_connection(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(payload)


def test_in_tcp_parser_json_success():
    service = Service("in_tcp_parser_json.yaml")
    service.start()

    try:
        _send_line(service.flb_listener_port, '{"message":"hello","value":42}\n')
        record = service.wait_for_single_record()
    finally:
        service.stop()

    assert record["message"] == "hello"
    assert record["value"] == 42


def test_in_tcp_parser_json_fallback_to_log():
    service = Service("in_tcp_parser_json.yaml")
    service.start()

    try:
        _send_line(service.flb_listener_port, 'not-json\n')
        record = service.wait_for_single_record()
    finally:
        service.stop()

    assert "log" in record
    assert record["log"].strip() == "not-json"


def test_in_tcp_parser_json_workers_concurrent_records():
    total_records = 16
    service = Service("in_tcp_parser_json_workers.yaml")
    service.start()

    try:
        service.wait_for_log_message("with 4 workers", timeout=10)
        with ThreadPoolExecutor(max_workers=total_records) as executor:
            list(executor.map(
                lambda i: _send_line(service.flb_listener_port,
                                     f'{{"message":"worker-{i}","value":{i}}}\n'),
                range(total_records),
            ))
        records = service.wait_for_record_count(total_records, timeout=20)
    finally:
        service.stop()

    values = sorted(record["value"] for record in records)
    assert values == list(range(total_records))


def test_in_tcp_workers_drop_partial_connections_and_continue():
    dropped_connections = 8
    valid_records = 8
    service = Service("in_tcp_parser_json_workers.yaml")
    service.start()

    try:
        service.wait_for_log_message("with 4 workers", timeout=10)
        with ThreadPoolExecutor(max_workers=dropped_connections) as executor:
            list(executor.map(
                lambda i: _drop_partial_connection(service.flb_listener_port,
                                                   f'{{"message":"partial-{i}"'),
                range(dropped_connections),
            ))

        with ThreadPoolExecutor(max_workers=valid_records) as executor:
            list(executor.map(
                lambda i: _send_line(service.flb_listener_port,
                                     f'{{"message":"valid-{i}","value":{i}}}\n'),
                range(valid_records),
            ))
        records = service.wait_for_record_count(valid_records, timeout=20)
    finally:
        service.stop()

    values = sorted(record["value"] for record in records)
    assert values == list(range(valid_records))


def test_in_tcp_tls_workers_concurrent_records():
    total_records = 16
    service = Service("in_tcp_parser_json_tls_workers.yaml")
    service.start()

    try:
        service.wait_for_log_message("with 4 workers", timeout=10)
        with ThreadPoolExecutor(max_workers=total_records) as executor:
            list(executor.map(
                lambda i: _send_tls_line(service.flb_listener_port,
                                         f'{{"message":"tls-worker-{i}","value":{i}}}\n',
                                         service.tls_crt_file),
                range(total_records),
            ))
        records = service.wait_for_record_count(total_records, timeout=20)
    finally:
        service.stop()

    values = sorted(record["value"] for record in records)
    assert values == list(range(total_records))


def test_in_tcp_tls_workers_drop_bad_handshakes_and_continue():
    dropped_connections = 8
    valid_records = 8
    service = Service("in_tcp_parser_json_tls_workers.yaml")
    service.start()

    try:
        service.wait_for_log_message("with 4 workers", timeout=10)
        with ThreadPoolExecutor(max_workers=dropped_connections) as executor:
            list(executor.map(
                lambda i: _drop_raw_tls_connection(service.flb_listener_port,
                                                   f"not-tls-{i}".encode("utf-8")),
                range(dropped_connections),
            ))

        with ThreadPoolExecutor(max_workers=valid_records) as executor:
            list(executor.map(
                lambda i: _send_tls_line(service.flb_listener_port,
                                         f'{{"message":"valid-tls-{i}","value":{i}}}\n',
                                         service.tls_crt_file),
                range(valid_records),
            ))
        records = service.wait_for_record_count(valid_records, timeout=20)
    finally:
        service.stop()

    values = sorted(record["value"] for record in records)
    assert values == list(range(valid_records))
