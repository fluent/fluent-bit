import os
import socket
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
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads"],
            extra_env={
                "PARSERS_FILE_TEST": self.parsers_file,
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
            description="forwarded UDP payloads",
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
            description=f"{minimum_count} forwarded UDP payloads",
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


def _send_datagram(port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload.encode("utf-8"), ("127.0.0.1", port))


def test_in_udp_parser_json_success():
    service = Service("in_udp_parser_json.yaml")
    service.start()

    try:
        _send_datagram(service.flb_listener_port, '{"message":"hello","value":42}\n')
        record = service.wait_for_single_record()
    finally:
        service.stop()

    assert record["message"] == "hello"
    assert record["value"] == 42


def test_in_udp_parser_json_fallback_to_log():
    service = Service("in_udp_parser_json.yaml")
    service.start()

    try:
        _send_datagram(service.flb_listener_port, 'not-json\n')
        record = service.wait_for_single_record()
    finally:
        service.stop()

    assert "log" in record
    assert record["log"].strip() == "not-json"


def test_in_udp_parser_json_workers_concurrent_records():
    total_records = 16
    service = Service("in_udp_parser_json_workers.yaml")
    service.start()
    service.wait_for_log_message("with 4 workers", timeout=10)

    try:
        with ThreadPoolExecutor(max_workers=total_records) as executor:
            list(executor.map(
                lambda i: _send_datagram(service.flb_listener_port,
                                         f'{{"message":"worker-{i}","value":{i}}}\n'),
                range(total_records),
            ))
        records = service.wait_for_record_count(total_records, timeout=20)
    finally:
        service.stop()

    values = sorted(record["value"] for record in records)
    assert values == list(range(total_records))


def test_in_udp_workers_drop_malformed_datagrams_and_continue():
    malformed_datagrams = 8
    valid_records = 8
    service = Service("in_udp_json_workers.yaml")
    service.start()
    service.wait_for_log_message("with 4 workers", timeout=10)

    try:
        with ThreadPoolExecutor(max_workers=malformed_datagrams) as executor:
            list(executor.map(
                lambda i: _send_datagram(service.flb_listener_port,
                                         f'{{"message":"malformed-{i}"'),
                range(malformed_datagrams),
            ))

        with ThreadPoolExecutor(max_workers=valid_records) as executor:
            list(executor.map(
                lambda i: _send_datagram(service.flb_listener_port,
                                         f'{{"message":"valid-{i}","value":{i}}}'),
                range(valid_records),
            ))
        records = service.wait_for_record_count(valid_records, timeout=20)
    finally:
        service.stop()

    values = sorted(record["value"] for record in records)
    assert values == list(range(valid_records))
