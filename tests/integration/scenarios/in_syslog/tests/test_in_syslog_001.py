import os
import socket
import ssl
import sys
import uuid

import pytest
import requests

from server.http_server import data_storage, http_server_run
from utils.test_service import FluentBitTestService


TCP_RFC5424_MESSAGE = b"<13>1 1970-01-01T00:00:00.000000+00:00 testhost testuser - - [] Hello!\n"
UDS_RFC3164_MESSAGE = b"<13>Jan  1 00:00:00 testuser:  Hello!\n"


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        test_path = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.abspath(os.path.join(test_path, "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.parsers_file = os.environ.get("FLUENT_BIT_PARSERS_FILE") or os.path.abspath(os.path.join(test_path, "../../../../../conf/parsers.conf"))
        self.socket_path = f"/tmp/fluent_bit_syslog_{uuid.uuid4().hex}.sock"
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads"],
            extra_env={
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
                "PARSERS_FILE_TEST": self.parsers_file,
                "SYSLOG_SOCKET_PATH": self.socket_path,
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
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def start(self):
        self.service.start()
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def read_forwarded_payloads(self, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["payloads"] if data_storage["payloads"] else None,
            timeout=timeout,
            interval=0.5,
            description="forwarded syslog payloads",
        )


def _assert_message(payloads):
    assert len(payloads) == 1
    assert isinstance(payloads[0], list)
    assert len(payloads[0]) == 1
    record = payloads[0][0]
    assert record["message"] == "Hello!"


def test_in_syslog_tcp_plaintext():
    service = Service("in_syslog_tcp_plaintext.yaml")
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(TCP_RFC5424_MESSAGE)
            sock.shutdown(socket.SHUT_WR)

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_message(payloads)


def test_in_syslog_tcp_tls():
    service = Service("in_syslog_tcp_tls.yaml")
    service.start()

    try:
        context = ssl.create_default_context(cafile=service.tls_crt_file)
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
                tls_sock.sendall(TCP_RFC5424_MESSAGE)
                tls_sock.shutdown(socket.SHUT_WR)

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_message(payloads)


def test_in_syslog_udp_plaintext():
    service = Service("in_syslog_udp_plaintext.yaml")
    service.start()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(TCP_RFC5424_MESSAGE, ("127.0.0.1", service.flb_listener_port))

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_message(payloads)


def test_in_syslog_uds_stream_plaintext():
    service = Service("in_syslog_uds_stream_plaintext.yaml")
    service.start()

    try:
        service.service.wait_for_condition(
            lambda: os.path.exists(service.socket_path),
            timeout=10,
            interval=0.2,
            description="syslog unix stream socket",
        )

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(service.socket_path)
            sock.sendall(UDS_RFC3164_MESSAGE)
            sock.shutdown(socket.SHUT_WR)

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_message(payloads)


@pytest.mark.skipif(sys.platform == "darwin", reason="unix datagram syslog runtime-shell test is skipped on Darwin")
def test_in_syslog_uds_dgram_plaintext():
    service = Service("in_syslog_uds_dgram_plaintext.yaml")
    service.start()

    try:
        service.service.wait_for_condition(
            lambda: os.path.exists(service.socket_path),
            timeout=10,
            interval=0.2,
            description="syslog unix datagram socket",
        )

        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(service.socket_path)
            sock.sendall(UDS_RFC3164_MESSAGE)

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_message(payloads)
