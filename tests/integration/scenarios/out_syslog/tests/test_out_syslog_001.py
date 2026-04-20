import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from utils.test_service import FluentBitTestService


class UdpReceiver:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.message = None
        self.error = None
        self._ready = threading.Event()
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.host, self.port))
                server.settimeout(120)
                self._ready.set()

                data, _ = server.recvfrom(4096)
                self.message = data
                self._done.set()
        except Exception as exc:
            self.error = exc
            self._ready.set()
            self._done.set()

    def start(self):
        self._thread.start()

    def wait_ready(self, timeout=5):
        if not self._ready.wait(timeout):
            raise TimeoutError("Timed out waiting for UDP receiver readiness")

    def wait_message(self, timeout=10):
        if not self._done.wait(timeout):
            raise TimeoutError("Timed out waiting for UDP syslog payload")

        if self.error is not None:
            raise self.error

        return self.message


class TcpReceiver:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.message = None
        self.error = None
        self._ready = threading.Event()
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.host, self.port))
                server.listen(1)
                server.settimeout(120)
                self._ready.set()
                conn, _ = server.accept()

                with conn:
                    conn.settimeout(20)
                    chunks = []

                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if b"\n" in chunk:
                            break

                    self.message = b"".join(chunks)
                    self._done.set()
        except Exception as exc:
            self.error = exc
            self._ready.set()
            self._done.set()

    def start(self):
        self._thread.start()

    def wait_ready(self, timeout=5):
        if not self._ready.wait(timeout):
            raise TimeoutError("Timed out waiting for TCP receiver readiness")

    def wait_message(self, timeout=10):
        if not self._done.wait(timeout):
            raise TimeoutError("Timed out waiting for TCP syslog payload")

        if self.error is not None:
            raise self.error

        return self.message


class DtlsReceiver:
    def __init__(self, port, cert_file, key_file):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.process = None

    def start(self):
        self.process = subprocess.Popen(
            [
                "openssl",
                "s_server",
                "-dtls",
                "-accept",
                str(self.port),
                "-cert",
                self.cert_file,
                "-key",
                self.key_file,
                "-naccept",
                "1",
                "-ign_eof",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(0.5)
        if self.process.poll() is not None:
            output = self._read_output(timeout=2)
            raise RuntimeError(f"DTLS receiver failed to start: {output}")

    def wait_ready(self, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                output = self._read_output(timeout=2)
                raise RuntimeError(f"DTLS receiver terminated early: {output}")
            time.sleep(0.1)

    def _read_output(self, timeout=2):
        stdout, stderr = self.process.communicate(timeout=timeout)
        return (stdout + stderr).decode("utf-8", errors="replace")

    def wait_message(self, timeout=30):
        try:
            output = self._read_output(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Timed out waiting for DTLS handshake") from exc

        return output

    def stop(self):
        if self.process is None:
            return

        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


class Service:
    def __init__(self, config_file, receiver_type):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.receiver_type = receiver_type
        self.receiver = None

        cert_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate")
        )
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")

        self.service = FluentBitTestService(
            self.config_file,
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.receiver_port = service.allocate_port_env("SYSLOG_RECEIVER_PORT")

        if self.receiver_type == "udp":
            self.receiver = UdpReceiver("127.0.0.1", self.receiver_port)
        elif self.receiver_type == "tcp":
            self.receiver = TcpReceiver("127.0.0.1", self.receiver_port)
        elif self.receiver_type == "dtls":
            self.receiver = DtlsReceiver(self.receiver_port, self.tls_crt_file, self.tls_key_file)
        else:
            raise ValueError(f"Unknown receiver type: {self.receiver_type}")

        self.receiver.start()
        self.receiver.wait_ready(timeout=5)

    def _stop_receiver(self, _service):
        if self.receiver_type == "dtls" and self.receiver is not None:
            self.receiver.stop()

    def start(self):
        self.service.start()

    def stop(self):
        self.service.stop()


def _assert_syslog_payload(payload):
    text = payload.decode("utf-8", errors="replace")
    assert "hello from out_syslog" in text
    assert text.startswith("<")


def _assert_dtls_payload(output):
    assert "ACCEPT" in output
    assert "DONE" in output


def test_out_syslog_udp():
    service = Service("out_syslog_udp.yaml", "udp")
    service.start()

    try:
        payload = service.receiver.wait_message(timeout=20)
    finally:
        service.stop()

    _assert_syslog_payload(payload)


def test_out_syslog_tcp():
    service = Service("out_syslog_tcp.yaml", "tcp")
    service.start()

    try:
        payload = service.receiver.wait_message(timeout=15)
    finally:
        service.stop()

    _assert_syslog_payload(payload)


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl is required for DTLS test")
def test_out_syslog_dtls():
    service = Service("out_syslog_dtls.yaml", "dtls")
    service.start()

    try:
        output = service.receiver.wait_message(timeout=30)
    finally:
        service.stop()

    _assert_dtls_payload(output)
