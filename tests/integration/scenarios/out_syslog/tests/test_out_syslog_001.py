import os
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError
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
    def __init__(self, host, port, framing="newline", expected_messages=1):
        self.host = host
        self.port = port
        self.framing = framing
        self.expected_messages = expected_messages
        self.message = None
        self.messages = []
        self.remaining = b""
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
                    self._read_messages(conn)
        except Exception as exc:
            self.error = exc
            self._ready.set()
            self._done.set()

    def _extract_messages(self, buffer):
        while len(self.messages) < self.expected_messages:
            if self.framing == "newline":
                delimiter = buffer.find(b"\n")
                if delimiter == -1:
                    break
                self.messages.append(bytes(buffer[:delimiter]))
                del buffer[: delimiter + 1]
            else:
                delimiter = buffer.find(b" ")
                if delimiter == -1:
                    break

                length_field = bytes(buffer[:delimiter])
                if not length_field.isdigit():
                    raise ValueError(f"Invalid RFC 6587 length prefix: {length_field!r}")

                message_length = int(length_field)
                frame_end = delimiter + 1 + message_length
                if len(buffer) < frame_end:
                    break

                self.messages.append(bytes(buffer[delimiter + 1 : frame_end]))
                del buffer[:frame_end]

    def _read_messages(self, conn):
        conn.settimeout(20)
        buffer = bytearray()

        while len(self.messages) < self.expected_messages:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buffer.extend(chunk)
            self._extract_messages(buffer)

        if len(self.messages) != self.expected_messages:
            raise ValueError(
                f"Expected {self.expected_messages} syslog messages, got {len(self.messages)}"
            )

        # Give the peer a brief chance to send an invalid delimiter after the
        # final octet-counted frame without waiting for it to close the stream.
        conn.settimeout(0.2)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)
        except socket.timeout:
            pass

        self._extract_messages(buffer)
        self.remaining = bytes(buffer)
        self.message = self.messages[0]
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

    def wait_messages(self, timeout=10):
        self.wait_message(timeout)
        return self.messages


class TlsReceiver(TcpReceiver):
    def __init__(
        self,
        host,
        port,
        cert_file,
        key_file,
        framing="newline",
        expected_messages=1,
    ):
        super().__init__(host, port, framing, expected_messages)
        self.cert_file = cert_file
        self.key_file = key_file

    def _run(self):
        try:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.host, self.port))
                server.listen(1)
                server.settimeout(120)
                self._ready.set()
                conn, _ = server.accept()

                with tls_context.wrap_socket(conn, server_side=True) as tls_conn:
                    self._read_messages(tls_conn)
        except Exception as exc:
            self.error = exc
            self._ready.set()
            self._done.set()


class DtlsReceiver:
    def __init__(self, port, cert_file, key_file):
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.process = None

    def start(self):
        openssl = shutil.which("openssl")
        if openssl is None:
            raise RuntimeError("openssl is required for DTLS test")

        self.process = subprocess.Popen(  # noqa: S603 - controlled test command
            [
                openssl,
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
    def __init__(
        self,
        config_file,
        receiver_type,
        framing="newline",
        expected_messages=1,
    ):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.receiver_type = receiver_type
        self.framing = framing
        self.expected_messages = expected_messages
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
            self.receiver = TcpReceiver(
                "127.0.0.1",
                self.receiver_port,
                self.framing,
                self.expected_messages,
            )
        elif self.receiver_type == "tls":
            self.receiver = TlsReceiver(
                "127.0.0.1",
                self.receiver_port,
                self.tls_crt_file,
                self.tls_key_file,
                self.framing,
                self.expected_messages,
            )
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


def _assert_octet_counted_messages(service, messages):
    assert len(messages) == 2
    assert service.receiver.remaining == b""
    for message in messages:
        assert message.startswith(b"<")
        assert b"multiline first\nsecond line \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e" in message
        assert not message.endswith(b"\n")


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


def test_out_syslog_tls_auto_enable():
    service = Service("out_syslog_tls.yaml", "tls")
    service.start()

    try:
        payload = service.receiver.wait_message(timeout=20)
    finally:
        service.stop()

    _assert_syslog_payload(payload)


@pytest.mark.parametrize(
    ("config_file", "receiver_type"),
    [
        ("out_syslog_tcp_octet_counting.yaml", "tcp"),
        ("out_syslog_tls_octet_counting.yaml", "tls"),
    ],
)
def test_out_syslog_octet_counting_multiline_utf8(config_file, receiver_type):
    service = Service(
        config_file,
        receiver_type,
        framing="octet_counting",
        expected_messages=2,
    )
    service.start()

    try:
        messages = service.receiver.wait_messages(timeout=20)
    finally:
        service.stop()

    _assert_octet_counted_messages(service, messages)


def test_out_syslog_octet_counting_prefix_uses_truncated_size():
    service = Service(
        "out_syslog_tcp_octet_counting_truncated.yaml",
        "tcp",
        framing="octet_counting",
    )
    service.start()

    try:
        message = service.receiver.wait_message(timeout=15)
    finally:
        service.stop()

    assert len(message) == 160
    assert message.startswith(b"<")
    assert service.receiver.remaining == b""


def test_out_syslog_sd_preset_is_fallback():
    service = Service("out_syslog_tcp_sd_preset.yaml", "tcp", expected_messages=2)
    service.start()

    try:
        messages = service.receiver.wait_messages(timeout=15)
    finally:
        service.stop()

    preset_message = next(message for message in messages if b"preset-message" in message)
    record_message = next(message for message in messages if b"record-message" in message)
    assert b'[meta@32473 source="preset"]' in preset_message
    assert b'[sd source="record"]' in record_message
    assert b"meta@32473" not in record_message


@pytest.mark.parametrize("mode", ["udp", "dtls"])
def test_out_syslog_datagram_rejects_octet_counting(tmp_path, mode):
    config_file = tmp_path / f"out_syslog_{mode}_octet_counting.yaml"
    config_file.write_text(
        f"""service:
  flush: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}

pipeline:
  inputs:
    - name: dummy
      tag: out_syslog
      dummy: '{{"message":"must not be sent"}}'
      samples: 1

  outputs:
    - name: syslog
      match: out_syslog
      host: 127.0.0.1
      port: 9
      mode: {mode}
      syslog_message_key: message
      syslog_framing: octet_counting
""",
        encoding="utf-8",
    )
    fluent_bit = FluentBitManager(str(config_file))

    try:
        with pytest.raises(FluentBitStartupError, match="exited early with code"):
            fluent_bit.start()

        assert fluent_bit.process.returncode != 0
        with open(fluent_bit.log_file, encoding="utf-8") as log_file:
            log_contents = log_file.read()
        assert "octet_counting" in log_contents
        assert "requires mode=tcp or mode=tls" in log_contents
    finally:
        fluent_bit.stop()


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl is required for DTLS test")
def test_out_syslog_dtls_auto_enable():
    service = Service("out_syslog_dtls.yaml", "dtls")
    service.start()

    try:
        output = service.receiver.wait_message(timeout=30)
    finally:
        service.stop()

    _assert_dtls_payload(output)
