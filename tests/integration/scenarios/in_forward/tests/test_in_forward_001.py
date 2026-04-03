import gzip
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest
import requests
from google.protobuf import json_format
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from server.forward_server import (
    data_storage as forward_data_storage,
    forward_server_run,
    forward_server_stop,
)
from server.http_server import configure_http_response, data_storage, http_server_run
from utils.data_utils import read_json_file
from utils.test_service import FluentBitTestService


TEST_TAG = "test"
TEST_TS = 1234567890
SECURE_SHARED_KEY = "shared-secret"
SECURE_USERNAME = "alice"
SECURE_PASSWORD = "s3cr3t"
SECURE_SELF_HOSTNAME = "server-node"


class Service:
    def __init__(self, config_file, *, use_unix_socket=False):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.use_unix_socket = use_unix_socket
        self.socket_path = None
        test_path = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.abspath(os.path.join(test_path, "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        extra_env = {
            "CERTIFICATE_TEST": self.tls_crt_file,
            "PRIVATE_KEY_TEST": self.tls_key_file,
        }

        if use_unix_socket:
            self.socket_path = os.path.join(tempfile.gettempdir(), f"fluent_bit_forward_{uuid.uuid4().hex}.sock")
            extra_env["FORWARD_UNIX_PATH"] = self.socket_path

        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads"],
            extra_env=extra_env,
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
        if self.socket_path:
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass

    def start(self):
        self.service.start()
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

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
            description=f"{minimum_count} forwarded forward records",
        )


class StorageLimitService(Service):
    def __init__(self, config_file):
        super().__init__(config_file)
        self.storage_path = tempfile.mkdtemp(prefix="fluent_bit_forward_storage_")
        self.service.extra_env["FORWARD_STORAGE_PATH"] = self.storage_path

    def stop(self):
        try:
            super().stop()
        finally:
            shutil.rmtree(self.storage_path, ignore_errors=True)

    def count_chunk_files(self):
        stream_dir = Path(self.storage_path) / "forward.0"
        if not stream_dir.exists():
            return 0

        return sum(1 for path in stream_dir.rglob("*.flb") if path.is_file())

    def chunk_file_contents(self):
        stream_dir = Path(self.storage_path) / "forward.0"
        if not stream_dir.exists():
            return []

        return [path.read_bytes() for path in stream_dir.rglob("*.flb") if path.is_file()]


class ForwardReceiverService:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.service = FluentBitTestService(
            self.config_file,
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.forward_receiver_port = service.allocate_port_env("FORWARD_RECEIVER_PORT")
        forward_server_run(self.forward_receiver_port)

    def _stop_receiver(self, service):
        forward_server_stop()

    def start(self):
        self.service.start()
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def wait_for_forward_messages(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: forward_data_storage["messages"] if len(forward_data_storage["messages"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.2,
            description=f"{minimum_count} captured forward messages",
        )

    def send_request(self, endpoint, payload, content_type="application/x-protobuf"):
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}{endpoint}",
            data=payload.SerializeToString(),
            headers={"Content-Type": content_type},
            timeout=5,
        )
        response.raise_for_status()
        return response

    def send_json_as_otel_protobuf(self, json_input, signal_type):
        base_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "../../in_opentelemetry/tests/data_files",
            )
        )
        json_payload_dict = read_json_file(os.path.join(base_path, json_input))
        request_map = {
            "metrics": (ExportMetricsServiceRequest(), "/v1/metrics"),
            "traces": (ExportTraceServiceRequest(), "/v1/traces"),
        }
        request_message, endpoint = request_map[signal_type]
        protobuf_payload = json_format.Parse(json.dumps(json_payload_dict), request_message)
        return self.send_request(endpoint, protobuf_payload)


def _pack_uint(value):
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return b"\xCC" + bytes([value])
    if value <= 0xFFFF:
        return b"\xCD" + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return b"\xCE" + value.to_bytes(4, "big")
    return b"\xCF" + value.to_bytes(8, "big")


def _pack_bool(value):
    return b"\xC3" if value else b"\xC2"


def _pack_str(value):
    data = value.encode()
    length = len(data)
    if length <= 31:
        return bytes([0xA0 | length]) + data
    if length <= 0xFF:
        return b"\xD9" + bytes([length]) + data
    if length <= 0xFFFF:
        return b"\xDA" + length.to_bytes(2, "big") + data
    return b"\xDB" + length.to_bytes(4, "big") + data


def _pack_bin(value):
    length = len(value)
    if length <= 0xFF:
        return b"\xC4" + bytes([length]) + value
    if length <= 0xFFFF:
        return b"\xC5" + length.to_bytes(2, "big") + value
    return b"\xC6" + length.to_bytes(4, "big") + value


def _pack_ext(type_code, payload):
    length = len(payload)
    if length == 1:
        return b"\xD4" + type_code.to_bytes(1, "big", signed=True) + payload
    if length == 2:
        return b"\xD5" + type_code.to_bytes(1, "big", signed=True) + payload
    if length == 4:
        return b"\xD6" + type_code.to_bytes(1, "big", signed=True) + payload
    if length == 8:
        return b"\xD7" + type_code.to_bytes(1, "big", signed=True) + payload
    if length == 16:
        return b"\xD8" + type_code.to_bytes(1, "big", signed=True) + payload
    raise ValueError(f"Unsupported ext payload size {length}")


def _pack_array(items):
    length = len(items)
    if length <= 15:
        prefix = bytes([0x90 | length])
    elif length <= 0xFFFF:
        prefix = b"\xDC" + length.to_bytes(2, "big")
    else:
        prefix = b"\xDD" + length.to_bytes(4, "big")
    return prefix + b"".join(_pack_obj(item) for item in items)


def _pack_map(mapping):
    items = list(mapping.items())
    length = len(items)
    if length <= 15:
        prefix = bytes([0x80 | length])
    elif length <= 0xFFFF:
        prefix = b"\xDE" + length.to_bytes(2, "big")
    else:
        prefix = b"\xDF" + length.to_bytes(4, "big")
    encoded = []
    for key, value in items:
        encoded.append(_pack_obj(key))
        encoded.append(_pack_obj(value))
    return prefix + b"".join(encoded)


def _pack_obj(value):
    if value is None:
        return b"\xC0"
    if value is False:
        return b"\xC2"
    if value is True:
        return b"\xC3"
    if isinstance(value, int):
        return _pack_uint(value)
    if isinstance(value, bool):
        return _pack_bool(value)
    if isinstance(value, str):
        return _pack_str(value)
    if isinstance(value, bytes):
        return _pack_bin(value)
    if isinstance(value, tuple) and len(value) == 3 and value[0] == "__ext__":
        return _pack_ext(value[1], value[2])
    if isinstance(value, list):
        return _pack_array(value)
    if isinstance(value, dict):
        return _pack_map(value)
    raise TypeError(f"Unsupported value type {type(value)!r}")


def _message_mode_payload(tag, body):
    return _pack_obj([tag, TEST_TS, body])


def _message_mode_eventtime_payload(tag, body, *, seconds, nanoseconds):
    ext_payload = seconds.to_bytes(4, "big") + nanoseconds.to_bytes(4, "big")
    return _pack_obj([tag, ("__ext__", 0, ext_payload), body])


def _forward_mode_payload(tag, entries):
    return _pack_obj([tag, [[TEST_TS, entry] for entry in entries]])


def _packed_forward_payload(tag, packed_entries, *, compressed=None):
    options = {}
    if compressed:
        options["compressed"] = compressed
    payload = [tag, packed_entries]
    if options:
        payload.append(options)
    return _pack_obj(payload)


def _gzip_bytes(data):
    return gzip.compress(data)


def _zstd_bytes(data):
    if not shutil.which("zstd"):
        pytest.skip("zstd binary is required for this test")

    result = subprocess.run(
        ["zstd", "-q", "-c"],
        input=data,
        capture_output=True,
        check=True,
    )
    return result.stdout


def _send_tcp_payload(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(payload)


def _send_unix_payload(path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(path)
        sock.sendall(payload)


def _send_tls_payload(port, payload, cafile):
    context = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
            tls_sock.sendall(payload)


def _recv_msgpack_value(sock):
    sock.settimeout(5)
    data = sock.recv(4096)
    assert data
    value, offset = _unpack_obj(data, 0)
    assert offset == len(data)
    return value


def _decode_str_like(raw):
    try:
        return raw.decode()
    except UnicodeDecodeError:
        return raw


def _unpack_obj(data, offset):
    first = data[offset]
    offset += 1

    if first <= 0x7F:
        return first, offset
    if 0x80 <= first <= 0x8F:
        size = first & 0x0F
        result = {}
        for _ in range(size):
            key, offset = _unpack_obj(data, offset)
            value, offset = _unpack_obj(data, offset)
            result[key] = value
        return result, offset
    if 0x90 <= first <= 0x9F:
        size = first & 0x0F
        result = []
        for _ in range(size):
            value, offset = _unpack_obj(data, offset)
            result.append(value)
        return result, offset
    if 0xA0 <= first <= 0xBF:
        size = first & 0x1F
        raw = data[offset:offset + size]
        return _decode_str_like(raw), offset + size
    if first == 0xC0:
        return None, offset
    if first == 0xC2:
        return False, offset
    if first == 0xC3:
        return True, offset
    if first == 0xC4:
        size = data[offset]
        offset += 1
        return data[offset:offset + size], offset + size
    if first == 0xCC:
        return data[offset], offset + 1
    if first == 0xCD:
        return int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    if first == 0xCE:
        return int.from_bytes(data[offset:offset + 4], "big"), offset + 4
    if first == 0xCF:
        return int.from_bytes(data[offset:offset + 8], "big"), offset + 8
    if first == 0xD9:
        size = data[offset]
        offset += 1
        raw = data[offset:offset + size]
        return _decode_str_like(raw), offset + size
    if first == 0xDA:
        size = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        raw = data[offset:offset + size]
        return _decode_str_like(raw), offset + size
    if first == 0xDE:
        size = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        result = {}
        for _ in range(size):
            key, offset = _unpack_obj(data, offset)
            value, offset = _unpack_obj(data, offset)
            result[key] = value
        return result, offset

    raise ValueError(f"Unsupported MessagePack type 0x{first:02x}")


def _sha512_hex(*parts):
    hasher = hashlib.sha512()
    for part in parts:
        if isinstance(part, str):
            part = part.encode()
        hasher.update(part)
    return hasher.hexdigest()


def _secure_forward_handshake(sock, *, username, password, shared_key, hostname="client-node", shared_key_salt="client-salt-1234"):
    helo = _recv_msgpack_value(sock)
    assert helo[0] == "HELO"

    helo_options = helo[1]
    nonce = helo_options["nonce"]
    auth_salt = helo_options["auth"]

    shared_key_digest = _sha512_hex(shared_key_salt, hostname, nonce, shared_key)
    password_digest = _sha512_hex(auth_salt, username, password)

    ping = _pack_obj(["PING", hostname, shared_key_salt, shared_key_digest, username, password_digest])
    sock.sendall(ping)

    return _recv_msgpack_value(sock)


def test_in_forward_message_mode_tcp():
    service = Service("in_forward.yaml")
    service.start()

    try:
        payload = _message_mode_payload(TEST_TAG, {"message": "message-mode"})
        _send_tcp_payload(service.flb_listener_port, payload)
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "message-mode"


def test_in_forward_message_mode_partial_tcp_writes():
    service = Service("in_forward.yaml")
    service.start()

    try:
        payload = _message_mode_payload(TEST_TAG, {"message": "partial"})
        midpoint = len(payload) // 2
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(payload[:midpoint])
            sock.sendall(payload[midpoint:])
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "partial"


def test_in_forward_message_mode_eventtime_ext():
    service = Service("in_forward.yaml")
    service.start()

    try:
        payload = _message_mode_eventtime_payload(
            TEST_TAG,
            {"message": "eventtime"},
            seconds=TEST_TS,
            nanoseconds=123456789,
        )
        _send_tcp_payload(service.flb_listener_port, payload)
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "eventtime"


def test_in_forward_forward_mode_multiple_entries():
    service = Service("in_forward.yaml")
    service.start()

    try:
        payload = _forward_mode_payload(TEST_TAG, [{"message": "entry-1"}, {"message": "entry-2"}])
        _send_tcp_payload(service.flb_listener_port, payload)
        records = service.wait_for_record_count(2)
    finally:
        service.stop()

    assert [record["message"] for record in records[:2]] == ["entry-1", "entry-2"]


def test_in_forward_packed_forward_gzip():
    service = Service("in_forward.yaml")
    service.start()

    try:
        packed_entries = _pack_obj([TEST_TS, {"message": "gzip-packed-forward"}])
        payload = _packed_forward_payload(TEST_TAG, _gzip_bytes(packed_entries), compressed="gzip")
        _send_tcp_payload(service.flb_listener_port, payload)
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "gzip-packed-forward"


def test_in_forward_packed_forward_uncompressed_with_ack():
    service = Service("in_forward.yaml")
    service.start()

    try:
        chunk = "packed-chunk-001"
        packed_entries = _pack_obj([TEST_TS, {"message": "packed-uncompressed"}])
        payload = _packed_forward_payload(TEST_TAG, packed_entries, compressed=None)
        payload = _pack_obj([TEST_TAG, packed_entries, {"chunk": chunk}])

        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(payload)
            ack = _recv_msgpack_value(sock)

        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert ack == {"ack": chunk}
    assert records[0]["message"] == "packed-uncompressed"


def test_in_forward_packed_forward_zstd():
    service = Service("in_forward.yaml")
    service.start()

    try:
        packed_entries = _pack_obj([TEST_TS, {"message": "zstd-packed-forward"}])
        payload = _packed_forward_payload(TEST_TAG, _zstd_bytes(packed_entries), compressed="zstd")
        _send_tcp_payload(service.flb_listener_port, payload)
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "zstd-packed-forward"


def test_in_forward_message_mode_chunk_ack_and_metadata():
    service = Service("in_forward.yaml")
    service.start()

    try:
        chunk = "chunk-001"
        payload = _pack_obj(
            [
                TEST_TAG,
                TEST_TS,
                {"message": "metadata-ack"},
                {"chunk": chunk, "metadata": {"source": "suite", "path": "message-mode"}},
            ]
        )

        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(payload)
            ack = _recv_msgpack_value(sock)

        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert ack == {"ack": chunk}
    assert records[0]["message"] == "metadata-ack"


def test_in_forward_forward_mode_chunk_ack():
    service = Service("in_forward.yaml")
    service.start()

    try:
        chunk = "forward-chunk-001"
        payload = _pack_obj(
            [
                TEST_TAG,
                [[TEST_TS, {"message": "forward-ack"}]],
                {"chunk": chunk},
            ]
        )

        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(payload)
            ack = _recv_msgpack_value(sock)

        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert ack == {"ack": chunk}
    assert records[0]["message"] == "forward-ack"


def test_in_forward_tag_prefix_routes_records():
    service = Service("in_forward_tag_prefix.yaml")
    service.start()

    try:
        payload = _message_mode_payload(TEST_TAG, {"message": "prefixed"})
        _send_tcp_payload(service.flb_listener_port, payload)
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "prefixed"


def test_in_forward_forced_input_tag_overrides_incoming_tag():
    service = Service("in_forward_forced_tag.yaml")
    service.start()

    try:
        payload = _message_mode_payload("ignored.incoming.tag", {"message": "forced-tag"})
        _send_tcp_payload(service.flb_listener_port, payload)
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "forced-tag"


def test_in_forward_unix_socket_message_mode():
    service = Service("in_forward_unix.yaml", use_unix_socket=True)
    service.start()

    try:
        service.service.wait_for_condition(
            lambda: os.path.exists(service.socket_path),
            timeout=10,
            interval=0.2,
            description="forward unix socket",
        )
        payload = _message_mode_payload(TEST_TAG, {"message": "unix-socket"})
        _send_unix_payload(service.socket_path, payload)
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "unix-socket"


def test_in_forward_unix_socket_permissions():
    service = Service("in_forward_unix_perm.yaml", use_unix_socket=True)
    service.start()

    try:
        service.service.wait_for_condition(
            lambda: os.path.exists(service.socket_path),
            timeout=10,
            interval=0.2,
            description="forward unix socket with permissions",
        )
        mode = os.stat(service.socket_path).st_mode & 0o777
    finally:
        service.stop()

    assert mode == 0o600


def test_in_forward_tls_message_mode():
    service = Service("in_forward_tls.yaml")
    service.start()

    try:
        payload = _message_mode_payload(TEST_TAG, {"message": "tls-message"})
        _send_tls_payload(service.flb_listener_port, payload, service.tls_crt_file)
        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert records[0]["message"] == "tls-message"


def test_in_forward_secure_forward_auth_success():
    service = Service("in_forward_secure.yaml")
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            pong = _secure_forward_handshake(
                sock,
                username=SECURE_USERNAME,
                password=SECURE_PASSWORD,
                shared_key=SECURE_SHARED_KEY,
            )
            sock.sendall(_message_mode_payload(TEST_TAG, {"message": "secure-success"}))

        records = service.wait_for_record_count(1)
    finally:
        service.stop()

    assert pong[0] == "PONG"
    assert pong[1] is True
    assert pong[2] == ""
    assert pong[3] == SECURE_SELF_HOSTNAME
    assert records[0]["message"] == "secure-success"


def test_in_forward_secure_forward_auth_failure():
    service = Service("in_forward_secure.yaml")
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            pong = _secure_forward_handshake(
                sock,
                username=SECURE_USERNAME,
                password="wrong-password",
                shared_key=SECURE_SHARED_KEY,
            )
            sock.sendall(_message_mode_payload(TEST_TAG, {"message": "should-not-pass"}))

        with pytest.raises(TimeoutError):
            service.wait_for_record_count(1, timeout=2)
    finally:
        service.stop()

    assert pong[0] == "PONG"
    assert pong[1] is False
    assert "username/password mismatch" in pong[2]


def test_in_forward_e2e_forward_receiver_preserves_metadata_and_signal_options():
    service = ForwardReceiverService("in_forward_to_forward_receiver.yaml")
    service.start()

    try:
        payload = _pack_obj(
            [
                TEST_TAG,
                TEST_TS,
                {"message": "end-to-end-forward"},
                {"metadata": {"source": "suite", "scope": "log"}, "chunk": "input-chunk"},
            ]
        )
        _send_tcp_payload(service.flb_listener_port, payload)
        messages = service.wait_for_forward_messages(1)
    finally:
        service.stop()

    message = messages[0]
    record = message["records"][0]
    raw_record = record["raw"]

    assert message["mode"] == "forward"
    assert message["tag"] == TEST_TAG
    assert message["options"]["fluent_signal"] == 0
    assert message["options"]["size"] == 1
    assert message["options"]["chunk"]
    assert "metadata" not in message["options"]
    assert len(raw_record) == 2
    assert len(raw_record[0]) == 2
    assert raw_record[0][1] == {"source": "suite", "scope": "log"}
    assert record["body"]["message"] == "end-to-end-forward"
    assert record["metadata"]["source"] == "suite"
    assert record["metadata"]["scope"] == "log"


def test_in_forward_e2e_forward_receiver_gzip_preserves_metadata_and_signal_options():
    service = ForwardReceiverService("in_forward_to_forward_receiver_gzip.yaml")
    service.start()

    try:
        payload = _pack_obj(
            [
                TEST_TAG,
                TEST_TS,
                {"message": "end-to-end-gzip"},
                {"metadata": {"source": "suite", "scope": "gzip"}, "chunk": "input-chunk-gzip"},
            ]
        )
        _send_tcp_payload(service.flb_listener_port, payload)
        messages = service.wait_for_forward_messages(1)
    finally:
        service.stop()

    message = messages[0]
    record = message["records"][0]
    raw_record = record["raw"]

    assert message["mode"] == "packed_forward"
    assert message["tag"] == TEST_TAG
    assert message["options"]["compressed"] == "gzip"
    assert message["options"]["fluent_signal"] == 0
    assert message["options"]["size"] == 1
    assert message["options"]["chunk"]
    assert "metadata" not in message["options"]
    assert len(raw_record) == 2
    assert len(raw_record[0]) == 2
    assert raw_record[0][1] == {"source": "suite", "scope": "gzip"}
    assert record["body"]["message"] == "end-to-end-gzip"
    assert record["metadata"]["source"] == "suite"
    assert record["metadata"]["scope"] == "gzip"


def test_out_forward_metrics_signal_e2e_with_forward_receiver():
    service = ForwardReceiverService("in_opentelemetry_to_forward_receiver.yaml")
    service.start()

    try:
        service.send_json_as_otel_protobuf("test_metrics_001.in.json", "metrics")
        messages = service.wait_for_forward_messages(1)
    finally:
        service.stop()

    message = messages[0]
    record_payload = message["records"][0]["raw"]

    assert message["mode"] == "packed_forward"
    assert message["tag"] == "v1_metrics"
    assert message["options"]["fluent_signal"] == 1
    assert message["options"]["chunk"]
    assert "size" not in message["options"]
    assert len(message["records"]) >= 1
    assert record_payload["meta"]["external"]["scope"]["metadata"]["name"] == "metrics-scope"
    assert record_payload["metrics"][0]["meta"]["opts"]["name"] == "requests_total"
    assert record_payload["metrics"][0]["values"][0]["labels"] == ["checkout"]
    assert record_payload["metrics"][0]["values"][0]["value_int64"] == 42


def test_out_forward_traces_signal_e2e_with_forward_receiver():
    service = ForwardReceiverService("in_opentelemetry_to_forward_receiver.yaml")
    service.start()

    try:
        service.send_json_as_otel_protobuf("test_traces_001.in.json", "traces")
        messages = service.wait_for_forward_messages(1)
    finally:
        service.stop()

    message = messages[0]
    record_payload = message["records"][0]["raw"]

    assert message["mode"] == "packed_forward"
    assert message["tag"] == "v1_traces"
    assert message["options"]["fluent_signal"] == 2
    assert message["options"]["chunk"]
    assert "size" not in message["options"]
    assert len(message["records"]) >= 1
    span = record_payload["resourceSpans"][0]["scope_spans"][0]["spans"][0]
    assert record_payload["resourceSpans"][0]["scope_spans"][0]["scope"]["name"] == "trace-scope"
    assert record_payload["resourceSpans"][0]["resource"]["attributes"]["service.name"] == "checkout"
    assert span["name"] == "checkout-span"
    assert span["attributes"]["http.method"] == "GET"


def test_in_forward_storage_limit_single_output_prefers_actual_chunk_deletion():
    service = StorageLimitService("in_forward_storage_limit_single_output.yaml")
    service.start()

    try:
        configure_http_response(status_code=500, body={"status": "retry"})

        _send_tcp_payload(service.flb_listener_port, _message_mode_payload("solo.one", {"message": "single-one"}))
        _send_tcp_payload(service.flb_listener_port, _message_mode_payload("solo.two", {"message": "single-two"}))

        service.service.wait_for_condition(
            lambda: service.count_chunk_files() == 2,
            timeout=10,
            interval=0.2,
            description="2 chunk files after two solo messages",
        )

        _send_tcp_payload(service.flb_listener_port, _message_mode_payload("solo.three", {"message": "single-three"}))

        def single_output_eviction_snapshot():
            chunk_contents = service.chunk_file_contents()

            if len(chunk_contents) != 2:
                return None

            if any(b"solo.one" in content for content in chunk_contents):
                return None

            if not any(b"solo.three" in content for content in chunk_contents):
                return None

            return chunk_contents

        try:
            chunk_contents = service.service.wait_for_condition(
                single_output_eviction_snapshot,
                timeout=10,
                interval=0.2,
                description="single-output storage eviction snapshot",
            )
        except TimeoutError:
            if service.count_chunk_files() >= 3:
                pytest.skip(
                    "forward storage eviction preference is not supported by this Fluent Bit binary"
                )
            raise
    finally:
        service.stop()

    assert not any(b"solo.one" in content for content in chunk_contents)
    assert any(b"solo.three" in content for content in chunk_contents)


def test_in_forward_storage_limit_multi_output_prefers_deletable_solo_chunk():
    service = StorageLimitService("in_forward_storage_limit_multi_output.yaml")
    service.start()

    try:
        configure_http_response(status_code=500, body={"status": "retry"})

        _send_tcp_payload(service.flb_listener_port, _message_mode_payload("shared.one", {"message": "shared-one"}))
        _send_tcp_payload(service.flb_listener_port, _message_mode_payload("solo.one", {"message": "solo-one"}))

        service.service.wait_for_condition(
            lambda: service.count_chunk_files() == 2,
            timeout=10,
            interval=0.2,
            description="2 chunk files after shared and solo messages",
        )

        _send_tcp_payload(service.flb_listener_port, _message_mode_payload("solo.two", {"message": "solo-two"}))

        def multi_output_eviction_snapshot():
            chunk_contents = service.chunk_file_contents()

            if len(chunk_contents) != 2:
                return None

            if any(b"solo.one" in content for content in chunk_contents):
                return None

            if not any(b"shared.one" in content for content in chunk_contents):
                return None

            if not any(b"solo.two" in content for content in chunk_contents):
                return None

            return chunk_contents

        try:
            chunk_contents = service.service.wait_for_condition(
                multi_output_eviction_snapshot,
                timeout=10,
                interval=0.2,
                description="multi-output storage eviction snapshot",
            )
        except TimeoutError:
            if service.count_chunk_files() >= 3:
                pytest.skip(
                    "forward storage eviction preference is not supported by this Fluent Bit binary"
                )
            raise
    finally:
        service.stop()

    assert any(b"shared.one" in content for content in chunk_contents)
    assert not any(b"solo.one" in content for content in chunk_contents)
