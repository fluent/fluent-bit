"""Bound decoded HTTP/2 headers, including indexed fields and trailers."""

import http.client
import socket
import ssl
from pathlib import Path

import pytest
from hpack import Decoder, Encoder
from hyperframe.frame import Frame, HeadersFrame, ContinuationFrame, DataFrame, SettingsFrame

from utils.test_service import FluentBitTestService


MAX_BYTES = 65536
MAX_FIELDS = 100
BASE_HEADERS = [(b":method", b"GET"), (b":scheme", b"http"),
                (b":authority", b"localhost"), (b":path", b"/health")]
# XXH3_64bits("x-collision-N") % 16 == 0 for these suffixes.
COLLISIONS = [
    2, 12, 17, 20, 39, 54, 96, 146, 163, 198, 270, 278, 296, 314, 368, 380,
    387, 394, 418, 428, 446, 458, 484, 485, 489, 490, 496, 502, 509, 524,
    526, 531, 546, 550, 585, 658, 671, 676, 697, 707, 727, 740, 765, 766,
    778, 783, 800, 853, 863, 898, 909, 910, 934, 954, 958, 969, 994, 996,
    1007, 1015, 1030, 1043, 1047, 1068, 1079, 1097, 1111, 1112, 1138,
    1148, 1166, 1183, 1210, 1213, 1229, 1241, 1250, 1251, 1268, 1285,
    1297, 1303, 1334, 1390, 1424, 1463, 1483, 1486, 1533, 1558, 1567,
    1582, 1591, 1647, 1651, 1661, 1666, 1671, 1683, 1687,
]


class Client:
    def __init__(self, port, tls):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=5)
        if tls:
            context = ssl._create_unverified_context()
            context.set_alpn_protocols(["h2"])
            self.socket = context.wrap_socket(self.socket, server_hostname="localhost")
            assert self.socket.selected_alpn_protocol() == "h2"
        self.encoder = Encoder()
        self.decoder = Decoder()
        self.pending = b""
        self.settings = {}
        self.socket.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SettingsFrame().serialize())

    def headers(self, stream, headers, end=True):
        frames = self.header_frames(stream, headers, end=end)
        self.socket.sendall(frames)
        return len(frames)

    def header_frames(self, stream, headers, end=True):
        # Bypass client-side advisory limits; keep valid frame sizes.
        block = self.encoder.encode(headers, huffman=False)
        frames = bytearray()
        for offset in range(0, len(block), 16384):
            frame = HeadersFrame(stream) if offset == 0 else ContinuationFrame(stream)
            frame.data = block[offset:offset + 16384]
            if offset + 16384 >= len(block):
                frame.flags.add("END_HEADERS")
            if offset == 0 and end:
                frame.flags.add("END_STREAM")
            frames.extend(frame.serialize())
        return bytes(frames)

    def result(self, stream):
        while True:
            while len(self.pending) < 9:
                data = self.socket.recv(65536)
                assert data, "connection closed before stream result"
                self.pending += data
            frame, length = Frame.parse_frame_header(memoryview(self.pending[:9]))
            while len(self.pending) < 9 + length:
                data = self.socket.recv(65536)
                assert data, "connection closed during frame"
                self.pending += data
            frame.parse_body(memoryview(self.pending[9:9 + length]))
            self.pending = self.pending[9 + length:]
            if frame.type == 4 and "ACK" not in frame.flags:
                self.settings.update(frame.settings)
                self.socket.sendall(SettingsFrame(flags=["ACK"]).serialize())
            if frame.stream_id == stream and frame.type in (1, 3):
                if frame.type == 1:
                    assert (":status", "200") in self.decoder.decode(frame.data)
                return frame
            assert frame.type != 7, "unexpected connection-level GOAWAY"


@pytest.fixture(params=[False, True], ids=["cleartext", "tls"])
def listener(request, tmp_path):
    cert_dir = Path(__file__).resolve().parents[2] / "in_splunk" / "certificate"
    config = tmp_path / "headers.yaml"
    config.write_text("""service:
  flush: 1
  http_server: on
  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}
pipeline:
  inputs:
    - name: http
      listen: 127.0.0.1
      port: ${FLUENT_BIT_TEST_LISTENER_PORT}
      enable_health_endpoint: on
      http2: on
      tls: ${HEADER_TEST_TLS}
      tls.crt_file: ${CERTIFICATE_TEST}
      tls.key_file: ${PRIVATE_KEY_TEST}
  outputs:
    - name: null
      match: '*'
""")
    service = FluentBitTestService(str(config), extra_env={
        "HEADER_TEST_TLS": "on" if request.param else "off",
        "CERTIFICATE_TEST": str(cert_dir / "certificate.pem"),
        "PRIVATE_KEY_TEST": str(cert_dir / "private_key.pem"),
    })
    service.start()
    try:
        yield service, request.param
    finally:
        service.stop()


@pytest.mark.parametrize("case,rejected", [
    ("count_exact", False), ("count_over", True),
    ("bytes_exact", False), ("bytes_over", True),
    ("indexed", True), ("unique", True),
    ("collisions_exact", False), ("collisions_over", True),
    ("path_over", True), ("name_over", True), ("value_over", True),
    ("trailers_count_exact", False), ("trailers_count_over", True),
    ("trailers_bytes_exact", False), ("trailers_bytes_over", True),
])
def test_http2_header_budget(listener, case, rejected):
    service, tls = listener
    client = Client(service.flb_listener_port, tls)
    headers = list(BASE_HEADERS)
    if tls:
        headers[1] = (b":scheme", b"https")
    base_size = sum(len(k) + len(v) + 32 for k, v in headers)
    trailers = None
    if case.startswith("collisions"):
        count = MAX_FIELDS - len(headers) + case.endswith("over")
        headers += [(f"x-collision-{i}".encode(), b"v") for i in COLLISIONS[:count]]
    elif case == "path_over":
        headers[3] = (b":path", b"/" + b"a" * (MAX_BYTES - 1))
    elif case == "name_over":
        headers += [(b"x" * MAX_BYTES, b"v")]
    elif case == "value_over":
        headers += [(b"x-pad", b"v" * MAX_BYTES)]
    elif "count" in case:
        fields = [(b"x-repeat", b"a")] * (MAX_FIELDS - len(headers) + case.endswith("over"))
        if case.startswith("trailers"):
            headers += fields[:40]
            trailers = fields[40:]
        else:
            headers += fields
    elif "bytes" in case:
        value_size = MAX_BYTES - base_size - 32 - len(b"x-pad") + case.endswith("over")
        if case.startswith("trailers"):
            headers += [(b"x-pad", b"a" * 30000)]
            trailers = [(b"x-pad", b"b" * (value_size - 30000 - 37))]
        else:
            headers += [(b"x-pad", b"a" * value_size)]
    elif case == "indexed":
        headers += [(b"x-repeat", b"a" * 4000)] * 200
    else:
        headers += [(f"x-unique-{i}".encode(), b"v") for i in range(200)]
    try:
        wire_bytes = client.headers(1, headers, end=trailers is None)
        if case == "indexed":
            assert wire_bytes < 4500  # Over 800 KB decoded from a small header block.
        if trailers is not None:
            client.headers(1, trailers)
        result = client.result(1)
        assert result.type == (3 if rejected else 1)
        assert client.settings[SettingsFrame.MAX_HEADER_LIST_SIZE] == MAX_BYTES
        if rejected:
            assert result.error_code == 11  # ENHANCE_YOUR_CALM
        # Rejection releases the stream and preserves the connection.
        client.headers(3, BASE_HEADERS)
        assert client.result(3).type == 1
        assert service.flb.process.poll() is None
    finally:
        client.socket.close()


def test_http1_health_with_http2_enabled(listener):
    service, tls = listener
    if tls:
        connection = http.client.HTTPSConnection(
            "localhost", service.flb_listener_port, timeout=5,
            context=ssl._create_unverified_context(),
        )
    else:
        connection = http.client.HTTPConnection("localhost", service.flb_listener_port, timeout=5)
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        assert response.status == 200
        response.read()
    finally:
        connection.close()


def test_http2_invalid_regular_header_resets_stream(listener):
    service, tls = listener
    client = Client(service.flb_listener_port, tls)
    try:
        headers = list(BASE_HEADERS)
        headers.append((b"x-invalid", b"bad\rvalue"))
        client.headers(1, headers)
        result = client.result(1)
        assert result.type == 3
        client.headers(3, BASE_HEADERS)
        assert client.result(3).type == 1
    finally:
        client.socket.close()


@pytest.mark.parametrize("budget", ["count", "bytes"])
def test_http2_trailers_after_complete_data(listener, budget):
    service, tls = listener
    client = Client(service.flb_listener_port, tls)
    headers = list(BASE_HEADERS) + [(b"content-length", b"2")]
    if budget == "count":
        trailers = [(b"x-repeat", b"a")] * (MAX_FIELDS - len(headers) + 1)
    else:
        initial_size = sum(len(name) + len(value) + 32 for name, value in headers)
        trailers = [(b"x-pad", b"a" * (MAX_BYTES - initial_size - 36))]
    data = DataFrame(1)
    data.data = b"{}"
    try:
        client.socket.sendall(
            client.header_frames(1, headers, end=False)
            + data.serialize()
            + client.header_frames(1, trailers)
        )
        result = client.result(1)
        assert result.type == 3
        assert result.error_code == 11
        client.headers(3, BASE_HEADERS)
        assert client.result(3).type == 1
    finally:
        client.socket.close()
