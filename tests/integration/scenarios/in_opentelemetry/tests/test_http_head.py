"""Shared HTTP response semantics, exercised through the OTLP listener."""
import socket

import pytest
import yaml
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, TrailersReceived

from utils.test_service import FluentBitTestService


@pytest.fixture
def listener(tmp_path):
    config = {
        "service": {"flush": 1, "grace": 1, "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "opentelemetry", "listen": "127.0.0.1",
                        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}],
            "outputs": [{"name": "null", "match": "*"}],
        },
    }
    path = tmp_path / "head.yaml"
    path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(path))
    service.start()
    try:
        yield service.flb_listener_port
    finally:
        service.stop()


def http1_request(port, method):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(f"{method} /v1/logs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        chunks = []
        while True:
            try:
                part = conn.recv(65536)
            except socket.timeout:
                assert chunks, "no HTTP response received"
                break
            if not part:
                break
            chunks.append(part)
            if b"\r\n\r\n" in b"".join(chunks):
                conn.settimeout(0.5)
    head, body = b"".join(chunks).split(b"\r\n\r\n", 1)
    return head, body


def test_http1_head_has_no_wire_body(listener):
    get_headers, get_body = http1_request(listener, "GET")
    head_headers, head_body = http1_request(listener, "HEAD")
    assert get_headers.splitlines()[0] == head_headers.splitlines()[0]
    assert b"400" in head_headers.splitlines()[0]
    assert get_body == b"error: invalid HTTP method\n"
    assert head_body == b""
    assert f"content-length: {len(get_body)}".encode() in head_headers.lower()


def http2_request(port, method, grpc):
    path = ("/opentelemetry.proto.collector.logs.v1.LogsService/Export"
            if grpc else "/v1/logs")
    h2 = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
    h2.initiate_connection()
    h2.send_headers(1, [(":method", method), (":scheme", "http"),
                       (":authority", "localhost"), (":path", path),
                       ("content-type", "application/grpc" if grpc else "application/json")],
                    end_stream=True)
    events = []
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(h2.data_to_send())
        while not any(isinstance(event, StreamEnded) for event in events):
            data = conn.recv(65536)
            assert data, "connection closed before END_STREAM"
            events.extend(h2.receive_data(data))
            pending = h2.data_to_send()
            if pending:
                conn.sendall(pending)
    return events


@pytest.mark.parametrize("grpc", [False, True])
def test_http2_head_preserves_headers_and_trailers(listener, grpc):
    get_events = http2_request(listener, "GET", grpc)
    head_events = http2_request(listener, "HEAD", grpc)
    get_headers = next(dict(e.headers) for e in get_events if isinstance(e, ResponseReceived))
    head_headers = next(dict(e.headers) for e in head_events if isinstance(e, ResponseReceived))
    assert head_headers == get_headers
    assert head_headers[":status"] == ("200" if grpc else "400")
    assert not b"".join(e.data for e in head_events if isinstance(e, DataReceived))
    if grpc:
        for events in (get_events, head_events):
            trailers = next(dict(e.headers) for e in events if isinstance(e, TrailersReceived))
            assert trailers["grpc-status"] == "3"
            assert trailers["grpc-message"] == "invalid HTTP method"
    else:
        assert not any(isinstance(e, DataReceived) for e in head_events)
        assert b"".join(e.data for e in get_events if isinstance(e, DataReceived)) == b"error: invalid HTTP method\n"
