"""Bound incomplete HTTP/1 headers independently of the body buffer."""

import http.client
import socket
import time

import pytest

from utils.test_service import FluentBitTestService


MAX_HEADERS = 32768


@pytest.fixture
def listener(tmp_path):
    config = tmp_path / "http1_headers.yaml"
    config.write_text("""service:
  flush: 1
  grace: 1
  http_server: on
  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}
pipeline:
  inputs:
    - name: http
      listen: 127.0.0.1
      port: ${FLUENT_BIT_TEST_LISTENER_PORT}
      enable_health_endpoint: on
      http_server.buffer_max_size: 64M
  outputs:
    - name: null
      match: '*'
""")
    service = FluentBitTestService(str(config))
    service.start()
    try:
        yield service.flb_listener_port
    finally:
        service.stop()


def response(sock):
    result = http.client.HTTPResponse(sock)
    result.begin()
    result.read()
    return result.status


@pytest.mark.parametrize("fragment", [512, 65536])
@pytest.mark.parametrize("case", ["exact", "over", "unterminated", "request_line"])
def test_http1_header_limit(listener, fragment, case):
    prefix = b"GET /health HTTP/1.1\r\nHost: localhost\r\nX-Pad: "
    if case == "request_line":
        request = b"GET /" + b"a" * MAX_HEADERS
    elif case == "unterminated":
        request = prefix + b"a" * (MAX_HEADERS - len(prefix))
    else:
        size = MAX_HEADERS + (case == "over")
        request = prefix + b"a" * (size - len(prefix) - 4) + b"\r\n\r\n"
    with socket.create_connection(("127.0.0.1", listener), timeout=5) as sock:
        try:
            for offset in range(0, len(request), fragment):
                sock.sendall(request[offset:offset + fragment])
                if fragment < len(request):
                    time.sleep(0.002)
            if case == "exact":
                assert response(sock) == 200
            else:
                assert sock.recv(1024) == b"", "oversized headers were not rejected"
        except (BrokenPipeError, ConnectionResetError):
            assert case != "exact"

    # Rejection must leave the listener available to other clients.
    with socket.create_connection(("127.0.0.1", listener), timeout=5) as sock:
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert response(sock) == 200


@pytest.mark.parametrize("chunked", [False, True])
def test_http1_fragmented_headers_and_large_body(listener, chunked):
    body = b'{"message":"' + b'a' * (2 * MAX_HEADERS) + b'"}'
    headers = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
    if chunked:
        headers += b"Transfer-Encoding: chunked\r\n\r\n"
        payload = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    else:
        headers += f"Content-Length: {len(body)}\r\n\r\n".encode()
        payload = body
    with socket.create_connection(("127.0.0.1", listener), timeout=5) as sock:
        # Split every byte of the header terminator and exercise body SDS growth.
        for byte in headers:
            sock.sendall(bytes([byte]))
            time.sleep(0.002)
        for offset in range(0, len(payload), 1024):
            sock.sendall(payload[offset:offset + 1024])
            time.sleep(0.002)
        assert response(sock) == 201
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert response(sock) == 200
