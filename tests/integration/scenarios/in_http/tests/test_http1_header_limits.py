"""Bound incomplete HTTP/1 headers independently of the body buffer."""

import http.client
import socket
import time

import pytest

from utils.test_service import FluentBitTestService


MAX_HEADERS = 32768


@pytest.fixture
def listener(tmp_path, request):
    parameters = getattr(request, "param", (None, 1))
    header_limit, workers = parameters[:2]
    config = tmp_path / "http1_headers.yaml"
    configuration = """service:
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
      http_server.workers: ${HEADER_TEST_WORKERS}
  outputs:
    - name: null
      match: '*'
"""
    if header_limit is not None:
        configuration = configuration.replace(
            "      http_server.buffer_max_size: 64M",
            f"      http_server.http1_max_header_size: {header_limit}\n"
            "      http_server.buffer_max_size: 64M",
        )
    if len(parameters) > 2:
        configuration = configuration.replace("  outputs:\n", parameters[2] + "  outputs:\n")
    config.write_text(configuration)
    service = FluentBitTestService(str(config), extra_env={
        "HEADER_TEST_WORKERS": str(workers),
    })
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


@pytest.mark.parametrize("listener,limit", [
    (("64KiB", 1), 65536),
    (("64KiB", 2), 65536),
    (("8KiB", 1), 8192),
    (("32KiB", 1), MAX_HEADERS),
    (("0", 1), MAX_HEADERS),
], indirect=["listener"])
def test_http1_configured_header_limit(listener, limit):
    prefix = b"GET /health HTTP/1.1\r\nHost: localhost\r\nX-Pad: "
    accepted = prefix + b"a" * (limit - len(prefix) - 4) + b"\r\n\r\n"
    for suffix in (b"\r\n\r\n", b""):
        with socket.create_connection(("127.0.0.1", listener), timeout=5) as sock:
            # Configured limits apply to the first request and keep-alive reuse.
            for offset in range(0, len(accepted), 512):
                sock.sendall(accepted[offset:offset + 512])
                time.sleep(0.002)
            assert response(sock) == 200
            padding = limit - len(prefix) - (3 if suffix else 0)
            rejected = prefix + b"a" * padding + suffix
            try:
                sock.sendall(rejected)
                assert sock.recv(1024) == b"", "configured header limit was not enforced"
            except (BrokenPipeError, ConnectionResetError):
                pass


@pytest.mark.parametrize("listener", [
    (None, 1, "      http_server.idle_timeout: 0\n      http_server.max_connections: 1\n"),
], indirect=True, ids=["no-timeout-one-slot"])
@pytest.mark.parametrize("fragment", [1, 1024])
def test_http1_invalid_request_line_releases_slot(listener, fragment):
    good_request = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
    for malformed in (
        b"ABCDEFGHIJKL", b"GET /bad\r", b"GET /bad\n",
        b"GET /health XXXXXXX", b"GET /health http/1.", b"GET /health HTTP/2.",
    ):
        for keepalive in (False, True):
            with socket.create_connection(("127.0.0.1", listener), timeout=5) as sock:
                if keepalive:
                    sock.sendall(good_request)
                    assert response(sock) == 200
                for offset in range(0, len(malformed), fragment):
                    sock.sendall(malformed[offset:offset + fragment])
                    time.sleep(0.002)
                try:
                    assert sock.recv(1024) == b"", "invalid request line retained the slot"
                except ConnectionResetError:
                    pass
            # The only slot must become available without an idle timeout.
            with socket.create_connection(("127.0.0.1", listener), timeout=5) as sock:
                sock.sendall(good_request)
                assert response(sock) == 200
