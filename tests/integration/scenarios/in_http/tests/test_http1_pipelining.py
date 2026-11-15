"""Pipelined HTTP/1.1 requests sent in a single write are all answered."""

import socket

import pytest

from utils.test_service import FluentBitTestService


@pytest.fixture
def listener(tmp_path):
    config = tmp_path / "http1_pipelining.yaml"
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


def read_response(stream):
    """Read one response from a buffered socket file, return its status."""
    status_line = stream.readline()
    assert status_line, "connection closed before a response arrived"
    status = int(status_line.split()[1])

    length = 0
    chunked = False
    while True:
        line = stream.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        name, _, value = line.decode("latin-1").partition(":")
        if name.strip().lower() == "content-length":
            length = int(value.strip())
        elif name.strip().lower() == "transfer-encoding" and "chunked" in value.lower():
            chunked = True

    if chunked:
        while True:
            size = int(stream.readline().split(b";")[0], 16)
            stream.read(size + 2)
            if size == 0:
                break
    else:
        stream.read(length)

    return status


def test_http1_pipelined_requests_in_one_write(listener):
    # A chunked body has an exact end. With Content-Length the body currently
    # runs to the end of the buffer (#12652), which is a separate bug.
    body = b'{"a":1}'
    first = (b"POST /one HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
             b"Transfer-Encoding: chunked\r\n\r\n"
             + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
    second = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"

    with socket.create_connection(("127.0.0.1", listener), timeout=5) as sock:
        # Both requests in one write, and nothing sent after them: the second
        # one must be answered without waiting for more data from the client.
        sock.sendall(first + second)
        stream = sock.makefile("rb")
        assert read_response(stream) == 201
        assert read_response(stream) == 200


def test_http1_pipelined_header_only_requests(listener):
    # Two requests without a body. The first one ends at its blank line, so
    # the second one has to be kept in the buffer when the first is evicted.
    request = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"

    with socket.create_connection(("127.0.0.1", listener), timeout=5) as sock:
        sock.sendall(request + request)
        stream = sock.makefile("rb")
        assert read_response(stream) == 200
        assert read_response(stream) == 200
