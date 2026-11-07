"""JWKS stalls must release token validation on both HTTP input users."""

import base64
import json
import platform
import shutil
import socket
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests
import yaml

from utils.test_service import FluentBitTestService


def jwt_requiring_jwks():
    """Create a parseable token whose signature requires a JWKS fetch."""
    def encode(value):
        """Encode one JWT segment without base64 padding."""
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return ".".join([
        encode({"alg": "RS256", "kid": "test"}),
        encode({"iss": "issuer", "aud": "audience", "azp": "client1", "exp": 4102444800}),
        "c2lnbmF0dXJl",
    ])


@pytest.fixture(scope="module")
def jwks_tls(tmp_path_factory):
    """Create a temporary CA for the local HTTPS peer."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("HTTPS JWKS fixtures require the openssl command")
    directory = tmp_path_factory.mktemp("jwks-tls")
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run([
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context, cert


@pytest.fixture(scope="module")
def jwks_faults(tmp_path_factory):
    """Build Linux interposition for receive-timeout failure and TLS write retries."""
    if platform.system() != "Linux":
        pytest.skip("JWKS fault interposition requires Linux LD_PRELOAD")
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("JWKS fault interposition requires a C compiler")
    source = Path(__file__).with_name("jwks_io_faults.c")
    library = tmp_path_factory.mktemp("jwks-faults") / "faults.so"
    subprocess.run([
        compiler, "-shared", "-fPIC", str(source), "-ldl", "-o", str(library),
    ], check=True)
    return library


@pytest.mark.parametrize("plugin,path", [("http", "/"), ("opentelemetry", "/v1/logs")])
@pytest.mark.parametrize("stall", [
    "handshake", "handshake_long", "response", "trickle", "https_idle", "https_partial",
    "https_want_write", "receive_timeout_failure",
])
def test_jwks_timeout_releases_validation(tmp_path, request, plugin, path, stall):
    """Bound connection and response stalls, then resume a queued validation."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    stop = threading.Event()
    accepted = threading.Event()
    request_received = threading.Event()
    accepted_at = []
    response_started_at = []
    server_errors = []
    environment = {}
    tls_context = None
    handshake = stall.startswith("handshake")
    https = handshake or stall.startswith("https_") or stall == "receive_timeout_failure"
    response_timeout = 300 if stall == "handshake_long" else 4 if stall.startswith("https_") else 2
    marker = tmp_path / "inject-fault"
    if stall.startswith("https_"):
        tls_context, cert = request.getfixturevalue("jwks_tls")
        environment["LD_PRELOAD"] = str(request.getfixturevalue("jwks_faults"))
        environment["JWKS_TEST_CA"] = str(cert)
    if stall in ("https_want_write", "receive_timeout_failure"):
        environment["LD_PRELOAD"] = str(request.getfixturevalue("jwks_faults"))
        fault = "JWKS_WANT_WRITE_MARKER" if stall == "https_want_write" else "JWKS_RCV_FAILURE_MARKER"
        environment[fault] = str(marker)

    def serve():
        """Keep the selected peer stalled until the test explicitly releases it."""
        try:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                accepted_at.append(time.monotonic())
                accepted.set()
                with conn:
                    conn.settimeout(10)
                    if tls_context is not None:
                        conn = tls_context.wrap_socket(conn, server_side=True)
                    with conn:
                        if handshake or stall == "receive_timeout_failure":
                            stop.wait()
                            continue
                        data = b""
                        while b"\r\n\r\n" not in data:
                            part = conn.recv(65536)
                            if not part:
                                raise ConnectionError("JWKS client closed before sending its request")
                            data += part
                        response_started_at.append(time.monotonic())
                        request_received.set()
                        if stall in ("trickle", "https_partial", "https_want_write"):
                            if stall == "https_want_write":
                                marker.touch()
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                        if stall == "https_partial":
                            if not stop.wait(2.2):
                                conn.sendall(b" ")
                        elif stall == "trickle":
                            while not stop.wait(0.2):
                                conn.sendall(b" ")
                        stop.wait()
        except OSError as error:
            if not stop.is_set() and not isinstance(error, (BrokenPipeError, ConnectionResetError)):
                server_errors.append(error)

    config = {
        "service": {
            "flush": 1, "grace": 1, "log_level": "info", "http_server": "on",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{
                "name": plugin, "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
                "oauth2.validate": True, "oauth2.issuer": "issuer",
                "oauth2.jwks_url": (
                    f"{'https' if https else 'http'}://127.0.0.1:{listener.getsockname()[1]}/keys"
                ),
                "oauth2.jwks_response_timeout": f"{response_timeout}s",
            }],
            "outputs": [{"name": "null", "match": "*"}],
        },
    }
    config_path = tmp_path / "jwks.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path), extra_env=environment)
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        service.start()
        url = f"http://127.0.0.1:{service.flb_listener_port}{path}"
        if stall == "receive_timeout_failure":
            marker.touch()

        def post(authorization):
            """Record completion separately from time spent joining the queued request."""
            result = requests.post(url, json={}, headers={"Authorization": authorization}, timeout=18)
            return result.status_code, time.monotonic()

        with ThreadPoolExecutor(max_workers=2) as pool:
            stalled = pool.submit(post, f"Bearer {jwt_requiring_jwks()}")
            if stall != "receive_timeout_failure":
                assert accepted.wait(10), "JWT validation did not connect to the JWKS endpoint"
                if not handshake:
                    assert request_received.wait(10), f"JWKS request missing: {server_errors}"
            waiting = pool.submit(post, "Bearer malformed")
            status, finished_at = stalled.result(timeout=20)
            assert status == 401
            assert waiting.result(timeout=5)[0] == 401
            if handshake:
                assert finished_at - accepted_at[0] < 12
            elif stall == "receive_timeout_failure":
                assert not marker.exists(), "receive-timeout failure was not injected"
                assert not accepted.is_set(), "connection proceeded after timeout setup failed"
            else:
                tolerance = 0.8 if stall == "https_partial" else 1.5
                assert finished_at - response_started_at[0] < response_timeout + tolerance
            assert not server_errors
    finally:
        stop.set()
        worker.join(timeout=3)
        listener.close()
        service.stop()

    # Read after shutdown so the native logger has flushed its buffered output.
    log = Path(service.flb.log_file).read_text()
    if handshake:
        assert "timed out after 10 seconds" in log
    elif stall == "receive_timeout_failure":
        assert "[oauth2_jwt] failed to get upstream connection" in log
    else:
        assert "[oauth2_jwt] HTTP request failed" in log
        assert (
            f"limit={response_timeout}s)" in log
            or "[http_client] upstream I/O timeout reached while waiting for response" in log
        )
