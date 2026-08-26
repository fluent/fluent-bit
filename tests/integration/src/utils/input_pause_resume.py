import re
import socket
import subprocess
import threading
import time

import requests

from utils.http_matrix import run_curl_request


INGESTION_PAUSED_RE = re.compile(
    r'^fluentbit_input_ingestion_paused\{name="([^"]+)"\}\s+([0-9.]+)'
)


class ConnectionFlood:
    def __init__(self, host, port, workers=16):
        self.host = host
        self.port = port
        self.workers = workers
        self.attempts = 0
        self.attempts_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.threads = []

    def _run(self):
        while not self.stop_event.is_set():
            connection = None
            try:
                connection = socket.create_connection(
                    (self.host, self.port),
                    timeout=0.5,
                )
                connection.sendall(b"G")
            except OSError:
                pass
            finally:
                if connection is not None:
                    connection.close()

                with self.attempts_lock:
                    self.attempts += 1

    def start(self):
        for _ in range(self.workers):
            thread = threading.Thread(target=self._run, daemon=True)
            thread.start()
            self.threads.append(thread)

    def wait_for_attempts(self, minimum, timeout=10):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            with self.attempts_lock:
                if self.attempts >= minimum:
                    return

            time.sleep(0.05)

        raise TimeoutError(
            f"Connection flood made fewer than {minimum} attempts"
        )

    def stop(self):
        self.stop_event.set()

        for thread in self.threads:
            thread.join(timeout=2)


def large_json_payload(size=65536):
    return '{"message":"' + ("x" * size) + '"}'


def payload_bytes(payload):
    if isinstance(payload, bytes):
        return payload

    return payload.encode()


def open_partial_http_request(host, port):
    connection = socket.create_connection((host, port), timeout=5)
    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 65536\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        '{"message":"partial'
    )

    connection.sendall(request.encode())
    time.sleep(0.25)

    return connection


def open_stalled_tcp_connection(host, port):
    connection = socket.create_connection((host, port), timeout=5)
    time.sleep(0.25)
    return connection


def assert_connection_closed(connection, *, timeout=5):
    deadline = time.time() + timeout
    connection.settimeout(0.25)

    while time.time() < deadline:
        try:
            if connection.recv(1) == b"":
                return
        except socket.timeout:
            continue
        except OSError:
            return

    raise AssertionError("HTTP connection remained open after the input paused")


def wait_for_input_pause_state(flb, input_name, expected, *, timeout=15, interval=0.25):
    deadline = time.time() + timeout
    expected_value = 1 if expected else 0

    while time.time() < deadline:
        if input_pause_state(flb, input_name) == expected_value:
            return

        time.sleep(interval)

    state = "paused" if expected else "resumed"
    raise TimeoutError(f"Timed out waiting for input to become {state}")


def input_pause_state(flb, input_name):
    try:
        response = requests.get(
            f"http://127.0.0.1:{flb.http_monitoring_port}/api/v2/metrics/prometheus",
            timeout=5 if is_valgrind() else 2,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException:
        return None

    for line in response.text.splitlines():
        match = INGESTION_PAUSED_RE.match(line)
        if match and match.group(1) == input_name:
            return int(float(match.group(2)))

    return None


def curl_status_code(result):
    match = re.search(rb"__META__(\d{3})", result.stdout)
    if match is None:
        return 0

    return int(match.group(1))


def assert_pause_resume_cycles(
    flb,
    url,
    payload,
    headers,
    *,
    input_name,
    success_status,
    cycles=2,
    http_mode="http1.1",
    paused_attempts=4,
    pause_trigger_requests=1,
    resume_payload=None,
    resume_requests=4,
    ca_cert_path=None,
    active_connection_factory=None,
):
    if resume_payload is None:
        resume_payload = '{"message":"resume-check"}'

    for _ in range(cycles):
        active_connections = []
        if active_connection_factory is not None:
            active_connections = active_connection_factory()
            if not isinstance(active_connections, (list, tuple)):
                active_connections = [active_connections]

        for _ in range(pause_trigger_requests):
            result = run_curl_without_check(
                url,
                payload,
                headers=headers,
                http_mode=http_mode,
                max_time=10,
                ca_cert_path=ca_cert_path,
            )
            paused = input_pause_state(flb, input_name) == 1
            if paused:
                break

            if result.returncode != 0 or curl_status_code(result) != success_status:
                wait_for_input_pause_state(flb, input_name, True, timeout=2)
                break

        wait_for_input_pause_state(
            flb,
            input_name,
            True,
            timeout=20 if is_valgrind() else 10,
        )

        for connection in active_connections:
            assert_connection_closed(
                connection,
                timeout=20 if is_valgrind() else 5,
            )
            connection.close()

        rejected_attempts = 0
        for _ in range(paused_attempts):
            if input_pause_state(flb, input_name) != 1:
                break

            paused_result = run_curl_without_check(
                url,
                payload,
                headers,
                http_mode=http_mode,
                max_time=2,
                ca_cert_path=ca_cert_path,
            )
            if paused_result.returncode != 0 or b"__META__000" in paused_result.stdout:
                rejected_attempts += 1
            else:
                assert input_pause_state(flb, input_name) != 1, (
                    "HTTP request succeeded while the input remained paused"
                )

        assert rejected_attempts > 0, "No HTTP request was rejected while the input was paused"

        wait_for_input_pause_state(
            flb,
            input_name,
            False,
            timeout=30 if is_valgrind() else 15,
        )

        for _ in range(resume_requests):
            result = run_curl_request(
                url,
                resume_payload,
                headers=headers,
                http_mode=http_mode,
                ca_cert_path=ca_cert_path,
            )
            assert result["status_code"] == success_status, result


def assert_shutdown_while_paused(
    flb,
    stop_service,
    host,
    port,
    url,
    payload,
    headers,
    *,
    input_name,
    success_status,
    connection_factory=open_partial_http_request,
    connection_count=8,
    pause_trigger_requests=2,
    http_mode="http1.1",
    ca_cert_path=None,
):
    active_connections = []
    connection_flood = ConnectionFlood(host, port)

    try:
        for _ in range(connection_count):
            active_connections.append(connection_factory(host, port))

        connection_flood.start()
        connection_flood.wait_for_attempts(128)

        for _ in range(pause_trigger_requests):
            result = run_curl_without_check(
                url,
                payload,
                headers=headers,
                http_mode=http_mode,
                max_time=10,
                ca_cert_path=ca_cert_path,
            )
            if input_pause_state(flb, input_name) == 1:
                break

            if result.returncode != 0 or curl_status_code(result) == 0:
                wait_for_input_pause_state(flb, input_name, True, timeout=2)
                break

            assert curl_status_code(result) == success_status, result.stdout

        wait_for_input_pause_state(
            flb,
            input_name,
            True,
            timeout=30 if is_valgrind() else 15,
        )

        shutdown_started = time.monotonic()
        stop_service()
        shutdown_elapsed = time.monotonic() - shutdown_started

        shutdown_limit = 30 if is_valgrind() else 8
        assert shutdown_elapsed < shutdown_limit

        for connection in active_connections:
            assert_connection_closed(
                connection,
                timeout=20 if is_valgrind() else 5,
            )
    finally:
        connection_flood.stop()
        for connection in active_connections:
            connection.close()


def run_curl_without_check(
    url,
    payload,
    headers,
    *,
    http_mode,
    max_time,
    ca_cert_path=None,
):
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--output",
        "-",
        "--write-out",
        "\n__META__%{http_code} %{http_version}",
        "--max-time",
        str(max_time),
        "-X",
        "POST",
    ]

    for header in headers:
        command.extend(["-H", header])

    command.extend(["--data-binary", "@-"])

    if http_mode == "http1.1":
        command.append("--http1.1")
    elif http_mode == "http2":
        command.append("--http2")
    elif http_mode == "http2-prior-knowledge":
        command.append("--http2-prior-knowledge")
    else:
        raise ValueError(f"Unsupported HTTP mode {http_mode}")

    if ca_cert_path is not None:
        command.extend(["--cacert", ca_cert_path])

    command.append(url)

    return subprocess.run(
        command,
        input=payload_bytes(payload),
        capture_output=True,
        check=False,
    )


def is_valgrind():
    import os

    return bool(os.environ.get("VALGRIND"))
