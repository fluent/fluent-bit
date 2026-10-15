"""Shared finite-load shutdown and failures."""

import base64
import json
import os
import signal
import subprocess
import threading
import time

import pytest

from test_out_manticore_001 import BulkServer, Producer, wait_for_service_log, wait_until


pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="the harness stops Fluent Bit with SIGTERM, which on "
    "Windows terminates it before the exit callback sends the Finish"
)


def reply(state, code=""):
    return {"items": [], "errors": bool(code), "error": code,
            "error_code": code, "shared_state": state}


def operation(request):
    return "finish" if request[2] == b"\n" else "data"


def shared_reply(server, request):
    """Data is staged and the Finish published."""
    return 200, reply({"data": "staged", "finish": "published"}[operation(request)])


@pytest.fixture
def server():
    value = BulkServer(shared_reply)
    try:
        yield value
    finally:
        value.close()


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    root = tmp_path_factory.mktemp("manticore-shared-tls")
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def records(*ids):
    return [{"id": value, "title": "shared ü {}".format(value), "gid": value * 11}
            for value in ids]


def integer_key_filter(root):
    """A Lua filter giving a record marked integer_key a key that is not a string, which the output refuses."""
    script = root / "integer_key.lua"
    script.write_text("function cb(tag, ts, record)\n"
                      "    if record['integer_key'] then return 2, ts, {[-1] = 'integer key', title = 'local'} end\n"
                      "    return 0, ts, record\n"
                      "end\n")
    return [{"name": "lua", "match": "'*'", "script": str(script), "call": "cb"}]


def ops(server):
    return [operation(request) for request in server.requests]


def completed(output):
    return "shared bulk_import complete: table=" in output


def failed(output):
    return "shared bulk_import failed: table=" in output


# Every request carries &shared=N; after the first staged reply data only joins the open pool. The
# data requests share one connection, and shutdown waits for the Finish on its own HTTP/1.0 one.
def test_shared_publication(tmp_path):
    entered, release = threading.Event(), threading.Event()

    def handle(server, request):
        state = "staged"
        if operation(request) == "finish":
            entered.set()
            assert release.wait(5)
            state = "published"
        return 200, b" \t\r\n" + json.dumps(reply(state)).encode() + b"\r\n\t "

    server = BulkServer(handle)
    producer = Producer(tmp_path, server.port, options={"shared_indexers": 4})
    producer.start()
    try:
        producer.write(records(1))
        producer.acknowledged(1)
        assert ops(server) == ["data"]  # An idle callback gap cannot publish.
        producer.write(records(2))
        producer.acknowledged(2)
        process = producer.service.flb.process
        producer.service.flb.send_signal(signal.SIGTERM)
        assert entered.wait(5)
        time.sleep(0.2)
        assert process.poll() is None  # Shutdown waits for the Finish reply.
        release.set()
        process.wait(timeout=10)
        code, output = producer.stop()
        assert code == 0, output
        assert completed(output), output
        assert [request[0] for request in server.requests] == [
            "POST /bulk?bulk_import=shared_logs&shared=4 HTTP/1.1",
            "POST /bulk?bulk_import=shared_logs&shared=4&shared_join HTTP/1.1",
            "POST /bulk?bulk_import=shared_logs&shared=4 HTTP/1.0",
        ]
        assert server.requests[-1][2] == b"\n"
        assert "connection" not in server.requests[-1][1]
        assert server.connections == 2
        for request in server.requests:
            assert request[1]["authorization"] == "Basic " + base64.b64encode(b"shared:test").decode()
            assert request[1]["content-type"] == "application/x-ndjson"
    finally:
        release.set()
        producer.service.stop()
        server.close()


# With workers 0 the flushes run in the engine thread, and the Finish from cb_exit has to leave
# their async stream; here over TLS, to a table whose name needs encoding.
def test_shared_finish_from_the_engine_thread_over_tls(tmp_path, tls_material):
    server = BulkServer(shared_reply, tls=tls_material)
    producer = Producer(tmp_path, server.port, tls=tls_material,
                        options={"table": "'wire logs+ü'", "workers": 0})
    producer.start()
    try:
        producer.write(records(1))
        producer.acknowledged(1)
        producer.write(records(2))
        producer.acknowledged(2)
        code, output = producer.stop()
        assert code == 0, output
        assert completed(output), output
        assert ops(server) == ["data", "data", "finish"]
        assert all(" /bulk?bulk_import=wire%20logs%2B%C3%BC&shared" in request[0]
                   for request in server.requests)
        assert json.loads(server.requests[0][2]) == {"id": 1, "title": "shared ü 1", "gid": 11}
    finally:
        producer.service.stop()
        server.close()


def test_empty_source_leaves_target_untouched(tmp_path, server):
    producer = Producer(tmp_path, server.port)
    producer.start()
    code, output = producer.stop()
    assert code == 0, output
    assert completed(output), output
    assert server.requests == []


# The reply must be one JSON object: a valid one before a malformed tail is no ACK either.
def test_malformed_data_reply_fails_the_load(tmp_path, server):
    server.handler = lambda *_: (200, json.dumps(reply("staged")).encode() + b"garbage")
    producer = Producer(tmp_path, server.port)
    producer.start()
    try:
        producer.write(records(1))
        producer.failed_records(1)
        producer.write(records(2))
        producer.failed_records(2)
        code, output = producer.stop()
        assert failed(output), output
        assert ops(server) == ["data"]
    finally:
        producer.service.stop()


# A machine error to the Finish fails the load; a success reply that does not confirm the
# publication leaves its outcome unknown.
@pytest.mark.parametrize("status, body, unknown", [
    (409, reply("busy", "shared_busy"), False),
    (200, reply("staged"), True),
])
def test_finish_failure_fails_the_load(tmp_path, server, status, body, unknown):
    server.handler = lambda _, request: (
        (200, reply("staged")) if operation(request) == "data" else (status, body))
    producer = Producer(tmp_path, server.port)
    producer.start()
    try:
        producer.write(records(1))
        producer.acknowledged(1)
        code, output = producer.stop()
        assert failed(output), output
        assert ops(server) == ["data", "finish"]
        assert ("Finish completion unknown" in output) == unknown, output
    finally:
        producer.service.stop()


def test_retried_data_is_finished_once(tmp_path, server):
    def handle(server, request):
        if len(server.requests) == 1:
            return 503, b"unavailable"
        return 200, reply("published" if operation(request) == "finish" else "staged")

    server.handler = handle
    producer = Producer(tmp_path, server.port)
    producer.start()
    try:
        producer.write(records(1, 2))
        producer.acknowledged(2)
        code, output = producer.stop()
        assert code == 0, output
        assert ops(server) == ["data", "data", "finish"]
        assert server.requests[0][2] == server.requests[1][2]
    finally:
        producer.service.stop()


def test_retry_exhaustion_fails_the_load(tmp_path, server):
    server.handler = lambda *_: (503, b"unavailable")
    producer = Producer(tmp_path, server.port, options={"retry_limit": 1})
    producer.start()
    try:
        producer.write(records(1))
        wait_for_service_log(producer.service, "cannot be retried")
        code, output = producer.stop()
        assert failed(output), output
        assert ops(server) == ["data", "data"]
        assert "exhausted=1" in output
    finally:
        producer.service.stop()


def test_pending_retry_fails_the_load(tmp_path, server):
    server.handler = lambda *_: (503, b"unavailable")
    producer = Producer(tmp_path, server.port, grace=1,
                        options={"retry_limit": "false"})
    producer.start()
    try:
        producer.write(records(1))
        wait_until(lambda: producer.metric("retries") > 0, "pending retry")
        code, output = producer.stop()
        assert failed(output), output
        assert all(value == "data" for value in ops(server))
        assert "Shared incomplete" in output
    finally:
        producer.service.stop()


@pytest.mark.parametrize("local", [False, True])
def test_failure_after_staging_needs_operator_recovery(tmp_path, server, local):
    def handle(server, request):
        if len(server.requests) == 1:
            return 200, reply("staged")
        return 500, reply("failed", "shared_failed")

    server.handler = handle
    producer = Producer(tmp_path, server.port, filters=integer_key_filter(tmp_path))
    producer.start()
    try:
        producer.write(records(1))
        producer.acknowledged(1)
        producer.write([{"integer_key": True}] if local else records(2))
        producer.failed_records(1)
        code, output = producer.stop()
        assert failed(output), output
        assert "PURGE BULK_IMPORT FROM TABLE shared_logs" in output, output
        assert ops(server) == (["data"] if local else ["data", "data"])
    finally:
        producer.service.stop()
