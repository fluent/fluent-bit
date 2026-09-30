"""Trace filesystem replay and output decode failure regressions."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import mmap
from pathlib import Path
import signal
import threading
import time

import pytest
import requests
import yaml
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from utils.fluent_bit_manager import FluentBitManager
from utils.memory_check import memory_check_enabled
from utils.network import find_available_port


def wait_until(predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail(f"Timed out waiting for {description}")


def trace_payload(codes, batch=0):
    spans = [{
        "traceId": "0123456789abcdef0123456789abcdef",
        "spanId": f"{index + 1:016x}",
        "name": f"batch-{batch}-status-{code}",
        "status": {"code": code, "message": f"message-{code}"},
    } for index, code in enumerate(codes)]
    return {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}


def start_sink(release, received, lock):
    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if release.is_set():
                request = ExportTraceServiceRequest.FromString(body)
                spans = [span for resource in request.resource_spans
                         for scope in resource.scope_spans for span in scope.spans]
                with lock:
                    received[int(self.path[1:])].extend(
                        (span.name, span.status.code, span.status.message) for span in spans
                    )
            self.send_response(200 if release.is_set() else 503)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    return sink, thread


def write_config(path, storage, input_port, sink_port, routes, flush=1):
    path.write_text(yaml.safe_dump({
        "service": {
            "flush": flush, "grace": 1, "log_level": "debug",
            "storage.path": str(storage), "storage.sync": "full",
            "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{"name": "opentelemetry", "port": input_port,
                        "http2": False, "storage.type": "filesystem"}],
            "outputs": [{"name": "opentelemetry", "match": "*", "host": "127.0.0.1",
                         "port": sink_port, "traces_uri": f"/{route}",
                         "retry_limit": False} for route in range(routes)],
        },
    }))


def send_traces(port, codes, batch=0):
    response = requests.post(f"http://127.0.0.1:{port}/v1/traces",
                             json=trace_payload(codes, batch), timeout=15)
    assert response.status_code in (200, 201), response.text


def test_trace_shutdown_completes_inflight_request(tmp_path):
    entered = threading.Event()
    release = threading.Event()
    received = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            entered.set()
            if not release.wait(15):
                return
            received.append(ExportTraceServiceRequest.FromString(body))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    storage = tmp_path / "storage"
    config = tmp_path / "fluent-bit.yaml"
    input_port = find_available_port()
    write_config(config, storage, input_port, sink.server_port, 1)
    settings = yaml.safe_load(config.read_text())
    settings["service"]["grace"] = 5
    config.write_text(yaml.safe_dump(settings))
    manager = FluentBitManager(str(config))
    timer = None
    try:
        manager.start()
        send_traces(input_port, [3])
        assert entered.wait(15), "The output request did not reach the receiver"
        # Let the suspended HTTP callback finish while shutdown waits for its task.
        timer = threading.Timer(0.5, release.set)
        timer.start()
        manager.stop()
        assert len(received) == 1
        spans = [span for resource in received[0].resource_spans
                 for scope in resource.scope_spans for span in scope.spans]
        assert [(span.name, span.status.code) for span in spans] == [("batch-0-status-3", 3)]
        assert not list(storage.glob("*/*.flb"))
    finally:
        release.set()
        if timer:
            timer.cancel()
        manager.stop()
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("routes", [1, 2], ids=["single-route", "fan-out"])
@pytest.mark.parametrize("shutdown", ["graceful", "crash"])
def test_trace_filesystem_restart(tmp_path, routes, shutdown):
    if shutdown == "crash" and not hasattr(signal, "SIGKILL"):
        pytest.skip("requires POSIX SIGKILL")
    if shutdown == "crash" and memory_check_enabled():
        pytest.skip("SIGKILL prevents the memory checker from producing its final summary")
    release = threading.Event()
    received = [[] for _ in range(routes)]
    lock = threading.Lock()
    sink, thread = start_sink(release, received, lock)
    storage = tmp_path / "storage"
    config = tmp_path / "fluent-bit.yaml"
    input_port = find_available_port()
    write_config(config, storage, input_port, sink.server_port, routes)
    manager = FluentBitManager(str(config))
    codes = [0, 1, 2, -2147483648, -1, 3, 2147483647]
    expected = sorted((f"batch-{batch}-status-{code}", code, f"message-{code}")
                      for batch in range(2) for code in codes)
    try:
        manager.start()
        send_traces(input_port, codes, 0)
        send_traces(input_port, codes, 1)
        if shutdown == "crash":
            manager.send_signal(signal.SIGKILL)
            manager.process.wait(timeout=5)
        manager.stop()
        assert list(storage.glob("*/*.flb")), "Pending trace chunks were not persisted"
        release.set()
        manager.start()

        def drained():
            with lock:
                return all(sorted(spans) == expected for spans in received)

        wait_until(drained, "all persisted traces to reach every output")
        wait_until(lambda: not list(storage.glob("*/*.flb")), "trace chunk deletion after export")
        log = Path(manager.log_file).read_text()
        assert "flush backlog chunk" in log
        assert "chunk validation failed" not in log
    finally:
        manager.stop()
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(not hasattr(signal, "SIGSTOP"), reason="requires POSIX process suspension")
@pytest.mark.parametrize("corrupt_context", [0, 1], ids=["first", "after-valid-prefix"])
def test_trace_output_decode_failure(tmp_path, corrupt_context):
    release = threading.Event()
    release.set()
    received = [[]]
    lock = threading.Lock()
    sink, thread = start_sink(release, received, lock)
    storage = tmp_path / "storage"
    config = tmp_path / "fluent-bit.yaml"
    input_port = find_available_port()
    write_config(config, storage, input_port, sink.server_port, 1, flush=60)
    manager = FluentBitManager(str(config))
    suspended = False
    try:
        manager.start()
        for batch in range(3):
            send_traces(input_port, [3], batch)
        manager.send_signal(signal.SIGSTOP)
        suspended = True
        chunks = list(storage.glob("*/*.flb"))
        assert len(chunks) == 1
        with chunks[0].open("r+b") as stream:
            with mmap.mmap(stream.fileno(), 0) as data:
                # Replace one int32 status with a boolean without changing chunk size.
                marker = b"\xa4code\x03"
                positions = []
                offset = 0
                while (offset := data.find(marker, offset)) >= 0:
                    positions.append(offset + len(marker) - 1)
                    offset += len(marker)
                assert len(positions) == 3
                data[positions[corrupt_context]] = 0xc3
                data.flush()
        manager.send_signal(signal.SIGCONT)
        suspended = False
        # Shutdown flushes the pending live chunk before the normal 60s interval.
        manager.stop()
        log = Path(manager.log_file).read_text()
        assert "could not decode traces msgpack" in log, log
        with lock:
            assert received == [[]], "A corrupt trace chunk was partially exported"
    finally:
        if suspended:
            manager.send_signal(signal.SIGCONT)
        manager.stop()
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=5)
