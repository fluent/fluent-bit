"""Trace filesystem replay and output decode failure regressions."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import gzip
import mmap
from pathlib import Path
import signal
import socket
import socketserver
import threading
import time

import pytest
import requests
import yaml
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded
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


@pytest.mark.parametrize("corrupt_context", [0, 1], ids=["first", "after-valid-prefix"])
def test_trace_restart_rejects_corrupt_chunk(tmp_path, corrupt_context):
    release = threading.Event()
    received = [[]]
    lock = threading.Lock()
    sink, thread = start_sink(release, received, lock)
    storage = tmp_path / "storage"
    config = tmp_path / "fluent-bit.yaml"
    input_port = find_available_port()
    write_config(config, storage, input_port, sink.server_port, 1)
    manager = FluentBitManager(str(config))
    try:
        manager.start()
        for batch in range(3):
            send_traces(input_port, [3], batch)
        manager.stop()
        chunks = list(storage.glob("*/*.flb"))
        assert len(chunks) == 1
        data = bytearray(chunks[0].read_bytes())
        marker = b"\xa4code\x03"
        positions = []
        offset = 0
        while (offset := data.find(marker, offset)) >= 0:
            positions.append(offset + len(marker) - 1)
            offset += len(marker)
        assert len(positions) == 3
        data[positions[corrupt_context]] = 0xc3
        chunks[0].write_bytes(data)
        release.set()
        manager.start()
        wait_until(lambda: "traces chunk validation failed" in Path(manager.log_file).read_text(),
                   "corrupt backlog rejection")
        manager.stop()
        with lock:
            assert received == [[]], "A corrupt persisted trace chunk was partially exported"
    finally:
        manager.stop()
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("transport", ["http", "http2", "grpc"])
@pytest.mark.parametrize("routes", [1, 2], ids=["single-route", "fan-out"])
def test_trace_shutdown_aborts_inflight_requests_and_replays(tmp_path, transport, routes):
    release = threading.Event()
    entered = threading.Event()
    stopping = threading.Event()
    received = [[] for _ in range(routes)]
    lock = threading.Lock()
    pending_requests = set()

    def capture(path, headers, body):
        if transport == "grpc":
            compressed = body[0]
            body = body[5:]
        else:
            compressed = headers.get("content-encoding") == "gzip"
        if compressed:
            body = gzip.decompress(body)
        request = ExportTraceServiceRequest.FromString(body)
        spans = [span for resource in request.resource_spans
                 for scope in resource.scope_spans for span in scope.spans]
        if not release.is_set():
            with lock:
                pending_requests.update((path, span.name) for span in spans)
                if len(pending_requests) == routes * 2:
                    entered.set()
            return False
        with lock:
            received[int(path[1:])].extend(
                (span.name, span.status.code) for span in spans
            )
        return True

    class HttpSink(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if not capture(self.path, self.headers, body):
                if not release.wait(30):
                    return
            try:
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    class H2Sink(socketserver.BaseRequestHandler):
        def handle(self):
            connection = H2Connection(H2Configuration(client_side=False,
                                                       header_encoding="utf-8"))
            connection.initiate_connection()
            self.request.sendall(connection.data_to_send())
            self.request.settimeout(1)
            streams = {}
            while not stopping.is_set():
                try:
                    data = self.request.recv(65536)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    return
                if not data:
                    return
                for event in connection.receive_data(data):
                    if isinstance(event, RequestReceived):
                        streams[event.stream_id] = [dict(event.headers), bytearray()]
                    elif isinstance(event, DataReceived):
                        streams[event.stream_id][1].extend(event.data)
                        connection.acknowledge_received_data(event.flow_controlled_length,
                                                            event.stream_id)
                    elif isinstance(event, StreamEnded):
                        headers, body = streams.pop(event.stream_id)
                        if capture(headers[":path"], headers, bytes(body)):
                            if transport == "grpc":
                                connection.send_headers(event.stream_id,
                                                        [(":status", "200"),
                                                         ("content-type", "application/grpc")])
                                connection.send_data(event.stream_id, b"\x00" * 5)
                                connection.send_headers(event.stream_id,
                                                        [("grpc-status", "0")], end_stream=True)
                            else:
                                connection.send_headers(event.stream_id,
                                                        [(":status", "200"),
                                                         ("content-length", "0")], end_stream=True)
                try:
                    self.request.sendall(connection.data_to_send())
                except (BrokenPipeError, ConnectionResetError):
                    return

    server_type = ThreadingHTTPServer if transport == "http" else socketserver.ThreadingTCPServer
    handler = HttpSink if transport == "http" else H2Sink
    sink = server_type(("127.0.0.1", 0), handler)
    sink.daemon_threads = True
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    storage = tmp_path / "storage"
    config = tmp_path / "fluent-bit.yaml"
    ports = [find_available_port(), find_available_port()]
    write_config(config, storage, ports[0], sink.server_address[1], routes)
    settings = yaml.safe_load(config.read_text())
    settings["pipeline"]["inputs"].append(dict(settings["pipeline"]["inputs"][0],
                                               port=ports[1], tag="second-input"))
    for route, output in enumerate(settings["pipeline"]["outputs"]):
        output.update({"compress": "gzip", "net.io_timeout": 120,
                       "http2": "off" if transport == "http" else "force",
                       "grpc": transport == "grpc", "grpc_traces_uri": f"/{route}"})
    config.write_text(yaml.safe_dump(settings))
    manager = FluentBitManager(str(config))
    expected = [("batch-0-status-3", 3), ("batch-1-status-3", 3)]
    try:
        manager.start()
        for batch, port in enumerate(ports):
            send_traces(port, [3], batch)
        assert entered.wait(20), "Not all output callbacks reached socket I/O"
        manager.stop()
        assert list(storage.glob("*/*.flb")), "Aborted requests lost their persisted chunks"
        release.set()
        manager.start()

        def drained():
            with lock:
                return all(sorted(spans) == expected for spans in received)

        wait_until(drained, "aborted traces to replay to every output")
        wait_until(lambda: not list(storage.glob("*/*.flb")), "successful replay to release chunks")
    finally:
        release.set()
        manager.stop()
        stopping.set()
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=5)
