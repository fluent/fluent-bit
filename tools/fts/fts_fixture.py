#!/usr/bin/env python3
"""Run typed FTS fixtures against a real local Fluent Bit binary (no policy simulation)."""
import argparse
import base64
import copy
import gzip
import http.server
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import struct
import sys
import subprocess
import tempfile
import threading
import time
import urllib.request
import urllib.error

import msgpack
import yaml


class FixtureLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("fixture map keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def integer(loader, node, unsigned=False):
    text = loader.construct_scalar(node)
    if not re.fullmatch(r"-?[0-9]+", text):
        raise ValueError("integer tags require a decimal integer")
    value = int(text)
    minimum, maximum = (0, 2**64 - 1) if unsigned else (-2**63, 2**63 - 1)
    if not minimum <= value <= maximum:
        raise ValueError("integer tag is out of range")
    return value


FixtureLoader.add_constructor("!int64", integer)
FixtureLoader.add_constructor("!uint64", lambda loader, node: integer(loader, node, True))
FixtureLoader.add_constructor("!double", lambda loader, node: float(loader.construct_scalar(node)))


def validate_tree(value, depth=0):
    if depth > 40:
        raise ValueError("fixture nesting exceeds 40")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("map keys must be strings")
            validate_tree(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            validate_tree(child, depth + 1)
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError("nonfinite fixture number")
    elif type(value) is int:
        if not -2**63 <= value < 2**64:
            raise ValueError("fixture integer is out of range")
    elif value is not None and type(value) not in (str, bytes, bool):
        raise ValueError(f"unsupported fixture type: {type(value).__name__}")


def load_fixture(path):
    data = path.read_text()
    if len(data.encode()) > 4 * 1024 * 1024:
        raise ValueError("fixture exceeds 4 MiB")
    if any(isinstance(event, yaml.AliasEvent) for event in yaml.parse(data)):
        raise ValueError("fixture aliases are not supported")
    fixture = yaml.load(data, Loader=FixtureLoader)
    validate_tree(fixture)
    if not isinstance(fixture, dict) or (type(fixture.get("fixture_version")) is not int or fixture["fixture_version"] != 1):
        raise ValueError("fixture_version must be 1")
    if fixture.get("signal") not in ("logs", "metrics", "traces"):
        raise ValueError("signal must be logs, metrics or traces")
    if set(fixture) - {"fixture_version", "signal", "transport", "environment", "processor", "cases"}:
        raise ValueError("unknown fixture field")
    if fixture.get("transport", "forward" if fixture["signal"]=="logs" else "otlp") not in ("forward", "otlp"):
        raise ValueError("unknown fixture transport")
    if fixture["signal"]!="logs" and fixture.get("transport", "otlp")!="otlp":
        raise ValueError("metrics/traces require OTLP")
    if not isinstance(fixture.get("processor"), dict) or fixture["processor"].get("name") != "fts":
        raise ValueError("processor must configure fts")
    if not isinstance(fixture.get("cases"), list) or not fixture["cases"]:
        raise ValueError("cases must be a nonempty array")
    environment = fixture.get("environment", {})
    if not isinstance(environment, dict) or len(environment) > 16:
        raise ValueError("fixture environment must be a map of at most 16 entries")
    for name, value in environment.items():
        if (not re.fullmatch(r"FTS_FIXTURE_[A-Z0-9_]{1,110}", name) or
                type(value) is not str or len(value.encode()) > 4096 or "\x00" in value):
            raise ValueError("only bounded public FTS_FIXTURE_ environment values are permitted")
    names = set()
    for case in fixture["cases"]:
        if not isinstance(case, dict) or set(case) != {"name", "input", "expected"}:
            raise ValueError("each case requires name, input and expected")
        if not isinstance(case["name"], str) or case["name"] in names:
            raise ValueError("case names must be unique strings")
        names.add(case["name"])
        expected = case["expected"]
        if not isinstance(expected, dict) or set(expected) - {"records", "otlp", "outcomes", "error", "metric_window_families"}:
            raise ValueError("unknown expected field")
        required = "records" if fixture["signal"] == "logs" and fixture.get("transport", "forward")=="forward" else "otlp"
        window = expected.get("metric_window_families")
        if window is not None:
            if (fixture["signal"] != "metrics" or not isinstance(window, dict) or
                    set(window) != {"held", "released", "reduced", "pending"} or
                    any(type(v) is not int or v < 0 for v in window.values())):
                raise ValueError("metric_window_families requires explicit nonnegative family counts")
        if required not in expected:
            raise ValueError(f"expected.{required} is required")
        if required == "records":
            for key, records in (("input", case["input"]), ("expected.records", expected["records"])):
                if not isinstance(records, list):
                    raise ValueError(f"{key} must be an array of Forward log records")
                for record in records:
                    normalized_log(record)
        else:
            batches = case["input"] if isinstance(case["input"], list) else [case["input"]]
            for batch in batches:
                otlp_message(fixture["signal"], batch)
            otlp_message(fixture["signal"], expected["otlp"])
    return fixture


def equal(actual, expected, path="output"):
    # Python considers True == 1 and 1 == 1.0. Telemetry fixtures must not.
    if type(actual) is not type(expected):
        raise AssertionError(f"{path}: type {type(actual).__name__} != {type(expected).__name__}")
    if isinstance(actual, dict):
        if actual.keys() != expected.keys():
            raise AssertionError(f"{path}: keys differ: {actual.keys()} != {expected.keys()}")
        for key in expected:
            equal(actual[key], expected[key], f"{path}.{key}")
    elif isinstance(actual, list):
        if len(actual) != len(expected):
            raise AssertionError(f"{path}: length {len(actual)} != {len(expected)}")
        for index, (left, right) in enumerate(zip(actual, expected)):
            equal(left, right, f"{path}[{index}]")
    elif actual != expected:
        raise AssertionError(f"{path}: value mismatch")


def port_pair():
    """Reserve both listener ports together so they cannot select the same port."""
    with socket.socket() as ingress, socket.socket() as monitor:
        ingress.bind(("127.0.0.1", 0))
        monitor.bind(("127.0.0.1", 0))
        return ingress.getsockname()[1], monitor.getsockname()[1]


def stop_process(process):
    """Reap the isolated native process, killing its process group on timeout."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=40)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.wait(timeout=10)
        raise AssertionError("Fluent Bit shutdown timed out; process group killed")


def fixture_sample(labels, source, signal_name, stage):
    """Select metrics for this fixture processor instead of auxiliary stages."""
    parsed = dict(re.findall(r'(\w+)="([^"\n]*)"', labels))
    return (parsed.get("name") == source + ".0" and parsed.get("scope") == "input" and
            parsed.get("processor") == "fts" and parsed.get("signal") == signal_name and
            parsed.get("stage") == str(stage))


def unpacker():
    def pairs(entries):
        result = {}
        for key, value in entries:
            if not isinstance(key, str) or key in result:
                raise ValueError("output contains duplicate or nonstring map keys")
            result[key] = value
        return result
    return msgpack.Unpacker(raw=False, strict_map_key=True, object_pairs_hook=pairs,
                            max_buffer_size=16 * 1024 * 1024)


def otlp_message(signal, payload=None):
    from google.protobuf.json_format import ParseDict
    if signal == "logs":
        from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
        message = ExportLogsServiceRequest()
    elif signal == "metrics":
        from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
        message = ExportMetricsServiceRequest()
    else:
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
        message = ExportTraceServiceRequest()
    def ids(value):
        if isinstance(value, dict):
            return {key: base64.b64encode(bytes.fromhex(child)).decode() if key in
                    ("traceId", "spanId", "parentSpanId") else ids(child) for key, child in value.items()}
        if isinstance(value, list):
            return [ids(child) for child in value]
        return value
    if payload is not None:
        ParseDict(ids(payload), message, ignore_unknown_fields=False)
    return message


def equal_otlp(actual, expected):
    """Compare every protobuf field, including unknown wire fields and presence."""
    if actual != expected:
        from google.protobuf.json_format import MessageToDict
        equal(MessageToDict(actual), MessageToDict(expected), "otlp")
        raise AssertionError("OTLP wire fields differ despite equal JSON projections")


class Capture:
    def __init__(self, signal, otlp=False):
        self.otlp=otlp
        self.signal, self.messages, self.errors = signal, [], []
        self.closed = False
        self.stopped = threading.Event()
        if signal == "logs" and not otlp:
            self.server = socket.socket()
            self.server.bind(("127.0.0.1", 0))
            self.server.listen(8)
            self.server.settimeout(0.1)
            self.port = self.server.getsockname()[1]
            target = self.forward
        else:
            capture = self
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_POST(self):
                    try:
                        size = int(self.headers.get("Content-Length", 0))
                        if not 0 < size <= 16 * 1024 * 1024:
                            raise ValueError("invalid OTLP payload length")
                        body = self.rfile.read(size)
                        if self.headers.get("Content-Encoding") == "gzip":
                            body = gzip.decompress(body)
                        message = otlp_message(signal)
                        message.ParseFromString(body)
                        capture.messages.append(message)
                        self.send_response(200)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                    except Exception as exc:
                        capture.errors.append(exc)
                        self.send_error(400)
                def log_message(self, *args):
                    pass
            self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            self.port = self.server.server_address[1]
            target = self.server.serve_forever
        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()

    def forward(self):
        try:
            while True:
                try:
                    connection, _ = self.server.accept()
                except socket.timeout:
                    if self.stopped.is_set():
                        break
                    continue
                with connection:
                    connection.settimeout(0.1)
                    decoder = unpacker()
                    while True:
                        try:
                            data = connection.recv(65536)
                        except socket.timeout:
                            if self.stopped.is_set():
                                break
                            continue
                        if not data:
                            break
                        decoder.feed(data)
                        self.messages.extend(decoder)
        except Exception as exc:
            self.errors.append(exc)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.stopped.set()
        if self.signal != "logs" or self.otlp:
            self.server.shutdown()
            self.server.server_close()
        self.thread.join(2)
        if self.thread.is_alive():
            raise AssertionError("capture did not drain before shutdown")
        if self.signal == "logs" and not self.otlp:
            self.server.close()
        if self.errors:
            raise AssertionError(f"capture failed: {self.errors}")


def normalized_log(record):
    if not isinstance(record, dict) or "body" not in record or set(record) - {"body", "metadata", "timestamp", "tag"}:
        raise ValueError("log record requires body; optional metadata, timestamp, tag")
    if not isinstance(record["body"], dict):
        raise ValueError("Forward log fixtures require a map body; arbitrary OTLP log bodies need the OTLP log adapter")
    result = {"body": record["body"], "metadata": record.get("metadata", {}),
              "timestamp": record.get("timestamp", {"sec": 1700000000, "nsec": 0}),
              "tag": record.get("tag", "fts.fixture")}
    timestamp = result["timestamp"]
    if (not isinstance(timestamp, dict) or set(timestamp) != {"sec", "nsec"} or
            type(timestamp["sec"]) is not int or not 0 <= timestamp["sec"] < 2**32 or
            type(timestamp["nsec"]) is not int or not 0 <= timestamp["nsec"] < 10**9):
        raise ValueError("timestamp requires uint32 sec and nsec in [0,1000000000)")
    if not isinstance(result["metadata"], dict) or not isinstance(result["tag"], str):
        raise ValueError("invalid log metadata or tag")
    return result


def log_output(messages):
    result = []
    for message in messages:
        tag, entries = message[:2]
        if isinstance(entries, bytes):
            decoder = unpacker()
            decoder.feed(entries)
            entries = list(decoder)
        for timestamp, body in entries:
            metadata = {}
            if isinstance(timestamp, list):
                timestamp, metadata = timestamp
            if isinstance(timestamp, msgpack.ExtType) and timestamp.code == 0 and len(timestamp.data) == 8:
                sec, nsec = struct.unpack(">II", timestamp.data)
            elif type(timestamp) is int:
                sec, nsec = timestamp, 0
            else:
                raise AssertionError("unsupported output timestamp encoding")
            result.append({"tag": tag, "body": body, "metadata": metadata,
                           "timestamp": {"sec": sec, "nsec": nsec}})
    return result


class FixtureBindError(AssertionError):
    """A native listener failed before readiness and before sending fixture data."""


def _run_case(fixture, case, fixture_path, binary, valgrind=False, *, threaded=False,
             before_processors=(), after_processors=()):
    signal = fixture["signal"]
    otlp=signal!="logs" or fixture.get("transport", "forward")=="otlp"
    capture = Capture(signal,otlp)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="fts-fixture-") as temporary:
            directory = Path(temporary)
            log_path = directory / "fluent-bit.log"
            ingress, monitor = port_pair()
            processor = copy.deepcopy(fixture["processor"])
            if "packs" in processor:
                # Fixture refs are relative to the fixture; runtime refs are relative to packages_dir.
                manifests = [(fixture_path.parent / path).resolve() for path in processor["packs"]]
                root = Path(os.path.commonpath([str(path.parent) for path in manifests]))
                processor["packages_dir"] = str(root)
                processor["packs"] = [str(path.relative_to(root)) for path in manifests]
            source = {"name": "opentelemetry" if otlp else "forward",
                      "listen": "127.0.0.1", "port": ingress, "threaded": threaded,
                      "processors": {signal: [*[copy.deepcopy(step) for step in before_processors],
                          processor, *[copy.deepcopy(step) for step in after_processors]]}}
            output = {"name": "opentelemetry" if otlp else "forward",
                      "host": "127.0.0.1", "port": capture.port, "match": "*"}
            if otlp:
                output.update({"tls": False, "http2": False})
            config = {"service": {"flush": 0.2, "grace": 1, "http_server": True,
                      "http_listen": "127.0.0.1", "http_port": monitor},
                      "pipeline": {"inputs": [source], "outputs": [output]}}
            config_path = directory / "fluent-bit.yaml"
            config_path.write_text(yaml.safe_dump(config))
            command = [str(binary), "-c", str(config_path)]
            memory_log = directory / "valgrind.log"
            if valgrind:
                command = ["valgrind", "--error-exitcode=99", "--leak-check=full",
                           "--errors-for-leak-kinds=definite,indirect,possible",
                           f"--log-file={memory_log}", *command]
            try:
                with log_path.open("wb") as log:
                    process_environment = os.environ.copy()
                    process_environment.update(fixture.get("environment", {}))
                    process = subprocess.Popen(command, stdout=log, stderr=log, env=process_environment,
                                               start_new_session=(os.name == "posix"))
                    deadline = time.monotonic() + 40
                    metrics_url = f"http://127.0.0.1:{monitor}/api/v2/metrics/prometheus"
                    while True:
                        if process.poll() is not None:
                            diagnostics = log_path.read_text()
                            if process.returncode in (1, 255) and "Error binding socket" in diagnostics:
                                raise FixtureBindError("native listener port was taken before readiness")
                            raise AssertionError(f"Fluent Bit exited {process.returncode}: {diagnostics}")
                        try:
                            urllib.request.urlopen(metrics_url, timeout=1).close()
                            break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise AssertionError("Fluent Bit readiness timed out")
                            time.sleep(0.05)
                    if not otlp:
                        records = [normalized_log(record) for record in case["input"]]
                        with socket.create_connection(("127.0.0.1", ingress), timeout=10) as connection:
                            for record in records:
                                timestamp = record["timestamp"]
                                event_time = msgpack.ExtType(0, struct.pack(">II", timestamp["sec"], timestamp["nsec"]))
                                entry = [[event_time, record["metadata"]], record["body"]]
                                connection.sendall(msgpack.packb([record["tag"], [entry]], use_bin_type=True))
                        expected_callbacks = len(records)
                    else:
                        batches = case["input"] if isinstance(case["input"], list) else [case["input"]]
                        resource_key, scope_key, item_key = {"metrics":("resourceMetrics","scopeMetrics","metrics"),
                            "traces":("resourceSpans","scopeSpans","spans"),
                            "logs":("resourceLogs","scopeLogs","logRecords")}[signal]
                        expected_callbacks = 0
                        for batch in batches:
                            payload = otlp_message(signal, batch).SerializeToString()
                            request = urllib.request.Request(f"http://127.0.0.1:{ingress}/v1/{signal}",
                                data=payload, headers={"Content-Type": "application/x-protobuf"})
                            with urllib.request.urlopen(request, timeout=10) as response:
                                assert response.status in (200, 201)
                            expected_callbacks += sum(len(scope.get(item_key, [])) for resource in
                                batch.get(resource_key, []) for scope in resource.get(scope_key, []))
                    counts = {}
                    while True:
                        try:
                            with urllib.request.urlopen(metrics_url, timeout=2) as response:
                                metrics = response.read().decode()
                        except urllib.error.HTTPError as exc:
                            # The v2 snapshot can be briefly unavailable after readiness.
                            if exc.code not in (404, 503) or time.monotonic() >= deadline:
                                raise
                            time.sleep(0.05)
                            continue
                        counts = {outcome: sum(float(value) for labels, value in re.findall(
                            r'^fluentbit_fts_recipe_callbacks_total\{([^\n]*)\}\s+(\S+)', metrics, re.M)
                            if f'outcome="{outcome}"' in labels and
                            fixture_sample(labels, source['name'], signal, len(before_processors))) for outcome in ("keep", "drop", "error", "hold")}
                        window_expected = case["expected"].get("metric_window_families")
                        window_ready = True
                        if window_expected is not None:
                            events = re.findall(r'^fluentbit_fts_metric_window_family_events_total\{([^\n]*)\}\s+(\S+)', metrics, re.M)
                            events = [(labels,value) for labels,value in events
                                      if fixture_sample(labels, source["name"], signal, len(before_processors))]
                            inventory = re.findall(r'^fluentbit_fts_metric_window_pending_input_families\{([^\n]*)\}\s+(\S+)', metrics, re.M)
                            inventory = [(labels,value) for labels,value in inventory
                                         if fixture_sample(labels, source["name"], signal, len(before_processors))]
                            if any('unit="metric_families"' not in label for label, _ in events + inventory):
                                raise AssertionError("metric window accounting lacks family units")
                            window_counts = {outcome: int(sum(float(value) for labels, value in events
                                if f'outcome="{outcome}"' in labels)) for outcome in ("held", "released", "reduced")}
                            window_counts["pending"] = int(sum(float(value) for _, value in inventory))
                            window_ready = bool(events and inventory) and window_counts == window_expected
                            # Release accepts the ingress queue; wait for downstream capture too.
                            captured = sum(len(scope.metrics) for message in capture.messages
                                for resource in message.resource_metrics for scope in resource.scope_metrics)
                            expected_families = sum(len(scope.get("metrics", [])) for resource in
                                case["expected"]["otlp"].get("resourceMetrics", []) for scope in resource.get("scopeMetrics", []))
                            window_ready = window_ready and captured >= expected_families
                        if sum(counts.values()) >= expected_callbacks and window_ready:
                            break
                        if time.monotonic() >= deadline:
                            raise AssertionError(f"callback/window completion timed out: {counts}; {metrics}")
                        time.sleep(0.05)
                    # Graceful shutdown drains the real output, including expected zero-output cases.
                    stop_process(process)
                if process.returncode != 0:
                    raise AssertionError(f"Fluent Bit exited {process.returncode}: {log_path.read_text()}")
                capture.close()
                process = None
                if valgrind and "ERROR SUMMARY: 0 errors" not in memory_log.read_text():
                    raise AssertionError(memory_log.read_text())
                expected = case["expected"]
                if not otlp:
                    equal(log_output(capture.messages), [normalized_log(record) for record in expected["records"]])
                else:
                    actual = otlp_message(signal)
                    resource_key = {"metrics":"resource_metrics","traces":"resource_spans","logs":"resource_logs"}[signal]
                    for message in capture.messages:
                        getattr(actual, resource_key).extend(getattr(message, resource_key))
                    equal_otlp(actual, otlp_message(signal, expected["otlp"]))
                if counts["hold"] and "metric_window_families" not in expected:
                    raise ValueError("HOLD requires explicit temporal metric family expectations")
                if "outcomes" in expected:
                    actual_counts = {"kept": int(counts["keep"]), "errors": int(counts["error"]),
                        "dropped": int(counts["drop"] + (counts["error"] if processor.get("error_mode", "drop") == "drop" else 0))}
                    if "held" in expected["outcomes"]:
                        actual_counts["held"] = int(counts["hold"])
                    equal(actual_counts, expected["outcomes"], "outcomes")
                error = expected.get("error")
                diagnostics = log_path.read_text()
                if error and f"step={error['step']} class={error['class']}" not in diagnostics:
                    raise AssertionError("expected step/error class is absent")
                if not error and (counts["error"] or "edits rolled back" in diagnostics):
                    raise AssertionError("unexpected policy error")
            finally:
                if process is not None:
                    if process.poll() is None:
                        stop_process(process)
                capture.close()
    finally:
        capture.close()


def run_case(fixture, case, fixture_path, binary, valgrind=False, *, threaded=False,
             before_processors=(), after_processors=()):
    """Retry only listener races before readiness; never retry submitted telemetry."""
    for attempt in range(3):
        try:
            return _run_case(fixture, case, fixture_path, binary, valgrind,
                             threaded=threaded, before_processors=before_processors,
                             after_processors=after_processors)
        except FixtureBindError:
            if attempt == 2:
                raise
            print("RETRY listener bind before fixture ingestion", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", nargs="+", type=Path)
    parser.add_argument("--binary", type=Path, default=Path(os.environ.get("FLUENT_BIT_BINARY", "build/bin/fluent-bit")))
    parser.add_argument("--valgrind", action="store_true")
    args = parser.parse_args()
    failures = 0
    for path in args.fixtures:
        fixture = load_fixture(path.resolve())
        for case in fixture["cases"]:
            try:
                run_case(fixture, case, path.resolve(), args.binary.resolve(), args.valgrind)
                print(f"PASS {path}:{case['name']}", flush=True)
            except Exception as exc:
                failures += 1
                print(f"FAIL {path}:{case['name']}: {exc}", flush=True)
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
