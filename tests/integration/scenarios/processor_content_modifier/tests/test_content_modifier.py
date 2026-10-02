"""Content modifier correctness across input/output processing and fan-out."""

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
import re
import threading

import pytest
import requests
import yaml

from utils.test_service import FluentBitTestService


RECORDS = [
    {"id": 1, "target": "original", "nested": {"array": [None, True, 1, 1.5]}},
    {"id": 2, "other": "untouched"},
]


def processor_metrics(text, scope, owner="http.0"):
    values = {}
    for line in text.splitlines():
        if not line.startswith("fluentbit_processor_") or "{" not in line:
            continue
        name, body = line.split("{", 1)
        labels, value = body.split("}", 1)
        labels = dict(re.findall(r'(\w+)="([^"]*)"', labels))
        if labels.get("scope") == scope and labels.get("owner") == owner:
            values[(name, int(labels["stage"]))] = float(value.split()[0])
    return values


def run_pipeline(tmp_path, processors, expected, *, location="input", storage="memory",
                 records=None, copies=1, stage_counts=None, input_workers=1,
                 output_workers=2, input_threaded=False, clients=4, unique_copies=False):
    records = RECORDS if records is None else records
    total_records = len(records) * copies
    stage_counts = ([(len(records), len(records))] * len(processors)
                    if stage_counts is None else stage_counts)
    assert len(stage_counts) == len(processors)
    route_counts = [len(expected) * copies,
                    len(expected if location == "input" else records) * copies]
    received = [[], []]
    lock = threading.Lock()

    class Sink(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            records = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            with lock:
                received[int(self.path[1:])].extend(records)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    class SinkServer(ThreadingHTTPServer):
        request_queue_size = 128

    sink = SinkServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    input_config = {
        "name": "http", "listen": "127.0.0.1",
        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "tag": "test",
        "storage.type": storage, "workers": input_workers, "threaded": input_threaded,
    }
    outputs = [{
        "name": "http", "match": "*", "host": "127.0.0.1",
        "port": sink.server_port, "uri": f"/{route}", "format": "json",
        "json_date_key": False, "workers": output_workers,
    } for route in range(2)]
    if location == "input":
        input_config["processors"] = {"logs": processors}
    else:
        outputs[0]["processors"] = {"logs": processors}
    config = {
        "service": {"flush": 0.1, "grace": 1, "log_level": "error",
                    "storage.path": str(tmp_path / "storage"),
                    "http_server": True, "http_listen": "127.0.0.1",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [input_config], "outputs": outputs},
    }
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    try:
        service.start()
        def send(index):
            batch = deepcopy(records)
            if unique_copies:
                for record in batch:
                    record["id"] += index * len(records)
                    record["request"] = index
            response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/test.{index}",
                                     json=batch, timeout=30)
            assert response.status_code == 201, response.text

        with ThreadPoolExecutor(max_workers=min(copies, clients)) as pool:
            list(pool.map(send, range(copies)))
        service.wait_for_condition(
            lambda: all(len(route_records) >= count
                        for route_records, count in zip(received, route_counts)),
            timeout=30, interval=0.1, description="both output routes to finish",
        )
        scope = "input" if location == "input" else "output"

        def metrics_ready():
            response = requests.get(
                f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus",
                timeout=10,
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            values = processor_metrics(response.text, scope)
            for stage, counts in enumerate(stage_counts):
                for metric, count in zip(["items_in_total", "items_out_total"], counts):
                    if values.get(("fluentbit_processor_" + metric, stage), 0) != count * copies:
                        return None
            return values

        values = service.wait_for_condition(metrics_ready, timeout=30, interval=0.2,
                                             description="per-processor accounting")
        invocations = values[("fluentbit_processor_invocations_total", 0)]
        if location == "input" and input_workers == 1:
            assert invocations == total_records
        elif copies == 1:
            assert invocations == 1
        else:
            assert 1 <= invocations <= total_records
        for stage in range(len(processors)):
            assert values[("fluentbit_processor_invocations_total", stage)] == invocations
            assert values.get(("fluentbit_processor_errors_total", stage), 0) == 0
            before, after = stage_counts[stage]
            assert values.get(("fluentbit_processor_items_drop_total", stage), 0) == (
                max(0, before - after) * copies
            )
            assert values.get(("fluentbit_processor_items_add_total", stage), 0) == (
                max(0, after - before) * copies
            )

    finally:
        try:
            service.stop()
        finally:
            sink.shutdown()
            sink.server_close()
            thread.join(timeout=5)
    def copied_records(source):
        result = []
        for index in range(copies):
            batch = deepcopy(source)
            if unique_copies:
                for record in batch:
                    record["id"] += index * len(records)
                    record["request"] = index
            result.extend(batch)
        return sorted(result, key=lambda record: record["id"])

    assert sorted(received[0], key=lambda record: record["id"]) == copied_records(expected)
    control = expected if location == "input" else records
    assert sorted(received[1], key=lambda record: record["id"]) == copied_records(control)


@pytest.mark.parametrize("action", ["insert", "upsert", "delete", "rename"])
@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("storage", ["memory", "filesystem"])
def test_body_actions(tmp_path, action, location, storage):
    processor = {"name": "content_modifier", "context": "body", "action": action,
                 "key": "target"}
    if action != "delete":
        processor["value"] = "replacement"
    expected = deepcopy(RECORDS)
    for record in expected:
        if action == "insert":
            record.setdefault("target", "replacement")
        elif action == "upsert":
            record["target"] = "replacement"
        elif action == "delete":
            record.pop("target", None)
        elif "target" in record:
            record["replacement"] = record.pop("target")
    run_pipeline(tmp_path, [processor], expected, location=location, storage=storage)


@pytest.mark.parametrize("location", ["input", "output"])
def test_mixed_processor_chain_and_condition(tmp_path, location):
    processors = [
        {"name": "content_modifier", "action": "insert", "key": "inserted", "value": "yes"},
        # A filter boundary consumes raw buffers and materializes them independently.
        {"name": "modify", "add": "filtered yes"},
        {"name": "content_modifier", "action": "upsert", "key": "conditional", "value": "yes",
         "condition": {"op": "and", "rules": [{"field": "$target", "op": "eq", "value": "original"}]}},
        # Later native units must see the materialized condition result.
        {"name": "content_modifier", "action": "rename", "key": "target", "value": "renamed"},
        {"name": "content_modifier", "action": "delete", "key": "inserted"},
    ]
    expected = deepcopy(RECORDS)
    for record in expected:
        record["filtered"] = "yes"
    expected[0]["conditional"] = "yes"
    expected[0]["renamed"] = expected[0].pop("target")
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem")


@pytest.mark.parametrize("action,key", [("insert", "id"), ("delete", "missing"),
                                        ("rename", "missing")])
@pytest.mark.parametrize("location", ["input", "output"])
def test_body_noop_preserves_shared_buffer(tmp_path, action, key, location):
    processor = {"name": "content_modifier", "action": action, "key": key}
    if action != "delete":
        processor["value"] = "replacement"
    run_pipeline(tmp_path, [processor], RECORDS, location=location, storage="filesystem")


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("mixed", [False, True], ids=["fused", "cfl-fallback"])
def test_ordered_native_segment(tmp_path, location, mixed):
    processors = [
        {"name": "content_modifier", "action": "insert", "key": "stage0", "value": "initial"},
        {"name": "content_modifier", "action": "rename", "key": "stage0", "value": "stage1"},
        {"name": "content_modifier", "action": "upsert", "key": "stage1", "value": "updated"},
        {"name": "content_modifier", "action": "delete", "key": "target"},
        {"name": "content_modifier", "action": "insert", "key": "target", "value": "done"},
        {"name": "content_modifier", "action": "delete", "key": "stage1"},
    ]
    expected = deepcopy(RECORDS)
    for record in expected:
        record["target"] = "done"
    if mixed:
        processors.append({"name": "content_modifier", "action": "hash", "key": "target"})
        for record in expected:
            record["target"] = hashlib.sha256(b"done").hexdigest()
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem")


@pytest.mark.parametrize("location", ["input", "output"])
def test_concurrent_fused_segments(tmp_path, location):
    processors = [{"name": "content_modifier", "action": "upsert", "key": f"field{index}",
                   "value": f"value{index}"} for index in range(6)]
    records = [{"id": index, "nested": {"values": [True, None, index]}}
               for index in range(256)]
    expected = deepcopy(records)
    for record in expected:
        record.update({f"field{index}": f"value{index}" for index in range(6)})
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem",
                 records=records, copies=8)


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("keep_id", [1, 99], ids=["partial-drop", "empty-batch"])
def test_native_drop_accounting(tmp_path, location, keep_id):
    # SQL and both modifiers share CFL, including when SQL removes every record.
    processors = [
        {"name": "content_modifier", "action": "insert", "key": "before", "value": "yes"},
        {"name": "sql", "query": f"SELECT * FROM STREAM WHERE id = {keep_id};"},
        {"name": "content_modifier", "action": "insert", "key": "after", "value": "yes"},
    ]
    expected = [dict(record, before="yes", after="yes")
                for record in RECORDS if record["id"] == keep_id]
    remaining = len(expected)
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem",
                 stage_counts=[(2, 2), (2, remaining), (remaining, remaining)])


@pytest.mark.parametrize("location", ["input", "output"])
def test_multiple_fused_segments_and_noop_tail(tmp_path, location):
    processors = [
        {"name": "content_modifier", "action": "insert", "key": "stage0", "value": "yes"},
        {"name": "content_modifier", "action": "rename", "key": "stage0", "value": "stage1"},
        {"name": "modify", "rename": "stage1 filtered"},
        {"name": "content_modifier", "action": "rename", "key": "filtered", "value": "stage2"},
        {"name": "content_modifier", "action": "upsert", "key": "stage2", "value": "done"},
        {"name": "modify", "add": "boundary yes"},
        # NOTOUCH must retain the buffer allocated by the preceding segment/filter.
        {"name": "content_modifier", "action": "insert", "key": "id", "value": "unused"},
        {"name": "content_modifier", "action": "delete", "key": "missing"},
    ]
    expected = [dict(record, stage2="done", boundary="yes") for record in RECORDS]
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem")


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("matches", [True, False], ids=["condition-matches", "condition-false"])
def test_condition_observes_previous_native_edit(tmp_path, location, matches):
    processors = [
        {"name": "content_modifier", "action": "insert", "key": "gate", "value": "ready"},
        {"name": "content_modifier", "action": "upsert", "key": "conditional", "value": "yes",
         "condition": {"op": "and", "rules": [
             {"field": "$gate", "op": "eq", "value": "ready" if matches else "absent"}]}},
        {"name": "content_modifier", "action": "rename", "key": "gate", "value": "renamed"},
    ]
    expected = [dict(record, renamed="ready") for record in RECORDS]
    if matches:
        for record in expected:
            record["conditional"] = "yes"
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem")


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("depth", [4, 40], ids=["raw-compatible", "deep-cfl-fallback"])
def test_nested_and_boundary_values(tmp_path, location, depth):
    nested = {"values": [None, True, False, -9223372036854775808, 18446744073709551615,
                         1.25, "embedded\0nul", "Unicode: café 日本語", [], {}]}
    for _ in range(depth):
        nested = {"nested": nested}
    # On output, a deep second record forces fallback after the first was rewritten.
    records = [{"id": 1, "target": "original", "payload": {},
                "large": "x" * 65536}, {"id": 2, "payload": nested}]
    processors = [
        {"name": "content_modifier", "action": "upsert", "key": "target", "value": "updated"},
        {"name": "content_modifier", "action": "rename", "key": "target", "value": "renamed"},
    ]
    expected = [dict(record, renamed="updated") for record in records]
    for record in expected:
        record.pop("target", None)
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem",
                 records=records)


@pytest.mark.parametrize("location", ["input", "output"])
def test_fused_mixed_noop_and_growing_maps(tmp_path, location):
    records = [
        {"id": 1, "target": {"nested": [True, None, "preserved"]}},
        dict({"id": 2}, **{f"field{index}": f"value{index}" for index in range(128)}),
        {"id": 3, "target": "last-record"},
        {"id": 4},
    ]
    processors = [
        {"name": "content_modifier", "action": "insert", "key": "id", "value": "unused"},
        {"name": "content_modifier", "action": "rename", "key": "target", "value": "renamed"},
        {"name": "content_modifier", "action": "delete", "key": "missing"},
    ]
    expected = deepcopy(records)
    for record in expected:
        if "target" in record:
            record["renamed"] = record.pop("target")
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem",
                 records=records)


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("threaded", [False, True], ids=["engine-input", "threaded-input"])
@pytest.mark.parametrize("chain", ["fused", "filter-boundary"])
def test_worker_threads_preserve_independent_batches(tmp_path, location, threaded, chain):
    records = [dict({"id": index, "target": f"record-{index}"},
                    **{f"field{field}": "payload" * 16 for field in range(32)})
               for index in range(128)]
    processors = [{"name": "content_modifier", "action": "upsert", "key": f"stage{index}",
                   "value": f"value{index}"} for index in range(6)]
    expected = deepcopy(records)
    for record in expected:
        record.update({f"stage{index}": f"value{index}" for index in range(6)})
    if chain == "filter-boundary":
        processors.insert(3, {"name": "modify", "add": "boundary yes"})
        for record in expected:
            record["boundary"] = "yes"
    run_pipeline(tmp_path, processors, expected, location=location, storage="filesystem",
                 records=records, copies=32, clients=8, unique_copies=True,
                 input_workers=4, output_workers=4, input_threaded=threaded)
