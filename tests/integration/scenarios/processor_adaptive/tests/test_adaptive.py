"""Adaptive log reduction: pattern mining, accounting, routing and the policy loop."""

from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

import pytest
import requests
import yaml
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from utils.fluent_bit_manager import FluentBitManager
from utils.test_service import FluentBitTestService

REPO_ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "tools" / "adaptive"))
import recommend  # noqa: E402

NOISY_TEMPLATE = "GET <*> <NUM> took <NUM>ms"
CACHE_TEMPLATE = "cache hit key=<*> ttl=<NUM>s"


def noisy(index, level="info", phase=0):
    return {"level": level, "phase": phase, "kind": "noisy",
            "log": f"GET /api/items/{index} 200 took {index % 250}ms"}


def cache(index, level="debug", phase=0):
    return {"level": level, "phase": phase, "kind": "cache",
            "log": f"cache hit key=user:{index} ttl={index % 300}s"}


def failure(index, phase=0):
    return {"level": "error", "phase": phase, "kind": "failure",
            "log": f"upstream timeout after {1000 + index}ms host=db-{index % 3}"}


def append(path, records):
    with open(path, "a", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_records(path):
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def adaptive_metrics(port):
    """Return {(metric, frozenset(labels)): value} for the adaptive processor."""
    response = requests.get(f"http://127.0.0.1:{port}/api/v2/metrics/prometheus", timeout=10)
    if response.status_code != 200:
        return {}
    values = {}
    for line in response.text.splitlines():
        if not line.startswith("fluentbit_adaptive_") or "{" not in line:
            continue
        name, body = line.split("{", 1)
        labels, value = body.rsplit("}", 1)
        labels = dict(re.findall(r'(\w+)="([^"]*)"', labels))
        values[(name, frozenset(labels.items()))] = float(value.split()[0])
    return values


def metric_sum(values, metric, **labels):
    wanted = set(labels.items())
    return sum(value for (name, found), value in values.items()
               if name == metric and wanted <= found)


class Pipeline:
    """tail -> [adaptive] -> file outputs, with a raw control route."""

    def __init__(self, tmp_path, processor, *, location="output", workers=1, parser="json"):
        self.tmp_path = tmp_path
        self.source = tmp_path / "source.log"
        self.source.write_text("")
        self.out_dir = tmp_path / "out"
        self.out_dir.mkdir()
        self.report = tmp_path / "report.json"
        self.policy = tmp_path / "policy.json"

        processor = dict({"name": "adaptive"}, **processor)
        tail = {"name": "tail", "path": str(self.source),
                "read_from_head": True, "refresh_interval": 1, "tag": "app"}
        if parser:
            tail["parser"] = parser
        raw = {"name": "file", "match": "app", "path": str(self.out_dir),
               "file": "raw.out", "format": "plain"}
        reduced = {"name": "file", "match": "app", "path": str(self.out_dir),
                   "file": "reduced.out", "format": "plain", "workers": workers}
        outputs = [reduced]
        if location == "input":
            tail["processors"] = {"logs": [processor]}
        else:
            reduced["processors"] = {"logs": [processor]}
            outputs.append(raw)

        config = {
            "service": {"flush": 0.2, "grace": 2, "log_level": "info",
                        "http_server": True, "http_listen": "127.0.0.1",
                        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
            "parsers": [{"name": "json", "format": "json"}],
            "pipeline": {"inputs": [tail], "outputs": outputs},
        }
        self.config_path = tmp_path / "fluent-bit.yaml"
        self.config_path.write_text(yaml.safe_dump(config))
        self.manager = FluentBitManager(str(self.config_path))

    @property
    def raw(self):
        return read_records(self.out_dir / "raw.out")

    @property
    def reduced(self):
        return read_records(self.out_dir / "reduced.out")

    def metrics(self):
        return adaptive_metrics(self.manager.http_monitoring_port)

    def wait_seen(self, total, timeout=120):
        """Block until the processor has decided on 'total' records."""
        deadline = time.monotonic() + timeout
        seen = 0
        while time.monotonic() < deadline:
            seen = metric_sum(self.metrics(), "fluentbit_adaptive_records_total")
            if seen >= total:
                return
            time.sleep(0.2)
        pytest.fail(f"processor saw {seen} of {total} records\n"
                    + Path(self.manager.log_file).read_text()[-4000:])

    def wait_reduced(self, total, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.reduced) >= total:
                return
            time.sleep(0.2)
        pytest.fail(f"reduced route has {len(self.reduced)} of {total} records")


@pytest.fixture(params=["fast", "decoded"])
def path_options(request):
    """Run a test on the MessagePack fast path and on the decoded path."""
    return {} if request.param == "fast" else {"fast_path": False}


def workload(count):
    """75% noisy, 20% cache, 5% errors, in a fixed interleaving."""
    records = []
    for index in range(count):
        slot = index % 20
        if slot == 19:
            records.append(failure(index))
        elif slot % 4 == 3:
            records.append(cache(index))
        else:
            records.append(noisy(index))
    return records


def test_output_route_is_reduced_and_archive_stays_complete(tmp_path, path_options):
    pipeline = Pipeline(tmp_path, {**path_options,
        "window": "300s", "allow_per_window": 5, "sample_mode": "sqrt",
        "min_events": 30, "report_file": str(tmp_path / "report.json"),
        "report_exemplars": True, "annotate_pattern_id": True,
    })
    records = workload(4000)
    # one protected record per pattern closes its suppressed counter
    records += [noisy(1, level="error"), cache(1, level="error")]
    expected_errors = sum(1 for record in records if record["level"] == "error")

    pipeline.manager.start()
    try:
        append(pipeline.source, records)
        pipeline.wait_seen(len(records))
        metrics = pipeline.metrics()
        kept_metric = metric_sum(metrics, "fluentbit_adaptive_records_total", action="kept")
        pipeline.wait_reduced(kept_metric)
    finally:
        pipeline.manager.stop()

    raw = pipeline.raw
    reduced = pipeline.reduced
    report = json.loads(pipeline.report.read_text())

    # the route without the processor is the lossless archive
    assert len(raw) == len(records)
    assert [record["log"] for record in raw] == [record["log"] for record in records]
    assert all("adaptive" not in record for record in raw)

    # the reduced route keeps every error and a fraction of the rest
    assert sum(1 for record in reduced if record["level"] == "error") == expected_errors
    assert len(reduced) < len(records) * 0.25
    assert all(re.fullmatch(r"[0-9a-f]{16}", record["adaptive"]["pattern_id"])
               for record in reduced)

    # every record is accounted for: delivered, or counted by a delivered one
    suppressed = sum(record["adaptive"].get("suppressed", 0) for record in reduced)
    assert len(reduced) + suppressed == len(records)

    totals = report["totals"]
    assert totals["records"] == len(records)
    assert totals["kept"] == len(reduced) == kept_metric
    assert totals["dropped"] == len(records) - len(reduced)
    assert totals["unmatched"] == 0
    assert totals["bytes"] == sum(len(record["log"]) for record in records)

    templates = {pattern["template"]: pattern for pattern in report["patterns"]}
    assert NOISY_TEMPLATE in templates and CACHE_TEMPLATE in templates
    assert len(templates) == 3
    for pattern in report["patterns"]:
        assert pattern["kept"] + pattern["dropped"] == pattern["count"]
        assert pattern["exemplar"]
    failure_pattern = next(pattern for pattern in report["patterns"]
                           if pattern["template"].startswith("upstream timeout"))
    assert failure_pattern["dropped"] == 0
    assert failure_pattern["protected"] == failure_pattern["count"] == 200
    assert sum(pattern["count"] for pattern in report["patterns"]) == len(records)

    # kept records of a sampled pattern carry the rate they were sampled at
    rates = [record["adaptive"]["sample_rate"] for record in reduced
             if "sample_rate" in record["adaptive"]]
    assert rates and max(rates) > 1


@pytest.mark.parametrize("workers", [1, 4])
def test_input_processor_metrics_match_delivery(tmp_path, workers):
    pipeline = Pipeline(tmp_path, {
        "window": "300s", "allow_per_window": 10, "sample_mode": "log",
        "report_file": str(tmp_path / "report.json"),
    }, location="input", workers=workers)
    records = workload(3000)

    pipeline.manager.start()
    try:
        # several appends, so the processor is entered more than once
        for start in range(0, len(records), 500):
            append(pipeline.source, records[start:start + 500])
            time.sleep(0.3)
        pipeline.wait_seen(len(records))
        metrics = pipeline.metrics()
        kept = metric_sum(metrics, "fluentbit_adaptive_records_total", action="kept")
        pipeline.wait_reduced(kept)
    finally:
        pipeline.manager.stop()

    reduced = pipeline.reduced
    dropped = metric_sum(metrics, "fluentbit_adaptive_records_total", action="dropped")
    assert kept + dropped == len(records)
    assert len(reduced) == kept
    assert 0 < kept < len(records) * 0.5
    # by default only records that stand for dropped ones are annotated
    annotated = [record["adaptive"] for record in reduced if "adaptive" in record]
    assert 0 < len(annotated) < len(reduced)
    assert all(set(info) <= {"suppressed", "sample_rate"} for info in annotated)
    assert metric_sum(metrics, "fluentbit_adaptive_records_total",
                      action="kept", reason="protected") == 150
    assert metric_sum(metrics, "fluentbit_adaptive_records_total",
                      action="dropped", reason="protected") == 0
    assert metric_sum(metrics, "fluentbit_adaptive_patterns") == 3
    assert metric_sum(metrics, "fluentbit_adaptive_pattern_events_total", event="created") == 3
    bytes_total = metric_sum(metrics, "fluentbit_adaptive_message_bytes_total")
    assert bytes_total == sum(len(record["log"]) for record in records)
    assert metric_sum(metrics, "fluentbit_adaptive_groups") == 1

    # every series carries the label set of the core processor metrics
    labels = [dict(found) for (name, found) in metrics]
    assert labels and all(
        found["name"] == "tail.0" and found["scope"] == "input" and
        found["processor"] == "adaptive" and found["stage"] == "0" and
        found["signal"] == "logs" for found in labels)

    report = json.loads(pipeline.report.read_text())
    assert report["totals"]["kept"] == kept
    assert report["mode"] == "enforce"


def test_observe_mode_marks_but_never_drops(tmp_path, path_options):
    pipeline = Pipeline(tmp_path, {**path_options,
        "mode": "observe", "window": "300s", "allow_per_window": 5,
        "sample_mode": "suppress", "annotate_template": True,
    }, location="input")
    records = workload(1000)

    pipeline.manager.start()
    try:
        append(pipeline.source, records)
        pipeline.wait_seen(len(records))
        pipeline.wait_reduced(len(records))
        metrics = pipeline.metrics()
    finally:
        pipeline.manager.stop()

    delivered = pipeline.reduced
    assert len(delivered) == len(records)
    assert all("pattern_id" not in record["adaptive"] for record in delivered)
    marked = [record for record in delivered
              if record["adaptive"].get("decision") == "drop"]
    would_drop = metric_sum(metrics, "fluentbit_adaptive_records_total", action="would_drop")
    assert len(marked) == would_drop == 1000 - 50 - 5 - 5
    assert metric_sum(metrics, "fluentbit_adaptive_records_total", action="dropped") == 0
    assert all(record["level"] != "error" for record in marked)
    assert Counter(record["adaptive"]["template"] for record in delivered) == Counter({
        NOISY_TEMPLATE: 750, CACHE_TEMPLATE: 200,
        "upstream timeout after <NUM>ms host=<*>": 50,
    })


def test_policy_feedback_loop(tmp_path):
    """report -> controller -> policy file -> reload, then bad and removed policies."""
    pipeline = Pipeline(tmp_path, {
        "sample_mode": "off", "window": "300s",
        "policy_file": str(tmp_path / "policy.json"), "policy_refresh": "1s",
        "report_file": str(tmp_path / "report.json"), "report_interval": "1s",
    })
    seen = 0

    def send(records):
        nonlocal seen
        append(pipeline.source, records)
        seen += len(records)
        pipeline.wait_seen(seen)

    def reloads(status):
        return metric_sum(pipeline.metrics(), "fluentbit_adaptive_policy_reloads_total",
                          status=status)

    pipeline.manager.start()
    try:
        # phase 1: no policy, automatic sampling off, everything passes
        send([noisy(i, phase=1) for i in range(200)] + [cache(i, phase=1) for i in range(100)])
        time.sleep(1.5)
        send([cache(1000, phase=1)])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if pipeline.report.exists() and \
                    len(json.loads(pipeline.report.read_text())["patterns"]) == 2:
                break
            time.sleep(0.2)
        report = json.loads(pipeline.report.read_text())
        assert {pattern["template"] for pattern in report["patterns"]} == \
            {NOISY_TEMPLATE, CACHE_TEMPLATE}

        # the controller knows that only the cache lines are ever read
        policy, _ = recommend.recommend(report, {CACHE_TEMPLATE: 101})
        assert policy["patterns"] == [
            {"template": NOISY_TEMPLATE, "drop_rate": 0.9},
            {"template": CACHE_TEMPLATE, "drop_rate": 0.0},
        ]
        recommend.write_atomic(str(pipeline.policy), policy)

        # phase 2: the policy applies without a restart
        time.sleep(1.5)
        send([cache(2000, phase=2)])
        assert reloads("ok") == 1
        send([noisy(i, phase=2) for i in range(1000)] + [cache(i, phase=2) for i in range(99)])

        # phase 3: a broken policy is rejected and the previous one stays
        pipeline.policy.write_text("{\"patterns\": [")
        time.sleep(1.5)
        send([cache(3000, phase=3)])
        assert reloads("error") == 1
        assert reloads("ok") == 1
        send([noisy(i, phase=3) for i in range(100)])

        # phase 4: removing the file withdraws the policy
        pipeline.policy.unlink()
        time.sleep(1.5)
        send([cache(4000, phase=4)])
        assert reloads("ok") == 2
        send([noisy(i, phase=4) for i in range(50)])

        kept = metric_sum(pipeline.metrics(), "fluentbit_adaptive_records_total", action="kept")
        pipeline.wait_reduced(kept)
    finally:
        pipeline.manager.stop()

    assert len(pipeline.raw) == seen
    delivered = Counter((record["phase"], record["kind"]) for record in pipeline.reduced)
    assert delivered == Counter({
        (1, "noisy"): 200, (1, "cache"): 101,
        (2, "noisy"): 100, (2, "cache"): 100,
        (3, "noisy"): 10, (3, "cache"): 1,
        (4, "noisy"): 50, (4, "cache"): 1,
    })
    rates = {record.get("adaptive", {}).get("sample_rate") for record in pipeline.reduced
             if record["phase"] == 2 and record["kind"] == "noisy"}
    assert rates == {10}

    final = json.loads(pipeline.report.read_text())
    assert final["policy"] == {"entries": 0, "reloads": 2, "errors": 1}
    assert final["totals"]["dropped"] == 900 + 90


def summaries_of(records):
    return [record for record in records
            if isinstance(record.get("adaptive"), dict) and record["adaptive"].get("summary")]


@pytest.mark.parametrize("location", ["input", "output"])
def test_summaries_account_for_every_dropped_record(tmp_path, location, path_options):
    """Kept records plus summary counts equal what was produced, also when idle."""
    pipeline = Pipeline(tmp_path, {**path_options,
        "window": "2s", "allow_per_window": 5, "sample_mode": "suppress",
        "annotate": False, "summary": True, "group_by": "$kind",
    }, location=location)
    records = workload(2000)
    dropped = 0

    def accounted():
        delivered = pipeline.reduced
        found = summaries_of(delivered)
        return (len(delivered) - len(found) +
                sum(record["adaptive"]["dropped"] for record in found))

    def wait_accounted(total):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if accounted() >= total:
                return
            time.sleep(0.2)
        pytest.fail(f"accounted for {accounted()} of {total} records")

    pipeline.manager.start()
    try:
        append(pipeline.source, records)
        pipeline.wait_seen(len(records))
        if location == "output":
            # nothing can be injected into one route: the summaries of the
            # last window wait for the next records that go through it
            time.sleep(2.5)
            records.append(failure(1))
            append(pipeline.source, records[-1:])
        # on the input the stream stays idle and the timer sends them
        wait_accounted(len(records))
        time.sleep(2.5)
        metrics = pipeline.metrics()
        dropped = metric_sum(metrics, "fluentbit_adaptive_records_total", action="dropped")
    finally:
        pipeline.manager.stop()

    delivered = pipeline.reduced
    summaries = summaries_of(delivered)
    assert accounted() == len(records)
    assert sum(record["adaptive"]["dropped"] for record in summaries) == dropped > 0
    assert metric_sum(metrics, "fluentbit_adaptive_summary_records_total",
                      status="emitted") == len(summaries)
    assert metric_sum(metrics, "fluentbit_adaptive_summary_records_total",
                      status="failed") == 0

    # a summary reads like the lines it stands for and names its group
    by_group = {}
    for record in summaries:
        info = record["adaptive"]
        assert info["count"] == info["kept"] + info["dropped"]
        assert info["window"] == 2 and info["bytes_dropped"] > 0
        assert re.fullmatch(r"[0-9a-f]{16}", info["pattern_id"])
        by_group.setdefault(info["group"], set()).add(record["log"])
    assert by_group == {"noisy": {NOISY_TEMPLATE}, "cache": {CACHE_TEMPLATE}}
    # protected records are never dropped, so that group has no summary
    assert sum(1 for record in delivered if record.get("level") == "error") == \
        sum(1 for record in records if record["level"] == "error")
    assert metric_sum(metrics, "fluentbit_adaptive_groups") == 3


def test_json_text_is_mined_by_message_and_fields(tmp_path, path_options):
    """Unparsed JSON lines: message and severity inside, or the fields themselves."""
    pipeline = Pipeline(tmp_path, {**path_options,
        "window": "300s", "allow_per_window": 5, "sample_mode": "suppress",
        "annotate": False, "report_file": str(tmp_path / "report.json"),
    }, location="input", parser=None)
    records = workload(1000)
    events = [{"event": "login", "user": f"u{index}", "ok": True,
               "http": {"status": 200, "path": f"/session/{index}"}}
              for index in range(300)]
    events += [{"event": "logout", "user": f"u{index}", "ok": True,
                "http": {"status": 200, "path": f"/session/{index}"}}
               for index in range(3)]

    pipeline.manager.start()
    try:
        append(pipeline.source, records + events)
        pipeline.wait_seen(len(records) + len(events))
        kept = metric_sum(pipeline.metrics(), "fluentbit_adaptive_records_total",
                          action="kept")
        pipeline.wait_reduced(kept)
    finally:
        pipeline.manager.stop()

    delivered = [json.loads(record["log"]) for record in pipeline.reduced]
    report = json.loads(pipeline.report.read_text())
    templates = {pattern["template"]: pattern for pattern in report["patterns"]}

    # the "log" field inside the JSON text is the message
    assert NOISY_TEMPLATE in templates and CACHE_TEMPLATE in templates
    assert templates[NOISY_TEMPLATE]["count"] == 750
    # the "level" field inside the JSON text protects the record
    assert sum(1 for record in delivered if record.get("level") == "error") == 50
    assert sum(1 for record in delivered if record.get("kind") == "noisy") == 5

    # no message: one token per field, the short word is the identity
    login = "event=login user=<*> ok=true http.status=<NUM> http.path=<*>"
    logout = "event=logout user=<*> ok=true http.status=<NUM> http.path=<*>"
    assert templates[login]["count"] == 300 and templates[login]["kept"] == 5
    assert templates[logout]["count"] == 3 and templates[logout]["kept"] == 3
    assert report["totals"]["unmatched"] == 0
    assert len(delivered) == 5 + 5 + 50 + 5 + 3


def otlp_payload(groups=2, info=60, errors=2):
    payload = ExportLogsServiceRequest()
    for group in range(groups):
        resource = payload.resource_logs.add()
        attribute = resource.resource.attributes.add(key="service.name")
        attribute.value.string_value = f"service-{group}"
        scope = resource.scope_logs.add()
        scope.scope.name = f"scope-{group}"
        for index in range(info + errors):
            record = scope.log_records.add()
            record.time_unix_nano = 1700000000000000000 + group * 1000 + index
            is_error = index >= info
            # one error is flagged by text, the next only by number
            record.severity_number = 17 if is_error else 9
            if not is_error:
                record.severity_text = "INFO"
            elif index % 2 == 0:
                record.severity_text = "ERROR"
            record.attributes.add(key="group").value.int_value = group
            status = 500 if is_error else 200
            record.body.string_value = f"GET /orders/{index} {status} took {index}ms"
    return payload


def otlp_flatten(payloads):
    result = []
    for payload in payloads:
        for resource in payload.resource_logs:
            service = next(attribute.value.string_value
                           for attribute in resource.resource.attributes
                           if attribute.key == "service.name")
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    result.append((service, scope.scope.name, record))
    return result


@pytest.mark.parametrize("location", ["input", "output"])
def test_state_survives_a_restart(tmp_path, location):
    """A second process continues from the patterns and counters of the first."""
    state = tmp_path / "state"
    pipeline = Pipeline(tmp_path, {
        "window": "1d", "allow_per_window": 5, "sample_mode": "suppress",
        "group_by": "$kind", "state_path": str(state), "state_interval": "1s",
        "report_file": str(tmp_path / "report.json"),
    }, location=location)
    records = workload(2000)
    errors = sum(1 for record in records if record["level"] == "error")

    def snapshots():
        return sorted(path.name for path in state.rglob("snapshot-*"))

    pipeline.manager.start()
    try:
        append(pipeline.source, records)
        pipeline.wait_seen(len(records))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            first = pipeline.metrics()
            if metric_sum(first, "fluentbit_adaptive_state_writes_total", status="ok") >= 1:
                break
            time.sleep(0.2)
        kept = metric_sum(first, "fluentbit_adaptive_records_total", action="kept")
        pipeline.wait_reduced(kept)
    finally:
        pipeline.manager.stop()

    # five of each sampled pattern, every error
    assert kept == 5 + 5 + errors
    assert metric_sum(first, "fluentbit_adaptive_state_writes_total", status="ok") >= 1
    assert metric_sum(first, "fluentbit_adaptive_state_writes_total", status="error") == 0
    assert metric_sum(first, "fluentbit_adaptive_pattern_events_total", event="created") >= 3

    # one directory per instance, one snapshot left in it
    owner = "tail" if location == "input" else "file"
    assert [path.name for path in state.iterdir()] == [f"{location}.{owner}.0.0"]
    assert len(snapshots()) == 1
    before = snapshots()[0]

    # same lines again, read by a new process
    pipeline.source.write_text("")
    pipeline.manager = FluentBitManager(str(pipeline.config_path))
    pipeline.manager.start()
    try:
        append(pipeline.source, records)
        pipeline.wait_seen(len(records))
        second = pipeline.metrics()
        pipeline.wait_reduced(kept + errors)
        time.sleep(1)
        log = Path(pipeline.manager.log_file).read_text()
    finally:
        pipeline.manager.stop()

    assert "state restored from " + before in log
    assert "3 groups" in log

    # nothing had to be learned again, and the allowance was already spent
    assert metric_sum(second, "fluentbit_adaptive_pattern_events_total", event="created") == 0
    assert metric_sum(second, "fluentbit_adaptive_records_total", action="kept") == errors
    assert metric_sum(second, "fluentbit_adaptive_records_total",
                      action="dropped") == len(records) - errors
    assert len(pipeline.reduced) == kept + errors

    # the report continues from the saved counters
    report = json.loads(pipeline.report.read_text())
    assert report["totals"]["records"] == 2 * len(records)
    assert sum(pattern["count"] for pattern in report["patterns"]) == 2 * len(records)
    assert len(snapshots()) == 1 and snapshots()[0] > before


def test_state_survives_a_hot_reload(tmp_path):
    """The reloaded pipeline starts from what the one before it saved on exit."""
    state = tmp_path / "state"
    pipeline = Pipeline(tmp_path, {
        "window": "1d", "allow_per_window": 5, "sample_mode": "suppress",
        "state_path": str(state),
    }, location="input")
    config = yaml.safe_load(pipeline.config_path.read_text())
    config["service"]["hot_reload"] = True
    pipeline.config_path.write_text(yaml.safe_dump(config))

    records = workload(2000)
    errors = sum(1 for record in records if record["level"] == "error")

    pipeline.manager.start()
    try:
        append(pipeline.source, records)
        pipeline.wait_seen(len(records))
        pipeline.wait_reduced(5 + 5 + errors)

        # no snapshot yet: the interval is a minute, only the exit path saves
        assert not list(state.rglob("snapshot-*"))

        pipeline.manager.send_sighup()
        pipeline.manager.wait_for_hot_reload_count(1, timeout=30)

        # the new tail has no position database and reads the file again
        pipeline.wait_seen(len(records))
        second = pipeline.metrics()
        pipeline.wait_reduced(5 + 5 + 2 * errors)
        time.sleep(1)
        log = Path(pipeline.manager.log_file).read_text()
    finally:
        pipeline.manager.stop()

    assert "state restored from snapshot-00000000000000000001" in log
    assert metric_sum(second, "fluentbit_adaptive_pattern_events_total", event="created") == 0
    assert metric_sum(second, "fluentbit_adaptive_records_total", action="kept") == errors
    assert len(pipeline.reduced) == 5 + 5 + 2 * errors
    assert [path.name for path in state.rglob("snapshot-*")] == ["snapshot-00000000000000000002"]


@pytest.mark.parametrize("location", ["input", "output"])
@pytest.mark.parametrize("grouped", [False, True])
def test_otlp_groups_and_severity(tmp_path, location, grouped, path_options):
    """Group envelopes survive, OTLP severity protects, resources can partition."""
    received = [[], []]
    lock = threading.Lock()

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = ExportLogsServiceRequest()
            payload.ParseFromString(self.rfile.read(int(self.headers["Content-Length"])))
            with lock:
                received[int(self.path[-1])].append(payload)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()

    processors = [{"name": "adaptive", **path_options, "window": "300s", "allow_per_window": 3,
                   "sample_mode": "suppress", "annotate": False}]
    if grouped:
        processors[0]["group_by"] = "resource:service.name"
    input_config = {"name": "opentelemetry", "listen": "127.0.0.1",
                    "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "tag": "test"}
    outputs = [{"name": "opentelemetry", "match": "*", "host": "127.0.0.1",
                "port": sink.server_port, "logs_uri": f"/logs/{route}"}
               for route in range(2)]
    if location == "input":
        input_config["processors"] = {"logs": processors}
    else:
        outputs[0]["processors"] = {"logs": processors}
    config = {
        "service": {"flush": 0.1, "grace": 1, "log_level": "error", "http_server": True,
                    "http_listen": "127.0.0.1",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [input_config], "outputs": outputs},
    }
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config))

    source = otlp_payload()
    # 3 info records of the shared pattern, or 3 per service when the resource
    # partitions the stream, plus 2 errors per group
    reduced_count = (6 if grouped else 3) + 4
    control_count = reduced_count if location == "input" else 124
    service = FluentBitTestService(str(config_path))
    try:
        service.start()
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",
                                 data=source.SerializeToString(),
                                 headers={"Content-Type": "application/x-protobuf"},
                                 timeout=30)
        assert response.status_code == 201, response.text
        service.wait_for_condition(
            lambda: len(otlp_flatten(received[0])) >= reduced_count and
                    len(otlp_flatten(received[1])) >= control_count,
            timeout=60, interval=0.1, description="both routes to deliver",
        )
        time.sleep(0.5)
    finally:
        service.stop()
        sink.shutdown()
        sink.server_close()

    reduced = otlp_flatten(received[0])
    control = otlp_flatten(received[1])
    assert len(reduced) == reduced_count
    assert len(control) == control_count

    # each surviving record is still under its own resource and scope
    for service_name, scope_name, record in reduced:
        group = next(attribute.value.int_value for attribute in record.attributes
                     if attribute.key == "group")
        assert service_name == f"service-{group}"
        assert scope_name == f"scope-{group}"

    errors = [(service_name, record) for service_name, _, record in reduced
              if record.severity_number == 17]
    assert Counter(service_name for service_name, _ in errors) == \
        Counter({"service-0": 2, "service-1": 2})
    info = Counter(service_name for service_name, _, record in reduced
                   if record.severity_number == 9)
    if grouped:
        assert info == Counter({"service-0": 3, "service-1": 3})
    else:
        assert sum(info.values()) == 3
