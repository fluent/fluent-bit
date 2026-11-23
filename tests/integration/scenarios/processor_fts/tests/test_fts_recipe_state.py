"""Local native decision contracts; exact clock boundaries live in flb-it-fts."""
import pytest
import requests
import yaml

from test_fts_recipe_catalog import send, sel, block
from test_fts_recipes import config_file, rejected_startup, redact
from test_fts_recipe_preflight import dry_run
from test_fts_records import rows, log_text
from utils.test_service import FluentBitTestService


def decision(kind="dedupe", **params):
    defaults = {"keys": [sel("key")], "ttl_ms": 60000}
    if kind == "throttle":
        defaults.update(rate=1, burst=2)
    return block("logs." + kind, **{**defaults, **params})


def processor(steps, **options):
    return {"name": "fts", "context": "native", "state_commit": "local", "recipe": steps, **options}


def metrics(service):
    response = requests.get(f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus", timeout=10)
    if response.status_code in (404, 503):
        return {}
    response.raise_for_status()
    result = {}
    for line in response.text.splitlines():
        if line.startswith("fluentbit_fts_"):
            result[line.split("{", 1)[0]] = float(line.rsplit(" ", 1)[-1])
    return result


def wait_rows(service, count):
    service.wait_for_condition(lambda: len(rows(service)) >= count, timeout=30)
    assert len(rows(service)) == count, log_text(service)


@pytest.mark.parametrize("threaded", [False, True])
def test_dedupe_batch_visibility_privacy_and_restart(tmp_path, threaded):
    config = config_file(tmp_path, processor([redact(), decision()]))
    data = yaml.safe_load(config.read_text())
    data["pipeline"]["inputs"][0]["threaded"] = threaded
    config.write_text(yaml.safe_dump(data))
    for _ in range(2):
        service = FluentBitTestService(str(config))
        try:
            service.start()
            send(service, [{"key": "a", "password": "synthetic-secret"}] * 3)
            wait_rows(service, 1)
            send(service, [{"key": "a"}, {"key": "b"}])
            wait_rows(service, 2)
            assert rows(service)[0]["password"] == "[REDACTED]"
            assert "synthetic-secret" not in log_text(service)
            service.wait_for_condition(lambda: metrics(service).get("fluentbit_fts_dropped_by_policy_total") == 3, timeout=30)
            counts = metrics(service)
            assert counts["fluentbit_fts_state_keys"] == 2
            assert counts["fluentbit_fts_local_state_commits_total"] >= 2
        finally:
            service.stop()


@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_failed_item_does_not_admit_key(tmp_path, error_mode):
    steps = [block("logs.validate_fields", rules=[{"selector": sel("valid"), "type": "bool"}]), decision()]
    service = FluentBitTestService(str(config_file(tmp_path, processor(steps, error_mode=error_mode))))
    try:
        service.start()
        send(service, [{"key": "a", "valid": "bad"}, {"key": "a", "valid": True},
                       {"key": "a", "valid": True}])
        wait_rows(service, 2 if error_mode == "keep" else 1)
        assert rows(service)[-1]["valid"] is True
        assert "class=validation_failed" in log_text(service, "class=validation_failed")
        service.wait_for_condition(lambda: metrics(service).get("fluentbit_fts_dropped_by_policy_total") == 1, timeout=30)
    finally:
        service.stop()


@pytest.mark.parametrize("limit", ["keys", "key_bytes", "state_bytes"])
def test_overflow_passes_untracked_without_eviction(tmp_path, limit):
    options = {}
    params = {}
    if limit == "keys":
        params["max_keys"] = 1
    elif limit == "key_bytes":
        params["max_key_bytes"] = 16
    else:
        options["state_limit"] = "1K"
        params["max_keys"] = 16
    config = config_file(tmp_path, processor([decision(**params)], **options))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [{"key": "a"}, {"key": "x" * 900}, {"key": "x" * 900}, {"key": "a"}])
        wait_rows(service, 3)
        service.wait_for_condition(lambda: metrics(service).get("fluentbit_fts_overflow_untracked_total") == 2, timeout=30)
        counts = metrics(service)
        assert counts["fluentbit_fts_state_keys"] == 1
        assert counts["fluentbit_fts_evictions_total"] == 0
    finally:
        service.stop()


def test_typed_keys_and_length_prefixes(tmp_path):
    service = FluentBitTestService(str(config_file(tmp_path, processor([
        decision(keys=[sel("key"), sel("other")], tenant=sel("tenant"))]))))
    records = [{"key": "a", "other": "bc", "tenant": "t"},
               {"key": "ab", "other": "c", "tenant": "t"},
               {"key": "1", "other": "", "tenant": "t"},
               {"key": 1, "other": "", "tenant": "t"},
               {"key": 1, "other": "", "tenant": "u"},
               {"key": True, "other": "", "tenant": "t"},
               {"key": None, "other": "", "tenant": "t"}]
    try:
        service.start()
        send(service, records + records)
        wait_rows(service, len(records))
        assert [{k: v for k, v in row.items() if k != "date"} for row in rows(service)] == records
    finally:
        service.stop()


def test_integer_key_normalizes_signed_and_unsigned_widths(tmp_path):
    steps = []
    for kind in ("int64", "uint64"):
        step = block("fields.edit", operations=[{"op": "set", "target": sel("key"),
                     "value": {"type": kind, "value": "1"}}])
        step["id"] = kind
        step["when"] = {"selector": sel("kind"), "op": "eq", "value": kind}
        steps.append(step)
    steps.append(decision())
    service = FluentBitTestService(str(config_file(tmp_path, processor(steps))))
    try:
        service.start()
        send(service, [{"kind": "int64"}, {"kind": "uint64"}])
        wait_rows(service, 1)
        service.wait_for_condition(lambda: metrics(service).get("fluentbit_fts_dropped_by_policy_total") == 1, timeout=30)
        assert rows(service)[0]["kind"] == "int64"
    finally:
        service.stop()


@pytest.mark.parametrize("on_missing", ["keep", "error"])
def test_missing_and_invalid_key(tmp_path, on_missing):
    service = FluentBitTestService(str(config_file(tmp_path, processor([decision(on_missing=on_missing)]))))
    try:
        service.start()
        send(service, [{"missing": True}, {"key": {}}, {"key": "control"}])
        wait_rows(service, 2 if on_missing == "keep" else 1)
        assert "class=wrong_type" in log_text(service, "class=wrong_type")
        if on_missing == "error":
            assert "class=missing_field" in log_text(service, "class=missing_field")
    finally:
        service.stop()


@pytest.mark.parametrize("threaded", [False, True])
def test_throttle_burst_per_key(tmp_path, threaded):
    config = config_file(tmp_path, processor([decision("throttle")]))
    data = yaml.safe_load(config.read_text())
    data["pipeline"]["inputs"][0]["threaded"] = threaded
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [{"key": "a"}] * 4 + [{"key": "b"}] * 3)
        wait_rows(service, 4)
        service.wait_for_condition(lambda: metrics(service).get("fluentbit_fts_dropped_by_policy_total") == 3, timeout=30)
    finally:
        service.stop()


def test_output_construction_failure_rolls_back_entire_overlay(tmp_path):
    service = FluentBitTestService(str(config_file(tmp_path, processor([decision()], output_limit="65536"))))
    try:
        service.start()
        send(service, [{"key": "a"}, {"key": "b", "large": "x" * 70000}])
        service.wait_for_condition(lambda: "cannot construct policy output" in log_text(service), timeout=30)
        assert not rows(service)
        assert metrics(service)["fluentbit_fts_state_keys"] == 0
        send(service, [{"key": "a"}, {"key": "b"}])
        wait_rows(service, 2)
    finally:
        service.stop()


@pytest.mark.parametrize("kind", ["dedupe", "throttle"])
@pytest.mark.parametrize("invalid", ["output", "not_terminal", "two_state_steps", "implicit_commit",
                                     "wrong_commit", "zero_keys", "zero_key_bytes", "tiny_state",
                                     "ttl", "fractional", "overflow", "privacy_keep"])
def test_state_rejected_by_preflight_and_startup(tmp_path, kind, invalid):
    policy = processor([decision(kind)])
    placement = "output" if invalid == "output" else "input"
    params = policy["recipe"][0]["with"]
    if invalid == "not_terminal":
        policy["recipe"].append(block("fields.edit", operations=[{"op": "remove", "target": sel("x")}]))
    elif invalid == "two_state_steps":
        policy["recipe"].append({**decision(kind), "id": "second"})
    elif invalid == "implicit_commit":
        policy.pop("state_commit")
    elif invalid == "wrong_commit":
        policy["state_commit"] = "delivery"
    elif invalid == "zero_keys":
        params["max_keys"] = 0
    elif invalid == "zero_key_bytes":
        params["max_key_bytes"] = 0
    elif invalid == "tiny_state":
        policy["state_limit"] = "1"
    elif invalid == "ttl":
        params["ttl_ms"] = 0
    elif invalid == "fractional":
        params["max_keys"] = 1.5
    elif invalid == "overflow":
        params["overflow"] = "evict"
    elif invalid == "privacy_keep":
        policy["recipe"].insert(0, redact())
        policy["error_mode"] = "keep"
    config = config_file(tmp_path, policy, placement)
    status, text = dry_run(config, tmp_path)
    assert status != 0, text
    rejected_startup(config, tmp_path)


@pytest.mark.parametrize("params", [{"rate": 0}, {"burst": 0}, {"rate": 1.5},
                                    {"burst": 1000001}, {"ttl_ms": 1999, "rate": 1, "burst": 2}])
def test_invalid_token_bucket_bounds(tmp_path, params):
    config = config_file(tmp_path, processor([decision("throttle", **params)]))
    status, text = dry_run(config, tmp_path)
    assert status != 0, text
    rejected_startup(config, tmp_path)


@pytest.mark.parametrize("threaded", [False, True])
def test_concurrent_http_batches_share_one_decision_state(tmp_path, threaded):
    from concurrent.futures import ThreadPoolExecutor

    config = config_file(tmp_path, processor([decision()]))
    data = yaml.safe_load(config.read_text())
    data["pipeline"]["inputs"][0].update(name="http", workers=4, threaded=threaded)
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()

        def submit(index):
            response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/state",
                                     json=[{"key": "shared"}, {"key": str(index)}], timeout=30)
            assert response.status_code == 201, response.text

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(submit, range(20)))
        wait_rows(service, 21)
        service.wait_for_condition(lambda: metrics(service).get("fluentbit_fts_dropped_by_policy_total") == 19, timeout=30)
        assert {row["key"] for row in rows(service)} == {"shared", *(str(i) for i in range(20))}
        assert metrics(service)["fluentbit_fts_state_keys"] == 21
    finally:
        service.stop()


def test_state_instances_have_independent_keys_and_metric_labels(tmp_path):
    config = config_file(tmp_path, processor([decision(keys=[sel("first")])]))
    data = yaml.safe_load(config.read_text())
    data["pipeline"]["inputs"][0]["processors"]["logs"].append(
        processor([decision(keys=[sel("second")])]))
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [{"first": "a", "second": "x"}, {"first": "b", "second": "x"}])
        wait_rows(service, 1)
        def visible():
            response = requests.get(f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus", timeout=10)
            response.raise_for_status()
            keys = [line for line in response.text.splitlines() if line.startswith("fluentbit_fts_state_keys{")]
            return (len(keys) == 2 and
                    any('stage="0"' in line and float(line.rsplit(" ", 1)[-1]) == 2 for line in keys) and
                    any('stage="1"' in line and float(line.rsplit(" ", 1)[-1]) == 1 for line in keys))

        # Monitoring snapshots can lag the output flush by one refresh interval.
        assert service.wait_for_condition(visible, timeout=30)
    finally:
        service.stop()
