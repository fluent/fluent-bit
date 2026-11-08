"""Production FTS log windows: native ownership, Lua decisions, engine release."""
from pathlib import Path
import socket

import pytest
import requests
import yaml

from test_fts_recipes import rejected_startup
from test_fts_recipe_preflight import dry_run
from test_fts_records import send, rows, log_text, pack
from utils.test_service import FluentBitTestService


def selector(key):
    return {"root": "body", "path": [key]}


def configuration(tmp_path, *, threaded=False, storage="memory", hold_ms=300, **parameters):
    params = {"keys": [selector("request_id")], "hold_ms": hold_ms, "late_ms": 5000,
              "ready_timeout_ms": 10000, "max_keys": 1024, "max_key_bytes": 256,
              "retain_when": {"selector": selector("level"), "op": "eq", "value": "ERROR"},
              "keep_when": {"selector": selector("level"), "op": "neq", "value": "DEBUG"},
              **parameters}
    processor = {"name": "fts", "recipe_version": 1, "context": "native", "error_mode": "drop",
                 "state_commit": "local", "state_limit": "1M", "recipe": [
                     {"id": "privacy", "use": "shared.redact_keys", "with": {
                         "targets": [{"root": "body", "path": []}], "keys": ["password"]}},
                     {"id": "window", "use": "window.hold_until", "with": params}]}
    config = tmp_path / "window.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "hot_reload": True,
                    "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
                    "storage.path": str(tmp_path / "storage")},
        "pipeline": {"inputs": [{"name": "forward", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
            "threaded": threaded, "storage.type": storage, "buffer_chunk_size": "1M",
            "buffer_max_size": "4M", "processors": {"logs": [processor, {
                "name": "fts", "code": 'function process(log) local n = log.body:get("visits"); log.body:set("visits", n and n:number() + 1 or 1) end'}]}}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}]}}))
    return config


def counters(service):
    try:
        response = requests.get(f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus", timeout=10)
    except requests.ConnectionError:
        return {}
    if response.status_code in (404, 503):
        # The monitoring routes/metric snapshot become available after reload status.
        return {}
    response.raise_for_status()
    values = {}
    for line in response.text.splitlines():
        if line.startswith("fluentbit_processor_") and 'processor="fts"' in line and 'stage="0"' in line:
            values[line.split("{", 1)[0]] = float(line.rsplit(" ", 1)[-1])
        if line.startswith("fluentbit_fts_window_events_total") and 'stage="0"' in line:
            outcome = line.split('outcome="', 1)[1].split('"', 1)[0]
            values[outcome] = float(line.rsplit(" ", 1)[-1])
    return values


def wait_count(service, name, expected):
    return service.wait_for_condition(lambda: counters(service).get(name) == expected,
                                      timeout=30, description=f"{name}={expected}")


def event(request, level, **extra):
    return {"request_id": request, "level": level, "password": "synthetic-secret", **extra}


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("storage", ["memory", "filesystem"])
def test_error_request_release_and_success_debug_drop(tmp_path, threaded, storage):
    service = FluentBitTestService(str(configuration(tmp_path, threaded=threaded, storage=storage)))
    try:
        service.start()
        send(service, [event("failed", "DEBUG"), event("success", "DEBUG"),
                       event("failed", "ERROR"), event("success", "INFO")])
        service.wait_for_condition(lambda: len(rows(service)) == 3, timeout=30)
        wait_count(service, "fluentbit_processor_items_out_total", 3)
        wait_count(service, "fluentbit_processor_items_drop_total", 1)
        wait_count(service, "fluentbit_processor_items_held_current", 0)
        counts = counters(service)
        assert counts["fluentbit_processor_items_in_total"] == 4
        assert counts["fluentbit_processor_items_out_total"] == 3
        assert counts["fluentbit_processor_items_drop_total"] == 1
        assert counts["fluentbit_processor_items_held_total"] == 4
        assert all(row["visits"] == 1 and row["password"] == "[REDACTED]" for row in rows(service))
        assert [row["level"] for row in rows(service) if row["request_id"] == "success"] == ["INFO"]
    finally:
        service.stop()


def test_late_error_does_not_resurrect_discarded_debug(tmp_path):
    service = FluentBitTestService(str(configuration(tmp_path)))
    try:
        service.start()
        send(service, event("closed", "DEBUG"))
        wait_count(service, "decision", 1)
        send(service, event("closed", "ERROR"))
        service.wait_for_condition(lambda: len(rows(service)) == 1, timeout=30)
        wait_count(service, "late_passthrough", 1)
        assert rows(service)[0]["level"] == "ERROR"
        assert rows(service)[0]["password"] == "[REDACTED]"
    finally:
        service.stop()


def test_overflow_keeps_sanitized_event_and_existing_window(tmp_path):
    service = FluentBitTestService(str(configuration(tmp_path, hold_ms=2000, max_keys=1)))
    try:
        service.start()
        send(service, [event("held", "DEBUG"), event("overflow", "INFO")])
        service.wait_for_condition(lambda: len(rows(service)) == 1, timeout=30)
        assert rows(service)[0]["request_id"] == "overflow"
        assert rows(service)[0]["password"] == "[REDACTED]"
        wait_count(service, "overflow_keep", 1)
        wait_count(service, "decision", 1)
    finally:
        service.stop()


@pytest.mark.parametrize("threaded", [False, True])
def test_batch_construction_failure_never_commits_hold(tmp_path, threaded):
    config = configuration(tmp_path, threaded=threaded, hold_ms=10000, max_keys=1)
    data = yaml.safe_load(config.read_text())
    data["pipeline"]["inputs"][0]["processors"]["logs"][0]["output_limit"] = "65536"
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [event("a", "DEBUG"), event("b", "ERROR"), event("c", "INFO", large="x" * 70000)])
        service.wait_for_condition(lambda: "cannot construct policy output" in log_text(service), timeout=30)
        wait_count(service, "fluentbit_processor_items_drop_total", 3)
        values = counters(service)
        assert values["fluentbit_processor_items_held_current"] == 0
        assert values["fluentbit_processor_items_held_total"] == 0
        assert rows(service) == []
    finally:
        service.stop()


@pytest.mark.parametrize("threaded", [False, True])
def test_reload_discards_pending_old_window(tmp_path, threaded):
    config = configuration(tmp_path, threaded=threaded, hold_ms=60000)
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, event("old", "ERROR"))
        wait_count(service, "fluentbit_processor_items_held_current", 1)
        service.flb.trigger_http_reload()
        service.flb.wait_for_hot_reload_count(1, timeout=30)
        wait_count(service, "fluentbit_processor_items_held_current", 0)
        assert rows(service) == []
        expected = "1 retained log records discarded at input stop"
        assert expected in log_text(service, expected)
    finally:
        service.stop()


@pytest.mark.parametrize("change", [
    {"hold_ms": 0}, {"hold_ms": 86400001}, {"late_ms": -1},
    {"ready_timeout_ms": 0}, {"max_keys": 0}, {"max_key_bytes": 65537},
    {"overflow": "evict"}, {"retain_when": {"op": "arbitrary"}},
])
def test_window_invalid_parameters_fail_preflight_and_startup(tmp_path, change):
    config = configuration(tmp_path, **change)
    data = yaml.safe_load(config.read_text())
    data["service"]["http_server"] = False
    data["service"].pop("http_port")
    data["pipeline"]["inputs"][0].update(name="dummy")
    data["pipeline"]["inputs"][0].pop("port")
    data["pipeline"]["inputs"][0].pop("buffer_chunk_size")
    data["pipeline"]["inputs"][0].pop("buffer_max_size")
    config.write_text(yaml.safe_dump(data))
    status, text = dry_run(config, tmp_path)
    assert status != 0, text
    # The existing helper expects this key before replacing listener config.
    data["service"]["http_port"] = "${FLUENT_BIT_HTTP_MONITORING_PORT}"
    config.write_text(yaml.safe_dump(data))
    rejected_startup(config, tmp_path)


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("storage", ["memory", "filesystem"])
@pytest.mark.parametrize("source_name", ["dummy", "tail", "http", "opentelemetry"])
def test_window_supported_input_matrix(tmp_path, source_name, threaded, storage):
    import json
    from test_fts_records import otlp_resources

    config = configuration(tmp_path, threaded=threaded, storage=storage)
    data = yaml.safe_load(config.read_text())
    source = data["pipeline"]["inputs"][0]
    source["name"] = source_name
    source.pop("buffer_chunk_size")
    source.pop("buffer_max_size")
    record = event("request", "ERROR")
    if source_name == "dummy":
        source.pop("port")
        source.update(dummy=json.dumps(record), samples=2, interval_sec=0, interval_nsec=100000000)
    elif source_name == "tail":
        source.pop("port")
        events = tmp_path / "events.jsonl"
        events.write_text(json.dumps(event("request", "DEBUG")) + "\n" + json.dumps(record) + "\n")
        source.update(path=str(events), read_from_head=True)
        processor = source["processors"]["logs"][0]
        processor["recipe"].insert(0, {"id": "parse", "use": "logs.parse_json", "with": {
            "source": selector("log"), "destination": selector("event"), "remove_source": True}})
        params = processor["recipe"][-1]["with"]
        for selected in [params["keys"][0], params["retain_when"]["selector"], params["keep_when"]["selector"]]:
            selected["path"].insert(0, "event")
    elif source_name == "opentelemetry":
        source["processors"]["logs"][0]["context"] = "otel"
        data["pipeline"]["outputs"][0]["format"] = "otlp_json"
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))

    def output_records():
        if source_name != "opentelemetry":
            return rows(service)
        return [body for _, bodies in otlp_resources(service) for body in bodies]

    try:
        service.start()
        if source_name == "http":
            response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/window",
                                     json=[event("request", "DEBUG"), record], timeout=10)
            assert response.status_code == 201, response.text
        elif source_name == "opentelemetry":
            values = lambda value: [{"key": key, "value": {"stringValue": item}} for key, item in value.items()]
            payload = {"resourceLogs": [{"resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "window-source"}}]},
                "scopeLogs": [{"scope": {"name": "window.scope"}, "logRecords": [
                    {"timeUnixNano": "1700000000000000000", "body": {"kvlistValue": {"values": values(item)}}}
                    for item in [event("request", "DEBUG"), record]]}]}]}
            response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/logs", json=payload, timeout=10)
            assert response.status_code in (200, 201), response.text
        service.wait_for_condition(lambda: len(output_records()) == 2, timeout=30)
        wait_count(service, "fluentbit_processor_items_held_total", 2)
        wait_count(service, "fluentbit_processor_items_out_total", 2)
        wait_count(service, "fluentbit_processor_items_held_current", 0)
        if source_name == "opentelemetry":
            assert all(body["password"] == {"stringValue": "[REDACTED]"} for body in output_records())
            assert all(body["visits"] == {"doubleValue": 1.0} for body in output_records())
            assert all(("service.name", {"stringValue": "window-source"}) in attrs
                       for attrs, _ in otlp_resources(service))
            assert all(scope["scope"]["name"] == "window.scope"
                       for row in rows(service) for resource in row["resourceLogs"] for scope in resource["scopeLogs"])
        else:
            assert all(row.get("event", row)["password"] == "[REDACTED]" and row["visits"] == 1
                       for row in output_records())
    finally:
        service.stop()


@pytest.mark.parametrize("case", ["output", "not_terminal", "no_commit", "external_commit", "small_state_limit", "unsupported_input"])
def test_window_placement_and_commit_contract(tmp_path, case):
    config = configuration(tmp_path)
    data = yaml.safe_load(config.read_text())
    source = data["pipeline"]["inputs"][0]
    processor = source["processors"]["logs"][0]
    if case == "output":
        source.pop("processors")
        data["pipeline"]["outputs"][0]["processors"] = {"logs": [processor]}
    elif case == "not_terminal":
        processor["recipe"].append({"id": "after", "use": "logs.drop_matching", "with": {
            "condition": {"selector": selector("level"), "op": "eq", "value": "DEBUG"}}})
    elif case == "no_commit":
        processor.pop("state_commit")
    elif case == "external_commit":
        processor["state_commit"] = "external"
    elif case == "small_state_limit":
        processor["state_limit"] = "128"
    else:
        source.update(name="cpu")
        source.pop("port")
        source.pop("buffer_chunk_size")
        source.pop("buffer_max_size")
    config.write_text(yaml.safe_dump(data))
    status, text = dry_run(config, tmp_path)
    assert status != 0 and "configuration test is successful" not in text


@pytest.mark.parametrize("threaded", [False, True])
def test_shutdown_discards_pending_and_counts_loss(tmp_path, threaded):
    service = FluentBitTestService(str(configuration(tmp_path, threaded=threaded, hold_ms=60000)))
    try:
        service.start()
        send(service, event("pending", "ERROR"))
        wait_count(service, "fluentbit_processor_items_held_current", 1)
    finally:
        service.stop()
    assert rows(service) == []
    expected = "1 retained log records discarded at input stop"
    assert expected in log_text(service, expected)


@pytest.mark.parametrize("threaded", [False, True])
def test_release_preserves_each_original_tag(tmp_path, threaded):
    config = configuration(tmp_path, threaded=threaded, hold_ms=1000)
    data = yaml.safe_load(config.read_text())
    data["pipeline"]["outputs"] = [
        {"name": "stdout", "match": "tenant." + name, "format": "json_lines", "processors": {"logs": [
            {"name": "fts", "code": 'function process(log) log.body:set("destination", "' + name + '") end'}]}}
        for name in ["a", "b"]]
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as connection:
            for index, name in enumerate(["a", "b"]):
                payload = pack([1700000000, event("shared", "ERROR" if index else "DEBUG", id=index)])
                connection.sendall(pack(["tenant." + name, payload, {"size": 1}]))
        service.wait_for_condition(lambda: len(rows(service)) == 2, timeout=30)
        assert {row["id"]: row["destination"] for row in rows(service)} == {0: "a", 1: "b"}
        assert all(row["visits"] == 1 and row["password"] == "[REDACTED]" for row in rows(service))
    finally:
        service.stop()



def test_visit_counter_detects_a_second_following_stage(tmp_path):
    import copy
    config = configuration(tmp_path)
    data = yaml.safe_load(config.read_text())
    processors = data["pipeline"]["inputs"][0]["processors"]["logs"]
    processors.append(copy.deepcopy(processors[1]))
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, event("counter-control", "ERROR"))
        service.wait_for_condition(lambda: len(rows(service)) == 1, timeout=30)
        assert rows(service)[0]["visits"] == 2
        assert "log policy failed" not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("threaded", [False, True])
def test_large_window_releases_ten_thousand_records_in_bounded_batches(tmp_path, threaded):
    config = configuration(tmp_path, threaded=threaded, hold_ms=10000)
    data = yaml.safe_load(config.read_text())
    source = data["pipeline"]["inputs"][0]
    source["buffer_chunk_size"] = "4M"
    source["buffer_max_size"] = "8M"
    source["processors"]["logs"][0]["state_limit"] = "16M"
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [event("large", "INFO", sequence=index) for index in range(10000)])
        wait_count(service, "held", 10000)
        wait_count(service, "released", 10000)
        wait_count(service, "fluentbit_processor_items_held_current", 0)
        service.wait_for_condition(lambda: len(rows(service)) == 10000, timeout=30)
        result = rows(service)
        assert [record["sequence"] for record in result] == list(range(10000))
        assert all(record["visits"] == 1 and record["password"] == "[REDACTED]" for record in result)
        assert 0 < counters(service)["release_batches"] < 1000
        assert counters(service).get("release_retry", 0) == 0
    finally:
        service.stop()


@pytest.mark.parametrize("threaded", [False, True])
def test_held_batch_does_not_consume_emitted_output_budget(tmp_path, threaded):
    config = configuration(tmp_path, threaded=threaded, hold_ms=700)
    data = yaml.safe_load(config.read_text())
    proc = data["pipeline"]["inputs"][0]["processors"]["logs"][0]
    proc.update(output_limit="65536", memory_limit="8M", state_limit="2M", instruction_limit=10000000)
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        records = [event("batch", "INFO", payload="x" * 2048, index=index) for index in range(50)]
        send(service, records)
        service.wait_for_condition(lambda: len(rows(service)) == 50, timeout=30)
        assert [row["index"] for row in rows(service)] == list(range(50))
        assert all(row["password"] == "[REDACTED]" and row["visits"] == 1 for row in rows(service))
        wait_count(service, "fluentbit_processor_items_held_total", 50)
        assert "edits rolled back" not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("threaded", [False, True])
def test_unresolved_group_continuation_passes_sanitized_without_retention(tmp_path, threaded):
    import msgpack
    service = FluentBitTestService(str(configuration(tmp_path, threaded=threaded, hold_ms=10000)))
    try:
        service.start()
        # This append continues a group opened in an earlier chunk. Its end marker
        # must stay with the record because the inherited context is unavailable.
        payload = msgpack.packb([[1700000000, {}], event("continued", "INFO")], use_bin_type=True)
        payload += msgpack.packb([[msgpack.ExtType(0, bytes.fromhex("fffffffe00000000")), {}], {}], use_bin_type=True)
        message = msgpack.packb(["stream", payload, {"size": 1}], use_bin_type=True)
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=10) as connection:
            connection.sendall(message)
        service.wait_for_condition(lambda: len(rows(service)) == 1, timeout=30)
        record = rows(service)[0]
        assert record["request_id"] == "continued" and record["password"] == "[REDACTED]"
        assert record["visits"] == 1
        wait_count(service, "context_passthrough", 1)
        assert counters(service)["fluentbit_processor_items_held_total"] == 0
    finally:
        service.stop()
