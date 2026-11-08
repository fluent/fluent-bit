"""Real OTLP temporal windows: Lua reductions and native ownership/release."""
import copy
import importlib.util
import os
from pathlib import Path

import pytest

from fts_test_utils import read_log

ROOT = Path(__file__).resolve().parents[5]
spec = importlib.util.spec_from_file_location("fts_window_fixture", ROOT / "tools/fts/fts_fixture.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
PACK = ROOT / "packs/fts/metrics/gauge-rollup"
BINARY = Path(os.environ.get("FLUENT_BIT_BINARY", ROOT / "build/bin/fluent-bit"))


def replay(operation, mutate=None, **options):
    path = PACK / f"tests/{operation}.yaml"
    fixture = runner.load_fixture(path)
    if mutate:
        mutate(fixture)
    for case in fixture["cases"]:
        runner.run_case(fixture, case, path, BINARY, os.environ.get("VALGRIND") == "1", **options)


@pytest.mark.parametrize("operation", ["sum", "mean", "min", "max", "count"])
@pytest.mark.parametrize("threaded", [False, True])
def test_lua_temporal_gauges_across_batches(operation, threaded):
    replay(operation, threaded=threaded)


def points(payload):
    return payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"]


@pytest.mark.parametrize("threaded", [False, True])
def test_temporal_resume_runs_only_following_stage(threaded):
    before = {"name": "fts", "code": '''local fb=require('fluentbit')
function process(metric)
    for i=1,metric.datapoints:len() do
        local point=metric.datapoints:get(i)
        fb.set_metric_value(point,fb._fts_add(fb.metric_value(point),fb.metric_value(point)))
    end
end'''}
    after = {"name": "fts", "code": '''local fb=require('fluentbit')
function process(metric)
    metric.name=metric.name..'.released'
    for i=1,metric.datapoints:len() do
        local point=metric.datapoints:get(i)
        fb.set_metric_value(point,fb._fts_add(fb.metric_value(point),fb.int64(100)))
    end
end'''}
    def mutate(fixture):
        expected = fixture["cases"][0]["expected"]["otlp"]
        expected["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["name"] += ".released"
        for point in points(expected):
            point["asInt"] = str(int(point["asInt"]) * 2 + 100)
    replay("sum", mutate, threaded=threaded, before_processors=[before], after_processors=[after])


@pytest.mark.parametrize("operation", ["sum", "min", "max"])
def test_temporal_exact_int64_above_double_precision(operation):
    def mutate(fixture):
        case = fixture["cases"][0]
        for batch in case["input"]:
            for point in points(batch):
                point["asInt"] = "9007199254740993"
        for point in points(case["expected"]["otlp"]):
            point["asInt"] = str(18014398509481986 if operation == "sum" else 9007199254740993)
    replay(operation, mutate)


def test_sample_overflow_keeps_original_not_partial_aggregate():
    def mutate(fixture):
        fixture["processor"]["recipe"][0]["with"]["max_samples"] = 1
        case = fixture["cases"][0]
        expected = case["expected"]
        # The second observation is returned intact before the first window closes.
        expected["otlp"] = {"resourceMetrics": copy.deepcopy(
            case["input"][1]["resourceMetrics"] + case["input"][0]["resourceMetrics"])}
        expected["outcomes"] = {"kept": 0, "dropped": 0, "errors": 1, "held": 1}
        expected["metric_window_families"] = {"held": 1, "released": 1, "reduced": 0, "pending": 0}
        expected["error"] = {"step": "rollup", "class": "operation_failed"}
    replay("sum", mutate)


def native_service(tmp_path, threaded, **processor_options):
    import yaml
    from utils.test_service import FluentBitTestService
    fixture = runner.load_fixture(PACK / "tests/sum.yaml")
    processor = fixture["processor"]
    processor.update(packages_dir=str(PACK), packs=["pack.json"], **processor_options)
    processor["recipe"][0]["with"]["interval_ms"] = 60000
    config = tmp_path / "metric-window.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "hot_reload": True, "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [{"name": "opentelemetry", "threaded": threaded,
            "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "processors": {"metrics": [processor]}}],
            "outputs": [{"name": "stdout", "match": "*", "format": "otlp_json"}]}}))
    return FluentBitTestService(str(config)), fixture["cases"][0]["input"][0]


def family_counts(service):
    import re
    import requests
    response = requests.get(f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus", timeout=10)
    if response.status_code in (404, 503):
        return {}
    response.raise_for_status()
    events = re.findall(r'^fluentbit_fts_metric_window_family_events_total\{([^\n]*)\}\s+(\S+)', response.text, re.M)
    counts = {outcome: sum(float(value) for labels, value in events if f'outcome="{outcome}"' in labels)
        for outcome in ("held", "released", "shutdown")}
    inventory = re.findall(r'^fluentbit_fts_metric_window_pending_input_families\{([^\n]*)\}\s+(\S+)', response.text, re.M)
    counts["pending"] = sum(float(value) for _, value in inventory)
    return counts


def send_metrics(service, payload):
    import requests
    response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/metrics", json=payload, timeout=10)
    assert response.status_code in (200, 201), response.text


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("reload", [False, True])
def test_pending_families_reported_at_stop_or_reload(tmp_path, threaded, reload):
    service, payload = native_service(tmp_path, threaded)
    try:
        service.start()
        send_metrics(service, payload)
        service.wait_for_condition(lambda: family_counts(service).get("pending") == 1, timeout=30)
        assert family_counts(service)["held"] == 1
        if reload:
            service.flb.trigger_http_reload()
            service.flb.wait_for_hot_reload_count(1, timeout=30)
            service.wait_for_condition(lambda: family_counts(service).get("pending") == 0, timeout=30)
        else:
            service.stop()
        expected = "1 retained metric families discarded at input stop"
        assert expected in read_log(service.flb.log_file, expected)
    finally:
        service.stop()


@pytest.mark.parametrize("threaded", [False, True])
def test_final_batch_failure_rolls_back_all_holds(tmp_path, threaded):
    service, payload = native_service(tmp_path, threaded, output_limit=65536)
    second = copy.deepcopy(payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0])
    second.update(name="unselected", description="x" * 70000)
    payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"].append(second)
    try:
        service.start()
        send_metrics(service, payload)
        service.wait_for_condition(lambda: "cannot construct FTS metrics output" in Path(service.flb.log_file).read_text(), timeout=30)
        assert family_counts(service)["held"] == 0
        assert family_counts(service)["pending"] == 0
    finally:
        service.stop()


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("mode", ["foreign_snapshot", "error_after_request", "bad_key", "bad_get"])
def test_hold_targets_current_family_and_error_aborts_request(tmp_path, threaded, mode):
    import json
    manifest = json.loads((PACK / "pack.json").read_text())
    manifest["blocks"][0]["source"] = "block.lua"
    (tmp_path / "pack.json").write_text(json.dumps(manifest))
    source = '''return function(p)
        local window=fb.metric_window{interval_ms=p.interval_ms}
        return function(metric)
            local key=fb.metric_window_key(metric)
            local previous,state,samples=window:get(key)
            local failing=fb.metric_value(metric.datapoints:get(1)):value()=='5'
            if failing and MODE=='bad_get' then window:get(7) end
            if failing and MODE=='bad_key' then return window:hold(7,metric,state) end
            if failing and MODE=='foreign_snapshot' then
                previous.name='unvalidated-previous-family'
                previous.datapoints:get(1):set('time_unix_nano',fb.uint64(0))
                return window:hold(key..':other',previous,state)
            end
            local next_state=fb.gauge_rollup(metric,previous,state,samples,'sum')
            local result=window:hold(key,metric,next_state)
            if failing then metric.name='partial-edit';error('wrong_type',0) end
            return result
        end
    end'''.replace('MODE', repr(mode))
    (tmp_path / "block.lua").write_text(source)
    path = PACK / "tests/sum.yaml"
    fixture = runner.load_fixture(path)
    fixture["processor"]["packs"] = [str(tmp_path / "pack.json")]
    case = fixture["cases"][0]
    original_first = copy.deepcopy(case["input"][0])
    second = copy.deepcopy(case["input"][1])
    expected = case["expected"]
    if mode != "error_after_request":
        final = original_first
        held, reduced = 1, 0
        error = "invalid_context" if mode == "foreign_snapshot" else "wrong_type"
    else:
        third = copy.deepcopy(second)
        for point, value in zip(points(third), (7, 9)):
            point.update(asInt=str(value), timeUnixNano="1700000003000000000")
        case["input"].append(third)
        final = copy.deepcopy(third)
        for point, value in zip(points(final), (10, 17)):
            point["asInt"] = str(value)
        held, reduced, error = 2, 1, "wrong_type"
    expected["otlp"] = {"resourceMetrics": second["resourceMetrics"] + final["resourceMetrics"]}
    expected["outcomes"] = {"kept": 0, "dropped": 0, "errors": 1, "held": held}
    expected["metric_window_families"] = {"held": held, "released": 1, "reduced": reduced, "pending": 0}
    expected["error"] = {"step": "rollup", "class": error}
    runner.run_case(fixture, case, path, BINARY, os.environ.get("VALGRIND") == "1", threaded=threaded)
