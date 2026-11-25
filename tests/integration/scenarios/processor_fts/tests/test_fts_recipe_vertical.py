"""Executable consumer examples and independent block contracts."""
import copy
import json
import re
import socket
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml

from test_fts_recipes import config_file, redact, rejected_startup
from test_fts_records import rows, send
from test_fts_signals import SignalRunner, metric, span, attr
from test_fts_policies import attributes
from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port
from utils.test_service import FluentBitTestService

from fts_test_utils import read_log

ROOT = Path(__file__).resolve().parents[5]


def examples():
    text = (ROOT / "documentation/fts/architecture.md").read_text()
    return [yaml.safe_load(code) for code in re.findall(r"```yaml\n(.*?)```", text, re.S)[:3]]


@contextmanager
def signal_recipe(tmp_path, signal, processor, placement="input"):
    port = find_available_port()
    source = {"name": "opentelemetry", "port": port}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    (source if placement == "input" else output)["processors"] = {signal: [processor]}
    config = tmp_path / "signal.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    class SignalRecipeManager(FluentBitManager):
        def set_http_monitoring_port(self, env_var_name, starting_port=0):
            # Keep our receiver port unavailable while choosing the monitor port.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(("127.0.0.1", port))
                super().set_http_monitoring_port(env_var_name, starting_port)

    manager = SignalRecipeManager(str(config))
    try:
        manager.start()
        yield SignalRunner(manager, port, signal)
    finally:
        manager.stop()


def test_documented_tail_recipe(tmp_path):
    config = examples()[0]
    source_file = tmp_path / "app.log"
    source_file.write_text('{"level":"Information","password":"synthetic",'
                           '"id":18446744073709551615}\n' * 2)
    source = config["pipeline"]["inputs"][0]
    source.update(path=str(source_file), read_from_head=True)
    config["service"] = {"flush": 0.2, "grace": 1, "http_server": True,
                         "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"}
    config["pipeline"]["outputs"][0]["format"] = "json_lines"
    filename = tmp_path / "tail.yaml"
    filename.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(filename))
    try:
        service.start()
        result = service.wait_for_condition(lambda: len(rows(service)) == 2 and rows(service), timeout=30)
        assert len(result) == 2
        for record in result:
            record.pop("date")
            assert record == {"level": "INFO", "app": {"level": "Information",
                "password": "[REDACTED]", "id": 18446744073709551615}}
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_documented_metric_recipe(tmp_path, placement):
    processor = examples()[1]["processors"]["metrics"][0]
    target = metric("histogram", "legacy_http_duration_ms")
    point = target["histogram"]["dataPoints"][0]
    point.update(explicitBounds=[50, 250, 1000, 2000], bucketCounts=["1", "2", "3", "4", "5"],
                 count="15", sum=9000, min=1, max=3000)
    with signal_recipe(tmp_path, "metrics", processor, placement) as runner:
        outputs = []
        for _ in range(2):
            _, result = runner.run("legacy_http_duration_ms", "histogram",
                                   custom_items=[target, metric("gauge", "control")])
            assert len(result) == 1
            item = result[0][2]
            assert item["name"] == "app.http.duration" and item["unit"] == "s"
            actual = item["histogram"]["dataPoints"][0]
            assert actual["explicitBounds"] == [0.05, 0.25, 1.0]
            assert [int(n) for n in actual["bucketCounts"]] == [1, 2, 3, 9]
            assert int(actual["count"]) == 15 and actual["sum"] == 9
            outputs.append(item)
        assert outputs[0] == outputs[1]


@pytest.mark.parametrize("placement", ["input", "output"])
def test_documented_trace_recipe(tmp_path, placement):
    processor = examples()[2]["processors"]["traces"][0]
    target = span("probe")
    target["attributes"] += [attr("http.request.method", "GET"), attr("http.route", "/users/{id}"),
                             attr("password", "synthetic")]
    target["events"][0]["attributes"].append(attr("password", "synthetic"))
    target["links"][0]["attributes"].append(attr("password", "synthetic"))
    control = span("control")
    control["kind"] = 3
    with signal_recipe(tmp_path, "traces", processor, placement) as runner:
        outputs = []
        for _ in range(2):
            _, result = runner.run("probe", custom_items=[target, control])
            assert len(result) == 2
            item = next(item for _, _, item in result if item["name"] != "control")
            assert item["name"] == "GET /users/{id}"
            assert attributes(item["attributes"])["password"] == "[REDACTED]"
            assert attributes(item["events"][0]["attributes"])["password"] == "[REDACTED]"
            assert attributes(item["links"][0]["attributes"])["password"] == "[REDACTED]"
            for key in ("traceId", "spanId", "parentSpanId", "startTimeUnixNano", "endTimeUnixNano"):
                assert item[key] == target[key]
            assert item["links"][0]["traceId"] == target["links"][0]["traceId"]
            outputs.append(item)
        assert outputs[0] == outputs[1]


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_field_edits_types_rollback_and_repetition(tmp_path, placement, error_mode):
    operations = [
        {"op": "set", "target": {"root": "body", "path": ["exact"]},
         "value": {"type": "uint64", "value": "18446744073709551615"}},
        {"op": "set_default", "target": {"root": "body", "path": ["level"]}, "value": "INFO"},
        {"op": "copy", "source": {"root": "body", "path": ["original"]},
         "target": {"root": "body", "path": ["copy"]}},
        {"op": "rename", "source": {"root": "body", "path": ["original"]},
         "target": {"root": "body", "path": ["renamed"]}},
        {"op": "set", "target": {"root": "body", "path": ["parent", "child"]}, "value": True},
    ]
    processor = {"name": "fts", "error_mode": error_mode,
                 "recipe": [{"id": "edit", "use": "fields.edit", "with": {"operations": operations}}]}
    config = config_file(tmp_path, processor, placement)
    service = FluentBitTestService(str(config))
    valid = {"original": "source", "parent": {}, "control": "ok"}
    invalid = {"original": "source", "parent": "bad", "control": "bad"}
    try:
        service.start()
        send(service, [valid, invalid, copy.deepcopy(valid)])
        result = service.wait_for_condition(lambda: len(rows(service)) == (3 if error_mode == "keep" else 2) and rows(service), timeout=30)
        good = [r for r in result if r["control"] == "ok"]
        assert len(good) == 2 and good[0] == good[1]
        for record in good:
            record.pop("date")
            assert record == {"exact": 18446744073709551615, "level": "INFO", "copy": "source",
                              "renamed": "source", "parent": {"child": True}, "control": "ok"}
        bad = [r for r in result if r["control"] == "bad"]
        if error_mode == "drop":
            assert not bad
        else:
            assert len(bad) == 1
            bad[0].pop("date")
            assert bad[0] == invalid
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_rename_rejects_existing_family_target(tmp_path, placement):
    processor = {"name": "fts", "error_mode": "keep", "recipe": [
        {"id": "rename", "use": "metrics.rename", "with": {"mapping": {"probe": "control"}}}]}
    with signal_recipe(tmp_path, "metrics", processor, placement) as runner:
        _, result = runner.run("probe")
        assert sorted(item["name"] for _, _, item in result) == ["control", "probe"]
    assert "class=collision" in read_log(runner.manager.log_file, "class=collision")


@pytest.mark.parametrize("signal,step,reason", [
    ("logs", {"id": "parse", "use": "logs.parse_json", "with": {
        "source": {"root": "body", "path": ["log"]},
        "destination": {"root": "body", "path": ["log", "nested"]}}}, "param=destination reason=range"),
    ("metrics", {"id": "select", "use": "metrics.select", "with": {"keep": {}}}, "reason=missing"),
    ("metrics", {"id": "rename", "use": "metrics.rename", "with": {"mapping": {"a": "b", "b": "a"}}}, "reason=range"),
    ("metrics", {"id": "rename", "use": "metrics.rename", "with": {"mapping": {"a": "c", "b": "c"}}}, "reason=duplicate"),
])
def test_vertical_parameter_validation(tmp_path, signal, step, reason):
    config = config_file(tmp_path, {"name": "fts", "recipe": [step]}, signal=signal)
    assert reason in rejected_startup(config, tmp_path)


@pytest.mark.parametrize("message", ['{', '{"x":1,"x":2}', '[]', {"already": "parsed"}])
@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_parse_failure_rolls_back_preceding_step(tmp_path, message, error_mode):
    processor = {"name": "fts", "error_mode": error_mode, "recipe": [
        {"id": "mark", "use": "fields.edit", "with": {"operations": [
            {"op": "set", "target": {"root": "body", "path": ["marked"]}, "value": True}]}},
        {"id": "parse", "use": "logs.parse_json", "with": {
            "source": {"root": "body", "path": ["message"]},
            "destination": {"root": "body", "path": ["parsed"]}, "remove_source": True}}]}
    service = FluentBitTestService(str(config_file(tmp_path, processor)))
    bad = {"message": message, "control": "bad"}
    try:
        service.start()
        send(service, [bad, {"message": '{"value":7}', "control": "ok"}])
        result = service.wait_for_condition(lambda: len(rows(service)) == (2 if error_mode == "keep" else 1) and rows(service), timeout=30)
        for record in result:
            record.pop("date")
        good = next(record for record in result if record["control"] == "ok")
        assert good == {"control": "ok", "marked": True, "parsed": {"value": 7}}
        assert [record for record in result if record["control"] == "bad"] == ([bad] if error_mode == "keep" else [])
    finally:
        service.stop()


@pytest.mark.parametrize("overwrite", [False, True])
def test_severity_aliases_missing_unknown_and_existing(tmp_path, overwrite):
    processor = {"name": "fts", "error_mode": "keep", "recipe": [
        {"id": "level", "use": "logs.normalize_severity", "with": {
            "source": {"root": "body", "path": ["level"]},
            "destination": {"root": "body", "path": ["normalized"]},
            "overwrite": overwrite, "on_unknown": "preserve"}}]}
    inputs = [{"level": "Information"}, {"level": "warning"}, {"level": "critical"},
              {"level": "custom"}, {}, {"level": 7}, {"level": "warn", "normalized": "CUSTOM"}]
    expected = [dict(inputs[0], normalized="INFO"), dict(inputs[1], normalized="WARN"),
                dict(inputs[2], normalized="FATAL"), inputs[3], inputs[4], inputs[5],
                dict(inputs[6], normalized="WARN" if overwrite else "CUSTOM")]
    service = FluentBitTestService(str(config_file(tmp_path, processor)))
    try:
        service.start()
        send(service, inputs * 2)
        result = service.wait_for_condition(lambda: len(rows(service)) == len(expected) * 2 and rows(service), timeout=30)
        for record in result:
            record.pop("date")
        assert result == expected * 2
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_trace_field_removal_updates_semantic_counts(tmp_path, placement):
    processor = {"name": "fts", "recipe": [{"id": "remove", "use": "fields.edit", "with": {
        "operations": [{"op": "remove", "target": {"root": root, "path": [key]}}
                       for root, key in [("attributes", "secret"), ("resource.attributes", "secret"),
                                         ("scope.attributes", "exact")]]}}]}
    with signal_recipe(tmp_path, "traces", processor, placement) as runner:
        for _ in range(2):
            _, result = runner.run("probe")
            assert len(result) == 2
            for resource, scope, item in result:
                assert "secret" not in attributes(item.get("attributes", []))
                assert item["droppedAttributesCount"] == 2
                assert resource["resource"]["droppedAttributesCount"] == 8
                assert scope["scope"]["droppedAttributesCount"] == 7
                assert "secret" not in attributes(resource["resource"].get("attributes", []))
                assert "exact" not in attributes(scope["scope"].get("attributes", []))


@pytest.mark.parametrize("kind", ["gauge", "sum", "histogram", "exponentialHistogram", "summary"])
@pytest.mark.parametrize("action", ["keep", "drop"])
def test_metric_selection_is_family_local(tmp_path, kind, action):
    processor = {"name": "fts", "recipe": [{"id": "choose", "use": "metrics.select", "with": {
        action: {"prefixes": ["pro"]}}}]}
    with signal_recipe(tmp_path, "metrics", processor) as runner:
        _, result = runner.run("probe", kind)
        assert len(result) == 1
        item = result[0][2]
        assert item["name"] == ("probe" if action == "keep" else "control")
        assert item["unit"] == "ms" and kind in item


@pytest.mark.parametrize("method,route,kind,expected", [
    ("_OTHER", "/users/{id}", 2, "HTTP /users/{id}"),
    ("GET", None, 2, "probe"),
    ("GET", "/users/{id}", 3, "probe"),
    ("get", "/users/{id}", 2, "GET /users/{id}"),
])
def test_trace_route_uses_real_server_metadata(tmp_path, method, route, kind, expected):
    processor = {"name": "fts", "recipe": [{"id": "name", "use": "traces.name_from_route"}]}
    target = span("probe")
    target["kind"] = kind
    target["attributes"] += [attr("http.request.method", method), attr("url.path", "/users/123")]
    if route is not None:
        target["attributes"].append(attr("http.route", route))
    with signal_recipe(tmp_path, "traces", processor) as runner:
        _, result = runner.run("probe", custom_items=[target])
        assert len(result) == 1 and result[0][2]["name"] == expected


def test_rename_cannot_hide_scale_before_merge(tmp_path):
    processor = {"name": "fts", "recipe": [
        {"id": "scale", "use": "metrics.scale", "with": {
            "names": ["a"], "input_unit": "ms", "output_unit": "s", "factor": 0.001}},
        {"id": "rename", "use": "metrics.rename", "with": {"mapping": {"a": "b"}}},
        {"id": "merge", "use": "metrics.merge_histogram_buckets", "with": {
            "names": ["b"], "bounds": [0.009]}}]}
    config = config_file(tmp_path, processor, signal="metrics")
    assert "merge_histogram_buckets must precede metrics.scale" in rejected_startup(config, tmp_path)


def test_redaction_preserves_link_ids_and_counts_duplicate_attributes(tmp_path):
    processor = {"name": "fts", "recipe": [redact(
        targets=[{"root": root, "path": []} for root in ("attributes", "events", "links")],
        keys=["password", "trace_id", "name"])]}
    target = span("probe")
    for owner in (target, target["events"][0], target["links"][0]):
        owner["attributes"] += [attr("password", "first"), attr("password", "second")]
    with signal_recipe(tmp_path, "traces", processor) as runner:
        _, result = runner.run("probe", custom_items=[target])
        item = result[0][2]
        assert item["name"] == target["name"]
        assert item["events"][0]["name"] == target["events"][0]["name"]
        assert item["links"][0]["traceId"] == target["links"][0]["traceId"]
        assert item["droppedAttributesCount"] == 2
        assert item["events"][0]["droppedAttributesCount"] == 5
        assert item["links"][0]["droppedAttributesCount"] == 6
        for owner in (item, item["events"][0], item["links"][0]):
            matches = [a for a in owner["attributes"] if a["key"] == "password"]
            assert len(matches) == 1 and matches[0]["value"]["stringValue"] == "[REDACTED]"


@pytest.mark.parametrize("operation,expected", [
    ("keep", {"k8s.pod.name": "pod", "k8s.namespace.name": "ns"}),
    ("remove", {"ordinary": "value"}),
])
def test_field_prefixes_are_literal(tmp_path, operation, expected):
    processor = {"name": "fts", "recipe": [{"id": "labels", "use": "fields.edit", "with": {
        "operations": [{"op": operation, "target": {"root": "body", "path": []}, "prefixes": ["k8s."]}]}}]}
    service = FluentBitTestService(str(config_file(tmp_path, processor)))
    try:
        service.start()
        send(service, {"k8s.pod.name": "pod", "k8s.namespace.name": "ns", "ordinary": "value"})
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert len(result) == 1
        result[0].pop("date")
        assert result[0] == expected
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("reverse", [False, True])
def test_metric_rename_uses_namespace_after_select(tmp_path, placement, reverse):
    proc = {"name": "fts", "error_mode": "drop", "recipe": [
        {"id": "select", "use": "metrics.select", "with": {"drop": {"names": ["control"]}}},
        {"id": "rename", "use": "metrics.rename", "with": {"mapping": {"probe": "control"}}}]}
    items = [metric("gauge", "probe"), metric("gauge", "control")]
    if reverse:
        items.reverse()
    with signal_recipe(tmp_path, "metrics", proc, placement) as runner:
        _, result = runner.run("probe", custom_items=items)
        assert len(result) == 1 and result[0][2]["name"] == "control"
    assert "class=collision" not in Path(runner.manager.log_file).read_text()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_failed_earlier_rename_does_not_hide_surviving_names(tmp_path, placement):
    proc = {"name": "fts", "error_mode": "keep", "recipe": [
        {"id": "first", "use": "metrics.rename", "with": {"mapping": {"probe": "control"}}},
        {"id": "second", "use": "metrics.rename", "with": {"mapping": {"third": "probe"}}}]}
    items = [metric("gauge", name) for name in ["probe", "control", "third"]]
    with signal_recipe(tmp_path, "metrics", proc, placement) as runner:
        _, result = runner.run("probe", custom_items=items)
        assert sorted(item["name"] for _, _, item in result) == ["control", "probe", "third"]
    text = read_log(runner.manager.log_file, "step=first class=collision", "step=second class=collision")
    assert "step=first class=collision" in text
    assert "step=second class=collision" in text
