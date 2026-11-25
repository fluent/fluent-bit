"""Remaining core contracts, typed conditions and review regressions."""
import copy
from contextlib import contextmanager

import pytest

from test_fts_recipes import config_file, rejected_startup
from test_fts_records import rows, send as send_records, log_text, Raw
from test_fts_recipe_vertical import signal_recipe
from test_fts_signals import metric, span, attr
from utils.test_service import FluentBitTestService


def send(service, records):
    def typed(value):
        if value is None:
            return Raw(b"\xc0")
        if isinstance(value, bool):
            return Raw(b"\xc3" if value else b"\xc2")
        if isinstance(value, dict):
            return {key: typed(child) for key, child in value.items()}
        if isinstance(value, list):
            return [typed(child) for child in value]
        return value
    send_records(service, typed(records))


def sel(key, root="body"):
    return {"root": root, "path": [key]}


def block(use, **params):
    return {"id": use.replace(".", "_"), "use": use, "with": params}


@contextmanager
def logs(tmp_path, steps, placement="input", **options):
    service = FluentBitTestService(str(config_file(tmp_path, {
        "name": "fts", "recipe": steps, **options}, placement)))
    try:
        service.start()
        yield service
    finally:
        service.stop()


def output(service, records):
    send(service, records)
    result = service.wait_for_condition(lambda: rows(service), timeout=30)
    for row in result:
        row.pop("date")
    return result


@pytest.mark.parametrize("placement", ["input", "output"])
def test_common_severity_default_and_in_place(tmp_path, placement):
    steps = [block("logs.normalize_severity", source=sel("level"), destination=sel("level"))]
    inputs = [{"level": v} for v in ["notice", "err", "crit", "alert", "emerg", "dbg", "warn ", "custom"]]
    expected = [{"level": v} for v in ["INFO", "ERROR", "FATAL", "FATAL", "FATAL", "DEBUG", "WARN", "custom"]]
    with logs(tmp_path, steps, placement) as service:
        assert output(service, inputs * 2) == expected * 2


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("memory", [False, True])
def test_parse_failure_class(tmp_path, placement, memory):
    steps = [block("logs.parse_json", source=sel("message"), destination=sel("parsed"))]
    message = '{"value":"' + 'x' * 100000 + '"}' if memory else '{bad-private'
    with logs(tmp_path, steps, placement, memory_limit="1M", error_mode="keep") as service:
        result = output(service, [{"message": message}, {"message": '{"value":true}'}])
        assert result[0] == {"message": message}
        assert result[1]["parsed"] == {"value": True}
        expected = "class=" + ("budget_exceeded" if memory else "invalid_json")
        assert expected in log_text(service, expected)


def test_literal_map_sorted(tmp_path):
    value = {"type": "map", "value": {"z": "last", "a": {"type": "map", "value": {"y": True, "b": False}}, "m": "middle"}}
    with logs(tmp_path, [block("fields.edit", operations=[{"op": "set", "target": sel("map"), "value": value}])]) as service:
        for record in output(service, [{"id": 1}, {"id": 2}]):
            assert list(record["map"]) == ["a", "m", "z"]
            assert list(record["map"]["a"]) == ["b", "y"]


@pytest.mark.parametrize("placement", ["input", "output"])
def test_timestamp_native_and_rollback(tmp_path, placement):
    steps = [block("logs.parse_timestamp", source=sel("time"), on_missing="skip")]
    inputs = [{"time": "2038-01-19T03:14:08.123456789Z"},
              {"time": "1969-12-31T23:00:00-01:00"},
              {"time": "2024-02-30T01:00:00Z"}, {"control": True}]
    with logs(tmp_path, steps, placement, error_mode="keep") as service:
        send(service, inputs)
        actual = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert len(actual) == 4
        assert abs(actual[0]["date"] - 2147483648.123456789) < 0.000001
        assert actual[1]["date"] == 0
        assert actual[2]["time"] == inputs[2]["time"]
        assert "class=invalid_timestamp" in log_text(service, "class=invalid_timestamp")


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("operator", ["eq", "neq", "in", "not_in"])
def test_typed_conditions_negative_and_missing(tmp_path, placement, operator):
    condition = {"selector": sel("value"), "op": operator}
    condition["values" if operator in ("in", "not_in") else "value"] = ["x"] if operator in ("in", "not_in") else "x"
    steps = [block("logs.drop_matching", condition=condition)]
    inputs = [{"value": "x"}, {"value": "y"}, {"value": 1}, {"value": None}, {}]
    expected = inputs[1:] if operator in ("eq", "in") else [inputs[0], *inputs[2:]]
    with logs(tmp_path, steps, placement) as service:
        assert output(service, inputs * 2) == expected * 2


@pytest.mark.parametrize("placement", ["input", "output"])
def test_conditions_current_edits_when_and_exactness(tmp_path, placement):
    steps = [block("fields.edit", operations=[{"op": "set", "target": sel("normalized"), "value": "health"}]),
             block("logs.drop_matching", condition={"all": [
                 {"selector": sel("normalized"), "op": "eq", "value": "health"},
                 {"selector": sel("latency"), "op": "lt", "value": {"type": "double", "value": 10}}]})]
    steps[0]["when"] = {"selector": sel("path"), "op": "eq", "value": "/health"}
    inputs = [{"path": "/health", "latency": 5}, {"path": "/health", "latency": 20},
              {"path": "/healthz", "latency": 1}, {"path": "/health", "latency": 18446744073709551615}]
    with logs(tmp_path, steps, placement, error_mode="keep") as service:
        result = output(service, inputs)
        assert result == [dict(inputs[1], normalized="health"), inputs[2], dict(inputs[3], normalized="health")]
        assert "class=unsupported_conversion" not in log_text(service)


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_validation_null_enum_types_and_rollback(tmp_path, placement, error_mode):
    steps = [block("fields.edit", operations=[{"op": "set", "target": sel("marked"), "value": True}]),
             block("logs.validate_fields", rules=[
                 {"selector": sel("level"), "type": "string", "enum": ["INFO", "ERROR"]},
                 {"selector": sel("nullable"), "type": "null", "required": False}])]
    inputs = [{"level": "INFO", "nullable": None}, {"level": "DEBUG"}, {"level": 5}, {}, {"level": "ERROR"}]
    expected = [dict(inputs[0], marked=True), *([] if error_mode == "drop" else inputs[1:4]), dict(inputs[4], marked=True)]
    with logs(tmp_path, steps, placement, error_mode=error_mode) as service:
        assert output(service, inputs * 2) == expected * 2
        assert "class=validation_failed" in log_text(service, "class=validation_failed")


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("limit", [0, 1, 2, 3, 4, 5, 7])
def test_truncate_utf8_boundary_marker_and_replay(tmp_path, placement, limit):
    step = block("fields.truncate", target=sel("text"), max_bytes=limit, marker=sel("was.cut"))
    text = "é🙂z"
    cut = text.encode()[:limit].decode("utf-8", errors="ignore")
    expected = {"text": cut, **({"was.cut": True} if limit < 7 else {})}
    with logs(tmp_path, [step], placement, error_mode="keep") as service:
        first = output(service, [{"text": text}, {"text": text}])
        assert first == [expected, expected]
        send(service, [expected])
        replay = service.wait_for_condition(lambda: rows(service) if len(rows(service)) == 3 else None, timeout=30)
        replay[-1].pop("date")
        assert replay[-1] == expected


@pytest.mark.parametrize("placement", ["input", "output"])
def test_truncate_collision_and_wrong_type_rollback(tmp_path, placement):
    step = block("fields.truncate", target=sel("text"), max_bytes=2, marker=sel("cut"))
    inputs = [{"text": "long", "cut": False}, {"text": 42}, {"text": "ok"}]
    with logs(tmp_path, [step], placement, error_mode="keep") as service:
        assert output(service, inputs) == inputs
        diagnostics = log_text(service, "class=collision", "class=wrong_type")
        assert "class=collision" in diagnostics and "class=wrong_type" in diagnostics


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("kind,operation", [("gauge", "sum"), ("gauge", "min"), ("gauge", "max"),
    ("gauge", "mean"), ("gauge", "count"), ("sum", "sum"), ("histogram", "sum")])
def test_aggregate_dimensions_bounded_and_windowed(tmp_path, placement, kind, operation):
    target = metric(kind, "probe")
    first = target[kind]["dataPoints"][0]
    first["attributes"] = [attr("region", "west"), attr("pod", "one")]
    first["exemplars"] = [{"asDouble": float(n), "timeUnixNano": first["timeUnixNano"]} for n in range(3)]
    if kind != "histogram":
        first.pop("asDouble", None)
        first["asInt"] = "7"
    second = copy.deepcopy(first)
    second["attributes"] = [attr("region", "west"), attr("pod", "two")]
    if kind != "histogram":
        second["asInt"] = "11"
    third = copy.deepcopy(first)
    third["startTimeUnixNano"] = "2000000000000000000"
    target[kind]["dataPoints"] = [first, second, third]
    processor = {"name": "fts", "recipe": [block("metrics.aggregate_dimensions", names=["probe"],
        keep_attributes=["region"], operation=operation, max_exemplars=1)]}
    with signal_recipe(tmp_path, "metrics", processor, placement) as runner:
        previous = None
        for _ in range(2):
            _, result = runner.run("probe", kind, custom_items=[target])
            assert len(result) == 1
            item = result[0][2]
            points = item[kind]["dataPoints"]
            assert len(points) == 2
            assert len(points[0]["exemplars"]) == 1
            assert points[0]["exemplars"][0]["asDouble"] == 0.0
            assert points[0]["attributes"] == [attr("region", "west")]
            if kind != "histogram":
                expected = {"sum": 18, "min": 7, "max": 11, "mean": 9, "count": 2}[operation]
                assert float(points[0].get("asInt", points[0].get("asDouble"))) == expected
            else:
                assert int(points[0]["count"]) == 2 * int(first["count"])
                assert [int(n) for n in points[0]["bucketCounts"]] == [2 * int(n) for n in first["bucketCounts"]]
            if previous is not None:
                assert item == previous
            previous = item


@pytest.mark.parametrize("placement", ["input", "output"])
def test_trace_route_length_bound(tmp_path, placement):
    target = span("probe")
    target["attributes"].append(attr("http.route", "/" + "a" * 1024))
    processor = {"name": "fts", "recipe": [block("traces.name_from_route")]}
    with signal_recipe(tmp_path, "traces", processor, placement) as runner:
        _, result = runner.run("probe", custom_items=[target])
        assert result[0][2]["name"] == "probe"


@pytest.mark.parametrize("step,signal,reason", [
    (block("metrics.rename", mapping={"a": "b", "b": "c"}), "metrics", "reason=chain"),
    (block("logs.drop_matching", condition={"all": []}), "logs", "reason=range"),
    (block("logs.drop_matching", condition={"selector": sel("x"), "op": "regex", "value": "x"}), "logs", "class=invalid_configuration"),
    (block("logs.drop_matching", condition={"selector": sel("x"), "op": "gt", "value": {"type": "uint64", "value": "18446744073709551616"}}), "logs", "reason=range"),
    (block("fields.truncate", target=sel("x"), marker=sel("x"), max_bytes=1), "logs", "reason=range"),
    (block("metrics.aggregate_dimensions", names=["a"], operation="sum", max_exemplars=129), "metrics", "reason=range"),
])
def test_catalog_invalid_configuration(tmp_path, step, signal, reason):
    config = config_file(tmp_path, {"name": "fts", "recipe": [step]}, signal=signal)
    assert reason in rejected_startup(config, tmp_path)


@pytest.mark.parametrize("placement", ["input", "output"])
def test_otel_timestamp_preserves_observed_and_zero_severity(tmp_path, placement):
    from test_fts_policies import PolicyRunner
    processor = {"name": "fts", "context": "otel", "recipe": [
        block("logs.normalize_severity", source=sel("level", "attributes"), destination="otel"),
        block("logs.parse_timestamp", source=sel("time", "attributes"))]}
    with signal_recipe(tmp_path, "logs", processor, placement) as signal_runner:
        runner = PolicyRunner(signal_runner.manager, signal_runner.port)
        payload = runner.payload("clock", "otel-clock")
        records = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        for record in records:
            record["severityNumber"] = 0
            record.pop("severityText")
            record["attributes"] += [attr("level", "notice"), attr("time", "2038-01-19T03:14:09.987654321Z")]
        runner.send(payload)
        result = runner.wait_for_condition(lambda: runner.collect("otel-clock"))
        actual = [r for resource in result for scope in resource["scopeLogs"] for r in scope["logRecords"]]
        assert len(actual) == 3
        for record in actual:
            assert record["timeUnixNano"] == "2147483649987654321"
            assert record["observedTimeUnixNano"] == "2147483648234567890"
            assert record["severityText"] == "INFO" and record["severityNumber"] == 9


@pytest.mark.parametrize("placement", ["input", "output"])
def test_invalid_utf8_rejected_before_truncation(tmp_path, placement):
    step = block("fields.truncate", target=sel("text"), marker=sel("cut"), max_bytes=1)
    with logs(tmp_path, [step], placement) as service:
        result = output(service, [{"text": Raw(b"\xa3ok\xff")}, {"text": "x"}])
        assert result == [{"text": "x"}]
        assert "class=invalid_utf8" in log_text(service, "class=invalid_utf8")


@pytest.mark.parametrize("placement", ["input", "output"])
def test_all_drop_batch_and_following_batch(tmp_path, placement):
    step = block("logs.drop_matching", condition={"selector": sel("drop"), "op": "eq", "value": True})
    with logs(tmp_path, [step], placement) as service:
        send(service, [{"drop": True}] * 3)
        assert output(service, [{"drop": False}]) == [{"drop": False}]
        assert "policy failed" not in log_text(service)


@pytest.mark.parametrize("placement", ["input", "output"])
def test_lua_allocation_failure_class_and_recovery(tmp_path, placement):
    step = block("logs.normalize_severity", source=sel("level"), destination=sel("level"))
    large = "X" * 1100000
    with logs(tmp_path, [step], placement, memory_limit="1M", error_mode="keep") as service:
        result = output(service, [{"level": large}, {"level": "notice"}])
        assert result == [{"level": large}, {"level": "INFO"}]
        assert "class=budget_exceeded" in log_text(service, "class=budget_exceeded")


@pytest.mark.parametrize("placement", ["input", "output"])
def test_exact_scalar_membership_and_any(tmp_path, placement):
    condition = {"any": [
        {"selector": sel("id"), "op": "eq", "value": {"type": "uint64", "value": "18446744073709551615"}},
        {"selector": sel("flag"), "op": "eq", "value": False},
        {"selector": sel("null"), "op": "eq", "value": {"type": "null"}}]}
    inputs = [{"id": 18446744073709551615}, {"id": "18446744073709551615"},
              {"flag": False}, {"flag": 0}, {"null": None}, {}]
    with logs(tmp_path, [block("logs.drop_matching", condition=condition)], placement) as service:
        assert output(service, inputs * 2) == [inputs[1], inputs[3], inputs[5]] * 2


@pytest.mark.parametrize("placement", ["input", "output"])
def test_timestamp_invalid_boundaries(tmp_path, placement):
    texts = ["1970-01-01T00:00:00+01:00", "1968-12-31T23:59:59Z",
             "2024-01-01T00:00:60Z", "2024-01-01T00:00:00.1234567890Z",
             "2024-01-01T00:00:00+24:00", "2107-01-01T00:00:00Z",
             "not-a-date"]
    inputs = [{"time": text} for text in texts] + [{"control": True}]
    with logs(tmp_path, [block("logs.parse_timestamp", source=sel("time"), on_missing="skip")],
              placement, error_mode="keep") as service:
        assert output(service, inputs) == inputs
        assert "class=invalid_timestamp" in log_text(service, "class=invalid_timestamp")


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("failure", ["flags", "layout", "overflow"])
def test_aggregation_failure_rolls_back_family(tmp_path, placement, failure):
    kind = "sum" if failure == "overflow" else "histogram"
    target = metric(kind, "probe")
    point = target[kind]["dataPoints"][0]
    if failure == "overflow":
        point["asInt"] = "9223372036854775807"
    point["attributes"] = [attr("region", "west"), attr("pod", "one")]
    other = copy.deepcopy(point)
    other["attributes"] = [attr("region", "west"), attr("pod", "two")]
    if failure == "flags":
        other["flags"] = 0
    elif failure == "layout":
        other["explicitBounds"] = [1.0, 3.0]
    target[kind]["dataPoints"] = [point, other]
    processor = {"name": "fts", "error_mode": "keep", "recipe": [
        block("metrics.aggregate_dimensions", names=["probe"], keep_attributes=[], operation="sum")]}
    with signal_recipe(tmp_path, "metrics", processor, placement) as runner:
        if failure == "layout":
            # The native OTLP decoder rejects mixed layouts before FTS receives a family.
            with pytest.raises(AssertionError, match="deserialisation error"):
                runner.run("probe", kind, custom_items=[target])
            _, controls = runner.run("control", kind)
            assert controls
            return
        _, result = runner.run("probe", kind, custom_items=[target, metric(kind, "control")])
        actual = next(item for _, _, item in result if item["name"] == "probe")
        assert len(actual[kind]["dataPoints"]) == 2
        for a, b in zip(actual[kind]["dataPoints"], target[kind]["dataPoints"]):
            assert a["attributes"] == b["attributes"]
            if failure == "overflow":
                assert a["asInt"] == b["asInt"]
            else:
                assert a["explicitBounds"] == b["explicitBounds"]
    # stdout is direct, diagnostics are asynchronous; context exit drains the logger.
    assert "recipe step=metrics_aggregate_dimensions" in open(runner.manager.log_file).read()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_trace_truncation_preserves_identity_and_rolls_back(tmp_path, placement):
    from test_fts_policies import attributes
    target = span("probe")
    target["attributes"].append(attr("text", "é🙂z"))
    bad = span("bad")
    bad["attributes"] += [attr("text", "too long"), attr("cut", "existing")]
    processor = {"name": "fts", "error_mode": "keep", "recipe": [
        block("fields.truncate", target=sel("text", "attributes"), max_bytes=3,
              marker=sel("cut", "attributes"))]}
    with signal_recipe(tmp_path, "traces", processor, placement) as runner:
        previous = None
        for _ in range(2):
            _, result = runner.run("probe", custom_items=[target, bad])
            actual = next(item for _, _, item in result if item["name"] == "probe")
            failed = next(item for _, _, item in result if item["name"] == "bad")
            assert attributes(actual["attributes"])["text"] == "é"
            assert attributes(actual["attributes"])["cut"] is True
            assert attributes(failed["attributes"])["text"] == "too long"
            assert attributes(failed["attributes"])["cut"] == "existing"
            for key in ("traceId", "spanId", "parentSpanId", "startTimeUnixNano", "endTimeUnixNano", "events", "links"):
                assert actual[key] == target[key]
            if previous is not None:
                assert actual == previous
            previous = actual


@pytest.mark.parametrize("placement", ["input", "output"])
def test_aggregation_defaults_drop_exemplars_and_dimensions(tmp_path, placement):
    target = metric("gauge", "probe")
    point = target["gauge"]["dataPoints"][0]
    point["exemplars"] = [{"asDouble": 3.0, "timeUnixNano": point["timeUnixNano"],
        "filteredAttributes": [attr("secret", "synthetic")]}]
    other = copy.deepcopy(point)
    other["attributes"] = [attr("region", "west")]
    target["gauge"]["dataPoints"].append(other)
    processor = {"name": "fts", "recipe": [block("metrics.aggregate_dimensions", names=["probe"], operation="sum")]}
    with signal_recipe(tmp_path, "metrics", processor, placement) as runner:
        _, result = runner.run("probe", custom_items=[target])
        points = result[0][2]["gauge"]["dataPoints"]
        assert len(points) == 1 and int(points[0]["asInt"]) == 16
        assert not points[0].get("attributes") and not points[0].get("exemplars")
