"""Logical numeric types and side-effect-free recipe preflight."""
import copy
import json
import struct

import pytest
import yaml

from test_fts_recipe_catalog import block, sel, logs, output
from test_fts_records import Raw, rows
from test_fts_recipes import config_file
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("placement", ["input", "output"])
def test_integer_rule_accepts_dummy_status(tmp_path, placement):
    processor = {"name": "fts", "recipe": [block("logs.validate_fields", rules=[
        {"selector": sel("status"), "type": "integer", "enum": [200]}])]}
    config = config_file(tmp_path, processor, placement)
    data = yaml.safe_load(config.read_text())
    source = data["pipeline"]["inputs"][0]
    source.update(name="dummy", dummy=json.dumps({"status": 200, "id": "a"}), samples=1)
    source.pop("port")
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert len(result) == 1 and result[0]["status"] == 200 and result[0]["id"] == "a"
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_integer_rule_accepts_parsed_json_and_plain_literals(tmp_path, placement):
    steps = [block("logs.parse_json", source=sel("message"), destination=sel("parsed")),
        block("logs.validate_fields", rules=[
            {"selector": {"root": "body", "path": ["parsed", "status"]}, "type": "integer", "enum": [200]}]),
        block("fields.edit", operations=[
            {"op": "set", "target": sel("positive"), "value": 18446744073709551615},
            {"op": "set", "target": sel("negative"), "value": -9223372036854775808},
            {"op": "set", "target": sel("fraction"), "value": 1.5}])]
    with logs(tmp_path, steps, placement) as service:
        result = output(service, [{"message": '{"status":200}'}] * 2)
        assert result[0] == result[1]
        assert result[0]["positive"] == 18446744073709551615
        assert result[0]["negative"] == -9223372036854775808
        assert result[0]["fraction"] == 1.5


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("value,matched,control", [
    (200, 200, 201),
    ({"type": "int64", "value": "9223372036854775807"}, 9223372036854775807, 9223372036854775808),
    (-7, Raw(b"\xd3" + struct.pack(">q", -7)), Raw(b"\xd3" + struct.pack(">q", -8))),
    (1.0, 1, 2),
    (1, Raw(b"\xcb" + struct.pack(">d", 1.0)), Raw(b"\xcb" + struct.pack(">d", 1.5))),
    (18446744073709551615, 18446744073709551615, Raw(b"\xcb" + struct.pack(">d", 18446744073709551616.0))),
])
def test_numeric_equality_transport_independent(tmp_path, placement, value, matched, control):
    condition = {"selector": sel("status"), "op": "eq", "value": value}
    with logs(tmp_path, [block("logs.drop_matching", condition=condition)], placement) as service:
        result = output(service, [{"status": matched, "id": "drop"}, {"status": control, "id": "keep"}])
        assert [row["id"] for row in result] == ["keep"]


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("operator,value,matched,control", [
    ("gt", 9223372036854775807, 9223372036854775808, 9223372036854775807),
    ("lt", -1, Raw(b"\xd3" + struct.pack(">q", -9223372036854775808)), 0),
    ("gte", {"type": "double", "value": 9223372036854775808.0}, 9223372036854775808, 9223372036854775807),
    ("lte", -2.5, Raw(b"\xd3" + struct.pack(">q", -3)), Raw(b"\xd3" + struct.pack(">q", -2))),
    ("lt", 18446744073709551615, Raw(b"\xcb" + struct.pack(">d", 9223372036854775808.0)), 18446744073709551615),
])
def test_numeric_ordering_is_exact(tmp_path, placement, operator, value, matched, control):
    condition = {"selector": sel("value"), "op": operator, "value": value}
    with logs(tmp_path, [block("logs.drop_matching", condition=condition)], placement) as service:
        result = output(service, [{"value": matched, "id": "drop"}, {"value": control, "id": "keep"}])
        assert [row["id"] for row in result] == ["keep"]


@pytest.mark.parametrize("operator", ["in", "not_in", "neq"])
def test_numeric_membership_and_negative_operators(tmp_path, operator):
    condition = {"selector": sel("status"), "op": operator}
    if operator == "neq":
        condition["value"] = {"type": "int64", "value": 200}
    else:
        condition["values"] = [{"type": "int64", "value": 200}, 201.0]
    values = [{"status": 200}, {"status": 202}, {"status": "200"}, {}]
    expected = values[1:] if operator == "in" else [values[0], *values[2:]]
    with logs(tmp_path, [block("logs.drop_matching", condition=condition)]) as service:
        assert output(service, values) == expected


def dry_run(config, tmp_path):
    import os
    import subprocess
    from pathlib import Path
    binary = Path(os.environ.get("FLUENT_BIT_BINARY", str(Path(__file__).resolve().parents[5] / "build/bin/fluent-bit")))
    command = [str(binary), "--dry-run", "-c", str(config)]
    memory_log = tmp_path / "preflight-valgrind.log"
    if os.environ.get("VALGRIND") == "1":
        command = ["valgrind", "--error-exitcode=99", "--leak-check=full",
                   "--errors-for-leak-kinds=definite,indirect,possible", f"--log-file={memory_log}", *command]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode in (0, 1, 255), result.stdout + result.stderr
    if os.environ.get("VALGRIND") == "1":
        assert "ERROR SUMMARY: 0 errors" in memory_log.read_text()
    return result.returncode, result.stdout + result.stderr


def preflight_config(tmp_path, processor, signal, placement, port):
    config = config_file(tmp_path, processor, placement, signal)
    data = yaml.safe_load(config.read_text())
    data["service"] = {"flush": 1, "grace": 1}
    data["pipeline"]["inputs"][0]["port"] = port
    config.write_text(yaml.safe_dump(data))
    return config


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("signal,step", [
    ("logs", block("logs.validate_fields", rules=[{"selector": sel("status"), "type": "integer"}])),
    ("metrics", block("metrics.scale", names=["duration"], input_unit="ms", output_unit="s", factor=0.001)),
    ("traces", block("traces.name_from_route")),
])
def test_preflight_validates_without_starting_listener(tmp_path, placement, signal, step):
    import socket
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        config = preflight_config(tmp_path, {"name": "fts", "recipe": [step]}, signal, placement, occupied.getsockname()[1])
        status, text = dry_run(config, tmp_path)
    assert status == 0, text
    assert "configuration test is successful" in text
    assert "[input:forward:" not in text


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("change,reason", [
    ({"recipe_version": "2"}, "recipe_version=1"),
    ({"recipe": [block("unknown.block")]}, "param=use reason=unknown"),
    ({"recipe": [block("logs.parse_json", source=sel("message"))]}, "param=destination reason=missing"),
    ({"recipe": [block("shared.redact_keys", targets=[{"root": "body", "path": []}], keys=["password"])], "error_mode": "keep"}, "privacy_requires_drop"),
    ({"recipe": [block("fields.truncate", target=sel("x"), marker=sel("cut"), max_bytes=-1)]}, "param=max_bytes reason=range"),
    ({"code": "function process(item) end"}, "exactly one of script, code or recipe"),
    ({"unknown_property": ["typed", "value"]}, "unknown configuration property"),
])
def test_preflight_rejects_invalid_recipes(tmp_path, placement, change, reason):
    processor = {"name": "fts", "recipe": [block("logs.parse_timestamp", source=sel("time"))], **change}
    config = preflight_config(tmp_path, processor, "logs", placement, 24567)
    status, text = dry_run(config, tmp_path)
    assert status != 0 and reason in text
    assert "configuration test is successful" not in text


@pytest.mark.parametrize("code,valid", [
    ("function process(item) end", True),
    ("function !invalid", False),
    ("function another(item) end", False),
    ("while true do end", False),
])
def test_preflight_legacy_script_compile_and_budget(tmp_path, code, valid):
    config = preflight_config(tmp_path, {"name": "fts", "code": code}, "logs", "input", 24567)
    status, text = dry_run(config, tmp_path)
    assert (status == 0) == valid, text


@pytest.mark.parametrize("placement", ["input", "output"])
def test_recipe_reload_reuses_configuration_and_rejects_invalid_replacement(tmp_path, placement):
    from test_fts_recipe_catalog import send
    from test_fts_records import log_text
    processor = {"name": "fts", "recipe": [block("fields.edit", operations=[
        {"op": "set", "target": sel("version"), "value": "before"}])]}
    config = config_file(tmp_path, processor, placement)
    data = yaml.safe_load(config.read_text())
    data["service"]["hot_reload"] = True
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        assert output(service, [{"id": "first"}])[0]["version"] == "before"
        owner = data["pipeline"]["inputs" if placement == "input" else "outputs"][0]
        owner["processors"]["logs"][0]["recipe"][0]["with"]["operations"][0]["value"] = "after"
        config.write_text(yaml.safe_dump(data))
        service.flb.trigger_http_reload()
        service.flb.wait_for_hot_reload_count(1, timeout=30)
        send(service, [{"id": "second"}])
        second = service.wait_for_condition(lambda: [r for r in rows(service) if r.get("id") == "second"], timeout=30)
        assert second[0]["version"] == "after"
        owner["processors"]["logs"][0]["recipe"] = [block("unknown.block")]
        config.write_text(yaml.safe_dump(data))
        service.flb.trigger_http_reload()
        service.wait_for_condition(lambda: "processor configuration preflight failed" in log_text(service), timeout=30)
        send(service, [{"id": "third"}])
        third = service.wait_for_condition(lambda: [r for r in rows(service) if r.get("id") == "third"], timeout=30)
        assert third[0]["version"] == "after"
        assert service.flb.get_reload_status()["hot_reload_count"] == 1
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("exists,active", [(True, True), (False, True), (False, False)])
def test_filter_processor_preflight_checks_lua_source(tmp_path, placement, exists, active):
    script = tmp_path / "filter.lua"
    if exists:
        script.write_text("function process(tag, timestamp, record) return 0, timestamp, record end")
    proc = {"name": "lua", "script": str(script), "call": "process", "active": active}
    status, text = dry_run(config_file(tmp_path, proc, placement), tmp_path)
    assert (status == 0) == (exists or not active), text
