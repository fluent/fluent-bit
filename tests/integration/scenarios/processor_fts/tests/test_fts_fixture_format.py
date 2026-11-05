"""Reject invalid fixture contracts before any native process is started."""
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[5]
spec = importlib.util.spec_from_file_location("fts_fixture", ROOT / "tools/fts/fts_fixture.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@pytest.mark.parametrize("value", [True, 1.0, b"1", "1", None, [], {}])
def test_fixture_equality_preserves_types(value):
    with pytest.raises(AssertionError):
        runner.equal(value, 1)


@pytest.mark.parametrize("field,value,reason", [
    ("fixture_version", "true", "fixture_version must be 1"),
    ("fixture_version", "1\nfixture_version: 1", "keys must be unique"),
    ("body", "{value: !uint64 -1}", "integer tag is out of range"),
    ("body", "{value: !int64 9223372036854775808}", "integer tag is out of range"),
    ("body", "{value: !double nan}", "nonfinite fixture number"),
    ("body", "{value: &x [*x]}", "aliases are not supported"),
    ("body", "{value: !!python/object/apply:os.system ['exit 1']}", "could not determine a constructor"),
])
def test_invalid_fixture_is_rejected(tmp_path, field, value, reason):
    payload = ("fixture_version: 1\nsignal: logs\nprocessor: {name: fts}\ncases:\n"
               "- name: one\n  input: [{body: {value: 1}}]\n  expected: {records: []}\n")
    payload = payload.replace("fixture_version: 1", "fixture_version: " + value, 1) if field == "fixture_version" else payload.replace("{value: 1}", value)
    path = tmp_path / "bad.yaml"
    path.write_text(payload)
    with pytest.raises((ValueError, runner.yaml.YAMLError), match=reason):
        runner.load_fixture(path)


def test_forward_capture_drains_queued_connections_on_close():
    import socket
    capture = runner.Capture("logs")
    frame = runner.msgpack.packb(["fixture", [[1700000000, {"value": 1}]]], use_bin_type=True)
    try:
        # Queue several connections before requesting close, as multiple native
        # output workers can finish sending before the capture accepts them all.
        for _ in range(6):
            with socket.create_connection(("127.0.0.1", capture.port), timeout=2) as connection:
                connection.sendall(frame)
        capture.close()
        assert len(capture.messages) == 6
    finally:
        capture.close()


@pytest.mark.parametrize("environment", [
    {"LD_PRELOAD": "library.so"}, {"FTS_FIXTURE_KEY": 7},
    {"FTS_FIXTURE_KEY": "x" * 4097},
])
def test_fixture_environment_is_bounded_and_test_scoped(tmp_path, environment):
    import yaml
    fixture = {"fixture_version": 1, "signal": "logs", "processor": {"name": "fts"},
        "environment": environment, "cases": [{"name": "x", "input": [],
        "expected": {"records": []}}]}
    path = tmp_path / "environment.yaml"
    path.write_text(yaml.safe_dump(fixture))
    with pytest.raises(ValueError):
        runner.load_fixture(path)


@pytest.mark.parametrize("field,value,reason", [
    ("body", "string", "require a map body"),
    ("timestamp", {"sec": 1, "nsec": 1000000000}, "timestamp requires"),
    ("metadata", [], "invalid log metadata"),
    ("tag", 1, "invalid log metadata or tag"),
])
@pytest.mark.parametrize("side", ["input", "expected"])
def test_forward_shape_is_validated_before_execution(tmp_path, field, value, reason, side):
    record = {"body": {"value": 1}, field: value}
    fixture = {"fixture_version": 1, "signal": "logs", "processor": {"name": "fts"},
        "cases": [{"name": "one", "input": [record] if side == "input" else [],
                   "expected": {"records": [record] if side == "expected" else []}}]}
    path = tmp_path / "bad.yaml"
    path.write_text(runner.yaml.safe_dump(fixture))
    with pytest.raises(ValueError, match=reason):
        runner.load_fixture(path)


def test_fixture_capture_closed_on_configuration_failure(monkeypatch, tmp_path):
    captures = []
    original = runner.Capture
    def capture(*args):
        item = original(*args)
        captures.append(item)
        return item
    monkeypatch.setattr(runner, "Capture", capture)
    with pytest.raises(ValueError):
        runner.run_case({"signal": "logs", "processor": {"name": "fts", "packs": []}},
            {}, tmp_path / "fixture.yaml", Path("unused"))
    assert len(captures) == 1
    assert not captures[0].thread.is_alive()


def test_fixture_metrics_ignore_auxiliary_recipe_stages(tmp_path):
    import os
    fixture = {"fixture_version": 1, "signal": "logs", "processor": {"name": "fts", "recipe": [{
        "id": "identity", "use": "logs.drop_matching", "with": {"condition": {
            "selector": {"root": "body", "path": ["missing"]}, "op": "eq", "value": 1}}}]},
        "cases": [{"name": "one", "input": [{"body": {"control": 1}}],
            "expected": {"records": [{"body": {"control": 1}}], "outcomes": {"kept": 1, "dropped": 0, "errors": 0}}}]}
    runner.run_case(fixture, fixture["cases"][0], tmp_path / "fixture.yaml",
        Path(os.environ.get("FLUENT_BIT_BINARY", str(ROOT / "build/bin/fluent-bit"))),
        os.environ.get("VALGRIND") == "1", before_processors=[fixture["processor"]],
        after_processors=[fixture["processor"]])



def test_protobuf_comparison_rejects_unknown_wire_fields():
    actual = runner.otlp_message("logs")
    actual.ParseFromString(bytes.fromhex("c03e01"))  # unknown field 1000, varint 1
    with pytest.raises(AssertionError, match="wire fields differ"):
        runner.equal_otlp(actual, runner.otlp_message("logs"))



def test_fixture_retries_listener_race_before_sending_records(monkeypatch, tmp_path, capsys):
    import os
    import socket
    original = runner.port_pair
    allocations = []
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        def ports():
            pair = original()
            allocations.append(pair)
            return (occupied.getsockname()[1], pair[1]) if len(allocations) == 1 else pair
        monkeypatch.setattr(runner, "port_pair", ports)
        fixture = {"signal": "logs", "processor": {"name": "fts", "recipe": [{
            "id": "identity", "use": "logs.drop_matching", "with": {"condition": {
                "selector": {"root": "body", "path": ["missing"]}, "op": "eq", "value": 1}}}]}}
        case = {"input": [{"body": {"control": 1}}], "expected": {
            "records": [{"body": {"control": 1}}], "outcomes": {"kept": 1, "dropped": 0, "errors": 0}}}
        runner.run_case(fixture, case, tmp_path / "fixture.yaml",
            Path(os.environ.get("FLUENT_BIT_BINARY", str(ROOT / "build/bin/fluent-bit"))),
            os.environ.get("VALGRIND") == "1")
    assert len(allocations) == 2
    assert "RETRY listener bind before fixture ingestion" in capsys.readouterr().err
