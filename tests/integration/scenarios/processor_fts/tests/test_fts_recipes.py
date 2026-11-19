"""Native recipe configuration and signal-adapter checks."""
import copy
import os
import subprocess
from pathlib import Path

import requests
import pytest
import yaml

from test_fts_records import send, rows
from utils.test_service import FluentBitTestService

from fts_test_utils import read_log


def redact(**params):
    return {"id": "privacy", "use": "shared.redact_keys", "with": {
        "targets": [{"root": "body", "path": []}], "keys": ["password"], **params}}


def config_file(tmp_path, processor, placement="input", signal="logs"):
    source = {"name": "forward", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}
    output = {"name": "stdout", "match": "*", "format": "json_lines"}
    (source if placement == "input" else output)["processors"] = {signal: [processor]}
    config = tmp_path / "recipe.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    return config


@pytest.mark.parametrize("placement", ["input", "output"])
def test_recipe_redacts_native_log(tmp_path, placement):
    config = config_file(tmp_path, {"name": "fts", "recipe": [redact()]}, placement)
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [{"password": "synthetic-private", "control": "preserved"}] * 2)
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert len(result) == 2
        assert result[0] == result[1]
        assert result[0]["password"] == "[REDACTED]"
        assert result[0]["control"] == "preserved"
    finally:
        service.stop()


def rejected_startup(config, tmp_path):
    # No network listeners are needed to exercise processor initialization.
    data = yaml.safe_load(config.read_text())
    source = data["pipeline"]["inputs"][0]
    source["name"] = "dummy"
    source.pop("port", None)
    data["service"]["http_server"] = False
    data["service"].pop("http_port")
    config.write_text(yaml.safe_dump(data))
    binary = Path(os.environ.get("FLUENT_BIT_BINARY", str(
        Path(__file__).resolve().parents[5] / "build/bin/fluent-bit")))
    command = [str(binary), "-c", str(config)]
    if os.environ.get("VALGRIND") == "1":
        command = ["valgrind", "--error-exitcode=99", "--leak-check=full",
                   "--errors-for-leak-kinds=definite,indirect,possible",
                   f"--log-file={tmp_path / 'valgrind-startup.log'}", *command]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode in (1, 255), result.stdout + result.stderr
    if os.environ.get("VALGRIND") == "1":
        assert "ERROR SUMMARY: 0 errors" in (tmp_path / "valgrind-startup.log").read_text()
    return result.stdout + result.stderr


@pytest.mark.parametrize("change,expected", [
    ({"code": "function process(log) end"}, "exactly one of script, code or recipe"),
    ({"script": "/does/not/exist"}, "exactly one of script, code or recipe"),
    ({"recipe": [{"id": "x", "use": "unknown.block"}]}, "param=use reason=unknown"),
    ({"recipe": [redact(unknown_parameter=True)]}, "param=<unknown> reason=unknown"),
    ({"error_mode": "keep"}, "param=error_mode reason=privacy_requires_drop"),
    ({"recipe_version": 2}, "recipe_version=1"),
    ({"recipe_version": "1.1"}, "recipe_version=1"),
    ({"recipe_version": "1junk"}, "recipe_version=1"),
    ({"recipe": []}, "class=invalid_configuration"),
    ({"recipe": [redact(), redact()]}, "param=id reason=duplicate"),
    ({"context": "otel", "recipe": [redact(targets=[{"root": "metadata", "path": []}])]},
     "param=targets reason=context"),
    ({"context": "native", "recipe": [redact(targets=[{"root": "metadata", "path": ["otlp"]}])]},
     "param=targets reason=context"),
])
def test_recipe_rejects_invalid_configuration(tmp_path, change, expected):
    processor = {"name": "fts", "recipe": [redact()], **change}
    config = config_file(tmp_path, processor)
    diagnostics = rejected_startup(config, tmp_path)
    assert expected in diagnostics
    assert "edits rolled back" not in diagnostics


def test_recipe_rejects_scale_before_merge(tmp_path):
    processor = {"name": "fts", "recipe": [
        {"id": "scale", "use": "metrics.scale", "with": {
            "names": ["duration"], "input_unit": "ms", "output_unit": "s", "factor": 0.001}},
        {"id": "merge", "use": "metrics.merge_histogram_buckets", "with": {
            "names": ["duration"], "bounds": [0.009]}}]}
    config = config_file(tmp_path, processor, signal="metrics")
    assert "merge_histogram_buckets must precede metrics.scale" in rejected_startup(config, tmp_path)


@pytest.mark.parametrize("placement", ["input", "output"])
def test_recipe_error_drops_mutated_item_and_sanitizes_diagnostics(tmp_path, placement):
    step = redact(targets=[{"root": "body", "path": []},
                           {"root": "body", "path": ["nested"]}])
    config = config_file(tmp_path, {"name": "fts", "recipe": [step]}, placement)
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [{"password": "synthetic-private", "nested": "synthetic-error-secret"},
                       {"password": "synthetic-private", "nested": {"deep": {}}, "control": "ok"}])
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert len(result) == 1
        assert result[0]["control"] == "ok"
        assert result[0]["password"] == "[REDACTED]"
        log = read_log(service.flb.log_file, "step=privacy class=wrong_type")
        assert "step=privacy class=wrong_type" in log
        assert "synthetic-error-secret" not in log
        assert "synthetic-private" not in log
        def counted():
            response = requests.get(
                f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus",
                timeout=10)
            response.raise_for_status()
            samples = [line for line in response.text.splitlines()
                       if line.startswith("fluentbit_fts_recipe_callbacks_total{")]
            return (any('outcome="error"' in line and float(line.split()[1]) == 1 for line in samples)
                    and any('outcome="keep"' in line and float(line.split()[1]) == 1 for line in samples))
        assert service.wait_for_condition(counted, timeout=30)
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("signal", ["metrics", "traces"])
def test_recipe_signal_adapters(tmp_path, placement, signal):
    from test_fts_signals import SignalRunner, metric
    from test_fts_policies import attributes
    from utils.fluent_bit_manager import FluentBitManager
    from utils.network import find_available_port

    port = find_available_port()
    source = {"name": "opentelemetry", "port": port}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    if signal == "metrics":
        steps = [
            {"id": "buckets", "use": "metrics.merge_histogram_buckets", "with": {
                "names": ["probe"], "bounds": [9.0]}},
            {"id": "seconds", "use": "metrics.scale", "with": {
                "names": ["probe"], "input_unit": "ms", "factor": 0.001,
                "output_unit": "s", "numeric_policy": "allow_double"}}]
    else:
        steps = [redact(targets=[{"root": "attributes", "path": []}], keys=["secret"])]
    (source if placement == "input" else output)["processors"] = {
        signal: [{"name": "fts", "recipe": steps}]}
    config = tmp_path / "signals.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    manager = FluentBitManager(str(config))
    try:
        manager.start()
        runner = SignalRunner(manager, port, signal)
        if signal == "metrics":
            point = metric("histogram", "probe")["histogram"]["dataPoints"][0]
            point["explicitBounds"] = [9.0, 10.0]
            _, result = runner.run("probe", "histogram", points=[point])
            target = next(item for _, _, item in result if item["name"] == "probe")
            assert target["unit"] == "s"
            actual = target["histogram"]["dataPoints"][0]
            assert actual["explicitBounds"] == [9.0 * 0.001]
            assert [int(n) for n in actual["bucketCounts"]] == [1, 2]
            control = next(item for _, _, item in result if item["name"] == "control")
            assert control["histogram"]["dataPoints"][0]["explicitBounds"] == [1.0, 2.0]
            _, repeated = runner.run("probe", "histogram", points=[point])
            assert next(item for _, _, item in repeated if item["name"] == "probe") == target
        else:
            original, result = runner.run("probe")
            target = next(item for _, _, item in result if item["name"] == "probe")
            assert attributes(target["attributes"])["secret"] == "[REDACTED]"
            for key in ("traceId", "spanId", "parentSpanId", "startTimeUnixNano", "endTimeUnixNano"):
                assert target[key] == original[key]
            _, repeated = runner.run("probe")
            assert next(item for _, _, item in repeated if item["name"] == "probe") == target
    finally:
        manager.stop()


@pytest.mark.parametrize("factor,reason", [("0x10", "type"), (" 1e3 ", "type"),
                                           ("NaN", "range"), ("Infinity", "range")])
def test_recipe_numeric_parameters_are_decimal(tmp_path, factor, reason):
    step = {"id": "scale", "use": "metrics.scale", "with": {
        "names": ["probe"], "input_unit": "ms", "output_unit": "s", "factor": factor}}
    config = config_file(tmp_path, {"name": "fts", "recipe": [step]}, signal="metrics")
    assert f"param=factor reason={reason}" in rejected_startup(config, tmp_path)


def test_recipe_counters_distinguish_owners(tmp_path):
    processor = {"name": "fts", "recipe": [redact()]}
    config = tmp_path / "owners.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [
            {"name": "dummy", "alias": name, "samples": 1,
             "processors": {"logs": [copy.deepcopy(processor)]}} for name in ("left", "right")],
            "outputs": [{"name": "null", "match": "*"}]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        def distinct():
            text = requests.get(
                f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus",
                timeout=10).text
            samples = [line for line in text.splitlines()
                       if line.startswith("fluentbit_fts_recipe_callbacks_total{")]
            return (len(samples) == 2 and all('scope="input"' in line for line in samples)
                    and any('name="left"' in line for line in samples)
                    and any('name="right"' in line for line in samples))
        assert service.wait_for_condition(distinct, timeout=30)
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_recipe_context_mismatch_has_own_class(tmp_path, placement):
    config = config_file(tmp_path, {"name": "fts", "context": "otel", "recipe": [redact()]}, placement)
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, {"password": "synthetic-private"})
        assert service.wait_for_condition(lambda: "class=invalid_context" in
                                          Path(service.flb.log_file).read_text(), timeout=30)
        assert rows(service) == []
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("fault,expected", [("unit", "wrong_type"),
                                            ("conversion", "unsupported_conversion")])
def test_recipe_reports_metric_error_class(tmp_path, placement, fault, expected):
    from test_fts_signals import SignalRunner
    from utils.fluent_bit_manager import FluentBitManager
    from utils.network import find_available_port

    port = find_available_port()
    source = {"name": "opentelemetry", "port": port}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    step = {"id": "scale", "use": "metrics.scale", "with": {
        "names": ["probe"], "input_unit": "synthetic-unit-secret" if fault == "unit" else "ms",
        "output_unit": "s", "factor": 0.5}}
    (source if placement == "input" else output)["processors"] = {
        "metrics": [{"name": "fts", "error_mode": "keep", "recipe": [step]}]}
    config = tmp_path / "error-class.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    manager = FluentBitManager(str(config))
    try:
        manager.start()
        runner = SignalRunner(manager, port, "metrics")
        _, result = runner.run("probe")
        target = next(item for _, _, item in result if item["name"] == "probe")
        assert target["unit"] == "ms"
        assert int(target["gauge"]["dataPoints"][0]["asInt"]) == 8
        diagnostics = read_log(manager.log_file, f"step=scale class={expected}")
        assert f"step=scale class={expected}" in diagnostics
        assert "synthetic-unit-secret" not in diagnostics
    finally:
        manager.stop()


def test_recipe_budget_error_is_not_swallowed_by_wrapper(tmp_path):
    config = config_file(tmp_path, {"name": "fts", "instruction_limit": 40000,
                                    "recipe": [redact()]})
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [{"items": [{"password": "synthetic"} for _ in range(50000)]},
                       {"password": "synthetic", "control": "ok"}])
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert len(result) == 1 and result[0]["control"] == "ok"
        assert result[0]["password"] == "[REDACTED]"
        assert "class=budget_exceeded" in read_log(service.flb.log_file, "class=budget_exceeded")
    finally:
        service.stop()


def test_recipe_otel_attributes_preserve_reserved_metadata(tmp_path):
    from test_fts_policies import PolicyRunner, attributes
    from utils.fluent_bit_manager import FluentBitManager
    from utils.network import find_available_port

    port = find_available_port()
    step = redact(targets=[{"root": "attributes", "path": []}], keys=["severity_text"])
    config = tmp_path / "otel-privacy.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [{"name": "opentelemetry", "port": port,
            "processors": {"logs": [{"name": "fts", "context": "otel", "recipe": [step]}]}}],
            "outputs": [{"name": "stdout", "match": "*", "format": "otlp_json"}]}}))
    manager = FluentBitManager(str(config))
    try:
        manager.start()
        runner = PolicyRunner(manager, port)
        payload = runner.payload("unused", "reserved-fields")
        for record in payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]:
            record["severityText"] = "INFO"
            record["attributes"].append({"key": "severity_text", "value": {"stringValue": "synthetic"}})
        runner.send(payload)
        result = runner.wait_for_condition(lambda: runner.collect("reserved-fields"))
        records = [r for resource in result for scope in resource["scopeLogs"] for r in scope["logRecords"]]
        assert len(records) == 3
        for record in records:
            assert record["severityText"] == "INFO"
            assert attributes(record["attributes"])["severity_text"] == "[REDACTED]"
    finally:
        manager.stop()
