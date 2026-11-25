"""Compare the IDE's public symbol inventory against a real FTS Lua VM."""

import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from test_fts import log_text, make_service, records


ROOT = Path(__file__).resolve().parents[5]


@pytest.mark.parametrize("signal", ["logs", "metrics", "traces"])
def test_public_api_definitions_match_runtime(tmp_path, signal):
    """Verify each signal VM exposes the declared script functions and methods."""
    output = tmp_path / "fts_api.json"
    subprocess.run([sys.executable, str(ROOT / "tools/fts/export_api_schema.py"),
                    "--output", str(output)], check=True)
    manifest = json.loads(output.read_text())
    functions = [function["name"] for function in manifest["modules"]["fb"]["functions"]
                 if signal in function["signals"] and "script" in function["modes"]]
    methods = [method["name"] for method in manifest["types"]["FtsValue"]["methods"]]
    code = '''
local fb = require("fluentbit")
local expected = {}
for _, name in ipairs(FUNCTIONS) do
    assert(type(fb[name]) == "function", "missing function: " .. name)
    expected[name] = true
end
for name, value in pairs(fb) do
    if name:sub(1, 1) ~= "_" and type(value) == "function" then
        assert(expected[name], "undocumented public function: " .. name)
    end
end
assert(fb.KEEP == "keep" and fb.DROP == "drop")
assert(fb.MODIFY == nil and fb.ERROR == nil)
assert(fb.hash64_algorithm == "xxh3-64-v1-seed0")
local map = fb.map()
for _, name in ipairs(METHODS) do
    assert(type(map[name]) == "function", "missing value method: " .. name)
end
assert(map.has == nil and map.delete == nil)
assert(fb.parse_json("null"):type() == "null")
assert(not pcall(fb.parse_json, "invalid json"))
assert(fb.int64("-9223372036854775808"):value() == "-9223372036854775808")
assert(fb.bytes("ff"):value() == "ff")
function process_log(log)
    assert(not fb.is_otel(log))
    assert(log.attributes == nil and log.resource == nil)
    assert(log.severity_number == nil and log.severity_text == nil)
    log.body:set("message", "api-verified")
    return fb.KEEP
end
'''.replace("FUNCTIONS", "{" + ",".join(json.dumps(name) for name in functions) + "}")
    code = code.replace("METHODS", "{" + ",".join(json.dumps(name) for name in methods) + "}")
    service = make_service(tmp_path, code)
    if signal != "logs":
        config = tmp_path / "typed.yaml"
        document = yaml.safe_load(config.read_text())
        processor = document["pipeline"]["inputs"][0]["processors"]["logs"]
        document["pipeline"]["inputs"] = [{"name": "opentelemetry",
            "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "processors": {signal: processor}}]
        config.write_text(yaml.safe_dump(document))
    try:
        service.start()
        if signal == "logs":
            result = service.wait_for_condition(lambda: records(service), timeout=30)
            assert all(record["message"] == "api-verified" for record in result)
        assert "edits rolled back" not in log_text(service)
    finally:
        service.stop()


def test_metric_window_methods_in_pack_binding(tmp_path):
    """Construct a window in an author factory and verify its declared methods."""
    if not (ROOT / "plugins/processor_fts/fts_recipe.lua").exists():
        pytest.skip("metric-window pack binding requires the separate FTS recipe implementation")
    output = tmp_path / "fts_api.json"
    subprocess.run([sys.executable, str(ROOT / "tools/fts/export_api_schema.py"),
                    "--output", str(output)], check=True)
    manifest = json.loads(output.read_text())
    methods = [method["name"] for method in manifest["types"]["FtsMetricWindow"]["methods"]]
    assert set(methods) == {"get", "hold"}
    (tmp_path / "check.lua").write_text('''return function(parameters)
    assert(type(fb.metric_window) == "function", "metric-window pack binding unavailable")
    local window = fb.metric_window{interval_ms=1000}
    for _, name in ipairs(METHODS) do
        assert(type(window[name]) == "function", "missing window method: " .. name)
    end
    return function(metric) end
end
'''.replace("METHODS", "{" + ",".join(json.dumps(name) for name in methods) + "}"))
    (tmp_path / "pack.json").write_text(json.dumps({"pack_version": 1,
        "fts_api_version": 1, "id": "org.fluentbit.api-check", "version": "1.0.0",
        "blocks": [{"name": "window", "signals": ["metrics"],
                    "source": "check.lua", "parameters": {}}]}))
    service = make_service(tmp_path, "unused")
    config = tmp_path / "typed.yaml"
    document = yaml.safe_load(config.read_text())
    processor = {"name": "fts", "packages_dir": str(tmp_path), "packs": ["pack.json"],
        "state_commit": "local", "recipe": [{"id": "check", "use": "org.fluentbit.api-check/window"}]}
    document["pipeline"]["inputs"] = [{"name": "opentelemetry",
        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "processors": {"metrics": [processor]}}]
    config.write_text(yaml.safe_dump(document))
    try:
        # Initialization runs the author factory and its native window binding.
        service.start()
    finally:
        service.stop()
