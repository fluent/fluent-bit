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
