"""Exercise the bundled LuaJIT VM through Lua filters and input processors."""

import json
from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


SCRIPT = """
local default_jit = jit.status()
local function calculate()
    local total = 0
    for i = 1, 10000 do
        total = total + string.byte(string.sub("abc", 2, 2))
    end
    return total
end

function enrich(tag, timestamp, record)
    record.total = calculate()
    record.jit_enabled = default_jit
    record.trace_compiled = require("jit.util").traceinfo(1) ~= nil
    record.unpacked = table.concat({table.unpack({"a", "b", "c"})}, "")
    record.message = record.message .. " café"
    local ok, err = pcall(function() error("protected-error") end)
    record.error_caught = not ok and string.find(err, "protected-error", 1, true) ~= nil
    return 2, timestamp, record
end
"""


@pytest.mark.parametrize("context", ["filter", "processor"])
@pytest.mark.parametrize("mode", ["hot_loop", "runtime_error", "syntax_error", "init_error"])
def test_luajit_callbacks(tmp_path, context, mode):
    code = SCRIPT
    if mode == "runtime_error":
        code = code.replace("record.total = calculate()", 'error("callback-error")')
    elif mode == "syntax_error":
        code = "function !bad syntax"
    elif mode == "init_error":
        code = 'error("initializer-error")'

    lua = {"name": "lua", "call": "enrich", "code": code, "protected_mode": True}
    dummy = {"name": "dummy", "tag": "lua.test", "rate": 2,
             "dummy": json.dumps({"message": "lua-test"})}
    pipeline = {"inputs": [dummy],
                "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}]}
    if context == "processor":
        dummy["processors"] = {"logs": [lua]}
    else:
        lua["match"] = "*"
        pipeline["filters"] = [lua]

    config = {"service": {"flush": 0.2, "grace": 1, "log_level": "info",
                          "http_server": True, "http_listen": "127.0.0.1",
                          "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
              "pipeline": pipeline}
    config_file = tmp_path / "lua.yaml"
    config_file.write_text(yaml.safe_dump(config, allow_unicode=True), encoding="utf-8")
    service = FluentBitTestService(str(config_file))

    def log_text():
        return Path(service.flb.log_file).read_text(encoding="utf-8")

    def records():
        output = [json.loads(line) for line in log_text().splitlines() if line.startswith("{")]
        for record in output:
            record.pop("date", None)
        return output

    if mode in ("syntax_error", "init_error"):
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert "error" in log_text().lower()
        return

    try:
        service.start()
        output = service.wait_for_condition(records, timeout=30)
        if mode == "runtime_error":
            assert "callback-error" in log_text()
            assert all(record == {"message": "lua-test"} for record in output)
        else:
            assert all(record == {"message": "lua-test café", "total": 980000,
                                  "jit_enabled": True, "trace_compiled": True,
                                  "unpacked": "abc", "error_caught": True}
                       for record in output)
    finally:
        service.stop()
