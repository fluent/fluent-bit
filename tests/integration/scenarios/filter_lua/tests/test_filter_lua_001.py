"""Keep native LuaJIT behavior intact while adding the browser Lua backend."""

import json
from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("context", ["filter", "processor"])
@pytest.mark.parametrize("mode", [
    "modify3", "modify5", "sparse", "drop", "runtime_error", "syntax_error", "missing_call", "init_error"
])
def test_lua_callbacks(tmp_path, context, mode):
    args = "tag, timestamp, record"
    result = "2, timestamp, record"
    if mode == "modify5":
        args = "tag, timestamp, group, metadata, record"
        result = "2, timestamp, metadata, record"
    code = f"""function enrich({args})
    record.total = 0
    for _, value in ipairs(record.values) do
        record.total = record.total + value
    end
    record.message = record.message .. " café"
    return {result}
end
"""
    if mode == "sparse":
        code = code.replace("return 2,", 'record.values = {[1] = "first", [3] = "third"}\n    return 2,')
    elif mode == "drop":
        code = code.replace("return 2,", "return -1,")
    elif mode == "runtime_error":
        code = code.replace("record.total = 0", 'error("lua-protected-test")')
    elif mode == "syntax_error":
        code = "function !bad syntax"
    elif mode == "init_error":
        code = 'error("lua-initializer-test")'
    lua_filter = {"name": "lua", "call": "missing" if mode == "missing_call" else "enrich",
                  "code": code, "time_as_table": True, "enable_flb_null": True}
    dummy = {"name": "dummy", "tag": "lua.test", "rate": 2,
             "dummy": json.dumps({"message": "lua-test", "values": [1, 2, 3], "optional": None})}
    pipeline = {"inputs": [dummy], "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}]}
    if context == "processor":
        dummy["processors"] = {"logs": [lua_filter]}
    else:
        lua_filter["match"] = "*"
        pipeline["filters"] = [lua_filter]
    config = {"service": {"flush": 0.2, "grace": 1, "log_level": "info", "http_server": True,
                          "http_listen": "127.0.0.1", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
              "pipeline": pipeline}
    config_file = tmp_path / "lua.yaml"
    config_file.write_text(yaml.safe_dump(config, allow_unicode=True), encoding="utf-8")
    service = FluentBitTestService(str(config_file))

    def log_text():
        return Path(service.flb.log_file).read_text(encoding="utf-8")

    def records():
        found = []
        for line in log_text().splitlines():
            if line.startswith("{"):
                found.append(json.loads(line))
        return found

    if mode in ("syntax_error", "missing_call", "init_error"):
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert "error" in log_text().lower()
        return

    try:
        service.start()
        if mode == "drop":
            # Health checks wait for >1s uptime, allowing several input callbacks.
            service.stop()
            assert not records()
        elif mode == "runtime_error":
            service.wait_for_condition(lambda: "lua-protected-test" in log_text(), timeout=20)
            output = service.wait_for_condition(records, timeout=20)
            assert output[0]["message"] == "lua-test"
        else:
            output = service.wait_for_condition(records, timeout=20)
            values = ["first", None, "third"] if mode == "sparse" else [1, 2, 3]
            assert all(record["message"] == "lua-test café" and record["total"] == 6 and
                       record["values"] == values and record["optional"] is None for record in output)
    finally:
        service.stop()
