"""Failed Lua initialization releases the VM and any initialized input."""

from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError


@pytest.mark.parametrize("context", ["filter", "processor"])
@pytest.mark.parametrize("code, call, diagnostic", [
    ("function !bad syntax", "enrich", "error loading buffer"),
    ("function enrich(tag, timestamp, record) return 0, timestamp, record end",
     "missing", "function missing is not found"),
    ('error("startup-cleanup-test")', "enrich", "invalid lua content"),
])
def test_lua_startup_cleanup(tmp_path, context, code, call, diagnostic):
    lua_filter = {"name": "lua", "code": code, "call": call}
    dummy = {"name": "dummy", "tag": "startup.test"}
    pipeline = {"inputs": [dummy], "outputs": [{"name": "null", "match": "*"}]}
    if context == "processor":
        dummy["processors"] = {"logs": [lua_filter]}
    else:
        lua_filter["match"] = "*"
        pipeline["filters"] = [lua_filter]
    config = tmp_path / "fluent-bit.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": pipeline,
    }))
    manager = FluentBitManager(str(config))
    try:
        with pytest.raises(FluentBitStartupError):
            manager.start()
        assert diagnostic in Path(manager.log_file).read_text()
    finally:
        manager.stop()
