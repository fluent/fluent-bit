"""Native Lua metrics, atomic validation and recovery through Prometheus output."""

from pathlib import Path
import re

import pytest
import requests
import yaml

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


def make_service(tmp_path, script, **properties):
    script_path = tmp_path / "metrics.lua"
    script_path.write_text(script)
    config = {
        "service": {
            "flush": 1, "grace": 5, "log_level": "info",
            "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{"name": "lua_metrics_exporter", "script": str(script_path),
                        "scrape_interval": "1s", **properties}],
            "outputs": [{"name": "prometheus_exporter", "match": "*",
                         "host": "127.0.0.1", "port": "${EXPORTER_PORT}"}],
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))

    def pre_start(service):
        service.exporter_port = service.allocate_port_env("EXPORTER_PORT")

    return FluentBitTestService(str(config_path), pre_start=pre_start, shutdown_timeout=30)


def scrape(service):
    try:
        response = requests.get(f"http://127.0.0.1:{service.exporter_port}/metrics", timeout=2)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        pass
    return ""


def wait_metrics(service, predicate):
    return service.wait_for_condition(
        lambda: text if predicate(text := scrape(service)) else None,
        timeout=40, interval=0.2, description="Lua metrics",
    )


def test_native_metrics_and_counter_reset(tmp_path):
    # A file handshake keeps the first collection observable even under Valgrind.
    reset_path = tmp_path / "reset"
    service = make_service(tmp_path, '''
local calls = 0
function query()
    calls = calls + 1
    local file = io.open(%s, "r")
    local total = 42
    if file then file:close(); total = 3 end
    return {
        {name="db_sessions", help="Active sessions", type="gauge",
         label_keys={"database"}, samples={
             {label_values={"orders"}, value=0},
             {label_values={"inventory"}, value=12}}},
        {name="db_executions_total", help="Executions", type="counter",
         samples={{value=total}}},
        {name="db_offset", help="Offset", type="gauge", samples={{value=-1.5}}},
        {name="collection_count", help="Collections", type="gauge", samples={{value=calls}}}
    }
end
''' % repr(str(reset_path)), call="query")
    service.start()
    try:
        text = wait_metrics(service, lambda text: re.search(r"db_executions_total 42(?:\s|$)", text))
        assert '# TYPE db_sessions gauge' in text
        assert '# TYPE db_executions_total counter' in text
        assert 'db_sessions{database="orders"} 0' in text
        assert 'db_sessions{database="inventory"} 12' in text
        assert 'db_offset -1.5' in text
        text = wait_metrics(service, lambda text: (
            (match := re.search(r"collection_count (\d+)", text)) and int(match[1]) >= 3
        ))
        assert re.search(r"db_executions_total 42(?:\s|$)", text)
        reset_path.touch()
        wait_metrics(service, lambda text: re.search(r"db_executions_total 3(?:\s|$)", text))
    finally:
        service.stop()


INVALID_RESULTS = [
    "nil",
    '(function() local t={} for i=1,1025 do t[i]={} end return t end)()',
    '{{name="bad",help="Bad",type="gauge",label_keys='
    '(function() local t={} for i=1,33 do t[i]="l"..i end return t end)(),'
    'samples={{value=1}}}}',
    '{{name="bad",help="Bad",type="gauge",samples='
    '(function() local t={} for i=1,10001 do t[i]={value=1} end return t end)()}}',
    '{{name="bad",help="Bad",type="gauge",label_keys={"__reserved"},samples={{value=1}}}}',
    '{{name="bad",help="Bad",type="gauge",label_keys={"db"},'
    'samples={{value=1,label_values={"nul"..string.char(0)}}}}}',

    '"not a table"',
    '{[2]={name="bad",help="Bad",type="gauge",samples={{value=1}}}}',
    '{{name="bad",help="Bad",type="histogram",samples={{value=1}}}}',
    '{{name="bad",help="Bad",type="counter",samples={{value=-1}}}}',
    '{{name="bad",help="Bad",type="gauge",samples={{value=0/0}}}}',
    '{{name="bad",help="Bad",type="gauge",samples={{value=math.huge}}}}',
    '{{name="bad",help="Bad",type="gauge",samples={{value="1"}}}}',
    '{{name="bad",help="Bad",type="gauge",samples={{}}}}',
    '{{name="bad",help="Bad",type="gauge",label_keys={"db"},samples={{value=1}}}}',
    '{{name="bad",help="Bad",type="gauge",label_keys={"db","db"},samples={{value=1}}}}',
    '{{name="bad",help="Bad",type="gauge",label_keys={"db"},'
    'samples={{value=1,label_values={123}}}}}',
    '{{name="bad name",help="Bad",type="gauge",samples={{value=1}}}}',
    '{{name="bad",type="gauge",samples={{value=1}}}}',
    '{{name="bad",help="Bad",type="gauge",samples={}}}',
    '{{name="bad",help="Bad",type="gauge",samples={{value=1}}},'
    '{name="bad",help="Bad",type="counter",samples={{value=2}}}}',
    'setmetatable({unexpected=1}, {__index=function() error("metatable must not run") end, key=1})',
]


@pytest.mark.parametrize("result", INVALID_RESULTS)
def test_invalid_collection_is_atomic_and_recovers(tmp_path, result):
    # Insert a valid family first to detect accidental partial emission.
    service = make_service(tmp_path, '''
local calls = 0
function collect()
    calls = calls + 1
    if calls == 1 then
        local result = %s
        if type(result) == "table" and next(result) ~= nil then
            local batch = {{name="partial_batch",help="Must be discarded",
                            type="gauge",samples={{value=99}}}}
            for key, value in pairs(result) do
                if type(key) == "number" then batch[key + 1] = value
                else batch[key] = value end
            end
            result = batch
        end
        return result
    end
    return {{name="recovered",help="Recovered",type="gauge",samples={{value=calls}}}}
end
''' % result)
    service.start()
    try:
        text = wait_metrics(service, lambda text: "recovered " in text)
        assert "partial_batch" not in text
        assert "invalid metrics result" in Path(service.flb.log_file).read_text()
    finally:
        service.stop()


def test_callback_error_and_empty_collection_recover(tmp_path):
    service = make_service(tmp_path, '''
local calls = 0
function collect()
    calls = calls + 1
    if calls == 1 then error({reason="query failed"}) end
    if calls == 2 then return {} end
    return {{name="recovered",help="Recovered",type="gauge",samples={{value=calls}}}}
end
''')
    service.start()
    try:
        wait_metrics(service, lambda text: "recovered " in text)
        log = Path(service.flb.log_file).read_text()
        assert "collection callback failed" in log
        assert "invalid metrics result" not in log
    finally:
        service.stop()


@pytest.mark.parametrize("script,properties", [
    ("function collect(", {}),
    ('error("initialization failed")', {}),
    ("function different() return {} end", {}),
    ("function collect() return {} end", {"scrape_interval": "0"}),
])
def test_invalid_initialization(tmp_path, script, properties):
    service = make_service(tmp_path, script, **properties)
    with pytest.raises(FluentBitStartupError):
        service.start()
