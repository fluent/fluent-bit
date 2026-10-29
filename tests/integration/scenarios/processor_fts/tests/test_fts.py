"""FTS (Fluent Typed Scripting): ownership, exact values, and OTel groups."""

import json
import re
import requests
from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


def make_service(tmp_path, code, *, grouped=False, error_mode="keep",
                 threaded=False, output_processor=False, second_processor=None, output_format="json_lines", runtime_options=None):
    processor = {"name": "fts", "code": code, "call": "process_log",
                 "error_mode": error_mode}
    processor.update(runtime_options or {})
    processors = ([{"name": "opentelemetry_envelope"}] if grouped else []) + [processor]
    if second_processor:
        processors.append(second_processor)
    dummy = {"name": "dummy", "tag": "typed.logs", "rate": 4, "threaded": threaded,
             "dummy": json.dumps({"message": "original", "secret": "sensitive",
                                  "Secret": "case-sensitive", "optional": None,
                                  "large": 18446744073709551615,
                                  "nested": {"one": 1}, "values": [1, 2]})}
    output = {"name": "stdout", "match": "*", "format": output_format}
    (output if output_processor else dummy)["processors"] = {"logs": processors}
    config = tmp_path / "typed.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "log_level": "info", "http_server": True,
                    "http_listen": "127.0.0.1",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [dummy], "outputs": [output]},
    }))
    return FluentBitTestService(str(config))


def log_text(service):
    return Path(service.flb.log_file).read_text(encoding="utf-8")


def records(service):
    return [json.loads(line) for line in log_text(service).splitlines() if line.startswith("{")]


@pytest.mark.parametrize("output_processor", [False, True])
def test_removed_libraries_cannot_be_recovered(tmp_path, output_processor):
    code = r'''
local function check_packages()
    for _, name in ipairs({"os", "io", "debug", "jit", "ffi", "package", "coroutine"}) do
        assert(rawget(_G, name) == nil)
        assert(getfenv == nil and setfenv == nil)
        assert(not pcall(require, name))
        assert(not pcall(function() module(name) end))
    end
    assert(module == nil and loadfile == nil and dofile == nil)
    assert(not pcall(require, "fluentbit\0os"))
    assert(type(require("fluentbit")) == "table")
end
check_packages()
function process_log(log)
    check_packages()
    log.body:set("message", "restricted")
end
'''
    service = make_service(tmp_path, code, output_processor=output_processor)
    try:
        service.start()
        output = service.wait_for_condition(lambda: records(service), timeout=30)
        assert all(record["message"] == "restricted" for record in output)
        assert "edits rolled back" not in log_text(service)
    finally:
        service.stop()


TYPED_CODE = r'''
local fb = require("fluentbit")
local previous, retained
function process_log(event)
    local body = event.body
    assert(body:get_string("message") == "original")
    assert(body:get_string("missing") == nil)
    assert(not pcall(function() body:get_number("values") end))
    assert(body:get("large"):type() == "uint64")
    assert(body:get("large"):value() == "18446744073709551615")
    assert(not pcall(function() return body:get("large"):number() end))
    assert(body:get("optional"):type() == "null")
    assert(body:get("missing") == nil)
    body:set("copied", body:get("large"))
    body:set("signed", fb.int64("-9223372036854775808"))
    body:set("unsigned", fb.uint64("18446744073709551615"))
    body:set("null", fb.null)
    body:set("empty_map", fb.map())
    body:set("empty_array", fb.array())
    body:set("flag", true)
    assert(body:get_bool("flag") == true)
    body:set("fraction", 1.25)
    assert(body:get_number("fraction") == 1.25)
    local allowed = fb.map()
    allowed:set("keep", true)
    allowed:set("remove", true)
    fb.keep_keys(allowed, {"keep"})
    assert(allowed:len() == 1 and allowed:get("remove") == nil)
    fb.redact(allowed, {"keep"}, false)
    assert(allowed:get("keep"):value() == false)
    allowed:set("nul\0key", "nul\0value")
    assert(allowed:get("nul\0key"):value() == "nul\0value")
    assert(not pcall(function() fb.uint64(" 1") end))
    assert(not pcall(function() fb.uint64("1\0") end))
    assert(not pcall(function() fb.int64(9007199254740992) end))
    assert(not pcall(function() fb.attributes(event) end))
    body:set("utf8", "café")
    body:get("nested"):set("one", fb.int64(7))
    local child = body:get("nested"):get("one")
    body:remove("nested")
    assert(not pcall(function() return child:value() end))
    body:set("nested", fb.map())
    body:get("nested"):set("one", fb.int64(8))
    assert(child:number() == 8) -- Views resolve paths after replacement.
    body:get("values"):set(1, fb.map())
    body:get("values"):get(1):set("temporary", true)
    body:get("values"):set(1, fb.int64(3))
    body:get("values"):append(fb.int64(4))
    assert(body:get("values"):len() == 3)
    local binary = fb.bytes("a\0b")
    assert(binary:type() == "bytes" and binary:value() == "a\0b")
    body:set("binary", binary)
    fb.redact(body, {"secret"})
    assert(body:get("Secret"):value() == "[REDACTED]")
    if previous then
        -- Copies are owned and cannot change already committed records.
        previous:set("message", "late mutation")
        assert(retained:value() == "18446744073709551615")
    end
    previous, retained = body:copy(), body:get("large"):copy()
    body:set("message", "typed")
    event.timestamp.sec, event.timestamp.nsec = 2147483648, 123456789
    return fb.KEEP
end
'''


@pytest.mark.parametrize("threaded,output_processor", [(False, False), (True, False), (False, True)])
def test_typed_values_and_ownership(tmp_path, threaded, output_processor):
    service = make_service(tmp_path, TYPED_CODE, threaded=threaded, output_processor=output_processor)
    try:
        service.start()
        output = service.wait_for_condition(lambda: records(service) if len(records(service)) >= 3 else None,
                                            timeout=30)
        assert "callback failed" not in log_text(service)
        for record in output:
            assert record["message"] == "typed"
            assert record["large"] == record["copied"] == record["unsigned"] == 18446744073709551615
            assert record["signed"] == -9223372036854775808
            assert record["null"] is None and record["optional"] is None
            assert record["empty_map"] == {} and record["empty_array"] == []
            assert record["nested"] == {"one": 8} and record["values"] == [3, 2, 4]
            assert record["secret"] == "[REDACTED]" and record["Secret"] == "[REDACTED]"
            assert record["flag"] is True and record["fraction"] == 1.25 and record["utf8"] == "café"
    finally:
        service.stop()


@pytest.mark.parametrize("failure", [
    'error("intentional")',
    'do return "invalid-result" end',
    'event.timestamp.nsec = 1000000000',
    'event.metadata = fb.array()',
    'event.body:set("bad", nil)',
    'fb.uint64("18446744073709551616")',
    'fb.int64("-9223372036854775809")',
    'fb.uint64(-1)',
    'event.body:get("values"):get(0)',
])
def test_errors_rollback_record(tmp_path, failure):
    code = f'''local fb = require("fluentbit")
function process_log(event)
    event.body:set("message", "partial edit")
    {failure}
    return fb.KEEP
end'''
    service = make_service(tmp_path, code)
    try:
        service.start()
        service.wait_for_condition(lambda: "edits rolled back" in log_text(service), timeout=30)
        output = service.wait_for_condition(lambda: records(service), timeout=30)
        assert all(record["message"] == "original" for record in output)
        def errors_visible():
            response = requests.get(f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus",
                                    timeout=5)
            matches = re.findall(r'^fluentbit_processor_errors_total\{[^}]*processor="fts"[^}]*\} ([0-9.eE+-]+)',
                                 response.text, re.MULTILINE)
            return any(float(value) > 0 for value in matches)
        service.wait_for_condition(errors_visible, timeout=30)
    finally:
        service.stop()


@pytest.mark.parametrize("explicit", [True, False])
def test_record_drop(tmp_path, explicit):
    code = '''local fb = require("fluentbit")
function process_log(event)
    %s
end''' % ('return fb.DROP' if explicit else 'error("drop-on-error")')
    service = make_service(tmp_path, code, grouped=True, error_mode="drop")
    try:
        service.start()
        service.stop()
        assert not records(service)
        if not explicit:
            assert "edits rolled back" in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("code", ["function !bad syntax", 'error("initializer-failed")', "function other() end"])
def test_startup_failure_cleanup(tmp_path, code):
    service = make_service(tmp_path, code)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert "FTS initialization failed" in log_text(service)
    finally:
        service.stop()


def test_context_aliases_survive_processor_chain(tmp_path):
    code = '''local fb = require("fluentbit")
function process_log(log)
    log.body:set("large", fb.int64("9223372036854775807"))
    log.resource.attributes:set("service.name", "payments")
    log.scope.name = "policy"
    log.scope.version = "2"
    log.scope.attributes:set("revision", fb.int64(3))
    log.attributes:set("redacted", true)
    fb.redact(log.body, {"secret"})
end'''
    downstream = {"name": "fts", "code": '''function process(log)
      assert(log.resource.attributes:get_string("service.name") == "payments")
      assert(log.scope.name == "policy" and log.scope.version == "2")
      assert(log.scope.attributes:get_number("revision") == 3)
      assert(log.attributes:get_bool("redacted"))
      log.body:set("verified", true)
    end'''}
    service = make_service(tmp_path, code, grouped=True, second_processor=downstream)
    try:
        service.start()
        output = service.wait_for_condition(lambda: records(service), timeout=30)
        assert all(record["verified"] and record["secret"] == "[REDACTED]" for record in output)
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()


def test_script_file_and_default_callback(tmp_path):
    script = tmp_path / "policy.lua"
    script.write_text('local fb=require("fluentbit"); function process(log) '
                      'log.body:set("message", "script-file"); log.body:set("count",fb.int64(1)) end')
    service = make_service(tmp_path, "unused")
    config = tmp_path / "typed.yaml"
    document = yaml.safe_load(config.read_text())
    processor = document["pipeline"]["inputs"][0]["processors"]["logs"][0]
    processor.pop("call"); processor.pop("code"); processor["script"] = str(script)
    config.write_text(yaml.safe_dump(document))
    try:
        service.start()
        output = service.wait_for_condition(lambda: records(service), timeout=30)
        assert all(log["message"] == "script-file" and log["count"] == 1 for log in output)
    finally:
        service.stop()


def test_script_prefers_config_directory(tmp_path, monkeypatch):
    working_dir = tmp_path / "working"
    working_dir.mkdir()
    (tmp_path / "policy.lua").write_text(
        'function process(log) log.body:set("message", "config") end')
    (working_dir / "policy.lua").write_text(
        'function process(log) log.body:set("message", "working") end')
    service = make_service(tmp_path, "unused")
    config = tmp_path / "typed.yaml"
    document = yaml.safe_load(config.read_text())
    processor = document["pipeline"]["inputs"][0]["processors"]["logs"][0]
    processor.pop("call")
    processor.pop("code")
    processor["script"] = "policy.lua"
    config.write_text(yaml.safe_dump(document))

    monkeypatch.chdir(working_dir)
    try:
        service.start()
        output = service.wait_for_condition(lambda: records(service), timeout=30)
        assert all(log["message"] == "config" for log in output)
    finally:
        service.stop()


@pytest.mark.parametrize("signal", ["profiles"])
def test_unsupported_signals_fail_startup(tmp_path, signal):
    service = make_service(tmp_path, "function process_log(log) end")
    config = tmp_path / "typed.yaml"
    document = yaml.safe_load(config.read_text())
    processors = document["pipeline"]["inputs"][0]["processors"]
    processors[signal] = processors.pop("logs")
    config.write_text(yaml.safe_dump(document))
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert "unknown processor 'profiles'" in log_text(service)
    finally:
        service.stop()


def test_unpublished_processor_name_is_not_registered(tmp_path):
    service = make_service(tmp_path, "function process_log(log) end")
    config = tmp_path / "typed.yaml"
    document = yaml.safe_load(config.read_text())
    document["pipeline"]["inputs"][0]["processors"]["logs"][0]["name"] = "lua_typed"
    config.write_text(yaml.safe_dump(document))
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
    finally:
        service.stop()


def test_record_edit_without_module_import(tmp_path):
    service = make_service(tmp_path, """function process_log(log)
        log.body:set("message", "no-import")
    end""")
    try:
        service.start()
        output = service.wait_for_condition(lambda: records(service), timeout=30)
        assert all(log["message"] == "no-import" for log in output)
    finally:
        service.stop()


@pytest.mark.parametrize("output_processor", [False, True])
def test_trusted_jit_policy_runs(tmp_path, output_processor):
    code = """local total=0
for j=1,30 do for i=1,100000 do total=total+i end end
function process_log(log)
    local sum=0; for i=1,50000 do sum=sum+i end
    log.body:set('message', tostring(sum))
end"""
    service = make_service(tmp_path, code, output_processor=output_processor,
                           runtime_options={"jit": True, "instruction_limit": 0})
    try:
        service.start()
        rows = service.wait_for_condition(lambda: records(service), timeout=30)
        assert all(row["message"] == "1250025000" for row in rows)
        assert "edits rolled back" not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("options", [{"jit": True}, {"jit": True, "instruction_limit": 1000},
                                     {"jit": False, "instruction_limit": 0}])
def test_jit_and_instruction_budget_cannot_be_combined(tmp_path, options):
    service = make_service(tmp_path, "function process_log(log) end", runtime_options=options)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        expected = ("jit requires instruction_limit=0" if options.get("jit") else
                    "instruction_limit must be between 1000 and 2147483647 with jit disabled")
        assert expected in log_text(service)
    finally:
        service.stop()
