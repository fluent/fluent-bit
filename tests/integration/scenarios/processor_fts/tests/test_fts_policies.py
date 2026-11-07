"""Log-policy matrix inspired by OTTL's log transform processor tests.

These are independent end-to-end assertions, not an OTTL interpreter or a
claim of parity with the complete OTTL function catalog. Every policy runs
through both input and output processor placement and OTLP JSON export.
"""

import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests
import yaml

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port


# (name, record policy, inherited-context policy, expected target, values for A/B)
POLICIES = [
    ("set", 'attrs:set("test", "pass")', "", "attrs", ["pass", "pass"]),
    ("condition_true", 'if body:get_string("text") == "operationA" then attrs:set("test", "pass") end',
     "", "attrs", ["pass", None]),
    ("condition_false", 'if body:get_string("text") == "absent" then attrs:set("test", "pass") end',
     "", "attrs", [None, None]),
    ("resource_condition", 'if event.resource.attributes:get_string("host.name") == "localhost" '
     'then attrs:set("test", "pass") end', "", "attrs", ["pass", "pass"]),
    ("scope_condition", 'if event.scope.name == "scope" '
     'then attrs:set("test", "pass") end', "", "attrs", ["pass", "pass"]),
    ("scope_wrong_version", 'if event.scope.version == "2" '
     'then attrs:set("test", "pass") end', "", "attrs", [None, None]),
    ("severity_text", 'if attrs:get_string("http.path") == "/health" then otlp:set("severity_text", "OK") end',
     "", "severityText", ["OK", "OK"]),
    ("severity_number", 'if otlp:get_number("severity_number") == 9 then '
     'otlp:set("severity_number", fb.int64(10)) end', "", "severityNumber", [10, 10]),
    ("flags_condition", 'if fb.log_field(event, "trace_flags"):number() == 1 then attrs:set("test", "pass") end',
     "", "attrs", ["pass", None]),
    ("dropped_count_condition", 'if otlp:get_number("dropped_attributes_count") == 1 then '
     'attrs:set("test", "pass") end', "", "attrs", ["pass", None]),
    ("trace_id_condition", 'if otlp:get("trace_id"):value() == string.char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16) '
     'then attrs:set("test", "pass") end', "", "attrs", ["pass", "pass"]),
    ("span_id_condition", 'if otlp:get("span_id"):value() == string.char(1,2,3,4,5,6,7,8) '
     'then attrs:set("test", "pass") end', "", "attrs", ["pass", "pass"]),
    ("pattern_condition", 'if body:get_string("text"):match("operation[AC]") then '
     'attrs:set("test", "pass") end', "", "attrs", ["pass", None]),
    ("replace_pattern", 'attrs:set("http.method", attrs:get_string("http.method"):gsub("g.t", "post"))',
     "", "http.method", ["post", "post"]),
    ("replace_all_values", 'for _, k in ipairs(attrs:keys()) do local v = attrs:get(k); '
     'if v:type() == "string" then attrs:set(k, (v:value():gsub("get", "post"))) end end',
     "", "http.method", ["post", "post"]),
    ("rename_key", 'attrs:set("url", attrs:get("http.url")); attrs:remove("http.url")',
     "", "rename", ["http://localhost/health", "http://localhost/health"]),
    ("delete_key", 'if body:get_string("text") == "operationA" then attrs:remove("http.url") end',
     "", "delete", [True, False]),
    ("delete_matching_keys", 'for _, k in ipairs(attrs:keys()) do '
     'if k:match("^http%..*t") then attrs:remove(k) end end', "", "delete_matching", [True, True]),
    ("keep_keys", 'fb.keep_keys(attrs, {"http.method", "request.id"})', "", "keep", [True, True]),
    ("concat", 'attrs:set("test", attrs:get_string("http.method") .. ": " .. attrs:get_string("http.url"))',
     "", "attrs", ["get: http://localhost/health", "get: http://localhost/health"]),
    ("split", 'local a = fb.array(); for s in attrs:get_string("flags"):gmatch("[^|]+") do '
     'a:append(s) end; attrs:set("test", a)', "", "attrs", [["A", "B", "C"], ["C", "D"]]),
    ("split_missing", 'local s = attrs:get_string("absent"); if s then '
     'attrs:set("test", s:sub(1, 1)) end', "", "attrs", [None, None]),
    ("substring", 'attrs:set("test", attrs:get_string("total.string"):sub(4, 6))',
     "", "attrs", ["456", "678"]),
    ("substring_missing", 'local s = attrs:get_string("absent"); if s then '
     'attrs:set("test", s:sub(4, 6)) end', "", "attrs", [None, None]),
    ("array_literal", 'local a = fb.array(); for _, s in ipairs({"A", "B", "C"}) do '
     'a:append(s) end; attrs:set("test", a)', "", "attrs", [["A", "B", "C"], ["A", "B", "C"]]),
    ("lower", 'attrs:set("test", body:get_string("text"):lower())',
     "", "attrs", ["operationa", "operationb"]),
    ("upper", 'attrs:set("test", body:get_string("text"):upper())',
     "", "attrs", ["OPERATIONA", "OPERATIONB"]),
    ("snake", 'attrs:set("test", (body:get_string("text"):gsub("(%l)(%u)", "%1_%2")):lower())',
     "", "attrs", ["operation_a", "operation_b"]),
    ("camel", 'local s = body:get_string("snake"); '
     'attrs:set("test", (s:gsub("_(%l)", string.upper)))',
     "", "attrs", ["operationA", "operationB"]),
    ("merge_insert", 'local values = { ["http.method"] = "post", json_test = "pass" }; '
     'for k, v in pairs(values) do if not attrs:get(k) then attrs:set(k, v) end end',
     "", "merge_insert", ["pass", "pass"]),
    ("merge_update", 'local values = { ["http.method"] = "post", absent = "ignored" }; '
     'for k, v in pairs(values) do if attrs:get(k) then attrs:set(k, v) end end',
     "", "http.method", ["post", "post"]),
    ("merge_upsert", 'for k, v in pairs({ ["http.method"] = "post", new = "added" }) do '
     'attrs:set(k, v) end', "", "merge_upsert", ["added", "added"]),
    ("limit_zero", 'fb.keep_keys(attrs, {"request.id"})', "", "empty", [True, True]),
    ("math_log", 'attrs:set("test", math.log(1))', "", "attrs", [0.0, 0.0]),
    ("nested_body", 'body:get("metadata"):set("uid", "12345")',
     "", "nested", ["12345", "12345"]),
    ("record_cache", 'local cache = { text = body:get_string("text") }; attrs:set("test", cache.text)',
     "", "attrs", ["operationA", "operationB"]),
    ("resource_set", "", 'event.resource.attributes:set("test", "pass")',
     "resource", "pass"),
    ("resource_false", "", 'local a = event.resource.attributes; if a:get_string("host.name") == "wrong" '
     'then a:set("test", "pass") end', "resource", None),
    ("resource_schema", "", 'event.resource.schema_url = "https://schema.example/resource"',
     "resource_schema", "https://schema.example/resource"),
    ("scope_set", "", 'event.scope.attributes:set("test", "pass")', "scope", "pass"),
    ("scope_schema", "", 'event.scope.schema_url = "https://schema.example/scope"',
     "scope_schema", "https://schema.example/scope"),
    ("scope_name", "", 'event.scope.name = "new-scope"', "scope_name", "new-scope"),
    ("scope_version", "", 'event.scope.version = "2.0"', "scope_version", "2.0"),
    ("timestamp", 'event.timestamp.sec = 2147483648; event.timestamp.nsec = 987654321',
     "", "timeUnixNano", ["2147483648987654321", "2147483648987654321"]),
    ("observed_timestamp", 'otlp:set("observed_timestamp", fb.uint64("2147483648987654321"))',
     "", "observedTimeUnixNano", ["2147483648987654321", "2147483648987654321"]),
    ("field_precedence", 'event.metadata:set("severity_text", "ROOT"); '
     'otlp:set("severity_text", "NESTED"); '
     'assert(fb.log_field(event, "severity_text"):value() == "NESTED")',
     "", "severityText", ["NESTED", "NESTED"]),
    ("field_zero", 'otlp:set("trace_flags", fb.uint64(0)); '
     'event.metadata:set("trace_flags", fb.uint64(1)); '
     'attrs:set("test", fb.log_field(event, "trace_flags"))', "", "attrs", [0, 0]),
    ("field_missing", 'assert(fb.log_field(event, "absent") == nil)',
     "", "attrs", [None, None]),
    ("signed_min", 'attrs:set("test", fb.int64("-9223372036854775808"))',
     "", "attrs", [-9223372036854775808, -9223372036854775808]),
    ("signed_max", 'attrs:set("test", fb.int64("9223372036854775807"))',
     "", "attrs", [9223372036854775807, 9223372036854775807]),
    ("empty_array", 'attrs:set("test", fb.array())', "", "attrs", [[], []]),
    ("empty_map", 'attrs:set("test", fb.map())', "", "attrs", [{}, {}]),
    ("binary", 'attrs:set("test", fb.bytes("a\\0b"))', "", "bytes", ["YQBi", "YQBi"]),
    ("nested_array", 'local a = fb.array(); local m = fb.map(); m:set("nested", true); '
     'a:append(m); a:append(fb.int64(7)); attrs:set("test", a)',
     "", "attrs", [[{"nested": True}, 7], [{"nested": True}, 7]]),
    ("rollback", 'body:set("text", "partial"); attrs:set("test", "partial"); error("matrix-rollback")',
     "", "attrs", [None, None]),
    ("context_rollback", "", 'event.resource.attributes:set("test", "partial"); error("matrix-context-rollback")',
     "resource", None),
    ("drop_first", 'if body:get_string("text") == "operationA" then return fb.DROP end',
     "", "drop", [True, False]),
    ("drop_both", 'return fb.DROP', "", "drop", [True, True]),
]


# Operational recipes: producer enrichment stays isolated; request identity remains
# on the event. Parse/normalize helpers remove the cache/type plumbing from policies.
POLICIES.extend([
    ("producer_from_record", 'event.resource.attributes:set("service.name", body:get_string("text"))',
     "", "producer", ["operationA", "operationB"]),
    ("scope_from_record", 'event.scope.name = body:get_string("text")',
     "", "scope_name_record", ["operationA", "operationB"]),
    ("tenant_on_event", 'attrs:set("tenant.id", body:get_string("text"))',
     "", "tenant", ["operationA", "operationB"]),
    ("named_severity", 'fb.set_severity(event, "Warning")',
     "", "named_severity", [13, 13]),
    ("fractional_time", 'event.timestamp = fb.parse_time("2024-11-19T18:05:24.0300402+00:00")',
     "", "timeUnixNano", ["1732039524030040200", "1732039524030040200"]),
    ("correlation", 'fb.set_trace_context(event, "abcdef0123456789abcdef0123456789", "abcdef0123456789")',
     "", "correlation", [True, True]),
    ("json_normalize", 'local parsed = fb.parse_json(\'{"Level":"Information","Properties":{"customer":"acme"}}\'); '
     'fb.set_severity(event, parsed:get_string("Level")); '
     'attrs:set("customer", parsed:get("Properties"):get("customer"))',
     "", "json_normalize", ["acme", "acme"]),
    ("recursive_privacy", 'local parsed = fb.parse_json(\'{"Authorization":"bearer","nested":{"password":"secret"},'
     '"headers":[{"AUTHORIZATION":"token"}]}\'); '
     'fb.redact(parsed, {"authorization", "password"}); body:set("sanitized", parsed)',
     "", "privacy", [True, True]),
    ("flags_preserve", 'otlp:set("trace_flags", fb.uint64(255))',
     "", "flags", [255, 255]),
    ("event_name", 'otlp:set("event_name", "policy.event")',
     "", "eventName", ["policy.event", "policy.event"]),
    ("dropped_count", 'otlp:set("dropped_attributes_count", fb.uint64(0))',
     "", "droppedAttributesCount", [0, 0]),
])

# Boundary/failure cases supplement the OTTL-inspired policy families. Each
# failure happens after a mutation, so the output must prove full rollback.
INVALID_OPERATIONS = {
    "signed_overflow": 'fb.int64("9223372036854775808")',
    "signed_underflow": 'fb.int64("-9223372036854775809")',
    "unsigned_overflow": 'fb.uint64("18446744073709551616")',
    "unsigned_negative": 'fb.uint64("-1")',
    "integer_whitespace": 'fb.int64(" 1")',
    "integer_plus": 'fb.int64("+1")',
    "integer_empty": 'fb.int64("")',
    "integer_nul": 'fb.int64("1\\0")',
    "integer_fraction": 'fb.int64(1.5)',
    "integer_unsafe_number": 'fb.uint64(9007199254740992)',
    "integer_nan": 'fb.int64(0/0)',
    "unsafe_number_read": 'fb.uint64("18446744073709551615"):number()',
    "nonfinite_write": 'body:set("bad", math.huge)',
    "nil_write": 'body:set("bad", nil)',
    "table_write": 'body:set("bad", {})',
    "map_numeric_key": 'body:get(1)',
    "map_numeric_set_key": 'body:set(1, "bad")',
    "scalar_get": 'body:get("text"):get("bad")',
    "scalar_set": 'body:get("text"):set("bad", "bad")',
    "scalar_len": 'body:get("text"):len()',
    "scalar_keys": 'body:get("text"):keys()',
    "get_string_wrong_type": 'body:get_string("metadata")',
    "get_bool_wrong_type": 'body:get_bool("text")',
    "get_number_wrong_type": 'body:get_number("text")',
    "ensure_map_conflict": 'body:ensure_map("text")',
    "bytes_nonstring": 'fb.bytes(3)',
    "map_constructor_args": 'fb.map({})',
    "array_constructor_args": 'fb.array({})',
    "empty_array_index": 'fb.array():get(1)',
    "array_index_zero": 'local a = fb.array(); a:append(true); a:get(0)',
    "array_index_fraction": 'local a = fb.array(); a:append(true); a:get(1.5)',
    "array_index_string": 'local a = fb.array(); a:append(true); a:get("1")',
    "array_index_nan": 'local a = fb.array(); a:append(true); a:get(0/0)',
    "array_index_infinity": 'local a = fb.array(); a:append(true); a:get(math.huge)',
    "array_set_out_of_bounds": 'fb.array():set(1, true)',
    "map_append": 'body:append(true)',
    "body_root_array": 'event.body = fb.array()',
    "metadata_root_array": 'event.metadata = fb.array()',
    "timestamp_negative": 'event.timestamp.sec = -1',
    "timestamp_overflow": 'event.timestamp.sec = 4294967296',
    "timestamp_fraction": 'event.timestamp.sec = 1.5',
    "timestamp_nan": 'event.timestamp.sec = 0/0',
    "timestamp_nsec_negative": 'event.timestamp.nsec = -1',
    "timestamp_nsec_overflow": 'event.timestamp.nsec = 1000000000',
    "timestamp_nsec_fraction": 'event.timestamp.nsec = 0.5',
    "timestamp_string": 'event.timestamp.sec = "1"',
    "timestamp_wrong_shape": 'event.timestamp = {}',
    "nonstring_error": 'error({message="typed error"})',
    "invalid_return": 'do return "invalid" end',
    "stale_view": 'local child = body:get("metadata"):get("uid"); '
                  'body:remove("metadata"); child:value()',
}
INVALID_OPERATIONS.update({
    "json_duplicate": 'fb.parse_json(\'{"secret":"one","secret":"two"}\')',
    "json_trailing": 'fb.parse_json(\'{"ok":1} trailing\')',
    "json_overflow": 'fb.parse_json("18446744073709551616")',
    "json_invalid": 'fb.parse_json("{broken")',
    "severity_unknown": 'fb.set_severity(event, "unexpected")',
    "severity_double": 'otlp:set("severity_number", 9)',
    "flags_bounds": 'otlp:set("trace_flags", fb.uint64(256))',
    "severity_bounds": 'otlp:set("severity_number", fb.int64(25))',
    "trace_bad_length": 'fb.set_trace_context(event, "abc", "abcdef0123456789")',
    "trace_all_zero": 'fb.set_trace_context(event, string.rep("0",32), "abcdef0123456789")',
    "trace_wrong_type": 'otlp:set("trace_id", "abcdef0123456789abcdef0123456789")',
    "time_missing_zone": 'fb.parse_time("2024-11-19T18:05:24")',
    "time_bad_leap": 'fb.parse_time("2023-02-29T12:00:00Z")',
    "time_bad_fraction": 'fb.parse_time("2024-02-29T12:00:00.1234567890Z")',
    "time_bad_zone": 'fb.parse_time("2024-02-29T12:00:00+24:00")',
    "time_bad_calendar": 'fb.parse_time("2024-02-30T12:00:00Z")',
    "scope_invalid_shape": 'event.context.attributes:set("scope", true)',
    "scope_invalid_name": 'event.context.attributes:get("scope"):set("name", fb.int64(1))',
    "resource_invalid_attrs": 'event.context.attributes:get("resource"):set("attributes", false)',
    "raw_time_conflict": 'otlp:set("timestamp", fb.uint64(1))',
    "zero_trace": 'otlp:set("trace_id", fb.bytes(string.rep(string.char(0),16)))',
    "invalid_utf8": 'attrs:set("bad", string.char(255))',
    "invalid_utf8_key": 'attrs:set(string.char(255), "bad")',
    "overlong_utf8": 'attrs:set("bad", string.char(192,128))',
    "surrogate_utf8": 'attrs:set("bad", string.char(237,160,128))',
    "otel_unsigned_overflow": 'attrs:set("bad", fb.uint64("18446744073709551615"))',
    "otel_nul_string": 'attrs:set("bad", "a" .. string.char(0) .. "b")',
    "otel_nul_key": 'attrs:set("a" .. string.char(0) .. "b", "bad")',
    "root_flags_invalid": 'otlp:remove("trace_flags"); event.metadata:set("trace_flags", "bad")',
    "event_name_invalid": 'otlp:set("event_name", fb.int64(1))',
    "context_metadata_gc": 'local replacement=fb.map(); for _,k in ipairs(event.context.metadata:keys()) do replacement:set(k,event.context.metadata:get(k)) end; event.context.metadata=replacement; collectgarbage()',
    "context_replace": 'event.context = {}',
    "context_root_replace": 'event.context.attributes = fb.map()',
    "resource_alias_replace": 'event.resource = {}',
    "transport_id_edit": 'event.context.metadata:set("resource_id", fb.int64(9))',
})
POLICIES.extend(("bad_" + name, 'body:set("text", "partial"); attrs:set("test", "partial"); ' + code,
                 "", "attrs", [None, None]) for name, code in INVALID_OPERATIONS.items())


def scalar(value):
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return int(value["intValue"])
    if "doubleValue" in value:
        return value["doubleValue"]
    if "boolValue" in value:
        return value["boolValue"]
    if "bytesValue" in value:
        return value["bytesValue"]
    if "arrayValue" in value:
        return [scalar(item) for item in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return attributes(value["kvlistValue"].get("values", []))
    return None


def attributes(items):
    return {item["key"]: scalar(item["value"]) for item in items}


def any_value(value):
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, dict):
        return {"kvlistValue": {"values": kvpairs(value)}}
    raise AssertionError(f"unsupported fixture value: {value!r}")


def kvpairs(values):
    return [{"key": key, "value": any_value(value)} for key, value in values.items()]


def policy_code():
    definitions = []
    for name, log_code, context_code, _, _ in POLICIES:
        definitions.append(f'logs[{json.dumps(name)}] = function(event)\n'
                           'local body = event.body; local attrs = event.attributes; '
                           'local otlp = event.metadata:get("otlp")\n' + log_code + '\n' + context_code + '\nend\n')
    return 'local fb = require("fluentbit"); local logs = {}\n' + "\n".join(definitions) + '''
function process_log(event)
    if event.body:get_string("text") == "control" then return end
    local name = event.resource.attributes:get_string("policy.case")
    return logs[name](event)
end
'''


class PolicyRunner:
    def __init__(self, manager, listener_port):
        self.manager = manager
        self.listener_port = listener_port
        self.sequence = 0

    def wait_for_condition(self, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.1)
        raise AssertionError("timed out waiting for exported policy batch")

    def batches(self):
        text = Path(self.manager.log_file).read_text()
        return [json.loads(line) for line in text.splitlines(keepends=True)
                if line.startswith("{") and line.endswith("\n")]

    def payload(self, name, request):
        logs = []
        for i, text in enumerate(["operationA", "operationB", "control"]):
            attrs = {"request.id": request, "http.method": "get", "http.path": "/health",
                     "http.url": "http://localhost/health", "flags": "A|B|C" if i == 0 else "C|D",
                     "total.string": "123456789" if i == 0 else "345678"}
            body = {"text": text, "snake": "operation_a" if i == 0 else "operation_b",
                    "metadata": {"uid": "original"}}
            logs.append({"timeUnixNano": "2147483648123456789",
                         "observedTimeUnixNano": "2147483648234567890",
                         "severityNumber": 9, "severityText": "INFO", "flags": 1 if i == 0 else 2,

                         "eventName": "application.event",
                         "droppedAttributesCount": 1 if i == 0 else 2,
                         "traceId": "0102030405060708090a0b0c0d0e0f10", "spanId": "0102030405060708",
                         "attributes": kvpairs(attrs), "body": any_value(body)})
        return {"resourceLogs": [{
            "schemaUrl": "https://schema.example/original-resource",
            "resource": {"attributes": kvpairs({"host.name": "localhost", "policy.case": name,
                                                 "policy.request": request})},
            "scopeLogs": [{"scope": {"name": "scope", "version": "1", "attributes": []},
                           "schemaUrl": "https://schema.example/original-scope", "logRecords": logs}],
        }]}

    def send(self, payload):
        response = requests.post(f"http://127.0.0.1:{self.listener_port}/v1/logs",
                                 json=payload, timeout=15)
        assert response.status_code in (200, 201), response.text

    def collect(self, request):
        found = []
        for batch in self.batches():
            for resource in batch["resourceLogs"]:
                if attributes(resource["resource"]["attributes"]).get("policy.request") == request:
                    found.append(resource)
        if any(scalar(log["body"]).get("text") == "control"
               for resource in found for scope in resource["scopeLogs"] for log in scope["logRecords"]):
            return found
        return None

    def run(self, name):
        self.sequence += 1
        request = f"{name}-{self.sequence}"
        payload = self.payload(name, request)
        log_offset = len(Path(self.manager.log_file).read_text())
        self.send(payload)
        found = self.wait_for_condition(lambda: self.collect(request), timeout=30)
        if not name.startswith("bad_") and name not in ("rollback", "context_rollback"):
            diagnostics = Path(self.manager.log_file).read_text()[log_offset:]
            assert "cannot construct" not in diagnostics
            assert "policy failed" not in diagnostics
        return payload["resourceLogs"][0], found


@pytest.fixture(scope="module", params=["input", "output"])
def runner(request, tmp_path_factory):
    config = tmp_path_factory.mktemp("typed-policies") / "policies.yaml"
    processor = {"name": "fts", "code": policy_code(), "call": "process_log",
                 "error_mode": "keep"}
    source = {"name": "opentelemetry", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    (source if request.param == "input" else output)["processors"] = {"logs": [processor]}
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]},
    }))
    # A module-owned manager survives the suite's per-test active-service
    # cleanup. Fixture finalization still performs strict memory verification.
    listener_port = find_available_port()
    with pytest.MonkeyPatch.context() as env:
        env.setenv("FLUENT_BIT_TEST_LISTENER_PORT", str(listener_port))
        env.setenv("FLUENT_BIT_HTTP_MONITORING_PORT", "0")
        manager = FluentBitManager(str(config))
        try:
            manager.start()
            yield PolicyRunner(manager, listener_port)
        finally:
            manager.stop()


@pytest.mark.parametrize("policy", POLICIES, ids=[case[0] for case in POLICIES])
def test_log_policy_matrix(runner, policy):
    name, _, _, target, expected = policy
    original, resources = runner.run(name)
    if name.startswith("bad_"):
        assert "edits rolled back" in Path(runner.manager.log_file).read_text()
    pairs = [(resource, scope, log) for resource in resources for scope in resource["scopeLogs"]
             for log in scope["logRecords"]]
    logs = [log for _, _, log in pairs]
    expected_count = 3 - sum(expected) if target == "drop" else 3
    assert len(logs) == expected_count
    original_logs = original["scopeLogs"][0]["logRecords"]
    kept_indices = [i for i in range(3) if target != "drop" or i == 2 or not expected[i]]
    for i, (resource, scope, log) in zip(kept_indices, pairs):
        resource_attrs = attributes(resource["resource"]["attributes"])
        scope_attrs = attributes(scope["scope"].get("attributes", []))
        if target == "resource":
            assert resource_attrs.get("test") == (expected if i < 2 else None)
        if target == "scope":
            assert scope_attrs.get("test") == (expected if i < 2 else None)
        if target == "resource_schema":
            assert resource["schemaUrl"] == (expected if i < 2 else original["schemaUrl"])
        if target == "scope_schema":
            assert scope["schemaUrl"] == (expected if i < 2 else original["scopeLogs"][0]["schemaUrl"])
        if target in ("scope_name", "scope_version"):
            key = target.split("_")[1]
            assert scope["scope"][key] == (expected if i < 2 else original["scopeLogs"][0]["scope"][key])
        original_log = original_logs[i]
        if target == "producer":
            assert resource_attrs.get("service.name") == (expected[i] if i < 2 else None)
        if target == "scope_name_record":
            assert scope["scope"]["name"] == (expected[i] if i < 2 else "scope")
        baseline_attrs = attributes(original_log["attributes"])
        actual_attrs = attributes(log["attributes"])
        baseline_body = scalar(original_log["body"])
        actual_body = scalar(log["body"])
        wanted_attrs = copy.deepcopy(baseline_attrs)
        wanted_body = copy.deepcopy(baseline_body)
        if i < 2:
            value = expected[i] if isinstance(expected, list) else expected
            if target in ("attrs", "bytes") and value is not None:
                wanted_attrs["test"] = value
            elif target == "http.method":
                wanted_attrs["http.method"] = value
            elif target == "rename":
                wanted_attrs["url"] = wanted_attrs.pop("http.url")
            elif target == "delete" and value:
                wanted_attrs.pop("http.url")
            elif target == "delete_matching":
                wanted_attrs.pop("http.method")
                wanted_attrs.pop("http.path")
            elif target == "keep":
                wanted_attrs = {k: v for k, v in wanted_attrs.items() if k in ("http.method", "request.id")}
            elif target == "empty":
                wanted_attrs = {"request.id": wanted_attrs["request.id"]}
            elif target == "merge_insert":
                wanted_attrs["json_test"] = value
            elif target == "merge_upsert":
                wanted_attrs.update({"http.method": "post", "new": value})
            elif target == "nested":
                wanted_body["metadata"]["uid"] = value
            elif target == "tenant":
                wanted_attrs["tenant.id"] = value
                assert "tenant.id" not in resource_attrs
            elif target == "json_normalize":
                wanted_attrs["customer"] = value
            elif target == "privacy":
                wanted_body["sanitized"] = {"Authorization": "[REDACTED]",
                    "nested": {"password": "[REDACTED]"}, "headers": [{"AUTHORIZATION": "[REDACTED]"}]}

        assert actual_attrs == wanted_attrs
        assert actual_body == wanted_body
        for field in ("timeUnixNano", "observedTimeUnixNano", "severityText", "severityNumber",
                      "traceId", "spanId", "flags", "droppedAttributesCount", "eventName"):
            wanted = expected[i] if target == field and i < 2 else original_log[field]
            if name == "field_zero" and field == "flags" and i < 2:
                wanted = 0
            if target == "flags" and field == "flags" and i < 2:
                wanted = expected[i]
            if target == "named_severity" and i < 2:
                if field == "severityNumber": wanted = 13
                if field == "severityText": wanted = "Warning"
            if target == "correlation" and i < 2:
                if field == "traceId": wanted = "abcdef0123456789abcdef0123456789"
                if field == "spanId": wanted = "abcdef0123456789"
            if target == "json_normalize" and i < 2:
                if field == "severityNumber": wanted = 9
                if field == "severityText": wanted = "Information"
            assert log[field] == wanted, (name, field, log[field], wanted)
    # The final control record proves that the batch was flushed, including
    # policies that drop every selected record or fail their callback.
    assert scalar(logs[-1]["body"])["text"] == "control"


def test_concurrent_requests_preserve_context(runner):
    payloads = [runner.payload("resource_set", f"concurrent-{i}") for i in range(8)]
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(runner.send, payloads))
    for i in range(8):
        resources = runner.wait_for_condition(lambda: runner.collect(f"concurrent-{i}"), timeout=30)
        pairs = [(attributes(resource["resource"]["attributes"]), scalar(log["body"]))
                 for resource in resources for scope in resource["scopeLogs"] for log in scope["logRecords"]]
        assert [body["text"] for _, body in pairs] == ["operationA", "operationB", "control"]
        assert [attrs.get("test") for attrs, _ in pairs] == ["pass", "pass", None]

@pytest.mark.parametrize("policy,field", [("producer_from_record", "resource"), ("scope_from_record", "scope")])
def test_interleaved_producers_preserve_event_order(runner, policy, field):
    request = f"interleaved-{policy}"
    payload = runner.payload(policy, request)
    logs = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    logs.insert(2, copy.deepcopy(logs[0]))
    runner.send(payload)
    resources = runner.wait_for_condition(lambda: runner.collect(request))
    rows = [(resource, scope, scalar(log["body"])["text"])
            for resource in resources for scope in resource["scopeLogs"] for log in scope["logRecords"]]
    assert [text for _, _, text in rows] == ["operationA", "operationB", "operationA", "control"]
    for resource, scope, text in rows[:-1]:
        if field == "resource":
            assert attributes(resource["resource"]["attributes"])["service.name"] == text
        else:
            assert scope["scope"]["name"] == text

@pytest.mark.parametrize("policy", ["producer_from_record", "scope_from_record", "named_severity", "correlation"])
def test_protobuf_ingestion_preserves_context_and_exact_time(runner, policy):
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
    request_id = f"protobuf-{policy}"
    payload = runner.payload(policy, request_id)
    original = payload["resourceLogs"][0]
    message = ExportLogsServiceRequest()
    resource = message.resource_logs.add()
    for key, value in attributes(original["resource"]["attributes"]).items():
        attr = resource.resource.attributes.add(); attr.key = key; attr.value.string_value = value
    resource.schema_url = original["schemaUrl"]
    scope = resource.scope_logs.add(); scope.scope.name = "scope"; scope.scope.version = "1"
    scope.schema_url = original["scopeLogs"][0]["schemaUrl"]
    for i, source in enumerate(original["scopeLogs"][0]["logRecords"]):
        log = scope.log_records.add()
        log.time_unix_nano = int(source["timeUnixNano"])
        log.observed_time_unix_nano = int(source["observedTimeUnixNano"])
        log.severity_number = 9; log.severity_text = "INFO"; log.flags = 257
        log.dropped_attributes_count = i + 1
        log.trace_id = bytes.fromhex(source["traceId"]); log.span_id = bytes.fromhex(source["spanId"])
        for key, value in scalar(source["body"]).items():
            item = log.body.kvlist_value.values.add(); item.key = key
            if isinstance(value, str): item.value.string_value = value
            else:
                child = item.value.kvlist_value.values.add(); child.key = "uid"; child.value.string_value = "original"
        for key, value in attributes(source["attributes"]).items():
            item = log.attributes.add(); item.key = key; item.value.string_value = value
    response = requests.post(f"http://127.0.0.1:{runner.listener_port}/v1/logs",
                             data=message.SerializeToString(), headers={"Content-Type":"application/x-protobuf"},
                             timeout=15)
    assert response.status_code in (200, 201), response.text
    resources = runner.wait_for_condition(lambda: runner.collect(request_id))
    pairs = [(resource, scope, log) for resource in resources for scope in resource["scopeLogs"]
             for log in scope["logRecords"]]
    assert [scalar(log["body"])["text"] for _, _, log in pairs] == ["operationA", "operationB", "control"]
    for i, (resource, scope, log) in enumerate(pairs):
        assert log["timeUnixNano"] == "2147483648123456789"
        assert log["observedTimeUnixNano"] == "2147483648234567890"
        assert log["flags"] == 1 and log["droppedAttributesCount"] == i + 1
        if policy == "producer_from_record":
            assert attributes(resource["resource"]["attributes"]).get("service.name") == (
                ["operationA", "operationB"][i] if i < 2 else None)
        if policy == "scope_from_record":
            assert scope["scope"]["name"] == ["operationA", "operationB", "scope"][i]
        assert log["severityNumber"] == (13 if policy == "named_severity" and i < 2 else 9)
        assert log["traceId"] == ("abcdef0123456789abcdef0123456789" if policy == "correlation" and i < 2
                                  else "0102030405060708090a0b0c0d0e0f10")


def test_adjacent_scopes_share_resource_without_reordering(runner):
    request_id = "adjacent-scopes"
    payload = runner.payload("set", request_id)
    scopes = payload["resourceLogs"][0]["scopeLogs"]
    for name in ["second", "third"]:
        scope = copy.deepcopy(scopes[0]); scope["scope"]["name"] = name; scopes.append(scope)
    runner.send(payload)
    resources = runner.wait_for_condition(lambda: runner.collect(request_id))
    assert len(resources) == 1
    assert [scope["scope"]["name"] for scope in resources[0]["scopeLogs"]] == ["scope", "second", "third"]
    assert all(len(scope["logRecords"]) == 3 for scope in resources[0]["scopeLogs"])
