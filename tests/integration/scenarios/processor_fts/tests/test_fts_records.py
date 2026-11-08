"""Record commits preserve policy lifetimes, rollback and chain boundaries."""
import json
import socket
import time

from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService

from fts_test_utils import read_log


def start_service(tmp_path, code, placement, *, following=None, **options):
    processors = [{"name": "fts", "code": code, **options}]
    if following:
        processors.append(following)
    source = {"name": "forward", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "tag": "stream"}
    output = {"name": "stdout", "match": "*", "format": "json_lines"}
    (source if placement == "input" else output)["processors"] = {"logs": processors}
    config = tmp_path / "records.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    service = FluentBitTestService(str(config))
    service.start()
    return service


def log_text(service, *expected):
    return read_log(service.flb.log_file, *expected)


def rows(service):
    return [json.loads(line) for line in log_text(service).splitlines(keepends=True)
            if line.startswith("{") and line.endswith("\n")]


class Raw(bytes):
    """Preencoded MessagePack value."""


def event_time(seconds):
    return Raw(b"\xd7\x00" + seconds.to_bytes(4, "big") + bytes(4))


def pack(value):
    """Encode fixture values without an optional MessagePack dependency."""
    if isinstance(value, Raw):
        return bytes(value)
    if isinstance(value, int):
        return b"\xcf" + value.to_bytes(8, "big")
    if isinstance(value, str):
        data = value.encode("utf-8")
        return b"\xdb" + len(data).to_bytes(4, "big") + data
    if isinstance(value, bytes):
        return b"\xc6" + len(value).to_bytes(4, "big") + value
    if isinstance(value, list):
        return b"\xdd" + len(value).to_bytes(4, "big") + b"".join(pack(item) for item in value)
    if isinstance(value, dict):
        return b"\xdf" + len(value).to_bytes(4, "big") + b"".join(
            pack(key) + pack(item) for key, item in value.items())
    raise TypeError(type(value))


def send(service, records):
    if isinstance(records, dict):
        records = [records]
    packed = b"".join(pack([1700000000, record]) for record in records)
    message = pack(["stream", packed, {"size": len(records)}])
    with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as connection:
        connection.sendall(message)


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("decoder", ["try_parse_json", "unpack_json"])
def test_json_embedded_messages(tmp_path, placement, decoder):
    """Parse or unpack mixed JSON and plain messages without losing exact integers."""
    code = '''
      local fb = require("fluentbit")
      function process(log)
        local app, err = fb.try_parse_json(log.body:get_string("message"))
        if not app then
          assert(type(err) == "string")
          return
        end
        assert(err == nil)
        if app:type() ~= "map" then return end
        fb.redact(app, {"authorization", "password"})
        log.body = app
      end
    '''
    if decoder == "unpack_json":
        code = '''
          local fb = require("fluentbit")
          function process(log)
            fb.unpack_json(log, "message")
            fb.redact(log.body, {"authorization", "password"})
          end
        '''
    records = [
        {"message": json.dumps({"level": "error", "user": "ana", "password": "secret",
                                "nested": {"authorization": "Bearer token"}})},
        {"message": "plain text line"},
        {"message": '{"level":"info","order_id":9007199254740993}'},
        {"message": '{"order_id":18446744073709551615}'},
        {"message": ' \n\t{"ok":true}'},
        {"message": '{"broken":'},
        {"message": '{"duplicate":1,"duplicate":2}'},
        {"message": '{} trailing'},
        {"message": '18446744073709551616'},
        {"message": ""},
        {"other": "missing message"},
        {"message": "null"},
        {"message": "false"},
        {"message": '[{"password":"secret"}]'},
        {"message": '"JSON string"'},
    ]
    expected = [
        {"level": "error", "user": "ana", "password": "[REDACTED]",
         "nested": {"authorization": "[REDACTED]"}},
        records[1],
        {"level": "info", "order_id": 9007199254740993},
        {"order_id": 18446744073709551615},
        {"ok": True},
        *records[5:],
    ]
    if decoder == "unpack_json":
        records.append({"message": 42})
        expected.append({"message": 42})
    service = start_service(tmp_path, code, placement)
    try:
        send(service, records)
        output = service.wait_for_condition(
            lambda: rows(service) if len(rows(service)) >= len(expected) else None,
            timeout=45, description="decoded embedded JSON messages")
        assert [{key: value for key, value in row.items() if key != "date"}
                for row in output] == expected
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_json_fields_decode_in_place(tmp_path, placement):
    """Body, nested map, and array fields use the same decoder and keep siblings."""
    code = '''
      local fb = require("fluentbit")
      function process(log)
        fb.decode_json(log.body, "message")
        fb.decode_json(log.body:get("attributes"), "payload")
        fb.decode_json(log.body:get("values"), 1)
        fb.redact(log.body, {"password"})
      end
    '''
    fixtures = [
        ('{"nested":{"password":"secret"}}', {"nested": {"password": "[REDACTED]"}}),
        ('{"id":9007199254740993}', {"id": 9007199254740993}),
        ('[1,2]', [1, 2]),
        ('null', None),
        ('false', False),
        ('18446744073709551615', 18446744073709551615),
        ('"text"', "text"),
        ('plain text', 'plain text'),
        ('{"broken":', '{"broken":'),
        ('{"a":1,"a":2}', '{"a":1,"a":2}'),
        (42, 42),
    ]
    records = [{"message": text, "host": "web", "attributes": {"payload": text, "keep": "s"},
                "values": [text, "sibling"]} for text, _ in fixtures]
    expected = [{"message": value, "host": "web", "attributes": {"payload": value, "keep": "s"},
                 "values": [value, "sibling"]} for _, value in fixtures]
    service = start_service(tmp_path, code, placement)
    try:
        send(service, records)
        output = service.wait_for_condition(
            lambda: rows(service) if len(rows(service)) >= len(expected) else None,
            timeout=45, description="decoded fields with preserved siblings")
        assert [{key: value for key, value in row.items() if key != "date"}
                for row in output] == expected
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("chain", ["direct", "filter", "native", "replacement"])
@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_records_commits_and_retained_views(tmp_path, placement, chain, error_mode):
    code = '''
      local fb = require("fluentbit")
      local previous, stale
      function process(log)
        if stale then
          -- Record handles expire with their callback; copy() keeps values.
          assert(not pcall(function() return stale.body:get_string("text") end))
          assert(not pcall(function() stale.metadata:set("late", true) end))
        end
        if previous then
          assert(previous.body:get_string("text") == "committed")
          previous.body:set("text", "late mutation")
          previous.body:get("values"):set(1, "late mutation")
          previous.metadata:set("late", true)
          previous.timestamp.sec = 1
        end
        assert(log.timestamp.sec ~= 1)
        assert(log.metadata:get("late") == nil)
        local index = log.body:get_number("index")
        if REPLACE then log.body = log.body:get("nested") end
        log.body:set("text", "committed")
        log.body:set("exact", fb.uint64("18446744073709551615"))
        log.body:set("bytes", fb.bytes("a\\0b"))
        log.body:set("empty", fb.array())
        fb.redact(log.body, {"password"})
        previous = {body = log.body:copy(), metadata = log.metadata:copy(),
                    timestamp = log.timestamp}
        stale = log
        if index == 2 then error("expected item failure") end
        if index == 4 then return fb.DROP end
      end
    '''.replace("REPLACE", "true" if chain == "replacement" else "false")
    following = None
    if chain == "filter":
        following = {"name": "grep", "regex": "text ^(original|committed)$"}
    elif chain == "native":
        following = {"name": "content_modifier", "context": "body", "action": "insert",
                     "key": "following", "value": "native"}
    service = start_service(tmp_path, code, placement, following=following, error_mode=error_mode)
    try:
        batch = []
        for index in range(10):
            body = {"index": index, "text": "original", "password": "secret", "values": ["original"]}
            batch.append({**body, "nested": dict(body)})
        send(service, batch)
        expected = [index for index in range(10) if index != 4 and
                    (error_mode == "keep" or index != 2)]
        output = service.wait_for_condition(lambda: rows(service) if len(rows(service)) >= len(expected)
                                            else None, timeout=45)
        assert [row["index"] for row in output] == expected
        for row in output:
            failed = row["index"] == 2
            assert row["text"] == ("original" if failed else "committed")
            assert row["values"] == ["original"]
            assert row["date"] == 1700000000.0
            assert row["password"] == ("secret" if failed else "[REDACTED]")
            if not failed:
                assert row["exact"] == 18446744073709551615
                assert row["bytes"] == "a\0b"
                assert row["empty"] == []
            if chain == "native":
                assert row["following"] == "native"
        diagnostics = log_text(service, "expected item failure")
        assert "cannot construct" not in diagnostics
        assert diagnostics.count("log policy failed:") == 1
        assert "expected item failure" in diagnostics
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_large_batch_edits_and_rollbacks_stay_record_local(tmp_path, placement, error_mode):
    """Edits and rollbacks in a batch whose decoded records exceed the chunk value pool."""
    code = '''
      local fb = require("fluentbit")
      function process(log)
        local index = log.body:get_number("index")
        log.body:remove("password")
        log.body:get("nested"):set("state", "edited")
        log.body:get("values"):append(index)
        log.body:set("note", string.rep("n", index % 50 == 0 and 20000 or 8))
        if index % 97 == 5 then error("expected item failure") end
      end
    '''
    service = start_service(tmp_path, code, placement, error_mode=error_mode)
    try:
        count = 3000
        batch = [{"index": index, "password": "secret", "text": "x" * 64,
                  "nested": {"state": "original", "keep": index}, "values": ["first"]}
                 for index in range(count)]
        send(service, batch)
        expected = [index for index in range(count)
                    if error_mode == "keep" or index % 97 != 5]
        output = service.wait_for_condition(
            lambda: rows(service) if len(rows(service)) >= len(expected) else None, timeout=90)
        assert [row["index"] for row in output] == expected
        for row in output:
            index = row["index"]
            assert row["text"] == "x" * 64
            assert row["nested"]["keep"] == index
            if index % 97 == 5:
                assert row["password"] == "secret"
                assert row["nested"]["state"] == "original"
                assert row["values"] == ["first"]
                assert "note" not in row
            else:
                assert "password" not in row
                assert row["nested"]["state"] == "edited"
                assert row["values"] == ["first", index]
                assert len(row["note"]) == (20000 if index % 50 == 0 else 8)
        assert "cannot construct" not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("error_mode", ["keep", "drop"])
@pytest.mark.parametrize("chain", ["direct", "native"])
def test_records_output_limit_rolls_back_complete_batch(tmp_path, placement, error_mode, chain):
    # The native chain edits chunk values in place; failure must restore every record,
    # including removed trailing keys, before the following processor runs.
    code = '''local saved; function process(log)
      if saved then saved:set("edited", false) end
      saved = log.body:copy()
      log.body:remove("text")
      log.body:set("edited", true)
      if log.body:get_number("index") == 599 then
        log.body:set("large", string.rep("x", 70000))
      end
    end'''
    following = None
    if chain == "native":
        following = {"name": "content_modifier", "context": "body", "action": "insert",
                     "key": "following", "value": "native"}
    service = start_service(tmp_path, code, placement, following=following,
                            error_mode=error_mode, output_limit="65536")
    try:
        send(service, [{"index": index, "text": "original"} for index in range(600)])
        service.wait_for_condition(lambda: "cannot construct policy output" in log_text(service),
                                   timeout=45)
        if error_mode == "keep":
            output = service.wait_for_condition(lambda: rows(service) if len(rows(service)) == 600
                                                else None, timeout=45)
            assert [row["index"] for row in output] == list(range(600))
            assert all("edited" not in row and "large" not in row for row in output)
            assert all(row["text"] == "original" for row in output)
            assert all(row.get("following") == ("native" if chain == "native" else None)
                       for row in output)
        # Stop flushes all pending output, so drop assertions cannot pass early.
        service.stop()
        if error_mode == "drop":
            assert rows(service) == []
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_records_edit_fits_single_tree_budget(tmp_path, placement):
    service = start_service(tmp_path, 'function process(log) log.body:set("edited", true) end',
                            placement, memory_limit="262144", error_mode="keep")
    try:
        send(service, {"payload": "x" * 120000})
        output = service.wait_for_condition(lambda: rows(service), timeout=45)
        assert len(output) == 1
        assert output[0]["edited"] is True
        assert output[0]["payload"] == "x" * 120000
        diagnostics = log_text(service)
        assert "policy failed" not in diagnostics and "cannot construct" not in diagnostics
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_records_depth_error_is_item_local(tmp_path, placement, error_mode):
    code = '''local fb = require("fluentbit")
      function process(log)
        fb.redact(log.body, {"password"})
        log.body:set("edited", true)
        if log.body:get_number("index") == 1 then
          local nested = fb.map()
          for i = 1,63 do
            local parent = fb.map(); parent:set("next", nested); nested = parent
          end
          log.body:set("deep", nested)
        end
      end'''
    service = start_service(tmp_path, code, placement, error_mode=error_mode)
    try:
        send(service, [{"index": index, "password": "secret"} for index in range(3)])
        expected = [0, 1, 2] if error_mode == "keep" else [0, 2]
        output = service.wait_for_condition(lambda: rows(service) if len(rows(service)) >= len(expected)
                                            else None, timeout=45)
        assert [row["index"] for row in output] == expected
        for row in output:
            assert "deep" not in row
            assert row["password"] == ("secret" if row["index"] == 1 else "[REDACTED]")
            assert ("edited" in row) == (row["index"] != 1)
        diagnostics = log_text(service, "log policy failed:")
        assert "cannot construct policy output" not in diagnostics
        assert diagnostics.count("log policy failed:") == 1
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_failed_records_do_not_poison_later_redactions(tmp_path, placement):
    code = '''local fb = require("fluentbit")
      function process(log)
        log.body:set("temporary", string.rep("x", 4096))
        if log.body:get_number("index") % 100 ~= 99 then error("expected rejection") end
        log.body:remove("temporary")
        fb.redact(log.body, {"password"})
      end'''
    service = start_service(tmp_path, code, placement, error_mode="drop", memory_limit="262144")
    try:
        send(service, [{"index": index, "password": "secret"} for index in range(2000)])
        # Wait for the complete output and its diagnostics together: slow
        # memory-checker runs can emit them in separate flushes.
        def ready():
            output = rows(service)
            if len(output) >= 20 and "expected rejection" in log_text(service):
                return output
            return None

        output = service.wait_for_condition(ready, timeout=120)
        assert [row["index"] for row in output] == list(range(99, 2000, 100))
        assert all(row["password"] == "[REDACTED]" and "temporary" not in row for row in output)
        diagnostics = log_text(service, "expected rejection")
        assert "cannot construct" not in diagnostics
        assert "memory limit" not in diagnostics
        assert "expected rejection" in diagnostics
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_empty_body_and_metadata_fork_on_first_write(tmp_path, placement):
    code = '''local previous
      function process(log)
        if previous then previous:ensure_map("nested"):set("value", "late") end
        assert(log.body:len() == 0 and log.metadata:len() == 0)
        log.body:ensure_map("nested"):set("value", "body")
        assert(log.metadata:len() == 0)
        log.metadata:ensure_map("nested"):set("value", "metadata")
        assert(log.body:get("nested"):get_string("value") == "body")
        previous = log.body:copy()
      end'''
    service = start_service(tmp_path, code, placement)
    try:
        send(service, [{}, {}])
        output = service.wait_for_condition(lambda: rows(service) if len(rows(service)) >= 2
                                            else None, timeout=45)
        assert [row["nested"] for row in output] == [{"value": "body"}, {"value": "body"}]
        diagnostics = log_text(service)
        assert "policy failed" not in diagnostics and "cannot construct" not in diagnostics
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("chain", ["direct", "native"])
def test_view_cache_follows_writes(tmp_path, placement, chain):
    # Views cache their resolved node; every write must invalidate that cache.
    code = r'''local fb = require("fluentbit")
      local stale
      function process(log)
        if stale then assert(not pcall(function() return stale:get_string("p") end)) end
        local b = log.body
        local h = b:get("h")
        assert(h:get_string("p") == "x")
        b:get("h"):set("p", "y")
        assert(h:get_string("p") == "y")
        b:remove("h")
        assert(not pcall(function() return h:get_string("p") end))
        b:set("h", fb.map())
        b:get("h"):set("p", "z")
        assert(h:get_string("p") == "z")
        local first = b:get("values"):get(1)
        b:get("values"):set(1, "b")
        assert(first:value() == "b")
        local copy = b:copy()
        local copied = copy:get("h")
        b:get("h"):set("p", "w")
        assert(copied:get_string("p") == "z")
        stale = b:get("h")
      end'''
    following = None
    if chain == "native":
        following = {"name": "content_modifier", "context": "body", "action": "insert",
                     "key": "following", "value": "native"}
    service = start_service(tmp_path, code, placement, following=following)
    try:
        send(service, [{"index": index, "h": {"p": "x"}, "values": ["a"]} for index in range(3)])
        output = service.wait_for_condition(lambda: rows(service) if len(rows(service)) >= 3
                                            else None, timeout=45)
        assert [row["h"] for row in output] == [{"p": "w"}] * 3
        assert [row["values"] for row in output] == [["b"]] * 3
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("chain", ["direct", "native"])
def test_untouched_bodies_keep_original_values(tmp_path, placement, chain):
    # Plain-log bodies are built only when a policy uses them; untouched bodies
    # must leave the pipeline exactly as they arrived.
    code = r'''local fb = require("fluentbit")
      function process(log)
        local index = log.timestamp.sec % 10
        if index == 1 then log.timestamp.sec = log.timestamp.sec + 100 end
        if index == 2 then log.metadata:set("seen", true) end
        if index == 3 then return fb.DROP end
        if index == 4 then assert(log.body:get_string("text") == "original") end
        if index == 5 then log.body = log.body:get("nested") end
      end'''
    following = None
    if chain == "native":
        following = {"name": "content_modifier", "context": "body", "action": "insert",
                     "key": "following", "value": "native"}
    service = start_service(tmp_path, code, placement, following=following)
    try:
        records = [{"text": "original", "big": 18446744073709551615, "bytes": b"a\0b",
                    "nested": {"inner": "value", "list": [1, "two"]}} for _ in range(6)]
        packed = b"".join(pack([1700000000 + index, record]) for index, record in enumerate(records))
        message = pack(["stream", packed, {"size": len(records)}])
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as conn:
            conn.sendall(message)
        output = service.wait_for_condition(lambda: rows(service) if len(rows(service)) >= 5
                                            else None, timeout=45)
        extra = {"following": "native"} if chain == "native" else {}
        full = {"text": "original", "big": 18446744073709551615, "bytes": "a\0b",
                "nested": {"inner": "value", "list": [1, "two"]}, **extra}
        assert [row["date"] for row in output] == [1700000000.0, 1700000101.0, 1700000002.0,
                                                   1700000004.0, 1700000005.0]
        for position, row in enumerate(output[:4]):
            row.pop("date")
            # stdout renders record metadata under __internal__.
            metadata = row.pop("__internal__", {}).get("log_metadata")
            assert metadata == ({"seen": True} if position == 2 else None)
            assert row == full
        nested = output[4]
        nested.pop("date")
        assert nested == {"inner": "value", "list": [1, "two"], **extra}
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()


NESTED_RECORD = {"top": "t", "n": {"a": {"b": "deep", "list": [{"x": 1}, [2, "three"]]}, "pw": "secret"},
                 "arr": [{"pw": "s1"}, {"k": "v"}]}
NESTED_CASES = {
    "read": ('assert(log.body:get("n"):get("a"):get_string("b") == "deep")', NESTED_RECORD),
    "write": ('log.body:get("n"):get("a"):set("b", "changed")',
              {**NESTED_RECORD, "n": {"a": {"b": "changed", "list": [{"x": 1}, [2, "three"]]},
                                      "pw": "secret"}}),
    "redact": ('fb.redact(log.body, {"pw"})',
               {**NESTED_RECORD, "n": {**NESTED_RECORD["n"], "pw": "[REDACTED]"},
                "arr": [{"pw": "[REDACTED]"}, {"k": "v"}]}),
    "append": ('log.body:get("n"):get("a"):get("list"):append("x")',
               {**NESTED_RECORD, "n": {"a": {"b": "deep", "list": [{"x": 1}, [2, "three"], "x"]},
                                       "pw": "secret"}}),
    "replace": ('log.body:set("n", "flat")', {**NESTED_RECORD, "n": "flat"}),
    "copy": ('log.body:set("dup", log.body:get("n"))', {**NESTED_RECORD, "dup": NESTED_RECORD["n"]}),
}


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("case", list(NESTED_CASES))
def test_nested_values_open_on_demand(tmp_path, placement, case):
    # Nested plain-log containers are built only when a policy opens them.
    statement, expected = NESTED_CASES[case]
    code = 'local fb = require("fluentbit")\nfunction process(log) ' + statement + ' end'
    service = start_service(tmp_path, code, placement)
    try:
        send(service, [NESTED_RECORD, NESTED_RECORD])
        output = service.wait_for_condition(lambda: rows(service) if len(rows(service)) >= 2
                                            else None, timeout=45)
        for row in output:
            row.pop("date")
            assert row == expected
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()


def test_failed_chunk_encoding_does_not_leak_records(tmp_path):
    """A chunk that cannot be encoded must not reach the next chunk's tag."""
    processors = [{"name": "fts", "code": "function process(log) end"},
                  {"name": "content_modifier", "action": "insert", "key": "added", "value": "v"}]
    source = {"name": "forward", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
              "processors": {"logs": processors}}
    output = {"name": "stdout", "match": "tagtwo", "format": "json_lines"}
    config = tmp_path / "encode.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    service = FluentBitTestService(str(config))
    service.start()
    try:
        # The second record carries a millisecond timestamp outside the event time range.
        first = pack([1700000000, {"msg": "one"}]) + pack([1700000000123, {"msg": "bad"}])
        second = pack([1700000001, {"msg": "two"}])
        for message in (pack(["tagone", first, {"size": 2}]), pack(["tagtwo", second, {"size": 1}])):
            with socket.create_connection(("127.0.0.1", service.flb_listener_port),
                                          timeout=30) as connection:
                connection.sendall(message)
            time.sleep(0.5)
        service.wait_for_condition(lambda: rows(service), timeout=20,
                                   description="tagtwo output")
        time.sleep(1)
        assert [row["msg"] for row in rows(service)] == ["two"]
    finally:
        service.stop()


@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_missing_transport_ids_are_group_local(tmp_path, error_mode):
    """A group without transport IDs does not skip the policy for other groups."""
    service = start_service(tmp_path, "function process(log) log.body:set('edited', true) end",
                            "input", following={"name": "content_modifier", "action": "insert",
                                                "key": "native", "value": "v"},
                            error_mode=error_mode)
    try:
        start, end = event_time(0xFFFFFFFF), event_time(0xFFFFFFFE)
        now = event_time(1700000000)
        entries = [[[start, {"schema": "otlp", "resource_id": 0, "scope_id": 0}],
                    {"resource": {}, "scope": {"name": "good"}}],
                   [[now, {"otlp": {}}], {"msg": "healthy-otel"}],
                   [[end, {}], {}],
                   [[start, {"schema": "otlp"}], {"resource": {}, "scope": {"name": "bad"}}],
                   [[now, {"otlp": {}}], {"msg": "missing-ids"}],
                   [[end, {}], {}],
                   [[now, {}], {"msg": "healthy-plain"}]]
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as connection:
            connection.sendall(pack(["stream", entries]))
        output = service.wait_for_condition(lambda: rows(service) if len(rows(service)) >= 3 else None,
                                            timeout=20, description="three records")
        assert sorted(row["msg"] for row in output) == ["healthy-otel", "healthy-plain", "missing-ids"]
        assert all(row["edited"] is True and row["native"] == "v" for row in output)
        assert "cannot construct policy output" not in log_text(service)
    finally:
        service.stop()


def start_otlp_json_service(tmp_path, processors, placement="input"):
    """Start a forward-to-OTLP JSON pipeline with processors at the selected stage."""
    source = {"name": "forward", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "tag": "stream"}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    if processors:
        (source if placement == "input" else output)["processors"] = {"logs": processors}
    config = tmp_path / "otlp-json.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 1, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    service = FluentBitTestService(str(config))
    service.start()
    return service


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("invalid_context", [False, True])
def test_json_fields_decode_otel_attributes(tmp_path, placement, invalid_context):
    """Decode actual OTel attribute maps and verify their exported values."""
    code = '''
      local fb = require("fluentbit")
      function process(log)
        assert(fb.decode_json(log.attributes, "payload"))
        assert(fb.decode_json(log.resource.attributes, "labels"))
        fb.redact(log.attributes, {"password"})
        assert(log.body:get_string("message") == "body stays unchanged")
      end
    '''
    if invalid_context:
        code = code.replace('function process(log)', '''function process(log)
          local context = log.context
          local scratch = fb.map()
          local function decode()
            scratch:set("payload", "18446744073709551615")
            assert(fb.decode_json(scratch, "payload"))
            assert(scratch:get("payload"):value() == "18446744073709551615")
          end
          for _, value in ipairs({false, 42, "context", fb.map(), fb.array()}) do
            log.context = value
            decode()
          end
          log.context = nil
          decode()
          log.context = context
        ''', 1)
    service = start_otlp_json_service(tmp_path, [{"name": "fts", "code": code}], placement)
    try:
        start, end = event_time(0xFFFFFFFF), event_time(0xFFFFFFFE)
        now = event_time(1700000000)
        entries = [
            [[start, {"schema": "otlp", "resource_id": 0, "scope_id": 0}],
             {"resource": {"attributes": {"labels": '{"region":"east"}', "keep": "r"}},
              "scope": {"name": "json-test"}}],
            [[now, {"otlp": {"attributes": {
                "payload": '{"id":9007199254740993,"password":"secret"}', "keep": "a"}}}],
             {"message": "body stays unchanged"}],
            [[end, {}], {}],
        ]
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as connection:
            connection.sendall(pack(["stream", entries]))
        output = service.wait_for_condition(lambda: rows(service), timeout=45,
                                            description="decoded OTel attributes")
        resources = [resource for document in output for resource in document["resourceLogs"]]
        assert len(resources) == 1
        resource = resources[0]
        attrs = {item["key"]: item["value"] for item in resource["resource"]["attributes"]}
        assert attrs["keep"] == {"stringValue": "r"}
        assert attrs["labels"] == {"kvlistValue": {"values": [
            {"key": "region", "value": {"stringValue": "east"}}]}}
        logs = [log for scope in resource["scopeLogs"] for log in scope["logRecords"]]
        assert len(logs) == 1
        attrs = {item["key"]: item["value"] for item in logs[0]["attributes"]}
        assert attrs["keep"] == {"stringValue": "a"}
        payload = {item["key"]: item["value"]
                   for item in attrs["payload"]["kvlistValue"]["values"]}
        assert payload == {"id": {"intValue": "9007199254740993"},
                           "password": {"stringValue": "[REDACTED]"}}
        assert logs[0]["body"] == {"stringValue": "body stays unchanged"}
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
def test_json_otel_unsigned_bounds(tmp_path, placement):
    """OTLP decode rejects unsigned overflow before any field is changed."""
    code = '''
      local fb = require("fluentbit")
      function process(log)
        local allowed = log.body:get_number("allowed") == 1
        local function check(container, key)
          local original = container:get(key):value()
          local ok, err = fb.decode_json(container, key)
          assert(ok == allowed)
          if allowed then assert(err == nil)
          else
            assert(type(err) == "string")
            assert(container:get(key):value() == original)
          end
        end
        if log.body:get_string("operation") == "unpack" then
          local body = log.body
          local ok, err = fb.unpack_json(log, "encoded")
          assert(ok == allowed)
          if not allowed then assert(type(err) == "string" and log.body == body) end
        else
          check(log.body, "payload")
          check(log.body:get("nested"), "payload")
          check(log.body:get("values"), 1)
          check(log.attributes, "payload")
          check(log.resource.attributes, "payload")
          check(log.scope.attributes, "payload")
        end
        local scratch = fb.map()
        scratch:set("payload", "18446744073709551615")
        assert(fb.decode_json(scratch, "payload"))
        assert(scratch:get("payload"):value() == "18446744073709551615")
        log.body:set("checked", true)
      end
    '''

    def any_value(value):
        """Decode exported AnyValue fixtures without rounding integer strings."""
        if "kvlistValue" in value:
            return {item["key"]: any_value(item["value"])
                    for item in value["kvlistValue"]["values"]}
        if "arrayValue" in value:
            return [any_value(item) for item in value["arrayValue"]["values"]]
        if "intValue" in value:
            return int(value["intValue"])
        if "boolValue" in value:
            return value["boolValue"]
        return value["stringValue"]

    fixtures = []
    entries = []
    start, end = event_time(0xFFFFFFFF), event_time(0xFFFFFFFE)
    now = event_time(1700000000)
    for operation in ("decode", "unpack"):
        for number in (9223372036854775807, 9223372036854775808, 18446744073709551615):
            index = len(fixtures)
            allowed = number <= 9223372036854775807
            text = json.dumps({"outer": [{"id": number}]})
            body = {"operation": operation, "allowed": int(allowed), "encoded": text,
                    "payload": text, "nested": {"payload": text}, "values": [text]}
            attrs = {"payload": text, "record_id": str(index)}
            entries.extend([
                [[start, {"schema": "otlp", "resource_id": index, "scope_id": index}],
                 {"resource": {"attributes": dict(attrs)},
                  "scope": {"name": "bounds", "attributes": dict(attrs)}}],
                [[now, {"otlp": {"attributes": dict(attrs)}}], body],
                [[end, {}], {}],
            ])
            fixtures.append((operation, allowed, text, body))

    service = start_otlp_json_service(tmp_path, [{"name": "fts", "code": code}], placement)
    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as connection:
            connection.sendall(pack(["stream", entries]))
        output = service.wait_for_condition(
            lambda: rows(service) if sum(len(scope["logRecords"])
                for document in rows(service) for resource in document["resourceLogs"]
                for scope in resource["scopeLogs"]) >= len(fixtures) else None,
            timeout=45, description="OTLP records with recoverable JSON overflow")
        seen = []
        for document in output:
            for resource in document["resourceLogs"]:
                for scope in resource["scopeLogs"]:
                    for log in scope["logRecords"]:
                        attrs = {item["key"]: any_value(item["value"]) for item in log["attributes"]}
                        index = int(attrs["record_id"])
                        seen.append(index)
                        operation, allowed, text, body = fixtures[index]
                        value = json.loads(text) if allowed else text
                        expected = dict(body)
                        if operation == "decode":
                            expected.update(payload=value, nested={"payload": value}, values=[value])
                        elif allowed:
                            expected = json.loads(text)
                        expected["checked"] = True
                        assert any_value(log["body"]) == expected
                        for attributes in (log["attributes"], resource["resource"]["attributes"],
                                           scope["scope"]["attributes"]):
                            decoded = {item["key"]: any_value(item["value"]) for item in attributes}
                            assert decoded["payload"] == (value if operation == "decode" else text)
        assert sorted(seen) == list(range(len(fixtures)))
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()


def otlp_resources(service):
    """(resource attributes, record bodies) for every exported resource."""
    resources = []
    for line in log_text(service).splitlines(keepends=True):
        if not line.startswith("{") or not line.endswith("\n"):
            continue
        for resource in json.loads(line)["resourceLogs"]:
            attrs = [(item["key"], item["value"]) for item in
                     resource.get("resource", {}).get("attributes", [])]
            bodies = [{item["key"]: item["value"] for item in log["body"]["kvlistValue"]["values"]}
                      for scope in resource["scopeLogs"] for log in scope["logRecords"]]
            resources.append((attrs, bodies))
    return resources


def raw_map(pairs):
    """Map with explicit, possibly duplicated, keys."""
    return Raw(b"\xdf" + len(pairs).to_bytes(4, "big") +
               b"".join(pack(key) + pack(value) for key, value in pairs))


@pytest.mark.parametrize("chain", ["fts", "content_modifier", "fts_and_content_modifier"])
def test_groups_split_across_appends_keep_their_records(tmp_path, chain):
    """A group whose end arrives in a later append keeps every record."""
    fts = {"name": "fts", "code": "function process(log) log.body:set('edited', true) end"}
    modifier = {"name": "content_modifier", "action": "insert", "key": "native", "value": "v"}
    processors = {"fts": [fts], "content_modifier": [modifier],
                  "fts_and_content_modifier": [fts, modifier]}[chain]
    service = start_otlp_json_service(tmp_path, processors)
    try:
        start, end = event_time(0xFFFFFFFF), event_time(0xFFFFFFFE)
        now = event_time(1700000000)
        head = [[[start, {"schema": "otlp", "resource_id": 0, "scope_id": 0}],
                 {"resource": {"attributes": {"service.name": "split"}}, "scope": {"name": "s"}}],
                [[now, {"otlp": {}}], {"msg": "r1"}]]
        tail = [[[now, {"otlp": {}}], {"msg": "r2"}], [[end, {}], {}]]
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as connection:
            connection.sendall(pack(["stream", head]))
            time.sleep(0.1)
            connection.sendall(pack(["stream", tail]))
        resources = service.wait_for_condition(
            lambda: otlp_resources(service) if sum(len(b) for _, b in otlp_resources(service)) >= 2
            else None, timeout=20, description="two exported records")
        # both records stay in the resource opened by the first append
        assert len(resources) == 1
        attrs, bodies = resources[0]
        assert attrs == [("service.name", {"stringValue": "split"})]
        assert [body["msg"]["stringValue"] for body in bodies] == ["r1", "r2"]
        for body in bodies:
            if "fts" in chain:
                assert body["edited"] == {"boolValue": True}
            if "content_modifier" in chain:
                assert body["native"] == {"stringValue": "v"}
        assert "cannot construct policy output" not in log_text(service)
    finally:
        service.stop()


def test_duplicate_resource_attributes_collapse_on_edit(tmp_path):
    """Setting a duplicated resource attribute exports a single value."""
    fts = {"name": "fts", "code": '''function process(log)
      log.context.attributes:get("resource"):get("attributes"):set("service.name", "a")
    end'''}
    service = start_otlp_json_service(tmp_path, [fts])
    try:
        start, end = event_time(0xFFFFFFFF), event_time(0xFFFFFFFE)
        now = event_time(1700000000)
        attributes = raw_map([("service.name", "a"), ("service.name", "b")])
        entries = [[[start, {"schema": "otlp", "resource_id": 0, "scope_id": 0}],
                    {"resource": {"attributes": attributes}, "scope": {"name": "s"}}],
                   [[now, {"otlp": {}}], {"msg": "x"}],
                   [[end, {}], {}]]
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as connection:
            connection.sendall(pack(["stream", entries]))
        resources = service.wait_for_condition(lambda: otlp_resources(service), timeout=20,
                                               description="exported resource")
        assert resources[0][0] == [("service.name", {"stringValue": "a"})]
        assert "policy failed" not in log_text(service)
    finally:
        service.stop()
