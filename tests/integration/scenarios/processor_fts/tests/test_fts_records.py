"""Record commits preserve policy lifetimes, rollback and chain boundaries."""
import json
import socket
import time

from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService


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


def log_text(service):
    return Path(service.flb.log_file).read_text()


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
        diagnostics = log_text(service)
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
        diagnostics = log_text(service)
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
        diagnostics = log_text(service)
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
