"""Versioned recursive pack parameters use the real loader and typed callbacks."""
import copy
import json
from pathlib import Path

import pytest

from test_fts_packs import processor
from test_fts_recipes import config_file, rejected_startup
from test_fts_recipe_preflight import dry_run
from test_fts_records import send, rows
from utils.test_service import FluentBitTestService

from fts_test_utils import read_log


SPEC = {"config": {"type": "object", "default": {}, "fields": {
    "label": {"type": "string", "default": "default"},
    "enabled": {"type": "bool", "default": "true"},
    "count": {"type": "number", "integer": True, "minimum": 1, "maximum": 10, "default": 2},
    "value": {"type": "literal", "default": {"type": "int64", "value": "9223372036854775807"}},
    "rules": {"type": "array", "default": [{"name": "a"}, {"name": "b"}],
        "items": {"type": "object", "fields": {"name": {"type": "string", "required": True}}}}
}}}
SOURCE = '''return function(p)
    return function(log)
        log.body:set('label',p.config.label)
        log.body:set('enabled',p.config.enabled)
        log.body:set('count',fb.int64(p.config.count))
        log.body:set('value',fb.literal(p.config.value))
        local rules=fb.array()
        for _,rule in ipairs(p.config.rules) do rules:append(rule.name) end
        log.body:set('rules',rules)
        if log.body:get('fail') then error('wrong_type',0) end
    end
end'''


def create_pack(tmp_path, specs=None, source=SOURCE, version=2, extra_blocks=()):
    (tmp_path / "block.lua").write_text(source)
    manifest = {"pack_version": version, "fts_api_version": 1, "id": "org.fluentbit.observability",
        "version": "1.0.0", "blocks": [{"name": "redact_log", "signals": ["logs"],
            "source": "block.lua", "parameters": copy.deepcopy(SPEC if specs is None else specs)}, *extra_blocks]}
    (tmp_path / "pack.json").write_text(json.dumps(manifest))
    return processor(tmp_path)


def clean_rows(service, count):
    result = service.wait_for_condition(lambda: len(rows(service)) == count and rows(service), timeout=30)
    for record in result:
        record.pop("date", None)
    return result


def test_recursive_defaults_exact_literal_and_error_rollback(tmp_path):
    proc = create_pack(tmp_path)
    proc["error_mode"] = "keep"
    path = config_file(tmp_path, proc)
    status, _ = dry_run(path, tmp_path)
    assert status == 0
    service = FluentBitTestService(str(path))
    try:
        service.start()
        send(service, [{"control": 1}, {"fail": True}])
        assert clean_rows(service, 2) == [{"control": 1, "label": "default", "enabled": True,
            "count": 2, "value": 9223372036854775807, "rules": ["a", "b"]}, {"fail": True}]
    finally:
        service.stop()


@pytest.mark.parametrize("changes", [
    {"config": {"extra": "synthetic-private-value"}},
    {"config": {"rules": [{"name": 7}]}}, {"config": {"rules": [{}]}},
    {"config": {"rules": {"not": "array"}}}, {"config": {"count": 0}},
    {"config": {"count": 11}}, {"config": {"count": 1.5}},
    {"config": {"value": {"type": "int64", "value": "9223372036854775808"}}},
])
def test_nested_values_rejected_before_startup(tmp_path, changes):
    proc = create_pack(tmp_path)
    proc["recipe"][0]["with"] = changes
    path = config_file(tmp_path, proc)
    status, diagnostics = dry_run(path, tmp_path)
    assert status != 0
    assert "synthetic-private-value" not in diagnostics
    startup = rejected_startup(path, tmp_path)
    assert "class=invalid_configuration" in startup
    assert "synthetic-private-value" not in startup


@pytest.mark.parametrize("spec", [
    {"type": "object"}, {"type": "array"}, {"type": "object", "fields": False},
    {"type": "array", "items": {"type": "string", "required": False}},
    {"type": "array", "items": {"type": "string", "default": "x"}},
    {"type": "object", "fields": {}, "items": {"type": "string"}},
    {"type": "string", "fields": {}}, {"type": "string", "minimum": 1},
    {"type": "number", "minimum": 10, "maximum": 1},
    {"type": "number", "enum": ["1", "2"]},
    {"type": "number", "integer": "true"}, {"type": "string", "unknown": True},
])
def test_invalid_recursive_declarations_rejected_even_if_unused(tmp_path, spec):
    extra = {"name": "unused", "signals": ["logs"], "source": "block.lua", "parameters": {"invalid": spec}}
    proc = create_pack(tmp_path, extra_blocks=[extra])
    assert "class=invalid_configuration" in rejected_startup(config_file(tmp_path, proc), tmp_path)


@pytest.mark.parametrize("spec", [
    {"type": "object", "fields": {}, "default": "wrong"},
    {"type": "array", "items": {"type": "string"}, "default": [7]},
    {"type": "string", "enum": ["a"], "default": "b"},
])
def test_unused_defaults_checked_independently_of_factory_selection(tmp_path, spec):
    extra = {"name": "unused", "signals": ["logs"], "source": "block.lua", "parameters": {"invalid": spec}}
    proc = create_pack(tmp_path, extra_blocks=[extra])
    assert "class=invalid_configuration" in rejected_startup(config_file(tmp_path, proc), tmp_path)


def test_v1_rejects_v2_recursive_grammar(tmp_path):
    proc = create_pack(tmp_path, version=1)
    assert "class=invalid_configuration" in rejected_startup(config_file(tmp_path, proc), tmp_path)


def test_recursive_defaults_private_between_factories(tmp_path):
    source = '''return function(p)
        local before=p.config.rules[1].name
        p.config.rules[1].name='changed'
        return function(log)
            local values=log.body:get('values') or fb.array()
            values:append(before);log.body:set('values',values)
        end
    end'''
    proc = create_pack(tmp_path, source=source)
    proc["recipe"].append({"id": "second", "use": "org.fluentbit.observability/redact_log"})
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        send(service, {"control": True})
        assert clean_rows(service, 1) == [{"control": True, "values": ["a", "a"]}]
    finally:
        service.stop()


@pytest.mark.parametrize("kind", ["depth", "nodes", "default_value_nodes"])
def test_recursive_declarations_and_values_have_absolute_bounds(tmp_path, kind):
    if kind == "depth":
        node = {"type": "string"}
        for _ in range(10):
            node = {"type": "object", "fields": {"child": node}}
        specs = {"value": node}
    elif kind == "nodes":
        specs = {f"group{i}": {"type": "object", "fields": {
            f"field{j}": {"type": "string"} for j in range(128)}} for i in range(16)}
    else:
        specs = {"config": {"type": "object", "default": {}, "fields": {
            f"field{i}": {"type": "array", "items": {"type": "number"}, "default": [1] * 128}
            for i in range(32)}}}
    proc = create_pack(tmp_path, specs=specs)
    assert "class=invalid_configuration" in rejected_startup(config_file(tmp_path, proc), tmp_path)


def test_legacy_flat_manifest_keeps_more_than_128_parameters(tmp_path):
    specs = {f"field{i}": {"type": "string"} for i in range(130)}
    proc = create_pack(tmp_path, specs=specs, version=1,
        source="return function(p) return function(log) end end")
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        send(service, {"control": True})
        assert clean_rows(service, 1) == [{"control": True}]
    finally:
        service.stop()


def test_integer_options_reject_silent_double_rounding(tmp_path):
    specs = {"count": {"type": "number", "integer": True, "default": "9007199254740993"}}
    proc = create_pack(tmp_path, specs=specs)
    assert "class=invalid_configuration" in rejected_startup(config_file(tmp_path, proc), tmp_path)


def test_public_literal_helper_rolls_back_runtime_range_error(tmp_path):
    source = """return function(p)
        return function(log)
            if log.body:get('fail') then
                log.body:set('partial',true)
                fb.literal{type='int64',value='9223372036854775808'}
            end
        end
    end"""
    proc = create_pack(tmp_path, specs={}, source=source)
    proc["error_mode"] = "keep"
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        send(service, [{"fail": True}, {"control": True}])
        assert clean_rows(service, 2) == [{"fail": True}, {"control": True}]
        assert "class=invalid_parameter" in read_log(service.flb.log_file, "class=invalid_parameter")
    finally:
        service.stop()


def test_nested_label_pack_real_typed_fixtures():
    import os
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[5]
    command = [sys.executable, str(root / "tools/fts/fts_fixture.py"), "--binary",
        os.environ.get("FLUENT_BIT_BINARY", str(root / "build/bin/fluent-bit"))]
    if os.environ.get("VALGRIND") == "1":
        command.append("--valgrind")
    command += [str(path) for path in sorted((root / "packs/fts/logs/nested-labels/tests").glob("*.yaml"))]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("PASS ") == 4
