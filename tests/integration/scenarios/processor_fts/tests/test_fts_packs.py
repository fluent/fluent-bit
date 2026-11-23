"""Local author Lua packs execute through the native recipe loader."""
import json
import shutil
from pathlib import Path

import pytest

from test_fts_recipes import config_file, rejected_startup
from test_fts_records import send, rows
from utils.test_service import FluentBitTestService

from fts_test_utils import read_log


ROOT = Path(__file__).resolve().parents[5]
PACK = ROOT / "packs/fts/multisignal/observability-basics"
BLOCK = "org.fluentbit.observability/redact_log"


def processor(directory=PACK, manifest="pack.json", **changes):
    return {"name": "fts", "packages_dir": str(directory), "packs": [manifest],
            "recipe": [{"id": "privacy", "use": BLOCK}], "error_mode": "drop", **changes}


@pytest.mark.parametrize("placement", ["input", "output"])
def test_local_pack_composes_with_builtin_and_validates_defaults(tmp_path, placement):
    proc = processor()
    proc["recipe"].append({"id": "trim", "use": "fields.truncate", "with": {
        "target": {"root": "body", "path": ["message"]}, "max_bytes": 4,
        "marker": {"root": "body", "path": ["truncated"]}}})
    # Each author factory owns ordinary parameter tables, isolated from other blocks.
    config = config_file(tmp_path, proc, placement)
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [{"password": "synthetic-secret", "nested": {"api_key": "synthetic"},
                        "message": "abcdefgh", "control": 42}])
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        for record in result:
            record.pop("date", None)
        assert result == [{"password": "[REDACTED]", "nested": {"api_key": "[REDACTED]"},
                           "message": "abcd", "control": 42, "truncated": True}]
    finally:
        service.stop()


@pytest.mark.parametrize("change,expected", [
    ({"packs": ["../pack.json"]}, "class=invalid_configuration"),
    ({"packs": ["missing.json"]}, "class=invalid_configuration"),
    ({"packs": ["pack.json", "pack.json"]}, "class=invalid_configuration"),
    ({"error_mode": "keep"}, "privacy_requires_drop"),
    ({"recipe": [{"id": "privacy", "use": BLOCK, "with": {"keys": 7}}]},
     "class=invalid_configuration"),
])
def test_pack_invalid_configuration(tmp_path, change, expected):
    assert expected in rejected_startup(config_file(tmp_path, processor(**change)), tmp_path)


@pytest.mark.parametrize("mutation", [
    {"pack_version": 3}, {"fts_api_version": 2}, {"version": "1"},
    {"id": "core/override"}, {"blocks": []},
])
def test_pack_rejects_invalid_manifest(tmp_path, mutation):
    shutil.copytree(PACK / "blocks", tmp_path / "blocks")
    manifest = json.loads((PACK / "pack.json").read_text())
    manifest.update(mutation)
    (tmp_path / "pack.json").write_text(json.dumps(manifest))
    assert "class=invalid_configuration" in rejected_startup(
        config_file(tmp_path, processor(tmp_path)), tmp_path)


@pytest.mark.parametrize("kind", ["parent", "absolute", "traversal"])
def test_pack_source_cannot_escape_manifest_directory(tmp_path, kind):
    sentinel = tmp_path.parent / (tmp_path.name + "-private.lua")
    sentinel.write_text("return function(p) return function(log) end end")
    source = {"parent": "../" + sentinel.name, "absolute": str(sentinel),
              "traversal": "blocks/../../" + sentinel.name}[kind]
    shutil.copytree(PACK / "blocks", tmp_path / "blocks")
    manifest = json.loads((PACK / "pack.json").read_text())
    manifest["blocks"][0]["source"] = source
    (tmp_path / "pack.json").write_text(json.dumps(manifest))
    assert "class=invalid_configuration" in rejected_startup(
        config_file(tmp_path, processor(tmp_path)), tmp_path)


def authored_pack(tmp_path, source, parameters=None):
    (tmp_path / "block.lua").write_text(source)
    manifest = {"pack_version": 1, "fts_api_version": 1, "id": "org.fluentbit.observability",
                "version": "1.0.0", "blocks": [{"name": "redact_log", "signals": ["logs"],
                "source": "block.lua", "parameters": parameters or {}}]}
    (tmp_path / "pack.json").write_text(json.dumps(manifest))
    return processor(tmp_path)


@pytest.mark.parametrize("source", [
    "return function(p) fb.changed=true; return function(log) end end",
    "return function(p) return pcall(function() end) end",
    "return function(p) return require('io') end",
    "return function(p) return 42 end",
    "return 42",
])
def test_author_factories_preserve_immutable_environment(tmp_path, source):
    proc = authored_pack(tmp_path, source)
    assert "class=invalid_configuration" in rejected_startup(config_file(tmp_path, proc), tmp_path)


def test_author_runtime_error_rolls_back_edits_and_preserves_control(tmp_path):
    proc = authored_pack(tmp_path, '''return function(p)
        return function(log)
            if log.body:get('fail') then
                log.body:set('edited', true)
                error('wrong_type',0)
            end
        end
    end''')
    proc["error_mode"] = "keep"
    config = config_file(tmp_path, proc)
    service = FluentBitTestService(str(config))
    try:
        service.start()
        send(service, [{"fail": "synthetic", "control": 1}, {"control": 2}])
        result = service.wait_for_condition(lambda: len(rows(service)) == 2 and rows(service), timeout=30)
        for record in result:
            record.pop("date", None)
        assert result == [{"fail": "synthetic", "control": 1}, {"control": 2}]
        assert "step=privacy class=wrong_type" in read_log(service.flb.log_file, "step=privacy class=wrong_type")
    finally:
        service.stop()


@pytest.mark.parametrize("placement,following", [("output", False), ("input", True)])
def test_author_state_constructor_rejects_unsupported_placement(tmp_path, placement, following):
    proc = processor(state_commit="local", recipe=[{"id": "state", "use":
        "org.fluentbit.observability/dedupe_log", "with": {
            "keys": [{"root": "body", "path": ["id"]}], "ttl_ms": 60000}}])
    if following:
        proc["recipe"].append({"id": "privacy", "use": BLOCK})
    assert "class=invalid_configuration" in rejected_startup(config_file(tmp_path, proc, placement), tmp_path)


def test_pack_typed_fixtures_against_real_runtime():
    import os
    import subprocess
    import sys
    command = [sys.executable, str(ROOT / "tools/fts/fts_fixture.py"),
               "--binary", os.environ.get("FLUENT_BIT_BINARY", str(ROOT / "build/bin/fluent-bit"))]
    if os.environ.get("VALGRIND") == "1":
        command.append("--valgrind")
    command += [str(path) for path in sorted((PACK / "tests").glob("*.yaml"))]
    result = subprocess.run(command, capture_output=True, text=True, timeout=240)
    assert result.returncode == 0, result.stdout + result.stderr
    fixtures = [PACK / reference for reference in json.loads((PACK / "pack.json").read_text())["fixtures"]]
    from test_fts_fixture_format import runner
    expected = sum(len(runner.load_fixture(path)["cases"]) for path in fixtures)
    assert result.stdout.count("PASS ") == expected


@pytest.mark.parametrize("kind", ["throttle", "window"])
def test_author_public_state_wrappers_execute_on_real_input(tmp_path, kind):
    options = "keys={{root='body',path={'id'}}}"
    if kind == "throttle":
        options += ",ttl_ms=60000,rate=1,burst=1"
    else:
        options += ",hold_ms=300,retain_when={selector={root='body',path={'level'}},op='eq',value='ERROR'}"
    proc = authored_pack(tmp_path, "return function(p) local apply=fb." + kind +
                         "({" + options + "}); return function(log) return apply(log) end end")
    proc["state_commit"] = "local"
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        records = [{"id": "a", "level": "DEBUG"}, {"id": "a", "level": "ERROR"},
                   {"id": "b", "level": "DEBUG"}]
        send(service, records)
        result = service.wait_for_condition(lambda: len(rows(service)) == 2 and rows(service), timeout=30)
        for record in result:
            record.pop("date", None)
        assert result == ([records[0], records[2]] if kind == "throttle" else records[:2])
    finally:
        service.stop()


@pytest.mark.parametrize("valid", [False, True])
def test_pack_preflight_uses_same_local_loader(tmp_path, valid):
    from test_fts_recipe_preflight import dry_run, preflight_config
    proc = processor(packs=["pack.json" if valid else "missing.json"])
    code, diagnostics = dry_run(preflight_config(tmp_path, proc, "logs", "input", 31337), tmp_path)
    assert (code == 0) is valid, diagnostics


def test_author_parameters_are_private_native_arrays(tmp_path):
    proc = authored_pack(tmp_path, '''return function(p)
        assert(#p.keys==1)
        if p.extra then p.keys[#p.keys+1]='token' end
        return function(log)
            fb.redact(log.body,p.keys,'[REDACTED]')
            log.body:set('factory_keys',#p.keys)
        end
    end''', {"keys": {"type": "strings", "default": ["password"]},
            "extra": {"type": "bool", "default": False}})
    proc["recipe"] = [{"id": "first", "use": BLOCK, "with": {"extra": True}},
                      {"id": "second", "use": BLOCK}]
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    try:
        service.start()
        send(service, [{"password": "synthetic", "token": "synthetic", "control": 1}])
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        result[0].pop("date", None)
        assert result == [{"password": "[REDACTED]", "token": "[REDACTED]",
                           "control": 1, "factory_keys": 1}]
    finally:
        service.stop()


def test_packages_dir_relative_to_explicit_process_cwd(tmp_path):
    import os
    import subprocess
    from test_fts_recipe_preflight import preflight_config
    binary = Path(os.environ.get("FLUENT_BIT_BINARY", str(ROOT / "build/bin/fluent-bit"))).resolve()
    config = preflight_config(tmp_path, processor(directory="."), "logs", "input", 31337)
    for cwd, expected in [(PACK, 0), (tmp_path, 1)]:
        command = [str(binary), "--dry-run", "-c", str(config)]
        log = tmp_path / ("cwd-valid.valgrind.log" if expected == 0 else "cwd-invalid.valgrind.log")
        if os.environ.get("VALGRIND") == "1":
            command = ["valgrind", "--error-exitcode=99", "--leak-check=full",
                "--errors-for-leak-kinds=definite,indirect,possible", f"--log-file={log}", *command]
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=60)
        assert (result.returncode == 0) == (expected == 0), result.stdout + result.stderr
        if os.environ.get("VALGRIND") == "1":
            assert "ERROR SUMMARY: 0 errors" in log.read_text()


@pytest.mark.parametrize("expression", [
    "fb.block('not.a.block',{})",
    "fb.block('logs.dedupe',{})",
    "fb.block('metrics.select',{keep={names={'x'}}})",
    "fb.block('shared.redact_keys',{targets={{root='body',path={}}},keys={'password'}})",
])
def test_author_core_composition_validates_contracts(tmp_path, expression):
    proc = authored_pack(tmp_path, "return function(p) return " + expression + " end")
    proc["error_mode"] = "keep"
    assert "class=invalid_configuration" in rejected_startup(config_file(tmp_path, proc), tmp_path)


@pytest.mark.parametrize("value", [False, 7, "false"])
def test_unused_invalid_enum_declaration_fails_preflight(tmp_path, value):
    from test_fts_recipe_preflight import dry_run
    proc = authored_pack(tmp_path, "return function(p) return function(log) end end",
                         {"flag": {"type": "bool", "default": False, "enum": value}})
    code, text = dry_run(config_file(tmp_path, proc), tmp_path)
    assert code != 0 and "class=invalid_configuration" in text


@pytest.mark.parametrize("returned", ["true", "42", "'Drop'"])
@pytest.mark.parametrize("error_mode", ["keep", "drop"])
def test_author_invalid_return_obeys_error_mode_and_rolls_back(tmp_path, returned, error_mode):
    proc = authored_pack(tmp_path, "return function(p) return function(log) "
        "if log.body:get('bad') then log.body:set('edited',true); return " + returned + " end end end")
    proc["error_mode"] = error_mode
    service = FluentBitTestService(str(config_file(tmp_path, proc)))
    bad, good = {"bad": True, "id": 1}, {"id": 2}
    try:
        service.start()
        send(service, [bad, good])
        count = 2 if error_mode == "keep" else 1
        result = service.wait_for_condition(lambda: len(rows(service)) == count and rows(service), timeout=30)
        for record in result:
            record.pop("date", None)
        assert result == ([bad, good] if error_mode == "keep" else [good])
        expected = "step=privacy class=invalid_parameter"
        assert expected in read_log(service.flb.log_file, expected)
    finally:
        service.stop()


def test_pack_source_allocation_respects_memory_limit(tmp_path):
    from test_fts_recipe_preflight import dry_run
    source = "return function(p) return function(log) end end"
    proc = authored_pack(tmp_path, source)
    proc["memory_limit"] = "640000"
    config = config_file(tmp_path, proc)
    code, text = dry_run(config, tmp_path)
    assert code == 0, text
    # The source string and its native read buffer coexist during loading.
    (tmp_path / "block.lua").write_text(source + "\n--" + "x" * 200000)
    code, text = dry_run(config, tmp_path)
    assert code != 0 and "configuration test is successful" not in text


@pytest.mark.parametrize("layout", [None, "custom"])
def test_vpc_requires_explicit_supported_producer_layout(tmp_path, layout):
    from test_fts_recipe_preflight import dry_run
    proc = processor(ROOT / "packs/fts/logs/vpc-flow", recipe=[{
        "id": "flow", "use": "org.fluentbit.policy.vpc-flow/apply",
        "with": {} if layout is None else {"layout": layout}}], error_mode="keep")
    code, text = dry_run(config_file(tmp_path, proc), tmp_path)
    assert code != 0 and "class=invalid_configuration" in text
