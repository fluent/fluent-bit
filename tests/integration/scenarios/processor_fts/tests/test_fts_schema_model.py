"""The exported author model is deterministic and covers actual canonical packs."""
import copy
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[5]
MODEL = ROOT / "plugins/processor_fts/schemas/fts-model.json"
TOOL = ROOT / "tools/fts/fts_schema.py"
BINARY = os.environ.get("FLUENT_BIT_BINARY", str(ROOT / "build/bin/fluent-bit"))


@pytest.fixture(scope="module", autouse=True)
def schema_lua_cli():
    interpreter = os.environ.get("FTS_LUA", "lua")
    if not shutil.which(interpreter):
        pytest.skip("schema export requires a Lua CLI on PATH or FTS_LUA; see tools/fts/README.md")


@pytest.fixture(scope="module")
def model():
    return json.loads(MODEL.read_text())


def test_model_matches_runtime_registry_and_native_options():
    result = subprocess.run([sys.executable, str(TOOL), "--binary", BINARY, "--check"],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["check"] is True


def test_all_exported_schemas_are_standard_draft_2020_12(model):
    schemas = [model["manifest"], model["recipe"], model["processor"]]
    schemas += [value["parameters"] for value in model["blocks"].values()]
    schemas += list(model["constructors"].values()) + list(model["helpers"].values())
    for schema in schemas:
        jsonschema.Draft202012Validator.check_schema(schema)
    assert len(model["blocks"]) == 17
    assert model["pack_versions"] == [1, 2]
    assert all(schema["x-fts-preflight-required"] for schema in schemas)


def test_model_validates_all_consumable_manifest_and_processor_shapes(model):
    manifest_validator = jsonschema.Draft202012Validator(model["manifest"])
    processor_validator = jsonschema.Draft202012Validator(model["processor"])
    for path in (ROOT / "packs/fts").rglob("pack.json"):
        manifest_validator.validate(json.loads(path.read_text()))
    for path in (ROOT / "packs/fts").rglob("fluent-bit.yaml"):
        config = yaml.safe_load(path.read_text())
        for source in config["pipeline"]["inputs"]:
            for processors in source.get("processors", {}).values():
                for processor in processors:
                    if processor["name"] == "fts": processor_validator.validate(processor)


@pytest.mark.parametrize("mutation", [
    {"pack_version": 3}, {"fts_api_version": 2}, {"unexpected": "synthetic"},
    {"blocks": []}, {"id": "../invalid"},
])
def test_manifest_model_rejects_invalid_shapes(model, mutation):
    pack = json.loads((ROOT / "packs/fts/multisignal/observability-basics/pack.json").read_text())
    pack.update(mutation)
    assert not jsonschema.Draft202012Validator(model["manifest"]).is_valid(pack)


def test_recursive_manifest_and_independent_parameter_schema(tmp_path, model):
    from test_fts_nested_parameters import create_pack, SPEC
    create_pack(tmp_path)
    pack = json.loads((tmp_path / "pack.json").read_text())
    jsonschema.Draft202012Validator(model["manifest"]).validate(pack)
    output = tmp_path / "model.json"
    result = subprocess.run([sys.executable, str(TOOL), "--binary", BINARY,
        "--pack", str(tmp_path / "pack.json"), "--output", str(output)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    schema = json.loads(output.read_text())["blocks"]["org.fluentbit.observability/redact_log"]["parameters"]
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate({"config": {"label": "test", "count": 3,
        "rules": [{"name": "a"}], "value": {"type": "int64", "value": "9223372036854775807"}}})
    for value in ({"config": {"unknown": 1}}, {"config": {"rules": [{}]}}, {"config": {"count": 0}}):
        assert not validator.is_valid(value)


def test_structural_validation_does_not_materialize_defaults(model):
    schema = model["blocks"]["metrics.aggregate_dimensions"]["parameters"]
    values = {"names": ["queue_depth"], "operation": "sum"}
    jsonschema.Draft202012Validator(schema).validate(values)
    assert "keep_attributes" not in values
    assert "default" in schema["properties"]["keep_attributes"]
    assert model["preflight_required"] is True


def test_model_check_detects_stale_artifact(tmp_path):
    path = tmp_path / "stale.json"
    path.write_text("{}\n")
    result = subprocess.run([sys.executable, str(TOOL), "--binary", BINARY, "--check", "--output", str(path)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "stale" in result.stderr


@pytest.mark.parametrize("selection", [["--select", "manifest"], ["--select", "processor"],
    ["--select", "recipe"], ["--block", "logs.parse_json"]])
def test_standalone_schema_export_has_local_refs_and_explicit_output(tmp_path, selection):
    output = tmp_path / "schema.json"
    result = subprocess.run([sys.executable, str(TOOL), "--binary", BINARY,
        *selection, "--output", str(output)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    schema = json.loads(output.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    def resolve_refs(value):
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                assert ref.startswith("#/"), ref
                target = schema
                for component in ref[2:].split("/"):
                    target = target[component.replace("~1", "/").replace("~0", "~")]
            for child in value.values():
                resolve_refs(child)
        elif isinstance(value, list):
            for child in value:
                resolve_refs(child)
    resolve_refs(schema)
    instance = {"--select": {"manifest": json.loads((ROOT / "packs/fts/logs/genai-privacy/pack.json").read_text()),
        "processor": {"name": "fts", "recipe": [{"id": "drop", "use": "logs.drop_matching", "with": {"condition": {"selector": {"root": "body", "path": ["id"]}, "op": "eq", "value": 1}}}]},
        "recipe": [{"id": "drop", "use": "logs.drop_matching", "with": {"condition": {"selector": {"root": "body", "path": ["id"]}, "op": "eq", "value": 1}}}]},
        "--block": {"logs.parse_json": {"source": {"root": "body", "path": ["message"]},
            "destination": {"root": "body", "path": ["parsed"]}}}}[selection[0]][selection[1]]
    jsonschema.Draft202012Validator(schema).validate(instance)
    result = subprocess.run([sys.executable, str(TOOL), "--binary", BINARY, *selection],
        capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "explicit --output" in result.stderr


def test_recipe_schema_links_known_block_parameters_and_conditions(model):
    validator = jsonschema.Draft202012Validator(model["recipe"])
    valid = [{"id": "decode", "use": "logs.parse_json", "with": {
        "source": {"root": "body", "path": ["message"]},
        "destination": {"root": "body", "path": ["app"]}}}]
    validator.validate(valid)
    bad = copy.deepcopy(valid)
    bad[0]["with"]["unrecognised"] = True
    assert not validator.is_valid(bad)
    assert not validator.is_valid([{"id": "decode", "use": "logs.parse_json"}])
    condition = [{"id": "drop", "use": "logs.drop_matching", "with": {"condition": {
        "selector": {"root": "body", "path": ["size"]}, "op": "gt", "value": "wrong-type"}}}]
    assert not validator.is_valid(condition)
    condition[0]["with"]["condition"]["value"] = 7
    validator.validate(condition)


@pytest.mark.parametrize("data", [
    '{"id":"public-marker-never-diagnose","id":"duplicate"}',
    '{"value":1e999}', '{"value":NaN}', '{"value":null}',
    '[' * 40 + '1' + ']' * 40,
])
def test_pack_export_rejects_unsafe_json_without_printing_values(tmp_path, data):
    manifest = tmp_path / "pack.json"
    manifest.write_text(data)
    output = tmp_path / "schema.json"
    result = subprocess.run([sys.executable, str(TOOL), "--binary", BINARY, "--pack", str(manifest),
        "--output", str(output)], capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "public-marker-never-diagnose" not in result.stderr
    assert not output.exists()


def test_processor_schema_preserves_declared_privacy_and_local_state_requirements(model):
    validator = jsonschema.Draft202012Validator(model["processor"])
    config = {"name": "fts", "error_mode": "keep", "recipe": [{"id": "privacy",
        "use": "shared.redact_keys", "with": {"targets": [{"root": "body", "path": []}], "keys": ["password"]}}]}
    assert not validator.is_valid(config)
    config["error_mode"] = "drop"
    validator.validate(config)
    config["recipe"] = [{"id": "dedupe", "use": "logs.dedupe", "with": {
        "keys": [{"root": "body", "path": ["id"]}], "ttl_ms": 1000}}]
    assert not validator.is_valid(config)
    config["state_commit"] = "local"
    validator.validate(config)
