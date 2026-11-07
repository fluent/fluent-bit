#!/usr/bin/env python3
"""Export canonical FTS authoring schemas from the trusted runtime registry.

This is developer tooling. Deploy the JSON artifact; Fluent Bit needs no external
Lua executable. Native --dry-run remains required for semantic/placement checks.
"""
import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DRAFT = "https://json-schema.org/draft/2020-12/schema"
ID = "urn:fluentbit:fts:model:1"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def object_schema(properties, required=()):
    result = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        result["required"] = list(required)
    return result


def text(maximum=256, minimum=0):
    # JSON Schema counts characters; runtime limits count encoded UTF-8 bytes.
    return {"type": "string", "minLength": minimum, "maxLength": maximum,
            "x-fts-max-utf8-bytes": maximum}


def enum_values(value):
    return sorted(value) if isinstance(value, dict) else value


class Exporter:
    def __init__(self, model):
        self.model = model
        self.raw = model["definitions"]
        self.limits = model["parameter_limits"]
        self.defs = {}

    def fields(self, fields):
        properties = {name: self.parameter(spec) for name, spec in sorted(fields.items())}
        return object_schema(properties, sorted(name for name, spec in fields.items() if spec.get("required")))

    def parameter(self, spec):
        kind = spec["type"]
        if "model" in spec:
            result = {"$ref": "#/$defs/" + spec["model"]}
        elif kind == "string":
            result = text(self.limits["string_bytes"])
        elif kind == "bool":
            result = {"anyOf": [{"type": "boolean"}, {"enum": ["true", "false"]}]}
        elif kind == "number":
            number = {"type": "integer" if spec.get("integer") else "number"}
            for source, target in (("minimum", "minimum"), ("maximum", "maximum"),
                                   ("exclusive_minimum", "exclusiveMinimum")):
                if source in spec:
                    number[target] = spec[source]
            if spec.get("integer"):
                number["minimum"] = max(number.get("minimum", -9007199254740991), -9007199254740991)
                number["maximum"] = min(number.get("maximum", 9007199254740991), 9007199254740991)
            result = {"anyOf": [number, {"$ref": "#/$defs/decimal"}],
                      "x-fts-numeric-constraints": copy.deepcopy(number)}
        elif kind in ("selector", "literal"):
            result = {"$ref": "#/$defs/" + kind}
        elif kind == "severity_destination":
            result = {"anyOf": [{"const": "otel"}, {"$ref": "#/$defs/selector"}],
                      "x-fts-preflight": "otel destination requires context=otel"}
        elif kind == "selectors":
            result = {"type": "array", "minItems": 1, "maxItems": self.limits["selectors"],
                      "items": {"$ref": "#/$defs/selector"}}
        elif kind in ("strings", "list", "bounds", "array"):
            result = {"type": "array", "maxItems": self.limits["bounds"] if kind == "bounds" else self.limits["array_items"]}
            if kind == "strings":
                result.update(minItems=1, maxItems=self.limits["string_items"], items=text(self.limits["string_bytes"], 1))
            elif kind == "bounds":
                result.update(items={"anyOf": [{"type": "number"}, {"$ref": "#/$defs/decimal"}]},
                              **{"x-fts-preflight": "finite strictly increasing bounds"})
            elif kind == "array":
                result.update(items=self.parameter(spec["items"]))
            else:
                result.update(items={})
        elif kind == "object":
            result = self.fields(spec["fields"])
        elif kind == "map":
            result = {"type": "object"}
        elif kind == "scalar_literals":
            result = {"type": "array", "minItems": 1, "maxItems": 128,
                      "items": {"$ref": "#/$defs/scalar_literal"}}
        elif kind == "field_kind":
            result = {"enum": ["array", "bool", "bytes", "double", "int64", "integer", "map", "null", "string", "uint64"]}
        else:
            raise ValueError("unsupported exported parameter kind")
        if "enum" in spec:
            result["enum"] = enum_values(spec["enum"])
        if "default" in spec:
            default = copy.deepcopy(spec["default"])
            if default == {} and kind in ("array", "list", "strings", "selectors", "bounds"):
                default = []
            result["default"] = default
        return result

    def definitions(self):
        decimal_string = {"type": "string", "maxLength": 128,
            "pattern": r"^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$"}
        self.defs["decimal"] = {"anyOf": [decimal_string, object_schema({
            "type": {"enum": ["integer", "double"]},
            "value": {"anyOf": [decimal_string, {"type": "number"}]}}, ["type", "value"])],
            "x-fts-preflight": "finite numeric conversion and declared bounds/integrality"}
        roots = sorted(set().union(*(value.keys() for value in self.raw["selector"]["roots"].values())))
        selector = self.raw["selector"]
        self.defs["selector"] = object_schema({"root": {"enum": roots}, "path": {
            "type": "array", "maxItems": selector["max_path"],
            "items": text(selector["max_segment_bytes"], 1)}}, ["root", "path"])
        self.defs["selector"].update({"x-fts-roots-by-signal": selector["roots"],
            "x-fts-preflight": "signal roots; metadata requires native context and first path segment != otlp"})
        literal = self.raw["literal"]
        variants = []
        for kind in ("null", "string", "bool", "bytes", "integer", "int64", "uint64", "double", "array", "map"):
            properties = {"type": {"const": kind}}
            required = ["type"]
            if kind == "string": value = text(literal["max_string_bytes"])
            elif kind == "bool": value = {"type": "boolean"}
            elif kind == "bytes": value = {"type": "string", "maxLength": literal["max_string_bytes"], "pattern": r"^(?:[0-9a-fA-F]{2})*$"}
            elif kind in ("integer", "int64", "uint64"):
                value = {"anyOf": [{"type": "integer"}, {"type": "string", "pattern": r"^[0-9]+$" if kind == "uint64" else r"^-?[0-9]+$"},
                    {"$ref": "#/$defs/decimal"}], "x-fts-preflight": "exact int64/uint64 range; use decimal strings"}
            elif kind == "double": value = {"anyOf": [{"type": "number"}, {"$ref": "#/$defs/decimal"}]}
            elif kind == "array": value = {"type": "array", "maxItems": literal["max_items"], "items": {"$ref": "#/$defs/literal"}}
            elif kind == "map": value = {"type": "object", "propertyNames": text(256),
                "maxProperties": literal["max_nodes"], "additionalProperties": {"$ref": "#/$defs/literal"}}
            if kind != "null": properties["value"] = value; required.append("value")
            variants.append(object_schema(properties, required))
        self.defs["literal"] = {"anyOf": [text(literal["max_string_bytes"]), {"type": "boolean"}, {"type": "number"}, *variants],
            "x-fts-max-depth": literal["max_depth"], "x-fts-max-nodes": literal["max_nodes"],
            "x-fts-preflight": "config numbers become exact typed literals; use explicit decimal strings for portable 64-bit values"}
        self.defs["scalar_literal"] = {"allOf": [{"$ref": "#/$defs/literal"},
            {"not": {"type": "object", "properties": {"type": {"enum": ["array", "map"]}}, "required": ["type"]}}]}
        operations = self.raw["field_operations"]
        operation_schemas = []
        for name, fields in sorted(operations.items()):
            operation = self.fields(fields)
            if name == "keep":
                operation["anyOf"] = [{"required": ["names"]}, {"required": ["prefixes"]}]
            operation_schemas.append(operation)
        self.defs["field_operations"] = {"type": "array", "minItems": 1, "maxItems": 128,
            "items": {"oneOf": operation_schemas},
            "x-fts-preflight": "nonempty paths, allowed target roots, no overlap; keep/remove selectors; literal budget"}
        # field_rules use exact booleans; runtime deliberately rejects string booleans here.
        rules = self.fields(self.raw["field_rules"])
        rules["properties"]["required"] = {"type": "boolean", "default": True}
        self.defs["field_rules"] = {"type": "array", "minItems": 1, "maxItems": 128, "items": rules,
            "x-fts-preflight": "enum values match the declared scalar kind"}
        self.defs["attribute_names"] = {"type": "array", "maxItems": 128, "items": text(256, 1)}
        self.defs["name_filter"] = self.fields(self.raw["name_filter"])
        self.defs["name_filter"]["anyOf"] = [{"required": ["names"]}, {"required": ["prefixes"]}]
        mapping = self.raw["metric_mapping"]
        self.defs["metric_mapping"] = {"type": "object", "minProperties": 1, "maxProperties": mapping["max_entries"],
            "propertyNames": text(mapping["max_name_bytes"], 1), "additionalProperties": text(mapping["max_name_bytes"], 1),
            "x-fts-preflight": "unique destinations, no chains/cycles and recipe rename collision rules"}
        self.defs["numeric_literal"] = {"anyOf": [{"type": "number"}, {"allOf": [
            {"$ref": "#/$defs/literal"}, {"type": "object", "properties": {"type": {
                "enum": ["integer", "int64", "uint64", "double"]}}, "required": ["type"]}]}]}
        condition = self.raw["condition"]
        branches = []
        for group in ("all", "any"):
            branches.append(object_schema({group: {"type": "array", "minItems": 1,
                "maxItems": condition["max_items"], "items": {"$ref": "#/$defs/condition"}}}, [group]))
        for operation in sorted(condition["fields"]["op"]["enum"]):
            field = "values" if operation in ("in", "not_in") else "value"
            value = {"$ref": "#/$defs/numeric_literal" if operation in ("gt", "gte", "lt", "lte") else "#/$defs/scalar_literal"}
            if field == "values": value = {"type": "array", "minItems": 1, "maxItems": 128, "items": value}
            branches.append(object_schema({"selector": {"$ref": "#/$defs/selector"}, "op": {"const": operation}, field: value},
                ["selector", "op", field]))
        self.defs["condition"] = {"oneOf": branches, "x-fts-max-depth": condition["max_depth"],
            "x-fts-max-nodes": condition["max_nodes"],
            "x-fts-preflight": "scalar homogeneous comparisons; numeric ordering; events/links excluded"}
        return self.defs

    def recipe(self, blocks):
        step = object_schema({"id": {"type": "string", "maxLength": self.model["recipe_limits"]["id_bytes"],
            "pattern": r"^[a-zA-Z][a-zA-Z0-9_-]*$"},
            "use": {"anyOf": [{"enum": sorted(blocks)}, {"type": "string", "maxLength": 193,
                "pattern": r"^[a-z][a-z0-9.-]*/[a-z][a-z0-9_-]*$"}]},
            "with": {"type": "object"}, "when": {"$ref": "#/$defs/condition"}}, ["id", "use"])
        step["allOf"] = []
        for name, block in sorted(blocks.items()):
            key = "block_parameters_" + hashlib.sha256(name.encode()).hexdigest()
            self.defs[key] = self.fields(block["parameters"])
            constraints = {"properties": {"with": {"$ref": "#/$defs/" + key}}}
            if self.defs[key].get("required"):
                constraints["required"] = ["with"]
            step["allOf"].append({"if": {"properties": {"use": {"const": name}}}, "then": constraints})
        return {"type": "array", "minItems": 1, "maxItems": self.model["recipe_limits"]["steps"], "items": step,
            "x-fts-preflight": "unique IDs; loaded sources; unknown external block parameters need --pack; signal/context/privacy; terminal/local/input; transform order"}

    def manifest(self):
        path = {"type": "string", "minLength": 1,
                "x-fts-preflight": "relative path; no NUL, backslash, colon or dot segments; trusted local files"}
        identifier = {"type": "string", "minLength": 1, "maxLength": 64, "pattern": r"^[a-z][a-z0-9_]*$"}
        variants = []
        for version in self.model["pack_versions"]:
            name = f"parameter_v{version}"
            properties = {"type": {"enum": sorted(self.model["parameter_kinds"]) +
                (sorted(self.model["recursive_parameter_kinds"]) if version == 2 else [])},
                "required": {"type": "boolean"}, "default": {},
                "enum": {"type": "array", "minItems": 1, "maxItems": 128, "items": text(256, 1)}}
            if version == 2:
                properties.update(fields={"type": "object", "maxProperties": self.model["parameter_limits"]["fields"],
                    "propertyNames": identifier, "additionalProperties": {"$ref": "#/$defs/" + name}},
                    items={"allOf": [{"$ref": "#/$defs/" + name},
                        {"not": {"anyOf": [{"required": ["default"]}, {"required": ["required"]}]}}]},
                    minimum={"type": "number"}, maximum={"type": "number"}, integer={"type": "boolean"})
            descriptor = object_schema(properties, ["type"])
            if version == 2:
                descriptor["allOf"] = []
                for kind, required, forbidden in (("object", ["fields"], ["items"]), ("array", ["items"], ["fields"])):
                    descriptor["allOf"].append({"if": {"properties": {"type": {"const": kind}}},
                        "then": {"required": required, "not": {"anyOf": [{"required": [key]} for key in forbidden]}}})
                descriptor["allOf"].append({"if": {"properties": {"type": {"not": {"enum": ["object", "array"]}}}},
                    "then": {"not": {"anyOf": [{"required": ["fields"]}, {"required": ["items"]}]}}})
                descriptor["allOf"].append({"if": {"properties": {"type": {"not": {"const": "number"}}}},
                    "then": {"not": {"anyOf": [{"required": [key]} for key in ("minimum", "maximum", "integer")]}}})
                descriptor["allOf"].append({"if": {"required": ["enum"]}, "then": {"properties": {"type": {"const": "string"}}}})
            self.defs[name] = descriptor
            parameters = {"type": "object", "propertyNames": identifier, "additionalProperties": {"$ref": "#/$defs/" + name}}
            if version == 2: parameters["maxProperties"] = self.model["parameter_limits"]["fields"]
            block = object_schema({"name": {"type": "string", "maxLength": 64, "pattern": r"^[a-z][a-z0-9_-]*$"},
                "signals": {"type": "array", "minItems": 1, "maxItems": 3, "uniqueItems": True,
                    "items": {"enum": ["logs", "metrics", "traces"]}},
                "parameters": parameters, "source": path, "privacy": {"type": "boolean"}},
                ["name", "signals", "parameters", "source"])
            variants.append(object_schema({"pack_version": {"const": version}, "fts_api_version": {"const": 1},
                "id": {"type": "string", "maxLength": 128, "pattern": r"^[a-z][a-z0-9.-]*$"},
                "version": {"type": "string", "pattern": r"^[0-9]+\.[0-9]+\.[0-9]+$"},
                "title": {}, "description": {}, "fixtures": {},
                "blocks": {"type": "array", "minItems": 1, "maxItems": 64, "items": block}},
                ["pack_version", "fts_api_version", "id", "version", "blocks"]))
        return {"oneOf": variants, "x-fts-preflight": "JSON resource bounds; recursive schema/default bounds; unique IDs; paths; source binding"}

    def schema(self, body):
        result = {"$schema": DRAFT, **body, "$defs": copy.deepcopy(self.defs),
                  "x-fts-preflight-required": True}
        content = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        result["$id"] = ID + ":" + hashlib.sha256(content).hexdigest()
        return result


def processor_schema(exporter, native, recipe, registry):
    properties = {"name": {"const": "fts"}}
    for option in native["properties"]["global_options"] + native["properties"]["options"]:
        kind, name = option["type"], option["name"]
        if kind == "string":
            schema = {"type": "string"}
        elif kind == "boolean":
            schema = {"anyOf": [{"type": "boolean"}, {"enum": ["true", "false"]}]}
        elif kind == "integer":
            schema = {"anyOf": [{"type": "integer"}, {"type": "string", "pattern": r"^[0-9]+$"}]}
        elif kind == "size":
            schema = {"anyOf": [{"type": "integer", "minimum": 0}, {"type": "string", "minLength": 1}],
                      "x-fts-preflight": "native size parser and processor budget minima"}
        elif kind == "variant":
            if name == "recipe":
                schema = recipe
            elif name == "packs":
                schema = {"type": "array", "maxItems": 16, "items": {"type": "string", "minLength": 1},
                          "x-fts-preflight": "trusted local relative manifests under explicit packages_dir"}
            elif name == "secret_refs":
                schema = {"type": "object", "maxProperties": 16,
                    "propertyNames": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": r"^[a-zA-Z0-9_.-]+$"},
                    "additionalProperties": {"type": "string", "minLength": 1, "maxLength": 128,
                        "pattern": r"^[a-zA-Z_][a-zA-Z0-9_]*$"},
                    "x-fts-preflight": "resolve public variable names to raw process-environment key bytes; no production keys in YAML env"}
            else:
                raise ValueError("unmodelled native variant option")
        else:
            raise ValueError("unmodelled native option type")
        schema = copy.deepcopy(schema)
        schema["description"] = option["description"]
        if option["default"] is not None:
            default = option["default"]
            if kind == "boolean": default = default == "true"
            if kind == "integer": default = int(default)
            schema["default"] = default
        properties[name] = schema
    properties["recipe_version"]["enum"] = [1, "1"]
    properties["recipe_version"].pop("type", None)
    properties["context"]["enum"] = ["native", "otel", "any"]
    properties["error_mode"]["enum"] = ["drop", "keep"]
    properties["state_commit"]["const"] = "local"
    result = object_schema(properties, ["name"])
    result["oneOf"] = [{"required": [key], "not": {"anyOf": [{"required": [other]} for other in
        ("code", "script", "recipe") if other != key]}} for key in ("code", "script", "recipe")]
    result["dependentRequired"] = {"packs": ["packages_dir", "recipe"], "state_commit": ["recipe"]}
    result["allOf"] = [{"if": {"required": ["recipe"]}, "then": {"properties": {
        "jit": {"enum": [False, "false"]}}}}]
    for constraint, names in (
        ({"properties": {"error_mode": {"const": "drop"}}},
         [name for name, block in registry["blocks"].items() if block.get("privacy")]),
        ({"required": ["state_commit"]},
         [name for name, block in registry["blocks"].items() if block.get("state") in ("local", "window")]),
    ):
        if names:
            result["allOf"].append({"if": {"required": ["recipe"], "properties": {"recipe": {
                "contains": {"type": "object", "properties": {"use": {"enum": sorted(names)}}, "required": ["use"]}}}},
                "then": constraint})
    return result


def build_model(registry, native):
    exporter = Exporter(registry)
    exporter.definitions()
    manifest = exporter.manifest()
    blocks = {name: {"signals": sorted(block["signals"]), "privacy": block["privacy"],
        "state": block["state"], "parameters": exporter.schema(exporter.fields(block["parameters"]))}
        for name, block in sorted(registry["blocks"].items())}
    recipe = exporter.recipe(registry["blocks"])
    return {"processor": exporter.schema(processor_schema(exporter, native, recipe, registry)),
        "manifest": exporter.schema(manifest), "model_version": registry["model_version"], "fts_api_version": registry["fts_api_version"],
        "recipe_version": registry["recipe_version"], "pack_versions": registry["pack_versions"],
        "native_properties": native["properties"], "parameter_limits": registry["parameter_limits"],
        "blocks": blocks, "recipe": exporter.schema(recipe),
        "constructors": {name: exporter.schema(exporter.fields(fields)) for name, fields in sorted(registry["constructors"].items())},
        "helpers": {"literal": exporter.schema({"$ref": "#/$defs/literal"})},
        "preflight_required": True,
        "preflight_command": "fluent-bit --dry-run -c CONFIG.yaml",
        "limits": ["Schemas describe canonical authoring forms, not proof of deployability.",
            "x-fts annotations require native preflight: byte lengths, exact ranges, total nodes/depth and semantic/placement constraints.",
            "Schema defaults are annotations. Native FTS materializes defaults and normalizes compatible legacy forms.",
            "Empty Lua tables in legacy config can represent either empty container; author JSON/YAML should use canonical arrays/maps."]}


def generate(binary, lua):
    output = subprocess.run([lua, str(ROOT / "tools/fts/fts_schema.lua"),
        str(ROOT / "plugins/processor_fts/fts_recipe.lua")], check=True, capture_output=True, text=True, encoding="utf-8", timeout=15)
    registry = json.loads(output.stdout)
    output = subprocess.run([str(binary), "-J"], check=True, capture_output=True, text=True, encoding="utf-8", timeout=30)
    native = next(plugin for plugin in json.loads(output.stdout)["processors"] if plugin["name"] == "fts")
    model = build_model(registry, native)
    sources = {path.relative_to(ROOT).as_posix(): path for pattern in ("*.c", "*.h", "*.lua", "*.in")
        for path in (ROOT / "plugins/processor_fts").glob(pattern)}
    for name in ("tools/fts/fts_schema.py", "tools/fts/fts_schema.lua"):
        sources[name] = ROOT / name
    model["source_sha256"] = {name: digest(path) for name, path in sorted(sources.items())}
    return model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "build/bin/fluent-bit")
    parser.add_argument("--lua", default=os.environ.get("FTS_LUA", "lua"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--pack", type=Path, action="append", default=[], help="include parameter schemas from local JSON manifests; never execute their Lua")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--select", choices=("model", "manifest", "recipe", "processor"), default="model")
    selection.add_argument("--block", help="export one known block's standalone parameter schema")
    args = parser.parse_args()
    if args.output is None:
        if args.block or args.select != "model":
            parser.error("selected schemas require an explicit --output path")
        args.output = ROOT / "plugins/processor_fts/schemas/fts-model.json"
    try:
        model = generate(args.binary.resolve(), args.lua)
        seen_packs = set()
        pack_blocks = {}
        for path in args.pack:
            import jsonschema
            if path.stat().st_size > 256 * 1024:
                raise ValueError("manifest exceeds the native size limit")
            def strict_pairs(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate manifest key")
                    result[key] = value
                return result
            def invalid_constant(value):
                raise ValueError("nonfinite manifest number")
            def finite_float(value):
                number = float(value)
                if not math.isfinite(number):
                    raise ValueError("nonfinite manifest number")
                return number
            try:
                pack = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_pairs,
                    parse_constant=invalid_constant, parse_float=finite_float)
            except RecursionError:
                raise ValueError("manifest exceeds native depth limits") from None
            pending = [(pack, 0)]
            while pending:
                value, depth = pending.pop()
                if depth > 32:
                    raise ValueError("manifest exceeds native depth limits")
                if value is None:
                    raise ValueError("untyped null is not supported in manifests; use a typed literal")
                if isinstance(value, dict):
                    pending.extend((child, depth + 1) for child in value.values())
                elif isinstance(value, list):
                    pending.extend((child, depth + 1) for child in value)
            if not jsonschema.Draft202012Validator(model["manifest"]).is_valid(pack):
                raise ValueError("manifest violates the supported structural grammar; run native preflight")
            if pack["id"] in seen_packs:
                raise ValueError("duplicate pack identifier")
            seen_packs.add(pack["id"])
            raw = json.loads(subprocess.run([args.lua, str(ROOT / "tools/fts/fts_schema.lua"),
                str(ROOT / "plugins/processor_fts/fts_recipe.lua")], check=True, capture_output=True, text=True, encoding="utf-8", timeout=15).stdout)
            exporter = Exporter(raw)
            exporter.definitions()
            for block in pack["blocks"]:
                block_id = pack["id"] + "/" + block["name"]
                if block_id in model["blocks"]:
                    raise ValueError("duplicate block identifier")
                pack_blocks[block_id] = {"parameters": block["parameters"], "privacy": block.get("privacy", False)}
                model["blocks"][block_id] = {"signals": block["signals"],
                    "privacy": block.get("privacy", False), "state": "author_declared_via_constructor",
                    "parameters": exporter.schema(exporter.fields(block["parameters"]))}
        if pack_blocks:
            combined = {**raw["blocks"], **pack_blocks}
            recipe = exporter.recipe(combined)
            model["recipe"] = exporter.schema(recipe)
            native = {"properties": model["native_properties"]}
            model["processor"] = exporter.schema(processor_schema(exporter, native, recipe, {**raw, "blocks": combined}))
        if args.block:
            if args.block not in model["blocks"]:
                raise ValueError("unknown block; include its local manifest with --pack")
            model = model["blocks"][args.block]["parameters"]
        elif args.select != "model":
            model = model[args.select]
        text = json.dumps(model, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
        if args.check:
            if not args.output.exists() or args.output.read_text(encoding="utf-8") != text:
                raise ValueError("FTS model is stale; rebuild the matching binary and regenerate the model")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8")
        print(json.dumps({"model": str(args.output), "model_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "runtime_sha256": digest(args.binary.resolve()), "check": args.check}))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, StopIteration, ImportError) as exc:
        parser.exit(1, f"FTS schema export failed: {exc}\n")


if __name__ == "__main__":
    main()
