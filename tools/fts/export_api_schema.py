#!/usr/bin/env python3
"""Export the public FTS LuaLS declarations without Lua, a compiler or dependencies.

This deliberately reads the declaration subset used by fluentbit.d.lua, not
arbitrary Lua. Unsupported annotations/declarations fail instead of silently
omitting API. Type expressions retain LuaLS syntax for downstream consumers.
"""

import argparse
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / "docs/fts/fluentbit.d.lua"
DEFAULT_OUTPUT = ROOT / "build/fts_api.json"


def typed(text):
    """Split a LuaLS type from its optional name/comment, respecting nesting."""
    quote = None
    depth = 0
    for index, char in enumerate(text):
        if quote:
            if char == quote and (index == 0 or text[index - 1] != "\\"):
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "(<[{":
            depth += 1
        elif char in ")>]}":
            depth -= 1
        elif char.isspace() and depth == 0:
            if text[:index].endswith("|") or text[index:].lstrip().startswith("|"):
                raise ValueError("whitespace around union pipes is unsupported")
            return text[:index], text[index:].strip().removeprefix("#").strip()
    return text, ""


def export(source):
    """Build a manifest from the supported LuaLS declaration subset."""
    manifest = {"version": "1.0.0", "engine": "fts", "constants": [],
                "modules": {"fb": {"require": "fluentbit", "functions": []}}, "types": {}}
    types = manifest["types"]
    owners = {}
    enums = {}
    current = None
    enum = None
    pending = {}
    description = []

    def documentation():
        """Join the documentation attached to the next declaration."""
        return " ".join(description)

    def reset():
        """Clear annotations and documentation consumed by a declaration."""
        pending.clear()
        description.clear()

    for number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("-- ") or line.startswith("-- Compatibility"):
            continue
        try:
            if line.startswith("---@"):
                annotation, _, text = line[4:].partition(" ")
                text = text.strip()
                if annotation == "meta":
                    continue
                if annotation == "alias":
                    name, expression = text.split(None, 1)
                    if name in types:
                        raise ValueError(f"duplicate type {name}")
                    types[name] = {"kind": "alias", "type": expression,
                                   "description": documentation()}
                    reset()
                elif annotation == "class":
                    match = re.fullmatch(r"(\w+)(<[^>]+>)?(?:\s*:\s*(.+))?", text)
                    if not match:
                        raise ValueError("invalid class declaration")
                    name, generics, base = match.groups()
                    if name in types:
                        raise ValueError(f"duplicate type {name}")
                    current = {"kind": "class", "description": documentation(),
                               "fields": [], "methods": []}
                    if generics:
                        current["generics"] = [name.strip() for name in generics[1:-1].split(",")]
                    if base:
                        current["extends"] = base
                    types[name] = current
                    reset()
                    pending["class"] = name
                elif annotation == "field":
                    if current is None:
                        raise ValueError("field outside class")
                    name, rest = text.split(None, 1)
                    expression, comment = typed(rest)
                    current["fields"].append({"name": name.rstrip("?"), "type": expression,
                                              "optional": name.endswith("?"), "description": comment})
                elif annotation == "enum":
                    if text in types:
                        raise ValueError(f"duplicate type {text}")
                    enum = {"kind": "enum", "description": documentation(), "values": []}
                    types[text] = enum
                    pending["enum"] = text
                elif annotation == "param":
                    name, rest = text.split(None, 1)
                    expression, comment = typed(rest)
                    pending.setdefault("parameters", []).append({"name": name.rstrip("?"),
                        "type": expression, "optional": name.endswith("?"), "description": comment})
                elif annotation == "return":
                    expression, comment = typed(text)
                    pending.setdefault("returns", []).append({"type": expression, "description": comment})
                elif annotation == "nodiscard":
                    pending["nodiscard"] = True
                elif annotation == "type":
                    pending["type"] = text
                else:
                    raise ValueError(f"unsupported annotation @{annotation}")
            elif line.startswith("---"):
                comment = line[3:].strip()
                availability = re.fullmatch(r"Availability: ([a-z,]+); modes: ([a-z,]+)\.", comment)
                if availability:
                    pending["signals"] = availability[1].split(",")
                    pending["modes"] = availability[2].split(",")
                else:
                    description.append(comment)
            elif enum is not None and line == "}":
                enum = None
                reset()
            elif enum is not None and not line.startswith("local "):
                match = re.fullmatch(r'(\w+)\s*=\s*("[^"]*"|-?\d+),\s*(?:--\s*(.*))?', line)
                if not match:
                    raise ValueError("unsupported enum member")
                name, value, comment = match.groups()
                enum["values"].append({"name": name, "value": json.loads(value),
                                        "description": comment or ""})
            elif line.startswith("local "):
                match = re.fullmatch(r"local (\w+) = \{\}?", line)
                if not match:
                    raise ValueError("unsupported local declaration")
                name = match[1]
                if "enum" in pending:
                    enums[name] = pending["enum"]
                elif "class" in pending:
                    owners[name] = pending["class"]
                    reset()
                else:
                    raise ValueError("local declaration without type")
            elif line.startswith("function "):
                match = re.fullmatch(r"function (\w+)([.:])(\w+)\(([^)]*)\) end", line)
                if not match:
                    raise ValueError("unsupported function declaration")
                owner, separator, name, arguments = match.groups()
                params = pending.get("parameters", [])
                if [p["name"] for p in params] != [a.strip() for a in arguments.split(",") if a.strip()]:
                    raise ValueError(f"parameter annotations do not match {owner}.{name}")
                function = {"name": name, "description": documentation(), "parameters": params,
                            "returns": pending.get("returns", []),
                            "nodiscard": pending.get("nodiscard", False)}
                if owner == "fb" and separator == ".":
                    function["signals"] = pending.get("signals", ["logs", "metrics", "traces"])
                    function["modes"] = pending.get("modes", ["script", "pack"])
                    manifest["modules"]["fb"]["functions"].append(function)
                elif separator == ":" and owner in owners:
                    types[owners[owner]]["methods"].append(function)
                else:
                    raise ValueError(f"unknown function owner {owner}")
                reset()
            elif line.startswith("fb."):
                match = re.fullmatch(r"fb\.(\w+) = (.+)", line)
                if not match:
                    raise ValueError("unsupported module constant")
                name, expression = match.groups()
                constant = {"name": name, "module": "fb", "description": documentation()}
                if re.fullmatch(r"[A-Za-z_]\w*\.[A-Za-z_]\w*", expression):
                    owner, member = expression.split(".", 1)
                    enum_name = enums[owner]
                    value = next(v for v in types[enum_name]["values"] if v["name"] == member)
                    constant.update(value=value["value"], type=enum_name, category="action")
                else:
                    constant.update(value=None if expression == "nil" else json.loads(expression),
                                    type=pending["type"], category="value")
                # null is a userdata singleton, not Lua nil; the stub uses nil as a placeholder.
                if constant["type"] == "FtsNull":
                    constant.pop("value")
                manifest["constants"].append(constant)
                reset()
            elif line == "return fb":
                if pending or description:
                    raise ValueError("unconsumed annotations or description before return fb")
                reset()
            else:
                raise ValueError("unsupported declaration")
        except (ValueError, KeyError, StopIteration) as error:
            raise ValueError(f"line {number}: {error}: {line}") from error

    if enum is not None:
        raise ValueError("unterminated enum")
    if not manifest["modules"]["fb"]["functions"]:
        raise ValueError("no fb functions found")
    return manifest


def main():
    """Write the manifest or check that the existing artifact is current."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the output is missing or stale")
    args = parser.parse_args()
    try:
        content = json.dumps(export(args.source.read_text(encoding="utf-8")), indent=2,
                             ensure_ascii=False, sort_keys=True) + "\n"
        if args.check:
            if not args.output.exists() or args.output.read_text(encoding="utf-8") != content:
                raise ValueError(f"stale API manifest: {args.output}")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(content, encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
