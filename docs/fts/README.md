# FTS editor definitions and API manifest

Add this directory to LuaLS `workspace.library` (or copy `fluentbit.d.lua` into
your project's definitions directory). For example, in `.luarc.json`:

```json
{
  "workspace.library": ["/path/to/fluent-bit/docs/fts"],
  "runtime.version": "Lua 5.1"
}
```

Use `Lua 5.4` for the portable browser WASM interpreter. The declarations are
IDE stubs; do not execute them or add them to the engine's runtime module path.
The engine supplies `require("fluentbit")`. Callback names come from the `call`
configuration (default `process`), and arguments are local to the callback:

```lua
local fb = require("fluentbit")

---@type FtsFilterCallback
function process(log)
    if log.body:get_string("path") == "/health" then
        return fb.DROP
    end
    if log.attributes then
        log.attributes:set("reviewed", true)
    end
    return fb.KEEP
end
```

For metrics or traces, annotate the callback with `FtsMetricCallback` or
`FtsSpanCallback`. `record` is simply another possible callback argument name,
not a separate global API. Helpers beginning with `_` are implementation details
and are deliberately excluded. There are no public logging utilities.

The definitions follow the bindings in `plugins/processor_fts/`: `KEEP` and
`DROP` are strings, edits commit on `nil`/`KEEP`, and Lua errors roll back edits.
There are no `MODIFY`/`ERROR`, `has`/`delete`, scalar comparison methods, or
hex-decoding bytes constructor. Use `get(key) ~= nil`, `remove(key)`,
`fb.numeric_compare` (author packs only, unavailable in script mode), and raw
byte strings respectively. `parse_json` returns
typed userdata (including typed null), and raises on invalid JSON. Log bodies
must be maps; severity fields use `fb.log_field` and `fb.set_severity` rather
than direct properties. `FtsClassicFilterCallback` documents the separate
numeric-status `filter_lua` ABI and is not an FTS callback contract.

`fb.try_parse_json(text)` returns a typed value or `nil, error` for ordinary
parse failures. `fb.decode_json(container, key)` decodes one string field in
place; log-only `fb.unpack_json(log, field)` replaces the body with a decoded
object, reading `message` by default. Both mutation helpers return `true` on
success or `false, error` without mutation for ordinary decoding failures.
OTel log destinations reject unsigned integers above `INT64_MAX` before mutation.
Invalid mutation arguments and budget exhaustion still raise errors. Helper
boolean results are separate from callback actions: do not return them from
`process`. Ignoring a decoding failure preserves the original data.

Generate the machine-readable manifest from the checkout root with Python
3.9 or later; no third-party packages, Lua executable or Fluent Bit binary are
needed:

```sh
python3 tools/fts/export_api_schema.py
python3 tools/fts/export_api_schema.py --output /tmp/fts_api.json
python3 tools/fts/export_api_schema.py --check
python3 -m unittest discover -s tools/fts/tests -v
```

The default output is `build/fts_api.json` relative to the checkout. The manifest
format version is `1.0.0`; it is independent of Fluent Bit, pack, and recipe
versions. `constants` contains values and descriptions, `modules.fb.functions`
contains signatures, and `types` contains classes, enums, and callback aliases.
Functions also declare `signals` and `modes`: log helpers load for logs only,
telemetry helpers load for metrics and traces, and recipe helpers such as
`numeric_compare` and the state constructors load only for author packs.
Availability describes which VM exports a function; helpers still enforce their
documented signal and binding restrictions at invocation.
Types are LuaLS type expressions, not JSON Schema validation constraints.
Class methods/fields include `extends` for inheritance and `generics` where
applicable; consumers should resolve inherited members. Optional parameters
and fields have an explicit `optional` flag; return types encode nil using `?`
or a union. `nodiscard` marks pure reads or required results; emitting a metric
and removing a key have useful side effects even when their results are ignored.
The `fb.null` constant is a userdata singleton, so it has no JSON `value`.

The exporter accepts the declaration subset used by this file and rejects
unknown annotations and unannotated parameters. Update both when introducing
new annotation syntax. Output is deterministic, and `--check` fails on missing
or stale artifacts. The runtime integration test compares all public module
functions and value methods with the real Lua VM. Keep generated JSON in build
output; downstream tools can distribute that artifact without parsing Lua.

This API manifest complements the recipe/configuration model exported by
`tools/fts/fts_schema.py`; it does not replace native recipe preflight validation.
