# FTS authoring model

`fts-model.json` is generated developer metadata for humans, agents and future
Studio forms. Consumers configure recipes and install trusted local packs; they
do not need Lua or a generator on their production host.

The model contains native processor options/defaults from `fluent-bit -J`,
standalone JSON Schemas for the processor, recipe and pack manifest, each core
block's parameters, constructor options and typed literals. Known recipe steps
link to their parameter schemas. Declared privacy blocks require drop behavior;
known native state blocks require explicit local commit. Definitions and numeric
ranges come from the same Lua registry used by binding. Native capability and
exporter source hashes detect drift. JSON Schemas use draft 2020-12.

## Export and check

Build a matching checkout/binary first. Install `tools/fts/requirements.txt` in a
virtual environment and provide a developer Lua interpreter (`lua` or `--lua`).
The bridge executes the trusted in-tree registry only. `--pack` reads local JSON
and never executes pack Lua or downloads dependencies.

```sh
cmake --build build -j8
python3 tools/fts/fts_schema.py --binary "$PWD/build/bin/fluent-bit"
python3 tools/fts/fts_schema.py --binary "$PWD/build/bin/fluent-bit" --check
python3 tools/fts/fts_schema.py --block logs.parse_json --output /tmp/parse.schema.json
python3 tools/fts/fts_schema.py --select processor --output /tmp/fts.schema.json
python3 tools/fts/fts_schema.py --pack packs/fts/logs/nested-labels/pack.json \
  --block org.fluentbit.nested-labels/enrich_logs --output /tmp/labels.schema.json
```

The tool prints the model/artifact and binary hashes. Pin both when reviewing or
deploying a package. `--check` fails when the generated artifact is stale. Select
one schema with `--block` or `--select`; an explicit output avoids overwriting the
full model. Each selected schema is self-contained with a stable content ID and
local definitions. To use a schema from the bundle, extract the chosen object,
for example `model.blocks['logs.parse_json'].parameters`, and pass that object to
a draft-2020-12 validator. Include installed manifests with `--pack` to model their
parameters inside the recipe/processor too.

## Versions and recursive parameters

| Name | Current grammar | Meaning |
| --- | --- | --- |
| `model_version` | 1 | Export bundle/metadata contract |
| `recipe_version` | 1 | Ordered recipe step grammar |
| `fts_api_version` | 1 | Author callbacks and helper API |
| `pack_version` | 1 or 2 | Manifest and parameter declaration grammar |
| Pack `version` | Numeric major.minor.patch | Pack behavior/default/output compatibility |
| `fixture_version` | 1 | Typed real-runtime test format |

Existing flat manifests remain version 1. Version 2 adds `object.fields`,
`array.items`, `literal`, and numeric `minimum`, `maximum`, `integer` constraints.
Unknown descriptor/value keys fail. Object fields use the same descriptors as
root parameters. Arrays have a required item descriptor, which cannot declare
`required` or `default`; those belong to object fields. Version-2 enums apply to
string parameters. Unsupported manifest/API versions fail before records run.

Recursive declarations are bounded to depth 8, 1024 descriptor nodes and 128
fields per object. Arrays have at most 128 items. Generic recursive validation
has depth/visit limits (16/4096), including defaults. Typed literals retain their
own depth/node/size bounds. Version-1 flat declarations retain their legacy
resource behavior. Defaults are deep private copies, then native binding applies
normalization/defaults. Each factory gets a separate mutable parameter graph.
Do not combine required fields with defaults: required means caller-supplied.

`number` is a Lua numeric option. `integer: true` rejects fractional values and
values outside ±9007199254740991. For exact 64-bit values, bytes, null or compound
values, declare `literal`, configure e.g.
`{type: uint64, value: '18446744073709551615'}`, and call `fb.literal(value)` in the
author Lua block. The result is a typed value, ready for `body:set`. A literal's
`bytes` value is a hex string; HMAC environment keys instead use raw bytes.
See the runnable [nested labels pack](../../../packs/fts/logs/nested-labels/README.md).

## What validation proves

Schemas describe canonical JSON/YAML authoring forms. The runtime accepts some
additional legacy normalizations, including empty Lua-container equivalence.
JSON Schema's defaults are annotations; validators do not insert them. Schema
character lengths differ from the runtime's UTF-8 byte limits. `x-fts-*` metadata
records checks that still require the real runtime: exact integer ranges,
finite conversions, total node/depth budgets, roots/context, overlap/collisions,
placement, transform order, state ownership, source paths and factory semantics.
Unknown external blocks require their manifest before their parameter shape is
known; factories can impose additional semantic restrictions.

Always run `fluent-bit --dry-run -c CONFIG.yaml` with the actual binary, pipeline,
installed files and process environment, then real typed fixtures normally and
under the platform memory checker. Offline schema success does not certify source
compatibility, credential provisioning, pipeline placement or delivery. Resolve
configuration templates using the deployment environment before offline value
validation; native preflight remains the final semantic check.

Agents must change runtime descriptors and regenerate the model together. Never
edit the generated JSON manually, maintain another validation definition in C or
Studio, generate expected telemetry from the current implementation, retain
callback views, or place production secrets in defaults/fixtures/schema artifacts.
Keep source/binary/test evidence tied to a commit or immutable snapshot. Packs
live in `packs/fts/`; the authoring tools live in `tools/fts/`.

Primary format references: [JSON Schema objects](https://json-schema.org/understanding-json-schema/reference/object),
[arrays](https://json-schema.org/understanding-json-schema/reference/array) and
[default annotations](https://json-schema.org/understanding-json-schema/reference/annotations).

Model drift checks, schema validation, recursive defaults/boundaries and typed
fixture replay are covered by the integration suite. See the
[verification record](../../../packs/fts/verification.json) for exact commands,
binary hashes, results and platform coverage.
