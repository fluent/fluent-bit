# FTS catalog: instructions for humans and agents

A block is a Lua factory returning one typed callback. A pack combines the block
source, parameter manifest, example configuration and independent fixtures. A
recipe is an ordered list of blocks; normal consumers configure it without
writing Lua. Studio can read catalog.json and pack.json later, using the same
identifiers and parameter declarations.

Start with catalog.json. A pending entry has policy.json and a dependency
explanation; it has no executable manifest and must not be presented as runnable.
An executable profile has pack.json, blocks/apply.lua, fluent-bit.yaml and
 tests/policy.yaml. Read the source contract and limits in its README first.

For consumption, install trusted files locally and set FTS_PACKAGES_DIR to the
absolute installed packs/fts directory. The example uses that directory plus a
relative manifest reference. External block names are <pack id>/<block name>.
Copy the processor stanza into the correct signal pipeline, choose parameters,
and configure your actual input and output. Relative packages_dir is relative
to the process cwd; use an absolute deployment value to avoid ambiguity.

For authoring, keep policy decisions and source mappings in Lua. Each factory
gets ordinary deep-copied parameter tables, isolated from other factories. The
helper environment remains read-only. Do not retain callback views or implement
persistent caches/counters in Lua closures. Use native state/window capabilities
with their explicit bounds and lifecycle. Dedupe/throttle remain C-backed by the
user's decision.

Reuse validated stateless core operations with fb.block(id, options), during
factory binding. Its signal/privacy/schema/order checks still apply. Compose
returned callbacks in order and propagate DROP. Construct stateful operations
through fb.dedupe, fb.throttle or fb.window instead; those require a terminal
input-log step and state_commit: local. For terminal input-metric steps, construct
`fb.metric_window(options)` and implement the reduction in Lua, as shown by
[the gauge rollup pack](metrics/gauge-rollup/README.md). Never silently replace a temporal window
with in-batch aggregation, or trace retention with individual-span filtering.

Use exact typed decimal-string literals for large integer options. Ordinary Lua
numeric literals are doubles; they cannot express arbitrary 64-bit integers.
Preserve resource, scope, IDs, timestamps, null, bytes and unselected fields.
Missing fields are distinct from explicit null. Keep unknown security/source
versions unless the profile explicitly documents another retention contract.

pack_version versions the manifest grammar; fts_api_version versions the author
API; version is the pack's numeric major.minor.patch. Pin deployed artifact
contents by hash, not just version metadata. Source schemas and parser profiles
need their own explicit supported contract. Breaking changes to output/defaults
require a versioned compatibility decision and fixture diff.

Write expected fixtures independently of the implementation. Include success,
unchanged controls and failure/rollback paths, then execute the real binary both
normally and under the platform memory checker. The runner supports native
Forward logs and OTLP logs/metrics/traces, and never simulates the policy.
Snapshots and verification.json associate source/binary hashes with commands and
results. Linux replay is not a claim of live Windows, macOS or vendor validation.

Construct composed core callbacks in their execution order. Construction-order
checks cannot inspect arbitrary later Lua control flow; helpers still validate
operations transactionally at runtime. Propagate a composed DROP explicitly:

```lua
local f = fb.block('logs.drop_matching', options)
return function(log)
    if f(log) == fb.DROP then return fb.DROP end
    -- Continue only for kept records.
end
```

For recursive parameters, use `pack_version: 2` with strict `object.fields` and
`array.items`. Existing flat packs remain version 1. `recipe_version`,
`fts_api_version` and `fixture_version` remain 1; they version different contracts.
The [schema model](../../plugins/processor_fts/schemas/README.md) explains the
supported subset, bounds, private defaults and the `fb.literal` helper. Copy the
[nested labels example](logs/nested-labels/README.md) for a complete runnable v2 pack
with independent typed fixtures. Do not use Lua numbers for arbitrary 64-bit data.

Agent workflow: read the manifest/source contract → export its block schema with
`--pack`/`--block` → configure the recipe → native `--dry-run` with its actual
pipeline/environment → normal and strict typed replay → pin artifact and runtime
hashes. JSON Schema defaults are annotations and structural success does not
replace native semantic validation. Schema artifacts contain declarations, not
pack Lua or key bytes. Keep required fields caller-supplied; use optional fields
with defaults when the consumer may omit them.
