# FTS authoring instructions for agents and humans

Status: the implemented API includes 18 catalog profiles, local Lua packs, log
and metric windows, hash/HMAC helpers, recursive manifest v2 parameters and
generated schemas. The OCSF and tenant/egress entries retain explicit dependencies.
Author parameters are private mutable copies; helper environments remain immutable.
Read [design](architecture.md), [catalog](blocks.md),
[current API](../../plugins/processor_fts/README.md),
[pack example](../../packs/fts/multisignal/observability-basics/README.md),
[fixture runner](../../tools/fts/README.md) and applicable AGENTS.md.

## Verification evidence

Tie reviews to a commit or immutable diff and record the binary hash alongside
exact verification commands. Record normal and platform memory-checker results separately.

## Implementation workflow

1. Identify signal, native/OTel context, source version, placement and build.
2. Reuse blocks/native plugins first. Distinguish parser, block, helper, routing
   and state-lifecycle work. Implement only the requested slice.
3. Specify input/output, preserved fields, types, failure behavior and budgets.
4. Write independent fixtures: success, no-match, missing/null, wrong type,
   mutation-then-error, control sibling, composition and replay.
5. Implement bounded operations with public APIs. Respect repository interface,
   test and commit rules; no bundled-library edits without authorization.
6. Share parameter schemas between runtime/docs/Studio. Reject unknowns. Ensure
   preflight continues to use the shared FTS loader through cb_preflight; never
   register runtime resources from that hook.
7. Verify real adapters/pipelines and strict platform memory checking. Report
   exact binary/commands/results/blockers; never invent verification.
8. Review fixture diffs, compatibility and release notes. Separate proposed,
   implemented, tested and certified states.

## Architecture and contracts

fts.c owns registration/config; fts_runtime.c owns VM/loading/budgets;
fts_values.c typed values; fts_recipe.c/fts_recipe.lua native recipe loading,
registry, validation, bounded conditions and isolated block factories; fts_logs.c log transactions; fts_metrics.c and
fts_traces.c native adapters; fts_telemetry.c/fts_proto.c typed staging.
The outer processor runner can fail after FTS commits. Inspect those boundaries.

Native binding: bind(validated parameters, immutable helpers) returns
apply(item), yielding KEEP/DROP or raising a safe classified error. One recipe
binds one callback. No external compiler in core v1. script/code/recipe are
exclusive. Author factories receive ordinary deep-copied parameter tables owned by that
block. Core factories retain immutable parameters; helper environments remain
read-only for both. Use fb.block(id, options) during binding to compose validated
stateless core blocks, respecting their signal/privacy contracts. Lua numeric
options are doubles; exact large integers require typed decimal-string literals.
Controlled per-block environments must protect existing and nested
keys: _G.__newindex and a regex linter alone are insufficient. No swallowed
mutation errors, helper overrides, globals, retained views, per-record I/O or
secret values. Wrapper errors use bounded step/class only, including adapter
failures. Privacy requires drop. Keep legacy script behavior separate.

Immutable environments do not prevent a factory from retaining mutable locals in
its closure. Core blocks must remain pure across items: no counters, mutable caches
or retained record views. Immutable bound constants are allowed. Map literals are recursively sorted by
bytewise key order. Only private pure helpers (parsing and checked numeric conversion) may catch and reclassify
errors before mutations; blocks cannot catch or continue after mutation errors. Each block needs
same-input-twice and interleaved-control tests across separate batches; native state
primitives have a separate explicit lifecycle contract. This is an authoring rule,
not a claim that Lua sandboxing proves purity for arbitrary third-party code.

Core blocks ship with Fluent Bit; recipe_version identifies grammar. Breaking
block revisions need explicit IDs/deprecation and fixture diffs. Co-shipment is
not proof all builds/inputs passed. External packs now use pack_version=1, fts_api_version=1, numeric SemVer and
<pack>/<block> IDs. Loading is local from explicit packages_dir plus relative
manifest paths in packs. Module paths resolve from their manifest. Deployments
must pin artifact hashes; a manifest version alone does not lock mutable files.

The v1 runner supports !int64/!uint64/!double and !!binary in safe bounded
fixtures. These are NOT Fluent Bit configuration tags. It rejects aliases and
duplicate map keys; duplicate-entry adapter cases remain in native integration
tests, rather than !!pairs pack fixtures. Preserve exact integer values, bytes,
null and empty container types. No unsafe loading, real secrets or expected
results derived from the implementation.

## Signal and state checks

Logs: native first; no implicit OTel envelope. Remove/sanitize raw parsed JSON.
Exact times, literal dotted keys, null distinct from missing; no writable tag.
Use logical integer for ordinary numeric field contracts. Plain numeric YAML
literals are supported; preserve exact typed wrappers when exporting through
JavaScript clients. Do not infer signedness from a positive source number.
Metrics: family callbacks; no blind dimension deletion, cumulative relabeling or
quantile sums. Merge buckets before scale; enforce numeric conversion limits and
bounded exemplars. Local checks do not prove global stream uniqueness.
Traces: preserve IDs/parents/times, semantic dropped counts, real route metadata.
A root span is not a complete trace; individual-span drops can orphan children.

Native state/windows are authorized scope. Read [their contract](state-and-windows.md):
input-only terminal step, typed tenant/resource keys, injected monotonic clock,
bounded same-batch overlays and rollback. Immediate decisions explicitly commit
locally, including retained items in v1; source retries after outer failure may
duplicate held items. Release requires atomic engine ownership transfer. HOLD differs from
DROP. One bounded store handles timer retries and closed-key markers. V1 gauge
rollups and volatile shutdown loss are explicit. No free Lua state/timers/emission.
Hash sampling is stateless; every-N is not. Verify native facilities before reuse.

Implementation uses the
existing processor_fts integration suite normally and with strict Valgrind on
Linux or Leaks on macOS. Windows functional/runtime tests remain applicable;
report memory-checker limitations separately. Include retry, filesystem replay,
outer encoding failure, virtual-clock window sequences, enqueue failure and drain.

## Minimal author-owned pack

Create this directory layout under `packs/fts/logs/`:

```text
example-logging/
  README.md
  pack.json
  blocks/redact.lua
  tests/redact.yaml
```

`pack.json` declares the supported signal, parameters and source file:

```json
{
  "pack_version": 1,
  "fts_api_version": 1,
  "id": "com.example.logging",
  "version": "1.0.0",
  "blocks": [{
    "name": "redact",
    "signals": ["logs"],
    "source": "blocks/redact.lua",
    "privacy": true,
    "parameters": {
      "keys": {"type": "strings", "default": ["password"]},
      "replacement": {"type": "string", "default": "[REDACTED]"}
    }
  }],
  "fixtures": ["tests/redact.yaml"]
}
```

`blocks/redact.lua` composes a core operation during factory binding:

```lua
return function(parameters)
    return fb.block('shared.redact_keys', {
        targets = {{root = 'body', path = {}}},
        keys = parameters.keys,
        replacement = parameters.replacement
    })
end
```

`tests/redact.yaml` supplies independent typed input and expected output:

```yaml
fixture_version: 1
signal: logs
processor:
  name: fts
  recipe_version: 1
  packs: [../pack.json]
  error_mode: drop
  recipe:
    - id: privacy
      use: com.example.logging/redact
cases:
  - name: preserve_typed_siblings
    input:
      - body:
          password: synthetic-secret
          sequence: !uint64 18446744073709551615
          payload: !!binary AAECAw==
    expected:
      records:
        - body:
            password: "[REDACTED]"
            sequence: !uint64 18446744073709551615
            payload: !!binary AAECAw==
      outcomes: {kept: 1, dropped: 0, errors: 0}
```

Run the fixture through [the real-runtime runner](../../tools/fts/README.md).
The relative pack reference is resolved from the fixture directory by that tool.
For consumer pipelines, install the pack and use `packages_dir` with
`packs: [logs/example-logging/pack.json]`, as explained in the
[end-user guide](../../packs/fts/README.md).

Add missing/null, wrong-type, no-match, mutation-then-error and composition cases
before distributing a new policy. Include unaffected siblings and verify rollback
with `error_mode: keep` for nonprivacy blocks. Match bounded error identifiers,
and inspect restored fields as well as output counts. Document parameters,
source assumptions, state/precision limits and upgrade behavior in the pack README.

## Shared authoring schemas

Use [the generated authoring model](../../plugins/processor_fts/schemas/README.md),
including the version matrix and semantic gates. `fluent-bit -J` already exposes
native options/defaults; the developer exporter enriches it from the same Lua
registry/descriptors used in binding. Never introduce another C/UI validation
language or manually edit generated JSON. Export one block with `--block`, include
local manifests with `--pack`, and use `--check` in verification. Pack Lua is never
executed by schema export. Match source and binary, then record both hashes.

For new recursive parameters choose manifest version 2; preserve existing flat
v1 packs. Use `object.fields`, `array.items` and `literal` as documented. Numbers
are Lua options; `integer: true` is bounded to safe integers. Exact 64-bit data,
bytes and null use typed literals and `fb.literal`. Arrays/items and schema/value
graphs are bounded. Unknown keys and invalid unused declarations/defaults fail
preflight; required fields remain caller-supplied. Factories get separate default
copies. [Nested labels](../../packs/fts/logs/nested-labels/README.md) supplies a complete
manifest, Lua policy, pipeline and independent real-runtime fixtures.

JSON Schema validates canonical shapes, not deployment semantics. Its defaults
are annotations. Context, sources, precision, total budgets, placement, ordering,
privacy, keys and ownership still require native preflight/replay. Do not label
OCSF mappings or tenant egress enforcement implemented without their dependencies.
