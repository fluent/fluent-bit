# FTS blocks: compose telemetry processing

Status: 18 executable catalog profiles, Lua packs, bounded state/windows,
hash/HMAC helpers and versioned authoring schemas are implemented. The OCSF and tenant/egress entries retain explicit dependencies. See [operational contracts](state-and-windows.md)
and [verification evidence](../../packs/fts/verification.json).

Read the [catalog](blocks.md) for operations and the
[authoring contract](authoring.md) for implementation instructions.
The [FTS README](../../plugins/processor_fts/README.md) remains the current API.

## Two things to learn

- A **block** performs one operation with parameters and included tests.
- A **recipe** runs an ordered list of blocks for one signal.

Example: parse a log message → normalize its level → redact sensitive keys.
The user configures values, not Lua. Core blocks ship with Fluent Bit. Local **packs** distribute additional blocks, recipes and fixtures; users do not need
an installation/registry workflow to try the core library.

Logs are the initial center of gravity, including ordinary `tail` and Kubernetes
logs. Metrics and traces have dedicated recipes and useful units from the first
release. Fluent Bit owns collection, routing, storage, retries, and export.
Studio will edit these same recipes and render parameter forms from the same
schemas. A CLI/file workflow must remain sufficient without Studio.

## Examples: native YAML recipes

### Native logs, no OpenTelemetry envelope required

```yaml
pipeline:
  inputs:
    - name: tail
      path: /var/log/app/*.log
      processors:
        logs:
          - name: fts
            recipe_version: 1
            context: native
            error_mode: drop
            recipe:
              - id: decode
                use: logs.parse_json
                with:
                  source: {root: body, path: [log]}
                  destination: {root: body, path: [app]}
                  remove_source: true
                  on_missing: error
              - id: level
                use: logs.normalize_severity
                with:
                  source: {root: body, path: [app, level]}
                  destination: {root: body, path: [level]}
                  on_unknown: preserve
              - id: protect
                use: shared.redact_keys
                with:
                  targets: [{root: body, path: []}]
                  keys: [authorization, password, access_token]
  outputs:
    - name: stdout
      match: '*'
```

This assumes each `tail` record has a JSON string in `body.log`. The JSON is
stored as `body.app` and the raw string is removed only after successful parsing.
Otherwise secrets could survive in the original string despite redacting the
parsed map. Level normalization writes a native body field, not OTel metadata.
Failure discards the item; some construction/limit failures affect a batch.

OTel recipes can choose `destination: otel` for severity and target OTel
attributes explicitly. They require `context: otel`. Native recipes that need
OTel semantics can place `opentelemetry_envelope` before FTS deliberately.
`context: any` permits mixed native/OTel records only when every step supports
that mixture. An absent optional OTel root in a recognized native record is a
no-op for redaction; malformed or unrecognized context is not proof of absence.
Context checks occur per item as well as at startup where input facts are known.

### Metrics: reduce buckets before converting units

```yaml
processors:
  metrics:
    - name: fts
      recipe_version: 1
      error_mode: keep
      recipe:
        - id: select
          use: metrics.select
          with: {keep: {names: [legacy_http_duration_ms]}}
        - id: buckets
          use: metrics.merge_histogram_buckets
          with: {names: [legacy_http_duration_ms], bounds: [50, 250, 1000]}
        - id: seconds
          use: metrics.scale
          with:
            names: [legacy_http_duration_ms]
            input_unit: ms
            factor: 0.001
            output_unit: s
            numeric_policy: allow_double
        - id: name
          use: metrics.rename
          with: {mapping: {legacy_http_duration_ms: app.http.duration}}
```

This fragment belongs under an appropriate input. Its source contract requires
an explicit histogram whose existing boundaries include 50, 250 and 1000 ms.
The allowlist intentionally discards every other family. Merge runs before scale
because the current merge helper requires exact boundary equality and floating
point multiplication can change the representation. No implicit step reordering.
The name is an application metric, not a claim of OTel semantic conformance.

### Traces: stable operations and privacy

```yaml
processors:
  traces:
    - name: fts
      recipe_version: 1
      error_mode: drop
      recipe:
        - id: operation
          use: traces.name_from_route
          with: {on_missing: preserve}
        - id: protect
          use: shared.redact_keys
          with:
            targets:
              - {root: attributes, path: []}
              - {root: events, path: []}
              - {root: links, path: []}
              - {root: resource.attributes, path: []}
              - {root: scope.attributes, path: []}
            keys: [authorization, cookie, password]
```

This fragment names HTTP SERVER spans from actual method/route metadata and
redacts configured structured keys. It preserves trace/span/parent IDs and
span timing. No inferred templates from arbitrary numeric paths. Whole-trace
sampling is composed with the native sampling processor, subject to its own
lifecycle verification. Dropping a SERVER/root span is not a safe substitute:
children can still reference that span.

## Native loading instead of an external compiler

Recommended first implementation: FTS accepts a nested YAML `recipe` variant,
validates parameters, binds embedded core blocks, and assembles one callback
at initialization. `script`, `code`, and `recipe` are mutually exclusive.
Existing script/code behavior remains available unchanged.

There is precedent for variant configuration in `processor_sampling` and for
embedding helper code in FTS. This avoids a separate recipe compiler, generated
Lua files, source maps, and a lockfile before external dependencies exist.
The recommendation is architectural, not an implementation effort estimate.
Typed configuration still requires a careful variant-to-Lua/FTS adapter, memory
accounting and immutable parameter views. No string concatenation into code.

Core block source has one declarative parameter schema used by runtime
validation, documentation, tests and Studio. Implement a small documented schema
subset; do not create competing C and UI validation definitions. Unknown block
IDs, parameters, operators, signals and recipe versions fail validation.

Use `fluent-bit --dry-run -c config.yaml` for preflight. The reload property-check
path now invokes the optional processor `cb_preflight` hook. FTS shares its bounded
loader/configuration checks with startup and destroys its temporary context without
starting collectors/listeners or registering metrics. Borrowed nested configuration
survives repeated preflight and subsequent startup. Hot reload rejects an invalid
replacement before stopping the working pipeline.

## Ordered composition and transactions

1. Each recipe processes one signal. Callback units are one log record, one
   metric family, or one span. DROP of a metric item removes a family.
2. Steps execute in file order and see earlier edits. A deliberate DROP stops
   the recipe. Reordering can change privacy, units, selection, and identity.
3. One bound callback per recipe provides item-level rollback on an uncaught
   policy error. Separate processors have independent commits.
4. The recipe has one `error_mode`: `keep` restores the original item at recipe
   entry; `drop` removes it. Privacy blocks require `drop` at validation time.
5. No per-step catch-and-continue. A trusted wrapper may catch only to replace
   error text with a bounded class and step ID, then rethrow. Never log raw
   exception text in recipe mode, even on a generic fallback path.
6. Blocks cannot alter globals, helpers, or other callbacks' items/parameters.
   External factories own private mutable parameter copies; core parameters and
   helper facades remain immutable. An `_G.__newindex` guard alone does not
   protect existing keys or nested tables; a regex linter is not enforcement.
7. All steps share execution budgets. C helpers need their own bounded-work
   contracts: the Lua instruction hook does not preempt arbitrary C work.
8. Resource/scope edits remain item-local. Snapshot views are not persistent
   state. Cross-callback state is native and transactional as specified below.

### What atomicity does not promise

FTS item rollback is not an end-to-end pipeline or delivery transaction. Log
output construction can fail as a batch; metrics/traces can fail after typed
staging during adapter decoding. Logs are encoded again by the outer processor
runner after the FTS callback returns. These boundaries matter for native state.

Existing safety limits and `error_mode` still apply to batch construction.
Privacy enforcement must cover all actual output routes; another route can
bypass FTS entirely. The sandbox handles trusted configuration, not hostile
code isolation. Recipes have no ordinary network, filesystem or secret access.

### Observable failures are a release requirement

Add bounded counters for item outcomes `kept`, `dropped_by_policy`,
`dropped_on_error`, and batch outcome `batch_failed`, labeled only with configured
instance/step IDs and enumerated error classes. Include signal and unit of count:
records, families, or spans. Batch failure is a separate measure; do not sum it
with item drops. Define rolled-back attempt accounting explicitly.

These are processing attempts, not unique deliveries or billing savings.
No customer IDs, dynamic field values, or exception strings in metric labels.
Current FTS error metrics count handled-error batches and cannot distinguish
all these outcomes. Error sanitization must also cover adapters and initialization.
A minimal sanitized tombstone is a future log-only option after rollback, not
an existing behavior and not a substitute for metrics-family failure handling.

## Selectors and simple conditions

Canonical selector: `{root: attributes, path: [http.request.method]}`. The path
contains one literal key. `[http, request, method]` contains three nested keys.
Recipe selectors currently traverse map keys; array indexes are not accepted. Do not add a dotted-string shortcut in v1;
OTel and application keys containing dots make context-dependent guessing costly.

`logs.drop_matching` uses a declared subset of existing condition semantics:
`eq`, `neq`, `in`, `not_in`, and supported numeric comparisons, with `all`/`any`.
Its resolver sees the current edited item. The existing FTS processor condition
runs before the callback, so it cannot simply substitute for per-step conditions.
The generic evaluator stringifies operands and uses atof, so recipes implement
a bounded typed evaluator instead of reusing that coercing path. Equality and
membership compare numeric values exactly across signed/unsigned integers.
Ordered integer comparisons use sign, decimal length and lexical digits, avoiding
Lua-number conversion. Mixed integer/double comparisons use the represented double
value without rounding the integer. Other scalar types must match. Missing/wrong-type operands do not match even neq/not_in.
Conditions are bounded to depth 8 and 128 nodes, with nonempty all/any lists.
A step may add `when` with the same condition object; it sees preceding edits.
No generic metric selectors are available for when in recipe v1.
Literal prefixes are supported for names/field selection, not represented as
unbounded regex. Prefix is not currently an existing condition operator.

## Versioning: start with built-in blocks

- Core code, schemas, fixtures and blocks ship with the Fluent Bit release.
- The optional `recipe_version` defaults to 1; unknown versions fail. Keep the
  version explicit in exported examples and Studio output.
- Stable block IDs define behavioral contracts. Breaking parameter/default/output
  changes require an explicitly versioned API/implementation and a documented
  migration. No block-ID suffix or automatic migration is implemented. Release notes include behavioral fixture diffs.
- Pin the deployed Fluent Bit artifact, not just a mutable image tag. Build
  features can differ; unknown or unavailable blocks fail preflight.
- Bundling runtime and block does not prove correctness. Certification covers
  published runtime/build/signal combinations and fixtures actually executed.

Local external packs declare `pack_version: 1` or `2`, `fts_api_version: 1` and
pack SemVer. Load explicit local JSON manifests from per-processor
`packages_dir`; external blocks use `<pack>/<block>` IDs and the same immutable
factory environment. See [the executable pack](../../packs/fts/multisignal/observability-basics/README.md).
Pin the deployed content hash. Supported runtime ranges, automatic artifact
resolution, publisher signatures and a lockfile remain future distribution work;
metadata SemVer alone does not lock a mutable directory. Source/schema versions
remain separate from runtime versions.
Never auto-upgrade production behavior. Customer recipes remain separate from
installed code so updates do not overwrite local parameters.

## Native state and windows

Native decisions and buffering extend the same recipe model, input-only initially.
Immediate dedupe/throttle use explicit local commits with declared failure risks.
Retaining windows require ownership integration and one bounded native store.
Initial temporal rollup supports gauges; windows explicitly allow shutdown loss.
Privacy runs before stateful steps. No unrestricted Lua state/timers/emission.
See the [state and window contract](state-and-windows.md) for lifecycle and tests.

## Tests and delivery

Fixtures ship with blocks and run through production adapters. Use registered
YAML tags !int64/!uint64/!double and !!binary with safe bounded parsing;
keep duplicate-entry adapter cases in native integration tests;
never assume arbitrary parser precision or Studio JavaScript Number fidelity.
Typed fixture syntax is separate from Fluent Bit configuration. Compare types,
contexts, order and counts; include full recipe rollback and privacy diagnostics.

Native windows add virtual-clock multi-batch tests, same-batch state visibility,
outer encode/adapter failure, rollback, bounded enqueue retry, overflow, restart,
drain and thread coordination. Native runtime tests require the platform memory
checker. The fourteen stateless blocks have passed their recorded runtime checks.
Local decisions, retained log windows and metric-family windows have focused
verification. See [authoring](authoring.md) for reproducible checks.
The fixture runner replays independent typed cases against the real runtime.

## Evidence

[Catalog research](blocks.md) links the public workflow precedents.
Architecture, ordering and launch priorities are design judgments, not usage or
performance measurements. Runtime verification is recorded in
[verification evidence](../../packs/fts/verification.json); source and placement
contracts still require deployment-specific validation.

The [generated authoring model](../../plugins/processor_fts/schemas/README.md)
shares runtime descriptors and native `-J` metadata. Manifest v2 extends existing
v1 packs with bounded recursive objects/arrays and typed literals. Forms and
agents use the exported canonical shapes, followed by native `--dry-run` and
independent typed fixtures. Production hosts need no schema exporter or Lua CLI.
