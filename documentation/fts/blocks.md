# FTS block catalog and outcome recipes

The catalog includes 14 stateless core blocks, native state/window operations,
18 executable outcome packs and two pending capability descriptors.
[Design](architecture.md) and [authoring instructions](authoring.md)
define the common contracts. Operators can start with the
[pack consumption guide](../../packs/fts/README.md).

| Users | Core operations |
| --- | --- |
| Logs | JSON parsing, severity, event time, conditional drop, field contracts |
| Shared, independently certified adapters | Field edits, key redaction, string truncation |
| Metrics | Family selection, rename, scale, dimension aggregation, bucket merging |
| Traces | Route-based naming; shared edits/redaction/truncation |

Logs can use eight core blocks. Traces have one specialized and three shared
operations, plus an explicit whole-trace sampling integration track. A shared
helper does not establish safety for every metric/trace root; publish the supported
adapter matrix and reject unsupported scopes at configuration time.

## Core contracts (14 registered blocks)

Each block needs parameter validation, native/OTel adapter fixtures, unaffected
controls, wrong-type/missing/null cases and mutation-then-error rollback tests.
The [verification record](../../packs/fts/verification.json) identifies the
build, adapter combinations and fixtures exercised. Validate additional sources
and platforms before deployment.

### 1. `logs.parse_json`

```yaml
with:
  source: {root: body, path: [log]}
  destination: {root: body, path: [app]}
  remove_source: true
```

Parse a string selector into a typed object at a destination selector. Reject
path overlap; collision defaults to error. `remove_source` defaults false, but
privacy recipes must remove/sanitize the raw JSON too. Remove only after successful
assignment within the transaction. Invalid/duplicate-key JSON, non-object roots,
size/depth/type errors fail. Test exact integers, duplicates and source leakage.

### 2. `logs.normalize_severity`

```yaml
with:
  source: {root: body, path: [level]}
  destination: {root: body, path: [severity]}
  on_unknown: preserve
```

Source selector, named alias profile, destination body selector or `otel`, unknown
policy, overwrite=false. Unknown levels default to preserve. The common profile
includes syslog aliases; equal source/destination implies in-place normalization. Native logs do not need an envelope. OTel destination
requires context and sets semantic text/number. Canonicalize text in the block:
today set_severity preserves the input spelling. Do not infer INFO on absence.
Test aliases, existing/partial severity, wrong types and native-tail behavior.

### 3. `logs.parse_timestamp`

```yaml
with:
  source: {root: body, path: [timestamp]}
  on_missing: skip
```

RFC3339 source selector and missing policy (`skip` or `error`, default `error`).
With `skip`, a missing source leaves the event timestamp unchanged. The OTel
observed timestamp is preserved. No inferred epoch units or wall-clock fallback.
Current helper requires calendar years
1969–2107 AND normalized seconds 0..4294967293, seconds below 60 and at most nine
fractional digits. It does not accept arbitrary pre-epoch dates. Test offset
boundary crossings, precision, invalid dates and overflow on native/OTel logs.

### 4. `logs.drop_matching`

```yaml
with:
  condition:
    all:
      - {selector: {root: body, path: [path]}, op: eq, value: /health}
      - selector: {root: body, path: [duration_ms]}
        op: lt
        value: {type: double, value: 100}
```

Typed selector conditions using supported eq/neq/in/not_in/numeric comparisons
and all/any. Missing/wrong-type operands do not match, including negative
operators. Evaluate the current edited item, not the pre-callback processor
condition. Plain YAML numbers work as literals; integer equality/order are exact
across int64/uint64. Mixed double comparisons do not round the integer operand. Prefix is not currently a conditional operator. No regex/Lua
expressions. Test success/failure/slow health probes, near-paths, missing fields,
prior edits, exactness limits, empty-condition rejection and all-drop batches.

### 5. `logs.validate_fields`

```yaml
with:
  rules:
    - selector: {root: body, path: [level]}
      type: string
      required: true
      enum: [INFO, WARN, ERROR, FATAL]
```

Bounded required/type/enum rules, no coercion. Use logical `integer` for status
codes and other ordinary integer fields; int64/uint64 require exact storage types. Failure invokes recipe error_mode;
report separately from intended filtering. Runtime drift detection complements
fixture tests. Not full JSON Schema or quarantine. Test missing/null, string vs
integer/double, enums, wrong roots and failure after earlier mutations.

### 6. `fields.edit`

```yaml
with:
  operations:
    - op: set_default
      target: {root: body, path: [deployment.environment.name]}
      value: production
```

Ordered set_default/set/copy/rename/remove/keep with structured selectors and typed
constants. Collision=error; preserve_destination leaves source untouched. Defaults
fill absent keys only. Literal prefix selection can apply to keep/remove.
Support native log body/user metadata, OTel attributes/resource/scope, and span
attributes/resource/scope; forbid reserved metadata/IDs/timestamps. Span attribute
removal updates dropped counts with overflow checks through a semantic adapter.
Metric resource/scope edits require an identity-safe profile; no arbitrary point
attribute removal. Test copies/types, duplicates, order, collisions, counts,
sibling isolation and cross-callback metric identity assumptions.

### 7. `shared.redact_keys`

```yaml
with:
  targets: [{root: body, path: []}]
  keys: [authorization, password]
```

Supported roots, case-insensitive exact keys and replacement. Recursive maps and
arrays; error_mode=drop mandatory. Known-absent optional roots can skip; malformed
context cannot. No text/URL/blob/embedded-JSON promise. Test each declared root,
duplicates, mixed case, arrays, raw-source survival, diagnostics and batch errors.
Metric identity scopes need separate certification, not automatic enablement.
Event/link roots redact attribute maps only, preserving their IDs, names and times.
Canonicalized duplicate attributes update semantic dropped counts.

### 8. `fields.truncate`

```yaml
with:
  target: {root: body, path: [message]}
  max_bytes: 4096
  marker: {root: body, path: [message_truncated]}
  collision: error
```

String selectors, UTF-8 byte ceiling, explicit marker selector and collision
behavior. Do not invent marker keys from dotted strings. Preserve valid codepoint
boundaries; reject invalid UTF-8/wrong types and protected ID targets. Test exact,
zero and multibyte boundaries, markers and replay. Even native log strings must
be valid UTF-8; invalid bytes raise invalid_utf8 and apply recipe error_mode. A private bounded UTF-8 helper enforces this contract.
This is neither exact serialized payload sizing nor sensitive-content detection.

### 9. `metrics.select`

```yaml
with: {keep: {names: [duration_ms]}}
```

Exactly one keep/drop rule with names and/or literal prefixes. Whole families;
retained data/context/type/unit/temporality untouched. Keep rules deliberately
remove unknown families. Test prefix near-matches, same names across contexts,
empty-rule rejection and all types/all-drop. No point-level selection implied.

### 10. `metrics.rename`

```yaml
with: {mapping: {duration_ms: duration_seconds}}
```

Exact old/new mapping; reject static many-to-one/cyclic/chained mappings. Preserve values,
unit and temporality. Target collisions in other batches/producers require source
contracts: no unbounded global name set. Test existing targets, contexts, replay
and unchanged values. Renaming does not establish semantic-convention compliance.

### 11. `metrics.scale`

```yaml
with:
  names: [duration_ms]
  input_unit: ms
  factor: 0.001
  output_unit: s
  numeric_policy: allow_double
```

Names, expected input unit, positive finite factor, output unit, numeric_policy
preserve_integer(default) or allow_double. Explicitly permit supported int64 to
double conversion; never silently round values beyond the helper's exact input
range. Even integral factors use number conversion today. Scale bounds/exemplars
with values; preserve counts/time/temporality. Reject exponential histograms.
Test every supported type, precision/overflow, units and replay. Merge explicit
buckets BEFORE scale using source-unit boundaries; exact-double comparisons can
fail afterward. No automatic tolerance or step reordering. Use exact source-unit bucket boundaries before scaling; add independent
precision and boundary fixtures for changes.

### 12. `metrics.aggregate_dimensions`

```yaml
with:
  names: [http.requests]
  keep_attributes: [http.request.method, http.response.status_code]
  operation: sum
  max_exemplars: 0
```

Names, retained attributes, supported operation and bounded deterministic exemplar
policy. Sum supported sums/explicit histograms; supported gauge operations require
explicit choice. Preserve context and start/end windows. Different reset times
remain distinct. Do not add summary quantiles/exponential histograms. The block caps exemplars DURING copying/accumulation, not afterward; the
legacy helper retains its old behavior when no cap argument is supplied. Test exact
sums, windows, flags/layouts, counts, exemplars and source stream uniqueness. This
is family-local aggregation, not a global cardinality cap or temporal rollup.

### 13. `metrics.merge_histogram_buckets`

```yaml
with: {names: [duration_ms], bounds: [50, 250, 1000]}
```

Exact names and retained source-unit bounds, an exact subset of existing bounds.
Preserve overflow bucket, totals, time, temporality and applicable exemplars.
Protect profile SLO thresholds. Test missing/exact bounds, count overflow,
conservation, windows and ordering with scale. The block and order guard have integration coverage; verify additional
producer/backend combinations with independent fixtures.

### 14. `traces.name_from_route`

```yaml
with:
  method_attribute: http.request.method
  route_attribute: http.route
  on_missing: preserve
```

Method/route attribute names and missing policy. Initial HTTP SERVER profile:
use actual route, display _OTHER as HTTP; preserve names if route absent. Other
span kinds pass unchanged. No digit-path guessing; client template support needs
another profile. Test type/context, replay, unchanged IDs/parents/time/status/
events/links. Traces additionally use shared stateless blocks. Whole-trace retention remains a future extension.

## Native decisions and windows

Read the [transaction and lifecycle contract](state-and-windows.md) before deploying
stateful processing. Local dedupe/throttle, request log windows, stable log
sampling and temporal gauge rollup are implemented. Cross-signal log-to-metric
connectors and whole-trace retention recipes are future extensions; they are not
available as the block IDs listed in this catalog.

| Unit | Consumer controls | Essential tests |
| --- | --- | --- |
| Stable-log-sampling pack | Stable hash/version/seed, key selectors, rate, missing-key policy | Cross-runtime vectors, replay, 0/100%, key absence; no claim of retaining every error in a trace |
| `logs.dedupe` | Trusted tenant/key, TTL, max keys/bytes, overflow | Same-batch duplicate, expiry, key ambiguity, restart, rollback, untracked overflow |
| `logs.throttle` | Key, declared token-bucket rate/burst, monotonic clock, limits | Boundary times, burst, concurrent batches, idle eviction, state rollback |
| `window.hold_until` | Request key, fixed max hold, error condition, expiry/late/overflow rules | ERROR before deadline, late ERROR, empty timer tick, retained exceptions, queue failure, drain |
| `metrics/gauge-rollup` author pack | Gauge sum/mean/min/max/count, fixed processing time, identity, limits | Arrival order, identity, selected timestamp, non-gauge rejection, retry |
| Log-to-metric connector (future) | Log selectors, metric schema/dimensions, window | Cross-signal routing, valid aggregation, count conservation, cardinality/queue bounds |
| Whole-trace retention (future) | Trace grouping/conditions/wait/limits | Late spans, worker affinity, retry, overflow, drain, topology and ownership |

Immediate stateful and buffered steps are terminal and input-only initially.
Buffered v1 requires `state_commit: local`: a source retry after an outer
encoding/append failure can duplicate items already held in the volatile store.
`state_commit: external` is a future v2 receipt design, not supported syntax.
Release into the engine still requires atomic ownership transfer on acceptance.
Hash sampling is stateless; every-N sampling is a different stateful policy.
Source-affinity requirements, volatile crash/shutdown loss and local-state scope are
visible configuration contracts. No promise of complete requests/traces or
exactly-once delivery. Existing native plugins may satisfy some units after
verification; do not duplicate them simply to claim an FTS-branded block.

## Twenty policy outcomes

The [executable catalog](../../packs/fts/CATALOG.md) contains eighteen
profiles, each with a source contract, parameters and independent fixtures.
OCSF and tenant/egress entries remain pending. Use each pack's README to determine whether its
source schema and behavior match your deployment.

| User outcome | Composition / missing dependency |
| --- | --- |
| Structured secrets protection | redact_keys on each certified signal/root |
| Application JSON logs | parse_json → severity → redaction; add explicit timestamp parsing if needed |
| Kubernetes metadata hygiene | native enrichment → fields.edit; backend label configuration separate |
| Successful-probe reduction | normalize source → drop_matching; failure/latency exemptions |
| Metric dimension reduction | aggregate_dimensions; identity-safe source contract |
| Service/resource identity | fields.edit defaults; trusted source, no request IDs as producer identity |
| Structured URL sanitization | Explicit absolute/origin-form URL profile; free-text detection is separate |
| Stable span operations | name_from_route; reviewed additional naming profiles later |
| Log/trace correlation | Semantic OTLP identifier promotion with validated IDs and fixtures |
| Metric compatibility | selected gauge scale → rename; histogram merging is a separate core block |
| Event quality and size | validate_fields + truncate; exact serializer budget remains future |
| Stable log sampling | Lua keep/drop over versioned fixed-seed XXH3 modulo |
| CloudTrail investigation | source parser/mapper → validation → redaction; retain relevant reads |
| Windows security logs | structured source + versioned event mapping; preserve unknown/security events |
| VPC flow normalization | declared layout parser → typed mapping; retain REJECT/SKIPDATA |
| Firewall onboarding | vendor/version parser + mappings; retain threat/deny/audit classes |
| OCSF mapping | source-specific mapper + pinned schema validation; no generic renaming shortcut |
| Tenant/egress governance | trusted identity + classification + native routing; attributes alone do not enforce it |
| Stable pseudonyms | Lua framing and field policy over native HMAC with opaque key references |
| GenAI privacy | source-version profiles remove content; retain usage/latency; no fabricated token counts |

Additional window-based recipes include duplicate suppression, burst control,
retain-debug-on-request-error and gauge rollups. Delta rollups and error-aware whole-trace sampling are future extensions.
The implemented subset and its limits are documented in the
[state/window contract](state-and-windows.md); delta rollups and whole-trace retention
remain future capabilities.

## Extension priorities and evidence

Extend coverage using real native-log, metric and trace adapters, classified
diagnostics and independent fixtures. Preserve local commit, release ownership
and timer teardown contracts when adding stateful operations.

Later capabilities include pinned OCSF mappings, authenticated tenant/egress
enforcement, broader bounded text scanning, exact output sizing, HTTP status
inference and trace-event projection. Semantic log/trace correlation and native
HMAC-backed pseudonyms have implemented, fixture-verified profiles.
We reject per-span filtering as a default replacement for whole-trace decisions.
The public README's span-drop example demonstrates API capability, not a safe
trace-retention guarantee.

Each block page must say what changes, what stays, how failures behave, which
parameters users choose, and which fixtures/platforms were actually verified.
No usage percentages or confidence scores have been measured for this catalog.

For workflow precedents and design tradeoffs, see [design references](research.md).
