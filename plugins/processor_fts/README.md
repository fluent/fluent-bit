# Fluent Typed Scripting (FTS) processor

FTS is a processor for writing telemetry policies in Lua. Policies get typed
access to the record and its context: integer widths, binary values, and
nanosecond timestamps are preserved, and OpenTelemetry resources, scopes, and
attributes are exposed as properties instead of raw metadata.

FTS supports logs, metrics, and traces. Its configuration name is `fts`.

The experimental browser WASM profile includes FTS when `FLB_WASM_LUA=ON`
(the default). It uses the portable Lua 5.4 interpreter; `jit: true` is rejected.
Typed values, restricted policy libraries and instruction/memory limits remain
available. Setting `FLB_WASM_LUA=OFF` disables both FTS and the Lua filter.

| Signal  | Callback          | Called once per |
| ------- | ----------------- | --------------- |
| Logs    | `process(log)`    | log record      |
| Metrics | `process(metric)` | metric family   |
| Traces  | `process(span)`   | span            |

## Quick start

```yaml
pipeline:
  inputs:
    - name: opentelemetry
      port: 4318
      processors:
        logs:
          - name: fts
            script: policy.lua
  outputs:
    - name: stdout
      match: '*'
      format: otlp_json
```

```lua
local fb = require("fluentbit")

function process(log)
    if log.body:get_string("path") == "/health" then
        return fb.DROP
    end

    fb.redact(log.body, {"authorization", "password", "access_token"})

    if fb.is_otel(log) then
        log.resource.attributes:set("deployment.environment.name", "production")
        log.attributes:set("sanitized", true)
    end
end
```

Use one processor entry and one script for each signal.

## Configuration

| Key                 | Default   | Description |
| ------------------- | --------- | ----------- |
| `script`            |           | Path to the Lua policy file. Set either `script` or `code`. |
| `code`              |           | Inline Lua policy. Set either `script` or `code`. |
| `call`              | `process` | Name of the callback function. |
| `error_mode`        | `drop`    | What happens to an item when its policy fails: `drop` removes it, `keep` forwards the original. |
| `instruction_limit` | `1000000` | Maximum Lua instructions per callback and during script load. Minimum `1000`. `0` is allowed only with `jit: true`. |
| `jit`               | `false`   | Enable the LuaJIT compiler. Requires `instruction_limit: 0`. |
| `memory_limit`      | `32M`     | Maximum memory for the policy: the Lua heap plus the typed values it holds. Minimum `262144`. |
| `output_limit`      | `64M`     | Maximum serialized size emitted by one processed batch. Held records use the state budget. Minimum `65536`. |

Size suffixes are decimal: `64K` is 64000 bytes.

## Callback results

| Return value         | Effect |
| -------------------- | ------ |
| `nil` or `fb.KEEP`   | Commit all changes made by the callback. |
| `fb.DROP`            | Remove the item. |
| Lua error            | Roll back every change made by the callback, then apply `error_mode`. |

Changes are transactional per item. Edits to the body, metadata, timestamp,
resource, and scope are committed or rolled back together.

For logs, if a processed batch exceeds `output_limit`, the whole batch is
treated as failed: `drop` discards it and `keep` forwards the original batch.
For metrics and traces the limit is checked per item: an item whose result does
not fit follows `error_mode` (`drop` removes it, `keep` forwards the original
item), and the whole batch fails only when the kept originals do not fit
either. Internal failures, such as a batch that cannot be decoded, apply
`error_mode` to the whole batch.

A batch is the set of records handed to one callback run. Small chunks are
processed as one batch. Larger buffers, such as complete chunks reaching output
processors, are processed in batches of about 64 KiB or 1024 records, so
decoded records never hold more than one batch in memory. Groups, such as one
OpenTelemetry resource and scope, are never split across batches.

A group can also span appends, for example when its start and end markers
arrive in separate forward messages. A group still open at the end of a batch
stays open for the records that follow. Records that arrive before the end
marker of a group opened earlier are processed without a context, keep their
place in that group, and cannot set one.

For privacy policies such as redaction, keep the default `error_mode: drop`.
With `keep`, an item whose policy fails is forwarded unmodified.

## Typed values

Bodies, attributes, and other structured fields are typed maps and arrays.

### Map and array methods

| Method                     | Applies to   | Description |
| -------------------------- | ------------ | ----------- |
| `v:get(key)`               | map, array   | Child value, or `nil` when missing. Array indexes start at 1. |
| `v:get_string(key)`        | map          | String value, or `nil` when missing. Fails on another type. |
| `v:get_number(key)`        | map          | Numeric value as a Lua number, or `nil` when missing. |
| `v:get_bool(key)`          | map          | Boolean value, or `nil` when missing. |
| `v:set(key, value)`        | map, array   | Set a value. Replaces every entry with the same key. |
| `v:remove(key)`            | map          | Remove every entry with that key. |
| `v:ensure_map(key)`        | map          | Return the child map, creating it when missing. |
| `v:append(value)`          | array        | Append a value. |
| `v:keys()`                 | map          | Lua table with the keys in order. |
| `v:len()`                  | map, array   | Number of entries. |
| `v:type()`                 | any          | `map`, `array`, `string`, `bytes`, `bool`, `int64`, `uint64`, `double`, or `null`. |
| `v:value()`                | scalar       | Lua value. 64-bit integers are returned as exact decimal strings. |
| `v:number()`               | numeric      | Lua number. Fails when an integer is beyond ±(2^53 − 1). |
| `v:copy()`                 | any          | Independent, writable copy. |

Keys match exact bytes; a dot in a key has no special meaning.

### Constructors

| Constructor        | Creates |
| ------------------ | ------- |
| `fb.map()`         | Empty map |
| `fb.array()`       | Empty array |
| `fb.int64(v)`      | Signed 64-bit integer from a decimal string or a safe Lua integer |
| `fb.uint64(v)`     | Unsigned 64-bit integer from a decimal string or a safe Lua integer |
| `fb.bytes(s)`      | Binary value |
| `fb.null`          | Null value |

Lua strings, booleans, and numbers can be passed to `set` and `append`
directly. Lua numbers are stored as doubles; use `fb.int64` or `fb.uint64` for
integers. Lua tables and `nil` are not values: use `fb.map()`, `fb.array()`,
and `fb.null`.

### Value lifetime

Log values passed to a callback, and the views obtained from them, are valid
only during that callback. Using one later raises an error. Metric and span
values are snapshots made for the callback: they stay readable afterwards, but
changing them never affects later items or committed output, and keeping them
retains their memory. To keep data between callbacks, store `v:copy()`. Copies
are independent: changing them never changes a committed record.

Lua globals persist for the lifetime of the processor instance.

## Logs

| Property                                    | Description |
| ------------------------------------------- | ----------- |
| `log.body`                                  | Record body map. Can be replaced with another map. |
| `log.metadata`                              | Record metadata map. |
| `log.timestamp`                             | `{sec, nsec}` table. Assign a new table to change the event time. |
| `log.tag`                                   | Routing tag, read-only. |
| `log.attributes`                            | OpenTelemetry log attributes. |
| `log.resource.attributes`, `.schema_url`    | OpenTelemetry resource. |
| `log.scope.attributes`, `.name`, `.version`, `.schema_url` | OpenTelemetry instrumentation scope. |
| `log.context.attributes`, `.metadata`       | Group attributes and metadata of non-OpenTelemetry grouped logs. |

OpenTelemetry properties exist only for logs that carry OpenTelemetry context,
for example logs received by the `opentelemetry` input. Use `fb.is_otel(log)`
to check. To give ordinary logs OpenTelemetry context, place the
`opentelemetry_envelope` processor before FTS.

Resource, scope, and context changes apply only to the current record. Record
order is preserved.

### Log helpers

| Helper | Description |
| ------ | ----------- |
| `fb.is_otel(log)` | `true` when the log has OpenTelemetry context. |
| `fb.set_severity(log, level)` | Set severity text and number from a level name: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, and common aliases. |
| `fb.set_trace_context(log, trace_hex, span_hex)` | Set the trace and span IDs from hexadecimal strings. IDs must be nonzero. |
| `fb.log_field(log, name)` | Read an OpenTelemetry log field such as `severity_number`, `trace_id`, or `observed_timestamp`. |
| `fb.unpack_json(log, field)` | Decode a JSON object from a body field (`message` by default) and replace `log.body`. Return `true` on success or `false, error` for a missing/non-string field, ordinary parse failure, or non-object JSON; the original body is preserved for these failures. Uses the same typed parser and limits as `fb.parse_json`. |

Instruction-limit exhaustion in the JSON helpers fails the callback instead of
returning a recoverable decode error. Changes are rolled
back and `error_mode` determines the record outcome: the default `drop` removes
the record, while `keep` forwards the original.

### Example: parse an embedded JSON message

```lua
local fb = require("fluentbit")

function process(log)
    fb.unpack_json(log, "message")
    fb.redact(log.body, {"authorization", "password"})
end
```

The example allows mixed streams to pass plain text through. The unpack call
keeps plain text, missing/non-string fields, malformed JSON, and non-object JSON
unchanged. `fb.redact` matches keys in maps and arrays; it does not inspect
secrets inside the unchanged message string. If every forwarded message must be
decoded for key-based redaction, drop records when decoding fails:

```lua
function process(log)
    if not fb.unpack_json(log, "message") then return fb.DROP end
    fb.redact(log.body, {"authorization", "password"})
end
```

### Decode a field in place

Use `fb.decode_json(container, key)` to replace only the selected string field
with its decoded value. The same helper works with body maps, nested maps,
OpenTelemetry attributes, and array elements:

```lua
function process(log)
    fb.decode_json(log.body, "message")
    if fb.is_otel(log) then
        fb.decode_json(log.attributes, "payload")
        fb.decode_json(log.resource.attributes, "labels")
    end
    fb.redact(log.body, {"authorization", "password"})
end
```

For example, `{"message":"{\"level\":\"info\"}","host":"web"}` becomes
`{"message":{"level":"info"},"host":"web"}`. By comparison,
`fb.unpack_json(log, "message")` produces `{"level":"info"}` as the whole body.
Both operations decode one selected string; strings inside the decoded JSON
require another explicit call.

`fb.decode_json` accepts any valid JSON value, including arrays, null, and
booleans. `fb.unpack_json` requires an object because a log body must be a map.
Missing/non-string fields and ordinary parse failures return `false, error`
without changing the target. Successful decoding returns `true`. Invalid
container/key arguments, expired views, and failures while applying a mutation
raise errors and follow the callback's `error_mode`.

For OpenTelemetry log bodies and attributes, the JSON helpers reject unsigned
integers above `9223372036854775807` (`INT64_MAX`), including values nested in
objects or arrays. OTLP AnyValue integers must fit signed 64 bits. The helpers
return `false, error` before mutation, preserving the original field or body.
Ordinary logs, detached scratch maps, `fb.parse_json`, and `fb.try_parse_json`
retain full unsigned 64-bit support.

These helper statuses are separate from callback results. Leaving `process`
without an explicit return is equivalent to `return fb.KEEP`: successful
changes are committed and the record is forwarded. To remove a record, return
`fb.DROP` explicitly; do not return a helper's boolean status from `process`.

Use `fb.try_parse_json(text)` when you need the parsed value without mutating a
container. `fb.parse_json(text)` remains the throwing parser.

## Metrics

`process(metric)` runs once per metric family. Resource and scope changes apply
to that family only.

```lua
local fb = require("fluentbit")

function process(metric)
    if metric.name == "http.server.duration" then
        metric.name = "http.server.request.duration"
        fb.scale_metric(metric, 0.001, "s")
    end

    for i = 1, metric.datapoints:len() do
        metric.datapoints:get(i):get("attributes"):remove("request.id")
    end
end
```

| Property                                      | Description |
| --------------------------------------------- | ----------- |
| `metric.name`, `.description`, `.unit`        | Family identity. |
| `metric.type`                                 | `gauge`, `sum`, `histogram`, `exponential_histogram`, or `summary`. Only gauge and sum can be converted into each other. |
| `metric.datapoints`                           | Array of datapoint maps. |
| `metric.aggregation_temporality`              | `unspecified`, `delta`, or `cumulative`. |
| `metric.is_monotonic`                         | Monotonicity of a sum. |
| `metric.resource`, `metric.scope`             | Same properties as for logs. |

Datapoint maps use OpenTelemetry field names in snake case, for example
`attributes`, `time_unix_nano`, `start_time_unix_nano`, `as_int`, `as_double`,
`count`, `sum`, `bucket_counts`, `explicit_bounds`, `quantile_values`, and
`exemplars`. Timestamps and counts are exact integers. Histogram buckets are
per-bucket counts.

Removing a datapoint attribute can make two series identical, which fails the
policy. Use `fb.aggregate_metric` to combine them deliberately.

### Metric helpers

| Helper | Description |
| ------ | ----------- |
| `fb.metric_value(point)` | Scalar value of a gauge or sum datapoint. |
| `fb.set_metric_value(point, value)` | Set the scalar value of a datapoint. |
| `fb.scale_metric(metric, factor, unit)` | Multiply values by a positive factor and optionally set the unit. Applies to gauges, sums, histograms, and summaries, including bounds and exemplars. |
| `fb.aggregate_metric(metric, keys, op)` | Keep only the listed attributes and combine equal series. `op` is `sum`, or for gauges also `min`, `max`, `mean`, or `count`. |
| `fb.merge_histogram_buckets(metric, bounds)` | Merge histogram buckets into a subset of the existing bounds. |
| `fb.copy_metric(metric, name, description, unit)` | Emit a copy of the family with a new name. |
| `fb.extract_metric(metric, field, name, monotonic)` | Emit a sum derived from a histogram or summary: `count`, `sum`, or `avg`. |

Emitted families follow the original and continue through the pipeline. They
are not passed to the callback again. Returning `fb.DROP` removes the original
and keeps the emitted families; an error discards both.

Scalar values use the OpenTelemetry int64 and double types. Native unsigned
64-bit values up to 2^63 − 1 are passed to the policy as int64. Families with
larger values are not passed to the policy; `error_mode` decides whether they
are kept unchanged or dropped.

## Traces

`process(span)` runs once per span. Resource and scope changes apply to that
span only.

```lua
local fb = require("fluentbit")

function process(span)
    if span.attributes:get_string("http.route") == "/health" then
        return fb.DROP
    end

    fb.redact(span.attributes, {"authorization", "password"})
    fb.redact(span.events, {"authorization", "password"})
end
```

| Property | Description |
| -------- | ----------- |
| `span.name`, `.trace_state`, `.kind`, `.flags` | Span fields. `kind` is the numeric OpenTelemetry span kind. |
| `span.trace_id`, `.span_id`, `.parent_span_id` | Hexadecimal IDs. An empty parent ID marks a root span. |
| `span.start_time_unix_nano`, `.end_time_unix_nano` | Exact nanosecond timestamps. The end must not precede the start. |
| `span.attributes` | Attribute map. |
| `span.status` | Map with `code` and `message`. |
| `span.events`, `span.links` | Arrays of event and link maps. |
| `span.dropped_attributes_count`, `.dropped_events_count`, `.dropped_links_count` | Dropped counts. |
| `span.resource`, `span.scope` | Same properties as for logs. |

Dropping spans or changing IDs can break trace topology; FTS does not repair
parent references.

## Common helpers

| Helper | Description |
| ------ | ----------- |
| `fb.redact(value, keys, replacement)` | Replace the values of matching keys in nested maps and arrays. Key matching is case-insensitive. The default replacement is `[REDACTED]`. |
| `fb.keep_keys(map, keys)` | Remove every key not listed. |
| `fb.parse_json(text)` | Parse a JSON document into typed values. Integer widths are preserved; duplicate keys and nesting beyond 64 levels are rejected. Input is limited to 1 MiB. |
| `fb.decode_json(container, key)` | Decode a string field in a typed map or array in place. Return `true` on success or `false, error` for a missing/non-string field or ordinary parse failure. Preserve sibling fields and leave the source unchanged on failure. Array indexes start at 1; map keys are literal. |
| `fb.try_parse_json(text)` | Return the same typed value as `fb.parse_json`, or `nil, error` for invalid JSON or non-string input (including a missing field). JSON `null` returns a typed null value, and JSON `false` returns a typed boolean value. The same parser and policy limits apply. |
| `fb.parse_time(text)` | Parse an RFC 3339 timestamp into `{sec, nsec}`. |

Key-based redaction does not inspect free-form strings; secrets embedded in
message text need an explicit string policy.

## Limits and sandbox

- Values can have at most 64 levels of nesting.
- OpenTelemetry strings and keys must be valid UTF-8 without NUL characters;
  use `fb.bytes` for binary data.
- Only `require("fluentbit")` is available. The filesystem, process, FFI,
  debug, coroutine, and module loading libraries are disabled, as are `print`,
  `xpcall`, `getfenv`, `setfenv`, and `module`. `collectgarbage` accepts only
  `collect`, `count`, and `step`.
- The instruction limit counts Lua instructions, not elapsed time. Lua string
  pattern functions run in C and are not interrupted; avoid unbounded patterns
  on untrusted input.
- With `jit: true` there is no CPU limit. Use it only for policies whose
  execution time you control.
- The sandbox is not a security boundary: policies are trusted configuration.
- Each processor instance has its own Lua state.

## Diagnostics

Each batch logs at most five policy errors plus a summary count. The processor
error metric counts batches with handled policy failures, and the drop metrics
count removed records.

## Native recipes

`recipe` is an ordered list of built-in operations. It is mutually exclusive
with `script` and `code`; `recipe_version` defaults to `1`. Unknown versions,
blocks, parameters, duplicate step IDs and unsupported signals fail initialization.
Fourteen stateless blocks are registered: `logs.parse_json`, `logs.normalize_severity`,
`shared.redact_keys`, `fields.edit`, `metrics.select`, `metrics.rename`,
`metrics.scale`, `metrics.merge_histogram_buckets`, `traces.name_from_route`,
`logs.parse_timestamp`, `logs.drop_matching`, `logs.validate_fields`,
`fields.truncate`, and `metrics.aggregate_dimensions`. Two additional local
state blocks, `logs.dedupe` and `logs.throttle`, are described below.
`fluent-bit --dry-run -c config.yaml`
validates recipes using the same bounded loader as startup, without starting
listeners, collectors or processor metrics. Hot reload also validates the new
recipes before stopping the old pipeline. Invalid replacements leave it running.
Validation creates and destroys one bounded Lua VM per FTS instance, roughly
one additional initialization per dry-run or reload. Native processor plugins
opt in to this hook with `FLB_PROCESSOR_FLAG_PREFLIGHT`; legacy DSO descriptors
retain their original field offsets and are copied only through their legacy size.

```yaml
processors:
  logs:
    - name: fts
      recipe_version: 1
      context: native
      error_mode: drop
      recipe:
        - id: privacy
          use: shared.redact_keys
          with:
            targets: [{root: body, path: []}]
            keys: [password, authorization]
            replacement: "[REDACTED]"
```

Selectors use a root plus an array of literal keys. Redaction traverses structured
maps/arrays; it does not inspect JSON embedded in strings. Privacy blocks require
`error_mode: drop`. Any failure reverses the item's preceding recipe edits and
applies the configured error mode. No `pcall`, global writes or helper mutation
is available to block code. Each core block receives its own immutable parameter graph
and environment. Maintainers iterate parameter lists with the provided `ipairs`
or `h.length`, not raw Lua table operations.

The core registry in `fts_recipe.lua` defines parameter validation and schema metadata
in one place and ships in the binary. Author-supplied source is loaded through
[reusable local Lua packs](#reusable-local-lua-packs). Block factories use separate
restricted environments. New blocks require signal-specific fixtures and adapter verification.

Recipe diagnostics include the validated step ID and a fixed error class; they
never include the raw Lua error. `fluentbit_fts_recipe_callbacks_total` counts
callback outcomes (`keep`, `drop`, `error`), labeled by owner name, input/output scope, processor, stage and signal in the
owner's metrics context. These are callback attempts, not delivery outcomes:
subsequent batch construction/encoding can still fail, output retries can repeat
callbacks, and an error kept by `error_mode` is counted as `error`, not `keep`.
A metric callback is one family; a trace callback is one span.

For recipe metric renames, collision checks account for preceding unconditional core `metrics.select` steps in the current OTLP scope, up to the first rename or author block. A preceding rename can fail and roll back; subsequent checks conservatively retain the original namespace. Conditional and author-defined transformations cannot be predicted. No batch-local check reserves names across independent producers or later batches.

Bucket merging must precede scaling for overlapping metric names; the loader
rejects the opposite order. Scale requires `names`, `input_unit`, positive finite
`factor`, and `output_unit`. `numeric_policy: preserve_integer` (default) rejects
fractional scaling of integer points/exemplars; `allow_double` permits it subject
to the existing exact input conversion limits. Merge takes `names` and strictly
increasing `bounds` which must be an exact subset of source-unit boundaries.

The [consumer examples](../../documentation/fts/architecture.md) cover
native tail logs, metrics and traces. The [catalog](../../documentation/fts/blocks.md)
contains parameter examples for fourteen stateless core blocks and documents
the implemented state/window APIs and local packs. Remote package distribution is a future capability.

`metadata` selectors require `context: native`, and their first path component
cannot be `otlp`. OTel attribute edits use `attributes`, `resource.attributes`, or
`scope.attributes`. Redaction of trace `events` and `links` visits their attribute
maps only, preserving event names, IDs and timestamps. Removing attributes with
`fields.edit`, or canonicalizing duplicate redacted attributes, increments the
applicable semantic dropped-attribute count with uint32 overflow checking.

`fields.edit` accepts an ordered `operations` list with `set`, `set_default`,
`copy`, `rename`, `remove`, and `keep`. `target` and `source` use structured selectors.
Existing parent maps are required. Keep and bulk remove accept `names` and/or
literal `prefixes` on a map target. Copy/rename default to `collision: error` and
`on_missing: skip`; `preserve_destination` leaves the source intact. `set_default`
fills only absent keys, preserving explicit null and false.

Constants may be strings, booleans, plain YAML integers/doubles, or explicit typed values such as
`{type: uint64, value: "18446744073709551615"}`,
`{type: double, value: 1.5}`, `{type: "null"}`, or
`{type: bytes, value: "0001ff"}` (hexadecimal bytes). Map/array literals use
`{type: map, value: {key: ...}}` / `{type: array, value: [...]}` recursively.
Plain YAML integers are preserved as exact decimal literals by the loader and
written as int64 when negative, uint64 otherwise. Explicit `type: integer` uses
the same logical type. Explicit int64/uint64 remain available. Use quoted decimal
strings with a typed wrapper when exporting through clients such as Studio that
use IEEE-754 numbers, or when requiring strict integer range validation. Numeric parameter strings use
decimal syntax without whitespace or hexadecimal notation; the YAML parser may
already have converted unquoted numeric scalars, whose spelling is no longer
available to FTS. Nonfinite numbers are rejected.

`metrics.rename` checks target names within the current resource/scope batch.
This is not a global uniqueness guarantee across producers or batches. Static
many-to-one/cyclic/chained mappings and incompatible scale/rename/merge order are rejected.
`traces.name_from_route` changes SERVER spans only; missing routes preserve the
name by default. Missing/unknown methods use `HTTP`, and client spans pass through.
Names longer than 1024 bytes preserve the original span name.

Configuration diagnostics identify `param` and a bounded `reason` without printing
values. Runtime classes distinguish `wrong_type`, `unsupported_conversion`,
`missing_field`, `collision`, `invalid_context`, `invalid_json`, `invalid_timestamp`,
`invalid_utf8`, `validation_failed`, and `budget_exceeded`, with
`operation_failed` as a fallback. The privileged wrapper relaunches classified
errors so that the normal transaction rollback still applies; blocks cannot catch
errors themselves. Immutable environments do not prove closure purity: core
blocks are reviewed and tested with repeated inputs and independent controls.

`logs.normalize_severity` preserves unknown levels by default and accepts common
syslog aliases. It trims surrounding whitespace. Equal source/destination means
in-place normalization even with `overwrite: false`. OTel severity number zero
is unspecified and does not prevent setting a level; an existing severity text
still does. Map constants in `fields.edit` are emitted in recursively sorted
bytewise key order, independent of YAML mapping order.

`fields.edit` remove/keep operations and duplicate canonicalization by
`shared.redact_keys` increment the applicable `dropped_attributes_count`, including
OTel log, resource, scope, span, event and link attributes where supported.
Renaming or overwriting a value is not counted as an explicit remove operation. This is the FTS recipe contract; it differs from Collector
transform processors that do not necessarily account for deliberate removals.

`logs.parse_timestamp` writes event time from strict RFC3339 while preserving
observed time. No epoch guessing or wall-clock fallback is used. `logs.validate_fields`
checks bounded required/type/enum rules without coercion; failure uses recipe
error_mode and is not an intentional filter. Use `type: integer` for ordinary
fields such as status codes: it accepts signed/unsigned 64-bit integers across
transports. Exact int64/uint64 type checks are opt-in; double remains distinct.
Null is a type, distinct from absence.

`logs.drop_matching` takes a `condition` object. Use `all`/`any` lists, or a leaf
with `selector`, `op` and `value` (`values` for `in`/`not_in`). Operators are
`eq`, `neq`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`. Constants use the same typed
literal format as fields.edit; `value: 200` works directly. Numeric comparisons
are exact across int64/uint64 without converting the integer to Lua number. Mixed
integer/double comparisons use the represented double value and preserve integer
boundaries; fractional doubles never equal integers. Non-numeric types must match.
Wrong types, nonfinite operands and missing fields never match, including negative
operators. An already-rounded double does not recover its original source integer. Step-level `when` uses this same grammar
and reads the current edited item. A false condition skips that step.

`fields.truncate` accepts a string target, max_bytes (0..1048576) and an explicit
marker selector. It validates the complete UTF-8 string before cutting at a
codepoint boundary, including for native log strings that can contain arbitrary
bytes. Invalid strings raise `invalid_utf8` and apply error_mode. On truncation it sets the marker to true, subject to
collision error/overwrite; otherwise it leaves the marker untouched. Parents
must exist; target/marker may not overlap. Replaying an already truncated value
makes no further edit. It does not measure serialized record size.

`metrics.aggregate_dimensions` groups points within each family by retained
attributes AND exact start/end timestamps. Gauge operation is explicit
sum/min/max/mean/count; sums and explicit histograms permit sum only. Flags and
histogram layouts must agree within a group. `max_exemplars` (0..128, default 0)
keeps the first N in input order, bounded during copying and accumulation.
Retained exemplars preserve their filtered attributes and IDs; dropping dimensions
does not redact those fields. The default zero retains no exemplars.
The optional fourth argument of legacy fb.aggregate_metric exposes the same cap;
omitting it preserves legacy behavior. Different resources/scopes and time
windows never merge. This is not cross-batch aggregation or a global series cap.

### Local deduplication and keyed throttling

`logs.dedupe` and `logs.throttle` are terminal recipe steps, available only in
input processors. Specify `state_commit: local` explicitly. State belongs to
one processor instance and disappears on restart, reload or shutdown. Route
related events to that same instance; multiple inputs/processes do not share
state. Apply privacy and normalization before the decision.

```yaml
processors:
  logs:
    - name: fts
      context: native
      state_commit: local
      state_limit: 1M
      recipe:
        - id: privacy
          use: shared.redact_keys
          with:
            targets: [{root: body, path: []}]
            keys: [password, authorization]
        - id: duplicates
          use: logs.dedupe
          with:
            tenant: {root: body, path: [trusted_tenant]}
            keys: [{root: body, path: [event_id]}]
            ttl_ms: 60000
            max_keys: 1024
            max_key_bytes: 1024
            on_missing: error
            overflow: keep
```

Use tenant identity from a trusted source. A key contains typed, length-prefixed
selector values in the configured order. String `"1"`, integer `1`, double `1.0`,
boolean and null are distinct; signed and unsigned integer widths normalize to
one exact decimal integer identity. Strings and bytes stay distinct. Containers
and nonfinite doubles are rejected. Missing keys default to an error; explicit
`on_missing: keep` passes the item without tracking it.

Both blocks accept `keys` (1–16 selectors), optional `tenant`, required `ttl_ms`
(1–86400000), `max_keys` (default 1024, maximum 65536), `max_key_bytes` (default
1024, maximum 65536) and `overflow: keep`. The byte limit applies to the whole
encoded identity, including type and length prefixes. `state_limit` (default
`1M`, decimal suffix) covers native entry payloads, tables and provisional state;
allocator overhead is not included. The base and overlay bucket tables each use
one pointer per bucket, rounded up to the next power of two at least `max_keys`
(maximum 65536 buckets). Their memory is reserved at initialization and counts
against `state_limit`; a limit too small for bookkeeping is rejected. A fresh
random per-instance seed distributes keys using XXH3; it is not a pseudonym or
cryptographic digest. Key identity and policy parameters do not depend on it.
Lua temporary keys also consume `memory_limit`.
Proposals for existing keys also need overlay space; a nearly full store can
overflow even for a known key. Capacity or oversized-key overflow passes an untracked sanitized item and counts
it; this weakens suppression deliberately. No live key is evicted to make room.
Allocation or instruction-budget failures remain policy errors, not overflow.

Dedupe keeps the first key and drops repeats until its TTL expires. A repeat does
not extend TTL. Throttle adds required integer `rate` (tokens/second) and `burst`
(initial and maximum tokens), each 1–1000000. Each admitted item consumes one
token; rejected items advance refill accounting without consuming a token.
Throttle TTL measures inactivity, including rejected attempts, and must be at
least `ceil(1000 * burst / rate)` milliseconds so idle expiration cannot grant
a premature burst. Time uses a monotonic clock sampled once per FTS batch;
expiration is swept on the next batch, without a timer or background thread.
This maintenance scan is outside the per-callback instruction budget: it visits
at most 65536 buckets and 65536 live keys per batch. Commit also visits the
bucket table. Size `max_keys` for the expected workload; tiny batches with a very
large configured table pay that scan even when most buckets are empty.

For example, replace the final step above with:

```yaml
- id: burst_control
  use: logs.throttle
  with:
    tenant: {root: body, path: [trusted_tenant]}
    keys: [{root: body, path: [service]}]
    rate: 10
    burst: 50
    ttl_ms: 60000
    overflow: keep
```

Later items in the same batch see earlier proposals. Item errors roll back their
proposals; intentional DROP confirms its specified accounting. FTS output
construction failure rolls back the entire batch overlay. Commit requires no new
allocation. The local commit occurs at the successful FTS batch boundary, before
outer serialization, downstream processors or storage can fail. Consequently,
a later failure can suppress a duplicate whose original was lost, or consume
throttle capacity without delivery. This is best-effort local suppression, not
end-to-end deduplication. There is no outer-failure observer or delivery counter.

Metrics share recipe owner/scope/processor/stage/signal labels, plus a fixed
`outcome`: `fluentbit_fts_state_keys` (`current`),
`fluentbit_fts_evictions_total` (`expired`, TTL cleanup only),
`fluentbit_fts_overflow_untracked_total` (`keep`),
`fluentbit_fts_local_state_commits_total` (`local`) and
`fluentbit_fts_dropped_by_policy_total` (`drop`). Suppression and overflow counters
publish only committed decisions; the keys gauge counts committed keys. TTL
cleanup is maintenance independent of policy rollback. None measures delivery.

### Request log windows

`window.hold_until` is a terminal input recipe step. It admits complete sanitized
log events into bounded native ownership, decides at a fixed processing-time
deadline, then resumes at the following processor stage. The Lua step evaluates
`retain_when` and optional `keep_when`; the native store does not interpret log
levels or request fields. Configure typed `keys`, `hold_ms`, `late_ms`,
`ready_timeout_ms`, `max_keys`, `max_key_bytes`, `overflow: keep` and
`on_missing: error|keep`. Retention requires `state_commit: local` and uses
`state_limit` separately from callback/output budgets.

See [the complete Tail example](examples/recipes/window-request-error/README.md)
for behavior, configuration, counters and the volatile ownership contract.
Supported input candidates are dummy, tail, forward, http and opentelemetry;
validate the selected input/build with the published fixtures. Metrics and
traces cannot use this log block. Temporal gauge rollup remains a separate unit.

## Reusable local Lua packs

A recipe can combine core blocks with author-owned Lua modules from local packs.
See the runnable [observability pack](../../packs/fts/multisignal/observability-basics/README.md)
and [typed fixture runner](../../tools/fts/README.md). Configure an explicit
`packages_dir` and a `packs` array of relative JSON manifest paths. External IDs
use `<pack>/<block>`; packs are trusted local configuration with no runtime
downloads. Manifest/API grammar versions are distinct from pack SemVer. Pin the
deployed artifact hash.

Author factories receive deep private copies of validated parameters in ordinary
Lua tables. The helper environment remains read-only. They can use `fb.dedupe`,
`fb.throttle` and `fb.window` during binding to construct a native bounded state
operation, then invoke the returned function on each typed log. The policy stays
in Lua. These constructors require a terminal input-log step and explicit
`state_commit: local`; their state is volatile and local to that instance.

Author factories can compose stateless core blocks using `fb.block(id, options)`.
The runtime validates options, signal, privacy mode, rename collisions and metric
transformation order through the core registry. Construct during binding; runtime
construction and wrapping stateful blocks are rejected. Use typed decimal-string
literals for exact large integer options; ordinary Lua numeric options are doubles.
Relative `packages_dir` paths resolve against the process cwd, not the config file
directory. Prefer explicit absolute paths (or an absolute deployment environment
variable) in services and containers.

See the [twenty-outcome catalog](../../packs/fts/CATALOG.md): eighteen
executable profiles and two pending capabilities. Profiles state their
source contracts and limits. Start with the [pack consumption guide](../../packs/fts/README.md).

### General author hash and HMAC APIs

`fb.hash64(bytes)` returns a 16-character lowercase XXH3-64 fingerprint.
`fb.hash64_algorithm` is `xxh3-64-v1-seed0`: fixed seed zero, stable versioned
contract. `fb.hash64_mod(bytes, modulus)` performs the full 64-bit remainder in C
and returns an exact Lua number for an integer modulus from 1 to 1,000,000,000.
Inputs are strict byte strings up to 1 MiB. Native work consumes the callback
instruction budget when instruction limits are enabled. Hashing is suitable for
stable sampling; it provides no secrecy.

`fb.hmac_sha256(key_ref, bytes)` returns 64 lowercase hexadecimal characters.
Configure `secret_refs: {email-v1: FTS_PSEUDONYM_KEY_V1}`: values are environment
variable names, resolved once during initialization into a native key cache.
References are opaque to Lua. Limit: 16 references, identifiers of 128 ASCII
characters, nonempty keys of at most 4096 bytes and messages up to 1 MiB. Missing
keys fail initialization without revealing their contents. The native cache is
charged to the callback VM memory budget and wiped when destroyed; the process
environment and core environment cache have their own lifecycle. This does not
claim to erase those other copies. Pack authors frame tenant/domain/input bytes
unambiguously and include the key version in emitted pseudonyms. Rotation needs
a new reference and deployment plan. See the [pseudonyms pack](../../packs/fts/logs/pseudonyms/README.md) and its public
RFC 4231 test vectors.

Key deployment: use a **process environment variable injected by the orchestrator**.
Fluent Bit also resolves names from its YAML `env:` block; putting a key there
stores it as plaintext in the configuration file and is unsuitable for these
examples. `secret_refs` contains only public variable names and key-version refs.
Keys use the raw non-NUL bytes of the environment string. Hex/base64 text is used
as those literal characters; it is not decoded. No `encoding` option is supported.
Provision the intended raw key bytes through the process environment and never
copy production keys into packs, fixtures, YAML `env:`, or schema artifacts.


### Temporal metric-family windows

The [gauge rollup pack](../../packs/fts/metrics/gauge-rollup/README.md) uses a general
snapshot-retention controller with Lua reductions. It requires OTLP input,
terminal placement in its recipe and explicit local state commit. It releases at
stage+1 without invoking Lua in the timer. Counters declare `metric_families` as
their unit; this is separate from metric datapoints and delivery acknowledgements.
The pack documents fixed processing-time windows, bounded state, overflow,
shutdown loss and integer precision.


### Versioned recursive author parameters and model export

Manifest grammar 1 remains available. Grammar 2 adds strict `object.fields`,
`array.items` and exact typed `literal` parameters, plus bounded numeric options.
Defaults are private recursive copies, validated at binding; unused v2 declarations
and defaults are checked too. `fb.literal` materializes validated literal config
as typed values in author packs. Runtime code and exported forms share nested
structural descriptors and numeric ranges.

Read the [authoring model and version matrix](schemas/README.md) and the runnable
[nested labels pack](../../packs/fts/logs/nested-labels/README.md). The generated model
combines live native `-J` options with block/constructor/manifest/recipe schemas.
Agents can export one reusable unit using `fts_schema.py --block`; native preflight
and real typed replay remain required for deployment. Export needs a matching
checkout/binary and a developer Lua CLI; production consumption needs neither.
