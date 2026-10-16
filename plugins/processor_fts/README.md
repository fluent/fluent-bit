# Fluent Typed Scripting (FTS) processor

FTS is a processor for writing telemetry policies in Lua. Policies get typed
access to the record and its context: integer widths, binary values, and
nanosecond timestamps are preserved, and OpenTelemetry resources, scopes, and
attributes are exposed as properties instead of raw metadata.

FTS supports logs, metrics, and traces. Its configuration name is `fts`.

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
| `output_limit`      | `64M`     | Maximum serialized size of one processed chunk. Minimum `65536`. |

Size suffixes are decimal: `64K` is 64000 bytes.

## Callback results

| Return value         | Effect |
| -------------------- | ------ |
| `nil` or `fb.KEEP`   | Commit all changes made by the callback. |
| `fb.DROP`            | Remove the item. |
| Lua error            | Roll back every change made by the callback, then apply `error_mode`. |

Changes are transactional per item. Edits to the body, metadata, timestamp,
resource, and scope are committed or rolled back together.

If a processed chunk exceeds `output_limit`, the whole chunk is treated as
failed: `drop` discards it and `keep` forwards the original chunk.

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

Values passed to a callback, and the views obtained from them, are valid only
during that callback. Using one later raises an error. To keep data between
callbacks, store `v:copy()`. Copies are independent: changing them never
changes a committed record.

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

### Example: parse an embedded JSON message

```lua
local fb = require("fluentbit")

function process(log)
    local text = log.body:get_string("message")
    if not text or not text:match("^%s*{") then
        return
    end

    local ok, app = pcall(fb.parse_json, text)
    if not ok then
        return fb.DROP
    end

    fb.redact(app, {"authorization", "password"})
    log.body = app

    if fb.is_otel(log) then
        local level = app:get_string("level")
        if level then
            fb.set_severity(log, level)
        end

        local time = app:get_string("time")
        if time then
            log.timestamp = fb.parse_time(time)
        end
    end
end
```

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

Each chunk logs at most five policy errors plus a summary count. The processor
error metric counts chunks with handled policy failures, and the drop metrics
count removed records.
