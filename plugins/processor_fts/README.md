# Fluent Typed Scripting (FTS) processor

Fluent Typed Scripting (FTS) runs telemetry policies written in Lua, with typed
access to logs, metrics, traces, and OpenTelemetry context. Its configuration
name is `fts`.

"Typed" describes how FTS handles telemetry data, not the Lua language. Lua
stays dynamically typed and policies are not type checked. What FTS keeps is
the type of every telemetry value: 64-bit signed and unsigned integers, doubles,
binary data, nulls, maps and arrays keep their exact type and value unless the
policy changes them. OpenTelemetry resources, scopes, and attributes are
properties of the item instead of raw metadata that the policy has to decode.

| Signal  | Callback          | Called once per |
| ------- | ----------------- | --------------- |
| Logs    | `process(log)`    | log record      |
| Metrics | `process(metric)` | metric family   |
| Traces  | `process(span)`   | span            |

- [Quick start](#quick-start)
- [Examples](#examples)
- [Availability](#availability)
- [FTS or the Lua filter](#fts-or-the-lua-filter)
- [Configuration](#configuration)
- [Callback results and errors](#callback-results-and-errors)
- [Typed values](#typed-values)
- [Logs](#logs), [Metrics](#metrics), [Traces](#traces)
- [Common helpers](#common-helpers) and [redaction limits](#redaction-limits)
- [Limits and sandbox](#limits-and-sandbox)
- [Diagnostics](#diagnostics)

## Quick start

Processors are configured in YAML. Save this as `fluent-bit.yaml`:

```yaml
pipeline:
  inputs:
    - name: dummy
      dummy: '{"user": "ana", "password": "hunter2", "path": "/login", "status": 200}'
      samples: 1
      processors:
        logs:
          - name: fts
            code: |
              local fb = require("fluentbit")

              function process(log)
                  if log.body:get_string("path") == "/healthz" then
                      return fb.DROP
                  end

                  fb.redact(log.body, {"password"})
                  log.body:set("environment", "dev")
              end

  outputs:
    - name: stdout
      match: '*'
      format: json_lines
      json_date_key: false
```

Run it and stop it with Ctrl-C:

```shell
fluent-bit -c fluent-bit.yaml
```

```json
{"user":"ana","password":"[REDACTED]","path":"/login","status":200,"environment":"dev"}
```

For longer policies, put the code in a file and set `script` instead of `code`.
Use one processor entry and one policy for each signal.

## Examples

[`examples/fts`](../../examples/fts/README.md) has complete examples with
configuration, policy, input, run command, and expected output:

- [Logs](../../examples/fts/logs-redaction/README.md): redaction of sensitive
  fields and free-form text, dropping records, severity and resource
  enrichment.
- [Metrics](../../examples/fts/metrics-normalization/README.md): unit
  normalization and aggregation that reduces series cardinality.
- [Traces](../../examples/fts/traces-filtering/README.md): attribute
  transformation and selective span drop.

## Availability

FTS is in the `master` branch, which currently builds as Fluent Bit 5.2.0. It
is not part of any published release: the latest release, v5.1.5, and the
`5.1` branch do not include it. Release packages and container images include
FTS only from the first release that contains it. Until then, build from
source.

Run `fluent-bit --help` and look for `fts` in the processor list to check
whether a binary includes it.

### Build options

| Option              | Default | Requirement |
| ------------------- | ------- | ----------- |
| `FLB_PROCESSOR_FTS` | `ON`    | Builds the processor. |
| `FLB_LUAJIT`        | `ON`    | Required for native builds. FTS is not built without it. |
| `FLB_YYJSON`        | `ON`    | Required. |

The build turns `FLB_LUAJIT` off on riscv64, and on s390x unless
`FLB_PREFER_SYSTEM_LIB_LUAJIT` is enabled with a system LuaJIT. FTS is not
available on those builds.

### Native and browser WASM runtimes

Native builds run policies on the bundled LuaJIT 2.1. The JIT compiler is off
unless `jit: true` is set.

The experimental browser WASM profile (`FLB_WASM_BROWSER=ON`) also includes
FTS, through the portable Lua 5.4 interpreter enabled by `FLB_WASM_LUA=ON`, the
browser default. Differences from native builds:

- `jit: true` is rejected.
- Lua 5.4 language and library behavior applies instead of LuaJIT's Lua 5.1.
- Typed values, the restricted policy environment, and instruction and memory
  limits work as in native builds.
- `FLB_WASM_LUA=OFF` removes both FTS and the Lua filter.

The browser profile as a whole is experimental; see
[the browser WASM guide](../../documentation/wasm-browser.md).

## FTS or the Lua filter

Both run Lua. They differ in what they process, how they see values, and what
happens when a script fails.

|                         | FTS processor (`fts`) | Lua filter (`lua`) |
| ----------------------- | --------------------- | ------------------ |
| Signals                 | Logs, metrics, traces | Logs |
| Where it runs           | Input and output `processors` | `pipeline.filters`, or `processors.logs` |
| Values                  | Typed: int64, uint64, double, bytes, null, maps and arrays are kept exactly | Converted to Lua tables and numbers |
| OpenTelemetry context   | `resource`, `scope`, `attributes` and log fields as properties | Group attributes and record metadata as plain tables (five-argument callback) |
| Failed script           | The item's edits are rolled back; `error_mode` drops it (default) or forwards the original | The error is logged and the whole chunk passes unmodified |
| Resource limits         | Instruction, memory and output limits | None |
| Lua environment         | Restricted: no `io`, `os`, `require` of other modules, `print` | Full standard library, `require` of modules |
| Records per call        | One item in, kept or dropped. Metrics can emit derived families | Can return several records for one input |
| Configuration format    | YAML | YAML and classic |

For example, with the record
`{"big": 18446744073709551615, "id": 9007199254740993, "n": null}`, a Lua
filter that only changes another field outputs `"big": -9223372036854775808`
and `"id": 9007199254740992`, and drops `"n"`. FTS forwards all three
unchanged.

Choose FTS for metrics and traces, for policies that must not change values
they do not touch, such as IDs, counters and nulls, for OpenTelemetry context,
and where a failure must not forward unprocessed data. Choose the Lua filter
when a script needs the standard library or Lua modules, such as file access or
`os.time`, needs to split one record into several, or must run in a classic
configuration file.

## Configuration

| Key                 | Default   | Description |
| ------------------- | --------- | ----------- |
| `script`            |           | Path to the Lua policy file. Set either `script` or `code`. |
| `code`              |           | Inline Lua policy. Set either `script` or `code`. |
| `call`              | `process` | Name of the callback function. |
| `error_mode`        | `drop`    | What happens to an item when its policy fails: `drop` removes it, `keep` forwards the original. |
| `instruction_limit` | `1000000` | Maximum Lua instructions per callback and during script load. Minimum `1000`. `0` is allowed only with `jit: true`. |
| `jit`               | `false`   | Enable the LuaJIT compiler. Requires `instruction_limit: 0`. Not available in browser WASM builds. |
| `memory_limit`      | `32M`     | Maximum memory for the policy: the Lua heap plus the typed values it holds. Minimum `262144`. |
| `output_limit`      | `64M`     | Maximum serialized size of one processed batch. Minimum `65536`. |

Size suffixes are decimal: `64K` is 64000 bytes.

A relative `script` path is resolved from the working directory of the Fluent
Bit process, not from the directory of the configuration file. Use absolute
paths in services.

The policy file is loaded once, when the processor starts. Fluent Bit does not
start if the policy fails to load, the callback function does not exist, or a
setting is invalid.

## Callback results and errors

| Callback result      | Effect |
| -------------------- | ------ |
| `nil` or `fb.KEEP`   | Commit all changes made by the callback. |
| `fb.DROP`            | Remove the item. |
| Lua error            | Roll back every change made by the callback, then apply `error_mode`. |
| Any other value      | Treated as an error: `callback must return nil, fb.KEEP or fb.DROP`. |

Changes are transactional per item. Edits to the body, metadata, timestamp,
resource, and scope are committed or rolled back together; a failed item is
never forwarded half-modified. Exceeding the instruction or memory limit, and
writing a value that is invalid for the signal, are errors like any other.

`error_mode` decides what happens to an item whose policy failed:

- `drop` (default) removes it.
- `keep` forwards the original, unmodified item.

For privacy policies such as redaction, keep `error_mode: drop`. With `keep`,
an item whose policy fails is forwarded without redaction.

Errors outside a single item apply `error_mode` to a whole batch:

- For logs, if a processed batch exceeds `output_limit`, `drop` discards it and
  `keep` forwards the original batch.
- For metrics and traces the limit is checked per item: an item whose result
  does not fit follows `error_mode`, and the whole batch fails only when the
  kept originals do not fit either.
- Internal failures, such as a batch that cannot be decoded, apply `error_mode`
  to the whole batch.

A batch is the set of records handed to one processor run. Small chunks are
processed as one batch. Larger buffers, such as complete chunks reaching output
processors, are processed in batches of about 64 KiB or 1024 records, so
decoded records never hold more than one batch in memory. Groups, such as one
OpenTelemetry resource and scope, are never split across batches.

A group can also span appends, for example when its start and end markers
arrive in separate forward messages. A group still open at the end of a batch
stays open for the records that follow. Records that arrive before the end
marker of a group opened earlier are processed without a context, keep their
place in that group, and cannot set one.

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

Keys match exact bytes; a dot in a key has no special meaning, so
`get("http.route")` reads the key `http.route`, not a nested path.

Passing a value obtained with `get` to `set` keeps its type. Nanosecond
timestamps are larger than 2^53, so `:number()` fails on them; copy or compare
them as typed values, or use `:value()` for the exact decimal string.

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
directly. Lua numbers are always stored as doubles, in both runtimes: `set("n",
3)` writes `3.0`. Use `fb.int64` or `fb.uint64` for integers. Lua tables and
`nil` are not values: use `fb.map()`, `fb.array()`, and `fb.null`.

### Value lifetime

Log values passed to a callback, and the views obtained from them, are valid
only during that callback. Using one later raises an error. Metric and span
values are snapshots made for the callback: they stay readable afterwards, but
changing them never affects later items or committed output, and keeping them
retains their memory. To keep data between callbacks, store `v:copy()`. Copies
are independent: changing them never changes a committed record.

Lua globals persist for the lifetime of the processor instance. Each processor
instance has its own Lua state.

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
for example logs received by the `opentelemetry` input; for other logs they are
`nil`. Use `fb.is_otel(log)` to check. To give ordinary logs OpenTelemetry
context, place the `opentelemetry_envelope` processor before FTS.

Resource, scope, and context changes apply only to the current record. Record
order is preserved.

### Log helpers

| Helper | Description |
| ------ | ----------- |
| `fb.is_otel(log)` | `true` when the log has OpenTelemetry context. |
| `fb.set_severity(log, level)` | Set severity text and number from a level name: `trace`, `debug`, `info`, `warn`, `error`, `fatal`, and common aliases. |
| `fb.set_trace_context(log, trace_hex, span_hex)` | Set the trace and span IDs from hexadecimal strings. IDs must be nonzero. |
| `fb.log_field(log, name)` | Read an OpenTelemetry log field such as `severity_number`, `trace_id`, or `observed_timestamp`. |

The OpenTelemetry helpers fail on logs without OpenTelemetry context.

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

    if metric.name == "http.server.requests" then
        fb.aggregate_metric(metric, {"http.route", "http.response.status_code"}, "sum")
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
policy with `duplicate series/window; aggregate explicitly`. Use
`fb.aggregate_metric` to combine them deliberately.

### Metric helpers

| Helper | Description |
| ------ | ----------- |
| `fb.metric_value(point)` | Scalar value of a gauge or sum datapoint. |
| `fb.set_metric_value(point, value)` | Set the scalar value of a datapoint. |
| `fb.scale_metric(metric, factor, unit)` | Multiply values by a positive factor and optionally set the unit. Applies to gauges, sums, histograms, and summaries, including bounds and exemplars. An integer factor keeps integer values; another factor turns them into doubles. |
| `fb.aggregate_metric(metric, keys, op)` | Keep only the listed attributes and combine series that become equal. Points are combined only when their start time and time are also equal. `op` is `sum`, or for gauges also `min`, `max`, `mean`, or `count`. Supports gauges, sums, and explicit histograms. |
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

FTS sees one span at a time. Dropping spans or changing IDs can break trace
topology, and FTS does not repair parent references. It does not make
trace-level sampling decisions; use the `sampling` processor for that.

## Common helpers

| Helper | Description |
| ------ | ----------- |
| `fb.redact(value, keys, replacement)` | Replace the values of matching keys in nested maps and arrays. The default replacement is `[REDACTED]`. See [redaction limits](#redaction-limits). |
| `fb.keep_keys(map, keys)` | Remove every top-level key not listed. |
| `fb.parse_json(text)` | Parse a JSON document into typed values. Integer widths are preserved; duplicate keys and nesting beyond 64 levels are rejected. Input is limited to 1 MiB. |
| `fb.parse_time(text)` | Parse an RFC 3339 timestamp into `{sec, nsec}`. |

### Redaction limits

`fb.redact` is key-based. It is useful for structured secrets, but it does not
find sensitive data by itself:

- It matches whole keys, ignoring ASCII case. `password` matches `Password`,
  but not `db_password`, `password_hash` or `pass`. There are no prefixes,
  patterns or paths; list every key name.
- A matching key has its whole value replaced, including nested maps and
  arrays. Duplicate occurrences of the same key in one map are removed.
- It never reads string values. Secrets inside free-form text, such as a token
  in a log message, need an explicit string policy, and that policy only
  catches the formats it describes.
- It only visits the value passed to it. Redacting `log.body` does not touch
  `log.attributes`, `log.metadata` or resource attributes; for spans,
  `span.attributes` and `span.events` are separate calls.
- With `error_mode: keep`, an item whose policy fails is forwarded unredacted.
- An FTS processor on one output only affects that output. To redact data for
  every destination, attach the policy to the input.

## Limits and sandbox

- Values can have at most 64 levels of nesting.
- OpenTelemetry strings and keys must be valid UTF-8 without NUL characters;
  use `fb.bytes` for binary data.
- OpenTelemetry values have no unsigned 64-bit type. In items with
  OpenTelemetry context, a `uint64` above 2^63 − 1 fails the policy.
- Only `require("fluentbit")` is available. The filesystem, process, FFI,
  debug, coroutine, and module loading libraries are disabled, as are `print`,
  `xpcall`, `getfenv`, `setfenv`, and `module`. `collectgarbage` accepts only
  `collect`, `count`, and `step`.
- The instruction limit counts Lua instructions, not elapsed time. Lua string
  pattern functions run in C and are not interrupted; avoid unbounded patterns
  on untrusted input.
- With `jit: true` there is no CPU limit. Use it only for policies whose
  execution time you control.

The restricted environment and the limits protect the pipeline from policy
mistakes, such as an endless loop or unbounded memory growth. They are not a
security boundary: do not run policies from untrusted authors. Treat policies
as trusted configuration, with the same access control as the rest of the
Fluent Bit configuration.

## Diagnostics

Policy errors are logged with the Lua message and `edits rolled back`, for
example:

```text
[error] [processor:fts:fts.0] log policy failed: [string "fts_policy"]:1: boom; edits rolled back
```

Each batch logs at most five policy errors plus a summary count. With
`http_server` enabled, `fluentbit_processor_errors_total` with the label
`processor="fts"` counts batches with handled policy failures, and
`fluentbit_processor_items_drop_total` counts removed items.
