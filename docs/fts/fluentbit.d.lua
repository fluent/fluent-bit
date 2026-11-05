---@meta fluentbit

-- Canonical public API for plugins/processor_fts. This is an IDE stub, not runtime code.
-- Use local fb = require("fluentbit"); fb, log and record are not injected globals.
-- A configured callback receives one log, metric family or span and commits edits
-- on nil/KEEP. Raise a Lua error to roll back and apply error_mode.
-- Log views expire after the callback. Keep copy() results for later callbacks.
-- Metric/span snapshots remain readable, but later edits cannot affect committed output.

---@alias FtsFilterCallback fun(log: FtsLogRecord): FtsResultCode?
---@alias FtsMetricCallback fun(metric: FtsMetric): FtsResultCode?
---@alias FtsSpanCallback fun(span: FtsSpan): FtsResultCode?
---@alias FtsTelemetry FtsLogRecord|FtsMetric|FtsSpan
---@alias FtsBlockCallback fun(record: FtsTelemetry): FtsResultCode?
---@alias FtsWindowCallback fun(log: FtsLogRecord): "hold"?
-- Compatibility documentation for filter_lua only: FTS does not call this ABI.
---@alias FtsClassicResultCode -1|0|1|2
---@alias FtsClassicFilterCallback fun(tag: string, timestamp: FtsTimestamp|number, record: table): FtsClassicResultCode, FtsTimestamp|number|nil, table?
---@alias FtsValueKind "map"|"array"|"string"|"bytes"|"bool"|"int64"|"uint64"|"double"|"null"
---@alias FtsWritableValue FtsValue|string|boolean|number
---@alias FtsNumeric FtsInt64|FtsUInt64|FtsDouble
---@alias FtsMetricKind "gauge"|"sum"|"histogram"|"exponential_histogram"|"summary"
---@alias FtsTemporality "unspecified"|"delta"|"cumulative"
---@alias FtsAggregation "sum"|"min"|"max"|"mean"|"count"

---@class FtsTimestamp
---@field sec integer # Seconds since Unix epoch, 0..4294967293.
---@field nsec integer # Nanoseconds, 0..999999999. Assign a new timestamp table to change time.

--- Typed userdata. Methods are registered on every value; incompatible kinds raise errors.
--- Lua tables and nil cannot be assigned as values; use typed containers and fb.null.
---@class FtsValue
local FtsValue = {}

--- Return the stored kind without coercion.
---@return FtsValueKind
---@nodiscard
function FtsValue:type() end

--- Scalars only. Integers return exact decimal strings, bytes return raw strings,
--- null returns nil. Containers raise errors.
---@return string|boolean|number|nil
---@nodiscard
function FtsValue:value() end

--- Numeric values only. Integers outside +/-9007199254740991 raise errors.
---@return number
---@nodiscard
function FtsValue:number() end

--- Independent writable copy, safe to retain beyond the callback.
---@return self
---@nodiscard
function FtsValue:copy() end

--- Map lookup returns nil for missing keys. Arrays use existing 1-based indexes;
--- out-of-bounds indexes raise errors. Children are typed views, including scalars.
---@param key string|integer
---@return FtsValue?
---@nodiscard
function FtsValue:get(key) end

--- Strict string accessor; missing map keys return nil, wrong types raise errors.
---@param key string|integer
---@return string?
---@nodiscard
function FtsValue:get_string(key) end

--- Strict boolean accessor; missing map keys return nil, wrong types raise errors.
---@param key string|integer
---@return boolean?
---@nodiscard
function FtsValue:get_bool(key) end

--- Numeric accessor; missing map keys return nil, unsafe integers raise errors.
---@param key string|integer
---@return number?
---@nodiscard
function FtsValue:get_number(key) end

--- Maps replace all entries matching the literal key. Arrays replace an existing index.
--- Plain Lua numbers are stored as doubles. Does not return a value.
---@param key string|integer
---@param value FtsWritableValue
function FtsValue:set(key, value) end

--- Maps only. Remove every entry matching the literal key; report whether any existed.
---@param key string
---@return boolean
function FtsValue:remove(key) end

--- Maps only. Return an existing child map or create one; wrong types raise errors.
---@param key string
---@return FtsMap
---@nodiscard
function FtsValue:ensure_map(key) end

--- Maps only. Return keys in stored order (including duplicates in unchanged input).
---@return string[]
---@nodiscard
function FtsValue:keys() end

--- Maps and arrays only. Number of entries.
---@return integer
---@nodiscard
function FtsValue:len() end

--- Arrays only. Append a typed value or Lua scalar.
---@param value FtsWritableValue
function FtsValue:append(value) end

---@class FtsMap: FtsValue
local FtsMap = {}

---@param key string
---@return FtsValue?
---@nodiscard
function FtsMap:get(key) end

---@param key string
---@param value FtsWritableValue
function FtsMap:set(key, value) end

---@class FtsArray<T>: FtsValue
local FtsArray = {}

---@param key integer
---@return T
---@nodiscard
function FtsArray:get(key) end

---@param key integer
---@param value FtsWritableValue
function FtsArray:set(key, value) end

---@class FtsInt64: FtsValue
local FtsInt64 = {}

--- Lossless signed decimal representation. In packs, compare numbers with fb.numeric_compare.
---@return string
---@nodiscard
function FtsInt64:value() end

---@class FtsUInt64: FtsValue
local FtsUInt64 = {}

--- Lossless unsigned decimal representation.
---@return string
---@nodiscard
function FtsUInt64:value() end

---@class FtsBytes: FtsValue
local FtsBytes = {}

--- Raw bytes, including NUL; no hexadecimal or base64 decoding/encoding.
--- Compare extracted strings for byte equality; userdata has no comparison methods.
---@return string
---@nodiscard
function FtsBytes:value() end

---@class FtsDouble: FtsValue
local FtsDouble = {}

---@return number
---@nodiscard
function FtsDouble:value() end

---@class FtsNull: FtsValue
local FtsNull = {}

---@return nil
---@nodiscard
function FtsNull:value() end

---@class FtsResource
---@field attributes FtsMap # Mutate through set/remove; do not replace this view.
---@field schema_url? string?
---@field dropped_attributes_count? integer? # Metric/span contexts; logs expose this through context maps.

---@class FtsScope: FtsResource
---@field name? string?
---@field version? string?

---@class FtsLogContext
---@field attributes FtsMap
---@field metadata FtsMap

--- Log bodies must remain maps. OTel aliases are nil on ordinary JSON-line logs.
--- Read severity_number/severity_text with fb.log_field, not direct log properties.
--- resource, scope, attributes, metadata and context roots cannot be replaced.
---@class FtsLogRecord
---@field body FtsMap # Replaceable with another map; arbitrary scalar bodies are not accepted.
---@field metadata FtsMap
---@field timestamp FtsTimestamp
---@field tag string # Read-only routing tag.
---@field attributes? FtsMap # Only present with OTel context, e.g. opentelemetry_envelope.
---@field resource? FtsResource # Only present with OTel context.
---@field scope? FtsScope # Only present with OTel context.
---@field context? FtsLogContext # Present on grouped records; roots cannot be replaced.

--- One metric family; datapoints are typed maps with OTLP snake_case keys.
--- time_unix_nano, start_time_unix_nano, count and bucket counts are exact integers.
---@class FtsMetric
---@field signal "metrics" # Read-only.
---@field tag string # Read-only.
---@field name string
---@field description string
---@field unit string
---@field type FtsMetricKind # Only gauge/sum conversion is supported.
---@field datapoints FtsArray<FtsMap>
---@field aggregation_temporality? FtsTemporality # Absent on gauges and summaries.
---@field is_monotonic? boolean # Sums only.
---@field resource FtsResource
---@field scope FtsScope
local FtsMetric = {}

--- Emit a family snapshot; returned view edits the emitted copy. Does not rerun the callback.
--- Emission from an already emitted view is unavailable. Errors discard all emissions.
---@return FtsMetric
function FtsMetric:emit() end

---@class FtsSpan
---@field signal "traces" # Read-only.
---@field tag string # Read-only.
---@field name string
---@field trace_state string?
---@field kind integer # Numeric OpenTelemetry span kind.
---@field flags integer
---@field trace_id string # 32 hexadecimal characters, nonzero.
---@field span_id string # 16 hexadecimal characters, nonzero.
---@field parent_span_id string # Empty for root spans, otherwise 16 hex characters.
---@field start_time_unix_nano FtsUInt64
---@field end_time_unix_nano FtsUInt64
---@field attributes FtsMap
---@field status FtsMap # code (integer) and message (string).
---@field events FtsArray<FtsMap>
---@field links FtsArray<FtsMap>
---@field dropped_attributes_count integer
---@field dropped_events_count integer
---@field dropped_links_count integer
---@field resource FtsResource
---@field scope FtsScope

---@class FtsSelector
---@field root string # Signal-appropriate root, e.g. body, attributes, resource.attributes.
---@field path string[] # Literal map keys, never a dotted-path expression.

---@class FtsCondition
---@field all? FtsCondition[]
---@field any? FtsCondition[]
---@field selector? FtsSelector # Leaf condition; mutually exclusive with all/any.
---@field op? "eq"|"neq"|"in"|"not_in"|"gt"|"gte"|"lt"|"lte"
---@field value? any # Validated scalar literal for non-membership operators.
---@field values? any[] # Validated scalar literals for in/not_in.

---@class FtsDedupeOptions
---@field keys FtsSelector[] # 1..16 selectors.
---@field tenant? FtsSelector
---@field ttl_ms integer # 1..86400000.
---@field max_keys? integer # Default 1024, maximum 65536.
---@field max_key_bytes? integer # Default 1024, maximum 65536.
---@field overflow? "keep"
---@field on_missing? "error"|"keep"

---@class FtsThrottleOptions: FtsDedupeOptions
---@field rate integer # Tokens/second, 1..1000000.
---@field burst integer # 1..1000000; TTL must cover a full refill.

---@class FtsWindowOptions
---@field keys FtsSelector[]
---@field tenant? FtsSelector
---@field hold_ms integer # 1..86400000.
---@field late_ms? integer # Default 60000; 0..86400000.
---@field ready_timeout_ms? integer # Default 60000; 1..86400000.
---@field max_keys? integer # Default 1024, maximum 65536.
---@field max_key_bytes? integer # Default 1024, maximum 65536.
---@field retain_when FtsCondition
---@field keep_when? FtsCondition
---@field overflow? "keep"
---@field on_missing? "error"|"keep"

---@class FtsMetricWindowOptions
---@field interval_ms integer # 1..86400000.
---@field ready_timeout_ms? integer # Default 60000; 1..86400000.
---@field max_keys? integer # Default 1024, maximum 65536.
---@field max_key_bytes? integer # Default 4096, maximum 65536.
---@field max_samples? integer # Default 1000000, maximum 1000000.

---@class FtsMetricWindow
local FtsMetricWindow = {}

--- Read a previous retained family and its reduction state; missing key returns nil,nil,0.
---@param key string
---@return FtsMetric? previous
---@return FtsMap? state
---@return integer samples
---@nodiscard
function FtsMetricWindow:get(key) end

--- Freeze a validated family snapshot for release at the following processor stage.
---@param key string
---@param metric FtsMetric
---@param state? FtsMap
---@return "hold"
---@nodiscard
function FtsMetricWindow:hold(key, metric, state) end

--- require("fluentbit") module, conventionally bound locally as fb.
---@class FtsModule
local fb = {}

--- Callback results are strings. MODIFY and ERROR are not exported: mutate then
--- return nil/KEEP to commit, or raise an error for rollback and error_mode.
---@enum FtsResultCode
local FtsResultCode = {
    KEEP = "keep", -- Commit edits and pass the item to the next stage.
    DROP = "drop", -- Drop this item; explicitly emitted metric families survive.
}

--- Commit changes and forward the item.
fb.KEEP = FtsResultCode.KEEP
--- Drop the item from the pipeline.
fb.DROP = FtsResultCode.DROP

--- Typed null singleton; distinct from missing map keys.
---@type FtsNull
fb.null = nil

--- Stable fixed-seed fingerprint algorithm; provides no secrecy.
---@type string
fb.hash64_algorithm = "xxh3-64-v1-seed0"

--- Empty typed map.
---@return FtsMap
---@nodiscard
function fb.map() end

--- Empty typed array.
---@return FtsArray<FtsValue>
---@nodiscard
function fb.array() end

--- Exact signed 64-bit integer. Numeric arguments must be safe integral Lua numbers.
---@param value number|string # Decimal string for values beyond +/-9007199254740991.
---@return FtsInt64
---@nodiscard
function fb.int64(value) end

--- Exact unsigned 64-bit integer; use decimal strings for large values.
---@param value number|string
---@return FtsUInt64
---@nodiscard
function fb.uint64(value) end

--- Binary value from raw bytes; does not decode hexadecimal strings.
---@param value string
---@return FtsBytes
---@nodiscard
function fb.bytes(value) end

--- Parse JSON into typed values, including scalar roots. Raises on invalid JSON,
--- duplicate keys, input over 1 MiB or nesting beyond 64 levels; never returns nil.
---@param text string
---@return FtsValue
---@nodiscard
function fb.parse_json(text) end

--- Parse JSON without throwing on ordinary parse errors or non-string input.
--- JSON null/false return typed values, not Lua nil/false. Same parser limits as parse_json.
--- Instruction-budget exhaustion still fails the callback.
---@param text any # JSON text; missing or non-string input returns nil and an error.
---@return FtsValue? value
---@return string? error
---@nodiscard
function fb.try_parse_json(text) end

--- Decode a string field in place, preserving siblings. Return false,error without
--- mutation for missing/non-string fields, ordinary parse errors or OTel log integers
--- above INT64_MAX. Accepts any JSON value. Map keys are literal; arrays are 1-based.
--- Invalid containers/keys, expired views, mutation errors and budget exhaustion raise.
--- These boolean results are not callback actions; do not return them from process.
---@param container FtsMap|FtsArray<FtsValue>
---@param key string|integer
---@return boolean success
---@return string? error
function fb.decode_json(container, key) end

--- Availability: logs; modes: script,pack.
--- Decode a JSON object and replace log.body. Preserve the body and return false,error
--- for missing/non-string fields, ordinary parse errors, non-object JSON or OTel log
--- integers above INT64_MAX. Invalid arguments and budget exhaustion still raise.
--- Ignoring failure keeps the original body. Boolean results are not callback actions.
---@param log FtsLogRecord
---@param field? string # Literal source field; defaults to message.
---@return boolean success
---@return string? error
function fb.unpack_json(log, field) end

--- Parse strict RFC3339 time; raises on invalid input or unsupported event time range.
---@param text string
---@return FtsTimestamp
---@nodiscard
function fb.parse_time(text) end

--- Recursively redact matching map keys (case-insensitive); default replacement [REDACTED].
---@param value FtsValue
---@param keys string[]
---@param replacement? FtsWritableValue
function fb.redact(value, keys, replacement) end

--- Remove all keys except the listed literal names.
---@param map FtsMap
---@param keys string[]
function fb.keep_keys(map, keys) end

--- Availability: logs; modes: script,pack.
--- Check before accessing optional OTel aliases.
---@param log FtsLogRecord
---@return boolean
---@nodiscard
function fb.is_otel(log) end

--- Availability: logs; modes: script,pack.
--- OTel-only; raises for native logs. Same view as log.attributes.
---@param log FtsLogRecord
---@return FtsMap
---@nodiscard
function fb.attributes(log) end

--- Availability: logs; modes: script,pack.
--- OTel-only; e.g. severity_number, severity_text, trace_id, observed_timestamp.
--- Returns a typed value or nil for a missing field. Raises for native logs.
---@param log FtsLogRecord
---@param name string
---@return FtsValue?
---@nodiscard
function fb.log_field(log, name) end

--- Availability: logs; modes: script,pack.
--- OTel-only. Set severity text and number; unknown names raise errors.
---@param log FtsLogRecord
---@param level string # trace, debug, info, warn, error, fatal and common aliases.
function fb.set_severity(log, level) end

--- Availability: logs; modes: script,pack.
--- OTel-only. Set nonzero correlation IDs from hexadecimal strings.
---@param log FtsLogRecord
---@param trace string # 32 hex characters.
---@param span string # 16 hex characters.
function fb.set_trace_context(log, trace, span) end

--- Availability: metrics,traces; modes: script,pack.
--- Gauge/sum value, or nil if neither as_int nor as_double exists.
---@param point FtsMap
---@return FtsNumeric?
---@nodiscard
function fb.metric_value(point) end

--- Availability: metrics,traces; modes: script,pack.
---@param point FtsMap
---@param value FtsNumeric|number
function fb.set_metric_value(point, value) end

--- Availability: metrics,traces; modes: script,pack.
--- Scale values, bounds and exemplars; exponential histogram scaling is unsupported.
---@param metric FtsMetric
---@param factor number # Finite and positive.
---@param unit? string
function fb.scale_metric(metric, factor, unit) end

--- Availability: metrics,traces; modes: script,pack.
--- Combine equal series after retaining attributes. Only gauges allow non-sum operations.
---@param metric FtsMetric
---@param keys string[]
---@param operation FtsAggregation
---@param max_exemplars? integer # 0..128; omitted preserves legacy exemplar behavior.
function fb.aggregate_metric(metric, keys, operation, max_exemplars) end

--- Availability: metrics,traces; modes: script,pack.
--- Explicit histogram only; bounds must be a subset of current bounds.
---@param metric FtsMetric
---@param bounds number[]
function fb.merge_histogram_buckets(metric, bounds) end

--- Availability: metrics,traces; modes: script,pack.
--- Emit a copy; returning DROP still preserves this emitted family.
---@param metric FtsMetric
---@param name? string
---@param description? string
---@param unit? string
---@return FtsMetric
function fb.copy_metric(metric, name, description, unit) end

--- Availability: metrics,traces; modes: script,pack.
--- Emit a sum derived from a distribution. No usable points returns nil.
---@param metric FtsMetric
---@param field "count"|"sum"|"avg"
---@param name? string
---@param monotonic? boolean
---@return FtsMetric?
function fb.extract_metric(metric, field, name, monotonic) end

--- Availability: logs,metrics,traces; modes: pack.
--- Exact ordering of typed numeric values: -1, 0, 1; nonfinite values return nil.
--- Same-kind nonnumeric scalars return 0 if equal, 1 otherwise; mismatched kinds return nil.
--- Containers raise errors. Integers are compared without Lua-number precision loss.
---@param left FtsValue
---@param right FtsValue
---@return integer?
---@nodiscard
function fb.numeric_compare(left, right) end

--- Stable lowercase 16-character XXH3 fingerprint of up to 1 MiB of bytes.
---@param bytes string
---@return string
---@nodiscard
function fb.hash64(bytes) end

--- Full-width unsigned hash remainder, computed before conversion to a Lua number.
---@param bytes string
---@param modulus integer # 1..1000000000.
---@return integer
---@nodiscard
function fb.hash64_mod(bytes, modulus) end

--- Lowercase 64-character HMAC hex; key_ref names a configured secret_refs entry.
--- Secret bytes are never exposed to Lua. Message limit: 1 MiB.
---@param key_ref string
---@param bytes string
---@return string
---@nodiscard
function fb.hmac_sha256(key_ref, bytes) end

--- Availability: logs,metrics,traces; modes: pack.
--- Materialize a validated literal parameter; for author packs (manifest grammar 2).
---@param value any # Literal descriptor or supported scalar; not an arbitrary Lua object.
---@return FtsWritableValue
---@nodiscard
function fb.literal(value) end

--- Availability: logs,metrics,traces; modes: pack.
--- Bind a validated stateless core block during pack factory binding only.
--- Options follow the block registry model; requires compatible signal/privacy context.
---@param id string
---@param options? table<string,any>
---@return FtsBlockCallback
---@nodiscard
function fb.block(id, options) end

--- Availability: logs,metrics,traces; modes: pack.
--- Pack binding only; terminal input-log step with explicit state_commit: local.
---@param options FtsDedupeOptions
---@return FtsFilterCallback
---@nodiscard
function fb.dedupe(options) end

--- Availability: logs,metrics,traces; modes: pack.
--- Pack binding only; terminal input-log step with explicit state_commit: local.
---@param options FtsThrottleOptions
---@return FtsFilterCallback
---@nodiscard
function fb.throttle(options) end

--- Availability: logs,metrics,traces; modes: pack.
--- Pack binding only; terminal input-log step. Returned hold action is recipe-only.
---@param options FtsWindowOptions
---@return FtsWindowCallback
---@nodiscard
function fb.window(options) end

--- Availability: logs,metrics,traces; modes: pack.
--- Pack binding only; terminal input-metric step with explicit state_commit: local.
---@param options FtsMetricWindowOptions
---@return FtsMetricWindow
---@nodiscard
function fb.metric_window(options) end

--- Availability: metrics,traces; modes: script,pack.
--- Stable identity of a nonempty gauge family for temporal retention; may raise.
---@param metric FtsMetric
---@return string
---@nodiscard
function fb.metric_window_key(metric) end

--- Availability: metrics,traces; modes: script,pack.
--- Reduce a gauge family in Lua using optional previous family/state; return new state.
---@param metric FtsMetric
---@param previous FtsMetric?
---@param state FtsMap?
---@param samples integer
---@param operation FtsAggregation
---@return FtsMap
---@nodiscard
function fb.gauge_rollup(metric, previous, state, samples, operation) end

return fb
