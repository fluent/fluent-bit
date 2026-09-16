# VIVO inspection API

VIVO is a bounded, volatile, best-effort inspection output. A successful flush
means the serialized chunk entered a local queue, not that a browser received it.
Eviction and process exit lose history. Use a separate durable output for delivery
or retention guarantees.

## Configuration

| Property | Default | Description |
| --- | --- | --- |
| `host` | `127.0.0.1` | HTTP listener address |
| `port` | `2025` | HTTP listener port |
| `stream_queue_size` | `20M` | Positive retained payload byte limit per signal |
| `stream_page_size` | `1M` | Uncompressed stream page byte limit; minimum `1K` |
| `compress` | `on` | Negotiate gzip response compression |
| `http_cors_allow_origin` | Unset | Value of the `Access-Control-Allow-Origin` header |
| `empty_stream_on_read` | `off` | Deprecated; enabling it is rejected |

Only one HTTP listener worker is supported. Other listener worker counts are
rejected, including the shared `workers` alias.

## Deployment

The default listener changes from `0.0.0.0:2025` to `127.0.0.1:2025`. Deployments
that previously relied on the all-interface default must explicitly set `host`
for remote access or route connections through a local reverse proxy.

The plugin serves telemetry over HTTP. `host` and `port` configure the listener,
not an outbound destination. The listener has no authentication or TLS. For remote
access, place it behind an authenticated HTTPS reverse proxy and restrict access
to the listener. Serve the UI from the same authenticated origin, or configure
`http_cors_allow_origin` for the intended UI origin. CORS does not provide access
control.

## Versions and framing

Both `/api/v1` and `/api/v2` expose `logs`, `metrics`, `traces`,
`internal/metrics`, and `health`. Routing counters, when available in the running
Fluent Bit build, are included in the internal metrics snapshot.

v1 retains the legacy log tuples and native CMetrics/CTraces JSON in
`application/x-ndjson` responses. Empty v1 streams return HTTP 200 with an empty
body. The single-group convenience fields and per-record `record_groups` remain.

v2 returns `application/json`: one page envelope containing OTLP JSON Export
request payloads. Empty pages contain `entries: []` and all recovery metadata.

```json
{
  "schemaVersion": 2,
  "signal": "logs",
  "generation": "opaque-instance-identifier",
  "nextCursor": "43",
  "oldestCursor": "10",
  "tailCursor": "50",
  "gap": false,
  "entries": [
    {
      "id": "42",
      "source": {"type": "opentelemetry", "name": "opentelemetry.0", "tag": "application"},
      "payload": {"resourceLogs": []}
    }
  ]
}
```

`payload` contains `resourceLogs`, `resourceMetrics`, or `resourceSpans` according
to the signal. It follows the [OTLP JSON encoding rules](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding):

* 64-bit integer fields are decimal strings; 32-bit integers and enums are numbers.
* Nanosecond timestamps retain their exact digits. Use BigInt for duration arithmetic.
* Trace/span/parent-span IDs are hexadecimal strings. Other bytes use base64.
* Non-finite doubles are `"NaN"`, `"Infinity"`, or `"-Infinity"` in numeric fields.
* Arbitrary log bodies/attributes use typed `AnyValue` objects: an integer `42`
  becomes `{"intValue":"42"}` while a string becomes `{"stringValue":"42"}`.
* Native unsigned log integers above INT64_MAX cannot fit OTLP's signed `intValue`.
  They use a `kvlistValue` with `fluentbit.type` = `"uint64"` and
  `fluentbit.value` = the exact decimal string. Nil becomes an empty AnyValue.
  Maps require string keys.
* MessagePack extension values use a `kvlistValue` with `fluentbit.type` =
  `"msgpack.ext"`, `fluentbit.ext_type` = the signed extension code as an
  `intValue`, and `fluentbit.value` = the payload as a `bytesValue`. In v1 these
  fields form a JSON object with a numeric extension code and base64 payload.
  Top-level Forward EventTime values remain record timestamps.
* Metrics follow the existing CMetrics OTLP mapping. Unsigned numeric data-point
  values above INT64_MAX become doubles and can round; unsigned OTLP fields such
  as histogram counts still use exact decimal strings. Conversion cannot recover
  information lost before the exporter receives a chunk.

Resource/scope associations and schema URLs are retained. Logs currently use one
resource/scope envelope per record; repeated resource identities are valid OTLP.
For OTLP logs, the input's configured `logs_body_key` (or the default `log`) is
unwrapped when it is the sole body field. Other log bodies remain structured
kvlist values. This follows the information available after Fluent Bit ingestion;
it is not a byte-for-byte replay of the original OTLP request.

Each retained entry represents one atomic Fluent Bit chunk and may contain many
records or contexts. v1 and v2 share entry IDs and retention.

`/api/v2/internal/metrics` returns one OTLP ExportMetricsServiceRequest JSON object
as a current snapshot, with no stream envelope or cursor. The v1 internal snapshot
retains its native CMetrics shape.

`GET /api/v2/health` advertises the versions, framing, OTLP JSON payload and gzip
capabilities without reading telemetry. HEAD and OPTIONS have no payload and never
consume telemetry. HEAD uses the same routing, validation, negotiation and stream
metadata as GET while suppressing the response body. Unsupported methods return 405. Responses include
`Cache-Control: no-store` and configured CORS headers. Authorization is allowed in
CORS preflight for deployments where the proxy supplies authentication.

## Browser compression

`compress` defaults to `on`. Stream and internal-metrics responses use gzip when
accepted through `Accept-Encoding`. No header, an unsupported encoding, or
`gzip;q=0` uses an uncompressed response when identity is acceptable. If neither
gzip nor identity is acceptable, the server returns 406. Explicit identity
preferences, wildcard encodings and quality values are honored.

Compressed responses retain the same Content-Type and use `Content-Encoding: gzip`
and the compressed Content-Length. Responses vary on `Accept-Encoding`. Browsers
send their supported encodings and transparently decompress `fetch()` responses;
the UI needs no decompression library and should not try to set Accept-Encoding.
`compress: off` disables compression. `curl --compressed` tests browser-style
negotiation and decoding; `curl -H 'Accept-Encoding: identity'` requests readable,
uncompressed JSON.

```javascript
const response = await fetch(`${baseUrl}/api/v2/logs?from=${cursor}&limit=100`);
if (!response.ok) throw new Error(`VIVO returned ${response.status}`);
const page = await response.json();
// Validate schema, generation and gaps; commit entries before advancing nextCursor.
```

## Cursors and retention

`from` and `to` are inclusive nonnegative entry IDs; omitted bounds are unbounded.
`to=0` means entry zero. `limit` is a positive number of entries. Unknown, duplicate,
negative, overflowing and malformed query parameters return 400.

Stream responses expose the following headers. Numeric values are decimal strings:

| Header | Meaning |
| --- | --- |
| `vivo-stream-generation` | Random identifier for this plugin instance; changes on restart |
| `vivo-stream-start-id`, `vivo-stream-end-id` | First/last returned entry; absent on empty pages |
| `vivo-stream-next-id` | Last returned ID plus one, or current tail on an empty page |
| `vivo-stream-oldest-id` | Earliest retained entry, or tail when empty |
| `vivo-stream-tail-id` | Next ID that will be allocated, exclusive upper bound |
| `vivo-stream-gap` | Requested `from` is older than retention or ahead of the current tail |
| `vivo-stream-retained-bytes`, `vivo-stream-retained-entries` | Current retained payload size/count |
| `vivo-stream-evicted-entries`, `vivo-stream-evicted-bytes` | Cumulative oldest-entry evictions |
| `vivo-stream-rejected-entries` | Cumulative entries rejected for exceeding a size limit |

Metadata describes the same locked snapshot as the selected page, including empty
pages. Keep the generation together with the cursor. On a generation change,
reset to `oldest-id` for replay or `tail-id` for live-only viewing. A gap within the
same generation means the UI should report expired history and resume from the
oldest retained ID. Advance the cursor only after validating and committing the
entire page. Multiple viewers never acknowledge or delete entries.

`empty_stream_on_read On` is rejected: implicit acknowledgment is incompatible
with shared inspection. `stream_queue_size` (default 20M) is a positive retained
payload byte limit **per signal**, counting the combined v1 and v2 representations.
They are prepared once, then inserted or rejected atomically. Oldest entries are
evicted only until an incoming entry fits. An oversized entry is rejected without
evicting history and logged as an output failure. No partial chunk is published
on a serialization failure.

`stream_page_size` (default 1M, minimum 1K) bounds uncompressed stream response
bodies. v2 reserves 512 bytes for its page envelope and space for each entry ID;
an entry must fit a page in both versions. Compression happens after pagination
and does not change cursors or retention accounting. The internal metrics snapshot
is independent of stream page limits. Allocation metadata, HTTP buffers, response
copies, compression and intermediate serialization memory are additional to
retained payload bytes; these are not process-wide memory limits.
