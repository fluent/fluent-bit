# FTS traces: attribute transformation and selective span drop

[`policy.lua`](policy.lua) processes the OpenTelemetry spans of a `checkout`
service:

1. Drops spans whose `http.route` attribute is `/healthz`.
2. Drops `cache.lookup` spans whose `cache.hit` attribute is `true`.
3. Renames `http.method` to `http.request.method` and `http.status_code` to
   `http.response.status_code`, keeping the original value types.
4. Replaces `http.target` with `url.path`, removing the query string.
5. Removes the `enduser.id` attribute.
6. Redacts `authorization` attributes inside span events.

## Run

```shell
examples/fts/run.sh examples/fts/traces-filtering
```

Or by hand, from this directory:

```shell
../../../build/bin/fluent-bit -c fluent-bit.yaml
# in another terminal
curl -H 'Content-Type: application/json' --data-binary @input.json \
     http://127.0.0.1:4318/v1/traces
```

## Expected output

The complete output is in [`expected-output.json`](expected-output.json).
[`input.json`](input.json) has four spans in two traces:

| Span | Output |
| ---- | ------ |
| `GET /checkout` (root) | Kept. Attributes become `http.route`, `http.request.method: GET`, `http.response.status_code: 200` (still `intValue`) and `url.path: /checkout`. The `request.headers` event keeps `user-agent` and has `authorization: [REDACTED]`. |
| `cache.lookup` (child, cache hit) | Dropped. |
| `SELECT orders` (child) | Kept unchanged, with its `parentSpanId` pointing at the root span. |
| `GET /healthz` (root of a second trace) | Dropped. |

## Notes

- FTS processes one span at a time and does not repair trace topology. Dropping
  a span that has children leaves them pointing at a parent that no longer
  exists. This policy only drops leaf spans and single-span traces.
- FTS does not make sampling decisions across a trace. For tail sampling, use
  the `sampling` processor.
- Span timestamps are exact 64-bit integers. They are larger than 2^53, so
  `:number()` on them fails; compare or copy them as typed values.
