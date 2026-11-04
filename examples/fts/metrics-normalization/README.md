# FTS metrics: unit normalization and cardinality reduction

[`policy.lua`](policy.lua) processes the OpenTelemetry metrics of a `checkout`
service:

1. Drops families whose name starts with `debug.`.
2. Converts `ms` to `s` and `KiBy` to `By` with `fb.scale_metric`.
3. Renames `http.server.duration` to `http.server.request.duration`.
4. Aggregates `http.server.requests` by `http.route` and
   `http.response.status_code`, removing the per-client `client.id`
   attribute and summing the series that become identical.

## Run

```shell
examples/fts/run.sh examples/fts/metrics-normalization
```

Or by hand, from this directory:

```shell
../../../build/bin/fluent-bit -c fluent-bit.yaml
# in another terminal
curl -H 'Content-Type: application/json' --data-binary @input.json \
     http://127.0.0.1:4318/v1/metrics
```

## Expected output

The complete output is in [`expected-output.json`](expected-output.json).
[`input.json`](input.json) has four families:

| Family | Input | Output |
| ------ | ----- | ------ |
| `http.server.requests` (sum) | 5 series: `/login 200` from `client-a` (10) and `client-b` (5), `/login 401` (2), `/pay 200` from `client-a` (7) and `client-d` (3) | 3 series without `client.id`: `/login 200` = 15, `/login 401` = 2, `/pay 200` = 10 |
| `http.server.duration` (histogram, `ms`) | bounds `10, 50, 250`; sum `850`; min `4`; max `240` | renamed to `http.server.request.duration`, unit `s`; bounds `0.01, 0.05, 0.25`; sum `0.85`; min `0.004`; max `0.24`; bucket counts unchanged |
| `process.memory.usage` (gauge, `KiBy`) | `asInt` 2048 | unit `By`, `asInt` 2097152 (an integer factor keeps the integer type) |
| `debug.queue.depth` | gauge | dropped |

## Notes

- `fb.aggregate_metric` combines only datapoints whose remaining attributes,
  start time and time are all equal. Series with different timestamps stay
  separate.
- For sums, the only aggregation is `sum`. Gauges also accept `min`, `max`,
  `mean` and `count`. Exponential histograms and summaries cannot be
  aggregated.
- Removing an attribute without aggregating can make two series identical,
  which fails the policy. That is why this example aggregates instead of
  calling `remove` on `client.id`.
- `fb.scale_metric` with a non-integer factor turns integer values into
  doubles. Exponential histograms cannot be scaled.
