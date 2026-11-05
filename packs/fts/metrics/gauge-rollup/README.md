# Temporal gauge rollup

Reduce repeated observations of selected gauges in fixed processing-time windows.
The author Lua block selects names and calculates `sum`, `mean`, `min`, `max` or
`count`. Native FTS freezes validated snapshots, bounds retention and releases
one metric family per window into the following processor stage.

## Semantics and limits

Each callback contains a metric family, possibly several points. An identity
includes the route tag, metric name/type/unit/description, resource and scope
with their schemas, numeric kind and the complete set of series attributes.
A changed set of series starts another window. Point order may differ. Each
series must occur once in a family. Window deadlines use monotonic ingestion
time, sampled once per batch; timestamps do not trigger watermarks or lateness.
Output uses the greatest observation timestamp and smallest start timestamp.

These operations reduce repeated observations per series; they do not compute a
rate, a time-weighted average or a sum across dimensions. Select the operation
that matches the gauge: `max` for a peak, `mean` for equally weighted observations,
`sum` only for values whose observations should be added. `count` emits samples
per series and unit `1`. Sums and comparisons preserve exact integers. Mean
requires exactly representable numeric conversions; unsuitable values preserve
the original family through `error_mode: keep`. Nonfinite values, flagged points,
exemplars and unsupported metric types are not silently aggregated.

Defaults bound the store to 1024 keys, 4096 bytes per key, 1,000,000 observations
per window, the configured `state_limit`, and 60 seconds of ready-queue retry.
The state budget includes snapshots, auxiliary Lua accumulator values and frozen
wire payloads. Callback memory, instructions and output budgets also apply.
Capacity or sample overflow preserves the current original family without
changing the existing aggregate. It can therefore emit a raw observation beside
a reduced family; monitor overflow before relying on complete reduction.

A callback error aborts its proposal; failure to construct the final FTS metrics
output aborts every proposal in that batch. Commit is local to FTS, before later
processors and storage. Timer release invokes no Lua. `BUSY` preserves ownership,
retries stop at the first busy item, and timeout records the actual lost input
families. Neither retained inventory nor accepted release measures delivery.

`fluentbit_fts_metric_window_family_events_total` has outcomes `held`, `released`,
`reduced`, `overflow`, `expired`, `shutdown`, `release_retry`. `held` counts input
families, `released` output families, `reduced` removed repeated families, and
`expired`/`shutdown` lost input families. The inventory gauge is
`fluentbit_fts_metric_window_pending_input_families`. Both include
`signal="metrics",unit="metric_families"`; datapoint counts are different units.

## Extending the reduction

Agents must keep policy arithmetic in Lua. `fb.metric_window(options)` constructs
a bounded controller during factory binding. In each callback, compute
`fb.metric_window_key(metric)` before changing values/units, call
`window:get(key)` for a private `(previous_metric, auxiliary_state, samples)` copy,
calculate the next state, and return `window:hold(key, metric, next_state)`.
HOLD must target the current callback metric; previous snapshots are read copies.
A HOLD cannot accompany metric emissions. Do not mutate expected fixtures to
mirror observed output. Version changed semantics in the pack and add independent
boundary cases; preserve a reviewed source/binary snapshot for verification.

## Pack contract

Manifest: [pack.json](pack.json). Pack ID: `org.fluentbit.gauge-rollup`; implementation version: `1.0.0`.

Requires FTS author API **1**, manifest grammar **1**, and recipe grammar **1**.
Install the complete pack directory, including its Lua sources. Pin the deployment artifact by hash.

The [complete pipeline](fluent-bit.yaml) declares its input, parsers and inspection output.
Select your real source and destination before deployment.

### `apply`

Block ID: `org.fluentbit.gauge-rollup/apply`. Signal: **metrics**.
Policy source: [blocks/apply.lua](blocks/apply.lua).

The example uses `error_mode: keep`. A callback failure preserves its original item and rolls back its edits.
Place this stateful block last in an input recipe and set `state_commit: local`.
State is local and volatile; route related observations to the same instance.

| Parameter | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `names` | `strings` | Yes | — | Exact metric family names to select or reduce. |
| `operation` | `string` | No | `"sum"` | Gauge reduction: sum, mean, min, max or count. |
| `interval_ms` | `number` | No | `2000` | Monotonic processing-time window duration in milliseconds. |
| `max_samples` | `number` | No | `1000000` | Maximum observations admitted to one window. |

Add this configuration under the input that carries the stated signal:

```yaml
processors:
  metrics:
  - name: fts
    packs:
    - metrics/gauge-rollup/pack.json
    recipe_version: 1
    state_commit: local
    error_mode: keep
    recipe:
    - id: rollup
      use: org.fluentbit.gauge-rollup/apply
      with:
        names:
        - queue_depth
        operation: sum
    packages_dir: ${FTS_PACKAGES_DIR}
```

## Use and verify

Set `FTS_PACKAGES_DIR` to the absolute installed directory containing these packs.
The `packs` path is relative to that directory; block source paths are relative to their manifest.
A relative `packages_dir` resolves against the process working directory.

From the repository root, try the included pipeline with the local build:

```sh
export FTS_PACKAGES_DIR="$PWD/packs/fts"
FTS_BINARY="$PWD/build/bin/fluent-bit"
(cd packs/fts/metrics/gauge-rollup && "$FTS_BINARY" --dry-run -c fluent-bit.yaml)
(cd packs/fts/metrics/gauge-rollup && "$FTS_BINARY" -c fluent-bit.yaml)
```

Replay every included fixture from the repository root with the [fixture runner](../../../../tools/fts/README.md):

```sh
python3 tools/fts/fts_fixture.py --binary "$PWD/build/bin/fluent-bit" packs/fts/metrics/gauge-rollup/tests/*.yaml
python3 tools/fts/fts_fixture.py --valgrind --binary "$PWD/build/bin/fluent-bit" packs/fts/metrics/gauge-rollup/tests/*.yaml
```

Install the runner dependencies from `tools/fts/requirements.txt` into your Python environment first.

| Fixture | Case | Assertions |
| --- | --- | --- |
| [sum.yaml](tests/sum.yaml) | two-families-four-points-one-output-family | kept=0, dropped=0, errors=0, held=2 |
| [mean.yaml](tests/mean.yaml) | two-families-four-points-one-output-family | kept=0, dropped=0, errors=0, held=2 |
| [count.yaml](tests/count.yaml) | two-families-four-points-one-output-family | kept=0, dropped=0, errors=0, held=2 |
| [min.yaml](tests/min.yaml) | two-families-four-points-one-output-family | kept=0, dropped=0, errors=0, held=2 |
| [max.yaml](tests/max.yaml) | two-families-four-points-one-output-family | kept=0, dropped=0, errors=0, held=2 |

Expected output is authored independently in these fixtures. Linux runtime and Valgrind results are recorded in [verification evidence](../../verification.json). Validate your own source schema, build and pipeline before rollout.

## Instructions for agents

Keep policy decisions in Lua and reuse `fb.block` for core operations. Preserve unrelated fields, exact numeric types, signal identity and the stated failure behavior. Update the manifest, this README and independent success/control/failure fixtures together. Breaking changes require a new implementation version and an explicit migration. Never rewrite expected output to match a regression or put production credentials in a pack.

License: Apache-2.0; see the repository LICENSE file.
