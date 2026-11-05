# Sampling processor

`probabilistic` supports logs, metrics and traces on input and output pipelines.
`tail` supports traces on input pipelines only. Sampling reduces exported volume;
it does not reduce the application's instrumentation or Fluent Bit ingestion cost.

## Probabilistic configuration

```yaml
service:
  flush: 1
pipeline:
  inputs:
    - name: opentelemetry
      port: 4318
      processors:
        logs:
          - name: sampling
            type: probabilistic
            sampling_settings:
              sampling_percentage: 12.5
        traces:
          - name: sampling
            type: probabilistic
            sampling_settings:
              sampling_percentage: 12.5
  outputs:
    - name: stdout
      match: '*'
      format: otlp_json
```

| Setting | Default | Behavior |
|---|---|---|
| `sampling_settings.sampling_percentage` | `10` | Finite percentage in `[0, 100]`, including fractions. Zero drops all eligible data; 100 keeps all eligible data. |
| `sampling_settings.sampling_key` | `trace_id` | Nonempty, literal log field name. String and byte values are supported. Ignored for metrics and traces. |
| `debug` | `false` | Print trace registries before and after processing. Intended for diagnostics. |

Omitting `sampling_settings` applies defaults. Unknown settings, invalid rates,
truncated settings and conditions on probabilistic sampling fail startup.

### Traces and correlated logs

Trace decisions hash all 16 bytes of the trace ID. Missing, incorrectly sized and
all-zero trace IDs are dropped. Spans sharing a trace ID make the same decision,
independent of request boundaries, span IDs, host byte order or processor instance.

Log key lookup checks OTLP record fields, OTLP record attributes, ordinary
record metadata fields, ordinary metadata attributes, then the log body.
For example, `sampling_key: customer` reads the OTLP log attribute named
`customer` before looking for a body field with that name. With the default `trace_id` key, 16-byte binary IDs and 32-character
hex IDs (including uppercase hex) normalize to the same value as trace spans.
Use the same percentage to retain corresponding logs and spans. A malformed,
zero or absent log trace ID uses an independent probabilistic decision, so
untraced events remain eligible. Group/resource/scope envelopes are preserved.

For ordinary JSON logs, set `sampling_key` to a string field such as
`request_id` or `customer_id`. Equal keys receive equal decisions. When that key
is absent, empty or has an unsupported type, each event receives an independent
decision. These unkeyed decisions are not stable across process restarts or
replays. Their generator is seeded once per processor, avoiding a system call
for every log record.

The stable hash uses FNV-1a followed by a 64-bit avalanche and a monotonic
percentage threshold. It is an internal sampling scheme, **not an implementation
of the OpenTelemetry consistent probability sampling specification**. It does
not read or rewrite W3C sampling probability fields or honor sampling priority.

**Upgrade compatibility:** the former implementation used only the first eight
trace-ID bytes and integer percentages. This implementation changes the selected
trace cohort at intermediate percentages. Upgrade instances that must agree on
trace decisions together. Configuration syntax and the default percentage stay
the same; explicit invalid percentages now fail startup.

### Sample logs from selected Kubernetes namespaces or applications

Use the generic processor `condition` (singular) to select which logs are
eligible for sampling. This example samples 10% of logs from the `checkout`
application in the `staging` namespace and preserves all other logs:

```yaml
processors:
  logs:
    - name: sampling
      type: probabilistic
      condition:
        op: and
        rules:
          - field: "$kubernetes['namespace_name']"
            op: eq
            value: staging
          - field: "$kubernetes['labels']['app']"
            op: eq
            value: checkout
      sampling_settings:
        sampling_percentage: 10
```

These accessors read the log body. Kubernetes enrichment must run before this
processor; for logs enriched by the Kubernetes filter, place the sampler on the
output pipeline. Records missing either field bypass this sampler. Remove one
rule to select only a namespace or application. Separate samplers can assign
different rates to disjoint selections; overlapping selections are sampled again
by each matching processor.

Keep `sampling_key` set to `trace_id`, or use a request ID for ordinary logs.
Namespace and application fields select eligible logs; using either as the
sampling key makes the entire namespace or application share one keep/drop
decision. Selecting only some logs can also break log/trace retention parity.

This generic log condition is separate from tail sampling's `conditions` array.
Tail attribute conditions retain matching traces and drop unmatched traces;
they do not provide a percentage for selected namespaces with bypass for others.

### Metrics: stable series selection

Metric sampling is opt-in under `processors.metrics`:

```yaml
processors:
  metrics:
    - name: sampling
      type: probabilistic
      sampling_settings:
        sampling_percentage: 25
```

The processor selects series using the fully qualified metric name plus label
names and values. Label order, values, timestamps and batching do not change the
decision. Resource and scope attributes are retained but are not part of the
sampling key; equal series keys in different resources share a decision. All
points of a selected series remain eligible across subsequent requests.

Counters, gauges, untyped metrics, explicit histograms, exponential histograms
and summaries are supported. Histogram buckets and summary quantiles are kept
or discarded together with their point. Values, aggregation temporality and
monotonicity are not changed. Empty metric families are removed.

This is series selection, **not temporal downsampling or unbiased estimation**.
Values are not multiplied by the inverse sampling rate. Fleet-wide totals,
alerts and SLO calculations over the selected series can undercount. Keep
critical metrics unsampled; use explicit metric selection or aggregation when
exact totals are required. Percentages describe expected coverage over diverse
keys, not a quota for each small batch.

## Tail sampling

```yaml
processors:
  traces:
    - name: sampling
      type: tail
      sampling_settings:
        decision_wait: 5s
        max_traces: 50000
      conditions:
        - type: status_code
          status_codes: [ERROR]
```

`decision_wait` defaults to `30s`; `max_traces` defaults to `50000`. Both must be
positive. Conditions are ORed: a match on any span retains its buffered trace.
Without conditions, buffered traces are retained. An explicitly empty conditions
array matches nothing. Existing condition types are `status_code`, `latency`,
`string_attribute`, `numeric_attribute`, `boolean_attribute`, `span_count` and
`trace_state`. The latency condition currently evaluates individual span latency.

Tail sampling retains spans in memory until a periodic decision timer runs.
All spans belonging to one trace must reach the same processor instance. The
trace count limit evicts the oldest buffered trace; it is not a byte or span
limit. Late spans can start a new decision after an earlier decision expires.
Pending traces are discarded during shutdown. Tail sampling re-injects selected
traces using the input's tag; dynamic per-request tags are not preserved.

## Adoption assessment

This assessment uses code inspection and the upstream capabilities below. The
priorities are engineering judgments, not measured customer or market demand.

| Priority | Adoption need | Finding and status |
|---|---|---|
| P0 | Basic multi-signal volume control | Log and metric callbacks were absent. Added correlated/keyed log sampling and stable metric-series selection. |
| P0 | Configuration and diagnostics | Fixed ignored backend failures, missing default config maps, truncated settings, diagnostic span destruction and backend registration through a shared global list node. |
| P0 | Reliable probability control | Added fractional percentages, bounded finite validation and hashing of the full trace ID. Fixed invalid trace IDs being treated as a valid zero-valued sampling key. |
| P0 | Defined deployment support | Tail sampling on outputs or non-trace signals now fails startup. Stateless sampling supports input/output processing and multiple instances. |
| P1 | Preserve valuable events while limiting cost | Tail conditions retain error traces, but no built-in mixed error/slow/baseline allocation or log sampling-priority overrides exist. Add explicit policy composition and retention overrides next. |
| P1 | Bounded state and late-arrival consistency | Tail sampling has a trace-count limit, but no byte/span budget, decision cache or persistence. Add those before positioning it for large production tail-sampling fleets. |
| P1 | Backend interoperability | No OpenTelemetry probability metadata propagation or compatible sampler mode. Implement as an explicit mode with interoperability fixtures; do not claim compatibility from deterministic hashing alone. |
| P1 | Routing and shutdown | Tail sampling loses dynamic tags and discards pending state at shutdown. Preserve route identity and define drain behavior before supporting those deployments. |
| P2 | Metric cost reduction with exact aggregates | Stable series selection is available; temporal aggregation, delta-aware downsampling and estimation are separate features. |
| P2 | Operator confidence | Add workload benchmarks, measured memory budgets, eviction/late-span counters and rollout recipes. Generic processor accounting alone cannot explain tail-buffer pressure. |

Upstream comparison, checked November 4, 2026:

- [OpenTelemetry probabilistic sampler](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/probabilisticsamplerprocessor)
  supports traces and logs, trace-ID/attribute decisions and priority overrides.
  Its probability metadata modes are a concrete interoperability target.
- [OpenTelemetry tail sampler](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor)
  exposes composition, rate/byte limiting and decision caches, and documents the
  requirement that a trace's spans reach the same instance.
- [Fluent Bit sampling manual](https://docs.fluentbit.io/manual/data-pipeline/processors/sampling)
  describes trace head/tail sampling. Public documentation needs to describe
  added log/metric semantics and the changed trace cohort before release.

## Verification

The focused integration scenario is
`tests/integration/scenarios/processor_sampling`. It exercises OTLP protobuf
input/output for all three signals, grouped logs, multiple resources/scopes,
0/100/fractional/default rates, repeated requests, sibling output isolation,
trace/log correlation, metric family preservation, label ordering, unkeyed and
custom-key logs, OTLP attribute keys, invalid configuration, configuration
dry-run cleanup, tail error retention, regular-expression conditions, and scope
schema preservation in both tail reconstruction modes.

```sh
FLUENT_BIT_BINARY=/path/to/build/bin/fluent-bit \
  tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/processor_sampling -q
VALGRIND=1 VALGRIND_STRICT=1 FLUENT_BIT_BINARY=/path/to/build/bin/fluent-bit \
  tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/processor_sampling -q
```


The sampling benchmark initializes its backend through the normal configuration
API and reports retained spans as well as total spans. With benchmarks enabled,
run the following command. Rates of 0 and 100 also check their retention boundaries.

```sh
build/bin/flb-bench-processor_sampling -m probabilistic -i 128 -w 2 -s 4 -a 0 -c 128 -p 50
```
