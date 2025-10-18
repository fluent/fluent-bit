# Telemetry Routing Overview

Fluent Bit's telemetry router provides a unified configuration surface for
logs, metrics, and traces.  Routes are defined on a per-input basis and apply to
all signals produced by that input.  Each route declares an optional signal
filter, a condition, per-route processors, and the list of output targets that
should receive matching telemetry.

## Configuration Structure

Routes are declared inside `pipeline.inputs[]` entries in the Fluent Bit YAML
configuration:

```yaml
pipeline:
  inputs:
    - name: opentelemetry
      processors:
        - name: parser
          parser: json
      routes:
        logs:
          - name: errors
            condition:
              rules:
                - field: "$level"
                  op: eq
                  value: "error"
            to:
              outputs:
                - name: loki
                  fallback: s3_archive
          - name: default
            condition:
              default: true
            to:
              outputs:
                - name: elasticsearch
        metrics:
          - name: cpu_hot
            condition:
              rules:
                - field: "$metric.name"
                  op: regex
                  value: "^cpu_"
            to:
              outputs:
                - name: prometheus_remote
```

### Key elements

* **Input processors** – shared processors executed before any routing logic.
* **Routes** – grouped by telemetry signal.  Each key under `routes` must be a
  signal label (`logs`, `metrics`, `traces`, or a comma-separated combination)
  whose array value contains the ordered route definitions for that signal.  A
  key of `any` targets all telemetry types.
  * `condition.rules` contains record accessor comparisons evaluated against the
    chunk.  Routes can also mark themselves as the default handler with
    `condition.default: true`.
  * `processors` (optional) define per-route processor chains executed after the
    condition succeeds and before dispatching to outputs.
  * `to.outputs` lists the primary output targets.  Entries may be simple names
    or objects with an optional `fallback` output used when the primary target
    fails.

## Evaluation Order

1. Execute input-level processors.
2. For each route whose signal mask matches the chunk type:
   1. Evaluate the route condition.  Routes flagged as `default` bypass rule
      evaluation.
   2. If the condition succeeds, run the route processors and then attempt to
      send the chunk to each configured output.
3. When an output write fails permanently, the router retries once using the
   configured fallback output (if any).

## Conditions and Field Resolution

Route conditions rely on record accessors that are aware of the telemetry type:

* **Logs** – record keys, metadata, `exists`, `eq`, `regex`, `contains`, `in`.
* **Metrics** – metric name/value, resource and attribute keys, numeric
  comparison operators (`gt`, `lt`, `gte`, `lte`).
* **Traces** – span fields and resource/scope attributes with equality, regex,
  and duration comparisons.

The loader validates that each referenced field is supported by the selected
signals, providing early feedback during configuration parsing.

## Output Fallbacks

Outputs may declare a secondary target that receives the chunk when the primary
write fails with a permanent error.  Fallback dispatch happens once per output
attempt and produces debug logs as well as `fluentbit_routing_fallback_total`
metrics to aid troubleshooting.

## Metrics and Observability

The router exposes Prometheus counters using the `fluentbit_routing_*` prefix
covering routed records, bytes, condition failures, and fallback events.  The
labels capture the input name, route name, target output, and signal type.

## Cleanup Helpers

The router exposes `flb_router_routes_destroy()` to release all resources
allocated during YAML parsing.  Callers should destroy the list after invoking
`flb_router_config_parse()` once the configuration has been consumed.
