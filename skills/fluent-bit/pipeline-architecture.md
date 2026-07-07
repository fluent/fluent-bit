# Fluent Bit Pipeline Architecture Skill

Use this guide for shared runtime, routing, task, chunk, storage, processor,
filter, output, metric, retry, and shutdown changes.

## Runtime Model

Data moves through:

```text
input -> chunk -> router -> task -> filter/processor -> output -> engine result
```

Routing is per output instance. One chunk can fan out to many routes. Route
state is independent, so success, retry, and drop can differ for each output.

## Data Units

- A signal is the high-level type: logs, metrics, traces, profiles, or blobs.
- A record/event is the logical payload unit inside a signal.
- A chunk is the persisted or queued container, often MessagePack-backed.
- A task is the engine execution unit for a chunk across routes.

Never assume "one chunk equals one route" or "one serialized event equals one
log record" in shared code.

## Component Responsibilities

- Inputs (`plugins/in_*`) create or append data and trigger ingestion.
- Input chunk layer (`src/flb_input_chunk.c`) manages chunk lifecycle, routing
  masks, storage pressure, and drop/release behavior.
- Router (`src/flb_router*.c`) resolves tag and signal matches to outputs.
- Task layer (`src/flb_task.c`) tracks per-route state and retries.
- Filters (`plugins/filter_*`) run on matching streams before output flush.
- Processors (`plugins/processor_*`) can run in input or output contexts and may
  mutate or drop payloads.
- Outputs (`plugins/out_*`) serialize or protocol-encode and return flush
  results.
- Engine (`src/flb_engine.c`) applies retry/drop accounting and task teardown.

## Signal-Aware Rules

- Shared paths must branch correctly by event type.
- Log-only record semantics may not apply to metrics, traces, profiles, or
  blobs.
- Group or metadata markers can be serialized events; treat them as data-shape
  artifacts unless an interface explicitly requires them.

## Counting and Metrics

Separate:

- serialized events in a buffer;
- logical records after processing;
- per-route processed, retry, and drop counters;
- byte accounting for chunk bytes versus route-effective bytes.

Prefer route-aware values for route metrics. Preserve explicit zero values.

## Retry and Drop Semantics

- `FLB_OK`: route succeeded.
- `FLB_RETRY`: route keeps the task or chunk for retry scheduling.
- `FLB_ERROR`: route failure/drop path.

Final chunk release happens only when all active routes are resolved.

## Storage and Backlog

In-memory and filesystem backlog paths may use different code paths. Validate
both when touching chunk, task, storage, lifecycle, or accounting code.
Backlog-loaded chunks must preserve route state and accounting parity with
live-ingested chunks.

## Review Checklist

- Trace one full path for affected signals:
  input -> chunk -> task -> output -> engine completion.
- Verify fan-out behavior: one chunk, multiple outputs.
- Verify processor behavior: drop, modify, and no-op in input and output
  contexts when relevant.
- Verify empty payload behavior.
- Verify metrics and counters for success, retry, and drop paths.
- Verify shutdown cleanup if event channels, file descriptors, coroutines, or
  scheduler state are touched.

