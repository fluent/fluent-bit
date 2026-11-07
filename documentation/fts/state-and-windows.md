# FTS state and window contracts

FTS provides three mechanisms with different ownership and timing semantics:

| Mechanism | Example | Retained data | Placement |
| --- | --- | --- | --- |
| Stateless keyed decision | Stable log sampling | None | Supported input/output recipes |
| Immediate stateful decision | Dedupe, keyed throttle | Bounded per-key state | Input only |
| Buffered window | Request log retention, temporal gauge rollup | Bounded owned events or metric snapshots | Input only |

Start with the [consumer guide](../../packs/fts/README.md),
[processor API](../../plugins/processor_fts/README.md) and the specific pack README.
State belongs to one processor instance. Related observations need affinity to
that instance; separate inputs, processes and workers do not share state.
Use trusted tenant/resource boundaries when defining keys.

## Composition and local commit

Construct at most one state/window operation per processor, in the terminal
recipe step. Apply parsing, normalization and privacy rules before it. Configure
`state_commit: local` explicitly and bound native memory with `state_limit`.
Lua callback memory and instruction budgets are separate limits.

A batch transaction stages state changes in a provisional overlay. Later items
in that batch see earlier proposals. Each item has a savepoint: callback errors
roll back that item's edits and proposals; intentional DROP confirms its declared
state accounting. Failure to construct the FTS batch output rolls back the batch
overlay. Commit-time memory and retained ownership are prepared before mutation.

The local commit happens at the successful FTS batch boundary, before later
encoding, processor, routing or storage operations can fail. A later failure can
consume throttle capacity without delivery, suppress a duplicate whose original
was lost, or lead to duplicate retained items if a source retries a batch.
State is volatile on crash, restart, reload and graceful shutdown. Filesystem
buffering downstream does not persist data still held by FTS.

`state_commit: external` is not supported. Durable retention and delivery-aware
state would require separate receipt, journal and recovery contracts. No current
state/window operation provides end-to-end exactly-once delivery.

## Dedupe and throttle

`logs.dedupe` keeps the first key and suppresses repeats until expiry; repeats do
not extend its TTL. `logs.throttle` uses an integer token bucket with explicit
rate and burst. Its inactivity TTL must cover a complete refill. Both use a
monotonic timestamp sampled once per batch.

Typed, length-prefixed keys distinguish strings, bytes, doubles, booleans and
null. Signed/unsigned integers normalize to the same exact integer identity.
Containers and nonfinite values cannot form key components. Missing-key behavior
is explicit. Capacity overflow keeps an untracked sanitized item and counts it,
weakening suppression without evicting a live key. Allocation and instruction
failures remain callback errors.

The native store bounds committed entries, provisional entries and bucket tables
within `state_limit`. Expiration is swept on the next batch; idle memory stays
bounded until traffic resumes or teardown. Cleanup and commit scans are outside
the callback instruction budget and can visit up to 65536 buckets and keys per
batch. Size `max_keys` for the workload. The internal random hash seed distributes
keys; it does not change canonical identity or provide a cryptographic pseudonym.

See the processor README for parameter ranges and counters. Existing native
throttle filters have their own contracts; a global sliding-window rate is not
the same operation as typed per-key transactional suppression.

## Request log windows

Unresolved group-continuation records are sanitized but passed through without
retention, preserving their source context. They increment the window event
outcome `context_passthrough`. Retained record bytes are bounded by `state_limit`;
`output_limit` applies only to output emitted by the current callback, rather than
records transferred into the window store.

`window.hold_until` retains complete sanitized events under a typed key until a
fixed monotonic processing-time deadline. Lua evaluates the retain/keep rules;
the native store supplies bounded ownership, timing and release. Decision timing
is independent of source event timestamps and does not implement watermarks.

Arrival order is preserved within a key; global order across keys can change.
Ready buffers remain frozen in the same bounded store while admission is busy.
Closed-key markers identify late arrivals until their configured late horizon
expires or their bounded metadata is evicted. Known-closed keys pass sanitized
late items through and increment the late counter. An unknown key can start a
new window after marker expiry/eviction.

Configure key limits, hold duration, late horizon, ready retry timeout and
`state_limit`. Payloads, frozen release data and bookkeeping count toward native
retention limits. Capacity overflow preserves the current sanitized original,
so complete grouping is no longer guaranteed. Retry expiry and shutdown discard
retained data and count the loss.

The [request-error example](../../plugins/processor_fts/examples/recipes/window-request-error/README.md)
provides a complete Tail pipeline, decision behavior and counters. This block
processes logs; it cannot retain metric families or whole traces.

## Temporal gauge windows

The [gauge-rollup pack](../../packs/fts/metrics/gauge-rollup/README.md) implements Lua
sum/mean/min/max/count reductions over a native bounded snapshot controller.
It requires OTLP input and a terminal input recipe with local commit.

A window identifies the complete metric family: route tag, metric header,
resource/scope and schemas, numeric kind, and the complete set of series
attributes. Changed series membership starts another window; point order may
change. Output uses the greatest observation timestamp and smallest start time.
These are observation reductions, not rates, time-weighted averages or dimension
aggregation. Preserve exact integers and reject unsupported precision conversions.

The implementation does not silently aggregate sums, histograms, flagged points
or exemplars. Capacity/sample overflow preserves the current original family
without changing the existing aggregate; raw and reduced output can coexist.
Inventory and loss counters measure metric families rather than datapoints.
Read the pack contract for identity, budgets, arithmetic and counter details.

## Release ownership and shutdown

A retained item is HOLD, not DROP. Log retention uses explicit held inventory and
conservation accounting. Release resumes at the next processor stage so the
holding recipe does not execute twice. Timer release invokes no pack Lua.

`flb_input_ingress_try_resume_log` and its metric counterpart are atomic,
nonblocking ownership transfers into the engine ingress queue. Success adopts
and clears the caller's payload pointer. BUSY and allocation errors preserve the
pointer and ownership for a later timer retry. Queue acceptance is not an
acknowledgment of storage or exporter delivery; do not retry after transfer.
The metric API also preserves list membership on failure.

Processors declaring `FLB_PROCESSOR_FLAG_INPUT_STOP` receive `cb_input_stop` once
on the input owner thread before input exit and scheduler destruction, including
partial initialization and reload. Stop blocks admissions, invalidates timers,
and discards/counts pending data. It leaves final context cleanup to processor
exit. Never append from `cb_exit`, where input storage/outputs may already be
gone. An already queued timer must not access freed state. The descriptor loader
reads appended callbacks only when their capability flags are set.

## Extending or verifying the APIs

Keep policy decisions and gauge arithmetic in Lua. Reuse native facilities when
their semantics match; add general typed, bounded or ownership APIs for actual
gaps. Whole-trace retention needs trace affinity, late-span handling and bounded
decision caches. Root arrival does not establish trace completeness. Cross-signal
log-to-metric emission needs an explicit output schema and routing contract.
Neither is provided by an ordinary same-signal FTS block.

Native tests cover exact clock sequences, rollback, capacity and allocation
failures. Integration scenarios cover both threading modes, memory/filesystem
storage, continuation stages, conservation, busy admission, timeout, partial
initialization and stop/reload behavior. Run affected scenarios normally and
with the platform memory checker; preserve source/binary hashes and exact results.
See [verification evidence](../../packs/fts/verification.json) for the published
Linux coverage and the [authoring workflow](authoring.md) for agents.
