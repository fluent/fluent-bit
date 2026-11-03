# CMetrics consumer API extension

Status: design proposal; no implementation or public API change in this patch.

This proposal targets upstream `fluent/cmetrics`. Fluent Bit should adopt a
released version afterward, with consumer migrations in separate commits.
The baseline reviewed here is CMetrics 2.3.1, bundled by Fluent Bit master
`237955b0b`, and the rebased FTS branch.

## Problem and scope

Consumers need operations on metrics, labels, and selections without owning
CMetrics' representation. Today:

| Consumer | Current dependency | Operation the public API should own |
| --- | --- | --- |
| `plugins/processor_labels/labels.c` | Label lists, static-sample storage, sample copies, ownership, hash fields and the index cursor | Insert, update, upsert, delete and transform labels |
| `plugins/processor_metrics_selector/selector.c` | Creates an intermediate context with `cmt_filter*()`, then copies it with `cmt_cat()` | Produce one selected context with explicit failure semantics |
| `plugins/in_node_exporter_metrics/ne_textfile_linux.c` | Merges into a persistent context whose counters remain referenced | Merge with diagnostics and a documented mutation guarantee |
| `plugins/processor_fts/fts_metrics.c` | Moves families, reparents them and edits OTLP routing metadata | Eventually copy or transfer families while preserving their telemetry context |
| Cumulative-to-delta and Windows exporter consumers | Traverse or remove native samples | Eventually iterate and remove samples through opaque handles |

The labels regression found during the rebase illustrates the boundary:
prepending a converted static sample before the indexed prefix made lookups
miss it. The immediate fix resets `map->last_metric`. A consumer API should
make that invariant entirely CMetrics' responsibility.

The first release should cover selection, exact cloning and label edits.
Atomic merging and general sample/family editing are separate follow-ups.
Existing APIs and exposed structs remain available; this is an additive
migration, not an immediate ABI redesign.

## Proposed public surface

Add an installed `cmetrics/cmt_consumer.h`. New views, plans, options and
errors are opaque forward declarations. Callers never allocate their structs,
inspect list links, assign hashes, or read metadata container keys.

The following signatures are proposed, not currently implemented:

```c
struct cmt_family_view;
struct cmt_label_view;
struct cmt_label_edit;
struct cmt_label_plan;
struct cmt_label_options;
struct cmt_consumer_error;

/* Return KEEP, DROP, or a negative consumer error status. */
typedef int (*cmt_family_predicate)(const struct cmt_family_view *family,
                                    void *user_data);

/* Read the old value through getters; use edit setters to copy a replacement. */
typedef int (*cmt_label_transformer)(const struct cmt_label_view *label,
                                     struct cmt_label_edit *edit,
                                     void *user_data);

int cmt_context_clone(const struct cmt *source, struct cmt **out,
                      struct cmt_consumer_error **error);

int cmt_context_select(const struct cmt *source,
                       cmt_family_predicate predicate, void *user_data,
                       struct cmt **out, struct cmt_consumer_error **error);

int cmt_context_apply_labels(const struct cmt *source,
                             const struct cmt_label_plan *plan,
                             const struct cmt_label_options *options,
                             struct cmt **out,
                             struct cmt_consumer_error **error);

void cmt_consumer_error_destroy(struct cmt_consumer_error *error);
```

Provide family getters for fully qualified name, description, type, unit,
temporality and monotonicity. A family view identifies one family in its
resource/scope context; a name alone is not a unique identity. Provide label
getters for key, value and target (context-static or point), plus an optional
borrowed family view for point labels. String getters return borrowed bytes
and length; no allocator ownership crosses the API boundary.

Plan creation, destruction and append functions express `INSERT`, `UPDATE`,
`UPSERT`, `DELETE`, and `TRANSFORM`. Plans copy their string arguments and
execute operations in insertion order. Opaque options specify label target,
key matching and collision policy. Options are immutable while applying a
plan; creation and setter functions permit future additions without callers
depending on a struct size.

An edit setter copies callback-supplied bytes before returning. Callbacks may
use stack buffers and never return allocations for CMetrics to free. Callback
state remains owned by the caller and must survive the synchronous call.

Add a row-selection operation alongside family selection for the selector's
`delete_label_value` context. Its predicate uses opaque point/label views and
keeps or drops whole points. Deleting matching points and deleting a label
from every point are distinct operations. Predicates see immutable input and
cannot modify or retain their views.

## Ownership, errors and mutation guarantees

All three initial operations have the same contract:

1. Validate output arguments; set `*out = NULL` and the optional error output
   to NULL before doing work. Callers pass an empty error slot or destroy an
   earlier error first.
2. Borrow the source for the duration of the call. It remains unchanged on
   success and failure. Synchronization against concurrent mutation belongs
   to the caller.
3. On success, return a newly owned context, destroyed with `cmt_destroy()`.
   A selection with no matches successfully returns an empty context.
4. On allocation, callback, limit or semantic failure, release all temporary
   state, return a specific status, and leave `*out == NULL`.

Use named statuses for invalid arguments, allocation failure, incompatible
family semantics, label/series collision, unsupported operation, callback
failure and configured limits. Optional diagnostics own copies of relevant
names and identify the failed operation and conflict category. They remain
usable after either context is destroyed; they never expose internal pointers.

Exact cloning preserves each family and point, including order and duplicate
native identities. It must not be implemented with `cmt_cat()`, whose merge
semantics can combine families or points, or through a serialization round
trip that can discard ambiguous sidecars.

## Label semantics and library invariants

Support counters, gauges, untyped values, summaries, classic histograms and
exponential histograms. Preserve exact signed/unsigned scalar values,
timestamps, start times and all distribution storage during label edits.

CMetrics owns these steps as one operation: changing keys and values,
promoting static samples where needed, updating counts, recomputing series
identity, rebuilding indexes, and releasing replaced storage. Consumers never
set `last_metric`, `_hash_head`, `hash_indexed`, or `metric_static_set`.

Make policy choices explicit:

- Native labels use string values. Typed OTLP attributes remain typed when
  untouched. A string replacement changes the corresponding attribute to a
  string; deletion removes the corresponding typed attribute. Refresh label
  projections without discarding unrelated attributes or point metadata.
- Context-static labels and point labels are separate targets. Include a
  public presence query so Fluent Bit can preserve its current dynamic-first
  lookup and static fallback without traversing either representation.
- Default key matching is byte-exact. An explicit ASCII case-insensitive
  option preserves the existing labels processor's matching behavior.
- Updating a missing key and deleting a missing key are successful no-ops;
  insert preserves an existing value; upsert creates or replaces it.
- Reject embedded NUL bytes where native labels require C strings. Validate
  other representability constraints at the appropriate codec boundary.
- If an edit collapses distinct series, reject it by default. Optional
  keep-first/keep-last behavior must be explicit and deterministic. Numeric
  aggregation requires its own operation with type-specific semantics.

Resource/scope attributes, schema URLs, flags, exemplars, units, temporality
and monotonicity stay attached to the family or point they describe. Dropping
families or points also removes their obsolete metadata references. Native
readers/writers retain their existing compatibility rules: the new API cannot
promise that ambiguous sidecars survive an unchanged MessagePack format.

## Selector migration

Use family predicates for prefix, substring, include/exclude and regex rules.
The Fluent Bit regex implementation stays in Fluent Bit; the callback reads
the family name through the public getter. Use row selection for label-pair
deletion. The API copies retained families, points and their telemetry context
once and never merges unrelated families as a side effect of selecting them.

The callback publishes only a successful result:

```c
*out_context = NULL;
ret = cmt_context_select(metrics_context, matches_rule, ctx, &selected, &error);
if (ret != CMT_CONSUMER_OK) {
    report_selection_error(error);
    cmt_consumer_error_destroy(error);
    return FLB_PROCESSOR_FAILURE;
}
*out_context = selected;
return FLB_PROCESSOR_SUCCESS;
```

This replaces the intermediate `filtered` context and second `cmt_cat()` call.
The current `cmt_filter*()` signatures and behavior remain unchanged.

## Labels migration

Build an ordered plan from the configured delete/update/upsert/insert/hash
operations, preserving the processor's current operation order. Resolve tag
record accessors in Fluent Bit before applying literal replacements. SHA256
remains a Fluent Bit callback; it receives a borrowed value and uses the edit
setter to copy the digest. CMetrics has no dependency on Fluent Bit, its
allocator, record-accessor syntax, or crypto implementation.

After migration, `labels.c` handles configuration, value resolution, callbacks
and logging. Remove its metric/label allocation helpers, static-sample
`memcpy()`, direct list edits and index maintenance. Verify existing pipeline
results before removing compatibility paths.

## Follow-up: atomic merge for persistent contexts

Keep `cmt_cat()`'s existing contract, including possible partial destination
mutation on failure. Add a distinct API when an atomic implementation is ready:

```c
int cmt_context_merge_atomic(struct cmt *destination, const struct cmt *source,
                             const struct cmt_merge_options *options,
                             struct cmt_consumer_error **error);
```

It must stage validation and allocations before publishing changes. Failure
leaves the destination unchanged. Success preserves the destination pointer
and existing public counter/gauge/family handles: the textfile collector keeps
`ctx->load_errors`, so destroying and replacing the whole context is unsafe.
Point views expire on mutation. Commit must be allocation-free and callers
must exclude concurrent readers and writers for the operation.

Reject incompatible explicit units, temporalities, monotonicity, label schemas
or distribution layouts with diagnostics; never reinterpret existing samples.
Options define whether compatible duplicate points replace values or remain
distinct, and how resource/scope identities participate in family matching.
Do not implement this API as a wrapper that calls `cmt_cat()` and reports its
error after it has already changed the destination.

Until this exists, textfile collection checks and reports merge errors while
retaining its shared context. Temporary-output consumers discard failed
destinations, as the current selector fix does.

## Compatibility and acceptance criteria

Introduce an advertised consumer-API feature/version macro in a CMetrics
release. Keep existing function signatures, struct layouts and wire formats
unchanged. New opaque handles allow later index and storage changes without
requiring consumer source changes. General family transfer and sample mutation
should use the same boundary in later extensions; they are not prerequisites
for the first two consumer migrations.

Acceptance tests must cover:

- All six metric types; static, dynamic and mixed samples; ordered plans;
  absent labels; regex/no-match selection; label-pair point deletion.
- Exact integer boundaries, histogram/summary/exponential-histogram storage,
  duplicate family names across scopes, and resource/scope preservation.
- Label edits followed by normal lookup/update/removal, including converted
  static samples before an existing indexed prefix and index resizing.
- Typed-attribute collisions, unchanged metadata, and the existing ambiguous
  sidecar fallback through MessagePack and OTLP relays.
- Allocation failure at each staging step, callback failure, limits and
  collisions: unchanged input, NULL output and no leaks or double frees.
- For atomic merge, unchanged destination on every failure and still-valid
  preexisting metric handles after success.
- Standalone C/C++ header consumers, shared/static linking, the full CMetrics
  suite, Fluent Bit consumer regression suites, and strict Valgrind or macOS
  Leaks runs. Include Windows functional coverage.

Measure large-family and high-cardinality workloads before adopting the APIs.
The initial out-of-place implementation may require one complete output
context, but should copy only once. Optimize staging inside CMetrics after
the ownership and atomicity contracts are proven; preserve those contracts.

## Current implementation references

- [Labels consumer](plugins/processor_labels/labels.c) and
  [selector consumer](plugins/processor_metrics_selector/selector.c).
- [Map/index ownership](lib/cmetrics/src/cmt_map.c),
  [merge behavior](lib/cmetrics/src/cmt_cat.c), and
  [existing selection functions](lib/cmetrics/include/cmetrics/cmt_filter.h).
- [Sidecar identity and restoration](lib/cmetrics/src/cmt_otlp_metadata.c) and
  [relay identity regression tests](lib/cmetrics/tests/otlp_pipeline.c).
