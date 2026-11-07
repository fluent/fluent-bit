# rewrite_tag batching POC

This POC batches rewritten logs by destination tag inside an input processor
callback. It continues each batch at the next processor stage, using the original
input's append/storage path. `batch_size: 0` remains the default.

```yaml
processors:
  logs:
    - name: rewrite_tag
      rule: $level ^error$ errors.$TAG false
      batch_size: 4096
```

`batch_size` limits the number of records in a callback eligible for batching;
it does not accumulate records between callbacks. The maximum is 4096. Callbacks
with fewer than two records, more than the configured maximum, or more than
256 KiB of serialized input use the existing path. Group expansion has the same
256 KiB payload bound. Metadata, tag strings, and allocator overhead are additional.
The option applies to input processors; regular filters retain their emitter path.

Preparation finishes before any records are emitted. Originals are saved in a
single buffer and compacted after emission without allocating another result.
If an inline batch append fails, records individually fall back to the emitter,
retaining the existing emitter admission policy. Rejected records keep their
original tag. Destination buffers start at the first record's size, avoiding an
8 KiB minimum allocation for every tag.

Grouping preserves order within each destination tag and among retained originals.
It changes interleaving across destination tags in downstream processors. This
matters for stateful processors that depend on a global record order. Appends and
downstream processor side effects remain nontransactional, including during
fallback. Processor conditions can reduce calls to individual records, which
prevents batching from helping those calls.

## Measurements

Results are generated on the machine described in [environment.json](environment.json).
Both executables use the same Release configuration and repository libraries;
the baseline is commit `05048e35d7106890006b7b593531bd51a16dfc93`. The POC executable
includes the bug fixes below. The `poc-processor-off` control includes those same
fixes with batching disabled.

The workload is a cached JSON file read by Tail with 128 KiB read buffers, two
native `content_modifier` stages, and a counter output. Processor variants run the
two stages after rewriting; the regular-filter variant runs them on the original
input before the global filter. Every sample must deliver the expected total
before the driver requests shutdown. Integration tests separately check record
identities, routing, group metadata, and fan-out.

The driver and child run on CPU 0. Variant order is shuffled for each repetition.
CPU time is GNU time's user plus system time for Fluent Bit. Wall time includes
startup, output flushes, and shutdown, so CPU cost is the primary comparison.
Peak RSS is the maximum for the whole process, not scratch allocation or a memory
limit. These are local CPU-focused measurements, without network outputs or slow
consumers.

All timings below are medians in CPU seconds. Every sample passed the output
count check. The primary cases use 500,000 input records and five repetitions.

| Destination tags | Regular filter, baseline | Input processor, baseline | POC, batching off | POC, batching on | CPU reduction vs baseline processor |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 2.89 | 4.77 | 4.66 | 3.03 | 36.5% |
| 16 | 2.97 | 5.93 | 5.77 | 3.24 | 45.4% |

Primary-case median peak RSS:

| Destination tags | Regular filter, baseline | Input processor, baseline | POC, batching off | POC, batching on |
| --- | ---: | ---: | ---: | ---: |
| 1 | 27.3 MiB | 23.0 MiB | 24.5 MiB | 26.6 MiB |
| 16 | 97.7 MiB | 120.0 MiB | 119.3 MiB | 98.8 MiB |

Controls use three repetitions each:

| Workload | Input records | Regular filter, baseline | Input processor, baseline | POC, batching off | POC, batching on |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1,024 tags | 50,000 | 5.11 | 8.46 | 8.51 | 8.95 |
| No rule matches, 1 tag | 500,000 | 2.58 | 2.88 | 2.80 | 2.91 |
| KEEP true, 1 tag | 250,000 | 1.75 | 3.24 | 3.16 | 2.34 |
| KEEP true, 16 tags | 250,000 | 1.82 | 3.72 | 3.64 | 2.44 |

Batching cuts CPU cost for repeated destination tags: about 36–45% in the primary
cases and 28–34% with KEEP true. Compared with the same fixed executable with
batching disabled, the primary reductions are 35.0% and 43.8%.

At 1,024 tags, batching costs 5.8% more CPU than the original processor and has
208.7 MiB median peak RSS, versus 204.2 MiB for the original processor. Most records
in a callback have distinct destination tags in this case, so there is little work
to combine. The no-match control differs by about 1% from the original processor,
and 3.9% from the fixed processor with batching off.

The regular filter uses less CPU in every measured case. Input processor batching
is useful when processor stage continuation is required and many records share
destination tags; these measurements do not justify enabling it by default.
High-cardinality tag creation also has substantial costs in the existing paths.
The 1,024-tag case uses a smaller input count because it is much slower; compare
variants within that row, rather than absolute times across workloads.

There are 88 verified samples totaling 32.6 million input records. This is a local
benchmark of cached ingestion and counting, rather than a network-output or
backpressure throughput result.


Raw samples: [throughput.csv](throughput.csv),
[high-cardinality.csv](high-cardinality.csv), [no-match.csv](no-match.csv),
and [keep.csv](keep.csv).

## Bugs fixed during validation

- Processor-owned filters can have the same instance name on different inputs.
  Their generated emitter aliases now include the input name and processor stage.
  The multi-input group tests previously failed startup on the baseline.
- Private emitters created during input processor initialization could initialize
  twice when the outer input initialization loop later visited them. Successful
  input initialization is now idempotent. Valgrind exposed leaked metrics, TLS
  configuration, and other emitter state in the multi-input cases.
- The processor framework discarded an allocated filter result when its size was
  zero. It now frees that buffer. Before the fix, the batching workload grew to
  about 171 MiB RSS for 500,000 records and one tag; the final measurements use
  the corrected executable.
- Failed or empty tag expansion preserves the original record, including mixed
  batches where other records emit successfully. The first matching rule still
  wins; an invalid expansion does not try a later rule.
- Output-processor placement is rejected during initialization. Its callback
  context is an output instance, while the emitter fallback expects an input.
- Emitters without an owner shutdown hook now publish their pending queue before
  ingestion stops. Downstream emitters that already received their shutdown pause
  publish newly forwarded records immediately. A guard prevents recursive emission
  during that publication. The reverse-order two-emitter regression lost all
  1000 records on the baseline and passes after the fix.
- Allocating an emitter sender reference now returns an error on failure. The
  former positive `FLB_FILTER_NOTOUCH` return was interpreted as successful
  emission by `rewrite_tag`.

## Validation

[verification.json](verification.json) records the final results: 39 integration
cases passed normally and 39 passed under strict Valgrind, with zero errors and
zero definitely, indirectly, or possibly lost bytes across all 39 Valgrind logs.
The 11 focused CTest executables also passed.

The integration cases cover ordinary filtering, input processing with batching
on/off, the callback-count fallback, alternating tags, KEEP true/false, missing
and empty destination fields, processor stage position, two-output fan-out, group
metadata, multiple source inputs, output-processor rejection, emitter shutdown
chains in both orders, multiline shutdown under backpressure, and log-to-metrics.
Core tests additionally cover storage limits, route restoration, processor
conditions, input pause behavior, dispatch, and adaptive flush.

Commands run from the repository root:

```sh
cmake -S . -B build-bench-otel -DFLB_TESTS_RUNTIME=On \
  -DFLB_TESTS_INTERNAL=On -DFLB_BENCHMARKS=On -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench-otel --target fluent-bit-bin \
  flb-rt-filter_rewrite_tag flb-it-processor flb-it-processor_conditional \
  flb-it-input_chunk flb-it-input_chunk_routes flb-it-input_pause \
  flb-it-engine_dispatch flb-it-engine_adaptive_flush flb-it-input_rate_gate \
  flb-it-mp_chunk_cobj flb-rt-processor_content_modifier -j8

FLUENT_BIT_BINARY=$PWD/build-bench-otel/bin/fluent-bit \
  tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/filter_rewrite_tag \
  tests/integration/scenarios/filter_multiline \
  tests/integration/scenarios/filter_log_to_metrics -q

FLUENT_BIT_BINARY=$PWD/build-bench-otel/bin/fluent-bit \
  VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/filter_rewrite_tag \
  tests/integration/scenarios/filter_multiline \
  tests/integration/scenarios/filter_log_to_metrics -q

ctest --test-dir build-bench-otel \
  -R '^(flb-rt-filter_rewrite_tag|flb-rt-processor_content_modifier|flb-it-(processor|processor_conditional|input_chunk|input_chunk_routes|input_pause|engine_dispatch|engine_adaptive_flush|input_rate_gate|mp_chunk_cobj))$' \
  --output-on-failure
```

The existing integration virtual environment and installed Valgrind were used.
Generated integration logs and environments remain ignored by git.

To repeat the benchmarks with the executable snapshots from this run:

```sh
python=tests/integration/.venv/bin/python
baseline=/tmp/rewrite-tag-poc/fluent-bit-baseline
poc=/tmp/rewrite-tag-poc/fluent-bit-poc
$python benchmarks/rewrite-tag/benchmark.py --baseline "$baseline" --poc "$poc" \
  --records 500000 --repetitions 5 --tags 1 16 --cpu 0 \
  --output /tmp/rewrite-tag-throughput.csv
$python benchmarks/rewrite-tag/benchmark.py --baseline "$baseline" --poc "$poc" \
  --records 50000 --repetitions 3 --tags 1024 --cpu 0 \
  --output /tmp/rewrite-tag-high-cardinality.csv
$python benchmarks/rewrite-tag/benchmark.py --baseline "$baseline" --poc "$poc" \
  --records 500000 --repetitions 3 --tags 1 --cpu 0 --no-match \
  --output /tmp/rewrite-tag-no-match.csv
$python benchmarks/rewrite-tag/benchmark.py --baseline "$baseline" --poc "$poc" \
  --records 250000 --repetitions 3 --tags 1 16 --cpu 0 --keep \
  --output /tmp/rewrite-tag-keep.csv
```

To recreate the baseline later, build the recorded base commit in a separate
checkout with the same CMake options and dependencies. Executable SHA-256 values
are included in `environment.json`. GNU time and stdbuf are required by the driver.
