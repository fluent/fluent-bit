# Select a harness

Paths below are relative to the checkout root. Keep runner and skill revisions
aligned and inspect actual CLI options instead of copying archived commands.

## Installed binaries and OTLP

Read `benchmarks/README.md`; use `benchmarks/run.py`:

```sh
# Functional smoke only
python3 benchmarks/run.py --system smoke=build/bin/fluent-bit \
  --records 2000 --warmup-records 100 --rate 1000 --runs 1 \
  --output /tmp/flb-benchmark-smoke

# Repeated native comparison
python3 benchmarks/run.py --system before=/path/to/old/fluent-bit \
  --system after=/path/to/new/fluent-bit --runs 5 \
  --output /tmp/flb-benchmark-compare
```

JSON is standard-library only; protobuf needs protobuf and opentelemetry-proto.
`--payload` accepts a sanitized OTLP JSON request. `--config` uses a prepared
BENCH_* template. General drop/fan-out accounting is unsupported. Null excludes
remote destination/TLS/durability costs. Source builds are optional.

## Tail overload

Read `benchmarks/ingestion/README.md`; use `benchmarks/ingestion/ramp.py` with
explicit rates/durations and a fresh directory. Custom config receives
BENCH_LOG_PATH, BENCH_STORAGE_PATH and BENCH_HTTP_PORT. Generated input is fixed
two-line events, not arbitrary production replay. Output counters sum routes;
its schema/validity model differ from the general runner.

## Processors and rewrite tags

Read `benchmarks/results/post-fts-12505/README.md` for `pipeline_compare.py`:
body modifiers, widths, mixed chains and input/output placement.

Read `benchmarks/rewrite-tag/README.md` for `rewrite-tag/benchmark.py`:
repeated/high-cardinality destinations, KEEP and no-match controls. Its --poc
argument names a candidate binary; inspect feature availability. Different
placement changes execution semantics, so check the requested comparison.

## Advanced source/build experiments

- `benchmarks/chunk_allocation/README.md`: filesystem reservations/remaps;
  matching build trees and instrumented GNU linking required.
- `benchmarks/allocator_compare/README.txt`: historical allocator evidence and
  reproduction patches. Check availability; do not silently apply patches to
  the user's tree. Confirm relink findings in normal builds.
- `lib/cfl/benchmarks/README.md`: heap/arena, ownership, distributions, reserved
  and used bytes. Run existing code without editing bundled sources. Do not
  extrapolate nanoseconds/object to pipeline throughput.
- `benchmarks/compare_fluent_bit_otelcol.py --help`: advanced OTLP driver with
  disjoint physical core checks and generator profiling. Defaults/accounting
  differ. Product comparisons require equivalent transformation/durability and
  completion boundaries, not just identical numeric queue settings.
