# Variant arena benchmark

Configure a release build and run the heap and arena workloads with identical
parameters:

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DCFL_BENCHMARKS=On
cmake --build build-bench -j8
build-bench/benchmarks/cfl-benchmark-variant-arena heap 1000 1000
build-bench/benchmarks/cfl-benchmark-variant-arena arena 1000 1000 8192
```

The tool reports elapsed time, peak RSS, glibc heap usage, and arena
reserved/used bytes. Use `perf stat` for CPU and allocator-independent memory
events:

```sh
perf stat -r 5 -e task-clock,cycles,instructions,cache-misses,page-faults \
  build-bench/benchmarks/cfl-benchmark-variant-arena heap 1000 1000
perf stat -r 5 -e task-clock,cycles,instructions,cache-misses,page-faults \
  build-bench/benchmarks/cfl-benchmark-variant-arena arena 1000 1000 8192
```

For fragmentation analysis, run both modes under heaptrack or Massif. Arena
slack is the difference between `arena_reserved` and `arena_used` for the last
constructed graph.

## Mutable OTLP-style logs

The mutable benchmark builds an OTLP JSON-like hierarchy of resource logs,
scope logs, log records, bodies, and attributes. Each mutation round replaces
severity and status attributes, appends a record, and removes the oldest one:

```sh
build-bench/benchmarks/cfl-benchmark-variant-mutable heap 100 100 10
build-bench/benchmarks/cfl-benchmark-variant-mutable arena 100 100 10 8192

perf stat -r 5 -e task-clock,cycles,instructions,cache-misses,page-faults \
  build-bench/benchmarks/cfl-benchmark-variant-mutable heap 100 100 10
perf stat -r 5 -e task-clock,cycles,instructions,cache-misses,page-faults \
  build-bench/benchmarks/cfl-benchmark-variant-mutable arena 100 100 10 8192
```

To compare a graph containing approximately 2 MiB of owned log-body strings:

```sh
build-bench/benchmarks/cfl-benchmark-variant-mutable heap 10 100 10 8192 2097152
build-bench/benchmarks/cfl-benchmark-variant-mutable arena 10 100 10 8192 2097152
```

The optional arguments after content size are the large-object threshold and
payload distribution (`uniform`, `bimodal`, `heavy`, or `random`). A threshold
of zero selects the default of half the arena chunk size. A very large
threshold effectively disables external large-object allocation. The final
optional argument sets the external-buffer cache limit; zero disables caching.

Run the deterministic validation matrix with:

```sh
benchmarks/run_variant_matrix.sh build-bench > variant-matrix.txt
awk -f benchmarks/summarize_variant_matrix.awk variant-matrix.txt
```

It covers zero, 64 KiB, and 2 MiB content; immutable and replacement-heavy
lifetimes; four size distributions; three chunk sizes; and five large-object
policies. Output uses one `key=value` record per configuration for mechanical
comparison. `CFL_MATRIX_ITERATIONS` and `CFL_MATRIX_RECORDS` control runtime.

The arena context is reused and reset between documents. Within one document,
the workload intentionally exposes growth from logically freed values:
individual removals do not reclaim arena storage until the next reset or
destroy.

On glibc, `heap_initial_live` and `heap_final_live` are sampled while the heap
document is still alive. Compare them with `arena_initial_used` and
`arena_used`. `max_rss_kb` is process-level high-water RSS and can remain the
same for small workloads because it is page-granular and includes executable,
library, and allocator-retained pages.
