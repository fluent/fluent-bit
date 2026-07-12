# CMetrics benchmarks

Benchmarks are opt-in and are intended for before/after comparisons on the
same machine. Build an optimized binary:

```sh
cmake -S . -B build-perf \
    -DCMT_BENCHMARKS=ON \
    -DCMT_INSTALL_TARGETS=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS_RELEASE='-O3 -DNDEBUG'
cmake --build build-perf -j --target cmt-benchmark
```

Run the standard repeated workloads and Linux hardware counters:

```sh
REPETITIONS=5 benchmarks/run-perf.sh \
    ./build-perf/benchmarks/cmt-benchmark
```

The executable also accepts individual workloads:

```text
cmt-benchmark lookup|update|prometheus|opentelemetry|opentelemetry-mixed CARDINALITY OPERATIONS
```

The `opentelemetry` workload repeatedly encodes a labeled counter with the
requested number of series. The `opentelemetry-mixed` workload creates that
many counter, gauge, and histogram series to exercise scalar and aggregate
protobuf data points in the same request.

Compare medians from at least five alternating before/after runs. Keep CPU
frequency policy, compiler, flags, machine load, and input parameters fixed.
Use the reported in-process `elapsed_ns` for the operation itself and `perf
stat` for whole-process hardware counters. Whole-process counters include
series construction and teardown by design, exposing setup complexity as well
as steady-state behavior.
