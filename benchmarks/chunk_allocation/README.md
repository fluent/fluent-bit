# Fluent Bit chunk allocation integration

This benchmark compares the Fluent Bit integration at PR #12699's original head
(`ec8e4fa66024c607c8419756831ab282b9f26db9`) with the changes in
`109b70447`. Both use the same bundled ChunkIO v1.5.5. The comparison measures
Fluent Bit's allocation policy and projection integration, rather than another
ChunkIO upgrade or the standalone caller simulation.

The integration uses ChunkIO's public capacity projection, opens new filesystem
chunks with the known append plus headers and metadata, and places filtered data
using its final size. Log chunks start with metadata alone when filters are
configured, since the filters can shrink or drop the incoming append. Memory
opening hints, chunk reuse, and the soft 2,048,000-byte rollover stay unchanged.

## Measurements

| Workload | CPU seconds, before → after | CPU change | Ingestion MiB/s, before → after | Peak allocated MiB, before → after | Remaps, before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1,000 sparse tags, FS | 0.356 → 0.321 | -9.8% | 92.30 → 108.08 | 250.00 → 19.53 | 0 → 0 |
| Busy FS, checksum off | 0.996 → 1.002 | +0.6% | 126.32 → 126.29 | 144.15 → 140.55 | 1105 → 1523 |
| Busy FS, checksum on | 1.011 → 1.032 | +2.1% | 123.94 → 121.86 | 146.21 → 140.55 | 1105 → 1523 |
| Memory control | 0.925 → 0.938 | +1.4% | 131.10 → 129.91 | 0.00 → 0.00 | 0 → 0 |

| CPU range across three measurements | Before, seconds | After, seconds |
| --- | ---: | ---: |
| 1,000 sparse tags, FS | 0.350–0.359 | 0.320–0.327 |
| Busy FS, checksum off | 0.949–1.004 | 1.001–1.006 |
| Busy FS, checksum on | 0.997–1.018 | 1.019–1.035 |
| Memory control | 0.922–0.966 | 0.926–0.974 |

The sparse-tag workload uses **92.2% less disk allocation** and **9.8% less median
CPU**. Busy filesystem chunks require 1,523 remaps versus 1,105 (+37.8%) from their
smaller initial reservations. The checksum-on workload uses 2.1% more CPU with 1.7%
lower observed ingestion rate. CPU ranges overlap for the checksum-off and memory cases.
These runs do not establish a general CPU or throughput improvement. The demonstrated
value is sparse-tag allocation efficiency and correct quota admission; the new
regression tests establish the latter.

## Method and limits

The existing ChunkIO Fluent Bit pipeline harness runs real tail input, storage,
routing, and null output. Each source record is 256 bytes. The many-tag case uses
1,000 files with 64 records each; the busy filesystem, checksum, and memory cases
each use one file with 1,000,000 records (244.14 MiB). It checks exact input/output
record counts and zero dropped records or exhausted retries in every run.

Each case/version has one excluded warmup and three measured repetitions. Version
order alternates between repetitions. The report uses medians and retains ranges
and every sample. GNU linker wrappers count allocation operations and record the
first/final tail append; both binaries have identical instrumentation. The harness
is read from `lib/chunkio/tools/benchmarks/fluent_bit` without changing bundled
library files.

Recorded host: Linux x86-64, AMD Ryzen 9 7940HS, ext4/NVMe, 4 KiB pages,
GCC 13.3.0. Both builds use the same full plugin configuration and effective
`-O2 -g -DNDEBUG` Fluent Bit flags without LTO. The process is pinned to CPU 2;
input files are warm in cache. Builds and tests finish before timing starts.
CPU boost remains enabled and the host is not isolated.

CPU means whole-process user plus system time, including initialization and
shutdown. Ingestion rate covers first through final tail append and excludes
startup and final drain. Disk allocation is the observed peak sum of
`st_blocks * 512`, sampled by the runner, rather than total I/O or a guaranteed
peak. RSS is process peak RSS. Null-output cases validate counts, not payload
contents. These short catch-up measurements do not establish sustained live
throughput, crash durability, or Windows/macOS performance. Small CPU/rate
changes with overlapping ranges should not be treated as a reliable speedup.

## Reproduce

Build the original PR head and the integration revision in separate source trees
with identical CMake options, including `-DFLB_RELEASE=On -DFLB_IPO=Off`.
Keep the benchmark driver in the updated checkout and point it at each build:

```sh
python3 benchmarks/chunk_allocation/run.py \
  --output /tmp/flb-chunk-allocation \
  --link-build /tmp/flb-base-build --variant base
python3 benchmarks/chunk_allocation/run.py \
  --output /tmp/flb-chunk-allocation \
  --link-build /tmp/flb-head-build --variant head
python3 benchmarks/chunk_allocation/run.py \
  --output /tmp/flb-chunk-allocation --measure --cpu 2 --repeats 3
```

The runner preserves binaries and build metadata under the output directory;
existing measurement directories are refused. It requires Linux, `taskset`, a C
compiler, and Fluent Bit builds with tail/null/HTTP server support. Use a fresh
output directory for a new measurement batch. Choose an available CPU if CPU 2
is outside the host's affinity mask. The committed `samples.csv` and `manifest.json` record this run's evidence.
The runner also retains complete `samples.json` and `summary.json` externally.

## Verification

The seven new allocation/quota regressions all fail against the original PR
binary and pass with the integration. They cover small and large initial
appends, filter expansion, shrinking and dropping, and adaptive growth of an
already-accounted chunk.

The final verification commands were:

```sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
ctest --test-dir build \
  -R 'flb-(it-(input_chunk|input_chunk_routes|storage_inherit|storage_dlq|engine_adaptive_flush|engine_dispatch|fstore|router|router_config|task_map|thread_storage)|rt-(in_storage_backlog|filter_rewrite_tag|filter_multiline))$' \
  --output-on-failure
tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/storage/tests \
  tests/integration/scenarios/in_storage_backlog/tests -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/storage/tests \
  tests/integration/scenarios/in_storage_backlog/tests -q
```

Results: 14/14 CTest tests passed; 32 integration cases passed normally;
30 passed under strict Valgrind with two intentional SIGKILL cases skipped.
SIGKILL prevents a final memory-checker summary; both cases passed normally.
The strict run reported no memory errors or leaks. Coverage includes fan-out,
down chunks, trace replay/corruption, backlog eviction and hot reload, alongside
rewrite-tag and multiline runtime coverage.
