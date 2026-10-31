# Fluent Bit consumer benchmark

These results describe **current Fluent Bit**, which supplies a fixed 256 KiB
opening hint. The [planned caller-policy comparison](../caller_allocation/README.md)
separately tests append-sized creation with adaptive growth, using a storage
lifecycle model based on `flb_input_chunk.c`. That planned behavior is not yet
implemented in Fluent Bit; the fixed-hint results here are not its final design.

These Linux benchmarks run Fluent Bit's tail input, engine, routing, storage,
and null/HTTP outputs against two ChunkIO versions. The same Fluent Bit object
files are linked twice; only the ChunkIO archive differs. No Fluent Bit runtime
source or bundled dependency is changed. Both executables include the same
benchmark observer, implemented with GNU linker wrappers.

The results describe finite-file tail catch-up and recovery from an output
outage. They are not a sustained live-ingestion capacity test or a universal
throughput prediction. The null output removes network serialization cost from
the tail cases; the HTTP case includes JSON serialization and a local receiver.

## Recorded results

Fluent Bit `66910c10a` with ChunkIO PR base `027c983` versus implementation
`4a949ab`; the latter uses adaptive growth by default. These are medians of five
measured runs per version/case, after one warmup. Environment: Ryzen 9 7940HS,
Linux 7.0.0-30, ext4/NVMe, 4 KiB pages, GCC 13.3, CPU affinity 2. The full
revisions and binary hashes are in [manifest.json](manifest.json); all 60 samples,
including the 10 excluded warmups, are in [results.csv](results.csv).

CPU is whole-process user plus system time. Rate measures source MiB from first
to last tail append, excluding startup and the final output drain. Lower CPU and
higher rate are better. All percentage changes compare PR default with previous.

| Fluent Bit workload | CPU seconds: previous → PR | CPU change | Tail MiB/s: previous → PR | Rate change |
| --- | ---: | ---: | ---: | ---: |
| Tail catch-up, FS, CRC off | 1.163 → 0.946 | -18.7% | 114.2 → 128.8 | +12.8% |
| Tail catch-up, FS, CRC on | 1.252 → 0.972 | -22.3% | 110.1 → 125.0 | +13.6% |
| 1,000 low-volume tags, FS | 0.352 → 0.365 | +3.9% | 87.8 → 85.4 | -2.7% |
| HTTP outage/recovery, FS, CRC on | 1.263 → 1.204 | -4.7% | 55.9 → 58.8 | +5.2% |
| Tail catch-up, memory | 0.942 → 0.957 | +1.6% | 129.0 → 127.5 | -1.1% |

The large filesystem cases show 18.7–22.3% lower CPU and 12.8–13.6% higher
observed tail ingestion rate. The many-tag case costs 3.9% more CPU and allocates
7.11 times as much disk space (35.16 → 250 MiB). Memory storage shows no clear
benefit: its small differences overlap the observed run ranges.

| Fluent Bit workload | Peak RSS MiB: previous → PR | Peak allocated disk MiB: previous → PR | Native remap calls: previous → PR |
| --- | ---: | ---: | ---: |
| Tail catch-up, FS, CRC off | 138.4 → 148.5 | 127.66 → 144.40 | 7,874 → 1,105 |
| Tail catch-up, FS, CRC on | 133.2 → 148.6 | 122.30 → 144.40 | 7,874 → 1,105 |
| 1,000 low-volume tags, FS | 75.2 → 78.6 | 35.16 → 250.00 | 1,000 → 0 |
| HTTP outage/recovery, FS, CRC on | 43.5 → 43.6 | 68.27 → 71.32 | 1,969 → 276 |
| Tail catch-up, memory | 148.7 → 149.9 | 0.00 → 0.00 | 0 → 0 |

Resource figures are medians of per-run observed peaks. Faster ingestion can
retain more data between flushes, so the higher peaks in the large-file cases
include occupancy/timing effects as well as allocation headroom. For the many-tag
case, both versions hold the same 1,000 files: the previous implementation reserves
36 KiB per chunk, while the PR honors Fluent Bit's 256 KiB opening hint. No adaptive
remap occurs in that PR case. RSS does not increase in proportion to disk capacity.

All 50 measured runs and 10 warmups passed exact input/output count checks and
reported no dropped records or exhausted retries. Each HTTP run delivered all
250,000 unique records with their complete payloads intact, after actual down
chunks and failed output attempts were observed. This exercises output recovery;
it is not a crash/power-loss durability test.

| Workload | CPU seconds range: previous / PR | Tail MiB/s range: previous / PR |
| --- | --- | --- |
| Tail catch-up, FS, CRC off | 1.140–1.194 / 0.912–0.973 | 110.9–116.0 / 125.8–130.3 |
| Tail catch-up, FS, CRC on | 1.247–1.264 / 0.954–0.996 | 109.5–110.4 / 120.9–126.8 |
| 1,000 low-volume tags, FS | 0.343–0.356 / 0.356–0.379 | 87.4–92.4 / 83.1–88.0 |
| HTTP outage/recovery, FS, CRC on | 1.252–1.291 / 1.182–1.226 | 55.3–56.9 / 57.1–59.4 |
| Tail catch-up, memory | 0.914–0.955 / 0.931–0.980 | 127.7–130.6 / 124.1–129.1 |

These ranges describe the five observations; they are not confidence intervals.

## Scenarios

Every source record is a 255-byte line plus newline, with a unique numeric ID.
Tail uses its default 32 KiB read buffer and 50 MB static batch limit, without a
parser, multiline processing, filters, or a position database. `Tag bench.*`
produces a separate tag for each source file. Fluent Bit supplies its unchanged
256 KiB opening hint. Flush is one second, filesystem sync is normal, and output
storage byte limits are unlimited.

| Name | Source data | Storage and output |
| --- | --- | --- |
| steady_fs | One file, 1,000,000 records (244.14 MiB) | Filesystem, checksum off, null |
| steady_crc | Same | Filesystem, checksum on, null |
| many_tags | 1,000 files, 64 records each (15.625 MiB total) | Filesystem, checksum off, null |
| backpressure | One file, 250,000 records (61.04 MiB) | Filesystem, checksum on, HTTP |
| memory | One file, 1,000,000 records | Memory, null |

The `steady_*` identifiers mean the finite-file catch-up cases above, not a
rate-controlled live source. The normal filesystem cases use
`storage.max_chunks_up=128`; backpressure uses 8. The HTTP receiver returns 503
until three seconds after all records have entered the pipeline, then 200.
Retries are unlimited, with scheduler base 1 and cap 2. The receiver checks every
accepted ID and complete log payload and rejects duplicates or missing records.
Down chunks must actually be observed in the backpressure scenario. All cases
require exact input/output record counters and zero dropped records or exhausted
retries. The null cases validate counts, not output payload contents.

## Measurements and limits

`results.csv` contains every warmup and measured sample. Exclude labels containing
`warmup` when calculating medians. Run one warmup and five measured repetitions
per case/version, alternating version order on successive pairs.

- `ingest_seconds`: monotonic time immediately before the first tail append to
  immediately after the last successful tail append. This includes subsequent
  tail reads, encoding, engine scheduling, and storage work. It excludes startup,
  the first read/encoding batch, and the final output drain.
- `ingest_mib_per_second`: source bytes divided by that interval. Flush and tail
  scheduling affect this rate; it is not maximum sustainable output throughput.
- `cpu_seconds`: process user plus system CPU over the whole run, including
  initialization, output drain, metrics serving, and graceful shutdown. CPU time
  of the external runner and HTTP receiver is excluded.
- `max_rss_kib`: process lifetime peak RSS from `getrusage`, in KiB on Linux.
- `peak_file_bytes` and `peak_allocated_bytes`: sampled sum of file lengths and
  `st_blocks * 512` in the ChunkIO storage directory. They exclude input files,
  directory metadata, and filesystem journal writes. Sampling is approximately
  every 20 ms, but HTTP polling and directory scans can lengthen the interval;
  these are observed peaks, not guaranteed maxima or bytes physically written.
- `remaps`, `resizes`, `maps`: calls across the corresponding native ChunkIO
  function boundaries, observed with identical wrappers in both binaries.
- `observed_completion_seconds`: process start to observing the final output
  counters. HTTP metrics are polled every 100 ms but are internally refreshed
  less frequently. This metric is too coarse for small performance claims.
- `recovery_seconds`: receiver release to observed completion. Retry timers and
  metrics refresh make this unsuitable for small latency comparisons.

The observer timestamps only the first/final append. It counts native allocation
operations and tail batches, without interpreting ChunkIO metadata. Tail is not
threaded in these configurations. The benchmark runs with a single CPU affinity,
raises the file descriptor soft limit to at least 8,192, warms the input page
cache, does not evict caches, and does not disable CPU boost. The host is not
isolated. Inspect all samples and report variation alongside medians.

Storage quota integration remains a separate requirement: Fluent Bit currently
predicts fixed allocation growth. It must use the new projection API or explicitly
select fixed growth before adopting this ChunkIO version with output byte limits.
These unlimited-quota runs do not validate that integration. They also do not
validate crash recovery, power-loss durability, or non-Linux performance.

## Reproduce

Use a clean Fluent Bit checkout at the revision recorded in `manifest.json` and
separate baseline/PR ChunkIO checkouts. Keep all builds and generated data outside
the repositories. The following names are placeholders for absolute paths:
`FLB_SOURCE`, `FLB_BUILD`, `CIO_BASE`, `CIO_HEAD`, `BASE_BUILD`, `HEAD_BUILD`,
`BENCH_ROOT`, and `HARNESS` (this directory).

In the isolated Fluent Bit source checkout, change only CMake wiring:

1. Replace `add_subdirectory(${FLB_PATH_LIB_CHUNKIO} EXCLUDE_FROM_ALL)` in
   `CMakeLists.txt` with
   `add_subdirectory(${CIO_BENCH_SOURCE} ${CMAKE_BINARY_DIR}/lib/chunkio EXCLUDE_FROM_ALL)`.
2. Replace `${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CHUNKIO}/include` in
   `cmake/headers.cmake` with `${CIO_BENCH_SOURCE}/include`.

Configure and build the common objects:

```sh
cmake -S "$FLB_SOURCE" -B "$FLB_BUILD" \
  -DCIO_BENCH_SOURCE="$CIO_BASE" -DFLB_RELEASE=On -DFLB_IPO=Off \
  -DFLB_MINIMAL=On -DFLB_KAFKA=Off -DFLB_SQLDB=On \
  -DFLB_IN_TAIL=On -DFLB_IN_STORAGE_BACKLOG=On -DFLB_IN_DUMMY=On \
  -DFLB_OUT_NULL=On -DFLB_OUT_HTTP=On -DFLB_OUT_FILE=On \
  -DFLB_HTTP_SERVER=On -DFLB_SHARED_LIB=Off \
  -DFLB_TESTS_RUNTIME=Off -DFLB_TESTS_INTERNAL=Off -DFLB_EXAMPLES=Off \
  -DFLB_WASM=Off -DFLB_WAMRC=Off -DFLB_LUAJIT=Off
cmake --build "$FLB_BUILD" -j8
cmake -S "$CIO_BASE" -B "$BASE_BUILD" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BASE_BUILD" -j8
cmake -S "$CIO_HEAD" -B "$HEAD_BUILD" -DCMAKE_BUILD_TYPE=Release
cmake --build "$HEAD_BUILD" -j8
python3 "$HARNESS/link.py" --build "$FLB_BUILD" \
  --base-library "$BASE_BUILD/src/libchunkio-static.a" \
  --head-library "$HEAD_BUILD/src/libchunkio-static.a" \
  --output "$BENCH_ROOT/bin"
export CIO_FLB_BENCH_ROOT="$BENCH_ROOT"
export CIO_FLB_BENCH_CPU=2
python3 "$HARNESS/batch.py"
```

Check the generated compile flags: Fluent Bit requires `FLB_RELEASE=On`, not
merely `CMAKE_BUILD_TYPE=Release`. The recorded run used Fluent Bit `-O2 -g
-DNDEBUG`, both ChunkIO archives `-O3 -DNDEBUG`, and a common CRC library from the
Fluent Bit build. Do not run Python with `-O`, which disables validation asserts.
The harness saves configurations, logs, counters, and results under `runs/`, plus
all results in `raw.json`. It refuses to reuse an existing run directory. Use a
fresh output directory for each full batch.
