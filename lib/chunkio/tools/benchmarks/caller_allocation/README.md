# Planned Fluent Bit caller allocation policy

This is a **ChunkIO caller simulation**, not a modified Fluent Bit executable.
It evaluates the planned integration before changing Fluent Bit: create a chunk
for the encoded append that caused its creation, reuse eligible matching chunks,
and delegate subsequent physical growth to ChunkIO. There is no traffic forecast,
per-tag sizing history, hot/cold allocation branch, or allocator modification.

The three comparisons use identical workloads and caller code:

| Variant | ChunkIO | Opening hint | Subsequent growth |
| --- | --- | --- | --- |
| Previous | PR base `027c983` | 256 KiB, ignored by that filesystem implementation | Previous fixed growth |
| PR fixed 256K hint | PR allocator `4a949ab` | 256 KiB, current Fluent Bit behavior | Default adaptive growth |
| PR append-sized hint | Same PR allocator | Header + metadata + current encoded append | Default adaptive growth |

**“Fixed hint” does not mean `CIO_FIXED_GROWTH`.** Both PR variants run the same
adaptive allocator. The planned policy has not been implemented in Fluent Bit.
The [real Fluent Bit pipeline benchmark](../fluent_bit/README.md) measures the
current fixed-hint integration; its CPU figures are not interchangeable with
this simulation's CPU figures.

## Results

Linux 7.0.0-30, Ryzen 9 7940HS, ext4/NVMe, 4 KiB pages, GCC 13.3, CPU affinity 2.
Medians of nine measurements per cell after one warmup. All 189 measured runs,
21 warmups, and 21 allocation diagnostic runs verified their complete content and
metadata. The same append/chunk/record counts were required across all variants.
Raw timed samples are in [results.csv](results.csv); source/library/binary hashes
and commands are in [manifest.json](manifest.json).

**Append-sized creation removes the 256 KiB sparse-tag reservation penalty while
retaining most of the adaptive-growth benefit for busy chunks.** It does not
eliminate growth headroom or make small starts as cheap as large reservations.
These are caller-model measurements, not Fluent Bit end-to-end CPU savings.

| Workload / metric | Previous | PR fixed 256K hint | PR append-sized hint |
| --- | ---: | ---: | ---: |
| Sparse: CPU ms | 107.62 | 122.12 | 91.30 |
| Sparse: allocated disk MiB | 35.16 | 250.00 | 19.53 |
| Sparse: allocation amplification | 2.250 | 16.000 | 1.250 |
| Sparse: remaps | 1,000 | 0 | 0 |
| Sparse, separate records: CPU ms | 114.42 | 129.00 | 114.61 |
| Sparse, separate records: allocated disk MiB | 35.16 | 250.00 | 35.16 |
| Sparse, separate records: allocation amplification | 2.250 | 16.000 | 2.250 |
| Sparse, separate records: remaps | 1,000 | 0 | 1,000 |
| Busy: CPU ms | 181.09 | 96.33 | 105.55 |
| Busy: allocated disk MiB | 64.73 | 67.69 | 66.40 |
| Busy: allocation amplification | 1.011 | 1.058 | 1.038 |
| Busy: remaps | 2,063 | 262 | 427 |
| Mixed: CPU ms | 316.70 | 226.38 | 206.23 |
| Mixed: allocated disk MiB | 99.97 | 318.12 | 86.28 |
| Mixed: allocation amplification | 1.255 | 3.995 | 1.084 |
| Mixed: remaps | 3,064 | 256 | 456 |
| Large first append: CPU ms | 115.16 | 117.38 | 114.01 |
| Large first append: allocated disk MiB | 64.25 | 72.00 | 64.25 |
| Large first append: allocation amplification | 1.004 | 1.125 | 1.004 |
| Large first append: remaps | 64 | 64 | 0 |
| Reopen: CPU ms | 22.79 | 12.09 | 13.18 |
| Reopen: allocated disk MiB | 8.10 | 8.52 | 8.34 |
| Reopen: allocation amplification | 1.013 | 1.064 | 1.043 |
| Reopen: remaps | 258 | 32 | 57 |
| Busy, CRC off: CPU ms | 140.80 | 56.83 | 65.93 |
| Busy, CRC off: allocated disk MiB | 64.73 | 67.69 | 66.40 |
| Busy, CRC off: allocation amplification | 1.011 | 1.058 | 1.038 |
| Busy, CRC off: remaps | 2,063 | 262 | 427 |

The allocated-disk rows are median retained allocations from the timed runs. The
separate diagnostic pass measured peak retained allocation at the same footprint
for these workloads (see `allocations.json`; a few KiB of extent allocation can
vary between runs). Amplification divides allocated disk by logical content bytes.

- With one known 16 KiB append per sparse tag, append-sized allocation reserves
  20 KiB per file after page rounding: 19.53 MiB total, versus 250 MiB for the fixed
  hint. No growth/remap is needed. CPU is 25.2% lower than the PR fixed-hint case.
- With 64 separate 256-byte appends, the same policy starts at 4 KiB and grows
  once to 36 KiB per file. This preserves the previous 35.16 MiB footprint, rather
  than anticipating the eventual 16 KiB total. The caller never forecasts traffic.
- Busy chunks start at 4 KiB and reuse their mappings through 65,536 appends and
  normal soft-threshold rollovers. The append-sized variant performs 427 remaps,
  versus 262 with the large hint and 2,063 previously: 79.3% fewer than previous,
  preserving 90.8% of the fixed-hint variant's reduction. Its CPU is 9.6% higher
  than PR fixed-hint, but 41.7% below previous, retaining about 89% of the CPU savings.
- Mixed traffic uses one policy for all tags: 86.28 MiB allocated versus 318.12 MiB
  with the fixed hint, with lower aggregate CPU despite extra hot-chunk remaps.
- A known 1 MiB first append reserves 1,028 KiB, including header/metadata/page
  rounding, and needs zero remaps. This behavior differs from always passing zero.
- Reopen checks retained capacity with unrelated small/large hints and continued
  writes successfully in all three variants. Capacity is determined by the existing
  nonempty file, not the replacement hint.

| Workload | Previous initial → final KiB/chunk | PR fixed hint initial → final | PR append-sized initial → final |
| --- | ---: | ---: | ---: |
| Sparse | 4 → 36 | 256 → 256 | 20 → 20 |
| Sparse, separate records | 4 → 36 | 256 → 256 | 4 → 36 |
| Busy | 4 → 1508–2020 | 256 → 1600–2112 | 4 → 1560–2072 |
| Mixed | 4 → 36–2020 | 256 → 256–2112 | 4–20 → 20–2072 |
| Large first append | 4 → 1028 | 256 → 1152 | 1028 → 1028 |
| Reopen | 4 → 196–2020 | 256 → 256–2112 | 4 → 236–2072 |
| Busy, CRC off | 4 → 1508–2020 | 256 → 1600–2112 | 4 → 1560–2072 |

Ranges above describe different chunks within the workload, including partially
filled final chunks. [allocations.json](allocations.json) records the counts at
each initial/final capacity, logical size, allocation, and append count.

| Workload | Logical MiB | Chunks | Appends | Records | Metadata bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Sparse | 15.625 | 1,000 | 1,000 | 64,000 | 64,000 |
| Sparse, separate records | 15.625 | 1,000 | 64,000 | 64,000 | 64,000 |
| Busy | 64 | 33 | 65,536 | 262,144 | 2,112 |
| Mixed | 79.625 | 1,040 | 66,536 | 326,144 | 66,560 |
| Large first append | 64 | 64 | 64 | 262,144 | 4,096 |
| Reopen | 8 | 5 | 8,192 | 32,768 | 320 |
| Busy, CRC off | 64 | 33 | 65,536 | 262,144 | 2,112 |

| Workload | Previous CPU ms range | PR fixed hint | PR append-sized |
| --- | ---: | ---: | ---: |
| Sparse | 107.07–116.24 | 121.70–127.30 | 90.35–104.19 |
| Sparse, separate records | 113.58–121.68 | 127.95–130.34 | 113.67–115.80 |
| Busy | 175.98–184.73 | 95.50–97.97 | 103.96–109.20 |
| Mixed | 314.42–318.18 | 224.12–230.92 | 201.16–208.37 |
| Large first append | 114.33–117.62 | 116.26–119.78 | 113.88–114.68 |
| Reopen | 22.38–23.76 | 11.93–12.47 | 13.02–13.41 |
| Busy, CRC off | 139.38–160.79 | 56.58–57.80 | 65.09–68.38 |

Ranges are the observed minimum and maximum CPU times over nine runs, not
confidence intervals. The small CPU difference between previous and append-sized
creation for separate-record sparse traffic overlaps these ranges.


## Relationship to flb_input_chunk.c

The reference is Fluent Bit [`66910c10a`](https://github.com/fluent/fluent-bit/blob/66910c10a4d7eafa810b84229cf2dcf7b0f26f97/src/flb_input_chunk.c).
The corresponding logic in the dirty sibling checkout was also inspected; its
local chunk-name formatting change does not change these decisions.

| Fluent Bit path | Behavior retained in the model |
| --- | --- |
| `input_chunk_get()` | Select the latest chunk for the same tag and event type. Reject busy/locked chunks; current physical capacity is not an eligibility check. Force a down chunk up for writing. |
| `flb_input_chunk_create()` | Open a new filesystem chunk and write opaque metadata. Force deferred creation up for metadata, then restore down state. The one planned change is deriving the opening hint from the current append. |
| `flb_input_chunk_write()` | Call `cio_chunk_write()` with the complete append and let ChunkIO grow the mapping. |
| `input_chunk_append_raw()` | After a successful append, lock when content **exceeds** 2,048,000 bytes. Restore a previously down chunk after the write. |
| `flb_input_chunk_flush()` | Lock before obtaining a content pointer for verification/drain. Already locked chunks remain locked. |

The threshold is **soft and checked after append**, as in Fluent Bit. A chunk
exactly at the threshold can accept another append, then locks. A first append
larger than the threshold is stored whole and locks immediately. The harness does
not introduce a strict pre-append fit check or split an encoded append. This is
why 64 MiB written in 1 KiB appends produces 33 chunks, with 2,001 appends in each
full chunk, rather than a new chunk whenever the initial mapping fills.

A key represents one `(tag, event type)` pair within a single input instance.
The array lookup substitutes for Fluent Bit's event-specific tag hash tables;
all timed workloads use one event type. Tests exercise independent keys for the
same tag/different type and for different tags, plus busy/locked replacement.
Offsets and byte counters exist only for content verification, never for choosing
an opening hint. The shared model is [tests/cio_test_caller.h](../../../tests/cio_test_caller.h).

The simulation has no changing filters/processors, so `buf_size` at selection is
the same as `final_data_size` passed to the writer. It omits routing decisions,
output byte quotas, tasks/retries, real-time flush scheduling, encoding, and hash
lookup costs. It is not a complete Fluent Bit integration or quota-accounting
test. Actual filter expansion can require growth after creation; the opening
hint remains advisory. These omissions are deliberate scope boundaries, not
claims that the subsystems are unnecessary.

## Workloads

Records are deterministic 256-byte **synthetic encoded records**, with a unique
key/sequence ID and a verifiable byte pattern. They are not real MessagePack
records and no Fluent Bit serialization is timed. Metadata is 64 opaque bytes
per chunk, including embedded NUL bytes; ChunkIO interprets none of it as tags
or routes. Filesystem opening hints include `CIO_FILE_HEADER_MIN` (24 bytes),
metadata, and the immediate append. The caller does not page-round the hint.

- **Sparse:** 1,000 tags, each receiving one 16 KiB append representing 64 records.
- **Sparse, separate records:** the same records/tags, arriving as 64 separate
  256-byte appends per tag. The hint knows only the first record, not the eventual
  16 KiB total. This guards against presenting full-tag presizing as append sizing.
- **Busy:** one tag, 64 MiB total, 1 KiB appends starting with the first write.
  Every later chunk also starts with the 1 KiB append that created it.
- **Mixed:** 1,000 sparse tags as above plus eight tags receiving 8 MiB each in
  1 KiB appends, interleaved round-robin. Every tag uses the same allocation rule.
- **Large first append:** 64 tags receiving a 1 MiB append each. This distinguishes
  sizing for known demand from always opening at zero/minimum capacity.
- **Reopen:** one tag, 8 MiB total, 1 KiB appends. After the eighth append in every
  chunk, down/up, close without deletion, reopen using an unrelated hint (1 byte
  or 8 MiB), verify unchanged capacity/content/metadata, and continue appending.
- **Busy, checksum off:** repeat the busy workload without checksums. All other
  workloads have checksums enabled.

All chunks are retained until a final drain to expose concurrent disk occupancy.
`max_chunks_up=4096` avoids conflating allocation policy with mapped-chunk limits;
the unit tests separately exercise deferred creation and down-state restoration.
Trimming and full sync are off; normal sync is used. Every retained chunk is
verified, locked/synced, moved down/up, verified again, and deleted at drain.

## Measurements

- CPU/elapsed time includes chunk creation, metadata, appends, threshold locks,
  explicit reopens, final verification/down/up, and chunk close/delete. Payload
  generation, context setup, and final directory cleanup are outside the timer.
  Ingestion-only CPU/elapsed time is also recorded in `results.csv`.
- Native remaps count calls to `cio_file_native_remap`; initial-write remaps are
  recorded separately. Resize calls and successful native size increases of
  existing files are also counted. These are boundary-call counts, not promises
  of a one-to-one mapping between a remap and a growth operation.
- Initial capacity is measured after opening/mapping and before metadata/write.
  Final capacity is the retained mapped file length, distinct from `st_blocks`.
- Allocated disk bytes are `st_blocks * 512`. The timed runs measure retained
  allocation at drain. An additional **untimed diagnostic run** per variant/case
  samples the changed file after every append and again during drain to capture
  peak retained allocation without charging those extra stat calls to CPU results.
  It does not sample transient states within a syscall or filesystem journal use.
- Amplification is allocated disk bytes divided by logical content bytes.
  Logical bytes exclude the file header and metadata. Both metadata totals and
  initial/final capacity totals/minima/maxima are recorded. Per-chunk capacity
  distributions, separated into traffic classes for mixed traffic, are in
  `allocations.json`; the traffic classes are reporting labels only.
- Every record byte and all metadata are checked before and after down/up. Per-key
  totals and identical append/chunk/record counts across all three policies are
  required. A failed check aborts the run; the benchmark must not use `-DNDEBUG`.

One warmup and nine measured repetitions per case/variant, rotating the three
variants between repetitions. Cases have a fixed order. CPU affinity is one
logical core; input payloads are generated before timing, caches are not evicted,
CPU boost is enabled, and the host is not isolated. The descriptor soft limit is
raised to at least 8,192. Reported ranges are observations, not confidence intervals.

## Regression tests and failures

`caller_allocation.c` is registered in CTest on all filesystem builds. It uses the
same caller model as the benchmark and checks checksum on/off, page boundaries,
large first appends, exact/crossed soft thresholds, oversized appends, independent
tag/event keys, busy/locked chunks, deferred creation, down-chunk reuse, reopening
with smaller/larger hints, and subsequent writes.

On Linux/GNU-compatible linkers it additionally injects initial reservation and
mapping failures for append-sized hints, a persistent allocation limit that
rejects the first write, and later remap failures. It verifies minimum-size
fallback, unchanged content length and metadata on failure, persisted state after
down/up, and successful retries. Fault-injection timings are not performance data.
Other platforms run the portable correctness cases without those linker wrappers.
Existing allocation tests continue to cover transaction rollback, metadata-size
changes, read-only/corrupt files, truncation, and projection accounting.

Local checks passed all eight CTest suites with GCC and with Clang ASan/UBSan
(the legacy Acutest callback function-type check is excluded). The new suite also
passed strict Valgrind with zero errors and no leaks. Compiling the opening-hint
regression test against the previous library fails its capacity assertions, as
expected, confirming that the test detects the behavior this PR changes.

## Reproduce

Build the baseline and PR libraries separately in Release mode. From the ChunkIO
PR checkout, with `CIO_BASE` pointing at a detached checkout of `027c983`:

```sh
cmake -S "$CIO_BASE" -B /tmp/cio-caller-base -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/cio-caller-base -j8
cmake -S . -B /tmp/cio-caller-head -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/cio-caller-head -j8
python3 tools/benchmarks/caller_allocation/run.py \
  --base-source "$CIO_BASE" --base-build /tmp/cio-caller-base \
  --head-build /tmp/cio-caller-head --output /tmp/cio-caller-results
python3 tools/benchmarks/caller_allocation/report.py /tmp/cio-caller-results
```

The output directory must not already exist. Linux, GNU-compatible linker
wrappers, `taskset`, `findmnt`, and Python 3 are required. `--cpu` selects the core;
`--runs` defaults to nine. `TMPDIR` selects the filesystem for chunk files. The
script compiles the same model against each version's headers/static archives
with `-O3`, keeping assertions enabled, then saves raw samples, capacity
histograms, source/library hashes, revisions, and build commands. Both library
archives in the recorded comparison use `-O3 -DNDEBUG`.

Run the correctness tests separately:

```sh
cmake -S . -B /tmp/cio-caller-tests -DCIO_TESTS=On -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/cio-caller-tests -j8
ctest --test-dir /tmp/cio-caller-tests --output-on-failure
```
