Fluent Bit 5.2 allocator comparison, 2026-10-31
=============================================

results-20261031.csv contains all 72 completed native timing observations.
provenance-20261031.json pins source revisions, allocator identity, settings,
record reconciliation and the shared-host limitations. The 5.1 allocator is
jemalloc 5.3.0, not 5.2. The old archive lacks VERSION metadata; all 192 checked
source/header/template files match official upstream 5.3.0 without differences.

The two 5.2 variants use identical application objects and libraries, with
only allocator archive references changed by a diagnostic relink. All timed
processes use default runtime options, no MALLOC_CONF and no LD_PRELOAD.
This isolates allocator choice; whole-version 5.1 versus 5.2 differences also
include pipeline, concurrency, ChunkIO and encoding changes.

Interpretation
--------------
Memory is MiB (1024 squared bytes). steady_rss_mib is the median of 50ms RSS
samples over send and drain; it is not an equal-backlog equilibrium measure.
peak_rss_mib is each run's sampled peak. cooldown_rss_mib is observed ten
seconds after completed delivery. CPU includes all server threads through
delivery, excluding that subsequent idle wait. rss_gib_seconds integrates
sampled RSS through delivery. Completion counters publish about once per
second. latency_p99_us is HTTP request/acknowledgement latency, not individual
record delivery latency. Client retries are reported separately from drop
counters. Matching final counts does not independently verify each payload ID.

Compute per-cell medians across the three restarts, and retain min/max ranges.
Saturation can produce different in-flight volumes. The 500k/s memory and
100k/s filesystem controls constrain offered load. The filesystem 100k/s
control was added after observing lower RSS but higher CPU with 5.3.0 in the
initial filesystem saturation runs; the original observations are retained.

normal-build-results-20261031.csv adds 12 runs comparing full normal 5.2
builds, each with its own allocator headers and archive. These followed a
material CPU difference between the diagnostic relink and the normal rollback
build. The initial relink measured +22% CPU in paced JSON and +24% CPU in
filesystem saturation. The normal-build repeats instead measured about -3%
and +4%, respectively. Do not present the relink costs as confirmed CPU costs
of the normal rollback build. Both modes and every observation are retained.
The normal-build comparison is used for the PR's release CPU assessment.
Both 5.2 variants remain below the 5.1 baseline's CPU/M in every tested cell.
Small CPU differences on this host are not a universal allocator speed claim.
These measurements do not establish an unbounded leak or one causally
responsible upstream commit.

Reproduction
------------
The tracked benchmark driver at the pinned 5.2 revision supports the base
saturation comparison. reproduce.patch adds the exact timing-runner features
used here: fixed offered rates, idle observation, additional RSS/backlog/disk
metrics, host swap counters, and stricter completion/error checks. It contains
no production-code changes and has been checked with git apply --check.
Apply it locally to reproduce the extended matrix:

    git apply benchmarks/allocator_compare/reproduce.patch

Build the 5.1 baseline at the pinned revision with its shipped allocator.
Build 5.2 with 5.4.0 using the flags in provenance-20261031.json. For the
allocator-only control, take build/src/CMakeFiles/fluent-bit-bin.dir/link.txt,
replace every ../lib/libjemalloc_pic.a reference with the absolute path to
the baseline's libjemalloc_pic.a, and change the executable output filename.
Run that linker argv from build/src. Preserve both binaries and archive hashes.
This control is a diagnostic relink, not a standard distributable build.

Use the integration Python environment and pass these common driver options
with paths to the three binaries (FLB51_BIN, FLB52_54_BIN, FLB52_53_BIN):

    --system flb51-jemalloc53=$FLB51_BIN
    --system flb52-jemalloc54=$FLB52_54_BIN
    --system flb52-jemalloc53=$FLB52_53_BIN
    --runs 3 --warmup-records 320000 --cooldown 10
    --server-cpus 0-3 --generator-cpus 4-7,12-15

The driver is benchmarks/compare_fluent_bit_otelcol.py. Select an output prefix
per group, and add the matching options below. The payload generator, 100 logs
per request, 16 persistent clients, four HTTP workers and 0.5-second flush are
the driver's defaults. Verify CPU topology; choose different disjoint physical
cores if the given affinity sets are not available or overlap on your machine.

memory-ingest:
    --records 30000000 --pipelines ingest --encodings json,protobuf --storage memory
memory-modified:
    --records 10000000 --pipelines modified --encodings json,protobuf --storage memory
filesystem-protobuf:
    --records 10000000 --pipelines ingest --encodings protobuf --storage filesystem
memory-paced-500k:
    --records 10000000 --pipelines ingest --encodings json,protobuf --storage memory --rate 500000
filesystem-paced-100k:
    --records 3200000 --pipelines ingest --encodings protobuf --storage filesystem --rate 100000

Each cell restarts the server. System order rotates with repetition. The
modified pipeline upserts log attribute bench.added="yes" with the native
content_modifier processor. Null output validates counters, not every body.
Small timing differences on this shared powersave/boost host remain noisy.
Use a quiet, controlled host for stricter performance qualification.

Normal-build controls
---------------------
Build the pinned 5.2 base normally with jemalloc 5.4.0 and the rollback
product tree normally with 5.3.0, using identical flags. Use labels normal54
and normal53 with the two normal binaries. Run the paced JSON memory and
protobuf filesystem saturation options above with three restarts per cell.
The latter uses 10M records per run; the former uses 10M at 500k logs/s.
All other warmup, idle, affinity, worker and payload settings are unchanged.
Do not substitute the diagnostic relink for the normal 5.3.0 build here.
