# Fluent Bit benchmarking

The Linux benchmark runner compares installed binaries through local OTLP/HTTP
logs pipelines and retains evidence. The matching
[agent skill](../skills/fluent-bit-benchmark/SKILL.md) chooses experiments and
interprets results. The CLI works independently of an agent.

## Quick start

From the checkout root, with Python 3.9 or newer:

```sh
python3 benchmarks/run.py --system current=/absolute/path/to/fluent-bit \
  --output /tmp/flb-benchmark
```

JSON uses only the Python standard library. Protobuf requires `protobuf` and
`opentelemetry-proto`; the integration virtualenv supplies them:

```sh
./tests/integration/setup-venv.sh
tests/integration/.venv/bin/python benchmarks/run.py \
  --system current=/absolute/path/to/fluent-bit --encoding protobuf \
  --output /tmp/flb-protobuf
```

Defaults: three fresh processes, 100,000 measured records, 1,000 warmup records,
100 records/request, four clients, two HTTP workers, 10,000 offered records/s,
two-second cooldown, and a 180-second per-trial work deadline plus bounded
network/cleanup waits. The generated pipeline is HTTP/1 without TLS to null.
Its synthetic payload is small/uniform; use representative samples before
making deployment conclusions. The runner launches separate processes and
does not modify installed services. Duration scales with runs and systems.

## Compare versions and settings

```sh
python3 benchmarks/run.py \
  --system baseline=/opt/fluent-bit-old/bin/fluent-bit \
  --system candidate=/opt/fluent-bit-new/bin/fluent-bit \
  --rate 100000 --records 3000000 --runs 5 --output /tmp/flb-upgrade
```

The first system is the baseline. Order rotates per repetition. Use comparable
normal optimized builds; binary hashes do not establish compiler flags or
allocator identity. Record those separately when known. Debug or instrumented
builds only qualify smoke behavior, not release performance. Inherited
`MALLOC_CONF` and `LD_PRELOAD` are retained and recorded. Use the same binary
under two labels for an A/A noise control.

`--workers`, `--clients`, `--flush`, `--pipeline ingest|modified`, and
`--storage memory|filesystem` control generated configurations. Modified adds
one native log-attribute upsert. Compare configurations in separate result
directories, changing one factor at a time and interleaving repeated campaigns.

Set `--rate 0` for closed-loop saturation. At fixed rate, clients follow absolute
scheduled times but cannot issue unlimited outstanding requests; busy clients
delay later sends. Achieved offered rate below 95% of target is inconclusive.
Schedule lag does not identify whether server or generator caused the shortfall.
Finite completion throughput does not establish sustainable long-term capacity.

`--cpus 2-3` optionally pins Fluent Bit using taskset; generator and sampler remain
unpinned. Without it, affinity is inherited. This is not CPU isolation. Prefer
an idle host and dedicated physical cores for qualification. The advanced
`compare_fluent_bit_otelcol.py` driver checks disjoint server/generator cores.

## User workloads

`--payload sanitized-request.json` accepts an OTLP JSON ExportLogs request with
`resourceLogs[].scopeLogs[].logRecords`. It repeats the request unchanged,
including timestamps/IDs. Its record count replaces `--batch-records`; measured
and warmup counts must be multiples of that count. `--encoding protobuf` converts
the JSON request. Requests are limited to 16 MiB and retained as payload.bin.

`--config benchmark.yaml` uses a user-prepared config template. The process
receives BENCH_INPUT_PORT, BENCH_HTTP_PORT, and BENCH_STORAGE_PATH. Use Fluent
Bit `${BENCH_INPUT_PORT}` expansion, HTTP metrics on
`127.0.0.1:${BENCH_HTTP_PORT}`, and a local OTLP HTTP/1 listener at
`127.0.0.1:${BENCH_INPUT_PORT}`. Configure one counted input/output route and one
output record per input record. Set --input-instance/--output-instance if their
metric names differ from opentelemetry.0/null.0.

The custom config owns worker, processor, flush and storage settings; generated
config options do not override it. Intentional drops, sampling, fan-out and
rewrite duplication are outside this runner's one-to-one accounting contract.
Prepare isolated paths, bounded storage and local test destinations. Review
includes, credentials and outputs before using a deployment config: custom
outputs can contact their configured services. An output counter may mean
admission to another buffer rather than downstream delivery.

## Evidence and interpretation

The output must be a new directory. Artifacts remain for review; remove them
when finished. Sanitize payloads/configs before running or sharing.

- manifest.json: schema, arguments, binary/runner/helper/payload hashes,
  allocator overrides, platform, allowed CPUs, page size and campaign status.
- NN-system/: config, invocation with BENCH_* environment, server log,
  samples.jsonl, storage and result.json.
- results.json/results.csv: every completed trial, including failures.
- summary.json: median/min/max per system, valid and attempted counts.
- comparison.json: valid matched repetitions versus first system; descriptive
  percentage changes, with fewer than three pairs marked insufficient.
- report.md: concise human-readable results and limitations.

Negative CPU/memory percentage means less resource use; positive completion-rate
percentage means more throughput. Descriptive ranges do not prove significance.
Investigate excluded trials before concluding that one candidate improved.

Exit 0 means all trials valid; exit 2 means invalid/inconclusive results needing
review. Argument errors also exit nonzero. Interrupted campaigns retain evidence.
Missing required counters are unknown, never zero. Sampling errors make trials
inconclusive. Responses other than HTTP 200/201, partial success, count mismatches, deadlines,
unexpected exits and forced shutdowns invalidate trials. Requests are not retried,
avoiding ambiguous retry duplicates. Aggregate counts do not prove payload
identity or exactly-once delivery.

CPU seconds/million and completed records/s cover send plus drain, excluding
startup, warmup, cooldown and shutdown. A quarter-second sampler captures RSS,
CPU and counters; metrics publication can be slower. Peak RSS is sampled rather
than a guaranteed high-water mark. HTTP request p99 is acknowledgement latency,
excluding prior schedule lag, not record delivery. Generator CPU includes
monitoring overhead. Backlog is approximate accepted-minus-completed records.
RSS, arena bytes and allocated disk bytes are different measures. The runner
does not measure allocated disk bytes, TLS, durable sink delivery or leaks.

## Specialized tools

- [Tail ramp](ingestion/README.md): overload/stalls and custom Tail templates;
  fixed multiline input and different schema/route accounting.
- [Processor experiments](results/post-fts-12505/README.md): HTTP/Forward/OTLP
  modifiers, narrow/wide records and input/output placement.
- [Rewrite tags](rewrite-tag/README.md): cardinality and KEEP semantics.
- [Chunk allocation](chunk_allocation/README.md): build-tree instrumentation,
  GNU linking, disk allocation and remaps.
- [Allocator research](allocator_compare/README.txt): historical evidence and
  reproduction patches; not a universal tuning preset.
- [CFL](../lib/cfl/benchmarks/README.md): library arenas/object allocation;
  not direct pipeline throughput claims.

Keep native timing separate from Valgrind, Massif, sanitizers and profiling.
Count reconciliation does not replace semantic integration/memory-safety tests.

```sh
python3 -m unittest discover -s benchmarks/tests -v
```
