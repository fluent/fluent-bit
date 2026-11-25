# Processor fusion after FTS

These measurements compare post-FTS master
`05048e35d7106890006b7b593531bd51a16dfc93` with the reviewed raw-segment
fusion and live-record counting changes. The candidate also contains the
independent SQL envelope fix from PR #12506; these benchmark pipelines do
not invoke SQL.

Both binaries use verified `-O3 -DNDEBUG` flags. Runs use Linux CPU 7,
fresh processes in alternating order, four clients, 1,000 records per batch,
10,000 warmup records, and null output. The host was shared. The confirmation
campaign ran after the competing benchmark and integration tests finished;
the CPU was not reserved.

## Confirmation

Each row contains five baseline/candidate pairs. Narrow runs measure 800,000
records; wide runs measure 200,000. CPU values are median seconds per million
records, and throughput changes compare median completed-record rates.

| Fields | Upserts | Master CPU | Candidate CPU | CPU reduction | Throughput change |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 12 | 0 | 0.8375 | 0.8250 | 1.5% | +0.1% |
| 12 | 6 | 3.7375 | 3.1500 | 15.7% | approximately 0% |
| 128 | 0 | 7.0000 | 6.8000 | 2.9% | -0.1% |
| 128 | 6 | 26.3000 | 21.2000 | 19.4% | +20.0% |

Compatible plain-log fusion remains useful after FTS. CPU savings do not
always increase throughput because ingestion and flush timing can limit it.
These are workload-specific results, not general release performance claims.

## Other workloads and limits

The initial campaign contains 20 workload/width combinations with three pairs
each, covering Forward, HTTP, grouped OTLP JSON/protobuf, input/output
placement, one/six upserts, ingestion controls and a CFL-only hash tail.
Six-upsert HTTP CPU reductions were 19.7% / 28.4% for 12 / 128 fields;
Forward output-side reductions were 27.9% / 15.0%.

Mixed Forward chains improved CPU by only 1.2% / 1.8%; no meaningful
mixed-chain speedup is claimed. Grouped OTLP declines raw fusion and measures
the live-record counting change instead. A resource group kept whole can
prevent the windowed path from splitting a batch. Initial ingestion controls
varied by about +/-6%, so not every observed grouped-fallback change can be
attributed to this patch. No general fallback speedup is claimed.

Peak RSS is recorded, but varies with queued input and flush timing; no
memory-saving claim is made. Stress tests and Memcheck are not race-detector
proofs.

All 160 runs delivered exactly 44 million measured records, plus 1.6 million
warmup records. Per-run CSVs retain output counts, payload/binary hashes,
CPU, elapsed time and peak RSS. `summary.csv` contains derived medians;
`manifest.json` records the base, machine and original invocation arguments.

## Reproduce

Configure both revisions with:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DFLB_DEBUG=Off \
  -DFLB_RELEASE=Off -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8 --target fluent-bit-bin
```

Then run, substituting the two binaries:

```sh
python benchmarks/pipeline_compare.py --baseline /path/to/master/fluent-bit \
  --candidate build/bin/fluent-bit --input forward --fields 12 --modifiers 6 \
  --records 800000 --runs 5 --cpu 7 --output narrow.csv
python benchmarks/pipeline_compare.py --baseline /path/to/master/fluent-bit \
  --candidate build/bin/fluent-bit --input forward --fields 128 --modifiers 6 \
  --records 200000 --runs 5 --cpu 7 --output wide.csv
```

Repeat with `--modifiers 0` for controls. OTLP protobuf requires the Python
dependencies in `tests/integration/requirements.txt`.
