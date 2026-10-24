# Sustained ingestion ramp

Run from the repository root on Linux with Python 3 (no packages required):

```sh
python3 benchmarks/ingestion/ramp.py --output /tmp/flb-ramp-before
```

The default workload writes two-line, 1024-byte events at 2, 2.5, 3, 3.5, and
4 decimal MB/s for 60 seconds each, followed by 60 seconds without new input.
It uses threaded tail → buffered multiline → eight regex parser filters → null
output, filesystem storage, eight up chunks, a 128 MB output limit, and one output
worker. The null sink isolates ingestion and scheduling cost from downstream
network performance. Increase `--parser-count` or `--rates` until CPU saturates.
Parser stages preserve the original log and extracted fields; repeated stages
also increase payload size, stressing storage as well as CPU. Use `--config`
to measure a production pipeline with its actual field-retention settings.
The generator runs independently of metrics polling; compare actual byte deltas
in samples.csv with target rates to detect a generator/disk bottleneck.

The default run writes approximately 900 MB of input, plus Fluent Bit storage.
Each run requires a new output directory. Artifacts remain there for inspection;
remove the directory when finished. Run before/after builds on the same host,
with the same arguments and CPU allocation. Do not compare Valgrind throughput
with native throughput.

```sh
python3 benchmarks/ingestion/ramp.py --binary /path/to/before/fluent-bit \
  --output /tmp/flb-before --parser-count 32
python3 benchmarks/ingestion/ramp.py --binary build/bin/fluent-bit \
  --output /tmp/flb-after --parser-count 32
```

`metadata.json` records parameters, platform, binary version, and config location.
`samples.jsonl` retains complete metrics/storage responses and sampling failures.
`samples.csv` includes cumulative processed/dropped records, errors, retries,
written bytes, CPU (100% = one core), RSS, and storage chunk counts.
`summary.json` includes per-phase achieved writer rates and sampled counter
deltas, and flags periods of at least 10 seconds
without output progress during ingestion, missing output metrics, and forced
shutdown. Exit status 2 means one of those conditions or a nonzero process exit;
startup/generator failures exit with an error. A successful drain does not erase
an earlier stall. These are benchmark thresholds, not universal service SLOs.
Metrics are periodically published snapshots, so short flat intervals are normal.

For the production pipeline, use `--config /path/to/custom.yaml`. The subprocess
receives `BENCH_LOG_PATH`, `BENCH_STORAGE_PATH`, and `BENCH_HTTP_PORT`; use those
in your configuration, enable HTTP metrics on 127.0.0.1 and storage metrics, and
match the generated `START ...` plus indented-continuation records. With multiple
outputs, processed/dropped counters are summed across routes, not unique records.
The benchmark launches a separate Fluent Bit process; it does not modify a service.

Quick functional smoke test (does not establish saturation performance):

```sh
python3 benchmarks/ingestion/ramp.py --output /tmp/flb-ramp-smoke \
  --rates 0.1,0.2 --phase-seconds 3 --drain-seconds 3 --parser-count 2
```
