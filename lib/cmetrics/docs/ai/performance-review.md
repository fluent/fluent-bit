# Performance-review workflow

## Purpose

Accept only repeatable CMetrics performance improvements without correctness or
workload regressions.

## When to use

Use for map lookup/update, codec allocation, cardinality, and hot-path changes.

## Investigation and implementation

1. Identify the hot path and representative existing benchmark workload.
2. Establish a correctness baseline and a performance baseline before editing.
3. Change one material factor at a time and preserve ownership/concurrency rules.
4. Add a benchmark workload only when existing modes cannot represent the path.

## Validation

Follow `benchmarks/README.md`. Build Release with `CMT_BENCHMARKS=ON`; run at
least five alternating before/after samples on the same idle machine with the
same compiler, flags, CPU policy, cardinality, and operations. Compare medians,
variability, allocations when relevant, and `perf stat` counters. Run
`scripts/agent-verify.sh` for correctness.

## Expected report

Report revisions, hardware/software environment, exact commands, raw samples,
medians, percentage changes, counter changes, correctness results, and affected
workloads. Explain any regression.

## Stop conditions

Do not ship noise-level, single-run, differently configured, or correctness-
regressing results. Escalate tradeoffs that improve one supported workload while
materially degrading another.
