# Tail shared file budget benchmark

`flb-bench-tail_file_budget` measures the production Tail reservation/release API
under saturation. It opens no tailed files and disables plugin logging; it measures
shared atomic admission costs, not file discovery, dormant reclamation, disk I/O,
or end-to-end Tail throughput. Every worker owns its own Tail context and shares
one process-wide pool. No fixed per-worker quota is used.

## Build and run

Enable Tail and benchmarks in an optimized build:

```sh
cmake -S . -B build-bench -DFLB_BENCHMARKS=On -DFLB_IN_TAIL=On -DFLB_RELEASE=On
cmake --build build-bench --target flb-bench-tail_file_budget -j8
./build-bench/bin/flb-bench-tail_file_budget --threads 4 --iterations 10000000 --budget 1024
```

On Windows, build the same target and run `flb-bench-tail_file_budget.exe` from the
build's binary directory (including the configuration directory for a multi-config
generator). Timing uses `QueryPerformanceCounter` on Windows and `CLOCK_MONOTONIC`
on POSIX. Synchronization uses Fluent Bit's pthread interface, without requiring
`pthread_barrier_t`.

Options are `--mode all|full|churn`, `--threads` (1–256), `--iterations` (attempts per
worker), `--budget` (positive hard cap), and `--slots` (positive available slots in
churn mode, at most the budget). Defaults are `all`, 4, 1000000, 1024, and 1.

- **full:** preclaim the entire budget and prime the full-warning latch. Every
  timed claim must fail. This isolates the steady-state saturated rejection path.
- **churn:** preclaim `budget - slots` reservations. Each worker repeatedly tries
  to claim a remaining slot and immediately releases successful claims. Releases
  clear the full-warning latch, exercising its contention as well as the count's
  compare-and-exchange operations. Use fewer slots than workers to create pressure;
  actual rejections depend on scheduling. A one-worker run provides a baseline.

A condition-variable start gate excludes thread creation from measurement. API
warmup, pool setup, joins, and verification are also excluded. Elapsed time runs
from opening the gate to the last worker's completion, so it includes wakeup and
scheduling delays. There are no per-attempt clocks or extra shared counting
atomics; workers accumulate their results locally. Successful churn iterations
include both claim and release costs.

CSV output reports attempts, successful claims, rejections, elapsed seconds,
attempts/second, successful claims/second, aggregate wall nanoseconds/attempt, and
minimum/maximum successful claims per worker. Wall nanoseconds/attempt is the
inverse of aggregate throughput, **not per-call latency**. Worker claim counts help
identify uneven access; the pool does not promise fairness. Full mode must report
zero claims; churn must make progress. After timing, each run verifies that exactly
the expected slots remain available and that another claim at the cap fails. Any
failed invariant or setup error produces a nonzero exit status.

Compare 1, 2, 4, 8, and more workers on the same machine, repeating runs to assess
variation. Keep build flags, CPU affinity, power settings, budget, and slots fixed.
For a one-slot churn test with a budget of 1024, occupancy remains at 1023–1024, so
the 75% warning latch stays armed throughout. A budget of 1 also exercises rearming
that latch on every release. Logging stays disabled in both cases.

## Memory checks

Run a short correctness/memory check separately from performance measurements:

```sh
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=definite,indirect --error-exitcode=1 \
  ./build-bench/bin/flb-bench-tail_file_budget --threads 4 --iterations 10000 --budget 1024
```

Do not compare Valgrind timings with native results: instrumentation changes both
costs and thread scheduling. This standalone benchmark has no HTTP integration
scenario and does not change Tail's runtime implementation.
