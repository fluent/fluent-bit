# Interpret evidence

Check requested trials, reconciled counts, unexpected errors/drops, adequate
sampling, actual offered load and drain. The general runner exits 2 for results
needing review. Use JSON evidence as the calculation source.

Summary medians exclude invalid/inconclusive trials but retain attempted counts.
Review exclusions before comparing. comparison.json pairs matching repetitions;
small differences, insufficient repetitions or noisy hosts do not prove a gain.

- CPU seconds/million: server cost divided by measured completed records; lower
  cost need not increase throughput when another stage limits it.
- Completed rate: named output boundary over the stated interval; acceptance
  and acknowledgement are earlier boundaries.
- Request p99: HTTP acknowledgement, not record delivery or prior schedule lag.
- RSS: process pages, sampled peak and finite cooldown observation. These do not
  establish a memory leak or long-term fragmentation.
- Arena reserved/used bytes: object capacity, not process RSS.
- Disk allocated/logical bytes: distinct from RAM, I/O volume and durability.
- Backlog: compare with RSS; different queued work can explain a memory difference.
- Generator CPU/lag: a target shortfall alone does not locate the bottleneck.

Repository lessons to retain:

- `benchmarks/results/post-fts-12505/README.md`: fusion CPU savings sometimes
  coexist with unchanged throughput.
- `benchmarks/chunk_allocation/README.md`: sparse-tag disk savings coexist with
  more remaps and a small busy-checksum CPU regression.
- `benchmarks/rewrite-tag/README.md`: repeated-tag gains do not generalize to
  high cardinality; batching changes cross-tag ordering.
- `benchmarks/allocator_compare/README.txt`: relink effects differed from normal
  builds; mixed-size and paced controls changed allocator conclusions.
- `lib/cfl/ARENA.md`: fewer allocations can trade CPU for retained capacity.

Deliver workload/host, measured changes and ranges, validity/limitations, exact
commands/artifacts and the decision supported. Separate measured effects from
inferred mechanisms. Never apply historical percentages to an unmeasured user
workload or average unrelated cases into a release-wide score.
