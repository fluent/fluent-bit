---
name: fluent-bit-benchmark
description: Run, compare, and interpret Fluent Bit throughput, CPU, memory, backlog, and storage benchmarks using installed binaries or source builds. Use for upgrade comparisons, configuration experiments, capacity investigation, and existing benchmark results. Excludes ordinary functional testing and universal release speedup claims.
---

# Fluent Bit benchmarking

Turn the user's question into a reproducible experiment and explain what the
measurements establish. Use maintained tools; do not invent a timing script or
make the agent the calculator. The CLI also works without an agent.

## Select and prepare

1. Establish whether the question concerns an upgrade, configuration, capacity,
   or a component. Inspect available binaries/configs before asking for missing
   information. State assumptions. Installed binaries need no source rebuild.
2. Read [methodology](references/methodology.md) and the applicable route in
   [workloads](references/workloads.md). Read the selected harness's own README.
3. Read [the runner documentation](../../benchmarks/README.md) and inspect
   `python3 benchmarks/run.py --help` in the matching checkout. Keep the runner,
   its sibling helper and skill together when copying; SKILL.md alone cannot
   execute experiments. Resolve paths from this checkout, not an assumed cwd.
4. Identify platform/dependencies, binary/build provenance, allowed CPUs, payload
   shape, tags/groups, batch size, processors, storage and completion boundary.
   Start with a bounded smoke test. Estimate runtime/disk use and choose a small
   relevant matrix rather than every available combination.

## Execute

- Use Linux `benchmarks/run.py` for local OTLP JSON/protobuf comparisons. JSON
  needs Python's standard library only. Protobuf needs the documented packages.
  Use existing binaries unless building is part of the request.
- Start with controlled offered load for CPU/memory comparisons; use saturation
  separately. Change one setting at a time and preserve required output semantics.
- Use synthetic data or sanitized samples. Keep paths, ports and state isolated.
  Review custom configs/includes for real inputs, destinations, credentials and
  shared state before launching. Benchmark authorization does not authorize
  sending user data to an unrelated service.
- Preserve artifacts outside tracked source. Avoid concurrent benchmarks. Do not
  change host governors, drop system caches, replace services, edit bundled
  libraries or tune production settings as a benchmark prerequisite.
- Preserve and report allocator overrides. Never treat a diagnostic relink,
  sanitizer or debug build as equivalent to a normal optimized release build.
- On failure inspect retained evidence, correct the demonstrated cause and rerun
  once with documented changes. A recurring blocker is a result to report, not
  permission for an expanding load campaign.
- Report unsupported host/harness combinations. Linux-only adapters do not imply
  Fluent Bit lacks Windows/macOS runtime support.

## Interpret and deliver

Read [interpretation](references/interpretation.md) before composing findings.
Use retained summaries/raw evidence, including failed and inconclusive trials.
Report exact invocations, binaries, workload, measurement boundaries, repetitions,
limitations and artifact location. Include CPU, completion, memory and backlog
together. Separate source-derived hypotheses from measured effects.

Label smoke tests as functional verification. Prefer five alternating repetitions
and an A/A control for performance comparisons where practical. Do not promise
an improvement before measuring. If available tooling cannot answer the question,
identify the missing measurement and the smallest necessary extension.

For code changes also follow repository testing rules. Benchmark counts do not
verify payload identity. Run focused semantic tests and platform memory checks
when implementation changes require them; keep diagnostic timing separate.
