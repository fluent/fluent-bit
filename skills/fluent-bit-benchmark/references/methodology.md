# Experiment rules

Define binaries/configuration, payload, protocol, resources, completion boundary,
offered load and duration. Version numbers alone do not establish comparability.
Record build flags, allocator identity and overrides if known; mark unknowns.

- Upgrade: equivalent normal builds, same workload/settings, different version.
- Configuration: same binary/workload, one setting changed, then combination confirmation.
- Capacity: load steps followed by longer confirmation near the apparent limit.
- Component: allocator/decoder/storage experiment followed by a pipeline check.

Check achieved offered rate, scheduling lag, completion and backlog. A missed
target cannot support a claim of sustaining it. Finite saturation throughput
is not long-term capacity. Request clients slow when responses slow, even when
following a fixed schedule; do not claim unconstrained open-loop latency.

Use representative widths, nesting, batches, size distributions, resource/scope
groups, tags, processor placement, storage and workers. Direct-CFL/fusion
eligibility depends on the whole chain. Source eligibility is a hypothesis
unless execution-path evidence confirms it.

Start with modest budgets. Use fresh processes, warmup and drain. Rotate order,
retain every observation and failure, prefer five repetitions and A/A controls.
Median/min/max describe observations; they do not establish significance. Do not
discard a result merely because it regresses.

Counters are per route. Fan-out, sampling, KEEP and intentional drops need an
explicit accounting model. The general runner supports one-to-one counts only;
those counts cannot prove payload identity. Complement them with focused semantic
tests when that claim matters.

Host contention, generator limits, SMT overlap, CPU quotas, cache/disk state,
frequency scaling and swapping can dominate results. Report known conditions;
do not silently modify the host. Missing metrics are unknown, never zero.
