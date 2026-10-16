# Investigation workflow

## Purpose

Establish an evidence-backed explanation of CMetrics behavior without assuming
that a code change is required.

## When to use

Use for bug reports, unexpected codec output, crashes, compatibility questions,
and performance reports before selecting a fix.

## Investigation

1. Restate the observed and expected behavior, including platform and input.
2. Separate reproduced facts, repository evidence, and working assumptions.
3. Identify the owning layer: CMetrics, CFL, fluent-otel-proto, generated code,
   or a downstream consumer.
4. Trace from the public entry point through allocation, mutation, codec, and
   cleanup paths. Include error exits and ownership transfers.
5. Locate focused tests and recent changes in the same subsystem.
6. Reproduce with the smallest representative input when practical.
7. For malformed input, retain a non-sensitive reproducer or describe its exact
   construction rather than relying on an external artifact.

## Validation

Run the closest existing CTest target. Use a sanitizer, Valgrind, or benchmarks
only when relevant to the reported behavior. Do not infer results from CI job
names.

## Expected report

Report reproduction status, owning subsystem/repository, traced code path,
root-cause confidence, affected versions or formats when known, and remaining
unknowns. Propose a minimal fix and test plan separately.

## Stop conditions

Stop and escalate when the reproducer depends on unavailable private data, the
behavior belongs to another repository, the expected contract is ambiguous, or
a compatibility decision is required before implementation.
