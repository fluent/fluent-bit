# Cross-repository workflow

## Purpose

Coordinate changes across CTraces, its pinned dependencies, and Fluent Bit
without obscuring behavior ownership.

## When to use

Use for CFL or fluent-otel-proto updates, public API changes consumed by Fluent
Bit, and bugs first observed in Fluent Bit whose implementation is in CTraces.

## Investigation

1. Identify which repository owns the behavior and why.
2. Record dependency direction, pinned revisions, affected public APIs, and
   format or ABI implications.
3. Inspect actual Fluent Bit call sites; do not infer consumer lifecycle.
4. Define the landing order and temporary branch or revision strategy.

## Implementation

1. Implement and test the fix in the owning repository first.
2. Keep each repository's change in a separate commit and pull request when
   practical.
3. Update submodule or vendored revisions explicitly; do not mix dependency
   source edits into the consumer repository.
4. Avoid temporary compatibility shims unless landing order requires them and
   their removal is tracked.

## Validation

Validate the standalone owner first. Then build and test CTraces at the proposed
dependency revision. Finally build and exercise the relevant Fluent Bit
consumer path, including the trace sampling processor when that path is affected.

## Final report

Report ownership, repositories and revisions, landing order, API/ABI or format
impact, standalone results, consumer integration results, and remaining rollout
risk.

## Stop conditions

Stop when write authority is missing for another repository, a required branch
or revision is unavailable, landing order would break a consumer, or the
downstream behavior cannot be exercised reliably.
