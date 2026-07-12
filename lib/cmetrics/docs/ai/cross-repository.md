# Cross-repository workflow

## Purpose

Coordinate changes whose behavior or validation spans CMetrics, its submodules,
or a downstream consumer.

## When to use

Use for CFL or fluent-otel-proto changes, CMetrics submodule updates, and
consumer integrations such as Fluent Bit.

## Investigation

1. Identify which repository owns the behavior and which repositories consume
   its API, ABI, generated code, or wire output.
2. Determine compatibility impact and the required landing order.
3. Record exact base branches, revisions, and temporary dependency revisions.
4. Reproduce in the owning repository before changing the consumer when
   practical.

## Implementation

1. Keep separate commits and pull requests per repository.
2. Land the owning-library fix first unless a coordinated transition is needed.
3. Update submodule or vendored revisions in a focused consumer change.
4. Avoid copying an unmerged implementation into multiple repositories.

## Validation

Run standalone validation in the owning repository. Then build and test each
consumer against the exact dependency branch/revision, including its relevant
integration and memory-safety jobs.

## Expected report

Report ownership, dependency direction, revisions, landing order, standalone
results, consumer integration results, and temporary coordination steps.

## Stop conditions

Stop when a required repository or CI environment is unavailable, the landing
order could break a supported branch, or ownership/compatibility policy is
unclear.
