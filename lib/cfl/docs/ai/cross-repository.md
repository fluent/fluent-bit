# Cross-repository workflow

## Purpose

Validate CFL changes that may affect Fluent Bit, cmetrics, ctraces, or cprofiles,
which bundle CFL under `lib/cfl`.

## Investigation

1. Decide which repository owns the behavior: generic CFL data structures and
   APIs belong here; product- or telemetry-specific behavior belongs to its
   consumer.
2. Identify changed public symbols, layouts, return values, ownership,
   allocation, mutation, and compatibility guarantees.
3. Search actual consumer call sites. Exclude copied `lib/cfl` implementations
   when counting production callers.
4. Determine dependency impact and landing order. A CFL API change normally
   lands first, followed by separate consumer changes after a usable CFL
   revision exists.

## Implementation strategy

Keep commits and pull requests separate per repository. For pre-merge testing,
replace the consumer's bundled `lib/cfl` with an archive of the CFL revision,
matching `.github/workflows/build.yaml`; do not commit a temporary dependency
copy unless explicitly requested.

## Validation

1. Run CFL focused tests and `scripts/agent-verify.sh` first.
2. Configure and build each affected consumer against the exact CFL revision.
3. Run cmetrics, ctraces, and cprofiles tests when affected. Fluent Bit's CI
   configuration builds selected processor plugins but does not run their test
   suites, so add focused consumer validation when behavior—not just linkage—is
   at risk.
4. Record the CFL and consumer revisions and exact configuration commands.

CI currently verifies all four consumers by replacing their bundled CFL tree.
Consult that workflow for the authoritative options rather than copying them
into another canonical document.

## Final report

Report behavior ownership, affected production callers, API/compatibility
impact, tested revision pairs, results, landing order, and any consumer not
validated.

## Stop conditions

Stop before changing another repository without authorization. Escalate when a
consumer requires an incompatible API, its expected revision is unavailable,
or standalone CFL validation passes but consumer integration fails.
