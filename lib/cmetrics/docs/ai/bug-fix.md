# Bug-fix workflow

## Purpose

Produce a minimal, regression-tested fix with explicit compatibility and memory
ownership review.

## When to use

Use after an observed defect has enough evidence to justify changing CMetrics.

## Investigation

1. Restate observed behavior and separate facts from assumptions.
2. Identify the owning subsystem and repository.
3. Trace the relevant public entry point, internal path, and cleanup path.
4. Locate existing tests and reproduce the defect when practical.

## Implementation

1. Add a focused regression test that fails for the reported reason.
2. Implement the smallest reasonable fix; avoid unrelated refactoring.
3. Check allocation failure, partial initialization, cleanup, concurrency, and
   malformed-input behavior where relevant.
4. Review public headers and encoded formats for compatibility impact.

## Validation

Run the focused CTest target, then `scripts/agent-verify.sh`. Ownership fixes
also require the applicable checks in `memory-safety-review.md`. Format changes
require round-trip and malformed-input coverage.

## Expected report

Report root cause, fix, regression test, exact commands/results, compatibility
impact, dependency impact, and unresolved risks.

## Stop conditions

Stop when the intended behavior requires a maintainer decision, the fix belongs
in a dependency, a public or wire contract must change without agreement, or a
safe reproducer cannot be created.
