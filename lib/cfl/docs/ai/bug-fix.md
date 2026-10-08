# Bug-fix workflow

## Purpose

Correct a reproducible CFL defect with the smallest safe change and permanent
regression coverage.

## Investigation

1. Restate the observed and expected behavior; label assumptions explicitly.
2. Identify the owning subsystem and repository.
3. Trace the complete code path, including allocation failures, partial
   initialization, ownership transfer, cleanup, and malformed inputs.
4. Locate existing tests and reproduce the defect when practical.
5. Inspect callers when return values, ownership, layout, or public behavior may
   change. Use [cross-repository.md](cross-repository.md) when needed.

## Implementation

1. Add a regression test that fails for the reported behavior.
2. Implement the smallest reasonable fix without unrelated refactoring.
3. Preserve API/ABI and existing valid behavior unless the task explicitly
   authorizes a compatibility change.
4. Cover failure and boundary paths relevant to the root cause.

## Validation

Run the focused CTest target while iterating, then `scripts/agent-verify.sh`.
Public API, allocator, ownership, or common-container changes also require the
relevant downstream assessment and CI coverage.

## Final report

Report the root cause, fix, regression test, exact commands and results,
compatibility impact, downstream impact, and unresolved risks.

## Stop conditions

Stop when the expected behavior is ambiguous, the fix belongs to a consumer,
or validation requires unavailable external state. Present the evidence and the
smallest decision needed to continue.
