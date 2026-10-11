# Bug-fix workflow

## Purpose

Fix confirmed CProfiles defects with a regression test and minimal compatibility risk.

## When to use

Use when behavior is incorrect, unsafe, or inconsistent with repository evidence.

## Investigation

1. Restate observed and expected behavior.
2. Separate verified facts from assumptions.
3. Identify the owning subsystem and repository.
4. Trace the relevant public entry point through allocation, mutation, codec, and cleanup paths.
5. Locate existing tests and CI coverage.
6. Reproduce the problem when practical.

## Implementation

1. Add a focused regression test that fails for the confirmed defect.
2. Implement the smallest reasonable fix in the owning layer.
3. Preserve public structure layouts and encoded formats unless the fix explicitly requires a reviewed compatibility change.
4. Handle allocation failure, partial initialization, cleanup, bounds, malformed input, and list ownership affected by the path.
5. Avoid unrelated refactoring.

## Validation

Run the focused test with `./scripts/agent-test.sh -R <test-name>`, then run `./scripts/agent-verify.sh`.
Use additional consumer or cross-repository validation when public API or encoded output changes.

## Final report

Report reproduction, root cause, fix, regression coverage, exact commands and results, compatibility impact, and unresolved risks.

## Stop conditions

Escalate when ownership is external, expected behavior is not defined, the smallest fix requires an API or format break, or the defect cannot be reproduced and evidence is insufficient.
