# Bug-fix workflow

## Purpose

Produce the smallest verified correction with a regression test.

## When to use

Use for crashes, leaks, invalid output, rejected valid input, accepted malformed
input, ownership corruption, and behavior regressions.

## Investigation

1. Restate observed behavior and separate facts from assumptions.
2. Identify the owning subsystem and repository.
3. Trace the relevant public API through its complete code and cleanup paths.
4. Locate existing focused and round-trip tests.
5. Reproduce the failure when practical.

## Implementation

1. Add a regression test that fails for the reported reason.
2. Implement the smallest reasonable fix in the owning subsystem.
3. Audit sibling error paths for the same ownership or validation mistake.
4. Avoid API, struct layout, enum, and wire-format changes unless required and
   explicitly justified.
5. Keep dependency and downstream changes in separate commits or repositories.

## Validation

Run the focused test with `scripts/agent-test.sh -R <name>`, then run
`scripts/agent-verify.sh`. For dependency-facing behavior, also validate the
standalone dependency and Fluent Bit consumer as described in
`cross-repository.md`.

## Final report

State root cause, fix, regression coverage, exact commands and results,
compatibility impact, downstream validation, and unresolved risks.

## Stop conditions

Escalate when the expected behavior is ambiguous, the fix requires a public or
wire-format break, the issue belongs elsewhere, or a reliable regression test
cannot be constructed from available evidence.
