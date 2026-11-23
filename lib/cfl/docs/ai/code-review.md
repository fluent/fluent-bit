# Code-review workflow

## Purpose

Review a CFL change for actionable defects and regressions. A review identifies
issues; it does not modify code unless implementation is separately requested.

## Investigation

1. Read the complete diff and identify the affected public APIs, ownership
   boundaries, generated files, vendor code, tests, and consumers.
2. Trace changed call paths rather than reviewing isolated lines.
3. Prioritize correctness, allocation and resource ownership, partial cleanup,
   concurrency, API/ABI compatibility, compiler portability, malformed input,
   integer overflow, missing tests, and measurable performance impact.
4. Check whether the implementation adds unnecessary state, abstraction, or
   duplicated logic.
5. Verify each suspected issue against current code and existing tests before
   reporting it.

## Validation

Run focused tests or small read-only checks when they materially confirm a
finding. Use `scripts/agent-verify.sh` only when review scope and time justify a
full local pass.

## Final report

List findings by severity. For each, give the file and line, triggering case,
consequence, and smallest useful correction. Then list validation gaps. If no
actionable findings remain, say so explicitly and note residual risk.

## Stop conditions

Do not speculate beyond available evidence. Escalate when intended semantics,
supported platforms, or consumer compatibility requirements are unclear.
