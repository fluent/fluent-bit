# Code-review workflow

## Purpose

Find actionable regressions and risks in a proposed change.

## When to use

Use for pull requests, patch series, dependency updates, and pre-merge audits.

## Investigation

1. Establish the merge base and read the complete diff and commit intent.
2. Map changed public headers to implementations, tests, and consumers.
3. Trace success and failure paths, including partial initialization and cleanup.
4. Check ownership, double unlink/free, use-after-free, null handling, integer
   widths, bounds, malformed input, and deterministic encoding.
5. Check API/ABI and MessagePack/OpenTelemetry compatibility.
6. Look for missing regression and round-trip coverage.
7. Reject unnecessary complexity and call out measurable performance impact,
   especially new allocation or repeated traversal in hot encode/decode paths.

## Implementation

Review does not authorize edits. Suggest the smallest concrete correction and
the test that demonstrates it.

## Validation

Run focused tests when practical and `scripts/agent-verify.sh` when assessing
merge readiness. Do not treat green CI as proof that untested ownership or
compatibility behavior is correct.

## Final report

List findings by severity with file/line, failure scenario, impact, and fix.
Then note validation performed and residual risk. If there are no findings, say
so explicitly and identify any coverage gaps.

## Stop conditions

Escalate when the diff is incomplete, generated output lacks its source change,
the downstream contract is unavailable, or required CI logs cannot be obtained.
