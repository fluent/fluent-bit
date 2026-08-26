# Code-review workflow

## Purpose

Find actionable defects and regression risks in a proposed change.

## When to use

Use for pull requests, local diffs, dependency updates, and pre-release audits.

## Investigation

1. Establish the diff base, intended behavior, and affected public entry points.
2. Read surrounding code and tests; verify findings against the current tree.
3. Prioritize correctness, memory/resource ownership, cleanup paths,
   concurrency, compatibility, malformed input, missing tests, regressions,
   unnecessary complexity, and measurable performance impact.
4. Trace callers before claiming a nullability, lifetime, or locking defect.
5. Distinguish confirmed findings from questions and optional improvements.

## Validation

Run focused tests that can confirm or reject each high-confidence finding. For
codec changes, inspect both encoding and decoding and relevant format
conversions. Use sanitizer or benchmark evidence where the claim depends on it.

## Expected report

List findings by severity with file/line, failure scenario, evidence, and the
smallest corrective action. Then list validation gaps and a short overall risk
assessment. Do not bury findings in a general summary.

## Stop conditions

Do not request speculative changes without a concrete failure mode. Escalate
public API, ABI, wire-format, or cross-repository policy decisions.
