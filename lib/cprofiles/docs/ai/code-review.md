# Code-review workflow

## Purpose

Find actionable regressions and risks in a proposed CProfiles change.

## When to use

Use for patches, commits, branches, or pull requests.

## Investigation

1. Establish the intended behavior and diff base.
2. Map changed files to public API, model lifecycle, codec, dependency, build, test, or packaging concerns.
3. Trace affected call paths and compare tests with the changed behavior.

## Review priorities

Prioritize correctness; allocation and resource ownership; partial initialization and cleanup; list lifecycle; concurrency assumptions; API and encoded-format compatibility; malformed or adversarial input; integer bounds; missing tests; regressions; unnecessary complexity; and performance impact.
Check that submodule, generated, bundled, and unrelated files were not changed accidentally.

## Validation

Run the narrowest relevant test first, then `./scripts/agent-verify.sh` when practical.
Do not treat passing tests as proof that ownership and compatibility are correct.

## Final report

List findings by severity with file and line, concrete impact, supporting reasoning, and a focused remediation.
Then state test coverage gaps and validation performed.
If there are no findings, say so and identify residual risks.

## Stop conditions

Escalate when the base or intended behavior is unknown, required dependency context is unavailable, or compatibility depends on an undocumented consumer contract.
