# Investigation workflow

## Purpose

Establish evidence before proposing or making a CProfiles change.

## When to use

Use this for unfamiliar behavior, issue triage, design questions, and failures without a confirmed root cause.

## Investigation

1. Restate the observed behavior and desired behavior separately.
2. Record facts from code, tests, logs, and reproducible commands; label assumptions.
3. Identify whether CProfiles, CFL, fluent-otel-proto, or a downstream consumer owns the behavior.
4. Start at the public declaration or codec entry point and trace creation, mutation, encoding or decoding, and destruction.
5. Check allocation failures, partial initialization, list ownership, cleanup paths, count and index validation, and malformed input.
6. Locate existing tests and relevant CI coverage.
7. Reproduce the behavior with the smallest practical input.

## Implementation and validation

Do not implement until the cause and owning repository are supported by evidence.
If a change is requested, choose the relevant workflow and run targeted tests followed by `./scripts/agent-verify.sh`.

## Final report

Report evidence, reproduction, root cause or leading hypotheses, ownership, affected compatibility surfaces, and recommended next action.

## Stop conditions

Stop and escalate when reproduction requires unavailable data, ownership belongs to another repository, expected behavior is ambiguous, or a public API or format decision needs maintainer direction.
