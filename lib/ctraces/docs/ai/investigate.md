# Investigation workflow

## Purpose

Establish evidence about CTraces behavior without silently expanding into an
implementation task.

## When to use

Use for bug reports, unclear ownership, compatibility questions, unexplained
test failures, and behavior observed through Fluent Bit.

## Investigation

1. Restate the observed and expected behavior; separate facts from assumptions.
2. Identify whether CTraces, CFL, fluent-otel-proto, or Fluent Bit owns it.
3. Start at the relevant public header and trace create, mutate, encode/decode,
   and destroy paths through `src/`.
4. Locate tests and recent history for the same interface.
5. Reproduce with the smallest existing test executable or a temporary harness.
6. Inspect allocation failures, partial objects, owner lists, malformed input,
   and format boundaries relevant to the path.
7. Compare downstream usage in Fluent Bit when consumer assumptions matter.

## Implementation

Do not change production code unless the task also authorizes a fix. Keep any
temporary instrumentation or harness out of the final diff.

## Validation

Record the exact reproduction command and distinguish reproduced facts from
source-based inference.

## Final report

Report the owning repository, root cause or leading hypothesis, affected APIs
and formats, reproduction evidence, likely fix scope, and unresolved questions.

## Stop conditions

Stop and request direction if ownership requires a different repository, the
expected behavior would change a public contract, or reproduction needs data or
environment access that is unavailable.
