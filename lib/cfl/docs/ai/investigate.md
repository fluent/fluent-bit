# Investigation workflow

## Purpose

Establish an evidence-based explanation of CFL behavior without changing code.
Use this for bug reports, design questions, compatibility concerns, and unclear
ownership or performance behavior.

## Investigation

1. Restate the observed behavior and separate verified facts from assumptions.
2. Identify the owning CFL module from the public header, implementation, and
   related tests. Check whether the behavior is actually consumer-owned.
3. Trace inputs, return values, ownership transfers, allocations, mutation,
   cleanup, and error paths through every relevant caller.
4. Search tests, changelog entries, documentation, and Git history for intended
   behavior and compatibility constraints.
5. Reproduce the behavior with an existing focused test or the smallest
   temporary diagnostic possible when practical.
6. For public behavior, inspect the bundled downstream callers described in
   [cross-repository.md](cross-repository.md).

## Validation

Run the focused test that exercises the path when one exists. Do not mutate
production files merely to complete an investigation.

## Final report

Report evidence, root cause or best-supported explanation, affected callers,
compatibility implications, commands run, and remaining uncertainty. Recommend
a change only when the evidence supports it.

## Stop conditions

Stop and request direction when reproduction requires unavailable inputs,
access to another repository was not authorized, or multiple plausible API
semantics would materially change the solution.
