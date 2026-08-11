# Dependency-update workflow

## Purpose

Update a Git submodule revision without mixing dependency implementation changes
into CMetrics.

## When to use

Use for `lib/cfl` and `lib/fluent-otel-proto` revisions.

## Investigation

1. Review `.gitmodules`, the current recorded revision, candidate commits/tags,
   and the dependency's release notes or diff.
2. Identify public API, generated protobuf, allocator, threading, compiler, and
   platform changes consumed by CMetrics.
3. Confirm the candidate revision exists in the dependency's upstream remote.

## Implementation

Update only the gitlink unless CMetrics requires a separate adaptation. Keep
adaptations explicit and avoid editing the submodule as uncommitted content.

## Validation

Run `scripts/agent-verify.sh`, relevant codec tests, and compiler/platform checks
affected by the dependency. For memory or performance changes, follow the
specialized workflows. Validate downstream consumers after CMetrics passes.

## Expected report

Report old/new revisions, included upstream changes, CMetrics adaptations,
standalone results, downstream results, and landing order.

## Stop conditions

Stop if the revision is not available upstream, includes unexplained generated
changes, requires an undocumented compatibility break, or cannot be tested in
the owning dependency first.
