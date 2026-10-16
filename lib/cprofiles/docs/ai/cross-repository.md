# Cross-repository workflow

## Purpose

Coordinate changes whose behavior or validation spans CProfiles, its pinned dependencies, or consumers.

## When to use

Use for CFL or fluent-otel-proto changes, submodule updates, and consumer-facing API or format changes.

## Investigation

1. Identify which repository owns the behavior.
2. Map dependency direction from manifests, submodule pointers, build files, and consumer code.
3. Assess public API, ABI, generated-code, and encoded-format impact.
4. Define landing order and the temporary branch, commit, or submodule revision used between landings.

## Implementation

Keep implementation and commits in the owning repository.
Use separate branches and pull requests per repository when practical.
Do not patch generated protobuf-C output in CProfiles; change its owning source and refresh through the dependency's process.
Update the CProfiles submodule pointer only as an intentional, reviewable dependency change.

## Validation

1. Build and test the changed library standalone.
2. Test CProfiles against the temporary dependency revision when applicable.
3. Run `./scripts/agent-verify.sh` in CProfiles.
4. Build and test each affected final consumer against the exact proposed revisions.

## Final report

Report ownership, repositories and revisions, dependency and compatibility impact, landing order, temporary revision strategy, standalone results, consumer integration results, and remaining coordination.

## Stop conditions

Escalate when ownership or landing order is unclear, a required repository or revision is unavailable, generated sources cannot be reproduced, or consumer compatibility cannot be validated.
