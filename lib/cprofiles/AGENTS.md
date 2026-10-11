# CProfiles agent guide

This file is the canonical repository guide for coding agents and human contributors.
Keep tool-specific adapters thin and put reusable procedures in `docs/ai/`.

## Project role

CProfiles is a C library for creating, managing, and transcoding profiling data based on the OpenTelemetry Profiles development schema.
It builds a static library and exposes its API through `include/cprofiles/`.

## Repository map

- `src/`: profile model, lifecycle code, and MessagePack, OpenTelemetry, and text codecs.
- `include/cprofiles/`: installed public headers and data structures.
- `tests/`: Acutest-based executables registered with CTest.
- `lib/cfl/`: pinned CFL submodule; do not edit it as part of a CProfiles change.
- `lib/fluent-otel-proto/`: pinned protobuf-C bindings submodule; do not edit it directly.
- `lib/mpack/`: bundled third-party MessagePack implementation; avoid direct edits.
- `cmake/`: project helpers plus bundled sanitizer CMake support.
- `.github/workflows/`: the authoritative CI build, lint, package, and release automation.
- `scripts/`: portable local wrappers and the Windows build script.

Start architecture investigation at `include/cprofiles/cprofiles.h`, then follow the owning implementation in `src/`.
Codec entry points are declared in the other public headers and implemented by files with matching names.

## Dependencies and related repositories

The `.gitmodules` file is authoritative for pinned source dependencies:

- [fluent/cfl](https://github.com/fluent/cfl) supplies containers, strings, variants, and utilities.
- [fluent/fluent-otel-proto](https://github.com/fluent/fluent-otel-proto) supplies generated OpenTelemetry protobuf-C bindings.

CI describes CProfiles as used downstream and repository history references Fluent Bit, but this repository does not define a complete downstream compatibility or landing-order policy.
For changes spanning repositories, use `docs/ai/cross-repository.md` and validate each owning repository separately.

Initialize exact pinned dependency revisions before building:

```sh
git submodule update --init --recursive
```

Do not add `--remote`; reproducible builds use the revisions recorded by this repository.

## Build and test

The supported build system is CMake 3.20 or newer.
The portable wrappers create an ignored out-of-tree build under `build/agent` by default:

```sh
./scripts/agent-build.sh
./scripts/agent-test.sh
./scripts/agent-verify.sh
```

`agent-build.sh` configures with `CPROF_TESTS=On` and builds all targets.
Pass additional CMake configuration arguments to it when needed:

```sh
./scripts/agent-build.sh -DCMAKE_BUILD_TYPE=Debug
```

Pass CTest arguments to target or diagnose tests:

```sh
./scripts/agent-test.sh -R cprof-test-profile
./scripts/agent-test.sh --rerun-failed --output-on-failure
```

The equivalent direct commands used by CI are:

```sh
cmake -S . -B build/agent -DCPROF_TESTS=On
cmake --build build/agent
ctest --test-dir build/agent --output-on-failure
```

CI also builds with GCC and Clang on Linux, macOS, ARM64, and Windows.
The repository has no verified local C formatting command or benchmark suite.
ShellCheck, actionlint, and Markdownlint run in `.github/workflows/lint.yaml`; keep shell and Markdown changes compatible with those checks.
Although sanitizer helper sources are bundled and CI names analysis configurations, no repository-level sanitizer target or verified local sanitizer command is wired into the top-level build.

## Change constraints

- Treat declarations and layouts in `include/cprofiles/` as compatibility-sensitive public API.
- Treat MessagePack and OpenTelemetry encoded data as compatibility-sensitive formats.
- Preserve object ownership, allocation-failure handling, partial-initialization cleanup, and list membership invariants.
- Validate sizes, indexes, counts, and malformed input before allocation or dereference in decoders.
- Keep compiler and platform portability consistent with the CI matrix; do not assume GNU-only behavior.
- Do not edit configured headers (`cprof_info.h` and `cprof_version.h`) in a build tree; edit their `.in` templates when necessary.
- Do not edit generated protobuf-C files in the fluent-otel-proto submodule.
- Do not update a submodule pointer unless the dependency update is the intended change.
- Keep unrelated cleanup out of focused changes.
- Follow the existing C style: four-space indentation, opening braces on the next line for functions, and explicit cleanup on error paths.
- Global ownership is recorded in `CODEOWNERS`; `.github/` has additional owners.

No formal API or ABI stability policy is present in this repository.
Do not claim compatibility without checking consumers and encoded-format behavior.

## Workflows

- Investigation: `docs/ai/investigate.md`
- Bug fixes: `docs/ai/bug-fix.md`
- Code review: `docs/ai/code-review.md`
- Cross-repository changes: `docs/ai/cross-repository.md`

## Definition of done

A change is complete when:

1. The owning code path and compatibility surface are identified.
2. The smallest relevant tests are added or updated for behavior changes.
3. Targeted tests pass.
4. `./scripts/agent-verify.sh` passes, or any unavailable validation is reported precisely.
5. Public API and wire-format effects, allocation and cleanup paths, and dependency impacts are reviewed.
6. No generated, vendored, submodule, or unrelated files changed accidentally.
7. The final report states the change, root cause when applicable, exact validation, compatibility impact, and remaining risks.
