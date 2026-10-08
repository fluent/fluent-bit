# Repository Guide

This is the canonical operating guide for contributors and coding agents. CFL
is a compact C library of data structures and low-level utilities embedded by
Fluent Bit and companion telemetry libraries. Keep it portable, allocation-safe,
and usable both as a bundled dependency and as an installed library.

## Repository map

- `include/cfl/`: public API. Each header must compile on its own.
- `src/`: implementations and private headers; `src/cfl_arena_internal.h` is
  not public API.
- `tests/`: acutest unit tests, public-header tests, and an installed-consumer
  fixture.
- `benchmarks/`: arena and mutable-variant performance tools; see
  [benchmarks/README.md](benchmarks/README.md).
- `cmake/`, `CMakeLists.txt`: CMake 3.20+ build and packaging definitions.
- `lib/xxhash/`: bundled third-party xxHash sources. Do not apply CFL style or
  unrelated edits there.
- `.github/workflows/`: authoritative cross-platform, sanitizer, Valgrind,
  installed-consumer, packaging, lint, and downstream validation.

Start architecture work with [README.md](README.md), the relevant public header,
and its matching source and test file. Arena ownership and tuning are detailed
in [ARENA.md](ARENA.md).

## Generated and bundled files

CMake generates these ignored files; edit their `.in` sources instead:

- `include/cfl/cfl_info.h` from `include/cfl/cfl_info.h.in`
- `include/cfl/cfl_version.h` from `include/cfl/cfl_version.h.in`
- `tests/cfl_tests_internal.h` from `tests/cfl_tests_internal.h.in`

Do not edit build directories or generated package output. Treat `lib/xxhash/`
and `tests/lib/acutest/` as vendored code unless the task explicitly updates the
dependency.

## Build and test

The verified local path is:

```sh
cmake -S . -B build -DCFL_TESTS=On
cmake --build build -j8
ctest --test-dir build --output-on-failure
```

Convenience wrappers run from any directory:

```sh
scripts/agent-build.sh
scripts/agent-test.sh
scripts/agent-test.sh cfl-test-arena
scripts/agent-verify.sh
```

`scripts/agent-test.sh` accepts a CTest regular expression. The verification
wrapper configures, builds, runs all tests, and checks tracked diffs for
whitespace errors. Set `BUILD_DIR` or `BUILD_JOBS` to override its defaults.

For a focused test without the wrapper:

```sh
ctest --test-dir build -R cfl-test-<name> --output-on-failure
```

Build benchmarks separately in release mode:

```sh
cmake -S . -B build/bench -DCMAKE_BUILD_TYPE=Release -DCFL_BENCHMARKS=On
cmake --build build/bench -j8
```

There is no repository-owned formatter or standalone local sanitizer command.
Always run `git diff --check`. GitHub CI is the canonical extended validation
for GNU99/GNU17, GCC/Clang, Windows/MSYS2, ARM64, sanitizers, Valgrind, shell
lint, installed consumers, and downstream consumers.

## Coding and ownership conventions

- Follow the existing Apache-style C: four-space indentation, braces for all
  control blocks, and function opening braces on the next line.
- Declare variables at the start of functions, not inside executable blocks.
- Use descriptive `snake_case`; public symbols use the `cfl_` prefix.
- Use `CFL_TRUE` and `CFL_FALSE` for CFL boolean-style results.
- Keep public headers self-contained and include the standard headers they use.
- Put public declarations in `include/cfl/`, implementation in `src/`, and
  behavioral coverage in `tests/`.
- Check allocation failure and partial initialization. Preserve cleanup paths
  and ownership on every error return.
- Verify container ownership transfer, arena lifetime, and mutation behavior
  before changing variants, arrays, kvlists, or SDS storage.
- Avoid unrelated formatting, refactoring, generated output, or vendor churn.

## Compatibility and downstream boundaries

Public headers and installed library symbols are compatibility-sensitive.
Before changing a public signature, return value, ownership rule, layout, or
allocation behavior, inspect all in-repository callers and tests. Maintain C99
portability and do not introduce compiler-specific behavior without an existing
compatibility abstraction and cross-platform coverage.

Fluent Bit, cmetrics, ctraces, and cprofiles bundle CFL under `lib/cfl`. CI tests
the current CFL tree by replacing each consumer's bundled copy. CFL owns its
generic data structures and APIs; consumer-specific behavior remains in the
consumer repository. For changes that can affect callers, follow
[docs/ai/cross-repository.md](docs/ai/cross-repository.md), inspect production
callers separately from bundled source copies, and report any unavailable
checkout or validation.

## Change workflow

- Investigation: [docs/ai/investigate.md](docs/ai/investigate.md)
- Bug fixes: [docs/ai/bug-fix.md](docs/ai/bug-fix.md)
- Reviews: [docs/ai/code-review.md](docs/ai/code-review.md)
- Cross-repository changes: [docs/ai/cross-repository.md](docs/ai/cross-repository.md)

Follow local commit history: `component: short imperative description`. Keep
commits scoped to one component or interface. Do not amend history, create or
delete remote branches, or open pull requests unless explicitly requested.

## Definition of done

1. The change is minimal and belongs in this repository.
2. New behavior has success, failure, and boundary tests where applicable.
3. Relevant focused tests pass, followed by `scripts/agent-verify.sh` for shared
   code, public APIs, ownership, CMake, or installation changes.
4. Public API and downstream impact are assessed and documented.
5. Generated and vendored files remain untouched unless explicitly in scope.
6. `git diff --check` passes and unrelated user changes remain intact.
7. The final report lists commands run, compatibility impact, and validation
   gaps or unresolved risks.

Do not modify repositories outside this checkout without explicit permission.
Preserve unrelated tracked and untracked work in the shared worktree.
