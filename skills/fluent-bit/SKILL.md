# Fluent Bit Repository Skill

Use this skill when working in the Fluent Bit repository or in a similar
C/C++ plugin-based telemetry pipeline. It is written for any LLM agent: read the
relevant linked files, inspect the current checkout, make the smallest correct
change, and report exact verification.

## When to Use

- A task mentions Fluent Bit source, tests, plugins, runtime behavior, routing,
  storage, shutdown, configuration validation, or protocol encoding.
- A task asks whether a reported Fluent Bit bug is still present.
- A task asks for implementation or review of a Fluent Bit patch.
- A task asks for the right focused tests, integration scenarios, or valgrind
  checks for a touched Fluent Bit component.

## Required Reading Order

1. Read this file.
2. Read `testing.md` before changing behavior or closing out a task.
3. Read `patch-workflow.md` before editing code or reviewing a patch.
4. Read `pipeline-architecture.md` for shared runtime, routing, lifecycle,
   processor, chunk, task, storage, metrics, retry, or signal-aware changes.
5. Read `subsystem-patterns.md` when the task touches one of the listed
   recurring areas.

## Operating Principles

- Verify the current checkout before patching. A report may already be fixed.
- Prefer the repository's existing helpers, source-of-truth resolvers, and
  local conventions over new parallel logic.
- Keep changes scoped to the affected component. Put plugin logic in its plugin
  directory; shared behavior belongs in `src/`, `include/fluent-bit/`, or `lib/`.
- Treat bundled libraries under `lib/` as third-party or separately maintained
  code unless the path is clearly Fluent Bit-owned. Ask for explicit user
  confirmation before editing them, using a confirmation popup when available.
  Keep those edits isolated and upstreamable as focused patches.
- Fix shared helper semantics when the bug is in a helper, instead of patching
  only one visible caller.
- Preserve real input paths. If the request asks to enrich or correct an
  existing path, solve it in the relevant layer instead of faking another input
  route.
- Treat shutdown, architecture-specific failures, memory errors, and route
  accounting mismatches as real lifecycle problems until traced through the
  exact failing path.
- Separate validated behavior from environment noise. If a focused test passes
  but a broader legacy suite fails for unrelated reasons, report both signals.

## Standard Commands

```sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
ctest --test-dir build --output-on-failure
ctest --test-dir build -R <name> --output-on-failure
./build/bin/fluent-bit -c conf/fluent-bit.conf
```

On Windows, skip runtime test cases. Runtime tests are not supported there yet,
so configure with runtime tests disabled, use applicable non-runtime
verification, and report the runtime-test skip:

```sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=Off -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
ctest --test-dir build -R <non-runtime-name> --output-on-failure
```

For Python integration scenarios:

```sh
cd tests/integration && ./setup-venv.sh
cd tests/integration && ./run_tests.py --list
cd tests/integration && ./run_tests.py
```

## Close-Out Requirements

Final responses for implementation tasks should include:

- What changed, with file paths.
- The exact verification commands run.
- Pass/fail status.
- Whether valgrind was used when integration coverage applies.
- Any runtime tests skipped on Windows because runtime test cases are
  unsupported there.
- Any bundled library patch touched, including the upstream project/path and
  confirmation that the user approved editing it.
- Any concrete blocker for required tests that could not run.
