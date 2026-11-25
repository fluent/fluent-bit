---
name: fluent-bit
description: Work in the Fluent Bit C/C++ repository using its scoped patch, plugin authoring, testing, verification, runtime, integration, lifecycle, and review conventions. Use for Fluent Bit source, new or changed plugins, pipeline, Windows runtime-test, CI, configuration, protocol, or regression tasks.
---

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
- A task adds a plugin or changes a plugin's callbacks, options, or
  registration.
- A task asks for the right focused tests, integration scenarios, or valgrind
  checks for a touched Fluent Bit component.

## Required Reading Order

1. Read this file.
2. Read `testing.md` before changing behavior or closing out a task.
3. Read `patch-workflow.md` before editing code or reviewing a patch.
4. Read `pipeline-architecture.md` for shared runtime, routing, lifecycle,
   processor, chunk, task, storage, metrics, retry, or signal-aware changes.
5. Read `plugin-authoring.md` before adding a plugin or changing plugin
   callbacks, config maps, or registration.
6. Read `verify.md` before closing any change that affects runtime behavior.
7. Read `subsystem-patterns.md` when the task touches one of the listed
   recurring areas.

## Operating Principles

- Verify the current checkout before patching. A report may already be fixed.
- Read before writing. Open the relevant header, the closest existing plugin
  or caller, and a neighboring test before editing. Do not write an API name,
  callback signature, config key, CMake option, or test name from memory.
- A successful compile is not proof. Run the focused tests and the real
  `fluent-bit` binary on the changed path, and report what was observed.
- Work locally and observably first: build, focused tests, one live run. Do
  not fan work out to parallel or remote agents before that loop passes.
- When the same review correction comes up twice, propose a test, lint, or CI
  check for it instead of another written rule.
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
- Never report a suspected vulnerability in a public issue, pull request, or
  commit message. Follow the private process in `SECURITY.md`.

## Standard Commands

```sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
ctest --test-dir build --output-on-failure
ctest --test-dir build -R <name> --output-on-failure
./build/bin/fluent-bit -c conf/fluent-bit.conf
```

Windows runtime tests, Python integration scenarios, and the memory-checker
passes are described in `testing.md`.

## Close-Out Requirements

Final responses for implementation tasks should include:

- What changed, with file paths.
- The exact verification commands run.
- Pass/fail status.
- What the live `fluent-bit` run showed when `verify.md` applies.
- Whether valgrind was used when integration coverage applies.
- Any bundled library patch touched, including the upstream project/path and
  confirmation that the user approved editing it.
- Any concrete blocker for required tests that could not run.
