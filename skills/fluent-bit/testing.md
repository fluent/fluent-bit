# Fluent Bit Testing Skill

Use this guide to choose and report verification for Fluent Bit changes.

## Test Selection

- Prefer targeted tests when the affected area is known:

```sh
ctest --test-dir build -R <name> --output-on-failure
```

- Use `tests/internal` for core lifecycle, accounting, parser, encoder, and
  helper logic.
- Use `tests/runtime` for plugin-level behavior and end-to-end C test binaries.
- Use `tests/integration` for network protocols, downstream request generation,
  fake-server behavior, and plugin behavior that is awkward to cover in CTest.
- Run broader tests when changing shared lifecycle, routing, storage, task,
  scheduler, or accounting behavior.

## Windows Runtime Test Support

The latest master revision supports building and running runtime tests on
Windows. Initialize the appropriate MSVC environment, enable runtime tests, and
run the focused target or CTest match for the affected component:

- use `VsDevCmd.bat -arch=x64` for x64;
- use `VsDevCmd.bat -arch=x86` for x86;
- use an ARM64-capable native or cross-build Developer Command Prompt for
  ARM64. For a cross-build, add `-DCMAKE_SYSTEM_NAME=Windows`,
  `-DCMAKE_SYSTEM_VERSION=10.0`, and `-DCMAKE_SYSTEM_PROCESSOR=ARM64`.

```sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build --target <flb-rt-target>
ctest --test-dir build -R '^<flb-rt-target>$' --output-on-failure
```

The Windows unit-test CI workflow in
`.github/workflows/call-windows-unit-tests.yaml` enables runtime tests only for
x64. Its x86 and ARM64 jobs deliberately use `FLB_TESTS_RUNTIME=Off` to control
GitHub Actions running time. This restriction applies only to that CI workflow.
Do not use it to skip runtime-test builds or execution by local agents or AI
cloud builders.

When a cross-built target cannot execute on the current host, report that
concrete host/toolchain limitation. Do not substitute the GitHub Actions
running-time policy as the reason for skipping it.

Use `ctest --test-dir build -N` only to inspect registration. It does not prove
that a runtime executable was built or passed; confirm the target build and run
the focused test before claiming runtime verification.

## Integration Test Expectations

If a touched component has a focused `tests/integration` scenario, run it before
closing the task. Run it once normally and once with valgrind when possible.

Default verification shape for supported platforms, including Windows:

```sh
./tests/integration/setup-venv.sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
tests/integration/.venv/bin/python -m pytest <focused-scenario> -q
VALGRIND=1 VALGRIND_STRICT=1 \
  tests/integration/.venv/bin/python -m pytest <focused-scenario> -q
```

On Windows, keep `FLB_TESTS_RUNTIME=On` and run relevant focused runtime cases.
Valgrind is normally unavailable on Windows, so report that blocker
explicitly when the required memory-safety run cannot be performed.

Equivalent run-test wrapper shape:

```sh
cd tests/integration
./run_tests.py <focused-scenario>
./run_tests.py --valgrind --valgrind-strict <focused-scenario>
```

## Reporting Blockers

Do not silently skip required integration or valgrind coverage. Report the exact
blocker, such as:

- missing `build/bin/fluent-bit`;
- missing Python virtualenv;
- missing `pytest` or another Python dependency;
- unavailable scenario;
- missing `valgrind`;
- network restriction during dependency setup;
- infrastructure failure unrelated to the patch.

## Useful Validation Habits

- Rerun CMake before building a brand-new test target in an older build tree.
  Target-not-found failures are often stale build trees, not source failures.
- Use `git diff --check` after edits to catch whitespace problems.
- Validate success and failure paths: invalid payloads, boundary sizes,
  null/missing fields, and non-last bad fields when parsing maps.
- Keep generated integration artifacts out of git:
  `.venv/`, `.pytest_cache/`, `results/`, and `__pycache__/`.
- If broad tests fail after focused tests pass, inspect whether failures are
  pre-existing or unrelated before expanding the patch.

## Close-Out Proof Format

Include exact commands and outcomes:

```text
Verification:
- PASS: cmake --build build -j8 --target <target>
- PASS: ctest --test-dir build -R '<regex>' --output-on-failure
- BLOCKED: VALGRIND=1 ... failed because valgrind is not installed
```
