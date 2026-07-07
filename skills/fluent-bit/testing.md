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

## Windows Runtime Test Exception

Runtime test cases are not supported on Windows yet. On Windows, do not run
`tests/runtime`, `flb-rt-*` targets, or CTest filters that select runtime test
cases as verification. Run applicable non-runtime tests instead, such as focused
internal tests or build-only checks, and report the skip explicitly. Configure
with runtime tests disabled so unsupported runtime targets are not built:

```sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=Off -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
ctest --test-dir build -R <non-runtime-name> --output-on-failure
```

## Integration Test Expectations

If a touched component has a focused `tests/integration` scenario, run it before
closing the task. Run it once normally and once with valgrind when possible.

Default verification shape for non-Windows platforms:

```sh
./tests/integration/setup-venv.sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
tests/integration/.venv/bin/python -m pytest <focused-scenario> -q
VALGRIND=1 VALGRIND_STRICT=1 \
  tests/integration/.venv/bin/python -m pytest <focused-scenario> -q
```

On Windows, replace the configure command with the
`-DFLB_TESTS_RUNTIME=Off` variant above and do not run runtime test cases.

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
- Windows runtime test skip because runtime tests are not supported there;
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
- SKIPPED: runtime tests on Windows because runtime test cases are unsupported
- BLOCKED: VALGRIND=1 ... failed because valgrind is not installed
```
