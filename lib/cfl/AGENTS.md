# Repository Guidelines

## Preferred Commands
- Configure with tests: `cmake -S . -B build -DCFL_TESTS=On`
- Build: `cmake --build build -j8`
- Run all tests: `ctest --test-dir build --output-on-failure`
- Run a focused test: `ctest --test-dir build -R <name> --output-on-failure`
- Check staged or local patches for whitespace before closing a change:
  `git diff --check`

## Project Structure & Module Organization
CFL is a small C library built with CMake.

- `include/cfl/`: public CFL headers.
- `src/`: library implementation files.
- `tests/`: acutest-based unit tests.
- `lib/xxhash/`: bundled xxHash dependency.
- `cmake/`: project CMake helpers.

Keep changes scoped to the affected module. Put public declarations in
`include/cfl/`, implementation in `src/`, and matching unit coverage in
`tests/` when behavior changes.

## Build, Test, and Development Commands
- `cmake -S . -B build -DCFL_TESTS=On`: configure the project with tests.
- `cmake --build build -j8`: compile the static library and tests.
- `ctest --test-dir build --output-on-failure`: run the enabled test suite.
- `ctest --test-dir build -R cfl-test-<name> --output-on-failure`: run a
  focused unit test.

Prefer targeted test runs while iterating, then run the full enabled suite
before closing changes that touch shared code or public APIs.

## Coding Style & Naming Conventions
- Follow the existing Apache-style C conventions used in this repository.
- Use 4-space indentation and keep lines readable; avoid unnecessary wrapping.
- Always use braces for `if/else/while/do` blocks.
- Put function opening braces on the next line:
  `int fn(void)\n{ ... }`
- Declare variables at the start of functions, not mid-block.
- Prefer descriptive `snake_case` names with the `cfl_` prefix for public APIs.
- Use `CFL_TRUE` and `CFL_FALSE` for CFL boolean-style return values.
- Use `/* ... */` comments, and add comments only where they clarify non-obvious
  behavior.
- Keep public headers self-contained by including the standard headers they need.

## Testing Guidelines
- Add or update acutest unit coverage for behavior changes.
- Keep tests close to the affected module and name test binaries through
  `tests/CMakeLists.txt`.
- Validate both success and failure paths for parsers, containers, allocation
  handling, and boundary conditions.
- Run broader coverage when changing shared headers, CMake wiring, memory
  ownership, or common data structures.
- If a relevant test cannot be run, report the exact blocker in the final
  response.

## Commit & Pull Request Guidelines
- Follow observed local history style:
  `component: short imperative description`
  Examples: `sds: do not export internal sds_alloc function`,
  `build: bump to v0.6.2`, `atomic: add atomic operations API`.
- Keep each commit scoped to one component or interface.
- Keep subject/body lines concise; use a body when the reason or scope is not
  obvious from the subject.
- Do not mix unrelated code and documentation updates in one commit unless the
  user explicitly asks for a combined commit.
- Do not rewrite history, amend commits, create remote branches, or open pull
  requests unless explicitly requested.

## Agent Action Limits
- Do not modify repositories or files outside this project unless the user
  explicitly asks.
- Do not revert user changes outside the requested scope.
- Preserve unrelated untracked or modified files in the worktree.
- Prefer minimal patches that avoid unrelated formatting or refactoring churn.
