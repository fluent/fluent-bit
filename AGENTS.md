# Repository Guidelines

## Preferred Commands
- Configure: `cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On`
- Build: `cmake --build build -j8`
- Test: `ctest --test-dir build --output-on-failure`
- Prefer targeted tests with `ctest --test-dir build -R <name> --output-on-failure`
  when the affected area is known, because the full enabled suite can be slow.
- Run a focused integration test with
  `ctest --test-dir build -R flb-it-opentelemetry --output-on-failure`
- Run the in-tree Python integration suite with:
  `cd tests/integration && ./setup-venv.sh && ./run_tests.py`
- List available Python integration scenarios with:
  `cd tests/integration && ./run_tests.py --list`
- Run locally with `./build/bin/fluent-bit -c conf/fluent-bit.conf`

## Project Structure & Module Organization
Fluent Bit is a C/C++ monorepo built with CMake.

- `src/`: core engine/runtime (`flb_*` components, schedulers, routing, I/O).
- `include/fluent-bit/`: public/internal headers used by core and plugins.
- `plugins/`: input/filter/processor/output plugins (`in_*`, `filter_*`, `processor_*`, `out_*`).
- `lib/`: bundled libraries (e.g., `cprofiles`, `ctraces`, `cmetrics`, `chunkio`).
- `tests/`: integration/runtime tests and fixtures.
- `tests/integration/`: in-tree Python integration test suite for end-to-end
  plugin and protocol validation; introduced from the original
  `github.com/fluent/fluent-bit-test-suite` project.
- `conf/`: sample configurations for local validation.

Keep changes scoped: plugin logic in its plugin directory, shared behavior in `src/` or `lib/`.

## Build, Test, and Development Commands
- `cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On`: configure with runtime + internal tests.
- `cmake --build build -j8`: compile Fluent Bit and tests.
- `ctest --test-dir build --output-on-failure`: run enabled tests.
- `ctest --test-dir build -R flb-it-opentelemetry --output-on-failure`: run a focused integration test.
- `cd tests/integration && ./setup-venv.sh`: create the local virtualenv for
  the Python integration suite.
- `cd tests/integration && ./run_tests.py --list`: list available Python
  integration scenarios.
- `cd tests/integration && ./run_tests.py`: run the full Python integration
  suite against `build/bin/fluent-bit`.
- `cd tests/integration && FLUENT_BIT_BINARY=/path/to/fluent-bit ./run_tests.py`:
  run the Python integration suite against a specific binary.
- `./build/bin/fluent-bit -c conf/fluent-bit.conf`: run locally with a config.

## Coding Style & Naming Conventions
- Follow Apache-style C conventions used by Fluent Bit.
- Use 4-space tabs/indentation and target 100 chars per line; 120 chars max.
- Always use braces for `if/else/while/do` blocks.
- Put function opening braces on the next line:
  `int fn(void)\n{ ... }`
- Keep short boolean conditions on one line when they fit within 100 chars.
- Wrap conditions only when needed, and break at logical operators (`&&`, `||`);
  do not force one operand per line when readability does not improve.
- Keep short function calls on one line when they fit; avoid splitting each
  argument into separate lines unless line length or clarity requires it.
- Declare variables at the start of functions, not mid-block.
- Prefer descriptive `snake_case` for functions/variables and `flb_*`/`cprof_*` prefixes.
- Use `/* ... */` comments (single or multiline), with wrapped long comments.

## Testing Guidelines
- Add or update tests for behavior changes, especially protocol parsing and encoder/decoder paths.
- Prefer targeted tests close to the changed module (`tests/internal`, plugin runtime tests).
- Prefer focused `ctest -R ...` runs or specific test binaries when the touched area is known.
- Use `tests/integration` when validating end-to-end plugin behavior, network
  protocols, downstream request generation, or local fake-server interactions
  that are awkward to cover in `ctest` binaries alone.
- The Python integration suite is not part of the default CMake `ctest` targets;
  run it explicitly from `tests/integration`.
- Run broader test coverage when changing shared lifecycle, routing, storage, or accounting code.
- Validate both success and failure paths (invalid payloads, boundary sizes, null/missing fields).
- You can also run specific binaries from `build/bin` (e.g., `./bin/flb-it-opentelemetry`).
- Keep generated integration artifacts out of git. Do not commit
  `.venv/`, `.pytest_cache/`, `results/`, or `__pycache__/` under
  `tests/integration`.

## Commit & Pull Request Guidelines
- Prefix commit subjects with the component/plugin name in lowercase, e.g.:
  - `engine: fix flush buffer handling`
  - `in_opentelemetry: profiles: fix ingestion path`
- Keep subject/body lines <= 80 chars.
- Keep each commit scoped to one component/prefix; avoid mixed-area commits.
- Sign commits with DCO: `git commit -s`.
- PRs should include: problem statement, scope, test evidence (`ctest` output), and compatibility notes.
- If behavior changes user output/config, include a short before/after example.
- Target `master` for next major by default; open backport PRs to release branches (`1.x`) when needed.

## Commit Pattern (Branch Practice)
- Follow observed local history style:
  - component/plugin: `component: short imperative description`
  - internal tests: `tests: internal: short imperative description`
  - runtime tests: `tests: runtime: short imperative description`
- Keep one interface per commit. If an interface touches both `.c` and `.h`,
  commit them together in the same commit.
- Do not mix unrelated interfaces in one commit.
- Prefer concise one-line subjects unless extra context is required.

## Agent Action Limits
- Do not open issues, pull requests, or remote branches unless the user explicitly asks.
- Do not rewrite git history, amend commits, or force-push unless the user explicitly asks.
- Do not revert user changes outside the requested scope.
- Prefer minimal patches that avoid unrelated formatting or refactoring churn.

## Agent Playbook (Pipeline Architecture Primer)

### Runtime model (mental map)
- Fluent Bit moves data through: input -> chunk -> router -> task ->
  filter/processor -> output -> engine result handling.
- Routing is per output instance; one chunk can fan out to many routes.
- Route state is independent (success/retry/drop can differ per output).

### Data units and boundaries
- A **signal** is the high-level type: logs, metrics, traces, profiles, blobs.
- A **record/event** is the logical payload unit inside a signal.
- A **chunk** is the persisted/queued container (often MessagePack-backed).
- A **task** is the engine execution unit for a chunk across routes.
- Never assume "one chunk = one route" or "one serialized event = one log
  record" in shared code.

### Component responsibilities
- Inputs (`plugins/in_*`) create/append data and trigger ingestion.
- Input chunk layer (`src/flb_input_chunk.c`) manages lifecycle, routing masks,
  storage pressure, and drop/release behavior.
- Router (`src/flb_router*.c`) resolves tag/signal matches to outputs.
- Task layer (`src/flb_task.c`) tracks per-route state and retries.
- Filters (`plugins/filter_*`) run on matching streams before output flush.
- Processors (`plugins/processor_*`) can run in input/output contexts depending
  on configuration and may mutate/drop payloads.
- Outputs (`plugins/out_*`) serialize/protocol-encode and return flush result.
- Engine (`src/flb_engine.c`) applies final retry/drop accounting and task
  teardown.

### Signal-aware behavior rules
- Shared paths must branch correctly by `event_type` (logs vs non-logs).
- Some logic is meaningful only for logs (record-level semantics), while
  metrics/traces/profiles/blobs may follow different serialization/counting.
- Group/metadata markers can exist as serialized events; treat them as
  transport/data-shape artifacts unless the interface explicitly requires them.

### Counting and metrics guidance
- Separate these concepts when reviewing code:
  - serialized events in a buffer
  - logical records after processing
  - per-route processed/retry/drop counters
  - byte accounting (chunk bytes vs route-effective bytes)
- Prefer route-aware values when updating route metrics.
- Preserve explicit zero values; use clear sentinel values for "unknown".

### Retry/drop semantics
- `FLB_OK`: route succeeded.
- `FLB_RETRY`: route keeps task/chunk for retry scheduling.
- `FLB_ERROR`: route failure/drop path.
- Final chunk release happens only when all active routes are resolved.

### Storage/backlog interaction
- In-memory and filesystem backlog paths may use different code paths; validate
  both when touching chunk/task lifecycle.
- Backlog-loaded chunks must preserve route state and accounting parity with
  live-ingested chunks.

### Review checklist before patching
- Trace one full path for affected signals: input -> chunk -> task -> output ->
  engine completion.
- Verify fan-out behavior (single chunk, multiple outputs).
- Verify processing behavior (drop/modify/no-op) in both input and output
  processor contexts.
- Verify empty payload behavior (outputs should not crash on zero records).
- Verify metrics/counters for success, retry, and drop paths.

### Testing strategy
- Use `tests/internal` for core lifecycle/accounting logic.
- Use `tests/runtime` for plugin-level behavior and end-to-end semantics.
- Add regression tests for:
  - mixed signals
  - processor drop/modify paths
  - multi-route fan-out
  - backlog + live ingestion parity
