# CMetrics repository guide

This is the canonical, vendor-neutral operating guide for automated tools and
human contributors. Tool-specific files must point here instead of duplicating
project rules.

## Project role

CMetrics is a standalone C library for creating, mutating, aggregating,
encoding, and decoding metrics contexts. It is consumed by downstream projects,
including Fluent Bit, so changes can affect public C APIs and serialized data.

## Repository map

- `include/cmetrics/`: installed public headers; treat layout and declarations
  as compatibility-sensitive.
- `src/`: metric implementations, map/index ownership, filters, and codecs.
- `tests/`: Acutest unit tests, one CTest executable per source file.
- `benchmarks/`: opt-in benchmark executable and Linux `perf stat` runner.
- `docs/`: design and behavior notes; agent-neutral workflows are in `docs/ai/`.
- `cmake/`, `CMakeLists.txt`: build, dependency, install, and packaging rules.
- `lib/cfl`: CFL Git submodule; owns containers, SDS strings, arenas, and
  supporting primitives.
- `lib/fluent-otel-proto`: generated OpenTelemetry protobuf support submodule.
- `.github/workflows/`: compiler/platform builds, tests, linting, and packages.

Start architecture investigation at `include/cmetrics/cmetrics.h`, the
metric-specific public header, and its matching `src/cmt_*.c` implementation.
For encoding or decoding, follow the corresponding `cmt_encode_*` or
`cmt_decode_*` pair and its tests. See `docs/architecture.md` for the component
map and `docs/dependencies.md` for repository boundaries.

## Dependency boundaries

Initialize submodules before building:

```sh
git submodule update --init --recursive
```

Changes owned by CFL or fluent-otel-proto should normally land in their source
repository first, then update the CMetrics submodule revision separately.
Validate CMetrics standalone before updating a downstream consumer such as
Fluent Bit. See `docs/ai/cross-repository.md` and
`docs/ai/dependency-update.md`.

## Build and test

The supported build system is CMake 3.20 or newer. Local builds require Git, a
C compiler, and the initialized submodules. Flex 2 and Bison 3 enable the
Prometheus text decoder and its tests; CMake omits that decoder if they are not
found. A normal development build:

```sh
cmake -S . -B build/agent -DCMT_TESTS=On -DCMT_INSTALL_TARGETS=Off
cmake --build build/agent
ctest --test-dir build/agent --output-on-failure
```

Repository wrappers provide the same flow:

```sh
scripts/agent-build.sh
scripts/agent-test.sh
scripts/agent-verify.sh
```

Use `BUILD_DIR=/path` to select another build directory. Pass extra CMake
configuration arguments to `agent-build.sh`. Pass a CTest regular expression
to `agent-test.sh`, for example:

```sh
scripts/agent-test.sh '^cmt-test-opentelemetry$'
```

When making code changes, run the related unit test when one is available.
Before handoff, run `scripts/agent-verify.sh` unless the change is documentation
only or the environment cannot build the project; report any omitted check.

There is no repository-defined C formatter or C static-lint command. Preserve
the surrounding four-space, no-tab style. Shell changes must pass `sh -n`; CI
also runs ShellCheck. Do not claim sanitizer coverage unless the binary was
actually compiled and executed with the requested sanitizer.

## Memory and ownership

- Check every allocation and preserve cleanup for partial initialization.
- Match allocation families (`malloc`/`free`, CFL SDS create/destroy, arena
  lifetime) and make ownership transfers explicit in code structure.
- Exercise failure and cleanup paths for codec and container changes.
- Treat map mutation, metric indexing, expiration, and destruction as
  concurrency-sensitive.
- Use AddressSanitizer or Valgrind for ownership changes; follow
  `docs/ai/memory-safety-review.md`.

## Compatibility-sensitive changes

- Public declarations under `include/cmetrics/` can affect source or ABI
  compatibility. Avoid changing established public structure layout without
  explicit review of downstream users.
- Internal MessagePack, OTLP protobuf, Prometheus formats, and remote write are
  wire-sensitive. Add round-trip and malformed-input coverage where relevant.
- Preserve integer value types, timestamps, start timestamps, label ordering,
  and metric identity unless the change intentionally revises their contract.
- Decoders process untrusted lengths and values: prevent overflow, oversized
  allocation from incomplete input, desynchronization, and partial-result leaks.

## Generated and vendored content

- Do not edit CMake-generated `include/cmetrics/cmt_info.h` or
  `include/cmetrics/cmt_version.h`; edit their `.in` templates or CMake version.
- Flex/Bison outputs are generated in the build directory from
  `src/cmt_decode_prometheus.l` and `.y`; edit the grammar sources.
- Files marked generated under `src/external/` and
  `include/prometheus_remote_write/` must be regenerated from their source
  schema/toolchain, not hand-edited.
- Do not edit submodule contents as part of a CMetrics-only change. Make the
  change in the owning repository and update the recorded revision.
- Build outputs and generated payloads do not belong in commits unless an
  existing tracked fixture is intentionally updated and reviewed.

## Performance changes

Build benchmarks with `CMT_BENCHMARKS=ON` and an optimized Release build. Use
`benchmarks/run-perf.sh` for standard workloads and Linux hardware counters.
Capture at least five before and five after runs on the same machine with
identical compiler flags and workload parameters. Keep only repeatable gains
with no relevant regression. See `docs/ai/performance-review.md`.

## Change discipline and definition of done

- Keep changes scoped; preserve unrelated user work and avoid drive-by cleanup.
- Add a regression test for a bug when practical.
- Verify every documented command against repository files before adding it.
- Review error paths, compatibility, generated files, and dependency ownership.
- Run targeted tests plus the strongest practical complete validation.
- Report root cause or intent, files changed, exact checks, compatibility
  impact, unresolved risks, and anything not validated.

Detailed workflows:

- `docs/ai/investigate.md`
- `docs/ai/bug-fix.md`
- `docs/ai/code-review.md`
- `docs/ai/cross-repository.md`
- `docs/ai/dependency-update.md`
- `docs/ai/memory-safety-review.md`
- `docs/ai/performance-review.md`
