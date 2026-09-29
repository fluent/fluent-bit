# CTraces repository guide

This is the canonical operating guide for humans and coding agents working in
CTraces. Tool-specific files may point here but must not redefine these rules.

## Project role

CTraces is a C library for constructing trace contexts and encoding or decoding
them as the library's MessagePack representation, text, or OpenTelemetry
protobuf. Fluent Bit consumes this library, so changes can affect a larger
downstream runtime.

## Repository map

- `include/ctraces/`: public headers and public data structures.
- `src/`: lifecycle, IDs, resources, scopes, spans, attributes, logging, and
  format encoders/decoders.
- `tests/`: Acutest-based unit and round-trip tests registered with CTest.
- `examples/`: small API and OpenTelemetry examples, built by `CTR_DEV`.
- `cmake/`: dependency paths and CMake helper macros.
- `lib/cfl`: pinned CFL submodule used for variants and containers.
- `lib/fluent-otel-proto`: pinned OpenTelemetry protobuf C bindings.
- `lib/mpack`: vendored MPack source.
- `.github/workflows/`: platform, lint, package, and release automation.
- `docs/ai/`: detailed investigation and change workflows.

Start architecture work at `include/ctraces/ctraces.h`, then follow the owning
public header into the matching `src/ctr_*.c` file. Encoding changes begin at
`ctr_encode_*`; parsing and input validation begin at `ctr_decode_*`.

## Dependencies and downstream use

Dependency direction is CTraces -> CFL, fluent-otel-proto, and MPack. These
dependencies do not own CTraces lifecycle or wire-format behavior. Fluent Bit
is the verified downstream consumer.

Do not edit files inside a submodule for a CTraces-only change. Land a change in
the owning dependency first, update its pinned revision separately, validate
the standalone dependency, and then validate CTraces and Fluent Bit. Follow
[`docs/ai/cross-repository.md`](docs/ai/cross-repository.md).

## Build and test

Initialize dependencies once:

```sh
git submodule update --init --recursive
```

Canonical development build:

```sh
scripts/agent-build.sh
```

Run the full test suite after building:

```sh
scripts/agent-test.sh
```

Run a targeted CTest selection:

```sh
scripts/agent-test.sh -R ctr-test-span
scripts/agent-test.sh -R ctr-test-opentelemetry
```

Run the complete local verification wrapper:

```sh
scripts/agent-verify.sh
```

The wrappers use `build/agent/` by default. Set `CTR_BUILD_DIR` to select a
different out-of-source directory. Direct equivalents are:

```sh
cmake -S . -B build/agent -DCTR_DEV=On -DCTR_TESTS=On
cmake --build build/agent --parallel
ctest --test-dir build/agent --output-on-failure
```

Windows CI uses `scripts/win_build.bat`. Packaging is exercised by
`.github/workflows/packages.yaml`; it is not part of routine local verification.

## Lint and analysis

Check repository shell scripts locally with:

```sh
bash -n scripts/agent-build.sh scripts/agent-test.sh scripts/agent-verify.sh
```

CI runs ShellCheck and actionlint. The repository does not currently provide a
formatter, static-analysis target, working sanitizer preset, Valgrind target,
fuzzer, or CTraces benchmark. Do not claim those checks ran unless a concrete
command was added and executed. CFL's benchmarks are dependency-local, not
CTraces benchmarks.

## Correctness and compatibility

- Treat `include/ctraces/` as public API. Avoid gratuitous signature, struct
  layout, enum value, or ownership changes.
- Preserve create/destroy pairing and list ownership. Audit allocation failure,
  partial initialization, unlinking, and cleanup paths together.
- A `ctrace` owns its linked resources and spans. Direct child destruction must
  leave owner lists valid and make later parent destruction safe.
- Encoders and decoders are compatibility-sensitive. Preserve field meaning,
  integer widths, IDs, flags, ordering where output comparisons depend on it,
  and rejection of malformed or incomplete input.
- OpenTelemetry changes must be checked against the pinned generated bindings;
  do not hand-edit generated protobuf sources in the submodule.
- Exercise null, empty, truncated, duplicate, invalid-enum, oversized, and
  allocation/error cleanup cases when they are relevant to the change.
- Keep compiler portability covered by CMake and CI in mind, including MSVC and
  the CentOS 7 GCC build.

## Generated and vendored files

`include/ctraces/ctr_info.h` and `include/ctraces/ctr_version.h` are generated
from their `.in` templates during configuration and are ignored by Git. Modify
the templates or CMake inputs, not generated copies. Do not make incidental
changes under `lib/`; update pinned submodules or vendored MPack only when the
task explicitly owns that dependency change.

## Change discipline

- Keep changes in the owning subsystem and avoid unrelated cleanup.
- Preserve existing user changes and untracked files.
- Add a focused regression test for behavior changes when practical.
- Use the existing commit prefix for the touched interface when history makes
  it clear; examples include `core:`, `span:`, `decode_msgpack:`, `tests:`, and
  `workflows:`.
- Do not infer compatibility promises or release procedures absent from the
  repository.

## Definition of done

A change is complete when its owning code path is understood, compatibility and
ownership effects are accounted for, focused tests cover the changed behavior,
`scripts/agent-verify.sh` passes, and the final report states validation and any
remaining downstream risk. Cross-repository changes also require standalone
dependency validation and final Fluent Bit integration validation.

Detailed workflows:

- [`docs/ai/investigate.md`](docs/ai/investigate.md)
- [`docs/ai/bug-fix.md`](docs/ai/bug-fix.md)
- [`docs/ai/code-review.md`](docs/ai/code-review.md)
- [`docs/ai/cross-repository.md`](docs/ai/cross-repository.md)
