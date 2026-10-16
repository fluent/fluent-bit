# Repository dependencies

## Build dependencies

- CMake 3.20 or newer configures the project.
- A platform C compiler builds the static library and tests.
- Flex 2 and Bison 3 generate the optional Prometheus text decoder.
- CTest runs the Acutest executables registered by `tests/CMakeLists.txt`.
- Linux `perf` is required only for the standard hardware-counter benchmarks.

## Repository relationships

CMetrics records two Git submodules:

- `lib/cfl` → `fluent/cfl`: containers, SDS strings, variants, arenas, hashes,
  atomic helpers, and other foundational C utilities.
- `lib/fluent-otel-proto` → `fluent/fluent-otel-proto`: generated OpenTelemetry
  protobuf-C definitions and runtime integration used by the OTLP codec.

The top-level build can use system-detected copies of these libraries; otherwise
it builds the recorded submodules. Behavior owned by either dependency should
be fixed and validated there before updating the CMetrics gitlink.

Fluent Bit is an evidenced downstream consumer of CMetrics. It is not part of
this source tree, so consumer integration validation must use a separate Fluent
Bit checkout with the intended CMetrics revision. A normal landing order is:

1. Land and validate a dependency change in its owning repository.
2. Update and validate CMetrics against that dependency revision.
3. Update the CMetrics revision or bundled copy in the downstream consumer.
4. Run the consumer's focused integration tests and applicable CI checks.

Keep commits and pull requests separate per repository so each project can be
built, reviewed, and reverted independently.
