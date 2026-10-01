# CTraces

CTraces is a small C library for creating and managing distributed trace data.
It provides an in-memory trace model plus encoders and decoders for:

- OpenTelemetry protobuf
- CTraces MessagePack
- human-readable text

CTraces is a core library used by [Fluent Bit](https://fluentbit.io/).

## Requirements

- a C compiler
- CMake 3.20 or newer
- Git, including submodule support
- libcurl development files when building all examples

The repository pins [CFL](https://github.com/fluent/cfl) and
[fluent-otel-proto](https://github.com/fluent/fluent-otel-proto) as Git
submodules. MPack is vendored under `lib/mpack`.

## Build

Clone the repository and its pinned dependencies:

```sh
git clone --recurse-submodules https://github.com/fluent/ctraces.git
cd ctraces
```

For an existing checkout, initialize the dependencies with:

```sh
git submodule update --init --recursive
```

Configure and build the static library and tests out of source:

```sh
cmake -S . -B build -DCTR_TESTS=On
cmake --build build --parallel
```

Available project options:

| Option | Default | Purpose |
| --- | --- | --- |
| `CTR_DEV` | `Off` | Enable a Debug build, tests, and examples |
| `CTR_TESTS` | `Off` | Build the unit tests |
| `CTR_EXAMPLES` | `Off` | Build the examples |
| `CTR_INSTALL_TARGETS` | `On` | Enable library and header installation |

To build the complete development configuration:

```sh
scripts/agent-build.sh
```

The wrapper uses `build/agent` by default. Set `CTR_BUILD_DIR` to use another
out-of-source build directory.

## Test

Run all registered tests:

```sh
ctest --test-dir build --output-on-failure
```

Or use the repository wrappers:

```sh
scripts/agent-test.sh
scripts/agent-test.sh -R ctr-test-opentelemetry
scripts/agent-verify.sh
```

`agent-test.sh` uses the build produced by `agent-build.sh`. The verification
wrapper checks the shell scripts, builds the development configuration, and
runs the complete test suite.

## Use the library

Public headers are installed under `include/ctraces`. Start with
[`ctraces.h`](include/ctraces/ctraces.h) for context lifecycle and follow the
resource, scope, span, attribute, encoder, and decoder headers for focused APIs.

[`examples/simple-c-api.c`](examples/simple-c-api.c) demonstrates construction
and cleanup of a complete trace. The other programs under [`examples/`](examples/)
show OpenTelemetry encoding and decoding.

Install a configured build with:

```sh
cmake --install build
```

## Contributing

Repository architecture, ownership rules, compatibility-sensitive areas, and
canonical validation commands are documented in [`AGENTS.md`](AGENTS.md).
Detailed investigation, bug-fix, review, and cross-repository workflows live in
[`docs/ai/`](docs/ai/).

Keep changes focused and add regression coverage for behavior changes. Public
headers and encoded formats are consumed outside this repository, particularly
by Fluent Bit.

## License

CTraces is licensed under the [Apache License 2.0](LICENSE).
