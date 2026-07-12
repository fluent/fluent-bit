# CFL

CFL is a compact C library of data structures and low-level utilities used by
[Fluent Bit](https://fluentbit.io/) and its companion telemetry libraries. It
provides dynamic strings, intrusive lists, typed variants, arrays, key/value
containers, hashing, checksums, atomics, and an optional arena allocator.

CFL started as a C library for Fluent Bit, a.k.a. `C:\Floppy`.

The library is designed to be embedded. Callers can include the complete public
interface with:

```c
#include <cfl/cfl.h>
```

Individual headers under `include/cfl/` can be used when a component needs a
smaller interface.

## Highlights

- Small C API with no required runtime framework.
- Typed recursive values through `cfl_variant`, `cfl_array`, and `cfl_kvlist`.
- Length-aware dynamic strings through `cfl_sds`.
- Intrusive lists and lightweight string key/value entries.
- Portable 64-bit atomics and time helpers.
- xxHash wrappers and CRC32C checksums.
- Optional arenas for allocation-heavy, bounded object graphs and arbitrary
  request-lifetime objects.
- CMake support for embedding, installation, tests, and benchmarks.

## Core data structures

| Interface | Purpose |
| --- | --- |
| `cfl_sds` | Growable binary-safe strings with explicit length and capacity |
| `cfl_list` | Intrusive doubly linked lists and safe iteration helpers |
| `cfl_kv` | String key/value entries stored in a CFL list |
| `cfl_variant` | Tagged bool, integer, double, null, reference, string, bytes, array, or map value |
| `cfl_array` | Ordered collection of variants |
| `cfl_kvlist` | String-keyed map of variants |
| `cfl_object` | Generic wrapper for a variant, array, or key/value list |
| `cfl_arena` | Optional shared allocator for bounded CFL object graphs |

Heap-backed constructors remain the default. Applications that construct and
discard complete variant graphs can opt into `cfl_arena`; see
[ARENA.md](ARENA.md) for its ownership model, API, examples, and tuning advice.

## Utility interfaces

- `cfl_atomic`: 64-bit compare-exchange, store, and load operations with
  platform-specific backends.
- `cfl_time`: wall-clock timestamps in nanoseconds.
- `cfl_hash`: xxHash 64-bit and 128-bit wrappers.
- `cfl_checksum`: CRC32C checksums.
- `cfl_utils`: string splitting, including quote-aware parsing.
- `cfl_log`: runtime error-reporting helpers.
- `cfl_compat`, `cfl_found`, and `cfl_info`: platform and build integration.

## Build

CFL requires CMake 3.20 or newer and a C compiler:

```sh
cmake -S . -B build
cmake --build build -j8
```

To build and run the unit tests:

```sh
cmake -S . -B build -DCFL_TESTS=On
cmake --build build -j8
ctest --test-dir build --output-on-failure
```

Useful configuration options are:

| Option | Default | Description |
| --- | --- | --- |
| `CFL_DEV` | `No` | Enable the debug development configuration and tests |
| `CFL_TESTS` | `No` | Build unit and public-header tests |
| `CFL_BENCHMARKS` | `No` | Build allocation and mutation benchmarks |
| `CFL_INSTALL_BUNDLED_XXHASH_HEADERS` | `Yes` | Install bundled xxHash headers |

For arena performance and memory comparisons, see
[benchmarks/README.md](benchmarks/README.md).

## Embedding with CMake

Projects commonly embed CFL with `add_subdirectory` and link the static target:

```cmake
add_subdirectory(path/to/cfl)
target_link_libraries(my_target PRIVATE cfl-static)
```

Applications using installed headers can include either `<cfl/cfl.h>` or the
specific module headers they require.

## API conventions

- Public functions and types use the `cfl_` prefix.
- Constructors return `NULL` when allocation or validation fails.
- Container insertion functions report success or failure and document when
  ownership transfers to the container.
- Heap-created values are destroyed through their matching CFL destroy APIs.
- Arena-created values are invalidated together by arena reset or destruction.
- An arena is not thread-safe; access to a shared arena must be serialized.

## Documentation

- Release history: see [CHANGELOG.md](CHANGELOG.md) for notable changes in each
  version.
- Public API: the self-contained headers under [`include/cfl/`](include/cfl/)
  describe each supported interface.
- Building and embedding: see the build and CMake examples above.
- Testing: enable `CFL_TESTS` and run the suite through CTest as shown above.
- Optional arena allocation: see [ARENA.md](ARENA.md) for lifecycle and
  ownership rules.
- Performance tools: see [benchmarks/README.md](benchmarks/README.md) for the
  supplied benchmark programs and measurement guidance.

## License

CFL is distributed under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Authors

Copyright is assigned to the CFL Authors. The contributor list is available on
[GitHub](https://github.com/fluent/cfl/graphs/contributors).
