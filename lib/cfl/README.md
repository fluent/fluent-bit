# CFL

CFL is a tiny C library that provides small data-structure and utility
interfaces. It was originally created to satisfy the needs of Fluent Bit and
related libraries such as CMetrics and CTraces.

Note: The name does not mean anything specific; you can call it `c:\ floppy`
if you want.

## Interfaces

Applications can include `<cfl/cfl.h>` to pull in the common CFL interfaces.
Specialized headers are also available under `include/cfl/` when a caller only
needs one module.

### Core

- `cfl_init()`: initializes library-level facilities.
- `cfl_version()`: returns the CFL version string.
- `CFL_TRUE` and `CFL_FALSE`: common boolean-style constants used by CFL APIs.

### Data Structures

- `cfl_sds`: dynamic string storage with explicit length and allocation
  tracking. It supports creation from strings or buffers, growth, concatenation,
  formatted writes, length updates, and destruction.
- `cfl_list`: intrusive doubly linked list helpers. It provides initialization,
  add, append, prepend, delete, concatenate, size, entry lookup, and safe
  iteration macros.
- `cfl_kv`: SDS-backed string key/value entries stored in a `cfl_list`. This is
  useful for simple string maps where values are plain strings.
- `cfl_variant`: tagged value container for bool, signed integer, unsigned
  integer, double, null, reference, string, bytes, array, and key/value list
  values.
- `cfl_array`: ordered collection of `cfl_variant` entries. It supports fixed
  or resizable arrays, append helpers for all variant types, fetch by index,
  removal, size inspection, and printing.
- `cfl_kvlist`: string-keyed map whose values are `cfl_variant` instances. It
  supports typed insert helpers, size-aware key APIs, fetch, contains, remove,
  count, and printing.
- `cfl_object`: generic wrapper that can hold a `cfl_kvlist`, `cfl_variant`, or
  `cfl_array` and print the associated value.

### Utilities

- `cfl_atomic`: 64-bit atomic initialization, compare-exchange, store, and load
  operations with platform-specific backends.
- `cfl_time`: wall-clock timestamp helper that returns nanoseconds.
- `cfl_hash`: naming wrappers around xxHash 64-bit and 128-bit hashing APIs.
- `cfl_checksum`: CRC32C checksum helper.
- `cfl_utils`: string split helpers, including quote-aware splitting, with
  results returned as `cfl_list` entries.
- `cfl_log`: runtime error reporting helpers.

### Support Headers

- `cfl_compat`: platform compatibility macros.
- `cfl_found`: lightweight include-probe helper for parent projects.
- `cfl_info`: generated build information and feature flags.
- `cfl_version`: version macros.

## Build and Test

```sh
cmake -S . -B build -DCFL_TESTS=On
cmake --build build -j8
ctest --test-dir build --output-on-failure
```

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

Copyright is assigned to the `CFL Authors`, you can see a list of contributors [here](https://github.com/fluent/cfl/graphs/contributors).
