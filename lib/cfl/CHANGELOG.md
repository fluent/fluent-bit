# Changelog

This file records the notable changes in each CFL release.

## Unreleased

- Added public request-lifetime arena allocation, duplication helpers,
  allocator callbacks, and optional bounded geometric chunk growth.

## 1.0.0 - 2026-07-11

The first stable CFL release establishes the variant, container, utility, and
optional arena interfaces used by Fluent Bit and its companion telemetry
libraries.

### Highlights

- Added optional arena allocation for strings, variants, arrays, and key/value
  lists, including reset, cache control, ownership validation, benchmarks, and
  lifecycle documentation.
- Added case-sensitive and case-insensitive key/value lookup variants.
- Strengthened container ownership and cycle validation for mutable variant
  graphs.
- Improved allocation failure handling and made dynamic-string formatting
  preserve the original value when growth fails.
- Improved portability across GNU C99 and GNU C17, ARM64, Windows, macOS, and
  supported Linux environments.
- Expanded sanitizer, Valgrind, installed-consumer, and downstream validation
  for Fluent Bit, cmetrics, ctraces, and cprofiles.
- Installed the bundled xxHash archive with its headers so installed consumers
  can use CFL's public hash interface.

### Behavior changes

- `cfl_array_remove_by_reference()` now returns `-1` when the supplied variant
  is not present in the array.
