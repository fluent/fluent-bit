# Chunk allocation and growth

`cio_chunk_open(..., size, ...)` treats `size` as initial capacity, not a
content length or maximum chunk size. New or empty filesystem chunks reserve
`max(size, CIO_FILE_HEADER_MIN)`, rounded to a page. This capacity includes the
file header and subsequent metadata. Memory chunks reserve `size` content bytes;
their metadata is separate.

Nonempty files keep their existing size, including when reopened read-only or
loaded as backlog. A deferred open retains its hint until the first successful
mapping, but uses an existing file's size if that file appears before mapping.
If reserving or mapping a valid filesystem hint fails, creation retries with
one page. Unrepresentable hints on new files return an error.

## Adaptive growth

Adaptive growth is enabled by default, including when callers assign their own
`options.flags` or create a context with `cio_create(NULL)`. To explicitly retain
the previous fixed growth policy:

```c
struct cio_options options;

cio_options_init(&options);
options.flags |= CIO_FIXED_GROWTH;
```

Growth is computed independently for each chunk, only when an append exceeds
its capacity. The increment is:

```
max(configured_realloc_step, min(current_capacity / 2, 256 KiB))
```

The allocation covers the entire append in one resize, rounding up by that
increment, then to a page for filesystem storage. Explicit reallocation hints
larger than 256 KiB retain their configured size. There is no stream-level
learning or interpretation of metadata, tags, routes, or record contents.
Trimming reduces the capacity used by the next growth calculation.

If optional headroom cannot be allocated, adaptive writes retry with just the
required capacity (page-rounded for filesystem storage). Failed appends leave
content length and checksum state unchanged. Unix mapping failures retain the
old mapping and attempt to undo the disk reservation. If undoing that reservation
also fails, the larger file size remains visible in accounting and projection.

## Consumer accounting

`cio_chunk_get_projected_size(chunk, append_bytes, &capacity)` returns an upper
bound on capacity after an append. The chunk must be up. Filesystem results
include the header, metadata, and any outstanding disk reservation; memory
results describe the content buffer. An allocation fallback can use less space.
Errors leave the output argument unchanged. Serialize projection and append
with other mutations, including metadata changes and trimming.

The sibling Fluent Bit implementation in `src/flb_input_chunk.c` currently
predicts fixed growth from ChunkIO's leading allocation fields. Those fields
retain their offsets, and fixed growth retains that calculation. Fluent Bit
must adopt the projection API when updating to this version, or explicitly set
`CIO_FIXED_GROWTH` until that integration is complete. Otherwise its output
storage limits could underestimate the new default growth. For a new chunk, budget
the entire projected size; for an already accounted chunk, budget its positive
increase over the previously accounted size.

**Honoring the opening hint has a cost for tiny chunks.** Fluent Bit currently
requests 256 KiB: a one-page chunk can therefore reserve 64 times as much space
on a system with 4 KiB pages. Many low-volume tags can increase disk usage and
creation cost even with adaptive growth disabled. Callers should select smaller
hints for that workload. A hint of zero retains minimum initial allocation.
This change does not alter the on-disk format.

## Verification

`tests/allocation.c` covers both backends and both growth policies, checksums
on/off, full sync, arbitrary reallocation steps, large single appends, maximum
metadata, overflow boundaries, zero-byte truncation, transaction rollback,
read-only and corrupt-file reopen, backlog loading, deferred creation, trim and
regrowth, and independence between hot and cold chunks. Fixed-growth expectations
use the consumer's existing increment calculation; projected capacity is checked
against actual allocation after each successful write.

Linux linker wrappers inject reservation, mmap/mremap, stat, and realloc errors.
Tests check retry, content preservation, counters, descriptor cleanup, minimal
allocation fallback, failed writes at offsets, and failure to undo a reservation.
These failure-injection cases are not compiled on Windows or macOS.

The tests exposed two surrounding bugs, fixed alongside allocation: failed
offset writes retained a shortened length, and checksum-disabled transaction
rollback did not persist the restored length. The PR also persists the logical
length when truncating through zero-byte writes and when syncing a rollback.
These changes are tested directly against upstream master; the separate local
checksum-recovery commits are not included.

All seven suites passed on Linux x86-64 with GCC, strict Valgrind, and Clang
AddressSanitizer/UndefinedBehaviorSanitizer. The legacy Acutest callback function
type check is excluded (`-fno-sanitize=function`); address, leak, and other UB
checks remain enabled. Tests use `--exec=never` for sanitizer/Valgrind execution.
The portable Unix mmap replacement path was also forced in an isolated Linux
source copy and passed all seven suites. This does not establish Windows/macOS
runtime compatibility. Full Fluent Bit tail pipelines are now compared against
the PR base; see the [consumer benchmark](../tools/benchmarks/fluent_bit/README.md)
for configurations, raw results, correctness checks, and limits.

## Fluent Bit benchmarks

The [planned caller-policy comparison](../tools/benchmarks/caller_allocation/README.md)
models append-sized creation, reuse according to `flb_input_chunk.c`, and default
adaptive growth before the policy is ported to Fluent Bit. It compares previous
ChunkIO, the current 256 KiB hint, and the planned append-sized hint across sparse,
busy, mixed, large-first-append, and reopen workloads. It is a storage simulation,
not an already implemented Fluent Bit change.

The [Fluent Bit consumer benchmark](../tools/benchmarks/fluent_bit/README.md) is
the performance comparison for the current Fluent Bit integration. It measures
finite-file tail ingestion,
many tags, output backpressure, and a memory-storage control. It reports CPU,
ingestion rate, RSS, and allocated disk space, with exact record-count checks
and HTTP payload validation during recovery.

## Supporting allocation microbenchmark

On Linux with GCC or Clang, build a release library and the standalone harness
without `-DNDEBUG` (the harness checks every operation):

```sh
cmake -S . -B /tmp/cio-release -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/cio-release -j8
cc -O3 -Iinclude -Ideps -Ideps/monkey/include -I/tmp/cio-release/include \
  tools/cio_bench_allocation.c /tmp/cio-release/src/libchunkio-static.a \
  /tmp/cio-release/deps/crc32/libcio-crc32.a \
  -Wl,--wrap=cio_file_native_remap -Wl,--wrap=realloc \
  -o /tmp/cio-bench-allocation
/tmp/cio-bench-allocation fs 100 2048000 1024 262144 0 1
/tmp/cio-bench-allocation fs 100 2048000 1024 262144 1 1
```

Arguments are backend, chunk count, bytes per chunk, append batch, opening hint,
adaptive flag, and checksum flag. The harness verifies payload and metadata
after down/up. It can also link against the original library for comparison.

The PR description retains the allocation microbenchmarks as supporting
diagnostics. Use the consumer measurements above when assessing Fluent Bit
impact: isolated append/lifecycle timings do not translate directly into
pipeline throughput, CPU use, or disk footprint.
