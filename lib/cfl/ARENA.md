# CFL arena allocator

`cfl_arena` is an optional allocator for CFL variants, arrays, key/value lists,
kvpairs, owned SDS strings, and arbitrary request-lifetime objects. It reduces
allocator traffic when an application constructs, mutates, and discards a
complete object graph as one unit.

The normal CFL constructors remain heap-backed. Arena use is explicit and does
not change existing callers.

## When to use an arena

An arena is a good fit when:

- many related CFL values have the same lifetime;
- the complete graph has a clear owner and reset point;
- processing finishes before the graph is reset;
- individual removals do not need to immediately return memory to the system;
- the arena can be reused across documents or batches.

Examples include a decoded document, a mutable telemetry record, or a batch
that remains owned through a processor chain and is serialized before reset.

Keep heap allocation when objects have unrelated lifetimes, children move to
longer-lived owners, memory must be reclaimed individually, or a long-lived
container experiences unbounded churn.

## Public API

Include the arena interface directly:

```c
#include <cfl/cfl_arena.h>
```

It is also included by `<cfl/cfl.h>`.

```c
struct cfl_arena;

struct cfl_arena *cfl_arena_create(size_t chunk_size);
struct cfl_arena *cfl_arena_create_ex(size_t chunk_size,
                                      size_t large_object_threshold);
void cfl_arena_options_init(struct cfl_arena_options *options);
struct cfl_arena *cfl_arena_create_with_options(
    const struct cfl_arena_options *options);
void cfl_arena_destroy(struct cfl_arena *arena);
void cfl_arena_reset(struct cfl_arena *arena);

void *cfl_arena_malloc(struct cfl_arena *arena, size_t size);
void *cfl_arena_calloc(struct cfl_arena *arena,
                       size_t count, size_t size);
void *cfl_arena_memdup(struct cfl_arena *arena,
                       const void *source, size_t size);
char *cfl_arena_strndup(struct cfl_arena *arena,
                        const char *source, size_t length);

size_t cfl_arena_bytes_reserved(struct cfl_arena *arena);
size_t cfl_arena_bytes_used(struct cfl_arena *arena);
size_t cfl_arena_large_object_threshold(struct cfl_arena *arena);

void cfl_arena_external_cache_limit_set(struct cfl_arena *arena,
                                        size_t limit);
size_t cfl_arena_external_cache_limit_get(struct cfl_arena *arena);
size_t cfl_arena_external_cache_bytes(struct cfl_arena *arena);
```

Passing zero as `chunk_size` selects the default chunk size. With
`cfl_arena_create_ex()`, a zero large-object threshold selects the default
policy derived from the chunk size.

## Raw request-lifetime allocation

Raw allocation supports objects that do not have CFL-specific constructors,
including temporary encoder trees:

```c
struct request_state *state;
char *name;

state = cfl_arena_calloc(arena, 1, sizeof(*state));
name = cfl_arena_strndup(arena, input_name, input_name_length);
if (state == NULL || name == NULL) {
    /* The arena remains valid and can still be reset or destroyed. */
}
```

Raw pointers cannot be freed individually. They remain valid until the arena
is reset or destroyed. Returned pointers are aligned for CFL-supported
fundamental C types, including `long double`, pointers, and 64-bit integers.

The raw allocation rules are:

- `cfl_arena_malloc()` returns uninitialized storage.
- `cfl_arena_calloc()` checks multiplication overflow and zeroes the result.
- `cfl_arena_memdup()` copies an exact number of bytes.
- `cfl_arena_strndup()` appends a null terminator to the requested prefix.
- Zero-sized `malloc`, `calloc`, and `memdup` requests return `NULL`.
- `strndup` accepts a zero length and returns an allocated empty string.
- A null source, arithmetic overflow, invalid arena, or allocation failure
  returns `NULL`.
- Failure leaves the arena usable and does not define `errno`.

## Growth and allocator options

Existing constructors retain fixed-size chunks. Optional geometric growth and
allocator callbacks are configured through an initialized options structure:

```c
struct cfl_arena_options options;

cfl_arena_options_init(&options);
options.chunk_size = 4096;
options.maximum_chunk_size = 65536;
options.malloc_fn = application_malloc;
options.free_fn = application_free;
options.allocator_context = application_context;

arena = cfl_arena_create_with_options(&options);
```

The first normal chunk uses `chunk_size`. Later chunks double in size until
`maximum_chunk_size`; a request larger than the current chunk size receives a
dedicated chunk large enough for that request. A zero maximum selects fixed
growth, making the maximum equal to the initial chunk size. A maximum smaller
than the initial size is invalid.

The callback pair is optional, but callers must provide both callbacks or
neither. Callbacks allocate and release the arena context, normal chunks,
external allocations, and cached external allocations. The allocation callback
must return storage with normal `malloc` alignment. CFL implements zeroing and
does not require `calloc` or `realloc` callbacks. `struct_size` must be set by
`cfl_arena_options_init()` so future CFL versions can extend the structure.

## Arena-aware constructors

The following constructors associate new values with an arena:

```c
struct cfl_variant *cfl_variant_create_in(struct cfl_arena *arena);
struct cfl_array *cfl_array_create_in(struct cfl_arena *arena,
                                      size_t slot_count);
struct cfl_kvlist *cfl_kvlist_create_in(struct cfl_arena *arena);
cfl_sds_t cfl_sds_create_len_in(struct cfl_arena *arena,
                                const char *str, int len);
```

Typed variant constructors have matching `_in` forms, including strings,
bytes, booleans, integers, doubles, nulls, references, arrays, and kvlists.

Nested containers can inherit their parent's allocator:

```c
struct cfl_array *cfl_array_create_like(struct cfl_array *parent,
                                        size_t slot_count);
struct cfl_kvlist *cfl_kvlist_create_like(struct cfl_kvlist *parent);
```

For a heap-backed parent, `create_like()` creates a heap-backed child. For an
arena-backed parent, it creates the child in the same arena.

## Basic example

```c
#include <cfl/cfl.h>

int process_batch(void)
{
    int result;
    struct cfl_arena *arena;
    struct cfl_kvlist *record;

    arena = cfl_arena_create(8192);
    if (arena == NULL) {
        return -1;
    }

    result = 0;

    record = cfl_kvlist_create_in(arena);
    if (record == NULL) {
        result = -1;
        goto done;
    }

    if (cfl_kvlist_insert_string(record, "message", "ready") != 0 ||
        cfl_kvlist_insert_int64(record, "status", 200) != 0) {
        result = -1;
        goto done;
    }

    /* Mutate, inspect, or serialize record before resetting the arena. */

done:
    cfl_arena_destroy(arena);

    return result;
}
```

For repeated batches, reuse the arena:

```c
while (next_batch()) {
    /* Construct and completely process one graph. */
    process_with_arena(arena);

    /* Every arena-backed pointer is invalid after this call. */
    cfl_arena_reset(arena);
}
```

## Ownership rules

Arena lifetime is part of object ownership:

- Reset and destruction invalidate every pointer allocated from the arena.
- Do not retain arena-backed values after reset or destruction.
- Do not attach values from different arenas to one array or kvlist.
- Do not mix heap-backed and arena-backed children in the same object graph.
- Use `create_like()` when constructing nested containers during mutation.
- A raw array or kvlist must have only one owning variant at a time.
- If an object must outlive the arena, copy it into its destination allocator
  before resetting the source arena.

CFL validates allocator ownership for supported container attachments. A
rejected cross-arena insertion leaves ownership with the caller.

Destroy functions can be used on arena-backed values while the arena is alive.
They release owned external storage and make reusable internal slots available
where supported. They do not replace the need to destroy the arena itself.

## Reset and reclamation

`cfl_arena_reset()` prepares the arena for another graph. It invalidates the
previous graph, resets chunk allocation positions, clears reusable-object
state, and handles external allocations according to the configured cache.

Removing an individual value does not necessarily reduce reserved memory.
Chunk storage is reclaimed for reuse at reset, not returned after every object
destruction. This is the central throughput-versus-retention tradeoff of arena
allocation.

## Large values and external caching

Raw allocations and small CFL objects come from arena chunks. Raw requests
larger than the active chunk receive a dedicated chunk. The large-object
threshold applies to arena-aware owned SDS values, which use separately tracked
external storage so unusually large strings do not consume normal chunks.

Reusable external buffers may remain cached after reset. Configure the maximum
cached capacity with:

```c
cfl_arena_external_cache_limit_set(arena, limit);
```

Setting the limit to zero disables external-buffer caching. Reducing the limit
immediately trims the cache. A larger limit can improve throughput for repeated
large payloads but may increase retained memory and RSS.

The arena also maintains size classes for commonly-sized owned SDS values.
Callers do not need to select a class.

## Memory statistics

The statistics API separates live capacity from retained storage:

- `cfl_arena_bytes_used()` reports live arena payload capacity.
- `cfl_arena_bytes_reserved()` reports memory reserved by chunks and external
  allocations, including CFL allocation headers but excluding allocator
  metadata.
- `cfl_arena_external_cache_bytes()` reports the portion held in the reusable
  external cache.

Reserved bytes can remain higher than used bytes after removals or reset. Peak
RSS can also exceed both values because it includes the process, allocator
metadata, page granularity, and allocator-retained memory.

Measure CPU, peak RSS, reserved bytes, used bytes, and cached bytes when tuning.
Fewer calls to `malloc()` do not by themselves prove lower memory usage.

## Thread safety

An arena is not thread-safe. All allocation, mutation, destruction, statistic,
cache-configuration, and reset operations involving the same arena must be
serialized by the caller.

Separate arenas can be used independently by separate threads as long as their
object graphs are not mixed.

## Error handling

Arena constructors return `NULL` on invalid input, ownership violations, or
allocation failure. Container insert operations retain their documented return
conventions. Check every constructor and insertion before continuing to mutate
the graph.

An allocation failure does not require abandoning the arena. The caller may
destroy or reset it normally, provided no partially-created pointer is used.

## Tuning

Start with the default policy:

```c
arena = cfl_arena_create(0);
```

Tune only with representative workloads:

1. Choose a chunk size large enough for common graphs without excessive unused
   capacity.
2. Keep very large values external so they do not fragment normal chunks.
3. Bound or disable the external cache when retained memory matters more than
   repeated large-buffer throughput.
4. Test multiple payload distributions and mutation patterns.
5. Compare against the heap implementation rather than assuming the arena wins.

A separate arena per small object is usually counterproductive. Prefer one
arena for the complete bounded document or batch.

## Benchmarks

Build the supplied benchmark tools with:

```sh
cmake -S . -B build-bench \
  -DCMAKE_BUILD_TYPE=Release \
  -DCFL_BENCHMARKS=On
cmake --build build-bench -j8
```

See [benchmarks/README.md](benchmarks/README.md) for heap-versus-arena CPU, RSS,
fragmentation, mutable OTLP-style workloads, and the deterministic payload
matrix.
