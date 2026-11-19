/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cfl/cfl_arena.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_variant.h>

#include "cfl_arena_internal.h"

#define CFL_ARENA_DEFAULT_CHUNK_SIZE 8192
#define CFL_ARENA_SDS_SMALL_PAYLOAD 128
#define CFL_ARENA_SDS_MEDIUM_CLASS_COUNT 10
#define CFL_ARENA_EXTERNAL_CLASS_COUNT 24
#define CFL_ARENA_EXTERNAL_EXACT_CLASS UINT8_MAX

union cfl_arena_max_align {
    long double long_double_value;
    void *pointer_value;
    uint64_t uint64_value;
};

struct cfl_arena_alignment_probe {
    char byte;
    union cfl_arena_max_align value;
};

/*
 * CFL objects only hold pointers, sizes, integers and doubles, so they are
 * packed with the strictest of those alignments instead of the raw allocation
 * alignment, which can be larger because of long double.
 */
union cfl_arena_object_align {
    void *pointer_value;
    size_t size_value;
    uint64_t uint64_value;
    double double_value;
};

struct cfl_arena_object_alignment_probe {
    char byte;
    union cfl_arena_object_align value;
};

#define CFL_ARENA_MAX_ALIGNMENT \
    offsetof(struct cfl_arena_alignment_probe, value)
#define CFL_ARENA_OBJECT_ALIGNMENT \
    offsetof(struct cfl_arena_object_alignment_probe, value)

/* small SDS classes cover payloads below 128 bytes in alignment steps */
#define CFL_ARENA_SDS_SMALL_CLASS_COUNT \
    (CFL_ARENA_SDS_SMALL_PAYLOAD / CFL_ARENA_OBJECT_ALIGNMENT)
#define CFL_ARENA_SDS_CLASS_COUNT \
    (CFL_ARENA_SDS_SMALL_CLASS_COUNT + CFL_ARENA_SDS_MEDIUM_CLASS_COUNT)

struct cfl_arena_variant_probe {
    char byte;
    struct cfl_variant value;
};

struct cfl_arena_kvpair_probe {
    char byte;
    struct cfl_kvpair value;
};

struct cfl_arena_kvlist_probe {
    char byte;
    struct cfl_kvlist value;
};

struct cfl_arena_array_probe {
    char byte;
    struct cfl_array value;
};

/* compile time checks: every object type fits the object alignment */
typedef char cfl_arena_check_object_alignment[
    (CFL_ARENA_MAX_ALIGNMENT % CFL_ARENA_OBJECT_ALIGNMENT == 0 &&
     (CFL_ARENA_OBJECT_ALIGNMENT & (CFL_ARENA_OBJECT_ALIGNMENT - 1)) == 0 &&
     CFL_ARENA_SDS_CLASS_COUNT < UINT8_MAX) ? 1 : -1];
typedef char cfl_arena_check_variant_alignment[
    (CFL_ARENA_OBJECT_ALIGNMENT %
     offsetof(struct cfl_arena_variant_probe, value) == 0) ? 1 : -1];
typedef char cfl_arena_check_kvpair_alignment[
    (CFL_ARENA_OBJECT_ALIGNMENT %
     offsetof(struct cfl_arena_kvpair_probe, value) == 0) ? 1 : -1];
typedef char cfl_arena_check_kvlist_alignment[
    (CFL_ARENA_OBJECT_ALIGNMENT %
     offsetof(struct cfl_arena_kvlist_probe, value) == 0) ? 1 : -1];
typedef char cfl_arena_check_array_alignment[
    (CFL_ARENA_OBJECT_ALIGNMENT %
     offsetof(struct cfl_arena_array_probe, value) == 0) ? 1 : -1];

struct cfl_arena_chunk {
    struct cfl_arena_chunk *next;
    size_t capacity;
    size_t used;
    union cfl_arena_max_align alignment;
    unsigned char data[];
};

struct cfl_arena_external {
    struct cfl_arena_external *next;
    struct cfl_arena_external *previous;
    size_t size;
    uint8_t allocation_class;
    union cfl_arena_max_align alignment;
    unsigned char data[];
};

struct cfl_arena {
    struct cfl_arena_chunk *head;
    struct cfl_arena_chunk *current;
    struct cfl_arena_external *external;
    struct cfl_arena_external *external_cache[CFL_ARENA_EXTERNAL_CLASS_COUNT];
    struct cfl_arena_external *external_exact_cache;
    size_t external_cache_count[CFL_ARENA_EXTERNAL_CLASS_COUNT];
    size_t external_cache_bytes;
    size_t external_cache_limit;
    size_t chunk_size;
    size_t maximum_chunk_size;
    size_t next_chunk_size;
    size_t bytes_reserved;
    size_t bytes_used;
    size_t large_object_threshold;
    void *free_variants;
    void *free_kvpairs;
    void *free_sds[CFL_ARENA_SDS_CLASS_COUNT];
    cfl_arena_malloc_fn malloc_fn;
    cfl_arena_free_fn free_fn;
    void *allocator_context;
};

static void *arena_default_malloc(void *context, size_t size)
{
    (void) context;
    return malloc(size);
}

static void arena_default_free(void *context, void *pointer)
{
    (void) context;
    free(pointer);
}

static void arena_chunks_destroy(struct cfl_arena *arena)
{
    struct cfl_arena_chunk *chunk;
    struct cfl_arena_chunk *next;

    chunk = arena->head;
    while (chunk != NULL) {
        next = chunk->next;
        arena->free_fn(arena->allocator_context, chunk);
        chunk = next;
    }

    arena->head = NULL;
    arena->current = NULL;
    arena->bytes_reserved = 0;
    arena->bytes_used = 0;
}

static void arena_external_destroy(struct cfl_arena *arena)
{
    struct cfl_arena_external *allocation;
    struct cfl_arena_external *next;
    size_t index;

    allocation = arena->external;
    while (allocation != NULL) {
        next = allocation->next;
        arena->bytes_reserved -= allocation->size +
                                 sizeof(struct cfl_arena_external);
        arena->bytes_used -= allocation->size;
        arena->free_fn(arena->allocator_context, allocation);
        allocation = next;
    }
    arena->external = NULL;

    for (index = 0; index < CFL_ARENA_EXTERNAL_CLASS_COUNT; index++) {
        allocation = arena->external_cache[index];
        while (allocation != NULL) {
            next = allocation->next;
            arena->bytes_reserved -= allocation->size +
                                     sizeof(struct cfl_arena_external);
            arena->free_fn(arena->allocator_context, allocation);
            allocation = next;
        }
        arena->external_cache[index] = NULL;
        arena->external_cache_count[index] = 0;
    }
    arena->external_cache_bytes = 0;

    allocation = arena->external_exact_cache;
    while (allocation != NULL) {
        next = allocation->next;
        arena->bytes_reserved -= allocation->size +
                                 sizeof(struct cfl_arena_external);
        arena->free_fn(arena->allocator_context, allocation);
        allocation = next;
    }
    arena->external_exact_cache = NULL;
}

struct cfl_arena *cfl_arena_create(size_t chunk_size)
{
    return cfl_arena_create_ex(chunk_size, 0);
}

struct cfl_arena *cfl_arena_create_ex(size_t chunk_size,
                                      size_t large_object_threshold)
{
    struct cfl_arena_options options;

    cfl_arena_options_init(&options);
    options.chunk_size = chunk_size;
    options.large_object_threshold = large_object_threshold;

    return cfl_arena_create_with_options(&options);
}

void cfl_arena_options_init(struct cfl_arena_options *options)
{
    if (options == NULL) {
        return;
    }

    memset(options, 0, sizeof(struct cfl_arena_options));
    options->struct_size = sizeof(struct cfl_arena_options);
}

struct cfl_arena *cfl_arena_create_with_options(
    const struct cfl_arena_options *options)
{
    struct cfl_arena *arena;
    size_t chunk_size;
    size_t maximum_chunk_size;
    size_t large_object_threshold;
    cfl_arena_malloc_fn malloc_fn;
    cfl_arena_free_fn free_fn;
    void *allocator_context;

    if (options == NULL ||
        options->struct_size <
        offsetof(struct cfl_arena_options, allocator_context) +
        sizeof(options->allocator_context)) {
        return NULL;
    }

    if ((options->malloc_fn == NULL) != (options->free_fn == NULL)) {
        return NULL;
    }

    chunk_size = options->chunk_size;
    maximum_chunk_size = options->maximum_chunk_size;
    large_object_threshold = options->large_object_threshold;
    malloc_fn = options->malloc_fn;
    free_fn = options->free_fn;
    allocator_context = options->allocator_context;

    if (chunk_size == 0) {
        chunk_size = CFL_ARENA_DEFAULT_CHUNK_SIZE;
    }
    if (maximum_chunk_size == 0) {
        maximum_chunk_size = chunk_size;
    }
    if (maximum_chunk_size < chunk_size) {
        return NULL;
    }
    if (malloc_fn == NULL) {
        malloc_fn = arena_default_malloc;
        free_fn = arena_default_free;
        allocator_context = NULL;
    }

    arena = malloc_fn(allocator_context, sizeof(struct cfl_arena));
    if (arena == NULL) {
        return NULL;
    }
    memset(arena, 0, sizeof(struct cfl_arena));

    arena->chunk_size = chunk_size;
    arena->maximum_chunk_size = maximum_chunk_size;
    arena->next_chunk_size = chunk_size;
    arena->malloc_fn = malloc_fn;
    arena->free_fn = free_fn;
    arena->allocator_context = allocator_context;
    if (large_object_threshold == 0) {
        large_object_threshold = chunk_size / 2;
        if (large_object_threshold == 0) {
            large_object_threshold = 1;
        }
    }
    arena->large_object_threshold = large_object_threshold;
    if (chunk_size <= SIZE_MAX / 256) {
        arena->external_cache_limit = chunk_size * 256;
    }
    else {
        arena->external_cache_limit = SIZE_MAX;
    }
    return arena;
}

void cfl_arena_destroy(struct cfl_arena *arena)
{
    if (arena == NULL) {
        return;
    }

    arena_external_destroy(arena);
    arena_chunks_destroy(arena);
    arena->free_fn(arena->allocator_context, arena);
}

void cfl_arena_reset(struct cfl_arena *arena)
{
    struct cfl_arena_chunk *chunk;
    struct cfl_arena_external *allocation;
    struct cfl_arena_external *next;

    if (arena == NULL) {
        return;
    }

    allocation = arena->external;
    while (allocation != NULL) {
        next = allocation->next;
        cfl_arena_free_external(arena, allocation->data);
        allocation = next;
    }

    chunk = arena->head;
    while (chunk != NULL) {
        chunk->used = 0;
        chunk = chunk->next;
    }

    arena->bytes_used = 0;
    arena->current = arena->head;
    arena->next_chunk_size = arena->chunk_size;
    arena->free_variants = NULL;
    arena->free_kvpairs = NULL;
    memset(arena->free_sds, 0, sizeof(arena->free_sds));
}

/* walks the remaining chunks, then reserves a new one */
static void *arena_allocate_slow(struct cfl_arena *arena, size_t size,
                                 size_t alignment)
{
    struct cfl_arena_chunk *chunk;
    size_t offset;
    size_t remainder;
    size_t capacity;
    void *result;

    chunk = arena->current;
    while (chunk != NULL) {
        offset = chunk->used;
        remainder = offset & (alignment - 1);
        if (remainder != 0) {
            if (offset > SIZE_MAX - (alignment - remainder)) {
                return NULL;
            }
            offset += alignment - remainder;
        }
        if (offset <= chunk->capacity && size <= chunk->capacity - offset) {
            result = &chunk->data[offset];
            chunk->used = offset + size;
            arena->current = chunk;
            arena->bytes_used += size;
            return result;
        }
        chunk = chunk->next;
    }

    capacity = arena->next_chunk_size;
    if (capacity < size) {
        capacity = size;
    }
    if (capacity > SIZE_MAX - sizeof(struct cfl_arena_chunk)) {
        return NULL;
    }

    chunk = arena->malloc_fn(arena->allocator_context,
                             sizeof(struct cfl_arena_chunk) + capacity);
    if (chunk == NULL) {
        return NULL;
    }

    chunk->next = arena->head;
    chunk->capacity = capacity;
    chunk->used = size;
    arena->head = chunk;
    arena->current = chunk;
    arena->bytes_reserved += capacity +
                             sizeof(struct cfl_arena_chunk);
    arena->bytes_used += size;

    if (capacity == arena->next_chunk_size &&
        arena->next_chunk_size < arena->maximum_chunk_size) {
        if (arena->next_chunk_size > arena->maximum_chunk_size / 2) {
            arena->next_chunk_size = arena->maximum_chunk_size;
        }
        else {
            arena->next_chunk_size *= 2;
        }
    }

    return chunk->data;
}

/* bump allocation from the current chunk, the common case */
static inline void *arena_allocate(struct cfl_arena *arena, size_t size,
                                   size_t alignment)
{
    struct cfl_arena_chunk *chunk;
    size_t offset;
    void *result;

    if (arena == NULL || size == 0) {
        return NULL;
    }

    chunk = arena->current;
    if (chunk != NULL) {
        offset = (chunk->used + alignment - 1) & ~(alignment - 1);
        if (offset >= chunk->used && offset <= chunk->capacity &&
            size <= chunk->capacity - offset) {
            result = &chunk->data[offset];
            chunk->used = offset + size;
            arena->bytes_used += size;
            return result;
        }
    }

    return arena_allocate_slow(arena, size, alignment);
}

void *cfl_arena_malloc(struct cfl_arena *arena, size_t size)
{
    return arena_allocate(arena, size, CFL_ARENA_MAX_ALIGNMENT);
}

void *cfl_arena_alloc_object(struct cfl_arena *arena, size_t size)
{
    return arena_allocate(arena, size, CFL_ARENA_OBJECT_ALIGNMENT);
}

void *cfl_arena_calloc_object(struct cfl_arena *arena,
                              size_t count, size_t size)
{
    void *result;
    size_t total;

    if (count != 0 && size > SIZE_MAX / count) {
        return NULL;
    }

    total = count * size;
    result = arena_allocate(arena, total, CFL_ARENA_OBJECT_ALIGNMENT);
    if (result != NULL) {
        memset(result, 0, total);
    }

    return result;
}

void *cfl_arena_alloc(struct cfl_arena *arena, size_t size)
{
    return cfl_arena_malloc(arena, size);
}

void *cfl_arena_calloc(struct cfl_arena *arena,
                       size_t count, size_t size)
{
    void *result;
    size_t total;

    if (count != 0 && size > SIZE_MAX / count) {
        return NULL;
    }

    total = count * size;
    result = cfl_arena_malloc(arena, total);
    if (result != NULL) {
        memset(result, 0, total);
    }

    return result;
}

void *cfl_arena_memdup(struct cfl_arena *arena,
                       const void *source, size_t size)
{
    void *result;

    if (source == NULL || size == 0) {
        return NULL;
    }

    result = cfl_arena_malloc(arena, size);
    if (result != NULL) {
        memcpy(result, source, size);
    }

    return result;
}

char *cfl_arena_strndup(struct cfl_arena *arena,
                        const char *source, size_t length)
{
    char *result;

    if (source == NULL || length == SIZE_MAX) {
        return NULL;
    }

    result = cfl_arena_malloc(arena, length + 1);
    if (result != NULL) {
        memcpy(result, source, length);
        result[length] = '\0';
    }

    return result;
}

size_t cfl_arena_bytes_reserved(struct cfl_arena *arena)
{
    return arena == NULL ? 0 : arena->bytes_reserved;
}

size_t cfl_arena_bytes_used(struct cfl_arena *arena)
{
    return arena == NULL ? 0 : arena->bytes_used;
}

size_t cfl_arena_large_object_threshold(struct cfl_arena *arena)
{
    return arena == NULL ? 0 : arena->large_object_threshold;
}

void cfl_arena_external_cache_limit_set(struct cfl_arena *arena,
                                        size_t limit)
{
    struct cfl_arena_external *allocation;
    size_t index;

    if (arena == NULL) {
        return;
    }

    arena->external_cache_limit = limit;
    for (index = CFL_ARENA_EXTERNAL_CLASS_COUNT;
         index > 0 && arena->external_cache_bytes > limit;
         index--) {
        while (arena->external_cache[index - 1] != NULL &&
               arena->external_cache_bytes > limit) {
            allocation = arena->external_cache[index - 1];
            arena->external_cache[index - 1] = allocation->next;
            arena->external_cache_count[index - 1]--;
            arena->external_cache_bytes -= allocation->size;
            arena->bytes_reserved -= allocation->size +
                                     sizeof(struct cfl_arena_external);
            arena->free_fn(arena->allocator_context, allocation);
        }
    }

    while (arena->external_exact_cache != NULL &&
           arena->external_cache_bytes > limit) {
        allocation = arena->external_exact_cache;
        arena->external_exact_cache = allocation->next;
        arena->external_cache_bytes -= allocation->size;
        arena->bytes_reserved -= allocation->size +
                                 sizeof(struct cfl_arena_external);
        arena->free_fn(arena->allocator_context, allocation);
    }
}

size_t cfl_arena_external_cache_limit_get(struct cfl_arena *arena)
{
    return arena == NULL ? 0 : arena->external_cache_limit;
}

size_t cfl_arena_external_cache_bytes(struct cfl_arena *arena)
{
    return arena == NULL ? 0 : arena->external_cache_bytes;
}

void *cfl_arena_alloc_external(struct cfl_arena *arena,
                               size_t size)
{
    static const size_t class_sizes[CFL_ARENA_EXTERNAL_CLASS_COUNT] = {
        4096, 6144, 8192, 12288, 16384, 24576,
        32768, 49152, 65536, 98304, 131072, 196608,
        262144, 327680, 393216, 458752, 524288, 655360,
        786432, 917504, 1048576, 1310720, 1572864, 2097152
    };
    struct cfl_arena_external *allocation;
    struct cfl_arena_external *previous;
    size_t allocation_size;
    size_t index;
    uint8_t allocation_class;

    if (arena == NULL || size == 0 ||
        size > SIZE_MAX - sizeof(struct cfl_arena_external)) {
        return NULL;
    }

    allocation_class = 0;
    allocation_size = size;
    for (index = 0; index < CFL_ARENA_EXTERNAL_CLASS_COUNT; index++) {
        if (size <= class_sizes[index]) {
            allocation_class = (uint8_t) (index + 1);
            allocation_size = class_sizes[index];
            break;
        }
    }

    if (allocation_class != 0 &&
        allocation_size - size > size / 8) {
        allocation_class = CFL_ARENA_EXTERNAL_EXACT_CLASS;
        allocation_size = size;
    }

    allocation = NULL;
    if (allocation_class == CFL_ARENA_EXTERNAL_EXACT_CLASS) {
        previous = NULL;
        allocation = arena->external_exact_cache;
        while (allocation != NULL) {
            if (allocation->size == allocation_size) {
                if (previous == NULL) {
                    arena->external_exact_cache = allocation->next;
                }
                else {
                    previous->next = allocation->next;
                }
                arena->external_cache_bytes -= allocation->size;
                break;
            }
            previous = allocation;
            allocation = allocation->next;
        }
    }
    else if (allocation_class != 0) {
        index = allocation_class - 1;
        allocation = arena->external_cache[index];
        if (allocation != NULL) {
            arena->external_cache[index] = allocation->next;
            arena->external_cache_count[index]--;
            arena->external_cache_bytes -= allocation->size;
        }
    }

    if (allocation == NULL) {
        allocation = arena->malloc_fn(
            arena->allocator_context,
            sizeof(struct cfl_arena_external) + allocation_size);
        if (allocation == NULL) {
            return NULL;
        }
        allocation->size = allocation_size;
        arena->bytes_reserved += allocation_size +
                                 sizeof(struct cfl_arena_external);
    }

    allocation->next = arena->external;
    allocation->previous = NULL;
    if (arena->external != NULL) {
        arena->external->previous = allocation;
    }
    allocation->allocation_class = allocation_class;
    arena->external = allocation;
    arena->bytes_used += allocation->size;
    return allocation->data;
}

void cfl_arena_free_external(struct cfl_arena *arena,
                             void *pointer)
{
    struct cfl_arena_external *allocation;
    size_t index;

    if (arena == NULL || pointer == NULL) {
        return;
    }

    allocation = (struct cfl_arena_external *)
                 ((unsigned char *) pointer -
                  offsetof(struct cfl_arena_external, data));
    if (allocation->previous == NULL) {
        arena->external = allocation->next;
    }
    else {
        allocation->previous->next = allocation->next;
    }
    if (allocation->next != NULL) {
        allocation->next->previous = allocation->previous;
    }
    arena->bytes_used -= allocation->size;
    if (allocation->allocation_class != 0 &&
        allocation->size <= arena->external_cache_limit &&
        arena->external_cache_bytes <= arena->external_cache_limit -
                                       allocation->size) {
        if (allocation->allocation_class ==
            CFL_ARENA_EXTERNAL_EXACT_CLASS) {
            allocation->next = arena->external_exact_cache;
            arena->external_exact_cache = allocation;
        }
        else {
            index = allocation->allocation_class - 1;
            allocation->next = arena->external_cache[index];
            arena->external_cache[index] = allocation;
            arena->external_cache_count[index]++;
        }
        allocation->previous = NULL;
        arena->external_cache_bytes += allocation->size;
    }
    else {
        arena->bytes_reserved -= allocation->size +
                                 sizeof(struct cfl_arena_external);
        arena->free_fn(arena->allocator_context, allocation);
    }
}

static void *arena_reusable_alloc(struct cfl_arena *arena,
                                  void **free_list, size_t size, int zero)
{
    void *result;

    if (arena == NULL) {
        return NULL;
    }

    if (*free_list != NULL) {
        result = *free_list;
        *free_list = *((void **) result);
        arena->bytes_used += size;
    }
    else {
        result = arena_allocate(arena, size, CFL_ARENA_OBJECT_ALIGNMENT);
        if (result == NULL) {
            return NULL;
        }
    }

    if (zero) {
        memset(result, 0, size);
    }

    return result;
}

static void arena_reusable_free(struct cfl_arena *arena,
                                void **free_list, void *pointer, size_t size)
{
    if (arena == NULL || pointer == NULL) {
        return;
    }

    *((void **) pointer) = *free_list;
    *free_list = pointer;
    arena->bytes_used -= size;
}

void *cfl_arena_alloc_variant(struct cfl_arena *arena,
                              size_t size)
{
    return arena_reusable_alloc(arena, &arena->free_variants, size, CFL_TRUE);
}

void cfl_arena_free_variant(struct cfl_arena *arena,
                            void *pointer, size_t size)
{
    arena_reusable_free(arena, &arena->free_variants, pointer, size);
}

void *cfl_arena_alloc_kvpair(struct cfl_arena *arena,
                             size_t size)
{
    return arena_reusable_alloc(arena, &arena->free_kvpairs, size, CFL_TRUE);
}

void cfl_arena_free_kvpair(struct cfl_arena *arena,
                           void *pointer, size_t size)
{
    arena_reusable_free(arena, &arena->free_kvpairs, pointer, size);
}

/*
 * Owned SDS strings are recycled through size classes. Small classes grow in
 * object alignment steps of the complete allocation up to about 128 bytes of
 * payload, so short strings such as map keys waste less than one alignment
 * unit. Medium classes grow by roughly 25 percent up to the largest pooled
 * payload.
 */
static int arena_sds_class(size_t payload_size, size_t overhead_size,
                           size_t *index, size_t *payload_capacity)
{
    static const size_t medium_payloads[CFL_ARENA_SDS_MEDIUM_CLASS_COUNT] = {
        160, 200, 248, 312, 392, 488, 608, 760, 952, CFL_ARENA_SDS_MAX_PAYLOAD
    };
    size_t alignment;
    size_t smallest;
    size_t total;
    size_t class_index;

    alignment = CFL_ARENA_OBJECT_ALIGNMENT;
    if (payload_size > CFL_ARENA_SDS_MAX_PAYLOAD ||
        overhead_size > SIZE_MAX - CFL_ARENA_SDS_MAX_PAYLOAD - 1 - alignment) {
        return -1;
    }

    /* smallest allocation holds the overhead, the terminator and one byte */
    smallest = (overhead_size + 2 + alignment - 1) & ~(alignment - 1);
    total = (overhead_size + payload_size + 1 + alignment - 1) &
            ~(alignment - 1);
    if (total < smallest) {
        total = smallest;
    }

    if (total <= smallest + (CFL_ARENA_SDS_SMALL_CLASS_COUNT - 1) * alignment) {
        *index = (total - smallest) / alignment;
        *payload_capacity = total - overhead_size - 1;
        return 0;
    }

    for (class_index = 0; class_index < CFL_ARENA_SDS_MEDIUM_CLASS_COUNT;
         class_index++) {
        total = (overhead_size + medium_payloads[class_index] + 1 +
                 alignment - 1) & ~(alignment - 1);
        if (payload_size <= total - overhead_size - 1) {
            *index = CFL_ARENA_SDS_SMALL_CLASS_COUNT + class_index;
            *payload_capacity = total - overhead_size - 1;
            return 0;
        }
    }

    return -1;
}

void *cfl_arena_alloc_sds(struct cfl_arena *arena,
                          size_t payload_size, size_t overhead_size,
                          uint8_t *allocation_class,
                          size_t *payload_capacity)
{
    size_t index;

    if (arena == NULL || allocation_class == NULL || payload_capacity == NULL) {
        return NULL;
    }

    if (arena_sds_class(payload_size, overhead_size, &index,
                        payload_capacity) != 0) {
        *allocation_class = 0;
        *payload_capacity = payload_size;
        return NULL;
    }

    /* the SDS layer initializes the headers and the payload it uses */
    *allocation_class = (uint8_t) (index + 1);
    return arena_reusable_alloc(arena, &arena->free_sds[index],
                                overhead_size + *payload_capacity + 1, CFL_FALSE);
}

void cfl_arena_free_sds(struct cfl_arena *arena,
                        void *pointer, uint8_t allocation_class,
                        size_t allocation_size)
{
    size_t index;

    if (allocation_class == 0 ||
        allocation_class > CFL_ARENA_SDS_CLASS_COUNT) {
        return;
    }

    index = allocation_class - 1;
    arena_reusable_free(arena, &arena->free_sds[index], pointer,
                        allocation_size);
}
