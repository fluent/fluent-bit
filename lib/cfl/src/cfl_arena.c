/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cfl/cfl_arena.h>

#include "cfl_arena_internal.h"

#define CFL_ARENA_DEFAULT_CHUNK_SIZE 8192
#define CFL_ARENA_SDS_CLASS_COUNT 6
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
    size_t bytes_reserved;
    size_t bytes_used;
    size_t large_object_threshold;
    void *free_variants;
    void *free_kvpairs;
    void *free_sds[CFL_ARENA_SDS_CLASS_COUNT];
};

static void arena_chunks_destroy(struct cfl_arena *arena)
{
    struct cfl_arena_chunk *chunk;
    struct cfl_arena_chunk *next;

    chunk = arena->head;
    while (chunk != NULL) {
        next = chunk->next;
        free(chunk);
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
        free(allocation);
        allocation = next;
    }
    arena->external = NULL;

    for (index = 0; index < CFL_ARENA_EXTERNAL_CLASS_COUNT; index++) {
        allocation = arena->external_cache[index];
        while (allocation != NULL) {
            next = allocation->next;
            arena->bytes_reserved -= allocation->size +
                                     sizeof(struct cfl_arena_external);
            free(allocation);
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
        free(allocation);
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
    struct cfl_arena *arena;

    if (chunk_size == 0) {
        chunk_size = CFL_ARENA_DEFAULT_CHUNK_SIZE;
    }

    arena = calloc(1, sizeof(struct cfl_arena));
    if (arena == NULL) {
        return NULL;
    }

    arena->chunk_size = chunk_size;
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
    free(arena);
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
    arena->free_variants = NULL;
    arena->free_kvpairs = NULL;
    memset(arena->free_sds, 0, sizeof(arena->free_sds));
}

void *cfl_arena_alloc(struct cfl_arena *arena, size_t size)
{
    struct cfl_arena_chunk *chunk;
    size_t alignment;
    size_t offset;
    size_t remainder;
    size_t capacity;
    void *result;

    if (arena == NULL || size == 0) {
        return NULL;
    }

    alignment = offsetof(struct cfl_arena_alignment_probe, value);
    chunk = arena->current;
    while (chunk != NULL) {
        offset = chunk->used;
        remainder = offset % alignment;
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

    capacity = arena->chunk_size;
    if (capacity < size) {
        capacity = size;
    }
    if (capacity > SIZE_MAX - sizeof(struct cfl_arena_chunk)) {
        return NULL;
    }

    chunk = malloc(sizeof(struct cfl_arena_chunk) + capacity);
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

    return chunk->data;
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
    result = cfl_arena_alloc(arena, total);
    if (result != NULL) {
        memset(result, 0, total);
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
            free(allocation);
        }
    }

    while (arena->external_exact_cache != NULL &&
           arena->external_cache_bytes > limit) {
        allocation = arena->external_exact_cache;
        arena->external_exact_cache = allocation->next;
        arena->external_cache_bytes -= allocation->size;
        arena->bytes_reserved -= allocation->size +
                                 sizeof(struct cfl_arena_external);
        free(allocation);
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
        allocation = malloc(sizeof(struct cfl_arena_external) +
                            allocation_size);
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
        free(allocation);
    }
}

static void *arena_reusable_alloc(struct cfl_arena *arena,
                                  void **free_list, size_t size)
{
    void *result;

    if (arena == NULL) {
        return NULL;
    }

    if (*free_list != NULL) {
        result = *free_list;
        *free_list = *((void **) result);
        arena->bytes_used += size;
        memset(result, 0, size);
        return result;
    }

    return cfl_arena_calloc(arena, 1, size);
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
    return arena_reusable_alloc(arena, &arena->free_variants, size);
}

void cfl_arena_free_variant(struct cfl_arena *arena,
                            void *pointer, size_t size)
{
    arena_reusable_free(arena, &arena->free_variants, pointer, size);
}

void *cfl_arena_alloc_kvpair(struct cfl_arena *arena,
                             size_t size)
{
    return arena_reusable_alloc(arena, &arena->free_kvpairs, size);
}

void cfl_arena_free_kvpair(struct cfl_arena *arena,
                           void *pointer, size_t size)
{
    arena_reusable_free(arena, &arena->free_kvpairs, pointer, size);
}

void *cfl_arena_alloc_sds(struct cfl_arena *arena,
                          size_t payload_size, size_t overhead_size,
                          uint8_t *allocation_class,
                          size_t *payload_capacity)
{
    static const size_t class_sizes[CFL_ARENA_SDS_CLASS_COUNT] = {
        32, 64, 128, 256, 512, 1024
    };
    size_t index;

    if (arena == NULL || allocation_class == NULL || payload_capacity == NULL) {
        return NULL;
    }

    for (index = 0; index < CFL_ARENA_SDS_CLASS_COUNT; index++) {
        if (payload_size <= class_sizes[index]) {
            *allocation_class = (uint8_t) (index + 1);
            *payload_capacity = class_sizes[index];
            return arena_reusable_alloc(arena, &arena->free_sds[index],
                                        overhead_size + class_sizes[index] + 1);
        }
    }

    *allocation_class = 0;
    *payload_capacity = payload_size;
    return NULL;
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
