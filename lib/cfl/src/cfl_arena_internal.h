#ifndef CFL_ARENA_INTERNAL_H
#define CFL_ARENA_INTERNAL_H

#include <stddef.h>

#include <cfl/cfl_arena.h>

void *cfl_arena_alloc(struct cfl_arena *arena, size_t size);
void *cfl_arena_calloc(struct cfl_arena *arena,
                       size_t count, size_t size);
void *cfl_arena_alloc_external(struct cfl_arena *arena,
                               size_t size);
void cfl_arena_free_external(struct cfl_arena *arena,
                             void *pointer);
void *cfl_arena_alloc_variant(struct cfl_arena *arena,
                              size_t size);
void cfl_arena_free_variant(struct cfl_arena *arena,
                            void *pointer, size_t size);
void *cfl_arena_alloc_kvpair(struct cfl_arena *arena,
                             size_t size);
void cfl_arena_free_kvpair(struct cfl_arena *arena,
                           void *pointer, size_t size);
void *cfl_arena_alloc_sds(struct cfl_arena *arena,
                          size_t payload_size, size_t overhead_size,
                          uint8_t *allocation_class,
                          size_t *payload_capacity);
void cfl_arena_free_sds(struct cfl_arena *arena,
                        void *pointer, uint8_t allocation_class,
                        size_t allocation_size);

#endif
