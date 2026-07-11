/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CFL_ARENA_H
#define CFL_ARENA_H

#include <stddef.h>

struct cfl_arena;

/*
 * Arena-created objects remain valid until the arena is reset or destroyed.
 * Reset and destroy invalidate every pointer allocated from the arena.
 * Objects from different arenas, including heap-backed objects, cannot be
 * attached to the same array or kvlist.
 * An arena is not thread-safe. Callers must serialize all operations that use
 * the same arena, including allocation, mutation, reset, and destruction.
 * The reserved byte count includes CFL's allocation headers, but not allocator
 * implementation metadata. The used byte count is the live payload capacity.
 */
struct cfl_arena *cfl_arena_create(size_t chunk_size);
struct cfl_arena *cfl_arena_create_ex(size_t chunk_size,
                                      size_t large_object_threshold);
void cfl_arena_destroy(struct cfl_arena *arena);
void cfl_arena_reset(struct cfl_arena *arena);
size_t cfl_arena_bytes_reserved(struct cfl_arena *arena);
size_t cfl_arena_bytes_used(struct cfl_arena *arena);
size_t cfl_arena_large_object_threshold(struct cfl_arena *arena);
void cfl_arena_external_cache_limit_set(struct cfl_arena *arena,
                                        size_t limit);
size_t cfl_arena_external_cache_limit_get(struct cfl_arena *arena);
size_t cfl_arena_external_cache_bytes(struct cfl_arena *arena);

#endif
