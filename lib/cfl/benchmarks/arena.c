/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#if !defined(CFL_SYSTEM_WINDOWS)
#include <sys/resource.h>
#endif

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#include <cfl/cfl.h>

static uint64_t monotonic_nanoseconds(void)
{
    return cfl_time_now();
}

static int build_heap(size_t entries)
{
    struct cfl_kvlist *list;
    size_t index;
    char key[32];

    list = cfl_kvlist_create();
    if (list == NULL) {
        return -1;
    }
    for (index = 0; index < entries; index++) {
        snprintf(key, sizeof(key), "key-%zu", index);
        if (cfl_kvlist_insert_int64(list, key, (int64_t) index) != 0) {
            cfl_kvlist_destroy(list);
            return -1;
        }
    }
    cfl_kvlist_destroy(list);
    return 0;
}

static int build_arena(size_t entries, size_t chunk_size,
                       size_t maximum_chunk_size,
                       size_t *reserved, size_t *used)
{
    struct cfl_arena *arena;
    struct cfl_arena_options options;
    struct cfl_kvlist *list;
    size_t index;
    char key[32];

    if (maximum_chunk_size == 0) {
        arena = cfl_arena_create(chunk_size);
    }
    else {
        cfl_arena_options_init(&options);
        options.chunk_size = chunk_size;
        options.maximum_chunk_size = maximum_chunk_size;
        arena = cfl_arena_create_with_options(&options);
    }
    if (arena == NULL) {
        return -1;
    }
    list = cfl_kvlist_create_in(arena);
    if (list == NULL) {
        cfl_arena_destroy(arena);
        return -1;
    }
    for (index = 0; index < entries; index++) {
        snprintf(key, sizeof(key), "key-%zu", index);
        if (cfl_kvlist_insert_int64(list, key, (int64_t) index) != 0) {
            cfl_arena_destroy(arena);
            return -1;
        }
    }
    *reserved = cfl_arena_bytes_reserved(arena);
    *used = cfl_arena_bytes_used(arena);
    cfl_arena_destroy(arena);
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode;
    size_t iterations;
    size_t entries;
    size_t chunk_size;
    size_t maximum_chunk_size;
    size_t iteration;
    size_t reserved;
    size_t used;
    uint64_t start;
    uint64_t elapsed;
#if !defined(CFL_SYSTEM_WINDOWS)
    struct rusage usage;
#endif
#if defined(__GLIBC__)
    struct mallinfo2 memory;
#endif

    mode = argc > 1 ? argv[1] : "heap";
    iterations = argc > 2 ? strtoull(argv[2], NULL, 10) : 1000;
    entries = argc > 3 ? strtoull(argv[3], NULL, 10) : 1000;
    chunk_size = argc > 4 ? strtoull(argv[4], NULL, 10) : 8192;
    maximum_chunk_size = argc > 5 ? strtoull(argv[5], NULL, 10) : 65536;
    reserved = 0;
    used = 0;

    start = monotonic_nanoseconds();
    for (iteration = 0; iteration < iterations; iteration++) {
        if (strcmp(mode, "arena") == 0 ||
            strcmp(mode, "arena-grow") == 0) {
            if (build_arena(entries, chunk_size,
                            strcmp(mode, "arena-grow") == 0 ?
                            maximum_chunk_size : 0,
                            &reserved, &used) != 0) {
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(mode, "heap") == 0) {
            if (build_heap(entries) != 0) {
                return EXIT_FAILURE;
            }
        }
        else {
            fprintf(stderr,
                    "usage: %s heap|arena|arena-grow [iterations] "
                    "[entries] [chunk-size] [maximum-chunk-size]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }
    }
    elapsed = monotonic_nanoseconds() - start;

    printf("mode=%s iterations=%zu entries=%zu elapsed_ns=%llu ns_per_entry=%.2f",
           mode, iterations, entries, (unsigned long long) elapsed,
           (double) elapsed / (double) (iterations * entries));
#if !defined(CFL_SYSTEM_WINDOWS)
    getrusage(RUSAGE_SELF, &usage);
    printf(" max_rss_kb=%ld", usage.ru_maxrss);
#endif
#if defined(__GLIBC__)
    memory = mallinfo2();
    printf(" heap_in_use=%zu heap_free=%zu", (size_t) memory.uordblks,
           (size_t) memory.fordblks);
#endif
    if (strcmp(mode, "arena") == 0 ||
        strcmp(mode, "arena-grow") == 0) {
        printf(" arena_reserved=%zu arena_used=%zu arena_slack=%zu",
               reserved, used, reserved - used);
    }
    putchar('\n');
    return EXIT_SUCCESS;
}
