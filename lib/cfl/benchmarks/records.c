/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Decoded telemetry batch benchmark: every batch holds many small records
 * with short keys, a nested map and an array, as produced by decoding a
 * buffer of log records. Values can reference the source buffer or be owned
 * copies, and records can be edited after construction.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if !defined(CFL_SYSTEM_WINDOWS)
#include <sys/resource.h>
#endif

#include <cfl/cfl.h>

struct batch_options {
    size_t records;
    int referenced;
    int mutate;
};

static int insert_string(struct cfl_kvlist *list, char *key, char *value,
                         int referenced)
{
    return cfl_kvlist_insert_string_s(list, key, strlen(key), value,
                                      strlen(value), referenced);
}

static struct cfl_variant *build_record(struct cfl_arena *arena, size_t index,
                                        struct batch_options *options)
{
    char message[64];
    struct cfl_kvlist *record;
    struct cfl_kvlist *http;
    struct cfl_array *tags;
    struct cfl_variant *root;

    snprintf(message, sizeof(message), "request %zu completed", index);

    record = cfl_kvlist_create_in(arena);
    http = cfl_kvlist_create_in(arena);
    tags = cfl_array_create_in(arena, 2);
    if (record == NULL || http == NULL || tags == NULL) {
        return NULL;
    }

    /* referenced values must outlive the record, keep them static */
    if (insert_string(record, "msg", options->referenced ?
                      "request completed" : message,
                      options->referenced) != 0 ||
        insert_string(record, "level", "info", options->referenced) != 0 ||
        insert_string(record, "user", "u-1234", options->referenced) != 0 ||
        insert_string(record, "password", "secret", options->referenced) != 0 ||
        insert_string(http, "path", "/api/v1/items", options->referenced) != 0 ||
        insert_string(http, "method", "GET", options->referenced) != 0 ||
        cfl_kvlist_insert_int64(http, "status", 200) != 0 ||
        cfl_kvlist_insert_kvlist(record, "http", http) != 0 ||
        cfl_kvlist_insert_double(record, "duration_ms", 12.5) != 0 ||
        cfl_array_append_string_s(tags, "edge", 4, options->referenced) != 0 ||
        cfl_array_append_string_s(tags, "eu-west-1", 9,
                                  options->referenced) != 0 ||
        cfl_kvlist_insert_array(record, "tags", tags) != 0) {
        return NULL;
    }

    if (options->mutate) {
        if (cfl_kvlist_remove(record, "password") != CFL_TRUE ||
            cfl_kvlist_insert_int64(record, "x", 1) != 0 ||
            cfl_kvlist_rename_s(record, "user", 4, "user.id", 7) != 0) {
            return NULL;
        }
    }

    root = cfl_variant_create_from_kvlist_in(arena, record);
    return root;
}

static int run_batch(struct cfl_arena *arena, struct cfl_variant **roots,
                     struct batch_options *options)
{
    size_t index;
    int result;

    result = 0;
    for (index = 0; index < options->records; index++) {
        roots[index] = build_record(arena, index, options);
        if (roots[index] == NULL) {
            result = -1;
            break;
        }
    }

    /* arena records are released by the reset, heap ones one by one */
    if (arena == NULL) {
        for (index = 0; index < options->records; index++) {
            if (roots[index] != NULL) {
                cfl_variant_destroy(roots[index]);
            }
        }
    }

    return result;
}

int main(int argc, char **argv)
{
    const char *mode;
    size_t batches;
    size_t batch;
    size_t chunk_size;
    size_t reserved;
    size_t used;
    uint64_t start;
    uint64_t elapsed;
    struct cfl_arena *arena;
    struct cfl_variant **roots;
    struct batch_options options;
#if !defined(CFL_SYSTEM_WINDOWS)
    struct rusage usage;
#endif

    mode = argc > 1 ? argv[1] : "arena";
    options.records = argc > 2 ? strtoull(argv[2], NULL, 10) : 512;
    batches = argc > 3 ? strtoull(argv[3], NULL, 10) : 2000;
    options.referenced = argc > 4 ? strcmp(argv[4], "owned") != 0 : CFL_TRUE;
    options.mutate = argc > 5 ? atoi(argv[5]) : 0;
    chunk_size = argc > 6 ? strtoull(argv[6], NULL, 10) : 16384;

    if ((strcmp(mode, "arena") != 0 && strcmp(mode, "heap") != 0) ||
        options.records == 0) {
        fprintf(stderr,
                "usage: %s arena|heap [records] [batches] "
                "[referenced|owned] [mutate] [chunk-size]\n", argv[0]);
        return EXIT_FAILURE;
    }

    roots = calloc(options.records, sizeof(struct cfl_variant *));
    if (roots == NULL) {
        return EXIT_FAILURE;
    }

    arena = NULL;
    if (strcmp(mode, "arena") == 0) {
        arena = cfl_arena_create(chunk_size);
        if (arena == NULL) {
            free(roots);
            return EXIT_FAILURE;
        }
    }

    reserved = 0;
    used = 0;
    start = cfl_time_now();
    for (batch = 0; batch < batches; batch++) {
        if (run_batch(arena, roots, &options) != 0) {
            fprintf(stderr, "batch construction failed\n");
            cfl_arena_destroy(arena);
            free(roots);
            return EXIT_FAILURE;
        }
        if (arena != NULL) {
            reserved = cfl_arena_bytes_reserved(arena);
            used = cfl_arena_bytes_used(arena);
            cfl_arena_reset(arena);
        }
    }
    elapsed = cfl_time_now() - start;

    printf("mode=%s records=%zu batches=%zu values=%s mutate=%d "
           "elapsed_ns=%llu ns_per_record=%.2f",
           mode, options.records, batches,
           options.referenced ? "referenced" : "owned", options.mutate,
           (unsigned long long) elapsed,
           (double) elapsed / (double) (batches * options.records));
    if (arena != NULL) {
        printf(" arena_reserved=%zu arena_used=%zu used_per_record=%.1f "
               "reserved_per_record=%.1f", reserved, used,
               (double) used / (double) options.records,
               (double) reserved / (double) options.records);
    }
#if !defined(CFL_SYSTEM_WINDOWS)
    getrusage(RUSAGE_SELF, &usage);
    printf(" max_rss_kb=%ld", usage.ru_maxrss);
#endif
    putchar('\n');

    cfl_arena_destroy(arena);
    free(roots);
    return EXIT_SUCCESS;
}
