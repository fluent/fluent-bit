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

struct otlp_document {
    struct cfl_variant *root;
    struct cfl_array *log_records;
};

static size_t record_payload_size(const char *distribution,
                                  size_t total_size, size_t record_count,
                                  size_t index)
{
    size_t large_count;
    size_t small_count;
    size_t small_size;
    size_t remaining;
    size_t weight;

    if (record_count == 0 || total_size == 0) {
        return 0;
    }
    index %= record_count;
    if (strcmp(distribution, "bimodal") == 0) {
        large_count = (record_count + 9) / 10;
        small_count = record_count - large_count;
        small_size = total_size / record_count;
        if (small_size > 128) {
            small_size = 128;
        }
        if (index % 10 != 0) {
            return small_size;
        }
        remaining = total_size - (small_size * small_count);
        return remaining / large_count;
    }
    if (strcmp(distribution, "heavy") == 0) {
        if (record_count == 1 || index == 0) {
            return total_size / 2;
        }
        return (total_size - (total_size / 2)) / (record_count - 1);
    }
    if (strcmp(distribution, "random") == 0) {
        weight = ((index * 1103515245U + 12345U) >> 16) % 31 + 1;
        return (total_size / record_count) * weight / 16;
    }
    return total_size / record_count;
}

static uint64_t wall_nanoseconds(void)
{
    struct timespec now;

    timespec_get(&now, TIME_UTC);
    return ((uint64_t) now.tv_sec * 1000000000ULL) + now.tv_nsec;
}

static struct cfl_kvlist *create_record(struct cfl_arena *arena,
                                        size_t sequence,
                                        char *payload, size_t payload_size)
{
    struct cfl_kvlist *record;
    struct cfl_kvlist *body;
    struct cfl_kvlist *attributes;
    char message[64];

    record = cfl_kvlist_create_in(arena);
    body = cfl_kvlist_create_in(arena);
    attributes = cfl_kvlist_create_in(arena);
    if (record == NULL || body == NULL || attributes == NULL) {
        return NULL;
    }

    snprintf(message, sizeof(message), "request completed sequence=%zu", sequence);
    if (cfl_kvlist_insert_uint64(record, "timeUnixNano", sequence) != 0 ||
        cfl_kvlist_insert_string(record, "severityText", "INFO") != 0 ||
        (payload_size == 0 &&
         cfl_kvlist_insert_string(body, "stringValue", message) != 0) ||
        (payload_size > 0 &&
         cfl_kvlist_insert_string_s(body, "stringValue", 11, payload,
                                    payload_size, CFL_FALSE) != 0) ||
        cfl_kvlist_insert_kvlist(record, "body", body) != 0 ||
        cfl_kvlist_insert_string(attributes, "service.name", "api") != 0 ||
        cfl_kvlist_insert_int64(attributes, "http.status_code", 200) != 0 ||
        cfl_kvlist_insert_kvlist(record, "attributes", attributes) != 0) {
        return NULL;
    }

    return record;
}

static int create_document(struct cfl_arena *arena, size_t record_count,
                           char *payload, size_t content_size,
                           const char *distribution,
                           struct otlp_document *document)
{
    struct cfl_kvlist *root;
    struct cfl_kvlist *resource_log;
    struct cfl_kvlist *resource;
    struct cfl_kvlist *scope_log;
    struct cfl_kvlist *scope;
    struct cfl_kvlist *record;
    struct cfl_array *resource_logs;
    struct cfl_array *scope_logs;
    struct cfl_array *log_records;
    size_t index;

    root = cfl_kvlist_create_in(arena);
    resource_log = cfl_kvlist_create_in(arena);
    resource = cfl_kvlist_create_in(arena);
    scope_log = cfl_kvlist_create_in(arena);
    scope = cfl_kvlist_create_in(arena);
    resource_logs = cfl_array_create_in(arena, 1);
    scope_logs = cfl_array_create_in(arena, 1);
    log_records = cfl_array_create_in(arena, record_count + 1);
    if (root == NULL || resource_log == NULL || resource == NULL ||
        scope_log == NULL || scope == NULL || resource_logs == NULL ||
        scope_logs == NULL || log_records == NULL) {
        return -1;
    }

    cfl_array_resizable(log_records, CFL_TRUE);
    if (cfl_kvlist_insert_string(resource, "service.name", "checkout") != 0 ||
        cfl_kvlist_insert_kvlist(resource_log, "resource", resource) != 0 ||
        cfl_kvlist_insert_string(scope, "name", "benchmark.scope") != 0 ||
        cfl_kvlist_insert_kvlist(scope_log, "scope", scope) != 0) {
        return -1;
    }

    for (index = 0; index < record_count; index++) {
        record = create_record(arena, index, payload,
                               record_payload_size(distribution, content_size,
                                                   record_count, index));
        if (record == NULL || cfl_array_append_kvlist(log_records, record) != 0) {
            return -1;
        }
    }

    if (cfl_kvlist_insert_array(scope_log, "logRecords", log_records) != 0 ||
        cfl_array_append_kvlist(scope_logs, scope_log) != 0 ||
        cfl_kvlist_insert_array(resource_log, "scopeLogs", scope_logs) != 0 ||
        cfl_array_append_kvlist(resource_logs, resource_log) != 0 ||
        cfl_kvlist_insert_array(root, "resourceLogs", resource_logs) != 0) {
        return -1;
    }

    document->root = cfl_variant_create_from_kvlist_in(arena, root);
    document->log_records = log_records;
    return document->root == NULL ? -1 : 0;
}

static int mutate_document(struct cfl_arena *arena,
                           struct otlp_document *document,
                           size_t mutation_round,
                           char *payload, size_t content_size,
                           const char *distribution)
{
    struct cfl_variant *record_variant;
    struct cfl_variant *attributes_variant;
    struct cfl_kvlist *record;
    struct cfl_kvlist *attributes;
    struct cfl_kvlist *new_record;
    size_t index;
    size_t payload_size;

    for (index = 0; index < document->log_records->entry_count; index++) {
        record_variant = document->log_records->entries[index];
        record = record_variant->data.as_kvlist;
        attributes_variant = cfl_kvlist_fetch(record, "attributes");
        if (attributes_variant == NULL) {
            return -1;
        }
        attributes = attributes_variant->data.as_kvlist;

        cfl_kvlist_remove(record, "severityText");
        cfl_kvlist_remove(attributes, "http.status_code");
        if (cfl_kvlist_insert_string(record, "severityText",
                                     mutation_round % 2 == 0 ? "WARN" : "INFO") != 0 ||
            cfl_kvlist_insert_int64(attributes, "http.status_code",
                                    mutation_round % 2 == 0 ? 503 : 200) != 0) {
            return -1;
        }
    }

    payload_size = record_payload_size(distribution, content_size,
                                       document->log_records->entry_count,
                                       mutation_round);
    new_record = create_record(arena, mutation_round + 1000000,
                               payload, payload_size);
    if (new_record == NULL ||
        cfl_array_append_kvlist(document->log_records, new_record) != 0 ||
        cfl_array_remove_by_index(document->log_records, 0) != 0) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode;
    struct cfl_arena *arena;
    struct otlp_document document;
    size_t iterations;
    size_t records;
    size_t mutation_rounds;
    size_t chunk_size;
    size_t content_size;
    size_t payload_size;
    size_t large_object_threshold;
    size_t external_cache_limit;
    int external_cache_limit_set;
    size_t iteration;
    size_t round;
    size_t reserved;
    size_t used;
    size_t initial_used;
    size_t arena_cache_bytes;
    size_t arena_cache_limit;
    uint64_t start;
    uint64_t elapsed;
    double operation_count;
    char *payload;
    const char *distribution;
#if !defined(CFL_SYSTEM_WINDOWS)
    struct rusage usage;
#endif
#if defined(__GLIBC__)
    struct mallinfo2 memory;
    size_t heap_baseline;
    size_t heap_initial_live;
    size_t heap_final_live;
#endif

    mode = argc > 1 ? argv[1] : "heap";
    iterations = argc > 2 ? strtoull(argv[2], NULL, 10) : 100;
    records = argc > 3 ? strtoull(argv[3], NULL, 10) : 100;
    mutation_rounds = argc > 4 ? strtoull(argv[4], NULL, 10) : 10;
    chunk_size = argc > 5 ? strtoull(argv[5], NULL, 10) : 8192;
    content_size = argc > 6 ? strtoull(argv[6], NULL, 10) : 0;
    large_object_threshold = argc > 7 ? strtoull(argv[7], NULL, 10) : 0;
    distribution = argc > 8 ? argv[8] : "uniform";
    external_cache_limit_set = argc > 9;
    external_cache_limit = external_cache_limit_set ?
                           strtoull(argv[9], NULL, 10) : 0;
    payload_size = content_size;
    reserved = 0;
    used = 0;
    initial_used = 0;
    arena_cache_bytes = 0;
    arena_cache_limit = 0;
    if (strcmp(mode, "heap") != 0 && strcmp(mode, "arena") != 0) {
        fprintf(stderr, "usage: %s heap|arena [iterations] [records] "
                        "[mutation-rounds] [chunk-size] [content-bytes] "
                        "[large-object-threshold] [distribution] "
                        "[external-cache-limit]\n", argv[0]);
        return EXIT_FAILURE;
    }

    payload = NULL;
    if (payload_size > 0) {
        payload = malloc(payload_size);
        if (payload == NULL) {
            return EXIT_FAILURE;
        }
        memset(payload, 'x', payload_size);
    }

#if defined(__GLIBC__)
    memory = mallinfo2();
    heap_baseline = (size_t) memory.uordblks;
    heap_initial_live = 0;
    heap_final_live = 0;
#endif

    arena = NULL;
    if (strcmp(mode, "arena") == 0) {
        arena = cfl_arena_create_ex(chunk_size,
                                    large_object_threshold);
        if (arena == NULL) {
            return EXIT_FAILURE;
        }
        if (external_cache_limit_set) {
            cfl_arena_external_cache_limit_set(arena,
                                               external_cache_limit);
        }
    }

    start = wall_nanoseconds();
    for (iteration = 0; iteration < iterations; iteration++) {
        if (create_document(arena, records, payload, content_size,
                            distribution,
                            &document) != 0) {
            return EXIT_FAILURE;
        }
        if (arena != NULL) {
            initial_used = cfl_arena_bytes_used(arena);
        }
#if defined(__GLIBC__)
        else {
            memory = mallinfo2();
            heap_initial_live = (size_t) memory.uordblks - heap_baseline;
        }
#endif
        for (round = 0; round < mutation_rounds; round++) {
            if (mutate_document(arena, &document, round,
                                payload, content_size, distribution) != 0) {
                return EXIT_FAILURE;
            }
        }

#if defined(__GLIBC__)
        if (arena == NULL) {
            memory = mallinfo2();
            heap_final_live = (size_t) memory.uordblks - heap_baseline;
        }
#endif

        if (arena == NULL) {
            cfl_variant_destroy(document.root);
        }
        else {
            reserved = cfl_arena_bytes_reserved(arena);
            used = cfl_arena_bytes_used(arena);
            arena_cache_bytes =
                cfl_arena_external_cache_bytes(arena);
            arena_cache_limit =
                cfl_arena_external_cache_limit_get(arena);
            if (iteration + 1 < iterations) {
                cfl_arena_reset(arena);
            }
        }
    }
    elapsed = wall_nanoseconds() - start;
    operation_count = (double) iterations * (double) records;
    if (mutation_rounds > 0) {
        operation_count *= (double) mutation_rounds;
    }

    if (arena != NULL) {
        cfl_arena_destroy(arena);
    }
    printf("mode=%s distribution=%s iterations=%zu records=%zu "
           "mutation_rounds=%zu content_bytes=%zu chunk_size=%zu threshold=%zu "
           "elapsed_ns=%llu ns_per_operation=%.2f",
           mode, distribution, iterations, records, mutation_rounds,
           content_size, chunk_size, large_object_threshold,
           (unsigned long long) elapsed,
           (double) elapsed / operation_count);
#if !defined(CFL_SYSTEM_WINDOWS)
    getrusage(RUSAGE_SELF, &usage);
    printf(" max_rss_kb=%ld", usage.ru_maxrss);
#endif
#if defined(__GLIBC__)
    memory = mallinfo2();
    if (strcmp(mode, "heap") == 0) {
        printf(" heap_initial_live=%zu heap_final_live=%zu "
               "heap_retained_after_destroy=%zu heap_free=%zu",
               heap_initial_live, heap_final_live,
               (size_t) memory.uordblks - heap_baseline,
               (size_t) memory.fordblks);
    }
#endif
    if (strcmp(mode, "arena") == 0) {
        printf(" arena_reserved=%zu arena_initial_used=%zu arena_used=%zu "
               "arena_mutation_growth=%zu arena_slack=%zu "
               "arena_external_cache=%zu arena_external_cache_limit=%zu",
               reserved, initial_used, used, used - initial_used,
               reserved - used,
               arena_cache_bytes, arena_cache_limit);
    }
    putchar('\n');
    free(payload);
    return EXIT_SUCCESS;
}
