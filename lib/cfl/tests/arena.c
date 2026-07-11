/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <cfl/cfl.h>
#include <string.h>
#include <limits.h>

#include "cfl_tests_internal.h"

union test_max_align {
    long double long_double_value;
    void *pointer_value;
    uint64_t uint64_value;
};

struct test_alignment_probe {
    char byte;
    union test_max_align value;
};

static void arena_build_and_destroy(void)
{
    struct cfl_arena *arena;
    struct cfl_array *array;
    struct cfl_kvlist *list;
    struct cfl_variant *root;
    int ret;

    arena = cfl_arena_create(256);
    TEST_CHECK(arena != NULL);

    list = cfl_kvlist_create_in(arena);
    TEST_CHECK(list != NULL);
    ret = cfl_kvlist_insert_string(list, "name", "cfl");
    TEST_CHECK(ret == 0);

    array = cfl_array_create_in(arena, 2);
    TEST_CHECK(array != NULL);
    ret = cfl_array_append_int64(array, 42);
    TEST_CHECK(ret == 0);
    ret = cfl_kvlist_insert_array(list, "values", array);
    TEST_CHECK(ret == 0);

    root = cfl_variant_create_from_kvlist_in(arena, list);
    TEST_CHECK(root != NULL);
    TEST_CHECK(cfl_arena_bytes_used(arena) > 0);
    TEST_CHECK(cfl_arena_bytes_reserved(arena) >=
               cfl_arena_bytes_used(arena));

    cfl_variant_destroy(root);
    cfl_arena_destroy(arena);
}

static void arena_reset(void)
{
    struct cfl_arena *arena;
    struct cfl_array *array;

    arena = cfl_arena_create(128);
    TEST_CHECK(arena != NULL);
    array = cfl_array_create_in(arena, 4);
    TEST_CHECK(array != NULL);
    TEST_CHECK(cfl_arena_bytes_reserved(arena) > 0);

    cfl_arena_reset(arena);
    TEST_CHECK(cfl_arena_bytes_reserved(arena) >= 128);
    TEST_CHECK(cfl_arena_bytes_used(arena) == 0);
    cfl_arena_destroy(arena);
}

static void reject_cross_arena_values(void)
{
    struct cfl_arena *arena;
    struct cfl_array *array;
    struct cfl_variant *value;

    arena = cfl_arena_create(128);
    TEST_CHECK(arena != NULL);
    array = cfl_array_create_in(arena, 1);
    value = cfl_variant_create_from_int64(1);
    TEST_CHECK(array != NULL && value != NULL);

    TEST_CHECK(cfl_array_append(array, value) == -1);
    cfl_variant_destroy(value);
    cfl_arena_destroy(arena);
}

static void mutable_otlp_log_graph(void)
{
    struct cfl_arena *arena;
    struct cfl_kvlist *root;
    struct cfl_kvlist *record;
    struct cfl_kvlist *attributes;
    struct cfl_array *records;
    struct cfl_variant *root_variant;
    struct cfl_variant *value;
    size_t initial_used;
    size_t final_used;
    int round;

    arena = cfl_arena_create(256);
    TEST_CHECK(arena != NULL);
    root = cfl_kvlist_create_in(arena);
    record = cfl_kvlist_create_in(arena);
    attributes = cfl_kvlist_create_in(arena);
    records = cfl_array_create_in(arena, 1);
    TEST_CHECK(root != NULL && record != NULL && attributes != NULL &&
               records != NULL);

    TEST_CHECK(cfl_kvlist_insert_string(record, "severityText", "INFO") == 0);
    TEST_CHECK(cfl_kvlist_insert_int64(attributes, "http.status_code", 200) == 0);
    TEST_CHECK(cfl_kvlist_insert_kvlist(record, "attributes", attributes) == 0);
    TEST_CHECK(cfl_array_append_kvlist(records, record) == 0);
    TEST_CHECK(cfl_kvlist_insert_array(root, "logRecords", records) == 0);
    root_variant = cfl_variant_create_from_kvlist_in(arena, root);
    TEST_CHECK(root_variant != NULL);
    initial_used = cfl_arena_bytes_used(arena);

    for (round = 0; round < 10; round++) {
        TEST_CHECK(cfl_kvlist_remove(record, "severityText") == CFL_TRUE);
        TEST_CHECK(cfl_kvlist_remove(attributes, "http.status_code") == CFL_TRUE);
        TEST_CHECK(cfl_kvlist_insert_string(record, "severityText", "WARN") == 0);
        TEST_CHECK(cfl_kvlist_insert_int64(attributes, "http.status_code", 503) == 0);
    }

    value = cfl_kvlist_fetch(record, "severityText");
    TEST_CHECK(value != NULL);
    TEST_CHECK(strcmp(value->data.as_string, "WARN") == 0);
    value = cfl_kvlist_fetch(attributes, "http.status_code");
    TEST_CHECK(value != NULL);
    TEST_CHECK(value->data.as_int64 == 503);
    TEST_CHECK(cfl_array_size(records) == 1);

    final_used = cfl_arena_bytes_used(arena);
    TEST_CHECK(final_used == initial_used);
    cfl_variant_destroy(root_variant);
    cfl_arena_destroy(arena);
}

static void reclaim_large_string_on_remove(void)
{
    struct cfl_arena *arena;
    struct cfl_kvlist *list;
    char payload[8192];
    size_t before_remove;
    size_t after_remove;
    size_t reserved_before_remove;
    char *first_buffer;
    struct cfl_variant *value;

    memset(payload, 'x', sizeof(payload));
    arena = cfl_arena_create_ex(1024, 4096);
    list = cfl_kvlist_create_in(arena);
    TEST_CHECK(arena != NULL && list != NULL);
    TEST_CHECK(cfl_arena_large_object_threshold(arena) == 4096);
    TEST_CHECK(cfl_kvlist_insert_string_s(list, "body", 4, payload,
                                          sizeof(payload), CFL_FALSE) == 0);
    value = cfl_kvlist_fetch(list, "body");
    TEST_CHECK(value != NULL);
    first_buffer = value->data.as_string;
    before_remove = cfl_arena_bytes_used(arena);
    reserved_before_remove = cfl_arena_bytes_reserved(arena);
    TEST_CHECK(cfl_kvlist_remove(list, "body") == CFL_TRUE);
    after_remove = cfl_arena_bytes_used(arena);
    TEST_CHECK(before_remove - after_remove >= sizeof(payload));
    TEST_CHECK(cfl_arena_bytes_reserved(arena) ==
               reserved_before_remove);
    TEST_CHECK(cfl_arena_external_cache_bytes(arena) >=
               sizeof(payload));
    TEST_CHECK(cfl_kvlist_insert_string_s(list, "body", 4, payload,
                                          sizeof(payload), CFL_FALSE) == 0);
    value = cfl_kvlist_fetch(list, "body");
    TEST_CHECK(value != NULL);
    TEST_CHECK(value->data.as_string == first_buffer);

    TEST_CHECK(cfl_kvlist_remove(list, "body") == CFL_TRUE);
    TEST_CHECK(cfl_arena_external_cache_bytes(arena) > 0);
    cfl_arena_external_cache_limit_set(arena, 0);
    TEST_CHECK(cfl_arena_external_cache_limit_get(arena) == 0);
    TEST_CHECK(cfl_arena_external_cache_bytes(arena) == 0);
    cfl_arena_destroy(arena);
}

static void reuse_variant_and_kvpair_slots(void)
{
    struct cfl_arena *arena;
    struct cfl_variant *first_variant;
    struct cfl_variant *second_variant;
    struct cfl_kvlist *list;
    struct cfl_kvpair *first_pair;
    struct cfl_kvpair *second_pair;

    arena = cfl_arena_create(1024);
    TEST_CHECK(arena != NULL);
    first_variant = cfl_variant_create_from_int64_in(arena, 1);
    TEST_CHECK(first_variant != NULL);
    cfl_variant_destroy(first_variant);
    second_variant = cfl_variant_create_from_int64_in(arena, 2);
    TEST_CHECK(second_variant == first_variant);
    cfl_variant_destroy(second_variant);

    list = cfl_kvlist_create_in(arena);
    TEST_CHECK(list != NULL);
    TEST_CHECK(cfl_kvlist_insert_int64(list, "first", 1) == 0);
    first_pair = cfl_list_entry_first(&list->list, struct cfl_kvpair, _head);
    TEST_CHECK(cfl_kvlist_remove(list, "first") == CFL_TRUE);
    TEST_CHECK(cfl_kvlist_insert_int64(list, "second", 2) == 0);
    second_pair = cfl_list_entry_first(&list->list, struct cfl_kvpair, _head);
    TEST_CHECK(second_pair == first_pair);
    cfl_kvlist_destroy(list);
    cfl_arena_destroy(arena);
}

static void create_like_and_rename(void)
{
    struct cfl_arena *arena;
    struct cfl_kvlist *parent;
    struct cfl_kvlist *child;
    struct cfl_array *array;
    struct cfl_array *child_array;

    arena = cfl_arena_create(1024);
    parent = cfl_kvlist_create_in(arena);
    child = cfl_kvlist_create_like(parent);
    array = cfl_array_create_in(arena, 1);
    child_array = cfl_array_create_like(array, 1);
    TEST_CHECK(arena != NULL && parent != NULL && child != NULL);
    TEST_CHECK(array != NULL && child_array != NULL);
    TEST_CHECK(child->arena == arena && child_array->arena == arena);

    TEST_CHECK(cfl_kvlist_insert_string(parent, "old", "value") == 0);
    TEST_CHECK(cfl_kvlist_rename_s(parent, "old", 3, "new", 3) == 0);
    TEST_CHECK(cfl_kvlist_fetch(parent, "old") == NULL);
    TEST_CHECK(cfl_kvlist_fetch(parent, "new") != NULL);

    cfl_array_destroy(child_array);
    cfl_array_destroy(array);
    cfl_kvlist_destroy(child);
    cfl_kvlist_destroy(parent);
    cfl_arena_destroy(arena);
}

static void reuse_sds_size_classes(void)
{
    static const size_t sizes[] = {1, 32, 33, 64, 65, 128,
                                   129, 256, 257, 512, 513, 1024};
    struct cfl_arena *arena;
    cfl_sds_t first;
    cfl_sds_t second;
    cfl_sds_t grown;
    char payload[1024];
    size_t index;

    memset(payload, 's', sizeof(payload));
    arena = cfl_arena_create(8192);
    TEST_CHECK(arena != NULL);

    for (index = 0; index < sizeof(sizes) / sizeof(sizes[0]); index++) {
        first = cfl_sds_create_len_in(arena, payload, (int) sizes[index]);
        TEST_CHECK(first != NULL);
        cfl_sds_destroy(first);
        second = cfl_sds_create_len_in(arena, payload, (int) sizes[index]);
        TEST_CHECK(second == first);
        cfl_sds_destroy(second);
    }

    first = cfl_sds_create_len_in(arena, payload, 31);
    TEST_CHECK(first != NULL);
    TEST_CHECK(cfl_sds_alloc(first) == 32);
    grown = cfl_sds_increase(first, 1);
    TEST_CHECK(grown != NULL);
    TEST_CHECK(cfl_sds_alloc(grown) == 64);
    TEST_CHECK(cfl_sds_len(grown) == 31);
    TEST_CHECK(memcmp(grown, payload, 31) == 0);

    second = cfl_sds_create_len_in(arena, payload, 32);
    TEST_CHECK(second == first);
    cfl_sds_destroy(second);
    cfl_sds_destroy(grown);
    cfl_arena_destroy(arena);
}

static void bound_external_rounding_and_cache(void)
{
    struct cfl_arena *arena;
    cfl_sds_t value;
    char *payload;
    size_t payload_size;
    size_t used;

    payload_size = 1024 * 1024;
    payload = malloc(payload_size);
    TEST_CHECK(payload != NULL);
    memset(payload, 'x', payload_size);

    arena = cfl_arena_create(8192);
    TEST_CHECK(arena != NULL);
    cfl_arena_external_cache_limit_set(arena, 1024 * 1024);

    value = cfl_sds_create_len_in(arena, payload, (int) payload_size);
    TEST_CHECK(value != NULL);
    used = cfl_arena_bytes_used(arena);
    TEST_CHECK(used <= payload_size + (payload_size / 4) + 4096);
    cfl_sds_destroy(value);
    TEST_CHECK(cfl_arena_external_cache_bytes(arena) <=
               cfl_arena_external_cache_limit_get(arena));

    cfl_arena_destroy(arena);
    free(payload);
}

static void reclaim_failed_variant_construction(void)
{
    struct cfl_arena *arena;
    struct cfl_array *array;
    struct cfl_variant *value;
    struct cfl_variant *reused;
    size_t before_failure;
    size_t after_failure;

    arena = cfl_arena_create(1024);
    TEST_CHECK(arena != NULL);
    before_failure = cfl_arena_bytes_used(arena);
    value = cfl_variant_create_from_string_s_in(arena, "x",
                                                (size_t) INT_MAX + 1,
                                                CFL_FALSE);
    TEST_CHECK(value == NULL);
    after_failure = cfl_arena_bytes_used(arena);
    TEST_CHECK(after_failure == before_failure);

    array = cfl_array_create_in(arena, SIZE_MAX);
    TEST_CHECK(array == NULL);
    TEST_CHECK(cfl_arena_bytes_used(arena) == after_failure);

    reused = cfl_variant_create_from_int64_in(arena, 1);
    TEST_CHECK(reused != NULL);
    TEST_CHECK(((uintptr_t) reused %
                offsetof(struct test_alignment_probe, value)) == 0);
    cfl_variant_destroy(reused);
    cfl_arena_destroy(arena);
}

TEST_LIST = {
    {"arena_build_and_destroy", arena_build_and_destroy},
    {"arena_reset", arena_reset},
    {"reject_cross_arena_values", reject_cross_arena_values},
    {"mutable_otlp_log_graph", mutable_otlp_log_graph},
    {"reclaim_large_string_on_remove", reclaim_large_string_on_remove},
    {"reuse_variant_and_kvpair_slots", reuse_variant_and_kvpair_slots},
    {"create_like_and_rename", create_like_and_rename},
    {"reuse_sds_size_classes", reuse_sds_size_classes},
    {"bound_external_rounding_and_cache", bound_external_rounding_and_cache},
    {"reclaim_failed_variant_construction", reclaim_failed_variant_construction},
    {NULL, NULL}
};
