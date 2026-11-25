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

/* CFL objects hold pointers, sizes, integers and doubles */
union test_object_align {
    void *pointer_value;
    size_t size_value;
    uint64_t uint64_value;
    double double_value;
};

struct test_object_alignment_probe {
    char byte;
    union test_object_align value;
};

struct test_variant_probe {
    char byte;
    struct cfl_variant value;
};

struct test_kvpair_probe {
    char byte;
    struct cfl_kvpair value;
};

struct test_kvlist_probe {
    char byte;
    struct cfl_kvlist value;
};

struct test_array_probe {
    char byte;
    struct cfl_array value;
};

#define TEST_MAX_ALIGNMENT offsetof(struct test_alignment_probe, value)
#define TEST_OBJECT_ALIGNMENT offsetof(struct test_object_alignment_probe, value)

/* owned SDS payloads up to this size are recycled through size classes */
#define TEST_SDS_POOLED_PAYLOAD 1024

static int is_aligned(const void *pointer, size_t alignment)
{
    return ((uintptr_t) pointer % alignment) == 0;
}

static uint32_t test_random(uint32_t *state)
{
    *state = (*state * 1103515245u) + 12345u;
    return (*state >> 8) & 0xffffff;
}

struct test_allocator_context {
    size_t allocation_count;
    size_t free_count;
    size_t fail_after;
    size_t allocation_sizes[8];
};

static void *test_allocator_malloc(void *data, size_t size)
{
    void *result;
    struct test_allocator_context *context;

    context = data;
    if (context->allocation_count >= context->fail_after) {
        return NULL;
    }

    result = malloc(size);
    if (result != NULL) {
        if (context->allocation_count < 8) {
            context->allocation_sizes[context->allocation_count] = size;
        }
        context->allocation_count++;
    }

    return result;
}

static void test_allocator_free(void *data, void *pointer)
{
    struct test_allocator_context *context;

    context = data;
    context->free_count++;
    free(pointer);
}

static void public_raw_allocations(void)
{
    unsigned char *zeroed;
    unsigned char source[] = {0x01, 0x02, 0x03, 0x04};
    unsigned char *copy;
    char *string;
    void *pointer;
    size_t alignment;
    size_t index;
    struct cfl_arena *arena;

    arena = cfl_arena_create(128);
    TEST_CHECK(arena != NULL);
    alignment = offsetof(struct test_alignment_probe, value);

    for (index = 1; index <= 64; index++) {
        pointer = cfl_arena_malloc(arena, index);
        TEST_CHECK(pointer != NULL);
        TEST_CHECK((uintptr_t) pointer % alignment == 0);
    }

    zeroed = cfl_arena_calloc(arena, 8, sizeof(unsigned char));
    TEST_CHECK(zeroed != NULL);
    for (index = 0; index < 8; index++) {
        TEST_CHECK(zeroed[index] == 0);
    }

    copy = cfl_arena_memdup(arena, source, sizeof(source));
    TEST_CHECK(copy != NULL);
    TEST_CHECK(memcmp(copy, source, sizeof(source)) == 0);

    string = cfl_arena_strndup(arena, "arena-data", 5);
    TEST_CHECK(string != NULL);
    TEST_CHECK(strcmp(string, "arena") == 0);
    string = cfl_arena_strndup(arena, "", 0);
    TEST_CHECK(string != NULL);
    TEST_CHECK(string[0] == '\0');

    cfl_arena_destroy(arena);
}

static void public_raw_allocation_failures(void)
{
    size_t used;
    struct cfl_arena *arena;

    arena = cfl_arena_create(128);
    TEST_CHECK(arena != NULL);
    used = cfl_arena_bytes_used(arena);

    TEST_CHECK(cfl_arena_malloc(NULL, 1) == NULL);
    TEST_CHECK(cfl_arena_malloc(arena, 0) == NULL);
    TEST_CHECK(cfl_arena_malloc(arena, SIZE_MAX) == NULL);
    TEST_CHECK(cfl_arena_calloc(arena, SIZE_MAX, 2) == NULL);
    TEST_CHECK(cfl_arena_calloc(arena, 0, 1) == NULL);
    TEST_CHECK(cfl_arena_memdup(arena, NULL, 1) == NULL);
    TEST_CHECK(cfl_arena_memdup(arena, "x", 0) == NULL);
    TEST_CHECK(cfl_arena_strndup(arena, NULL, 0) == NULL);
    TEST_CHECK(cfl_arena_strndup(arena, "x", SIZE_MAX) == NULL);
    TEST_CHECK(cfl_arena_bytes_used(arena) == used);

    cfl_arena_destroy(arena);
}

static void options_growth_and_callbacks(void)
{
    char payload[2048];
    cfl_sds_t value;
    void *pointer;
    struct cfl_arena *arena;
    struct cfl_arena_options options;
    struct test_allocator_context context;

    memset(&context, 0, sizeof(context));
    context.fail_after = SIZE_MAX;
    cfl_arena_options_init(&options);
    options.chunk_size = 64;
    options.maximum_chunk_size = 256;
    options.malloc_fn = test_allocator_malloc;
    options.free_fn = test_allocator_free;
    options.allocator_context = &context;

    arena = cfl_arena_create_with_options(&options);
    TEST_CHECK(arena != NULL);
    TEST_CHECK(context.allocation_count == 1);

    pointer = cfl_arena_malloc(arena, 48);
    TEST_CHECK(pointer != NULL);
    pointer = cfl_arena_malloc(arena, 48);
    TEST_CHECK(pointer != NULL);
    pointer = cfl_arena_malloc(arena, 96);
    TEST_CHECK(pointer != NULL);
    TEST_CHECK(context.allocation_count == 4);
    TEST_CHECK(context.allocation_sizes[1] < context.allocation_sizes[2]);
    TEST_CHECK(context.allocation_sizes[2] < context.allocation_sizes[3]);

    cfl_arena_reset(arena);
    TEST_CHECK(cfl_arena_bytes_used(arena) == 0);
    pointer = cfl_arena_malloc(arena, 48);
    TEST_CHECK(pointer != NULL);

    memset(payload, 'x', sizeof(payload));
    value = cfl_sds_create_len_in(arena, payload, (int) sizeof(payload));
    TEST_CHECK(value != NULL);
    cfl_sds_destroy(value);

    cfl_arena_destroy(arena);
    TEST_CHECK(context.free_count == context.allocation_count);

    options.maximum_chunk_size = 32;
    TEST_CHECK(cfl_arena_create_with_options(&options) == NULL);
    options.maximum_chunk_size = 64;
    options.free_fn = NULL;
    TEST_CHECK(cfl_arena_create_with_options(&options) == NULL);
    TEST_CHECK(cfl_arena_create_with_options(NULL) == NULL);
    options.free_fn = test_allocator_free;
    options.struct_size = offsetof(struct cfl_arena_options,
                                   allocator_context);
    TEST_CHECK(cfl_arena_create_with_options(&options) == NULL);
}

static void callback_allocation_failure(void)
{
    void *pointer;
    struct cfl_arena *arena;
    struct cfl_arena_options options;
    struct test_allocator_context context;

    memset(&context, 0, sizeof(context));
    context.fail_after = 0;
    cfl_arena_options_init(&options);
    options.chunk_size = 64;
    options.malloc_fn = test_allocator_malloc;
    options.free_fn = test_allocator_free;
    options.allocator_context = &context;
    TEST_CHECK(cfl_arena_create_with_options(&options) == NULL);

    context.fail_after = 1;
    arena = cfl_arena_create_with_options(&options);
    TEST_CHECK(arena != NULL);
    TEST_CHECK(cfl_arena_malloc(arena, 1) == NULL);
    TEST_CHECK(cfl_arena_bytes_used(arena) == 0);

    context.fail_after = SIZE_MAX;
    pointer = cfl_arena_malloc(arena, 1);
    TEST_CHECK(pointer != NULL);
    cfl_arena_destroy(arena);
    TEST_CHECK(context.free_count == context.allocation_count);
}

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
    TEST_CHECK(is_aligned(CFL_SDS_HEADER(first_buffer), TEST_OBJECT_ALIGNMENT));
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
    static const size_t sizes[] = {0, 1, 7, 8, 15, 16, 31, 32, 33, 64, 65,
                                   127, 128, 129, 256, 257, 512, 513, 1023,
                                   1024};
    struct cfl_arena *arena;
    cfl_sds_t first;
    cfl_sds_t second;
    cfl_sds_t grown;
    char payload[1024];
    size_t capacity;
    size_t index;

    memset(payload, 's', sizeof(payload));
    arena = cfl_arena_create(8192);
    TEST_CHECK(arena != NULL);

    for (index = 0; index < sizeof(sizes) / sizeof(sizes[0]); index++) {
        first = cfl_sds_create_len_in(arena, payload, (int) sizes[index]);
        TEST_CHECK(first != NULL);
        TEST_CHECK(cfl_sds_alloc(first) >= sizes[index]);
        cfl_sds_destroy(first);
        second = cfl_sds_create_len_in(arena, payload, (int) sizes[index]);
        TEST_CHECK(second == first);
        cfl_sds_destroy(second);
    }

    /* growing past the capacity moves to the next class, keeping the data */
    first = cfl_sds_create_len_in(arena, payload, 31);
    TEST_CHECK(first != NULL);
    capacity = cfl_sds_alloc(first);
    TEST_CHECK(capacity >= 31);
    grown = cfl_sds_increase(first, capacity - 31 + 1);
    TEST_CHECK(grown != NULL);
    TEST_CHECK(grown != first);
    TEST_CHECK(cfl_sds_alloc(grown) > capacity);
    TEST_CHECK(cfl_sds_len(grown) == 31);
    TEST_CHECK(memcmp(grown, payload, 31) == 0);
    TEST_CHECK(grown[31] == '\0');

    /* the released slot serves the next string of the same class */
    second = cfl_sds_create_len_in(arena, payload, 31);
    TEST_CHECK(second == first);
    cfl_sds_destroy(second);
    cfl_sds_destroy(grown);
    cfl_arena_destroy(arena);
}

static void sds_class_boundaries(void)
{
    struct cfl_arena *arena;
    cfl_sds_t value;
    cfl_sds_t again;
    char payload[TEST_SDS_POOLED_PAYLOAD + 64];
    size_t previous_capacity;
    size_t capacity;
    size_t used;
    size_t size;

    memset(payload, 'b', sizeof(payload));
    arena = cfl_arena_create(4096);
    TEST_CHECK(arena != NULL);
    if (arena == NULL) {
        return;
    }

    previous_capacity = 0;
    for (size = 0; size <= TEST_SDS_POOLED_PAYLOAD + 32; size++) {
        used = cfl_arena_bytes_used(arena);
        value = cfl_sds_create_len_in(arena, payload, (int) size);
        TEST_CHECK(value != NULL);
        if (value == NULL) {
            break;
        }

        capacity = cfl_sds_alloc(value);
        TEST_CHECK(cfl_sds_len(value) == size);
        TEST_CHECK(capacity >= size);
        TEST_CHECK(cfl_sds_avail(value) == capacity - size);
        TEST_CHECK(value[size] == '\0');
        TEST_CHECK(memcmp(value, payload, size) == 0);
        TEST_CHECK(is_aligned(CFL_SDS_HEADER(value), TEST_OBJECT_ALIGNMENT));

        if (size <= TEST_SDS_POOLED_PAYLOAD) {
            /* class capacities never shrink as the payload grows */
            TEST_CHECK(capacity >= previous_capacity);
            previous_capacity = capacity;

            /* short strings are sized within one alignment unit */
            if (size < 128) {
                TEST_CHECK(capacity - size < TEST_OBJECT_ALIGNMENT);
            }
            else {
                TEST_CHECK(capacity - size <= size / 4 + TEST_OBJECT_ALIGNMENT);
            }
        }
        else {
            TEST_CHECK(capacity == size);
        }

        cfl_sds_destroy(value);

        /* larger strings below the external threshold live until reset */
        if (size <= TEST_SDS_POOLED_PAYLOAD) {
            TEST_CHECK(cfl_arena_bytes_used(arena) == used);
            again = cfl_sds_create_len_in(arena, payload, (int) size);
            TEST_CHECK(again == value);
            cfl_sds_destroy(again);
        }
    }

    cfl_arena_destroy(arena);
}

static void sds_capacity_is_writable(void)
{
    struct cfl_arena *arena;
    cfl_sds_t values[256];
    char payload[2048];
    size_t capacity;
    size_t index;
    size_t offset;
    int intact;

    memset(payload, 'p', sizeof(payload));
    arena = cfl_arena_create(1024);
    TEST_CHECK(arena != NULL);
    if (arena == NULL) {
        return;
    }

    /* fill every string to its reported capacity, neighbours must survive */
    for (index = 0; index < 256; index++) {
        values[index] = cfl_sds_create_len_in(arena, payload,
                                              (int) ((index * 37) % 1500));
        TEST_CHECK(values[index] != NULL);
        if (values[index] == NULL) {
            cfl_arena_destroy(arena);
            return;
        }
        capacity = cfl_sds_alloc(values[index]);
        memset(values[index], (int) ('A' + (index % 26)), capacity);
        cfl_sds_set_len(values[index], capacity);
        TEST_CHECK(values[index][capacity] == '\0');
    }

    for (index = 0; index < 256; index++) {
        capacity = cfl_sds_alloc(values[index]);
        TEST_CHECK(cfl_sds_len(values[index]) == capacity);
        intact = 1;
        for (offset = 0; offset < capacity; offset++) {
            if (values[index][offset] != (char) ('A' + (index % 26))) {
                intact = 0;
                break;
            }
        }
        TEST_CHECK(intact == 1);
        TEST_CHECK(values[index][capacity] == '\0');
        TEST_MSG("string %zu with capacity %zu", index, capacity);
    }

    for (index = 0; index < 256; index += 2) {
        cfl_sds_destroy(values[index]);
    }
    for (index = 1; index < 256; index += 2) {
        TEST_CHECK(values[index][0] == (char) ('A' + (index % 26)));
        cfl_sds_destroy(values[index]);
    }
    TEST_CHECK(cfl_arena_bytes_used(arena) == 0);

    cfl_arena_destroy(arena);
}

static void sds_grow_across_classes(void)
{
    struct cfl_arena *arena;
    cfl_sds_t value;
    cfl_sds_t result;
    char expected[3001];
    size_t index;

    arena = cfl_arena_create_ex(2048, 1500);
    TEST_CHECK(arena != NULL);
    if (arena == NULL) {
        return;
    }

    /* small classes, medium classes, chunk storage and external storage */
    value = cfl_sds_create_len_in(arena, "", 0);
    TEST_CHECK(value != NULL);
    for (index = 0; index < 3000 && value != NULL; index++) {
        expected[index] = (char) ('a' + (index % 26));
        result = cfl_sds_cat(value, &expected[index], 1);
        TEST_CHECK(result != NULL);
        if (result == NULL) {
            break;
        }
        value = result;
        TEST_CHECK(is_aligned(CFL_SDS_HEADER(value), TEST_OBJECT_ALIGNMENT));
        TEST_CHECK(cfl_sds_len(value) == index + 1);
        TEST_CHECK(cfl_sds_alloc(value) >= index + 1);
        TEST_CHECK(value[index + 1] == '\0');
    }
    expected[3000] = '\0';
    TEST_CHECK(value != NULL && strcmp(value, expected) == 0);

    /* self append and printf keep working on arena storage */
    result = cfl_sds_cat(value, value, 10);
    TEST_CHECK(result != NULL);
    if (result != NULL) {
        value = result;
        TEST_CHECK(cfl_sds_len(value) == 3010);
        TEST_CHECK(memcmp(value + 3000, expected, 10) == 0);
    }
    result = cfl_sds_printf(&value, "-%d", 42);
    TEST_CHECK(result != NULL);
    TEST_CHECK(cfl_sds_len(value) == 3013);
    TEST_CHECK(strcmp(value + 3010, "-42") == 0);

    cfl_sds_destroy(value);
    cfl_arena_destroy(arena);
}

static void object_alignment(void)
{
    struct cfl_arena *arena;
    struct cfl_variant *variant;
    struct cfl_kvlist *list;
    struct cfl_kvpair *pair;
    struct cfl_array *array;
    struct cfl_variant *entry;
    struct cfl_list *head;
    char key[8];
    size_t index;

    arena = cfl_arena_create(512);
    TEST_CHECK(arena != NULL);
    if (arena == NULL) {
        return;
    }

    list = cfl_kvlist_create_in(arena);
    array = cfl_array_create_in(arena, 1);
    TEST_CHECK(list != NULL && array != NULL);
    if (list == NULL || array == NULL) {
        cfl_arena_destroy(arena);
        return;
    }
    TEST_CHECK(cfl_array_resizable(array, CFL_TRUE) == 0);

    /* odd sized keys and payloads shift the bump pointer between objects */
    for (index = 0; index < 64; index++) {
        snprintf(key, sizeof(key), "k%zu", index);
        TEST_CHECK(cfl_kvlist_insert_string_s(list, key, strlen(key), "abc",
                                              index % 4, CFL_FALSE) == 0);
        TEST_CHECK(cfl_kvlist_insert_double(list, "", (double) index) == 0);
        TEST_CHECK(cfl_array_append_uint64(array, index) == 0);

        variant = cfl_variant_create_from_int64_in(arena, (int64_t) index);
        TEST_CHECK(variant != NULL);
        TEST_CHECK(is_aligned(variant, TEST_OBJECT_ALIGNMENT));
        TEST_CHECK(is_aligned(variant,
                              offsetof(struct test_variant_probe, value)));
        cfl_variant_destroy(variant);
    }

    TEST_CHECK(is_aligned(list, offsetof(struct test_kvlist_probe, value)));
    TEST_CHECK(is_aligned(array, offsetof(struct test_array_probe, value)));
    TEST_CHECK(is_aligned(array->entries, sizeof(void *)));

    cfl_list_foreach(head, &list->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        TEST_CHECK(is_aligned(pair, offsetof(struct test_kvpair_probe, value)));
        TEST_CHECK(is_aligned(pair->val,
                              offsetof(struct test_variant_probe, value)));
        TEST_CHECK(is_aligned(CFL_SDS_HEADER(pair->key),
                              TEST_OBJECT_ALIGNMENT));
    }

    for (index = 0; index < cfl_array_size(array); index++) {
        entry = cfl_array_fetch_by_index(array, index);
        TEST_CHECK(entry != NULL);
        TEST_CHECK(is_aligned(entry, offsetof(struct test_variant_probe, value)));
        TEST_CHECK(entry->data.as_uint64 == index);
    }

    cfl_kvlist_destroy(list);
    cfl_array_destroy(array);
    cfl_arena_destroy(arena);
}

static void raw_alignment_after_objects(void)
{
    struct cfl_arena *arena;
    struct cfl_variant *variant;
    cfl_sds_t key;
    void *pointer;
    size_t index;

    arena = cfl_arena_create(256);
    TEST_CHECK(arena != NULL);
    if (arena == NULL) {
        return;
    }

    /* raw allocations keep the public alignment between packed objects */
    for (index = 0; index < 64; index++) {
        variant = cfl_variant_create_from_bool_in(arena, CFL_TRUE);
        TEST_CHECK(variant != NULL);
        key = cfl_sds_create_len_in(arena, "key", (int) (index % 5));
        TEST_CHECK(key != NULL);

        pointer = cfl_arena_malloc(arena, 1 + (index % 3));
        TEST_CHECK(pointer != NULL && is_aligned(pointer, TEST_MAX_ALIGNMENT));
        pointer = cfl_arena_calloc(arena, 3, 1);
        TEST_CHECK(pointer != NULL && is_aligned(pointer, TEST_MAX_ALIGNMENT));
        pointer = cfl_arena_memdup(arena, "abc", 3);
        TEST_CHECK(pointer != NULL && is_aligned(pointer, TEST_MAX_ALIGNMENT));
        pointer = cfl_arena_strndup(arena, "abc", 2);
        TEST_CHECK(pointer != NULL && is_aligned(pointer, TEST_MAX_ALIGNMENT));
    }

    cfl_arena_destroy(arena);
}

static void compact_short_keys(void)
{
    struct cfl_arena *arena;
    struct cfl_kvlist *record;
    struct cfl_variant *root;
    static char *keys[] = {"msg", "user", "path", "status", "level", "ts"};
    size_t record_count;
    size_t index;
    size_t key_index;
    size_t limit;
    size_t reserved;
    size_t object;

    record_count = 256;
    arena = cfl_arena_create(16384);
    TEST_CHECK(arena != NULL);
    if (arena == NULL) {
        return;
    }

    /* worst case: every object padded by one alignment unit */
    object = TEST_OBJECT_ALIGNMENT;
    limit = sizeof(struct cfl_kvlist) + object + sizeof(struct cfl_variant) + object;
    for (key_index = 0; key_index < 6; key_index++) {
        limit += sizeof(struct cfl_kvpair) + object +
                 sizeof(struct cfl_variant) + object +
                 2 * sizeof(void *) + CFL_SDS_HEADER_SIZE +
                 strlen(keys[key_index]) + 1 + object;
    }

    for (index = 0; index < record_count; index++) {
        record = cfl_kvlist_create_in(arena);
        TEST_CHECK(record != NULL);
        if (record == NULL) {
            break;
        }
        for (key_index = 0; key_index < 6; key_index++) {
            TEST_CHECK(cfl_kvlist_insert_int64(record, keys[key_index],
                                               (int64_t) index) == 0);
        }
        root = cfl_variant_create_from_kvlist_in(arena, record);
        TEST_CHECK(root != NULL);
    }

    /* allow one partially used chunk plus chunk headers */
    reserved = cfl_arena_bytes_reserved(arena);
    TEST_CHECK(reserved <= record_count * limit + 16384 + 256);
    TEST_MSG("reserved %zu limit %zu", reserved, record_count * limit + 16384 + 256);

    cfl_arena_destroy(arena);
}

static void reset_reuses_storage_without_aliasing(void)
{
    struct cfl_arena *arena;
    cfl_sds_t first;
    cfl_sds_t second;
    struct cfl_variant *variant;
    struct cfl_variant *other;
    size_t reserved;
    int round;

    arena = cfl_arena_create(1024);
    TEST_CHECK(arena != NULL);
    if (arena == NULL) {
        return;
    }

    for (round = 0; round < 8; round++) {
        /* released slots must not survive the reset in the free lists */
        first = cfl_sds_create_len_in(arena, "abc", 3);
        variant = cfl_variant_create_from_int64_in(arena, round);
        TEST_CHECK(first != NULL && variant != NULL);
        cfl_sds_destroy(first);
        cfl_variant_destroy(variant);
        reserved = cfl_arena_bytes_reserved(arena);
        cfl_arena_reset(arena);
        TEST_CHECK(cfl_arena_bytes_used(arena) == 0);
        TEST_CHECK(cfl_arena_bytes_reserved(arena) == reserved);

        first = cfl_sds_create_len_in(arena, "abc", 3);
        second = cfl_sds_create_len_in(arena, "xyz", 3);
        variant = cfl_variant_create_from_int64_in(arena, 1);
        other = cfl_variant_create_from_int64_in(arena, 2);
        TEST_CHECK(first != NULL && second != NULL);
        TEST_CHECK(variant != NULL && other != NULL);
        TEST_CHECK(first != second && variant != other);
        TEST_CHECK(strcmp(first, "abc") == 0 && strcmp(second, "xyz") == 0);
        TEST_CHECK(variant->data.as_int64 == 1 && other->data.as_int64 == 2);
        cfl_arena_reset(arena);
    }

    cfl_arena_destroy(arena);
}

static void heap_storage_unchanged(void)
{
    cfl_sds_t value;
    struct cfl_kvlist *list;
    struct cfl_kvpair *pair;

    /* heap strings keep their exact capacities */
    value = cfl_sds_create_len("abc", 3);
    TEST_CHECK(value != NULL);
    TEST_CHECK(cfl_sds_alloc(value) == 3);
    cfl_sds_destroy(value);

    value = cfl_sds_create_size(100);
    TEST_CHECK(value != NULL);
    TEST_CHECK(cfl_sds_alloc(value) == 100);
    TEST_CHECK(cfl_sds_len(value) == 0);
    cfl_sds_destroy(value);

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);
    if (list == NULL) {
        return;
    }
    TEST_CHECK(cfl_kvlist_insert_int64(list, "status", 200) == 0);
    pair = cfl_list_entry_first(&list->list, struct cfl_kvpair, _head);
    TEST_CHECK(pair->arena == NULL);
    TEST_CHECK(cfl_sds_alloc(pair->key) == 6);
    cfl_kvlist_destroy(list);
}

#define TEST_MUTATION_KEYS 48

static void randomized_kvlist_mutation(void)
{
    struct cfl_arena *arena;
    struct cfl_kvlist *list;
    struct cfl_variant *value;
    char *payload;
    char keys[TEST_MUTATION_KEYS][224];
    char names[TEST_MUTATION_KEYS][224];
    size_t lengths[TEST_MUTATION_KEYS];
    int present[TEST_MUTATION_KEYS];
    uint32_t state;
    size_t key_length;
    size_t index;
    size_t slot;
    size_t count;
    int operation;
    int round;
    int expected;

    payload = malloc(4096);
    TEST_CHECK(payload != NULL);
    if (payload == NULL) {
        return;
    }
    for (index = 0; index < 4096; index++) {
        payload[index] = (char) ('a' + (index % 23));
    }

    /* small chunks and a low external threshold stress every storage path */
    arena = cfl_arena_create_ex(1024, 2048);
    TEST_CHECK(arena != NULL);
    if (arena == NULL) {
        free(payload);
        return;
    }

    state = 2026;
    for (round = 0; round < 4; round++) {
        list = cfl_kvlist_create_in(arena);
        TEST_CHECK(list != NULL);
        if (list == NULL) {
            break;
        }

        for (slot = 0; slot < TEST_MUTATION_KEYS; slot++) {
            key_length = 1 + test_random(&state) % 200;
            memset(keys[slot], 'k', key_length);
            snprintf(keys[slot], 8, "%02zu", slot);
            keys[slot][2] = 'k';
            keys[slot][key_length] = '\0';
            strcpy(names[slot], keys[slot]);
            present[slot] = 0;
            lengths[slot] = 0;
        }

        for (index = 0; index < 4000; index++) {
            slot = test_random(&state) % TEST_MUTATION_KEYS;
            operation = (int) (test_random(&state) % 4);

            if (operation == 0 && !present[slot]) {
                lengths[slot] = test_random(&state) % 3000;
                TEST_CHECK(cfl_kvlist_insert_string_s(list, names[slot],
                                                      strlen(names[slot]),
                                                      payload, lengths[slot],
                                                      CFL_FALSE) == 0);
                present[slot] = 1;
            }
            else if (operation == 1 && present[slot]) {
                TEST_CHECK(cfl_kvlist_remove(list, names[slot]) == CFL_TRUE);
                present[slot] = 0;
            }
            else if (operation == 2 && present[slot]) {
                /* rename between the short and the long spelling */
                if (strcmp(names[slot], keys[slot]) == 0) {
                    snprintf(names[slot], 8, "%02zu", slot);
                }
                else {
                    strcpy(names[slot], keys[slot]);
                }
                TEST_CHECK(cfl_kvlist_rename_s(list, keys[slot], strlen(keys[slot]),
                                               names[slot], strlen(names[slot])) == 0 ||
                           strcmp(names[slot], keys[slot]) == 0);
                if (strcmp(names[slot], keys[slot]) == 0) {
                    snprintf(names[slot], 8, "%02zu", slot);
                    TEST_CHECK(cfl_kvlist_rename_s(list, names[slot],
                                                   strlen(names[slot]),
                                                   keys[slot],
                                                   strlen(keys[slot])) == 0);
                    strcpy(names[slot], keys[slot]);
                }
            }
            else if (operation == 3 && present[slot]) {
                TEST_CHECK(cfl_kvlist_remove(list, names[slot]) == CFL_TRUE);
                lengths[slot] = test_random(&state) % 3000;
                TEST_CHECK(cfl_kvlist_insert_string_s(list, names[slot],
                                                      strlen(names[slot]),
                                                      payload, lengths[slot],
                                                      CFL_FALSE) == 0);
            }
        }

        count = 0;
        for (slot = 0; slot < TEST_MUTATION_KEYS; slot++) {
            value = cfl_kvlist_fetch(list, names[slot]);
            expected = present[slot];
            TEST_CHECK((value != NULL) == expected);
            if (value == NULL || !expected) {
                continue;
            }
            count++;
            TEST_CHECK(value->type == CFL_VARIANT_STRING);
            TEST_CHECK(cfl_sds_len(value->data.as_string) == lengths[slot]);
            TEST_CHECK(memcmp(value->data.as_string, payload,
                              lengths[slot]) == 0);
            TEST_CHECK(value->data.as_string[lengths[slot]] == '\0');
        }
        TEST_CHECK((size_t) cfl_kvlist_count(list) == count);

        cfl_kvlist_destroy(list);
        cfl_arena_reset(arena);
        TEST_CHECK(cfl_arena_bytes_used(arena) == 0);
    }

    cfl_arena_destroy(arena);
    free(payload);
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
    if (payload == NULL) {
        return;
    }
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
    TEST_CHECK(is_aligned(reused, offsetof(struct test_variant_probe, value)));
    cfl_variant_destroy(reused);
    cfl_arena_destroy(arena);
}

TEST_LIST = {
    {"public_raw_allocations", public_raw_allocations},
    {"public_raw_allocation_failures", public_raw_allocation_failures},
    {"options_growth_and_callbacks", options_growth_and_callbacks},
    {"callback_allocation_failure", callback_allocation_failure},
    {"arena_build_and_destroy", arena_build_and_destroy},
    {"arena_reset", arena_reset},
    {"reject_cross_arena_values", reject_cross_arena_values},
    {"mutable_otlp_log_graph", mutable_otlp_log_graph},
    {"reclaim_large_string_on_remove", reclaim_large_string_on_remove},
    {"reuse_variant_and_kvpair_slots", reuse_variant_and_kvpair_slots},
    {"create_like_and_rename", create_like_and_rename},
    {"reuse_sds_size_classes", reuse_sds_size_classes},
    {"sds_class_boundaries", sds_class_boundaries},
    {"sds_capacity_is_writable", sds_capacity_is_writable},
    {"sds_grow_across_classes", sds_grow_across_classes},
    {"object_alignment", object_alignment},
    {"raw_alignment_after_objects", raw_alignment_after_objects},
    {"compact_short_keys", compact_short_keys},
    {"reset_reuses_storage_without_aliasing", reset_reuses_storage_without_aliasing},
    {"heap_storage_unchanged", heap_storage_unchanged},
    {"randomized_kvlist_mutation", randomized_kvlist_mutation},
    {"bound_external_rounding_and_cache", bound_external_rounding_and_cache},
    {"reclaim_failed_variant_construction", reclaim_failed_variant_construction},
    {NULL, NULL}
};
