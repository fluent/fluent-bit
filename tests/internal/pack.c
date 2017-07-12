/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <monkey/mk_core.h>

#include "flb_tests_internal.h"

#define JSON_SINGLE_MAP1 FLB_TESTS_DATA_PATH "/data/pack/json_single_map_001.json"
#define JSON_SINGLE_MAP2 FLB_TESTS_DATA_PATH "/data/pack/json_single_map_002.json"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

/* Pack a simple JSON map */
void test_json_pack()
{
    int ret;
    size_t len;
    char *data;
    char *out_buf;
    int out_size;

    data = mk_file_to_buffer(JSON_SINGLE_MAP1);
    TEST_CHECK(data != NULL);

    len = strlen(data);

    ret = flb_pack_json(data, len, &out_buf, &out_size);
    TEST_CHECK(ret == 0);

    flb_free(data);
    flb_free(out_buf);
}

/* Pack a simple JSON map using a state */
void test_json_pack_iter()
{
    int i;
    int ret;
    size_t len;
    char *data;
    char *out_buf = NULL;
    int out_size;
    struct flb_pack_state state;

    data = mk_file_to_buffer(JSON_SINGLE_MAP1);
    TEST_CHECK(data != NULL);

    len = strlen(data);

    ret = flb_pack_state_init(&state);
    TEST_CHECK(ret == 0);

    /* Pass byte by byte */
    for (i = 1; i < len; i++) {
        ret = flb_pack_json_state(data, i, &out_buf, &out_size, &state);
        if (i + 1 != len) {
            TEST_CHECK(ret == FLB_ERR_JSON_PART);
        }
    }
    TEST_CHECK(ret != FLB_ERR_JSON_INVAL && ret != FLB_ERR_JSON_PART);

    flb_pack_state_reset(&state);
    flb_free(data);
    flb_free(out_buf);
}

/* Pack two concatenated JSON maps using a state */
void test_json_pack_mult()

{
    int ret;
    int maps = 0;
    size_t off = 0;
    size_t len1;
    size_t len2;
    size_t total;
    char *buf;
    char *data1;
    char *data2;
    char *out_buf;
    int out_size;
    msgpack_unpacked result;
    msgpack_object root;
    struct flb_pack_state state;

    data1 = mk_file_to_buffer(JSON_SINGLE_MAP1);
    TEST_CHECK(data1 != NULL);
    len1 = strlen(data1);

    data2 = mk_file_to_buffer(JSON_SINGLE_MAP2);
    TEST_CHECK(data2 != NULL);
    len2 = strlen(data2);

    buf = flb_malloc(len1 + len2 + 1);
    TEST_CHECK(buf != NULL);

    /* Merge buffers */
    memcpy(buf, data1, len1);
    memcpy(buf + len1, data2, len2);
    total = len1 + len2;
    buf[total] = '\0';

    /* Release buffers */
    flb_free(data1);
    flb_free(data2);

    ret = flb_pack_state_init(&state);
    TEST_CHECK(ret == 0);

    /* Enable the 'multiple' flag so the parser will accept concatenated msgs */
    state.multiple = FLB_TRUE;

    /* It should pack two msgpack-maps in out_buf */
    ret = flb_pack_json_state(buf, total, &out_buf, &out_size, &state);
    TEST_CHECK(ret == 0);

    /* Validate output buffer */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, out_buf, out_size, &off)) {
        maps++;
        root = result.data;
        TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);
    }
    msgpack_unpacked_destroy(&result);

    TEST_CHECK(maps == 2);

    flb_pack_state_reset(&state);
    flb_free(out_buf);
    flb_free(buf);
}

/* Pack two concatenated JSON maps byte by byte using a state */
void test_json_pack_mult_iter()

{
    int i;
    int ret;
    int maps = 0;
    int total_maps = 0;
    size_t off = 0;
    size_t len1;
    size_t len2;
    size_t total;
    char *buf;
    char *data1;
    char *data2;
    char *out_buf;
    int out_size;
    msgpack_unpacked result;
    msgpack_object root;
    jsmntok_t *t;
    struct flb_pack_state state;

    data1 = mk_file_to_buffer(JSON_SINGLE_MAP1);
    TEST_CHECK(data1 != NULL);
    len1 = strlen(data1);

    data2 = mk_file_to_buffer(JSON_SINGLE_MAP2);
    TEST_CHECK(data2 != NULL);
    len2 = strlen(data2);

    buf = flb_malloc(len1 + len2 + 1);
    TEST_CHECK(buf != NULL);

    /* Merge buffers */
    memcpy(buf, data1, len1);
    memcpy(buf + len1, data2, len2);
    total = len1 + len2;
    buf[total] = '\0';

    /* Release buffers */
    flb_free(data1);
    flb_free(data2);

    ret = flb_pack_state_init(&state);
    TEST_CHECK(ret == 0);

    /* Enable the 'multiple' flag so the parser will accept concatenated msgs */
    state.multiple = FLB_TRUE;

    /* Pass byte by byte */
    for (i = 1; i < total; i++) {
        ret = flb_pack_json_state(buf, i, &out_buf, &out_size, &state);
        if (ret == 0) {
            /* Consume processed bytes */
            t = &state.tokens[0];
            consume_bytes(buf, t->end, total);
            i = 1;
            total -= t->end;
            flb_pack_state_reset(&state);
            flb_pack_state_init(&state);

            /* Validate output buffer */
            off = 0;
            maps = 0;
            msgpack_unpacked_init(&result);
            while (msgpack_unpack_next(&result, out_buf, out_size, &off)) {
                root = result.data;
                TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);
                maps++;
                total_maps++;
            }
            TEST_CHECK(maps == 1);
            msgpack_unpacked_destroy(&result);
            flb_free(out_buf);
        }
    }

    TEST_CHECK(total_maps == 2);
    flb_pack_state_reset(&state);
    flb_free(buf);
}

TEST_LIST = {
    { "json_pack", test_json_pack },
    { "json_pack_iter", test_json_pack_iter},
    { "json_pack_mult", test_json_pack_mult},
    { "json_pack_mult_iter", test_json_pack_mult_iter},
    { 0 }
};
