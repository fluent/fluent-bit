/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_str.h>
#include <monkey/mk_core.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include "flb_tests_internal.h"

/* JSON iteration tests */
#define JSON_SINGLE_MAP1 FLB_TESTS_DATA_PATH "/data/pack/json_single_map_001.json"
#define JSON_SINGLE_MAP2 FLB_TESTS_DATA_PATH "/data/pack/json_single_map_002.json"

/* Pack Samples path */
#define PACK_SAMPLES     FLB_TESTS_DATA_PATH "/data/pack/"

struct pack_test {
    char *msgpack;
    char *json;
};

/* If we get more than 256 tests, just update the size */
struct pack_test pt[256];

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

/* Iterate data/pack/ directory and compose an array with files to test */
static int utf8_tests_create()
{
    int i = 0;
    int len;
    int ret;
    char ext_mp[PATH_MAX];
    char ext_json[PATH_MAX];
    DIR *dir;
    struct pack_test *test;
    struct dirent *entry;
    struct stat st;

    memset(pt, '\0', sizeof(pt));

    dir = opendir(PACK_SAMPLES);
    TEST_CHECK(dir != NULL);
    if (dir == NULL) {
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) {
            continue;
        }

        len = strlen(entry->d_name);
        if (strcmp(entry->d_name + (len - 3), ".mp") != 0) {
            continue;
        }

        snprintf(ext_mp, sizeof(ext_mp) - 1,
                 "%s%s", PACK_SAMPLES, entry->d_name);
        len = snprintf(ext_json, sizeof(ext_json) - 1, "%s%s",
                       PACK_SAMPLES, entry->d_name);
        snprintf(ext_json + (len - 3), sizeof(ext_json) - len - 3,
                 "%s", ".json");


        /* Validate new paths */
        ret = stat(ext_mp, &st);
        if (ret == -1) {
            printf("Unit test msgpack not found: %s\n", ext_mp);
            exit(EXIT_FAILURE);
        }

        ret = stat(ext_json, &st);
        if (ret == -1) {
            printf("Unit test result JSON not found: %s\n", ext_json);
            exit(EXIT_FAILURE);
        }

        /* Insert into table */
        test = &pt[i];
        test->msgpack = flb_strdup(ext_mp);
        test->json    = flb_strdup(ext_json);
        i++;
    }

    closedir(dir);
    return i;
}

static void utf8_tests_destroy(int s)
{
    int i;
    struct pack_test *test;

    for (i = 0; i < s; i++) {
        test = &pt[i];
        flb_free(test->msgpack);
        flb_free(test->json);
    }
}

void test_utf8_to_json()
{
    int i;
    int ret;
    int n_tests;
    char *file_msgp;
    char *file_json;
    char *out_buf;
    size_t out_size;
    size_t msgp_size;
    size_t json_size;
    struct stat st;
    struct pack_test *test;

    n_tests = utf8_tests_create();

    /* Iterate unit tests table */
    for (i = 0; i < n_tests; i++) {
        test = &pt[i];
        if (!test->msgpack) {
            break;
        }

        file_msgp = mk_file_to_buffer(test->msgpack);
        TEST_CHECK(file_msgp != NULL);
        stat(test->msgpack, &st);
        msgp_size = st.st_size;

        file_json = mk_file_to_buffer(test->json);
        TEST_CHECK(file_json != NULL);
        if (!file_json) {
            printf("Missing JSON file: %s\n", test->json);
            flb_free(file_msgp);
            continue;
        }

        json_size = strlen(file_json);

        out_buf = NULL;
        ret = flb_msgpack_raw_to_json_str(file_msgp, msgp_size,
                                          &out_buf, &out_size);
        TEST_CHECK(ret == 0);

        ret = strcmp(file_json, out_buf);
        if (ret != 0) {
            TEST_CHECK(ret == 0);
            printf("[test] %s\n", test->json);
            printf("       EXPECTED => '%s'\n", file_json);
            printf("       ENCODED  => '%s'\n", out_buf);
        }

        TEST_CHECK(out_size == json_size);

        if (out_buf) {
            flb_free(out_buf);
        }
        flb_free(file_msgp);
        flb_free(file_json);
    }

    utf8_tests_destroy(n_tests);
}

TEST_LIST = {
    /* JSON maps iteration */
    { "json_pack", test_json_pack },
    { "json_pack_iter", test_json_pack_iter},
    { "json_pack_mult", test_json_pack_mult},
    { "json_pack_mult_iter", test_json_pack_mult_iter},

    /* Mixed bytes, check JSON encoding */
    { "utf8_to_json", test_utf8_to_json},
    { 0 }
};
