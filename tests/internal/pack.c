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
#include <fcntl.h>
#include <unistd.h>
#include <math.h> /* for NAN */


#include "flb_tests_internal.h"

/* JSON iteration tests */
#define JSON_SINGLE_MAP1 FLB_TESTS_DATA_PATH "/data/pack/json_single_map_001.json"
#define JSON_SINGLE_MAP2 FLB_TESTS_DATA_PATH "/data/pack/json_single_map_002.json"
#define JSON_DUP_KEYS_I  FLB_TESTS_DATA_PATH "/data/pack/dup_keys_in.json"
#define JSON_DUP_KEYS_O  FLB_TESTS_DATA_PATH "/data/pack/dup_keys_out.json"

#define JSON_BUG342      FLB_TESTS_DATA_PATH "/data/pack/bug342.json"

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
    int root_type;
    size_t len;
    char *data;
    char *out_buf;
    size_t out_size;

    data = mk_file_to_buffer(JSON_SINGLE_MAP1);
    TEST_CHECK(data != NULL);

    len = strlen(data);

    ret = flb_pack_json(data, len, &out_buf, &out_size, &root_type, NULL);
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
    while (msgpack_unpack_next(&result, out_buf, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {
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
            consume_bytes(buf, state.last_byte, total);
            i = 1;
            total -= state.last_byte;
            flb_pack_state_reset(&state);
            flb_pack_state_init(&state);

            /* Validate output buffer */
            off = 0;
            maps = 0;
            msgpack_unpacked_init(&result);
            while (msgpack_unpack_next(&result, out_buf, out_size, &off) == MSGPACK_UNPACK_SUCCESS) {
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

/* Validate default values of macros used in flb_msgpack_raw_to_json_sds */
void test_msgpack_to_json_macros()
{
    /* Verify default values */
    TEST_CHECK(FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE == 2.0);
    TEST_CHECK(FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE == 0.10);
}

/* Validate that duplicated keys are removed */
void test_json_dup_keys()
{
    int ret;
    int type;
    size_t len_in;
    char *out_buf;
    size_t out_size;
    char *data_in;
    char *data_out;
    flb_sds_t out_json;
    flb_sds_t d;

    /* Read JSON input file */
    data_in = mk_file_to_buffer(JSON_DUP_KEYS_I);
    TEST_CHECK(data_in != NULL);
    len_in = strlen(data_in);

    /* Read JSON output file */
    data_out = mk_file_to_buffer(JSON_DUP_KEYS_O);
    TEST_CHECK(data_out != NULL);

    /* Pack raw JSON as msgpack */
    ret = flb_pack_json(data_in, len_in, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);

    d = flb_sds_create("date");
    TEST_CHECK(d != NULL);

    /* Convert back to JSON */
    out_json = flb_pack_msgpack_to_json_format(out_buf, out_size,
                                               FLB_PACK_JSON_FORMAT_LINES,
                                               FLB_PACK_JSON_DATE_EPOCH,
                                               d);
    TEST_CHECK(out_json != NULL);

    TEST_CHECK(strncmp(out_json, data_out, flb_sds_len(out_json)) == 0);
    flb_sds_destroy(d);
    flb_sds_destroy(out_json);
    flb_free(out_buf);
    flb_free(data_in);
    flb_free(data_out);
}

void test_json_pack_bug342()
{
    int i = 0;
    int records = 0;
    int fd;
    int ret;
    size_t off = 0;
    ssize_t r = 0;
    char *out;
    char buf[1024*4];
    int out_size;
    size_t total = 0;
    int bytes[] = {1, 3, 3, 5, 5, 35, 17, 23,
                   46, 37, 49, 51, 68, 70, 86, 268,
                   120, 178, 315, 754, 753, 125};
    struct stat st;
    struct flb_pack_state state;
    msgpack_unpacked result;
    ret = stat(JSON_BUG342, &st);
    if (ret == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < (sizeof(bytes)/sizeof(int)); i++) {
        total += bytes[i];
    }

    TEST_CHECK(total == st.st_size);
    if (total != st.st_size) {
        exit(EXIT_FAILURE);
    }

    fd = open(JSON_BUG342, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    flb_pack_state_init(&state);
    state.multiple = FLB_TRUE;

    for (i = 0; i < (sizeof(bytes)/sizeof(int)); i++) {
        r = read(fd, buf + off, bytes[i]);
        TEST_CHECK(r == bytes[i]);
        if (r <= 0) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        off += r;

        ret = flb_pack_json_state(buf, off, &out, &out_size, &state);
        TEST_CHECK(ret != FLB_ERR_JSON_INVAL);
        if (ret == FLB_ERR_JSON_INVAL) {
            exit(EXIT_FAILURE);
        }
        else if (ret == FLB_ERR_JSON_PART) {
            continue;
        }
        else if (ret == 0) {
            /* remove used bytes */
            consume_bytes(buf, state.last_byte, off);
            off -= state.last_byte;

            /* reset the packer state */
            flb_pack_state_reset(&state);
            flb_pack_state_init(&state);
            state.multiple = FLB_TRUE;
        }

        size_t coff = 0;
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, out, out_size, &coff) == MSGPACK_UNPACK_SUCCESS) {
            records++;
        }
        msgpack_unpacked_destroy(&result);

        TEST_CHECK(off >= state.last_byte);
        if (off < state.last_byte) {
            exit(1);
        }
        flb_free(out);
    }
    flb_pack_state_reset(&state);
    close(fd);
    TEST_CHECK(records == 240);
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
    flb_sds_t out_buf;
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

        out_buf = flb_msgpack_raw_to_json_sds(file_msgp, msgp_size);
        TEST_CHECK(out_buf != NULL);
        out_size = flb_sds_len(out_buf);

        ret = strcmp(file_json, out_buf);
        if (ret != 0) {
            TEST_CHECK(ret == 0);
            printf("[test] %s\n", test->json);
            printf("       EXPECTED => '%s'\n", file_json);
            printf("       ENCODED  => '%s'\n", out_buf);
        }

        TEST_CHECK(out_size == json_size);

        if (out_buf) {
            flb_sds_destroy(out_buf);
        }
        flb_free(file_msgp);
        flb_free(file_json);
    }

    utf8_tests_destroy(n_tests);
}

void test_json_pack_surrogate_pairs()
{
    int i;
    int ret;
    int len;
    int type;
    int items;
    char *p_in;
    char *p_unescaped;
    size_t len_in;
    char *out_buf;
    size_t out_size;
    char *data_in[] = {
        "{\"text\":\"\\ud83e\\udd17\"}",
        "{\"text\":\"thinking...\\ud83e\\uddd0\"}",
        "{\"text\":\"\\ud83e\\udee1\"}",
    };
    char *data_unescaped[] = {
        "🤗",
        "thinking...🧐",
        "🫡",
    };
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object val;
    size_t off = 0;

    items = sizeof(data_in) / sizeof(char *);
    for (i = 0; i < items; i++) {
        p_in = data_in[i];
        len_in = strlen(p_in);
        p_unescaped = data_unescaped[i];

        /* Pack raw JSON as msgpack */
        ret = flb_pack_json(p_in, len_in, &out_buf, &out_size, &type, NULL);
        TEST_CHECK(ret == 0);

        /* Unpack 'text' value and compare it to the original raw */
        off = 0;
        msgpack_unpacked_init(&result);
        ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
        TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

        /* Check parent type is a map */
        root = result.data;
        TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

        /* Get map value */
        val = root.via.map.ptr[0].val;
        TEST_CHECK(val.type == MSGPACK_OBJECT_STR);

        /* Compare bytes length */
        len = strlen(p_unescaped);
        TEST_CHECK(len == val.via.str.size);
        if (len != val.via.str.size) {
            printf("failed comparing string length\n");
        }

        /* Compare raw bytes */
        ret = memcmp(val.via.str.ptr, p_unescaped, len);
        TEST_CHECK(ret == 0);
        if (ret != 0) {
            printf("failed comparing to original value\n");
        }

        msgpack_unpacked_destroy(&result);
        flb_free(out_buf);
    }
}

void test_json_pack_surrogate_pairs_with_replacement()
{
    int i;
    int ret;
    int len;
    int type;
    int items;
    char *p_in;
    char *p_unescaped;
    size_t len_in;
    char *out_buf;
    size_t out_size;
    char *data_in[] = {
        "{\"text\":\"\\fddd,\"}",
        "{\"text\":\"\\udee1,\"}",
        "{\"text\":\"\\ud83e,|,\"}",
    };
    char *data_unescaped[] = {
        "\fddd,",
        "�,",
        "�,|,",
    };
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object val;
    size_t off = 0;

    items = sizeof(data_in) / sizeof(char *);
    for (i = 0; i < items; i++) {
        p_in = data_in[i];
        len_in = strlen(p_in);
        p_unescaped = data_unescaped[i];

        /* Pack raw JSON as msgpack */
        ret = flb_pack_json(p_in, len_in, &out_buf, &out_size, &type, NULL);
        TEST_CHECK(ret == 0);

        /* Unpack 'text' value and compare it to the original raw */
        off = 0;
        msgpack_unpacked_init(&result);
        ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
        TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

        /* Check parent type is a map */
        root = result.data;
        TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

        /* Get map value */
        val = root.via.map.ptr[0].val;
        TEST_CHECK(val.type == MSGPACK_OBJECT_STR);

        /* Compare bytes length */
        len = strlen(p_unescaped);
        TEST_CHECK(len == val.via.str.size);
        if (len != val.via.str.size) {
            printf("failed comparing string length\n");
        }

        /* Compare raw bytes */
        ret = memcmp(val.via.str.ptr, p_unescaped, len);
        TEST_CHECK(ret == 0);
        if (ret != 0) {
            printf("failed comparing to original value\n");
        }

        msgpack_unpacked_destroy(&result);
        flb_free(out_buf);
    }
}

void test_json_pack_bug1278()
{
    int i;
    int len;
    int ret;
    int items;
    int type;
    char *p_in;
    char *p_out;
    char *out_buf;
    size_t out_size;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object val;
    size_t off = 0;
    flb_sds_t json;
    char tmp[32];

    char *in[]  = {
                   "one\atwo",
                   "one\btwo",
                   "one\ttwo",
                   "one\ntwo",
                   "one\vtwo",
                   "one\ftwo",
                   "one\rtwo",
                   "\\n",
    };

    char *out[] = {
                   "\"one\\u0007two\"",
                   "\"one\\btwo\"",
                   "\"one\\ttwo\"",
                   "\"one\\ntwo\"",
                   "\"one\\u000btwo\"",
                   "\"one\\ftwo\"",
                   "\"one\\rtwo\"",
                   "\"\\\\n\"",
    };

    printf("\n");
    items = sizeof(in) / sizeof(char *);
    for (i = 0; i < items; i++) {
        p_in = in[i];
        p_out = out[i];

        len = strlen(p_in);

        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        msgpack_pack_str(&mp_pck, len);
        msgpack_pack_str_body(&mp_pck, p_in, len);

        /* Pack raw string as JSON */
        json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);

        /* Compare expected JSON output */
        ret = strcmp(p_out, json);
        TEST_CHECK(ret == 0);
        if (ret != 0) {
            printf("== JSON comparisson failed ==\n");
            printf("expected: %s\n", p_out);
            printf("output  : %s\n", json);
        }
        else {
            printf("test %i out => %s\n", i, json);
        }
        /* Put JSON string in a map and convert it to msgpack */
        snprintf(tmp, sizeof(tmp) -1 , "{\"log\": %s}", json);
        ret = flb_pack_json(tmp, strlen(tmp), &out_buf, &out_size, &type, NULL);
        TEST_CHECK(ret == 0);
        if (ret != 0) {
            printf("failed packaging to JSON\n");
        }

        /* Unpack 'log' value and compare it to the original raw */
        off = 0;
        msgpack_unpacked_init(&result);
        ret = msgpack_unpack_next(&result, out_buf, out_size, &off);
        TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

        /* Check parent type is a map */
        root = result.data;
        TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

        /* Get map value */
        val = root.via.map.ptr[0].val;
        TEST_CHECK(val.type == MSGPACK_OBJECT_STR);

        /* Compare bytes length */
        len = strlen(p_in);
        TEST_CHECK(len == val.via.str.size);
        if (len != val.via.str.size) {
            printf("failed comparing string length\n");
        }

        /* Compare raw bytes */
        ret = memcmp(val.via.str.ptr, p_in, len);
        TEST_CHECK(ret == 0);
        if (ret != 0) {
            printf("failed comparing to original value\n");
        }

        /* Relese resources */
        flb_free(out_buf);
        flb_sds_destroy(json);
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&mp_sbuf);

    }
}

void test_json_pack_nan()
{
    int ret;
    char json_str[128] = {0};
    char *p = NULL;
    struct flb_config config;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    msgpack_object obj;
    msgpack_zone mempool;

    config.convert_nan_to_null = FLB_TRUE;

    // initialize msgpack
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_double(&mp_pck, NAN);
    msgpack_zone_init(&mempool, 2048);
    msgpack_unpack(mp_sbuf.data, mp_sbuf.size, NULL, &mempool, &obj);
    msgpack_zone_destroy(&mempool);
    msgpack_sbuffer_destroy(&mp_sbuf);

    // convert msgpack to json
    ret = flb_msgpack_to_json(&json_str[0], sizeof(json_str), &obj);
    TEST_CHECK(ret >= 0);

    p = strstr(&json_str[0], "nan");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("json should be nan. json_str=%s", json_str);
    }

    // convert. nan -> null
    memset(&json_str[0], 0, sizeof(json_str));
    flb_pack_init(&config);
    ret = flb_msgpack_to_json(&json_str[0], sizeof(json_str), &obj);
    TEST_CHECK(ret >= 0);

    p = strstr(&json_str[0], "null");
    if (!TEST_CHECK(p != NULL)) {
        TEST_MSG("json should be null. json_str=%s", json_str);
    }

    // clear setting
    config.convert_nan_to_null = FLB_FALSE;
    flb_pack_init(&config);
}

static int check_msgpack_val(msgpack_object obj, int expected_type, char *expected_val)
{
    int len;

    if (!TEST_CHECK(obj.type == expected_type)) {
        TEST_MSG("type mismatch\nexpected=%d got=%d", expected_type, obj.type);
        return -1;
    }
    switch(obj.type) {
    case MSGPACK_OBJECT_MAP:
        if(!TEST_CHECK(obj.via.map.size == atoi(expected_val))) {
            TEST_MSG("map size mismatch\nexpected=%s got=%d", expected_val, obj.via.map.size);
            return -1;
        }
        break;

    case MSGPACK_OBJECT_ARRAY:
        if(!TEST_CHECK(obj.via.array.size == atoi(expected_val))) {
            TEST_MSG("array size mismatch\nexpected=%s got=%d", expected_val, obj.via.array.size);
            return -1;
        }
        break;

    case MSGPACK_OBJECT_STR:
        len = strlen(expected_val);
        if (!TEST_CHECK(obj.via.str.size == strlen(expected_val))) {
            TEST_MSG("str size mismatch\nexpected=%d got=%d", len, obj.via.str.size);
            return -1;
        }
        else if(!TEST_CHECK(strncmp(expected_val, obj.via.str.ptr ,len) == 0)) {
            TEST_MSG("str mismatch\nexpected=%.*s got=%.*s", len, expected_val, len, obj.via.str.ptr);
            return -1;
        }
        break;

    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        if(!TEST_CHECK(obj.via.u64 == (uint64_t)atoi(expected_val))) {
            TEST_MSG("int mismatch\nexpected=%s got=%"PRIu64, expected_val, obj.via.u64);
            return -1;
        }
        break;

    case MSGPACK_OBJECT_BOOLEAN:
        if (obj.via.boolean) {
            if(!TEST_CHECK(strncasecmp(expected_val, "true",4) == 0)) {
                TEST_MSG("bool mismatch\nexpected=%s got=true", expected_val);
                return -1;
            }
        }
        else {
            if(!TEST_CHECK(strncasecmp(expected_val, "false",5) == 0)) {
                TEST_MSG("bool mismatch\nexpected=%s got=false", expected_val);
                return -1;
            }
        }
        break;

    default:
        TEST_MSG("unknown type %d", obj.type);
        return -1;
    }

    return 0;
}

/*
 * https://github.com/fluent/fluent-bit/issues/5336
 * Pack "valid JSON + partial JSON"
 */
#define JSON_BUG5336 "{\"int\":10, \"string\":\"hello\", \"bool\":true, \"array\":[0,1,2]}"
void test_json_pack_bug5336()
{
    int ret;
    char *json_valid = JSON_BUG5336;
    size_t len = strlen(json_valid);

    char *json_incomplete = JSON_BUG5336 JSON_BUG5336;
    char *out = NULL;
    int out_size;
    struct flb_pack_state state;
    int i;

    msgpack_unpacked result;
    msgpack_object obj;
    size_t off = 0;

    int loop_cnt = 0;

    for (i=len; i<len*2; i++) {
        loop_cnt++;

        flb_pack_state_init(&state);

        /* Pass small string size to create incomplete JSON */
        ret = flb_pack_json_state(json_incomplete, i, &out, &out_size, &state);
        if (!TEST_CHECK(ret != FLB_ERR_JSON_INVAL)) {
            TEST_MSG("%ld: FLB_ERR_JSON_INVAL\njson=%.*s", i-len, i, json_incomplete);
            exit(EXIT_FAILURE);
        }
        else if(!TEST_CHECK(ret != FLB_ERR_JSON_PART)) {
            TEST_MSG("%ld: FLB_ERR_JSON_PART\njson=%.*s", i-len, i, json_incomplete);
            exit(EXIT_FAILURE);
        }

        /* unpack parsed data */
        msgpack_unpacked_init(&result);
        off = 0;
        TEST_CHECK(msgpack_unpack_next(&result, out, out_size, &off) == MSGPACK_UNPACK_SUCCESS);

        TEST_CHECK(check_msgpack_val(result.data, MSGPACK_OBJECT_MAP, "4" /*map size*/) == 0);

        /* "int":10 */
        obj = result.data.via.map.ptr[0].key;
        TEST_CHECK(check_msgpack_val(obj, MSGPACK_OBJECT_STR, "int") == 0);
        obj = result.data.via.map.ptr[0].val;
        TEST_CHECK(check_msgpack_val(obj, MSGPACK_OBJECT_POSITIVE_INTEGER, "10") == 0);

        /* "string":"hello"*/
        obj = result.data.via.map.ptr[1].key;
        TEST_CHECK(check_msgpack_val(obj, MSGPACK_OBJECT_STR, "string") == 0);
        obj = result.data.via.map.ptr[1].val;
        TEST_CHECK(check_msgpack_val(obj, MSGPACK_OBJECT_STR, "hello") == 0);

        /* "bool":true */
        obj = result.data.via.map.ptr[2].key;
        TEST_CHECK(check_msgpack_val(obj, MSGPACK_OBJECT_STR, "bool") == 0);
        obj = result.data.via.map.ptr[2].val;
        TEST_CHECK(check_msgpack_val(obj, MSGPACK_OBJECT_BOOLEAN, "true") == 0);

        /* "array":[0,1,2] */
        obj = result.data.via.map.ptr[3].key;
        TEST_CHECK(check_msgpack_val(obj, MSGPACK_OBJECT_STR, "array") == 0);
        obj = result.data.via.map.ptr[3].val;
        TEST_CHECK(check_msgpack_val(obj, MSGPACK_OBJECT_ARRAY, "3" /*array size*/) == 0);
        TEST_CHECK(check_msgpack_val(obj.via.array.ptr[0], MSGPACK_OBJECT_POSITIVE_INTEGER, "0") == 0);
        TEST_CHECK(check_msgpack_val(obj.via.array.ptr[1], MSGPACK_OBJECT_POSITIVE_INTEGER, "1") == 0);
        TEST_CHECK(check_msgpack_val(obj.via.array.ptr[2], MSGPACK_OBJECT_POSITIVE_INTEGER, "2") == 0);

        msgpack_unpacked_destroy(&result);
        flb_free(out);
        flb_pack_state_reset(&state);
    }

    if(!TEST_CHECK(loop_cnt == len)) {
        TEST_MSG("loop_cnt expect=%ld got=%d", len, loop_cnt);
    }
}

const char input_msgpack[] = {0x92,/* array 2 */
                            0xd7, 0x00, /* event time*/
                            0x07, 0x5b, 0xcd, 0x15, /* second = 123456789 = 1973/11/29 21:33:09 */
                            0x07, 0x5b, 0xcd, 0x15, /* nanosecond = 123456789 */
                            0x81, 0xa2, 0x61, 0x61, 0xa2, 0x62, 0x62 /* {"aa":"bb"} */
};

void test_json_date(char* expect, int date_format)
{
    flb_sds_t json_key;
    flb_sds_t ret;

    json_key = flb_sds_create("date");
    if (!TEST_CHECK(json_key != NULL)) {
        TEST_MSG("flb_sds_create failed");
        exit(1);
    }

    ret = flb_pack_msgpack_to_json_format((const char*)&input_msgpack[0], sizeof(input_msgpack),
                                          FLB_PACK_JSON_FORMAT_JSON, date_format,
                                          json_key);
    if (!TEST_CHECK(ret != NULL)) {
        TEST_MSG("flb_pack_msgpack_to_json_format failed");
        flb_sds_destroy(json_key);
        exit(1);
    }
    flb_sds_destroy(json_key);

    if (!TEST_CHECK(strstr(ret, expect) != NULL)) {
        TEST_MSG("mismatch. Got=%s expect=%s", ret, expect);
    }

    flb_sds_destroy(ret);
}

void test_json_date_iso8601()
{
    test_json_date("1973-11-29T21:33:09.123456Z", FLB_PACK_JSON_DATE_ISO8601);
}

void test_json_date_double()
{
    test_json_date("123456789.123456", FLB_PACK_JSON_DATE_DOUBLE);
}

void test_json_date_java_sql()
{
    test_json_date("1973-11-29 21:33:09.123456", FLB_PACK_JSON_DATE_JAVA_SQL_TIMESTAMP);
}

void test_json_date_epoch()
{
    test_json_date("123456789", FLB_PACK_JSON_DATE_EPOCH);
}

void test_json_date_epoch_ms()
{
    test_json_date("123456789123", FLB_PACK_JSON_DATE_EPOCH_MS);
}

void test_json_invalid()
{
    const char *malformed_json = "{\"key1\": \"value1\", \"key2\": "; // incomplete JSON
    char *buffer = NULL;
    size_t size = 0;
    int root_type = 0;
    int ret;

    ret = flb_pack_json(malformed_json, strlen(malformed_json), &buffer, &size, &root_type, NULL);

    /* we expect this to fail and buffer == NULL */
    TEST_CHECK(ret != 0);
    TEST_CHECK(buffer == NULL);
}

TEST_LIST = {
    /* JSON maps iteration */
    { "json_pack"          , test_json_pack },
    { "json_pack_iter"     , test_json_pack_iter},
    { "json_pack_mult"     , test_json_pack_mult},
    { "json_pack_mult_iter", test_json_pack_mult_iter},
    { "json_macros"        , test_msgpack_to_json_macros},
    { "json_dup_keys"      , test_json_dup_keys},
    { "json_pack_bug342"   , test_json_pack_bug342},
    { "json_pack_bug1278"  , test_json_pack_bug1278},
    { "json_pack_nan"      , test_json_pack_nan},
    { "json_pack_bug5336"  , test_json_pack_bug5336},
    { "json_date_iso8601" , test_json_date_iso8601},
    { "json_date_double" , test_json_date_double},
    { "json_date_java_sql" , test_json_date_java_sql},
    { "json_date_epoch" , test_json_date_epoch},
    { "json_date_epoch_ms" , test_json_date_epoch_ms},
    { "json_invalid",        test_json_invalid},

    /* Mixed bytes, check JSON encoding */
    { "utf8_to_json", test_utf8_to_json},
    { "json_pack_surrogate_pairs", test_json_pack_surrogate_pairs},
    { "json_pack_surrogate_pairs_with_replacement",
      test_json_pack_surrogate_pairs_with_replacement},
    { 0 }
};
