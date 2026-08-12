/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <msgpack.h>
#include <float.h>
#include <math.h>
#include "flb_tests_internal.h"

static int msgpack_strncmp(char *str, size_t str_len, msgpack_object obj)
{
    int ret = -1;

    if (str == NULL) {
        return -1;
    }

    switch (obj.type) {
    case MSGPACK_OBJECT_STR:
        if (obj.via.str.size != str_len) {
            return -1;
        }
        ret = strncmp(str, obj.via.str.ptr, str_len);
        break;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        {
            unsigned long val = strtoul(str, NULL, 10);
            if (val == (unsigned long) obj.via.u64) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        {
            long long val = strtoll(str, NULL, 10);
            if (val == obj.via.i64) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        {
            double val = strtod(str, NULL);
            if (fabs(val - obj.via.f64) < DBL_EPSILON) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_BOOLEAN:
        if (obj.via.boolean) {
            ret = (str_len == 4) ? strncasecmp(str, "true", 4) : -1;
        }
        else {
            ret = (str_len == 5) ? strncasecmp(str, "false", 5) : -1;
        }
        break;
    default:
        break;
    }

    return ret;
}

struct str_list {
    size_t size;
    char **lists;
};

/* Compares a single-record msgpack map against a flat key,value,... list */
static int compare_msgpack(void *msgpack_data, size_t msgpack_size, struct str_list *l)
{
    msgpack_unpacked result;
    msgpack_object obj;
    size_t off = 0;
    int map_size;
    int i_map;
    int i_list;
    int num = 0;

    if (!TEST_CHECK(msgpack_data != NULL)) {
        TEST_MSG("msgpack_data is NULL");
        return -1;
    }
    if (!TEST_CHECK(msgpack_size > 0)) {
        TEST_MSG("msgpack_size is 0");
        return -1;
    }

    msgpack_unpacked_init(&result);
    if (!TEST_CHECK(msgpack_unpack_next(&result, msgpack_data, msgpack_size, &off)
                     == MSGPACK_UNPACK_SUCCESS)) {
        TEST_MSG("msgpack_unpack_next failed");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    obj = result.data;
    if (!TEST_CHECK(obj.type == MSGPACK_OBJECT_MAP)) {
        TEST_MSG("not a map. type = %d", obj.type);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    map_size = obj.via.map.size;
    if (!TEST_CHECK((size_t) map_size == l->size / 2)) {
        TEST_MSG("map size mismatch. got=%d expect=%zu", map_size, l->size / 2);
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    for (i_map = 0; i_map < map_size; i_map++) {
        for (i_list = 0; i_list < (int) (l->size / 2); i_list++) {
            if (msgpack_strncmp(l->lists[i_list * 2], strlen(l->lists[i_list * 2]),
                                obj.via.map.ptr[i_map].key) == 0 &&
                msgpack_strncmp(l->lists[i_list * 2 + 1], strlen(l->lists[i_list * 2 + 1]),
                                obj.via.map.ptr[i_map].val) == 0) {
                num++;
            }
        }
    }

    msgpack_unpacked_destroy(&result);
    if (!TEST_CHECK(num == (int) (l->size / 2))) {
        TEST_MSG("compare failed. matched_num=%d expect=%zu", num, l->size / 2);
        return -1;
    }
    return 0;
}

void test_basic()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret;
    char *input = "a,b,c";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = { "0", "a", "1", "b", "2", "c" };
    struct str_list expected = { sizeof(expected_strs) / sizeof(char *), expected_strs };

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    parser = flb_parser_create("csv", "csv", NULL, FLB_FALSE, NULL, NULL, NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    TEST_CHECK(parser != NULL);

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
    }
    else {
        compare_msgpack(out_buf, out_size, &expected);
        flb_free(out_buf);
    }

    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_trailing_empty_field()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret;
    char *input = "a,b,";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = { "0", "a", "1", "b", "2", "" };
    struct str_list expected = { sizeof(expected_strs) / sizeof(char *), expected_strs };

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    parser = flb_parser_create("csv", "csv", NULL, FLB_FALSE, NULL, NULL, NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    TEST_CHECK(parser != NULL);

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
    }
    else {
        compare_msgpack(out_buf, out_size, &expected);
        flb_free(out_buf);
    }

    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_quoted_fields()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret;
    char *input = "a,\"b,c\",\"d\"\"e\"";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = { "0", "a", "1", "b,c", "2", "d\"e" };
    struct str_list expected = { sizeof(expected_strs) / sizeof(char *), expected_strs };

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    parser = flb_parser_create("csv", "csv", NULL, FLB_FALSE, NULL, NULL, NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    TEST_CHECK(parser != NULL);

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
    }
    else {
        compare_msgpack(out_buf, out_size, &expected);
        flb_free(out_buf);
    }

    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_named_fields()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret;
    char *input = "1,2,3";
    char *field_names[] = { "x", "y", "z" };
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = { "x", "1", "y", "2", "z", "3" };
    struct str_list expected = { sizeof(expected_strs) / sizeof(char *), expected_strs };

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    parser = flb_parser_create("csv", "csv", NULL, FLB_FALSE, NULL, NULL, NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    TEST_CHECK(parser != NULL);

    ret = flb_parser_csv_set_fields(parser, field_names, 3);
    TEST_CHECK(ret == 0);

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
    }
    else {
        compare_msgpack(out_buf, out_size, &expected);
        flb_free(out_buf);
    }

    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_time_key_by_index()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret;
    char *input = "2022-10-31T12:00:01.123,text";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = { "1", "text" };
    struct str_list expected = { sizeof(expected_strs) / sizeof(char *), expected_strs };

    out_time.tm.tv_sec = 0;
    out_time.tm.tv_nsec = 0;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    parser = flb_parser_create("csv", "csv", NULL, FLB_FALSE,
                               "%Y-%m-%dT%H:%M:%S.%L", "0", NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    TEST_CHECK(parser != NULL);

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
    }
    else {
        compare_msgpack(out_buf, out_size, &expected);
        flb_free(out_buf);
    }

    if (!TEST_CHECK(out_time.tm.tv_sec == 1667217601 && out_time.tm.tv_nsec == 123000000)) {
        TEST_MSG("timestamp error. sec  Got=%ld Expect=1667217601", out_time.tm.tv_sec);
        TEST_MSG("timestamp error. nsec Got=%ld Expect=123000000", out_time.tm.tv_nsec);
    }

    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_time_key_by_name()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret;
    char *input = "text,2022-10-31T12:00:01.123";
    char *field_names[] = { "msg", "time" };
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = { "msg", "text" };
    struct str_list expected = { sizeof(expected_strs) / sizeof(char *), expected_strs };

    out_time.tm.tv_sec = 0;
    out_time.tm.tv_nsec = 0;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    parser = flb_parser_create("csv", "csv", NULL, FLB_FALSE,
                               "%Y-%m-%dT%H:%M:%S.%L", "time", NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    TEST_CHECK(parser != NULL);

    ret = flb_parser_csv_set_fields(parser, field_names, 2);
    TEST_CHECK(ret == 0);

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
    }
    else {
        compare_msgpack(out_buf, out_size, &expected);
        flb_free(out_buf);
    }

    if (!TEST_CHECK(out_time.tm.tv_sec == 1667217601 && out_time.tm.tv_nsec == 123000000)) {
        TEST_MSG("timestamp error. sec  Got=%ld Expect=1667217601", out_time.tm.tv_sec);
        TEST_MSG("timestamp error. nsec Got=%ld Expect=123000000", out_time.tm.tv_nsec);
    }

    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_time_keep()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret;
    char *input = "text,2022-10-31T12:00:01.123";
    char *field_names[] = { "msg", "time" };
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = { "msg", "text", "time", "2022-10-31T12:00:01.123" };
    struct str_list expected = { sizeof(expected_strs) / sizeof(char *), expected_strs };

    out_time.tm.tv_sec = 0;
    out_time.tm.tv_nsec = 0;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    parser = flb_parser_create("csv", "csv", NULL, FLB_FALSE,
                               "%Y-%m-%dT%H:%M:%S.%L", "time", NULL,
                               FLB_TRUE /* time_keep */, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    TEST_CHECK(parser != NULL);

    ret = flb_parser_csv_set_fields(parser, field_names, 2);
    TEST_CHECK(ret == 0);

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
    }
    else {
        compare_msgpack(out_buf, out_size, &expected);
        flb_free(out_buf);
    }

    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_types()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret;
    char *input = "text,100";
    char *field_names[] = { "msg", "count" };
    struct flb_parser_types *types = NULL;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = { "msg", "text", "count", "100" };
    struct str_list expected = { sizeof(expected_strs) / sizeof(char *), expected_strs };

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    /* Note: types will be released by flb_parser_destroy */
    types = flb_malloc(sizeof(struct flb_parser_types));
    TEST_CHECK(types != NULL);
    types->key = flb_malloc(strlen("count") + 1);
    TEST_CHECK(types->key != NULL);
    strcpy(types->key, "count");
    types->key_len = 5;
    types->type = FLB_PARSER_TYPE_INT;

    parser = flb_parser_create("csv", "csv", NULL, FLB_FALSE, NULL, NULL, NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               types, 1, NULL, config);
    TEST_CHECK(parser != NULL);

    ret = flb_parser_csv_set_fields(parser, field_names, 2);
    TEST_CHECK(ret == 0);

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
    }
    else {
        /* 'count' comes back as an integer, not a string: just check the
         * map size and the string field to make sure it went through */
        compare_msgpack(out_buf, out_size, &expected);
        flb_free(out_buf);
    }

    flb_parser_destroy(parser);
    flb_config_exit(config);
}

TEST_LIST = {
    { "basic", test_basic},
    { "trailing_empty_field", test_trailing_empty_field},
    { "quoted_fields", test_quoted_fields},
    { "named_fields", test_named_fields},
    { "time_key_by_index", test_time_key_by_index},
    { "time_key_by_name", test_time_key_by_name},
    { "time_keep", test_time_keep},
    { "types", test_types},
    { 0 }
};
