/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <msgpack.h>
#include <float.h>
#include <math.h>
#include "flb_tests_internal.h"

static int msgpack_strncmp(char* str, size_t str_len, msgpack_object obj)
{
    int ret = -1;

    if (str == NULL) {
        flb_error("str is NULL");
        return -1;
    }

    switch (obj.type)  {
    case MSGPACK_OBJECT_STR:
        if (obj.via.str.size != str_len) {
            return -1;
        }
        ret = strncmp(str, obj.via.str.ptr, str_len);
        break;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        {
            unsigned long val = strtoul(str, NULL, 10);
            if (val == (unsigned long)obj.via.u64) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        {
            long long val = strtoll(str, NULL, 10);
            if (val == (unsigned long)obj.via.i64) {
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
            if (str_len != 4 /*true*/) {
                return -1;
            }
            ret = strncasecmp(str, "true", 4);
        }
        else {
            if (str_len != 5 /*false*/) {
                return -1;
            }
            ret = strncasecmp(str, "false", 5);
        }
        break;
    default:
        flb_error("not supported");
    }

    return ret;
}

struct str_list {
    size_t size;
    char **lists;
};

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
    else if (!TEST_CHECK(msgpack_size > 0)) {
        TEST_MSG("msgpack_size is 0");
        return -1;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, msgpack_data, msgpack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        obj = result.data;
        /*
        msgpack_object_print(stdout, obj);
        */
        if (!TEST_CHECK(obj.type == MSGPACK_OBJECT_MAP)) {
            TEST_MSG("map error. type = %d", obj.type);
            continue;
        }
        map_size = obj.via.map.size;
        for (i_map=0; i_map<map_size; i_map++) {
            if (!TEST_CHECK(obj.via.map.ptr[i_map].key.type == MSGPACK_OBJECT_STR)) {
                TEST_MSG("key is not string. type =%d", obj.via.map.ptr[i_map].key.type);
                continue;
            }
            for (i_list=0; i_list< l->size/2; i_list++)  {
                if (msgpack_strncmp(l->lists[i_list*2], strlen(l->lists[i_list*2]),
                                    obj.via.map.ptr[i_map].key) == 0 &&
                    msgpack_strncmp(l->lists[i_list*2+1], strlen(l->lists[i_list*2+1]),
                                    obj.via.map.ptr[i_map].val) == 0) {
                    num++;
                }
            }
        }
    }
    msgpack_unpacked_destroy(&result);
    if (!TEST_CHECK(num == l->size/2)) {
        msgpack_object_print(stdout, obj);
        putchar('\n');
        TEST_MSG("compare failed. matched_num=%d expect=%lu", num, l->size/2);
        return -1;
    }
    return 0;
}

void test_basic()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret = 0;
    char *input = "{\"str\":\"text\", \"int\":100, \"double\":1.23, \"bool\":true}";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = {"str", "text", "int", "100", "double","1.23", "bool", "true"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    config = flb_config_init();
    if(!TEST_CHECK(config != NULL)) {
        TEST_MSG("flb_config_init failed");
        exit(1);
    }

    parser = flb_parser_create("json", "json", NULL, FLB_FALSE, NULL, NULL, NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    if (!TEST_CHECK(parser != NULL)) {
        TEST_MSG("flb_parser_create failed");
        flb_config_exit(config);
        exit(1);
    }

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    ret = compare_msgpack(out_buf, out_size, &expected);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
    }

    flb_free(out_buf);
    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_time_key()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret = 0;
    char *input = "{\"str\":\"text\", \"int\":100, \"double\":1.23, \"bool\":true, \"time\":\"2022-10-31T12:00:01.123\"}";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = {"str", "text", "int", "100", "double","1.23", "bool", "true"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    out_time.tm.tv_sec = 0;
    out_time.tm.tv_nsec = 0;


    config = flb_config_init();
    if(!TEST_CHECK(config != NULL)) {
        TEST_MSG("flb_config_init failed");
        exit(1);
    }

    parser = flb_parser_create("json", "json", NULL, FLB_FALSE, "%Y-%m-%dT%H:%M:%S.%L", "time", NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    if (!TEST_CHECK(parser != NULL)) {
        TEST_MSG("flb_parser_create failed");
        flb_config_exit(config);
        exit(1);
    }

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    ret = compare_msgpack(out_buf, out_size, &expected);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
        flb_free(out_buf);
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    if (!TEST_CHECK(out_time.tm.tv_sec == 1667217601 && out_time.tm.tv_nsec == 123000000)) {
        TEST_MSG("timestamp error. sec  Got=%ld Expect=1667217601", out_time.tm.tv_sec);
        TEST_MSG("timestamp error. nsec Got=%ld Expect=123000000", out_time.tm.tv_nsec);
    }

    flb_free(out_buf);
    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_time_keep()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret = 0;
    char *input = "{\"str\":\"text\", \"int\":100, \"double\":1.23, \"bool\":true, \"time\":\"2022-10-31T12:00:01.123\"}";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = {"str", "text", "int", "100", "double","1.23", "bool", "true", "time", "2022-10-31T12:00:01.123"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    out_time.tm.tv_sec = 0;
    out_time.tm.tv_nsec = 0;


    config = flb_config_init();
    if(!TEST_CHECK(config != NULL)) {
        TEST_MSG("flb_config_init failed");
        exit(1);
    }

    parser = flb_parser_create("json", "json", NULL, FLB_FALSE, "%Y-%m-%dT%H:%M:%S.%L", "time", NULL,
                               FLB_TRUE /*time_keep */, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    if (!TEST_CHECK(parser != NULL)) {
        TEST_MSG("flb_parser_create failed");
        flb_config_exit(config);
        exit(1);
    }

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    ret = compare_msgpack(out_buf, out_size, &expected);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
        flb_free(out_buf);
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    if (!TEST_CHECK(out_time.tm.tv_sec == 1667217601 && out_time.tm.tv_nsec == 123000000)) {
        TEST_MSG("timestamp error. sec  Got=%ld Expect=1667217601", out_time.tm.tv_sec);
        TEST_MSG("timestamp error. nsec Got=%ld Expect=123000000", out_time.tm.tv_nsec);
    }

    flb_free(out_buf);
    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_time_numeric()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret = 0;
    char *input = "{\"str\":\"text\", \"int\":100, \"double\":1.23, \"bool\":true, \"time\":422500}";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = {"str", "text", "int", "100", "double","1.23", "bool", "true"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    out_time.tm.tv_sec = 0;
    out_time.tm.tv_nsec = 0;


    config = flb_config_init();
    if(!TEST_CHECK(config != NULL)) {
        TEST_MSG("flb_config_init failed");
        exit(1);
    }

    parser = flb_parser_create("json", "json", NULL, FLB_FALSE, "MILLISECONDS", "time", NULL,
                               FLB_FALSE /*time_keep */, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    if (!TEST_CHECK(parser != NULL)) {
        TEST_MSG("flb_parser_create failed");
        flb_config_exit(config);
        exit(1);
    }

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    ret = compare_msgpack(out_buf, out_size, &expected);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
        flb_free(out_buf);
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    if (!TEST_CHECK(out_time.tm.tv_sec == 422 && out_time.tm.tv_nsec == 500000000)) {
        TEST_MSG("timestamp error. sec  Got=%ld Expect=422", out_time.tm.tv_sec);
        TEST_MSG("timestamp error. nsec Got=%ld Expect=500000000", out_time.tm.tv_nsec);
    }

    flb_free(out_buf);
    flb_parser_destroy(parser);
    flb_config_exit(config);
}

/*
 * JSON parser doesn't support 'types' option.
 * This test is to check that 'types' doesn't affect output.
 */
void test_types_is_not_supported()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret = 0;
    char *input = "{\"str\":\"text\", \"int\":100, \"double\":1.23, \"bool\":true}";
    struct flb_parser_types *types = NULL;

    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = {"str", "text", "int", "100", "double","1.23", "bool", "true"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    config = flb_config_init();
    if(!TEST_CHECK(config != NULL)) {
        TEST_MSG("flb_config_init failed");
        exit(1);
    }

    /* Note: types will be released by flb_parser_destroy */
    types = flb_malloc(sizeof(struct flb_parser_types));
    if (!TEST_CHECK(types != NULL)) {
        TEST_MSG("flb_malloc failed");
        flb_config_exit(config);
        exit(1);
    }
    types->key = flb_malloc(strlen("int")+1);
    if (!TEST_CHECK(types->key != NULL)) {
        TEST_MSG("flb_malloc failed");
        flb_free(types);
        flb_config_exit(config);
        exit(1);
    }
    strcpy(types->key, "int");
    types->key_len = 3;
    types->type = FLB_PARSER_TYPE_HEX;

    parser = flb_parser_create("json", "json", NULL, FLB_FALSE, NULL, NULL, NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               types, 1, NULL, config);
    if (!TEST_CHECK(parser != NULL)) {
        TEST_MSG("flb_parser_create failed");
        flb_free(types->key);
        flb_free(types);
        flb_config_exit(config);
        exit(1);
    }

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    ret = compare_msgpack(out_buf, out_size, &expected);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
    }

    flb_free(out_buf);
    flb_parser_destroy(parser);
    flb_config_exit(config);
}

void test_decode_field_json()
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    struct cfl_variant *var = NULL;
    int ret = 0;
    char *input = "{\"json_str\":\"{\\\"str\\\":\\\"text\\\", \\\"int\\\":100, \\\"double\\\":1.23, \\\"bool\\\":true}\"}";
    struct flb_cf *cf = NULL;
    struct flb_cf_section *section = NULL;
    struct mk_list *decoder = NULL;

    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = {"str", "text", "int", "100", "double","1.23", "bool", "true"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    config = flb_config_init();
    if(!TEST_CHECK(config != NULL)) {
        TEST_MSG("flb_config_init failed");
        exit(1);
    }
    cf = flb_cf_create();
    if (!TEST_CHECK(cf != NULL)) {
        TEST_MSG("flb_cf_create failed");
        flb_config_exit(config);
        exit(1);
    }

    section = flb_cf_section_create(cf, "TEST", 4);
    if (!TEST_CHECK(section != NULL)) {
        TEST_MSG("flb_cf_section_create failed");
        flb_cf_destroy(cf);
        flb_config_exit(config);
        exit(1);
    }

	var = flb_cf_section_property_add(cf, section->properties, "decode_field", 12, "json json_str", 13);
	if(!TEST_CHECK(var != NULL)) {
        TEST_MSG("flb_cf_section_property_add failed");
        flb_cf_destroy(cf);
        flb_config_exit(config);
        exit(1);
    }

    decoder = flb_parser_decoder_list_create(section);
    if (!TEST_CHECK(decoder != NULL)) {
        TEST_MSG("flb_parser_decoder_list_create failed");
        flb_cf_destroy(cf);
        flb_config_exit(config);
        exit(1);
    }

    parser = flb_parser_create("json", "json", NULL, FLB_FALSE, NULL, NULL, NULL,
                               FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, decoder, config);
    if (!TEST_CHECK(parser != NULL)) {
        TEST_MSG("flb_parser_create failed");
        flb_cf_destroy(cf);
        flb_config_exit(config);
        exit(1);
    }

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
        flb_parser_destroy(parser);
        flb_cf_destroy(cf);
        flb_config_exit(config);
        exit(1);
    }

    ret = compare_msgpack(out_buf, out_size, &expected);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
    }

    flb_free(out_buf);
    flb_parser_destroy(parser);
    flb_cf_destroy(cf);
    flb_config_exit(config);
}

void test_time_key_kept_if_parse_fails() 
{
    struct flb_parser *parser = NULL;
    struct flb_config *config = NULL;
    int ret = 0;
    char *input = "{\"str\":\"text\", \"time\":\"nonsense\"}";
    char *time_format = "%Y-%m-%dT%H:%M:%S.%L";
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    char *expected_strs[] = {"str", "text", "time", "nonsense"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    out_time.tm.tv_sec = 0;
    out_time.tm.tv_nsec = 0;

    config = flb_config_init();
    if(!TEST_CHECK(config != NULL)) {
        TEST_MSG("flb_config_init failed");
        exit(1);
    }

    parser = flb_parser_create("json", "json", NULL, FLB_FALSE, time_format, "time", NULL,
                               FLB_FALSE, FLB_TRUE, FLB_FALSE, FLB_FALSE,
                               NULL, 0, NULL, config);
    if (!TEST_CHECK(parser != NULL)) {
        TEST_MSG("flb_parser_create failed");
        flb_config_exit(config);
        exit(1);
    }

    ret = flb_parser_do(parser, input, strlen(input), &out_buf, &out_size, &out_time);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_parser_do failed");
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    ret = compare_msgpack(out_buf, out_size, &expected);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare failed");
        flb_free(out_buf);
        flb_parser_destroy(parser);
        flb_config_exit(config);
        exit(1);
    }

    flb_free(out_buf);
    flb_parser_destroy(parser);
    flb_config_exit(config);
}


TEST_LIST = {
    { "basic", test_basic},
    { "time_key", test_time_key},
    { "time_keep", test_time_keep},
    { "time_numeric", test_time_numeric},
    { "types_is_not_supported", test_types_is_not_supported},
    { "decode_field_json", test_decode_field_json},
    { "time_key_kept_if_parse_fails", test_time_key_kept_if_parse_fails},
    { 0 }
};
