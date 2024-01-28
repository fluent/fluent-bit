/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_msgpack.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>
#include <string.h>

#include "flb_tests_internal.h"


struct str_test {
    char *str1;
    char *str2;
    int  expect;
};

#define END_OF_TESTCASE 1000

struct str_test str_testcases[] = {
    {"input", "input", 0},
    {"input1", "input1", 0},
    {"aaa", "bbb", -1},
    {"", "bbb", -1},
    {"aaa", "", -1},
    {"aaa", NULL, -1},
    {NULL, NULL, END_OF_TESTCASE},
};

void test_msgpack_strcmp_str_len()
{
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    msgpack_unpacked result;
    size_t offset = 0;

    int ret;
    int i_testcase;

    char *str1;
    char *str2;
    size_t str2_len;

    for (i_testcase=0; str_testcases[i_testcase].expect != END_OF_TESTCASE; i_testcase++) {
        str1 = str_testcases[i_testcase].str1;
        str2 = str_testcases[i_testcase].str2;
        offset = 0;
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
        msgpack_pack_str_with_body(&pck, str1, strlen(str1));

        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, sbuf.data, sbuf.size, &offset);

        if (str2) {
            str2_len = strlen(str2);
        }
        else {
            str2_len = 0;
        }

        ret = flb_msgpack_strcmp_str_len(&result.data, str2, str2_len);
        if (!TEST_CHECK(ret == str_testcases[i_testcase].expect)) {
            TEST_MSG("%d: ret=%d expect=%d\nstr1=%s\nstr2=%s", i_testcase,
                     ret, str_testcases[i_testcase].expect, str1, str2);
        }
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
    }

    /* NULL inputs */
    ret = flb_msgpack_strcmp_str_len(NULL, "aaa", 3);
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("NULL input should be error");
    }
}

void test_msgpack_strcmp_str()
{
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    msgpack_unpacked result;
    size_t offset = 0;

    int ret;
    int i_testcase;

    char *str1;
    char *str2;

    for (i_testcase=0; str_testcases[i_testcase].expect != END_OF_TESTCASE; i_testcase++) {
        str1 = str_testcases[i_testcase].str1;
        str2 = str_testcases[i_testcase].str2;
        offset = 0;
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
        msgpack_pack_str_with_body(&pck, str1, strlen(str1));

        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, sbuf.data, sbuf.size, &offset);

        ret = flb_msgpack_strcmp_str(&result.data, str2);
        if (!TEST_CHECK(ret == str_testcases[i_testcase].expect)) {
            TEST_MSG("%d: ret=%d expect=%d\nstr1=%s\nstr2=%s", i_testcase,
                     ret, str_testcases[i_testcase].expect, str1, str2);
        }
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
    }

    /* NULL inputs */
    ret = flb_msgpack_strcmp_str(NULL, "aaa");
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("NULL input should be error");
    }
}

void test_msgpack_strcmp_sds()
{
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    msgpack_unpacked result;
    size_t offset = 0;

    int ret;
    int i_testcase;

    char *str1;
    char *str2;
    flb_sds_t sds_str;

    for (i_testcase=0; str_testcases[i_testcase].expect != END_OF_TESTCASE; i_testcase++) {
        str1 = str_testcases[i_testcase].str1;
        str2 = str_testcases[i_testcase].str2;
        sds_str = flb_sds_create(str2);

        offset = 0;
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
        msgpack_pack_str_with_body(&pck, str1, strlen(str1));

        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, sbuf.data, sbuf.size, &offset);

        ret = flb_msgpack_strcmp_sds(&result.data, sds_str);
        if (!TEST_CHECK(ret == str_testcases[i_testcase].expect)) {
            TEST_MSG("%d: ret=%d expect=%d\nstr1=%s\nstr2=%s", i_testcase,
                     ret, str_testcases[i_testcase].expect, str1, sds_str);
        }
        flb_sds_destroy(sds_str);
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
    }

    sds_str = flb_sds_create("aaa");
    ret = flb_msgpack_strcmp_sds(NULL, sds_str);
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("NULL input should be error");
    }
    flb_sds_destroy(sds_str);
}

void test_msgpack_strcmp_msgpack_str()
{
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    msgpack_unpacked result;
    size_t offset = 0;

    msgpack_sbuffer sbuf_2;
    msgpack_packer pck_2;
    msgpack_unpacked result_2;
    size_t offset_2 = 0;

    int ret;
    int i_testcase;

    char *str1;
    char *str2;
    size_t str2_len;

    for (i_testcase=0; str_testcases[i_testcase].expect != END_OF_TESTCASE; i_testcase++) {
        str1 = str_testcases[i_testcase].str1;
        str2 = str_testcases[i_testcase].str2;

        if (str2) {
            str2_len = strlen(str2);
        }
        else {
            str2_len = 0;
        }

        offset = 0;
        offset_2 = 0;
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
        msgpack_pack_str_with_body(&pck, str1, strlen(str1));

        msgpack_unpacked_init(&result);
        msgpack_unpack_next(&result, sbuf.data, sbuf.size, &offset);

        msgpack_sbuffer_init(&sbuf_2);
        msgpack_packer_init(&pck_2, &sbuf_2, msgpack_sbuffer_write);
        msgpack_pack_str_with_body(&pck_2, str2, str2_len);

        msgpack_unpacked_init(&result_2);
        msgpack_unpack_next(&result_2, sbuf_2.data, sbuf_2.size, &offset_2);

        ret = flb_msgpack_strcmp_msgpack_str(&result.data, &result_2.data);
        if (!TEST_CHECK(ret == str_testcases[i_testcase].expect)) {
            TEST_MSG("%d: ret=%d expect=%d\nstr1=%s\nstr2=%s", i_testcase,
                     ret, str_testcases[i_testcase].expect, str1, str2);
        }
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&sbuf);
        msgpack_unpacked_destroy(&result_2);
        msgpack_sbuffer_destroy(&sbuf_2);
    }
}

void test_msgpack_get_value_from_map()
{
    int ret;
    int root_type;
    char *out_buf;
    size_t out_size;
    char *json = "{\"key\":\"value\", \"int\":1, \"map\":{\"aa\":\"bb\"}}";
    msgpack_object *obj = NULL;
    msgpack_unpacked result;
    size_t offset = 0;

    ret = flb_pack_json(json, strlen(json), &out_buf, &out_size, &root_type, NULL);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_pack_json failed. input=%s", json);
    }

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &offset);

    obj = flb_msgpack_get_value_from_map(&result.data, "key", 3);
    if (!TEST_CHECK(obj != NULL)) {
        TEST_MSG("a value of \"key\" not found\ninput=%s", json);
    }
    ret = flb_msgpack_strcmp_str(obj, "value");
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("a value of \"key\" mismatch. got=%d expect=0 str=%.*s", ret,
                 obj->via.str.size,obj->via.str.ptr);
    }

    obj = flb_msgpack_get_value_from_map(&result.data, "int", 3);
    if (!TEST_CHECK(obj != NULL)) {
        TEST_MSG("a value of \"int\" not found\ninput=%s", json);
    }
    if (!TEST_CHECK(obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER)) {
        TEST_MSG("a value of \"int\" is not int type");
    }
    if (!TEST_CHECK(obj->via.i64  == 1)) {
        TEST_MSG("a value of \"int\" mismatch. got=%"PRId64 " expect=1", obj->via.i64);
    }

    obj = flb_msgpack_get_value_from_map(&result.data, "map", 3);
    if (!TEST_CHECK(obj != NULL)) {
        TEST_MSG("a value of \"map\" not found\ninput=%s", json);
    }
    if (!TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP)) {
        TEST_MSG("a value of \"map\" is not map type");
    }
    if (!TEST_CHECK(obj->via.map.size == 1)) {
        TEST_MSG("map size is not 1. got=%d", obj->via.map.size);
    }


    /* error case */
    obj = flb_msgpack_get_value_from_map(&result.data, "not_found_key", strlen("not_found_key"));
    if (!TEST_CHECK(obj == NULL)) {
        TEST_MSG("missing key should be error");
    }

    msgpack_unpacked_destroy(&result);
    flb_free(out_buf);
}

void test_msgpack_get_value_from_nested_map()
{
    int ret;
    int root_type;
    char *out_buf;
    size_t out_size;
    char *json = "{\"key1\":{\"key2\":{\"key3\":\"value\"}}}";
    char *nested_key[] = {"key1", "key2", "key3"};
    msgpack_object *obj = NULL;
    msgpack_unpacked result;
    size_t offset = 0;

    char *error_nested_key1[] = {"not_found_key"};
    char *error_nested_key2[] = {"key1","not_found_key"};

    ret = flb_pack_json(json, strlen(json), &out_buf, &out_size, &root_type, NULL);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_pack_json failed. input=%s", json);
    }

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &offset);

    /* seek a value of "key1" */
    obj = flb_msgpack_get_value_from_nested_map(&result.data, nested_key, 1);
    if (!TEST_CHECK(obj != NULL)) {
        TEST_MSG("a value of \"key1\" not found\ninput=%s", json);
    }
    if (!TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP)) {
        TEST_MSG("a value of \"key1\" should be map");
    }

    /* seek a value of "key1/key2" */
    obj = flb_msgpack_get_value_from_nested_map(&result.data, nested_key, 2);
    if (!TEST_CHECK(obj != NULL)) {
        TEST_MSG("a value of \"key1/key2\" not found\ninput=%s", json);
    }
    if (!TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP)) {
        TEST_MSG("a value of \"key1/key2\" should be map");
    }

    /* seek a value of "key1/key2/key3" */
    obj = flb_msgpack_get_value_from_nested_map(&result.data, nested_key, 3);
    if (!TEST_CHECK(obj != NULL)) {
        TEST_MSG("a value of \"key1/key2/key3\" not found\ninput=%s", json);
    }
    ret = flb_msgpack_strcmp_str(obj, "value");
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("a value of \"key1/key2/key3\" mismatch");
    }

    /* error case */
    obj = flb_msgpack_get_value_from_nested_map(&result.data, error_nested_key1, 1);
    if (!TEST_CHECK(obj == NULL)) {
        TEST_MSG("missing key should be error");
    }

    obj = flb_msgpack_get_value_from_nested_map(&result.data, error_nested_key2, 2);
    if (!TEST_CHECK(obj == NULL)) {
        TEST_MSG("missing key should be error");
    }

    msgpack_unpacked_destroy(&result);
    flb_free(out_buf);
}

TEST_LIST = {
    { "flb_msgpack_strcmp_str_len", test_msgpack_strcmp_str_len},
    { "flb_msgpack_strcmp_str", test_msgpack_strcmp_str},
    { "flb_msgpack_strcmp_sds", test_msgpack_strcmp_sds},
    { "flb_msgpack_strcmp_msgpack_str", test_msgpack_strcmp_msgpack_str},
    { "flb_msgpack_get_value_from_map", test_msgpack_get_value_from_map},
    { "flb_msgpack_get_value_from_nested_map", test_msgpack_get_value_from_nested_map},
    { 0 }
};
