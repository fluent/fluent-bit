/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_sds_list.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

#include <stdlib.h>

static int create_map(char *input_json, msgpack_object *out_map,
                      char **out_buf, msgpack_unpacked *out_result)
{
    int len;
    int ret;
    size_t out_size;
    int type;
    size_t off = 0;

    if (input_json == NULL || out_map == NULL) {
        return -1;
    }
    len = strlen(input_json);
    ret = flb_pack_json(input_json, len, out_buf, &out_size, &type, NULL);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("can't convert. input=%s", input_json);
        exit(EXIT_FAILURE);
    }
    /* Unpack msgpack object */
    msgpack_unpacked_init(out_result);
    msgpack_unpack_next(out_result, *out_buf, out_size, &off);
    *out_map = out_result->data;

    return 0;
}

static int set_str_to_msgpack_object(char *str, msgpack_object *obj)
{
    if (str == NULL || obj == NULL) {
        return -1;
    }
        /* create value object to overwrite */
    obj->type     = MSGPACK_OBJECT_STR;
    obj->via.str.size = strlen(str);
    obj->via.str.ptr  = str;
    return 0;
}


void cb_keys()
{
    struct flb_record_accessor *ra;

    printf("\n=== test ===");
    ra = flb_ra_create("$aaa['a'] extra $bbb['b'] final access", FLB_TRUE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(mk_list_size(&ra->list) == 4);
    flb_ra_dump(ra);
    flb_ra_destroy(ra);

    printf("\n=== test ===");
    ra = flb_ra_create("$b['x']['y']", FLB_TRUE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(mk_list_size(&ra->list) == 1);
    flb_ra_dump(ra);
    flb_ra_destroy(ra);

    printf("\n=== test ===");
    ra = flb_ra_create("$z", FLB_TRUE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(mk_list_size(&ra->list) == 1);
    flb_ra_dump(ra);
    flb_ra_destroy(ra);

    printf("\n=== test ===");
    ra = flb_ra_create("abc", FLB_TRUE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(mk_list_size(&ra->list) == 1);
    flb_ra_dump(ra);
    flb_ra_destroy(ra);

    ra = flb_ra_create("$abc['a'", FLB_TRUE);
    TEST_CHECK(ra == NULL);

    ra = flb_ra_create("", FLB_TRUE);
    flb_ra_destroy(ra);
}

void cb_translate()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json =
        "{\"k1\": \"string\", \"k2\": true, \"k3\": false," \
        " \"k4\": 0.123456789, \"k5\": 123456789,"          \
        " \"k6\": {\"s1\": {\"s2\": \"nested\"}}}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Set environment variables */
    putenv("FLB_ENV=translated");

    /* Formatter */
    fmt =                                                               \
        "START k1 => \"$k1\", k2 => $k2 (bool), k3 => $k3 (bool), "    \
        "k4 => $k4 (float), k5 => $k5 (int),"                           \
        "k6 => $k6['s1']['s2'] (nested), k8 => $k8 (nothing), ${FLB_ENV} END";

    fmt_out = \
        "START k1 => \"string\", k2 => true (bool), "                   \
        "k3 => false (bool), k4 => 0.123457 (float), "                  \
        "k5 => 123456789 (int),k6 => nested (nested), "           \
        "k8 =>  (nothing), translated END";

    ra = flb_ra_create(fmt, FLB_TRUE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_translate_tag()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json =
        "{\"k1\": \"string\", \"k2\": true, \"k3\": false," \
        " \"k4\": 0.123456789, \"k5\": 123456789,"          \
        " \"k6\": {\"s1\": {\"s2\": \"nested\"}}}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    fmt = "$TAG";
    ra = flb_ra_create(fmt, FLB_TRUE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, "testapp", 7, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(flb_sds_len(str) == 7);

    flb_sds_destroy(str);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_dots_subkeys()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", \"kubernetes\": {\"annotations\": "
        "{\"fluentbit.io/tag\": \"thetag\"}}}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes['annotations']['fluentbit.io/tag']");
    fmt_out = "thetag";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_array_id()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    fmt_out = "thetag";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_get_kv_pair()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    msgpack_object *start_key;
    msgpack_object *out_key;
    msgpack_object *out_val;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    fmt_out = "thetag";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    ret = flb_ra_get_kv_pair(ra, map, &start_key, &out_key, &out_val);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(out_val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_val->via.str.size == strlen(fmt_out));
    TEST_CHECK(memcmp(out_val->via.str.ptr, fmt_out, strlen(fmt_out)) == 0);

    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_update_key_val()
{
    int ret;
    size_t off = 0;
    char *json;
    flb_sds_t fmt;
    flb_sds_t updated_fmt;
    char *fmt_out_key = "updated_key";
    char *fmt_out_val = "updated_val";

    char *out_buf = NULL;
    size_t out_size = 0;

    msgpack_unpacked result;
    msgpack_unpacked out_result;

    msgpack_object map;
    msgpack_object *start_key = NULL;
    msgpack_object *out_key = NULL;
    msgpack_object *out_val = NULL;
    void *updated_map;
    msgpack_object in_key;
    msgpack_object in_val;

    struct flb_record_accessor *ra;
    struct flb_record_accessor *updated_ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";
    ret = create_map(json, &map, &out_buf, &result);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed create map");
        if (out_buf != NULL) {
            flb_free(out_buf);
        }
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    ra = flb_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$kubernetes[2]['annotations']['updated_key']");
    updated_ra = flb_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* create key object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out_key, &in_key);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }
    /* create value object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out_val, &in_val);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_ra_update_kv_pair(ra, map, (void**)&updated_map, &out_size, &in_key, &in_val);
    TEST_CHECK(ret == 0);
    off = 0;
    msgpack_unpacked_init(&out_result);
    if (msgpack_unpack_next(&out_result, updated_map, out_size, &off)
        != MSGPACK_UNPACK_SUCCESS) {
        TEST_MSG("failed to unpack");
        exit(EXIT_FAILURE);
    }
    ret = flb_ra_get_kv_pair(updated_ra, out_result.data, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        msgpack_object_print(stdout, out_result.data);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(out_key->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_key->via.str.size == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key->via.str.ptr, fmt_out_key, strlen(fmt_out_key)) == 0);

    /* Check updated val */
    TEST_CHECK(out_val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_val->via.str.size == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->via.str.ptr, fmt_out_val, strlen(fmt_out_val)) == 0);

    msgpack_unpacked_destroy(&out_result);
    msgpack_unpacked_destroy(&result);
    flb_free(updated_map);
    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_ra_destroy(updated_ra);
    flb_ra_destroy(ra);
    flb_free(out_buf);
}

void cb_update_val()
{
    int ret;
    size_t off = 0;
    char *json;
    flb_sds_t fmt;
    char *fmt_out = "updated";
    char *out_buf = NULL;
    size_t out_size = 0;

    msgpack_unpacked result;
    msgpack_unpacked out_result;

    msgpack_object map;
    msgpack_object *start_key = NULL;
    msgpack_object *out_key = NULL;
    msgpack_object *out_val = NULL;
    void *updated_map;
    msgpack_object in_val;

    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";
    ret = create_map(json, &map, &out_buf, &result);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed create map");
        if (out_buf != NULL) {
            flb_free(out_buf);
        }
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    ra = flb_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* create value object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out, &in_val);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_ra_update_kv_pair(ra, map, (void**)&updated_map, &out_size, NULL, &in_val);
    TEST_CHECK(ret == 0);
    off = 0;
    msgpack_unpacked_init(&out_result);
    if (msgpack_unpack_next(&out_result, updated_map, out_size, &off)
        != MSGPACK_UNPACK_SUCCESS) {
        TEST_MSG("failed to unpack");
        exit(EXIT_FAILURE);
    }
    ret = flb_ra_get_kv_pair(ra, out_result.data, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        msgpack_object_print(stdout, out_result.data);
        exit(EXIT_FAILURE);
    }

    /* Check updated val */
    TEST_CHECK(out_val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_val->via.str.size == strlen(fmt_out));
    TEST_CHECK(memcmp(out_val->via.str.ptr, fmt_out, strlen(fmt_out)) == 0);

    msgpack_unpacked_destroy(&out_result);
    msgpack_unpacked_destroy(&result);
    flb_free(updated_map);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
}

void cb_update_key()
{
    int ret;
    size_t off = 0;
    char *json;
    flb_sds_t fmt;
    flb_sds_t updated_fmt;
    char *fmt_out = "updated_key";


    char *out_buf = NULL;
    size_t out_size = 0;

    msgpack_unpacked result;
    msgpack_unpacked out_result;

    msgpack_object map;
    msgpack_object *start_key = NULL;
    msgpack_object *out_key = NULL;
    msgpack_object *out_val = NULL;
    void *updated_map;
    msgpack_object in_key;

    struct flb_record_accessor *ra;
    struct flb_record_accessor *updated_ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";
    ret = create_map(json, &map, &out_buf, &result);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed create map");
        if (out_buf != NULL) {
            flb_free(out_buf);
        }
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    ra = flb_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$kubernetes[2]['annotations']['updated_key']");
    updated_ra = flb_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* create key object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out, &in_key);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_ra_update_kv_pair(ra, map, (void**)&updated_map, &out_size, &in_key, NULL);
    TEST_CHECK(ret == 0);
    off = 0;
    msgpack_unpacked_init(&out_result);
    if (msgpack_unpack_next(&out_result, updated_map, out_size, &off)
        != MSGPACK_UNPACK_SUCCESS) {
        TEST_MSG("failed to unpack");
        exit(EXIT_FAILURE);
    }
    ret = flb_ra_get_kv_pair(updated_ra, out_result.data, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        msgpack_object_print(stdout, out_result.data);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(out_key->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_key->via.str.size == strlen(fmt_out));
    TEST_CHECK(memcmp(out_key->via.str.ptr, fmt_out, strlen(fmt_out)) == 0);

    msgpack_unpacked_destroy(&out_result);
    msgpack_unpacked_destroy(&result);
    flb_free(updated_map);
    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_ra_destroy(updated_ra);
    flb_ra_destroy(ra);
    flb_free(out_buf);
}

void cb_dash_key()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json = "{\"key-dash\": \"something\"}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$key-dash");
    fmt_out = "something";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_dot_and_slash_key()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json = "{\"root.with/symbols\": \"something\"}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$root.with/symbols");
    if (!TEST_CHECK(fmt != NULL)) {
        exit(EXIT_FAILURE);
    }

    fmt_out = "something";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

static int order_lookup_check(char *buf, size_t size,
                              char *fmt, char *expected_out)
{
    size_t off = 0;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Check bool is 'true' */
    fmt = flb_sds_create(fmt);
    if (!TEST_CHECK(fmt != NULL)) {
        exit(EXIT_FAILURE);
    }
    fmt_out = expected_out;

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, buf, size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(expected_out));
    if (flb_sds_len(str) != strlen(expected_out)) {
        printf("received: '%s', expected: '%s'\n", str, fmt_out);
    }

    TEST_CHECK(memcmp(str, expected_out, strlen(expected_out)) == 0);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);

    return 0;
}

void cb_key_order_lookup()
{
    int len;
    int ret;
    int type;
    char *out_buf;
    size_t out_size;
    char *json;

    /* Sample JSON message */
    json = "{\"key\": \"abc\", \"bool\": false, \"bool\": true, "
             "\"str\": \"bad\", \"str\": \"good\", "
             "\"num\": 0, \"num\": 1}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    printf("\n-- record --\n");
    flb_pack_print(out_buf, out_size);

    /* check expected outputs per record accessor pattern */
    order_lookup_check(out_buf, out_size, "$bool", "true");
    order_lookup_check(out_buf, out_size, "$str" , "good");
    order_lookup_check(out_buf, out_size, "$num" , "1");

    flb_free(out_buf);
}

void cb_issue_4917()
{
    int len;
    int ret;
    int type;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt_out;
    size_t off = 0;
    flb_sds_t fmt;
    flb_sds_t str;
    struct flb_record_accessor *ra;
    msgpack_unpacked result;
    msgpack_object map;

    fmt_out = "from.new.fluent.bit.out";

    /* Sample JSON message */
    json = "{\"tool\": \"fluent\", \"sub\": {\"s1\": {\"s2\": \"bit\"}}}";
    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    printf("\n-- record --\n");
    flb_pack_print(out_buf, out_size);

    /* Formatter */
    fmt = flb_sds_create("from.new.$tool.$sub['s1']['s2'].out");
    if (!TEST_CHECK(fmt != NULL)) {
        flb_free(out_buf);
        exit(EXIT_FAILURE);
    }

    /* create ra */
    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        flb_sds_destroy(fmt);
        flb_free(out_buf);
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        flb_ra_destroy(ra);
        msgpack_unpacked_destroy(&result);
        flb_sds_destroy(fmt);
        flb_free(out_buf);
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(fmt);
    flb_sds_destroy(str);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_update_root_key()
{
    int ret;
    size_t off = 0;
    char *json;
    flb_sds_t fmt;
    flb_sds_t updated_fmt;
    char *fmt_out = "updated_key";


    char *out_buf = NULL;
    size_t out_size = 0;

    msgpack_unpacked result;
    msgpack_unpacked out_result;

    msgpack_object map;
    msgpack_object *start_key = NULL;
    msgpack_object *out_key = NULL;
    msgpack_object *out_val = NULL;
    void *updated_map;
    msgpack_object in_key;

    struct flb_record_accessor *ra;
    struct flb_record_accessor *updated_ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";
    ret = create_map(json, &map, &out_buf, &result);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed create map");
        if (out_buf != NULL) {
            flb_free(out_buf);
        }
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$key1");
    ra = flb_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$updated_key");
    updated_ra = flb_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* create key object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out, &in_key);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_ra_update_kv_pair(ra, map, (void**)&updated_map, &out_size, &in_key, NULL);
    TEST_CHECK(ret == 0);
    off = 0;
    msgpack_unpacked_init(&out_result);
    if (msgpack_unpack_next(&out_result, updated_map, out_size, &off)
        != MSGPACK_UNPACK_SUCCESS) {
        TEST_MSG("failed to unpack");
        exit(EXIT_FAILURE);
    }
    ret = flb_ra_get_kv_pair(updated_ra, out_result.data, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        msgpack_object_print(stdout, out_result.data);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(out_key->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_key->via.str.size == strlen(fmt_out));
    TEST_CHECK(memcmp(out_key->via.str.ptr, fmt_out, strlen(fmt_out)) == 0);

    msgpack_unpacked_destroy(&out_result);
    msgpack_unpacked_destroy(&result);
    flb_free(updated_map);
    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_ra_destroy(updated_ra);
    flb_ra_destroy(ra);
    flb_free(out_buf);
}

void cb_update_root_key_val()
{
    int ret;
    size_t off = 0;
    char *json;
    flb_sds_t fmt;
    flb_sds_t updated_fmt;
    char *fmt_out_key = "updated_key";
    char *fmt_out_val = "updated_val";

    char *out_buf = NULL;
    size_t out_size = 0;

    msgpack_unpacked result;
    msgpack_unpacked out_result;

    msgpack_object map;
    msgpack_object *start_key = NULL;
    msgpack_object *out_key = NULL;
    msgpack_object *out_val = NULL;
    void *updated_map;
    msgpack_object in_key;
    msgpack_object in_val;

    struct flb_record_accessor *ra;
    struct flb_record_accessor *updated_ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";
    ret = create_map(json, &map, &out_buf, &result);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed create map");
        if (out_buf != NULL) {
            flb_free(out_buf);
        }
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$key1");
    ra = flb_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$updated_key");
    updated_ra = flb_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* create key object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out_key, &in_key);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }
    /* create value object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out_val, &in_val);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_ra_update_kv_pair(ra, map, (void**)&updated_map, &out_size, &in_key, &in_val);
    TEST_CHECK(ret == 0);
    off = 0;
    msgpack_unpacked_init(&out_result);
    if (msgpack_unpack_next(&out_result, updated_map, out_size, &off)
        != MSGPACK_UNPACK_SUCCESS) {
        TEST_MSG("failed to unpack");
        exit(EXIT_FAILURE);
    }
    ret = flb_ra_get_kv_pair(updated_ra, out_result.data, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        msgpack_object_print(stdout, out_result.data);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(out_key->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_key->via.str.size == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key->via.str.ptr, fmt_out_key, strlen(fmt_out_key)) == 0);

    /* Check updated val */
    TEST_CHECK(out_val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_val->via.str.size == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->via.str.ptr, fmt_out_val, strlen(fmt_out_val)) == 0);

    msgpack_unpacked_destroy(&out_result);
    msgpack_unpacked_destroy(&result);
    flb_free(updated_map);
    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_ra_destroy(updated_ra);
    flb_ra_destroy(ra);
    flb_free(out_buf);
}

void cb_add_key_val()
{
    int ret;
    size_t off = 0;
    char *json;
    flb_sds_t fmt;
    flb_sds_t updated_fmt;
    char *fmt_out_key = "add_key";
    char *fmt_out_val = "add_val";

    char *out_buf = NULL;
    size_t out_size = 0;

    msgpack_unpacked result;
    msgpack_unpacked out_result;

    msgpack_object map;
    msgpack_object *start_key = NULL;
    msgpack_object *out_key = NULL;
    msgpack_object *out_val = NULL;
    void *updated_map;
    msgpack_object in_val;

    struct flb_record_accessor *ra;
    struct flb_record_accessor *updated_ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";
    ret = create_map(json, &map, &out_buf, &result);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed create map");
        if (out_buf != NULL) {
            flb_free(out_buf);
        }
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['add_key']");
    ra = flb_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$kubernetes[2]['annotations']['add_key']");
    updated_ra = flb_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* create value object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out_val, &in_val);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }

    /* Add key/value */
    ret = flb_ra_append_kv_pair(ra, map, (void**)&updated_map, &out_size, &in_val);
    TEST_CHECK(ret == 0);

    off = 0;
    msgpack_unpacked_init(&out_result);
    ret = msgpack_unpack_next(&out_result, updated_map, out_size, &off);
    if (!TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS)) {
        TEST_MSG("failed to unpack");
        exit(EXIT_FAILURE);
    }
    ret = flb_ra_get_kv_pair(updated_ra, out_result.data, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("print out_result\n");
        msgpack_object_print(stdout, out_result.data);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(out_key->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_key->via.str.size == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key->via.str.ptr, fmt_out_key, strlen(fmt_out_key)) == 0);

    /* Check updated val */
    TEST_CHECK(out_val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_val->via.str.size == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->via.str.ptr, fmt_out_val, strlen(fmt_out_val)) == 0);

    msgpack_unpacked_destroy(&out_result);
    msgpack_unpacked_destroy(&result);
    flb_free(updated_map);
    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_ra_destroy(updated_ra);
    flb_ra_destroy(ra);
    flb_free(out_buf);
}

void cb_add_root_key_val()
{
    int ret;
    size_t off = 0;
    char *json;
    flb_sds_t fmt;
    flb_sds_t updated_fmt;
    char *fmt_out_key = "add_key";
    char *fmt_out_val = "add_val";

    char *out_buf = NULL;
    size_t out_size = 0;

    msgpack_unpacked result;
    msgpack_unpacked out_result;

    msgpack_object map;
    msgpack_object *start_key = NULL;
    msgpack_object *out_key = NULL;
    msgpack_object *out_val = NULL;
    void *updated_map;
    msgpack_object in_val;

    struct flb_record_accessor *ra;
    struct flb_record_accessor *updated_ra;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\""
        "}}]}";
    ret = create_map(json, &map, &out_buf, &result);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed create map");
        if (out_buf != NULL) {
            flb_free(out_buf);
        }
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$add_key");
    ra = flb_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$add_key");
    updated_ra = flb_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_ra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* create value object to overwrite */
    ret = set_str_to_msgpack_object(fmt_out_val, &in_val);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("failed to set object");
        exit(EXIT_FAILURE);
    }

    /* Add key/value */
    ret = flb_ra_append_kv_pair(ra, map, (void**)&updated_map, &out_size, &in_val);
    TEST_CHECK(ret == 0);

    off = 0;
    msgpack_unpacked_init(&out_result);
    ret = msgpack_unpack_next(&out_result, updated_map, out_size, &off);
    if (!TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS)) {
        TEST_MSG("failed to unpack");
        exit(EXIT_FAILURE);
    }
    ret = flb_ra_get_kv_pair(updated_ra, out_result.data, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("print out_result\n");
        msgpack_object_print(stdout, out_result.data);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(out_key->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_key->via.str.size == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key->via.str.ptr, fmt_out_key, strlen(fmt_out_key)) == 0);

    /* Check updated val */
    TEST_CHECK(out_val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(out_val->via.str.size == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->via.str.ptr, fmt_out_val, strlen(fmt_out_val)) == 0);

    msgpack_unpacked_destroy(&out_result);
    msgpack_unpacked_destroy(&result);
    flb_free(updated_map);
    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_ra_destroy(updated_ra);
    flb_ra_destroy(ra);
    flb_free(out_buf);
}

void cb_ra_translate_check()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;
    int check_translation = FLB_TRUE;

    /* Sample JSON message */
    json = "{\"root.with/symbols\": \"something\"}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$root");
    if (!TEST_CHECK(fmt != NULL)) {
        exit(EXIT_FAILURE);
    }

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation - with check enabled */
    str = flb_ra_translate_check(ra, NULL, -1, map, NULL, check_translation);
    /* since translation fails and check is enabled, it returns NULL */
    TEST_CHECK(str == NULL);
    if (str) {
        exit(EXIT_FAILURE);
    }

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

/*
 * https://github.com/fluent/fluent-bit/issues/5936
 *  If the last nested element is an array, record accessor can't get its value.
 */
void cb_issue_5936_last_array()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON message */
    json ="{ \"key\": {\"nested\":[\"val0\", \"val1\"]}}";


    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$key['nested'][1]");
    fmt_out = "val1";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

struct char_list_ra_str{
    char **strs;
    char *expect;
};

void cb_ra_create_str_from_list()
{
    char *case1[] = {"a", NULL};
    char *case2[] = {"aa", "bb", "cc", NULL};

    struct char_list_ra_str testcases[] = {
        { .strs = &case1[0], .expect = "$a"},
        { .strs = &case2[0], .expect = "$aa['bb']['cc']"},
    };
    size_t case_size = sizeof(testcases)/sizeof(struct char_list_ra_str);
    int case_i;
    struct flb_sds_list *list = NULL;
    flb_sds_t ret_str;
    char *str;
    int i;
    int ret;

    for (case_i = 0; case_i < case_size; case_i++) {
        list = flb_sds_list_create();
        if (!TEST_CHECK(list != NULL)) {
            TEST_MSG("%d: flb_sds_list_create failed", case_i);
            exit(EXIT_FAILURE);
        }
        i = 0;
        while(testcases[case_i].strs[i] != NULL) {
            str = testcases[case_i].strs[i];
            ret = flb_sds_list_add(list, str, strlen(str));
            if (!TEST_CHECK(ret == 0)) {
                TEST_MSG("%d: flb_sds_list_add failed", case_i);
                flb_sds_list_destroy(list);
                exit(EXIT_FAILURE);
            }
            i++;
        }

        ret_str = flb_ra_create_str_from_list(list);
        if (!TEST_CHECK(ret_str != NULL)) {
            TEST_MSG("%d: flb_ra_create_str_from failed", case_i);
            flb_sds_list_destroy(list);
            exit(EXIT_FAILURE);
        }
        if (!TEST_CHECK(strcmp(testcases[case_i].expect, ret_str) == 0)) {
            TEST_MSG("%d: strcmp error.got=%s expect=%s", case_i, ret_str, testcases[case_i].expect);
        }

        flb_sds_destroy(ret_str);
        flb_sds_list_destroy(list);
    }


    /* Error if we pass empty list */
    list = flb_sds_list_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("flb_sds_list_create failed");
        exit(EXIT_FAILURE);
    }
    ret_str = flb_ra_create_str_from_list(list);
    if (!TEST_CHECK(ret_str == NULL)) {
        TEST_MSG("flb_ra_create_str_from should be failed");
        flb_sds_list_destroy(list);
        exit(EXIT_FAILURE);
    }
    flb_sds_list_destroy(list);
}

/*
 * https://github.com/fluent/fluent-bit/issues/7330
 */
void cb_issue_7330_single_char()
{
    int ret;
    int type;
    char *json;
    char *out_buf = NULL;
    size_t out_size;
    size_t off = 0;
    flb_sds_t input = NULL;
    flb_sds_t out_tag = NULL;
    struct flb_regex_search regex_result;
    struct flb_record_accessor *ra_tag = NULL;
    msgpack_unpacked result;
    msgpack_object map;

    json = "{\"tool\":\"fluent\"}";
    ret = flb_pack_json(json, strlen(json), &out_buf, &out_size, &type, NULL);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_pack_json failed");
        exit(EXIT_FAILURE);
    }

    input = flb_sds_create("b");
    if (!TEST_CHECK(input != NULL)) {
        goto issue_7330;
    }

    /* create flb_record_accessor from single character */
    ra_tag = flb_ra_create(input, FLB_FALSE);
    if (!TEST_CHECK(ra_tag != NULL)) {
        TEST_MSG("flb_ra_create failed");
        goto issue_7330;
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    out_tag = flb_ra_translate(ra_tag, "old", 3, map, &regex_result);
    msgpack_unpacked_destroy(&result);
    if (!TEST_CHECK(out_tag != NULL)) {
        TEST_MSG("flb_ra_translate failed");
        goto issue_7330;
    }
    else if (!TEST_CHECK(flb_sds_len(out_tag) > 0)) {
        TEST_MSG("out_tag len error. len=%zd", flb_sds_len(out_tag));
        goto issue_7330;
    }

 issue_7330:
    if (input) {
        flb_sds_destroy(input);
    }
    if (out_tag) {
        flb_sds_destroy(out_tag);
    }
    if (out_buf) {
        flb_free(out_buf);
    }
    if (ra_tag) {
        flb_ra_destroy(ra_tag);
    }
}

void cb_direct_array_access()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON with direct array */
    json = "{\"array\": [\"a\", \"b\", \"c\"]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter for direct array access */
    fmt = flb_sds_create("$array[0]");
    fmt_out = "a";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== direct array access test ==\n== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_nested_array_access()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON with nested arrays */
    json = "{\"matrix\": [[1, 2, 3], [4, 5, 6], [7, 8, 9]]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter for nested array access */
    fmt = flb_sds_create("$matrix[1][2]");  /* Should access the value 6 */
    fmt_out = "6";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== nested array access test ==\n== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_mixed_array_map_access()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON with array containing maps */
    json = "{\"records\": [{\"name\": \"John\", \"age\": 30}, {\"name\": \"Jane\", \"age\": 25}]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter for mixed array+map access */
    fmt = flb_sds_create("$records[1]['name']");  /* Should access "Jane" */
    fmt_out = "Jane";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== mixed array+map access test ==\n== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_direct_array_element_access()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON with direct array - matches the example in the issue */
    json = "{\"array\": [\"a\", \"b\", \"c\"]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter for accessing the second element in the array */
    fmt = flb_sds_create("$array[1]");  /* Should access the value "b" */
    fmt_out = "b";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== direct array element access test ==\n== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_array_index_overflow()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    flb_sds_t fmt;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON with array */
    json = "{\"array\": [\"a\", \"b\", \"c\"]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter with out-of-bounds index */
    fmt = flb_sds_create("$array[99]");  /* Access beyond array bounds */

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation - should return empty string for out-of-bounds */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);

    if (str) {
        TEST_CHECK(flb_sds_len(str) == 0);
        flb_sds_destroy(str);
    }

    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_nonexistent_key_access()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    flb_sds_t fmt;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON */
    json = "{\"key1\": \"value1\", \"key2\": {\"nested\": \"value2\"}}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Formatter for nonexistent key */
    fmt = flb_sds_create("$nonexistent_key");

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    /* Unpack msgpack object */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Do translation - should return empty string for nonexistent key */
    str = flb_ra_translate(ra, NULL, -1, map, NULL);

    if (str) {
        TEST_CHECK(flb_sds_len(str) == 0);
        flb_sds_destroy(str);
    }

    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    flb_free(out_buf);
    msgpack_unpacked_destroy(&result);
}

void cb_wrong_type_access()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    flb_sds_t fmt;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON with mixed types */
    json = "{\"string\": \"text\", \"number\": 123, \"bool\": true, \"array\": [1,2,3]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Array access on string - returns original string value */
    fmt = flb_sds_create("$string[0]");

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    str = flb_ra_translate(ra, NULL, -1, map, NULL);

    if (str) {
        TEST_CHECK(flb_sds_len(str) > 0);
        TEST_CHECK(memcmp(str, "text", 4) == 0);
        flb_sds_destroy(str);
    }

    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);

    /* Map access on number - returns number as string */
    fmt = flb_sds_create("$number['key']");

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    off = 0;
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    str = flb_ra_translate(ra, NULL, -1, map, NULL);

    if (str) {
        TEST_CHECK(flb_sds_len(str) > 0);
        TEST_CHECK(memcmp(str, "123", 3) == 0);
        flb_sds_destroy(str);
    }

    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);

    flb_free(out_buf);
}

void cb_nested_failure_recovery()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *out_buf;
    size_t out_size;
    char *json;
    flb_sds_t fmt;
    char *fmt_out;
    flb_sds_t str;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;

    /* Sample JSON with nested structure */
    json = "{\"level1\": {\"level2\": {\"valid\": \"found\"}}}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Test invalid intermediate path */
    fmt = flb_sds_create("$level1['nonexistent']['key']");

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    str = flb_ra_translate(ra, NULL, -1, map, NULL);

    if (str) {
        TEST_CHECK(flb_sds_len(str) == 0);
        flb_sds_destroy(str);
    }

    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);

    /* Test valid nested path */
    fmt = flb_sds_create("$level1['level2']['valid']");
    fmt_out = "found";

    ra = flb_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(ra != NULL);
    if (!ra) {
        exit(EXIT_FAILURE);
    }

    off = 0;
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    str = flb_ra_translate(ra, NULL, -1, map, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);

    flb_free(out_buf);
}

/* --- binary/reference record accessor tests --- */

static const unsigned char BIN_DATA[4] = {0x01, 0x02, 0x03, 0x04};

static void build_ra_map(msgpack_sbuffer *sbuf, const char **bin_ptr)
{
    msgpack_packer pck;

    msgpack_sbuffer_init(sbuf);
    msgpack_packer_init(&pck, sbuf, msgpack_sbuffer_write);

    /* map {"bin": <bin>, "str": "abc"} */
    msgpack_pack_map(&pck, 2);

    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "bin", 3);
    msgpack_pack_bin(&pck, sizeof(BIN_DATA));
    msgpack_pack_bin_body(&pck, BIN_DATA, sizeof(BIN_DATA));

    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "str", 3);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "abc", 3);

    if (bin_ptr) {
        *bin_ptr = NULL;
        for (size_t i = 0; i + sizeof(BIN_DATA) <= sbuf->size; i++) {
            if (memcmp(sbuf->data + i, BIN_DATA, sizeof(BIN_DATA)) == 0) {
                *bin_ptr = sbuf->data + i;
                break;
            }
        }
    }
}

static void destroy_sbuf(msgpack_sbuffer *sbuf)
{
    msgpack_sbuffer_destroy(sbuf);
}

static void cb_ra_binary_copy()
{
    msgpack_sbuffer sbuf;
    const char *dummy;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;
    struct flb_ra_value *val;
    size_t off = 0, len;
    const char *buf;

    build_ra_map(&sbuf, &dummy);

    msgpack_unpacked_init(&result);
    TEST_CHECK(msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off) == MSGPACK_UNPACK_SUCCESS);
    map = result.data;

    ra = flb_ra_create("bin", FLB_TRUE);
    TEST_CHECK(ra != NULL);
    val = flb_ra_get_value_object(ra, map);
    TEST_CHECK(val != NULL && val->type == FLB_RA_BINARY && val->storage == FLB_RA_COPY);
    buf = flb_ra_value_buffer(val, &len);
    TEST_CHECK(len == sizeof(BIN_DATA));
    TEST_CHECK(memcmp(buf, BIN_DATA, sizeof(BIN_DATA)) == 0);

    flb_ra_key_value_destroy(val);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);
    destroy_sbuf(&sbuf);
}

static void cb_ra_binary_ref()
{
    msgpack_sbuffer sbuf;
    const char *bin_in_map;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;
    struct flb_ra_value *val;
    size_t off = 0, len;
    const char *buf;

    build_ra_map(&sbuf, &bin_in_map);

    msgpack_unpacked_init(&result);
    TEST_CHECK(msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off) == MSGPACK_UNPACK_SUCCESS);
    map = result.data;

    ra = flb_ra_create("bin", FLB_TRUE);
    TEST_CHECK(ra != NULL);
    val = flb_ra_get_value_object_ref(ra, map);
    TEST_CHECK(val != NULL && val->type == FLB_RA_BINARY && val->storage == FLB_RA_REF);
    buf = flb_ra_value_buffer(val, &len);
    TEST_CHECK(len == sizeof(BIN_DATA));
    TEST_CHECK(memcmp(buf, BIN_DATA, sizeof(BIN_DATA)) == 0);
    TEST_CHECK(buf == bin_in_map);

    flb_ra_key_value_destroy(val);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);
    destroy_sbuf(&sbuf);
}

static void cb_ra_string_copy()
{
    msgpack_sbuffer sbuf;
    const char *dummy;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;
    struct flb_ra_value *val;
    size_t off = 0, len;
    const char *buf;

    build_ra_map(&sbuf, &dummy);

    msgpack_unpacked_init(&result);
    TEST_CHECK(msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off) == MSGPACK_UNPACK_SUCCESS);
    map = result.data;

    ra = flb_ra_create("str", FLB_TRUE);
    TEST_CHECK(ra != NULL);
    val = flb_ra_get_value_object(ra, map);
    TEST_CHECK(val != NULL && val->type == FLB_RA_STRING && val->storage == FLB_RA_COPY);
    buf = flb_ra_value_buffer(val, &len);
    TEST_CHECK(len == 3 && strncmp(buf, "abc", 3) == 0);

    flb_ra_key_value_destroy(val);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);
    destroy_sbuf(&sbuf);
}

static void cb_ra_string_ref()
{
    msgpack_sbuffer sbuf;
    const char *dummy;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_record_accessor *ra;
    struct flb_ra_value *val;
    size_t off = 0, len;
    const char *buf;
    const char *expected;

    build_ra_map(&sbuf, &dummy);

    expected = NULL;
    for (size_t i = 0; i + 3 <= sbuf.size; i++) {
        if (memcmp(sbuf.data + i, "abc", 3) == 0) {
            expected = sbuf.data + i;
            break;
        }
    }

    msgpack_unpacked_init(&result);
    TEST_CHECK(msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off) == MSGPACK_UNPACK_SUCCESS);
    map = result.data;

    ra = flb_ra_create("str", FLB_TRUE);
    TEST_CHECK(ra != NULL);
    val = flb_ra_get_value_object_ref(ra, map);
    TEST_CHECK(val != NULL && val->type == FLB_RA_STRING && val->storage == FLB_RA_REF);
    buf = flb_ra_value_buffer(val, &len);
    TEST_CHECK(len == 3 && strncmp(buf, "abc", 3) == 0);
    TEST_CHECK(buf == expected);

    flb_ra_key_value_destroy(val);
    flb_ra_destroy(ra);
    msgpack_unpacked_destroy(&result);
    destroy_sbuf(&sbuf);
}

TEST_LIST = {
    { "keys"            , cb_keys},
    { "dash_key"        , cb_dash_key},
    /*
     * If #4370 is fixed, this testcase should be enabled.
    { "dot_slash_key"   , cb_dot_and_slash_key},
    */
    { "translate"       , cb_translate},
    { "translate_tag"   , cb_translate_tag},
    { "dots_subkeys"    , cb_dots_subkeys},
    { "array_id"        , cb_array_id},
    { "get_kv_pair"     , cb_get_kv_pair},
    { "key_order_lookup", cb_key_order_lookup},
    { "update_key_val", cb_update_key_val},
    { "update_key", cb_update_key},
    { "update_val", cb_update_val},
    { "update_root_key", cb_update_root_key},
    { "update_root_key_val", cb_update_root_key_val},
    { "add_key_val", cb_add_key_val},
    { "add_root_key_val", cb_add_root_key_val},
    { "issue_4917"      , cb_issue_4917},
    { "flb_ra_translate_check" , cb_ra_translate_check},
    { "issue_5936_last_array"      , cb_issue_5936_last_array},
    { "ra_create_str_from_list", cb_ra_create_str_from_list},
    { "issue_7330_single_character"  , cb_issue_7330_single_char},
    { "direct_array_access", cb_direct_array_access },
    { "nested_array_access", cb_nested_array_access },
    { "mixed_array_map_access", cb_mixed_array_map_access },
    { "direct_array_element_access", cb_direct_array_element_access },
    { "array_index_overflow", cb_array_index_overflow },
    { "nonexistent_key_access", cb_nonexistent_key_access },
    { "wrong_type_access", cb_wrong_type_access },
    { "nested_failure_recovery", cb_nested_failure_recovery },
    { "ra_binary_copy", cb_ra_binary_copy },
    { "ra_binary_ref", cb_ra_binary_ref },
    { "ra_string_copy", cb_ra_string_copy },
    { "ra_string_ref", cb_ra_string_ref },
    { NULL }
};
