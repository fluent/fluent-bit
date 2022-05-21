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
#include <fluent-bit/flb_record_accessor.h>
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
    ret = flb_pack_json(input_json, len, out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    ret = flb_pack_json(json, len, &out_buf, &out_size, &type);
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
    { NULL }
};
