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

TEST_LIST = {
    { "keys"        , cb_keys},
    { "translate"   , cb_translate},
    { "dots_subkeys", cb_dots_subkeys},
    { NULL }
};
