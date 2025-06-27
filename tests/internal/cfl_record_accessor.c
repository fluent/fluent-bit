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
#include <fluent-bit/flb_cfl_record_accessor.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

#include <stdlib.h>

void cb_keys()
{
    struct flb_cfl_record_accessor *cra;

    printf("\n=== test ===");
    cra = flb_cfl_ra_create("$aaa['a'] extra $bbb['b'] final access", FLB_TRUE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(mk_list_size(&cra->list) == 4);
    flb_cfl_ra_dump(cra);
    flb_cfl_ra_destroy(cra);

    printf("\n=== test ===");
    cra = flb_cfl_ra_create("$b['x']['y']", FLB_TRUE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(mk_list_size(&cra->list) == 1);
    flb_cfl_ra_dump(cra);
    flb_cfl_ra_destroy(cra);

    printf("\n=== test ===");
    cra = flb_cfl_ra_create("$z", FLB_TRUE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(mk_list_size(&cra->list) == 1);
    flb_cfl_ra_dump(cra);
    flb_cfl_ra_destroy(cra);

    printf("\n=== test ===");
    cra = flb_cfl_ra_create("abc", FLB_TRUE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(mk_list_size(&cra->list) == 1);
    flb_cfl_ra_dump(cra);
    flb_cfl_ra_destroy(cra);

    cra = flb_cfl_ra_create("$abc['a'", FLB_TRUE);
    TEST_CHECK(cra == NULL);

    cra = flb_cfl_ra_create("", FLB_TRUE);
    flb_cfl_ra_destroy(cra);
}

void cb_dash_key()
{
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_variant *vobj = NULL;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }

    /* kvlist: "{\"key-dash\" => \"something\"}" */
    cfl_kvlist_insert_string(kvlist, "key-dash", "something");

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$key-dash");
    fmt_out = "something";

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, NULL, -1, *vobj, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    cfl_variant_destroy(vobj);
    flb_cfl_ra_destroy(cra);
}

void cb_translate()
{
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_variant *vobj = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /*     "{\"k1\": \"string\", \"k2\": true, \"k3\": false," \ */
    /*     " \"k4\": 0.123456789, \"k5\": 123456789,"          \ */
    /*     " \"k6\": {\"s1\": {\"s2\": \"nested\"}}}"; */
    cfl_kvlist_insert_string(kvlist, "k1", "string");
    cfl_kvlist_insert_bool(kvlist, "k2", CFL_TRUE);
    cfl_kvlist_insert_bool(kvlist, "k3", CFL_FALSE);
    cfl_kvlist_insert_double(kvlist, "k4", (double)0.123456789);
    cfl_kvlist_insert_int64(kvlist, "k5", 123456789);
    cfl_kvlist_insert_string(nested, "s2", "nested");
    cfl_kvlist_insert_kvlist(inner, "s1", nested);
    cfl_kvlist_insert_kvlist(kvlist, "k6", inner);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
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

    cra = flb_cfl_ra_create(fmt, FLB_TRUE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, NULL, -1, *vobj, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        goto error;
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

error:
    flb_sds_destroy(str);
    cfl_variant_destroy(vobj);
    flb_cfl_ra_destroy(cra);
}

void cb_translate_tag()
{
    char *fmt;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_variant *vobj = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /*     "{\"k1\": \"string\", \"k2\": true, \"k3\": false," \ */
    /*     " \"k4\": 0.123456789, \"k5\": 123456789,"          \ */
    /*     " \"k6\": {\"s1\": {\"s2\": \"nested\"}}}"; */
    cfl_kvlist_insert_string(kvlist, "k1", "string");
    cfl_kvlist_insert_bool(kvlist, "k2", CFL_TRUE);
    cfl_kvlist_insert_bool(kvlist, "k3", CFL_FALSE);
    cfl_kvlist_insert_double(kvlist, "k4", (double)0.123456789);
    cfl_kvlist_insert_int64(kvlist, "k5", 123456789);
    cfl_kvlist_insert_string(nested, "s2", "nested");
    cfl_kvlist_insert_kvlist(inner, "s1", nested);
    cfl_kvlist_insert_kvlist(kvlist, "k6", inner);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    fmt = "$TAG";
    cra = flb_cfl_ra_create(fmt, FLB_TRUE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, "testapp", 7, *vobj, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }
    TEST_CHECK(flb_sds_len(str) == 7);

    flb_sds_destroy(str);
    cfl_variant_destroy(vobj);
    flb_cfl_ra_destroy(cra);
}

void cb_dots_subkeys()
{
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_variant *vobj = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", \"kubernetes\": {\"annotations\": " */
    /* "{\"fluentbit.io/tag\": \"thetag\"}}}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_kvlist(kvlist, "kubernetes", inner);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes['annotations']['fluentbit.io/tag']");
    fmt_out = "thetag";

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, NULL, -1, *vobj, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    cfl_variant_destroy(vobj);
    flb_cfl_ra_destroy(cra);
}

void cb_array_id()
{
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    fmt_out = "thetag";

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, NULL, -1, *vobj, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    cfl_variant_destroy(vobj);
    flb_cfl_ra_destroy(cra);
}

void cb_get_kv_pair()
{
    int ret;
    char *fmt;
    char *fmt_out;
    struct flb_cfl_record_accessor *cra;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;
    cfl_sds_t start_key;
    cfl_sds_t out_key;
    struct cfl_variant *out_val;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    fmt_out = "thetag";

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    ret = flb_cfl_ra_get_kv_pair(cra, *vobj, &start_key, &out_key, &out_val);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(out_val->type == CFL_VARIANT_STRING);
    TEST_CHECK(cfl_sds_len(out_val->data.as_string) == strlen(fmt_out));
    TEST_CHECK(memcmp(out_val->data.as_string, fmt_out, strlen(fmt_out)) == 0);

    flb_sds_destroy(fmt);
    cfl_variant_destroy(vobj);
    flb_cfl_ra_destroy(cra);
}

static int order_lookup_check(struct cfl_variant *vobj,
                              char *fmt, char *expected_out)
{
    char *fmt_out;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;

    /* Check bool is 'true' */
    fmt = flb_sds_create(fmt);
    if (!TEST_CHECK(fmt != NULL)) {
        exit(EXIT_FAILURE);
    }
    fmt_out = expected_out;

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, NULL, -1, *vobj, NULL);
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
    flb_cfl_ra_destroy(cra);

    return 0;
}

void cb_key_order_lookup()
{
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_variant *vobj = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Sample cfl_object structure */
    /* "{\"key\": \"abc\", \"bool\": false, \"bool\": true, " */
    /*    "\"str\": \"first\", \"str\": \"second\", " */
    /*    "\"num\": 0, \"num\": 1}"; */
    cfl_kvlist_insert_string(kvlist, "key", "abc");
    cfl_kvlist_insert_bool(kvlist, "bool", CFL_FALSE);
    cfl_kvlist_insert_bool(kvlist, "bool", CFL_TRUE);
    cfl_kvlist_insert_string(kvlist, "str", "first");
    cfl_kvlist_insert_string(kvlist, "str", "second");
    cfl_kvlist_insert_int64(kvlist, "num", 0);
    cfl_kvlist_insert_int64(kvlist, "num", 1);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    printf("\n-- record --\n");
    cfl_variant_print(stdout, vobj);

    /* check expected outputs per record accessor pattern */
    order_lookup_check(vobj, "$bool", "true");
    order_lookup_check(vobj, "$str" , "second");
    order_lookup_check(vobj, "$num" , "1");

    cfl_variant_destroy(vobj);
}

void cb_update_key_val()
{
    int ret;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;

    flb_sds_t fmt = NULL;
    flb_sds_t updated_fmt = NULL;
    char *fmt_out_key = "updated_key";
    char *fmt_out_val = "updated_val";

    cfl_sds_t start_key = NULL;
    cfl_sds_t out_key = NULL;
    struct cfl_variant *out_val = NULL;

    cfl_sds_t in_key = NULL;
    struct cfl_variant *in_val = NULL;

    struct flb_cfl_record_accessor *cra = NULL;
    struct flb_cfl_record_accessor *updated_cra = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* create key object to overwrite */
    in_key = cfl_sds_create("updated_key");
    /* create value object to overwrite */
    in_val = cfl_variant_create_from_string("updated_val");
    if (in_val == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$kubernetes[2]['annotations']['updated_key']");
    updated_cra = flb_cfl_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_cfl_ra_update_kv_pair(cra, *vobj, in_key, in_val);
    TEST_CHECK(ret == 0);

    ret = flb_cfl_ra_get_kv_pair(updated_cra, *vobj, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        cfl_variant_print(stdout, vobj);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(cfl_sds_len(out_key) == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key, fmt_out_key, strlen(fmt_out_key)) == 0);

    /* Check updated val */
    TEST_CHECK(out_val->type == CFL_VARIANT_STRING);
    TEST_CHECK(cfl_sds_len(out_val->data.as_string) == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->data.as_string, fmt_out_val, strlen(fmt_out_val)) == 0);

    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(updated_cra);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
    cfl_sds_destroy(in_key);
}

void cb_update_val()
{
    int ret;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;

    flb_sds_t fmt = NULL;
    flb_sds_t updated_fmt = NULL;
    char *fmt_out_val = "updated_val";

    cfl_sds_t start_key = NULL;
    cfl_sds_t out_key = NULL;
    struct cfl_variant *out_val = NULL;

    struct cfl_variant *in_val = NULL;

    struct flb_cfl_record_accessor *cra = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* create value object to overwrite */
    in_val = cfl_variant_create_from_string("updated_val");
    if (in_val == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_cfl_ra_update_kv_pair(cra, *vobj, NULL, in_val);
    TEST_CHECK(ret == 0);

    ret = flb_cfl_ra_get_kv_pair(cra, *vobj, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        cfl_variant_print(stdout, vobj);
        exit(EXIT_FAILURE);
    }

    /* Check updated val */
    TEST_CHECK(out_val->type == CFL_VARIANT_STRING);
    TEST_CHECK(cfl_sds_len(out_val->data.as_string) == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->data.as_string, fmt_out_val, strlen(fmt_out_val)) == 0);

    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
}

void cb_update_key()
{
    int ret;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;

    flb_sds_t fmt = NULL;
    flb_sds_t updated_fmt = NULL;
    char *fmt_out_key = "updated_key";

    cfl_sds_t start_key = NULL;
    cfl_sds_t out_key = NULL;
    struct cfl_variant *out_val = NULL;

    cfl_sds_t in_key = NULL;

    struct flb_cfl_record_accessor *cra = NULL;
    struct flb_cfl_record_accessor *updated_cra = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* create key object to overwrite */
    in_key = cfl_sds_create("updated_key");

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['fluentbit.io/tag']");
    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$kubernetes[2]['annotations']['updated_key']");
    updated_cra = flb_cfl_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_cfl_ra_update_kv_pair(cra, *vobj, in_key, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_cfl_ra_get_kv_pair(updated_cra, *vobj, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        cfl_variant_print(stdout, vobj);
        goto error;
    }

    /* Check updated key */
    TEST_CHECK(cfl_sds_len(out_key) == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key, fmt_out_key, strlen(fmt_out_key)) == 0);

error:
    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(cra);
    flb_cfl_ra_destroy(updated_cra);
    cfl_variant_destroy(vobj);
    cfl_sds_destroy(in_key);
}

void cb_update_root_key()
{
    int ret;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;

    flb_sds_t fmt = NULL;
    flb_sds_t updated_fmt = NULL;
    char *fmt_out_key = "updated_key";

    cfl_sds_t start_key = NULL;
    cfl_sds_t out_key = NULL;
    struct cfl_variant *out_val = NULL;

    cfl_sds_t in_key = NULL;
    struct cfl_variant *in_val = NULL;

    struct flb_cfl_record_accessor *cra = NULL;
    struct flb_cfl_record_accessor *updated_cra = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* create key object to overwrite */
    in_key = flb_sds_create("updated_key");

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$key1");
    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$updated_key");
    updated_cra = flb_cfl_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_cfl_ra_update_kv_pair(cra, *vobj, in_key, in_val);
    TEST_CHECK(ret == 0);

    ret = flb_cfl_ra_get_kv_pair(updated_cra, *vobj, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        cfl_variant_print(stdout, vobj);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(cfl_sds_len(out_key) == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key, fmt_out_key, strlen(fmt_out_key)) == 0);

    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(updated_cra);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
    cfl_sds_destroy(in_key);
}

void cb_update_root_key_val()
{
    int ret;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;

    flb_sds_t fmt = NULL;
    flb_sds_t updated_fmt = NULL;
    char *fmt_out_key = "updated_key";
    char *fmt_out_val = "updated_val";

    cfl_sds_t start_key = NULL;
    cfl_sds_t out_key = NULL;
    struct cfl_variant *out_val = NULL;

    cfl_sds_t in_key = NULL;
    struct cfl_variant *in_val = NULL;

    struct flb_cfl_record_accessor *cra = NULL;
    struct flb_cfl_record_accessor *updated_cra = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* create key object to overwrite */
    in_key = flb_sds_create("updated_key");
    /* create value object to overwrite */
    in_val = cfl_variant_create_from_string("updated_val");
    if (in_val == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$key1");
    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$updated_key");
    updated_cra = flb_cfl_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Update only value */
    ret = flb_cfl_ra_update_kv_pair(cra, *vobj, in_key, in_val);
    TEST_CHECK(ret == 0);

    ret = flb_cfl_ra_get_kv_pair(updated_cra, *vobj, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        cfl_variant_print(stdout, vobj);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(cfl_sds_len(out_key) == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key, fmt_out_key, strlen(fmt_out_key)) == 0);

    /* Check updated val */
    TEST_CHECK(out_val->type == CFL_VARIANT_STRING);
    TEST_CHECK(cfl_sds_len(out_val->data.as_string) == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->data.as_string, fmt_out_val, strlen(fmt_out_val)) == 0);

    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(updated_cra);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
    cfl_sds_destroy(in_key);
}

void cb_ra_translate_check()
{
    char *fmt;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_variant *vobj = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"root.with/symbols\": \"something\"}"; */
    cfl_kvlist_insert_string(kvlist, "root.with/symbols", "something");

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    int check_translation = FLB_TRUE;

    /* Formatter */
    fmt = flb_sds_create("$root");
    if (!TEST_CHECK(fmt != NULL)) {
        exit(EXIT_FAILURE);
    }

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation - with check enabled */
    str = flb_cfl_ra_translate_check(cra, NULL, -1, *vobj, NULL, check_translation);
    /* since translation fails and check is enabled, it returns NULL */
    TEST_CHECK(str == NULL);
    if (str) {
        exit(EXIT_FAILURE);
    }

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
}

struct char_list_cobj_ra_str{
    char **strs;
    char *expect;
};

void cb_ra_create_str_from_list()
{
    char *case1[] = {"a", NULL};
    char *case2[] = {"aa", "bb", "cc", NULL};

    struct char_list_cobj_ra_str testcases[] = {
        { .strs = &case1[0], .expect = "$a"},
        { .strs = &case2[0], .expect = "$aa['bb']['cc']"},
    };
    size_t case_size = sizeof(testcases)/sizeof(struct char_list_cobj_ra_str);
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

        ret_str = flb_cfl_ra_create_str_from_list(list);
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
    ret_str = flb_cfl_ra_create_str_from_list(list);
    if (!TEST_CHECK(ret_str == NULL)) {
        TEST_MSG("flb_ra_create_str_from should be failed");
        flb_sds_list_destroy(list);
        exit(EXIT_FAILURE);
    }
    flb_sds_list_destroy(list);
}

void cb_add_key_val()
{
    int ret;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;

    flb_sds_t fmt = NULL;
    flb_sds_t updated_fmt = NULL;
    char *fmt_out_key = "add_key";
    char *fmt_out_val = "add_val";

    cfl_sds_t start_key = NULL;
    cfl_sds_t out_key = NULL;
    struct cfl_variant *out_val = NULL;

    struct cfl_variant *in_val = NULL;

    struct flb_cfl_record_accessor *cra = NULL;
    struct flb_cfl_record_accessor *updated_cra = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* create value object to overwrite */
    in_val = cfl_variant_create_from_string("add_val");
    if (in_val == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$kubernetes[2]['annotations']['add_key']");
    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$kubernetes[2]['annotations']['add_key']");
    updated_cra = flb_cfl_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Add key/value */
    ret = flb_cfl_ra_append_kv_pair(cra, *vobj, in_val);
    TEST_CHECK(ret == 0);

    ret = flb_cfl_ra_get_kv_pair(updated_cra, *vobj, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        cfl_variant_print(stdout, vobj);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(cfl_sds_len(out_key) == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key, fmt_out_key, strlen(fmt_out_key)) == 0);

    /* Check updated val */
    TEST_CHECK(out_val->type == CFL_VARIANT_STRING);
    TEST_CHECK(cfl_sds_len(out_val->data.as_string) == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->data.as_string, fmt_out_val, strlen(fmt_out_val)) == 0);

    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(updated_cra);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
}

void cb_add_root_key_val()
{
    int ret;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *nested = NULL;
    struct cfl_kvlist *inner = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;

    flb_sds_t fmt = NULL;
    flb_sds_t updated_fmt = NULL;
    char *fmt_out_key = "add_key";
    char *fmt_out_val = "add_val";

    cfl_sds_t start_key = NULL;
    cfl_sds_t out_key = NULL;
    struct cfl_variant *out_val = NULL;

    struct cfl_variant *in_val = NULL;

    struct flb_cfl_record_accessor *cra = NULL;
    struct flb_cfl_record_accessor *updated_cra = NULL;

    /* Sample kvlist */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }
    inner = cfl_kvlist_create();
    if (inner == NULL) {
        exit(EXIT_FAILURE);
    }
    nested = cfl_kvlist_create();
    if (nested == NULL) {
        exit(EXIT_FAILURE);
    }
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    /* create value object to overwrite */
    in_val = cfl_variant_create_from_string("add_val");
    if (in_val == NULL) {
        exit(EXIT_FAILURE);
    }

    /* /\* Sample message structure *\/ */
    /* "{\"key1\": \"something\", " */
    /* "\"kubernetes\": " */
    /* "   [true, " */
    /* "    false, " */
    /* "    {\"a\": false, " */
    /* "     \"annotations\": { " */
    /* "                       \"fluentbit.io/tag\": \"thetag\"" */
    /* "}}]}"; */
    cfl_kvlist_insert_string(kvlist, "key1", "something");
    cfl_kvlist_insert_string(nested, "fluentbit.io/tag", "thetag");
    cfl_kvlist_insert_kvlist(inner, "annotations", nested);
    cfl_kvlist_insert_bool(inner, "a", CFL_FALSE);
    cfl_array_append_bool(array, CFL_TRUE);
    cfl_array_append_bool(array, CFL_FALSE);
    cfl_array_append_kvlist(array, inner);
    cfl_kvlist_insert_array(kvlist, "kubernetes", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    fmt = flb_sds_create("$add_key");
    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    if(!TEST_CHECK(cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Formatter */
    updated_fmt = flb_sds_create("$add_key");
    updated_cra = flb_cfl_ra_create(updated_fmt, FLB_FALSE);
    if(!TEST_CHECK(updated_cra != NULL)) {
        exit(EXIT_FAILURE);
    }

    /* Add key/value */
    ret = flb_cfl_ra_append_kv_pair(cra, *vobj, in_val);
    TEST_CHECK(ret == 0);

    ret = flb_cfl_ra_get_kv_pair(updated_cra, *vobj, &start_key, &out_key, &out_val);
    if (!TEST_CHECK(ret == 0)) {
        printf("print out_result\n");
        cfl_variant_print(stdout, vobj);
        exit(EXIT_FAILURE);
    }

    /* Check updated key */
    TEST_CHECK(cfl_sds_len(out_key) == strlen(fmt_out_key));
    TEST_CHECK(memcmp(out_key, fmt_out_key, strlen(fmt_out_key)) == 0);

    /* Check updated val */
    TEST_CHECK(out_val->type == CFL_VARIANT_STRING);
    TEST_CHECK(cfl_sds_len(out_val->data.as_string) == strlen(fmt_out_val));
    TEST_CHECK(memcmp(out_val->data.as_string, fmt_out_val, strlen(fmt_out_val)) == 0);

    flb_sds_destroy(updated_fmt);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(updated_cra);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
}

void cb_direct_array_access()
{
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_array *array = NULL;
    struct cfl_variant *vobj = NULL;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;

    /* Sample kvlist with direct array */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Create array with elements a, b, c */
    array = cfl_array_create(3);
    if (array == NULL) {
        exit(EXIT_FAILURE);
    }

    cfl_array_append_string(array, "a");
    cfl_array_append_string(array, "b");
    cfl_array_append_string(array, "c");

    /* Add array to kvlist */
    cfl_kvlist_insert_array(kvlist, "array", array);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter for direct array access */
    fmt = flb_sds_create("$array[0]");
    fmt_out = "a";

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, NULL, -1, *vobj, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== direct array access test ==\n== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
}

void cb_nested_array_access()
{
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_array *matrix = NULL;
    struct cfl_array *row1 = NULL;
    struct cfl_array *row2 = NULL;
    struct cfl_array *row3 = NULL;
    struct cfl_variant *vobj = NULL;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;

    /* Sample kvlist with nested arrays */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Create 3x3 matrix */
    matrix = cfl_array_create(3);
    row1 = cfl_array_create(3);
    row2 = cfl_array_create(3);
    row3 = cfl_array_create(3);

    if (matrix == NULL || row1 == NULL || row2 == NULL || row3 == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Fill the rows */
    cfl_array_append_int64(row1, 1);
    cfl_array_append_int64(row1, 2);
    cfl_array_append_int64(row1, 3);

    cfl_array_append_int64(row2, 4);
    cfl_array_append_int64(row2, 5);
    cfl_array_append_int64(row2, 6);

    cfl_array_append_int64(row3, 7);
    cfl_array_append_int64(row3, 8);
    cfl_array_append_int64(row3, 9);

    /* Add rows to matrix */
    cfl_array_append_array(matrix, row1);
    cfl_array_append_array(matrix, row2);
    cfl_array_append_array(matrix, row3);

    /* Add matrix to kvlist */
    cfl_kvlist_insert_array(kvlist, "matrix", matrix);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter for nested array access */
    fmt = flb_sds_create("$matrix[1][2]");  /* Should access the value 6 */
    fmt_out = "6";

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, NULL, -1, *vobj, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== nested array access test ==\n== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
}

void cb_mixed_array_map_access()
{
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_kvlist *person1 = NULL;
    struct cfl_kvlist *person2 = NULL;
    struct cfl_array *records = NULL;
    struct cfl_variant *vobj = NULL;
    char *fmt;
    char *fmt_out;
    flb_sds_t str;
    struct flb_cfl_record_accessor *cra;

    /* Sample kvlist with array containing maps */
    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Create records array */
    records = cfl_array_create(2);
    if (records == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Create person records */
    person1 = cfl_kvlist_create();
    person2 = cfl_kvlist_create();
    if (person1 == NULL || person2 == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Add properties to persons */
    cfl_kvlist_insert_string(person1, "name", "John");
    cfl_kvlist_insert_int64(person1, "age", 30);

    cfl_kvlist_insert_string(person2, "name", "Jane");
    cfl_kvlist_insert_int64(person2, "age", 25);

    /* Add persons to records */
    cfl_array_append_kvlist(records, person1);
    cfl_array_append_kvlist(records, person2);

    /* Add records to kvlist */
    cfl_kvlist_insert_array(kvlist, "records", records);

    /* Set up CFL variant(vobj) */
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Formatter for mixed array+map access */
    fmt = flb_sds_create("$records[1]['name']");  /* Should access "Jane" */
    fmt_out = "Jane";

    cra = flb_cfl_ra_create(fmt, FLB_FALSE);
    TEST_CHECK(cra != NULL);
    if (!cra) {
        exit(EXIT_FAILURE);
    }

    /* Do translation */
    str = flb_cfl_ra_translate(cra, NULL, -1, *vobj, NULL);
    TEST_CHECK(str != NULL);
    if (!str) {
        exit(EXIT_FAILURE);
    }

    TEST_CHECK(flb_sds_len(str) == strlen(fmt_out));
    TEST_CHECK(memcmp(str, fmt_out, strlen(fmt_out)) == 0);
    printf("== mixed array+map access test ==\n== input ==\n%s\n== output ==\n%s\n", str, fmt_out);

    flb_sds_destroy(str);
    flb_sds_destroy(fmt);
    flb_cfl_ra_destroy(cra);
    cfl_variant_destroy(vobj);
}

TEST_LIST = {
    { "keys"                   , cb_keys},
    { "dash_key"               , cb_dash_key},
    { "translate"              , cb_translate},
    { "translate_tag"          , cb_translate_tag},
    { "dots_subkeys"           , cb_dots_subkeys},
    { "array_id"               , cb_array_id},
    { "get_kv_pair"            , cb_get_kv_pair},
    { "key_order_lookup"       , cb_key_order_lookup},
    { "update_key_val"         , cb_update_key_val},
    { "update_val"             , cb_update_val},
    { "update_key"             , cb_update_key},
    { "update_root_key_val"    , cb_update_root_key_val},
    { "update_root_key"        , cb_update_root_key},
    { "add_key_val"            , cb_add_key_val},
    { "add_root_key_val"       , cb_add_root_key_val},
    { "flb_ra_translate_check" , cb_ra_translate_check},
    { "ra_create_str_from_list", cb_ra_create_str_from_list},
    { "direct_array_access"    , cb_direct_array_access},
    { "nested_array_access"    , cb_nested_array_access},
    { "mixed_array_map_access" , cb_mixed_array_map_access},
    { NULL }
};