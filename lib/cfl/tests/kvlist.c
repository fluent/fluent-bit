/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022-2024 The CFL Authors
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

#include <cfl/cfl.h>

#include <float.h>
#include <math.h>

#include "cfl_tests_internal.h"

static int compare(FILE *fp, char *expect)
{
    size_t len;
    size_t ret_fp;
    char buf[256] = {0};

    len = strlen(expect);

    if (fseek(fp, 0, SEEK_SET) != 0) {
        return -1;
    }

    ret_fp = fread(&buf[0], 1, sizeof(buf) - 1, fp);
    if (ret_fp == 0 && ferror(fp)) {
        return -1;
    }

    if (strlen(buf) != len) {
        return -1;
    }

    return strncmp(expect, &buf[0], len);
}

static void create_destroy()
{
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }
    cfl_kvlist_destroy(list);
}

static void count()
{
    struct cfl_kvlist *list = NULL;
    int i;
    int count = 12;
    int ret;
    char buf[128] = {0};

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    for (i=0; i<count; i++) {
        memset(&buf[0], 0, sizeof(buf));
        snprintf(&buf[0], sizeof(buf), "%d", i);
        ret = cfl_kvlist_insert_int64(list, &buf[0], i);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%d: cfl_kvlist_insert_int64 failed", i);
            cfl_kvlist_destroy(list);
            return;
        }
    }

    ret = cfl_kvlist_count(list);
    if (!TEST_CHECK(ret == count)) {
        TEST_MSG("cfl_list_size failed. got=%d expect=%d", i, count);
    }

    cfl_kvlist_destroy(list);
}

static void fetch()
{
    int ret;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_int64(list, "key", 128);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_int64 failed");
        cfl_kvlist_destroy(list);
        return;
    }

    /* invalid key name 'k' */
    var = cfl_kvlist_fetch(list, "k");
    if (!TEST_CHECK(var == NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned invalid pointer");
        cfl_kvlist_destroy(list);
        return;
    }

    /* invalid key name 'key_is_invalid' */
    var = cfl_kvlist_fetch(list, "key_is_invalid");
    if (!TEST_CHECK(var == NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned invalid pointer");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == CFL_VARIANT_INT)) {
        TEST_MSG("variant type is not int. ret=%d", var->type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_int64 == 128)) {
        TEST_MSG("variant value error.got=%"PRId64" expect=128", var->data.as_int64);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void fetch_s()
{
    int ret;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_int64(list, "key", 128);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_int64 failed");
        cfl_kvlist_destroy(list);
        return;
    }

    /* invalid key name 'k' */
    var = cfl_kvlist_fetch(list, "k");
    if (!TEST_CHECK(var == NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned invalid pointer");
        cfl_kvlist_destroy(list);
        return;
    }

    /* invalid key name 'key_is_invalid' */
    var = cfl_kvlist_fetch(list, "key_is_invalid");
    if (!TEST_CHECK(var == NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned invalid pointer");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key_is_long_name", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == CFL_VARIANT_INT)) {
        TEST_MSG("variant type is not int. ret=%d", var->type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_int64 == 128)) {
        TEST_MSG("variant value error.got=%"PRId64" expect=128", var->data.as_int64);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_string()
{
    int ret;
    int expect_type = CFL_VARIANT_STRING;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_string(list, "key", "value");
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_string failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(strncmp("value", var->data.as_string,5) == 0)) {
        TEST_MSG("variant value error.got=%s expect=value", var->data.as_string);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_bytes()
{
    int ret;
    int expect_type = CFL_VARIANT_BYTES;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_bytes(list, "key", "value", 5, CFL_TRUE);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_bytes failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(memcmp("value", var->data.as_bytes,5) == 0)) {
        TEST_MSG("variant value error.got=%s expect=value", var->data.as_bytes);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_reference()
{
    int ret;
    int expect_type = CFL_VARIANT_REFERENCE;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_reference(list, "key", &expect_type);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_reference failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_reference == &expect_type)) {
        TEST_MSG("variant value error.got=%p expect=%p", var->data.as_reference, &expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_bool()
{
    int ret;
    int expect_type = CFL_VARIANT_BOOL;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_bool(list, "key", CFL_TRUE);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_bool failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_bool == CFL_TRUE)) {
        TEST_MSG("variant value error.got=%d expect=%d", var->data.as_bool, CFL_TRUE);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_int64()
{
    int ret;
    int expect_type = CFL_VARIANT_INT;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_int64(list, "key", -123456);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_int64 failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_int64 == -123456)) {
        TEST_MSG("variant value error.got=%"PRId64" expect=-123456", var->data.as_int64);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_uint64()
{
    int ret;
    int expect_type = CFL_VARIANT_UINT;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_uint64(list, "key", 123456);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_uint64 failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_uint64 == 123456)) {
        TEST_MSG("variant value error.got=%"PRIu64" expect=123456", var->data.as_uint64);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_double()
{
    int ret;
    double input = 123456.789;
    int expect_type = CFL_VARIANT_DOUBLE;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_double(list, "key", input);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_double failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(fabs(var->data.as_double - input) < DBL_EPSILON)) {
        TEST_MSG("variant value error.got=%lf expect=%lf", var->data.as_double, input);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_new_array()
{
    int ret;
    int expect_type = CFL_VARIANT_ARRAY;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_new_array(list, "key", 123);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_new_array failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_array->slot_count == 123)) {
        TEST_MSG("variant value error.got=%d expect=123", var->data.as_array->slot_count);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_empty_array()
{
    int ret;
    int expect_type = CFL_VARIANT_ARRAY;
    struct cfl_array *input = NULL;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    input = cfl_array_create(123);
    if (!TEST_CHECK(input != NULL)) {
        TEST_MSG("cfl_array_create failed");
        cfl_kvlist_destroy(list);
        return;
    }

    ret = cfl_kvlist_insert_array(list, "key", input);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_array failed");
        cfl_kvlist_destroy(list);
        cfl_array_destroy(input);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_array->slot_count == 123)) {
        TEST_MSG("variant value error.got=%d expect=123", var->data.as_array->slot_count);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_empty_kvlist()
{
    int ret;
    int expect_type = CFL_VARIANT_KVLIST;
    struct cfl_kvlist *input = NULL;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    input = cfl_kvlist_create();
    if (!TEST_CHECK(input != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        cfl_kvlist_destroy(list);
        return;
    }

    ret = cfl_kvlist_insert_kvlist(list, "key", input);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_kvlist failed");
        cfl_kvlist_destroy(list);
        cfl_kvlist_destroy(input);
        return;
    }

    var = cfl_kvlist_fetch(list, "key");
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_string_s()
{
    int ret;
    int expect_type = CFL_VARIANT_STRING;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_string_s(list, "key!!!!!", 3, "value", 5, CFL_TRUE);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_string_s failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key?????", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(strncmp("value", var->data.as_string,5) == 0)) {
        TEST_MSG("variant value error.got=%s expect=value", var->data.as_string);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_bytes_s()
{
    int ret;
    int expect_type = CFL_VARIANT_BYTES;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_bytes_s(list, "key!!!!!", 3, "value", 5, CFL_FALSE);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_bytes_s failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key??????????????", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(memcmp("value", var->data.as_bytes,5) == 0)) {
        TEST_MSG("variant value error.got=%s expect=value", var->data.as_bytes);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_reference_s()
{
    int ret;
    int expect_type = CFL_VARIANT_REFERENCE;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_reference_s(list, "key!!!", 3, &expect_type);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_reference_s failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key????", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_reference == &expect_type)) {
        TEST_MSG("variant value error.got=%p expect=%p", var->data.as_reference, &expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_bool_s()
{
    int ret;
    int expect_type = CFL_VARIANT_BOOL;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_bool_s(list, "key!!!!", 3, CFL_TRUE);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_bool_s failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key???", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_bool == CFL_TRUE)) {
        TEST_MSG("variant value error.got=%d expect=%d", var->data.as_bool, CFL_TRUE);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_int64_s()
{
    int ret;
    int expect_type = CFL_VARIANT_INT;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_int64_s(list, "key!!!!", 3, -123456);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_int64_s failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key??", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_int64 == -123456)) {
        TEST_MSG("variant value error.got=%"PRId64" expect=-123456", var->data.as_int64);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_uint64_s()
{
    int ret;
    int expect_type = CFL_VARIANT_UINT;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_uint64_s(list, "key???", 3, 123456);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_uint64_s failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key!!!", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_uint64 == 123456)) {
        TEST_MSG("variant value error.got=%"PRIu64" expect=123456", var->data.as_uint64);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_double_s()
{
    int ret;
    double input = 123456.789;
    int expect_type = CFL_VARIANT_DOUBLE;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_double_s(list, "key????", 3, input);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_double_s failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key!!!", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(fabs(var->data.as_double - input) < DBL_EPSILON)) {
        TEST_MSG("variant value error.got=%lf expect=%lf", var->data.as_double, input);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_new_array_s()
{
    int ret;
    int expect_type = CFL_VARIANT_ARRAY;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    ret = cfl_kvlist_insert_new_array_s(list, "key???", 3, 123);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_new_array_s failed");
        cfl_kvlist_destroy(list);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key!!!!!", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_array->slot_count == 123)) {
        TEST_MSG("variant value error.got=%d expect=123", var->data.as_array->slot_count);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_empty_array_s()
{
    int ret;
    int expect_type = CFL_VARIANT_ARRAY;
    struct cfl_array *input = NULL;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    input = cfl_array_create(123);
    if (!TEST_CHECK(input != NULL)) {
        TEST_MSG("cfl_array_create failed");
        cfl_kvlist_destroy(list);
        return;
    }

    ret = cfl_kvlist_insert_array_s(list, "key!!!", 3, input);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_array_s failed");
        cfl_kvlist_destroy(list);
        cfl_array_destroy(input);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key??????", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->data.as_array->slot_count == 123)) {
        TEST_MSG("variant value error.got=%d expect=123", var->data.as_array->slot_count);
        cfl_kvlist_destroy(list);
        return;
    }

    cfl_kvlist_destroy(list);
}

static void insert_empty_kvlist_s()
{
    int ret;
    int expect_type = CFL_VARIANT_KVLIST;
    struct cfl_kvlist *input = NULL;
    struct cfl_variant *var = NULL;
    struct cfl_kvlist *list = NULL;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        return;
    }

    input = cfl_kvlist_create();
    if (!TEST_CHECK(input != NULL)) {
        TEST_MSG("cfl_kvlist_create failed");
        cfl_kvlist_destroy(list);
        return;
    }

    ret = cfl_kvlist_insert_kvlist_s(list, "key????", 3, input);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cfl_kvlist_insert_kvlist_s failed");
        cfl_kvlist_destroy(list);
        cfl_kvlist_destroy(input);
        return;
    }

    var = cfl_kvlist_fetch_s(list, "key!", 3);
    if (!TEST_CHECK(var != NULL)) {
        TEST_MSG("cfl_kvlist_fetch returned NULL");
        cfl_kvlist_destroy(list);
        return;
    }

    if (!TEST_CHECK(var->type == expect_type)) {
        TEST_MSG("variant type error. got=%d expect=%d", var->type, expect_type);
        cfl_kvlist_destroy(list);
        return;
    }
    cfl_kvlist_destroy(list);
}

static void test_basics()
{
    int ret;
    struct cfl_kvlist *list;
    struct cfl_kvlist *list2;
    struct cfl_array *array;
    struct cfl_variant *variant;

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    /*
     * Inserts
     */
    ret = cfl_kvlist_insert_string(list, "key1", "value1");
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_bytes(list, "key2", "value2", 6, CFL_TRUE);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_reference(list, "key3", (void *) 0xdeadbeef);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_bool(list, "key4", 1);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_int64(list, "key5", 1234567890);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_uint64(list, "key6", 1234567890);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_double(list, "key7", 1234567890.1234567890);
    TEST_CHECK(ret == 0);

    array = cfl_array_create(2);
    TEST_CHECK(array != NULL);

    ret = cfl_kvlist_insert_array(list, "key8", array);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_new_array(list, "key9", 0);
    TEST_CHECK(ret == 0);

    list2 = cfl_kvlist_create();
    ret = cfl_kvlist_insert_kvlist(list, "key10", list2);
    TEST_CHECK(ret == 0);

    variant = cfl_variant_create_from_string("value1");
    TEST_CHECK(variant != NULL);

    ret = cfl_kvlist_insert(list, "key11", variant);
    TEST_CHECK(ret == 0);

    /* Count elements */
    ret = cfl_kvlist_count(list);
    TEST_CHECK(ret == 11);

    /* Fetch */
    variant = cfl_kvlist_fetch(list, "key8");
    TEST_CHECK(variant != NULL);
    TEST_CHECK(variant->type == CFL_VARIANT_ARRAY);

    /* Check if entry exists */
    ret = cfl_kvlist_contains(list, "key7");
    TEST_CHECK(ret == 1);

    ret = cfl_kvlist_contains(list, "key12");
    TEST_CHECK(ret == 0);

    /* Remove entry */
    ret = cfl_kvlist_remove(list, "key5");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_count(list);
    TEST_CHECK(ret == 10);

    /* Remove all entries one by one (for memory sanitizer) */
    ret = cfl_kvlist_remove(list, "key1");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key2");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key3");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key4");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key6");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key7");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key8");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key9");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key10");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "key11");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_count(list);
    TEST_CHECK(ret == 0);

    /* failure scenarios */
    ret = cfl_kvlist_insert_string(list, NULL, "value1");
    TEST_CHECK(ret < 0);

    cfl_kvlist_destroy(list);
}

static void null_inputs()
{
    int ret;
    struct cfl_kvlist *list;
    struct cfl_variant *variant;

    cfl_kvlist_destroy(NULL);

    ret = cfl_kvlist_count(NULL);
    TEST_CHECK(ret == 0);

    variant = cfl_kvlist_fetch(NULL, "key");
    TEST_CHECK(variant == NULL);

    variant = cfl_kvlist_fetch_s(NULL, "key", 3);
    TEST_CHECK(variant == NULL);

    ret = cfl_kvlist_contains(NULL, "key");
    TEST_CHECK(ret == CFL_FALSE);

    ret = cfl_kvlist_remove(NULL, "key");
    TEST_CHECK(ret == CFL_FALSE);

    ret = cfl_kvlist_insert_string(NULL, "key", "value");
    TEST_CHECK(ret == -1);

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    ret = cfl_kvlist_insert_string(list, NULL, "value");
    TEST_CHECK(ret == -1);

    ret = cfl_kvlist_insert_bytes(list, "key", NULL, 1, CFL_TRUE);
    TEST_CHECK(ret == -1);

    ret = cfl_kvlist_insert_array(list, "key", NULL);
    TEST_CHECK(ret == -1);

    ret = cfl_kvlist_insert_kvlist(list, "key", NULL);
    TEST_CHECK(ret == -1);

    ret = cfl_kvlist_insert(list, "key", NULL);
    TEST_CHECK(ret == -1);

    variant = cfl_kvlist_fetch(list, NULL);
    TEST_CHECK(variant == NULL);

    cfl_kvpair_destroy(NULL);

    variant = cfl_kvpair_take_value(NULL);
    TEST_CHECK(variant == NULL);

    cfl_kvlist_destroy(list);
}

static void print_escaped_keys()
{
    int ret;
    FILE *fp;
    struct cfl_kvlist *list;

    list = cfl_kvlist_create();
    if (!TEST_CHECK(list != NULL)) {
        return;
    }

    ret = cfl_kvlist_insert_string(list, "a\"b\n", "v\n");
    if (!TEST_CHECK(ret == 0)) {
        cfl_kvlist_destroy(list);
        return;
    }

    fp = tmpfile();
    if (!TEST_CHECK(fp != NULL)) {
        cfl_kvlist_destroy(list);
        return;
    }

    ret = cfl_kvlist_print(fp, list);
    if (!TEST_CHECK(ret > 0)) {
        fclose(fp);
        cfl_kvlist_destroy(list);
        return;
    }

    ret = compare(fp, "{\"a\\\"b\\n\":\"v\\n\"}");
    TEST_CHECK(ret == 0);

    fclose(fp);
    cfl_kvlist_destroy(list);
}

static void embedded_nul_keys_do_not_match_short_name()
{
    int ret;
    char key[] = {'a', 'd', 'm', 'i', 'n', '\0', 'x'};
    struct cfl_kvlist *list;
    struct cfl_variant *variant;

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    ret = cfl_kvlist_insert_string(list, "admin", "plain");
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_string_s(list, key, sizeof(key),
                                     "hidden", 6, CFL_FALSE);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_contains(list, "admin");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove(list, "admin");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_count(list);
    TEST_CHECK(ret == 1);

    variant = cfl_kvlist_fetch_s(list, key, sizeof(key));
    TEST_CHECK(variant != NULL);

    ret = cfl_kvlist_contains(list, "admin");
    TEST_CHECK(ret == CFL_FALSE);

    ret = cfl_kvlist_remove(list, "admin");
    TEST_CHECK(ret == CFL_FALSE);

    ret = cfl_kvlist_count(list);
    TEST_CHECK(ret == 1);

    cfl_kvlist_destroy(list);
}

static void case_sensitive_operations()
{
    int ret;
    char upper_key[] = {'U', 's', 'e', 'r'};
    char lower_key[] = {'u', 's', 'e', 'r'};
    char nul_key[] = {'k', '\0', 'A'};
    char different_nul_key[] = {'K', '\0', 'B'};
    struct cfl_kvlist *list;
    struct cfl_variant *variant;

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    ret = cfl_kvlist_insert_int64(list, "User", 1);
    TEST_CHECK(ret == 0);
    ret = cfl_kvlist_insert_int64(list, "user", 2);
    TEST_CHECK(ret == 0);
    ret = cfl_kvlist_insert_int64_s(list, nul_key, sizeof(nul_key), 3);
    TEST_CHECK(ret == 0);

    variant = cfl_kvlist_fetch_s_ex(list, upper_key, sizeof(upper_key),
                                    CFL_KVLIST_MATCH_CASE_SENSITIVE);
    TEST_CHECK(variant != NULL);
    TEST_CHECK(variant->data.as_int64 == 1);

    variant = cfl_kvlist_fetch_case_s(list, lower_key, sizeof(lower_key));
    TEST_CHECK(variant != NULL);
    TEST_CHECK(variant->data.as_int64 == 2);

    variant = cfl_kvlist_fetch_ex(list, "USER",
                                  CFL_KVLIST_MATCH_CASE_SENSITIVE);
    TEST_CHECK(variant == NULL);
    variant = cfl_kvlist_fetch(list, "USER");
    TEST_CHECK(variant != NULL);

    ret = cfl_kvlist_contains_ex(list, "USER",
                                 CFL_KVLIST_MATCH_CASE_SENSITIVE);
    TEST_CHECK(ret == CFL_FALSE);
    ret = cfl_kvlist_contains(list, "USER");
    TEST_CHECK(ret == CFL_TRUE);

    ret = cfl_kvlist_remove_ex(list, "User",
                               CFL_KVLIST_MATCH_CASE_SENSITIVE);
    TEST_CHECK(ret == CFL_TRUE);
    TEST_CHECK(cfl_kvlist_count(list) == 2);
    TEST_CHECK(cfl_kvlist_fetch_ex(list, "User",
                                  CFL_KVLIST_MATCH_CASE_SENSITIVE) == NULL);
    variant = cfl_kvlist_fetch_ex(list, "user",
                                  CFL_KVLIST_MATCH_CASE_SENSITIVE);
    TEST_CHECK(variant != NULL);
    TEST_CHECK(variant->data.as_int64 == 2);

    variant = cfl_kvlist_fetch_s_ex(list, different_nul_key,
                                    sizeof(different_nul_key),
                                    CFL_KVLIST_MATCH_CASE_INSENSITIVE);
    TEST_CHECK(variant == NULL);
    variant = cfl_kvlist_fetch_s_ex(list, nul_key, sizeof(nul_key),
                                    CFL_KVLIST_MATCH_CASE_INSENSITIVE);
    TEST_CHECK(variant != NULL);
    TEST_CHECK(variant->data.as_int64 == 3);

    variant = cfl_kvlist_fetch_ex(list, "user",
                                  (enum cfl_kvlist_match_mode) 99);
    TEST_CHECK(variant == NULL);
    ret = cfl_kvlist_contains_ex(list, "user",
                                 (enum cfl_kvlist_match_mode) 99);
    TEST_CHECK(ret == CFL_FALSE);
    ret = cfl_kvlist_remove_ex(list, "user",
                               (enum cfl_kvlist_match_mode) 99);
    TEST_CHECK(ret == CFL_FALSE);
    TEST_CHECK(cfl_kvlist_count(list) == 2);

    cfl_kvlist_destroy(list);
}

static void case_sensitive_arena_operations()
{
    int ret;
    struct cfl_arena *arena;
    struct cfl_kvlist *list;
    struct cfl_variant *variant;

    arena = cfl_arena_create(256);
    TEST_CHECK(arena != NULL);
    list = cfl_kvlist_create_in(arena);
    TEST_CHECK(list != NULL);

    ret = cfl_kvlist_insert_string(list, "TraceId", "upper");
    TEST_CHECK(ret == 0);
    ret = cfl_kvlist_insert_string(list, "traceid", "lower");
    TEST_CHECK(ret == 0);

    variant = cfl_kvlist_fetch_ex(list, "TraceId",
                                  CFL_KVLIST_MATCH_CASE_SENSITIVE);
    TEST_CHECK(variant != NULL);
    TEST_CHECK(strcmp(variant->data.as_string, "upper") == 0);

    ret = cfl_kvlist_remove_ex(list, "traceid",
                               CFL_KVLIST_MATCH_CASE_SENSITIVE);
    TEST_CHECK(ret == CFL_TRUE);
    TEST_CHECK(cfl_kvlist_count(list) == 1);
    TEST_CHECK(cfl_kvlist_contains_ex(list, "TraceId",
                                     CFL_KVLIST_MATCH_CASE_SENSITIVE) ==
               CFL_TRUE);

    cfl_kvlist_destroy(list);
    cfl_arena_destroy(arena);
}

static void print_write_error()
{
#ifdef __linux__
    int ret;
    FILE *fp;
    struct cfl_kvlist *list;

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    fp = fopen("/dev/full", "w");
    if (fp == NULL) {
        cfl_kvlist_destroy(list);
        return;
    }

    setvbuf(fp, NULL, _IONBF, 0);

    ret = cfl_kvlist_print(fp, list);
    TEST_CHECK(ret == -1);

    fclose(fp);
    cfl_kvlist_destroy(list);
#endif
}

static void reject_kvlist_cycles()
{
    int ret;
    struct cfl_kvlist *list;
    struct cfl_kvlist *child;

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    ret = cfl_kvlist_insert_kvlist(list, "self", list);
    TEST_CHECK(ret == -1);

    child = cfl_kvlist_create();
    TEST_CHECK(child != NULL);

    ret = cfl_kvlist_insert_kvlist(list, "child", child);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_kvlist(list, "child-again", child);
    TEST_CHECK(ret == -1);

    ret = cfl_kvlist_insert_kvlist(child, "parent", list);
    TEST_CHECK(ret < 0);

    cfl_kvlist_destroy(list);
}

static void reject_variant_cycles()
{
    int ret;
    struct cfl_kvlist *list;
    struct cfl_variant *variant;

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    variant = cfl_variant_create_from_kvlist(list);
    TEST_CHECK(variant != NULL);

    ret = cfl_kvlist_insert(list, "self", variant);
    TEST_CHECK(ret == -1);

    cfl_variant_destroy(variant);
}

static void reject_shared_kvlist_between_parents()
{
    int ret;
    struct cfl_kvlist *list_a;
    struct cfl_kvlist *list_b;
    struct cfl_kvlist *child;

    list_a = cfl_kvlist_create();
    TEST_CHECK(list_a != NULL);

    list_b = cfl_kvlist_create();
    TEST_CHECK(list_b != NULL);

    child = cfl_kvlist_create();
    TEST_CHECK(child != NULL);

    ret = cfl_kvlist_insert_kvlist(list_a, "child", child);
    TEST_CHECK(ret == 0);

    ret = cfl_kvlist_insert_kvlist(list_b, "child", child);
    TEST_CHECK(ret == -1);
    TEST_CHECK(cfl_kvlist_count(list_b) == 0);

    cfl_kvlist_destroy(list_b);
    cfl_kvlist_destroy(list_a);
}

static void reject_array_cycles()
{
    int ret;
    struct cfl_array *array;
    struct cfl_kvlist *list;

    list = cfl_kvlist_create();
    TEST_CHECK(list != NULL);

    array = cfl_array_create(1);
    TEST_CHECK(array != NULL);

    ret = cfl_kvlist_insert_array(list, "array", array);
    TEST_CHECK(ret == 0);

    ret = cfl_array_append_kvlist(array, list);
    TEST_CHECK(ret < 0);

    cfl_kvlist_destroy(list);
}

static void move_taken_value_between_kvlists()
{
    int ret;
    struct cfl_list *head;
    struct cfl_kvlist *source;
    struct cfl_kvlist *destination;
    struct cfl_kvpair *pair;
    struct cfl_variant *value;
    struct cfl_variant *moved;

    source = cfl_kvlist_create();
    TEST_CHECK(source != NULL);

    destination = cfl_kvlist_create();
    TEST_CHECK(destination != NULL);

    ret = cfl_kvlist_insert_string(source, "source", "value");
    TEST_CHECK(ret == 0);

    head = source->list.next;
    pair = cfl_list_entry(head, struct cfl_kvpair, _head);
    value = cfl_kvpair_take_value(pair);
    TEST_CHECK(value != NULL);
    TEST_CHECK(pair->val == NULL);

    cfl_kvpair_destroy(pair);
    TEST_CHECK(cfl_kvlist_count(source) == 0);

    ret = cfl_kvlist_insert(destination, "destination", value);
    TEST_CHECK(ret == 0);

    moved = cfl_kvlist_fetch(destination, "destination");
    TEST_CHECK(moved == value);
    TEST_CHECK(moved->type == CFL_VARIANT_STRING);
    TEST_CHECK(strcmp(moved->data.as_string, "value") == 0);

    cfl_kvlist_destroy(source);
    cfl_kvlist_destroy(destination);
}

static void insert_rejects_owned_value()
{
    int ret;
    struct cfl_list *head;
    struct cfl_kvlist *source;
    struct cfl_kvlist *destination;
    struct cfl_kvpair *pair;
    struct cfl_variant *value;

    source = cfl_kvlist_create();
    TEST_CHECK(source != NULL);

    destination = cfl_kvlist_create();
    TEST_CHECK(destination != NULL);

    ret = cfl_kvlist_insert_string(source, "source", "value");
    TEST_CHECK(ret == 0);

    head = source->list.next;
    pair = cfl_list_entry(head, struct cfl_kvpair, _head);
    value = pair->val;

    ret = cfl_kvlist_insert(destination, "destination", value);
    TEST_CHECK(ret == -1);
    TEST_CHECK(cfl_kvlist_count(destination) == 0);

    cfl_kvlist_destroy(source);
    cfl_kvlist_destroy(destination);
}

TEST_LIST = {
    {"create_destroy",  create_destroy},
    {"count", count},
    {"fetch", fetch},
    {"insert_string", insert_string},
    {"insert_bytes", insert_bytes},
    {"insert_reference", insert_reference},
    {"insert_bool", insert_bool},
    {"insert_int64", insert_int64},
    {"insert_uint64", insert_uint64},
    {"insert_double", insert_double},
    {"insert_new_array", insert_new_array},
    {"insert_empty_array", insert_empty_array},
    {"insert_empty_kvlist", insert_empty_kvlist},

    {"fetch_s", fetch_s},
    {"insert_string_s", insert_string_s},
    {"insert_bytes_s", insert_bytes_s},
    {"insert_reference_s", insert_reference_s},
    {"insert_bool_s", insert_bool_s},
    {"insert_int64_s", insert_int64_s},
    {"insert_uint64_s", insert_uint64_s},
    {"insert_double_s", insert_double_s},
    {"insert_new_array_s", insert_new_array_s},
    {"insert_empty_array_s", insert_empty_array_s},
    {"insert_empty_kvlist_s", insert_empty_kvlist_s},
    {"basics", test_basics},
    {"null_inputs", null_inputs},
    {"print_escaped_keys", print_escaped_keys},
    {"embedded_nul_keys_do_not_match_short_name", embedded_nul_keys_do_not_match_short_name},
    {"case_sensitive_operations", case_sensitive_operations},
    {"case_sensitive_arena_operations", case_sensitive_arena_operations},
    {"print_write_error", print_write_error},
    {"reject_kvlist_cycles", reject_kvlist_cycles},
    {"reject_variant_cycles", reject_variant_cycles},
    {"reject_shared_kvlist_between_parents", reject_shared_kvlist_between_parents},
    {"reject_array_cycles", reject_array_cycles},
    {"move_taken_value_between_kvlists", move_taken_value_between_kvlists},
    {"insert_rejects_owned_value", insert_rejects_owned_value},
    { 0 }
};
