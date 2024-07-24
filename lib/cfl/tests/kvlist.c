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
    { 0 }
};
