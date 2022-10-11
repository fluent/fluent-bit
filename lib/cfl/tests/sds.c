/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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
#include "cfl_tests_internal.h"

static void test_sds_usage()
{
    cfl_sds_t s;

    s = cfl_sds_create("test");
    TEST_CHECK(s != NULL);
    TEST_CHECK(cfl_sds_len(s) == 4);
    TEST_CHECK(cfl_sds_alloc(s) == 4);
    TEST_CHECK(strcmp("test", s) == 0);

    s = cfl_sds_cat(s, ",cat message", 12);
    TEST_CHECK(strcmp("test,cat message", s) == 0);

    cfl_sds_destroy(s);
}

static void test_sds_printf()
{
    int len;
    cfl_sds_t s;
    cfl_sds_t tmp;
    char *str = "0123456789ABCDEFGHIJQLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvewxyz";

    s = cfl_sds_create_size(10);
    tmp = cfl_sds_printf(&s, "%s=%s", str, str);

    len = (strlen(str) * 2) + 1;
    TEST_CHECK(tmp == s);
    TEST_CHECK(cfl_sds_len(s) == len);
    cfl_sds_destroy(s);
}

TEST_LIST = {
    { "sds_usage" , test_sds_usage},
    { "sds_printf", test_sds_printf},
    { 0 }
};
