/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#include <ctraces/ctraces.h>
#include "ctr_tests.h"

#define OPTS_TRACE_ID  "4582829a12781087"

void test_basic()
{
    struct ctrace *ctx;

    printf("version => '%s'", ctr_version());

    ctx = ctr_create(NULL);
    TEST_CHECK(ctx != NULL);

    ctr_destroy(ctx);
}

void test_options()
{
    struct ctrace *ctx;
    struct ctrace_opts opts;

    /* options */
    ctr_opts_init(&opts);

    /* create & destroy context */
    ctx = ctr_create(&opts);

    TEST_CHECK(ctx != NULL);
    ctr_destroy(ctx);

    /* exit options */
    ctr_opts_exit(&opts);
}

TEST_LIST = {
    {"basic", test_basic},
    {"options", test_options},
    { 0 }
};
