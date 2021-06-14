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

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_internal.h"


void test_to_nanosec()
{
    uint64_t expect = 123000000456;
    uint64_t ret;
    struct flb_time tm;

    flb_time_set(&tm, 123, 456);

    ret = flb_time_to_nanosec(&tm);
    if (!TEST_CHECK(ret == expect)) {
      TEST_MSG("given  =%" PRIu64, ret);
      TEST_MSG("expect =%" PRIu64, expect);
    }
}

TEST_LIST = {
    { "flb_time_to_nanosec"           , test_to_nanosec},
    { NULL, NULL }
};
