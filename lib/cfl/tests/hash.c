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

#include <cfl/cfl_hash.h>

#include "cfl_tests_internal.h"

static void checks()
{
    int len;
    uint64_t cfl_hash;
    uint64_t xxh_hash;
    XXH3_state_t xxh_state;
    cfl_hash_state_t cfl_state;
    char *str = "this is a test";

    len = strlen(str);

    /* a dummy test, we just need to make sure the wrapper is working */
    cfl_hash = cfl_hash_64bits(str, len);
    xxh_hash = XXH3_64bits(str, len);
    TEST_CHECK(cfl_hash == xxh_hash);

    /* state and updates */
    cfl_hash_64bits_reset(&cfl_state);
    cfl_hash_64bits_update(&cfl_state, str, len);
    cfl_hash_64bits_update(&cfl_state, str, len);
    cfl_hash = cfl_hash_64bits_digest(&cfl_state);

    XXH3_64bits_reset(&xxh_state);
    XXH3_64bits_update(&xxh_state, str, len);
    XXH3_64bits_update(&xxh_state, str, len);
    xxh_hash = XXH3_64bits_digest(&xxh_state);

    TEST_CHECK(cfl_hash == xxh_hash);
}

TEST_LIST = {
    {"checks",  checks},
    { 0 }
};
