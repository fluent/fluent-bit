/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2026 The Fluent Bit Authors
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

#include "flb_tests_internal.h"

static void test_invalid_network_address_cleanup(void)
{
    int output_id;
    flb_ctx_t *ctx;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    output_id = flb_output(ctx, "http://[", NULL);
    TEST_CHECK(output_id == -1);

    flb_destroy(ctx);
}

TEST_LIST = {
    {"invalid_network_address_cleanup", test_invalid_network_address_cleanup},
    {NULL, NULL}
};
