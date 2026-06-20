/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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
#include <fluent-bit/flb_uri.h>
#include <string.h>

#include "flb_tests_internal.h"

void uri_create_destroy()
{
    struct flb_uri *uri;
    const char *uri_str = "https://fluentbit.io";

    uri = flb_uri_create(uri_str);
    if (!TEST_CHECK(uri != NULL)) {
        TEST_MSG("flb_uri_create failed");
        return;
    }

    flb_uri_destroy(uri);
}

void uri_get()
{
    struct flb_uri *uri;
    struct flb_uri_field *field;
    const char *uri_str = "https://fluentbit.io";

    uri = flb_uri_create(uri_str);
    if (!TEST_CHECK(uri != NULL)) {
        TEST_MSG("flb_uri_create failed");
        return;
    }

    field = flb_uri_get(uri, 0);
    if (!TEST_CHECK(field != NULL)) {
        TEST_MSG("flb_uri_get failed");
        return;
    }

    field = flb_uri_get(uri, -1);
    if (!TEST_CHECK(field == NULL)) {
        TEST_MSG("flb_uri_get should fail");
        return;
    }

    flb_uri_destroy(uri);
}

void uri_encode()
{
    flb_sds_t encoded_uri;
    const char *input = "&# ";
    const char *expect = "%26%23%20";

    encoded_uri = flb_uri_encode(input, strlen(input));
    if (!TEST_CHECK(encoded_uri != NULL)) {
        TEST_MSG("flb_uri_encode failed");
        return;
    }

    flb_sds_destroy(encoded_uri);
}

TEST_LIST = {
    { "uri_create_destroy", uri_create_destroy },
    { "uri_get", uri_get },
    { "uri_encode", uri_encode },
    { 0 }
};
