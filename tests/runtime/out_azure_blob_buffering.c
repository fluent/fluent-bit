/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include "flb_tests_runtime.h"

#include "../../plugins/out_azure_blob/azure_blob.h"

static void test_upload_backoff_schedule()
{
    TEST_CHECK(azure_blob_upload_backoff(1) == 2);
    TEST_CHECK(azure_blob_upload_backoff(2) == 4);
    TEST_CHECK(azure_blob_upload_backoff(3) == 8);
    TEST_CHECK(azure_blob_upload_backoff(5) == 32);
    TEST_CHECK(azure_blob_upload_backoff(6) == AZURE_BLOB_MAX_UPLOAD_BACKOFF);
    TEST_CHECK(azure_blob_upload_backoff(7) == AZURE_BLOB_MAX_UPLOAD_BACKOFF);
    TEST_CHECK(azure_blob_upload_backoff(1000) == AZURE_BLOB_MAX_UPLOAD_BACKOFF);
}

TEST_LIST = {
    {"upload_backoff_schedule", test_upload_backoff_schedule},
    {NULL, NULL}
};
