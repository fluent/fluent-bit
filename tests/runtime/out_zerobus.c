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

#include <fluent-bit.h>
#include <string.h>
#include "flb_tests_runtime.h"

static int is_missing(const char *missing, const char *name)
{
    return strcmp(missing, name) == 0;
}

static void flb_test_missing_required_field(const char *missing)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "zerobus", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    if (!is_missing(missing, "endpoint")) {
        flb_output_set(ctx, out_ffd, "endpoint", "localhost:443", NULL);
    }
    if (!is_missing(missing, "workspace_url")) {
        flb_output_set(ctx, out_ffd, "workspace_url", "localhost", NULL);
    }
    if (!is_missing(missing, "table_name")) {
        flb_output_set(ctx, out_ffd, "table_name", "catalog.schema.table", NULL);
    }
    if (!is_missing(missing, "client_id")) {
        flb_output_set(ctx, out_ffd, "client_id", "client-id", NULL);
    }
    if (!is_missing(missing, "client_secret")) {
        flb_output_set(ctx, out_ffd, "client_secret", "client-secret", NULL);
    }

    ret = flb_start(ctx);
    TEST_CHECK(ret == -1);
    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

void flb_test_missing_endpoint()
{
    flb_test_missing_required_field("endpoint");
}

void flb_test_missing_workspace_url()
{
    flb_test_missing_required_field("workspace_url");
}

void flb_test_missing_table_name()
{
    flb_test_missing_required_field("table_name");
}

void flb_test_missing_client_id()
{
    flb_test_missing_required_field("client_id");
}

void flb_test_missing_client_secret()
{
    flb_test_missing_required_field("client_secret");
}

TEST_LIST = {
  { "missing_endpoint", flb_test_missing_endpoint },
  { "missing_workspace_url", flb_test_missing_workspace_url },
  { "missing_table_name", flb_test_missing_table_name },
  { "missing_client_id", flb_test_missing_client_id },
  { "missing_client_secret", flb_test_missing_client_secret },
  { NULL, NULL },
};
