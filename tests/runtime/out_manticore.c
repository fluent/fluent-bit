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
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"

#define RECORD_WITH_ID    "[1448403340, {\"id\":42,\"message\":\"hello\"}]"
#define RECORD_WITHOUT_ID "[1448403340, {\"message\":\"no id\"}]"

/* The formatter may see the records in one chunk or in several. */
struct format_result {
    flb_sds_t ndjson;
    int failures;
};

static void cb_collect(void *ctx, int ffd, int res_ret,
                       void *res_data, size_t res_size, void *data)
{
    struct format_result *result = data;

    if (res_ret != 0 || res_data == NULL) {
        result->failures++;
        return;
    }
    flb_sds_cat_safe(&result->ndjson, res_data, res_size);
    flb_sds_destroy(res_data);
}

static void check_format(const char *mode, const char *action,
                         const char **records, int count,
                         const char *expected)
{
    int i;
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct format_result result;

    result.ndjson = flb_sds_create("");
    result.failures = 0;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "manticore", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "table", "logs",
                   "mode", mode,
                   "action", action,
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter", cb_collect,
                              &result, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < count; i++) {
        flb_lib_push(ctx, in_ffd, (char *) records[i], strlen(records[i]));
    }

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK(result.failures == 0);
    if (!TEST_CHECK(strcmp(result.ndjson, expected) == 0)) {
        TEST_MSG("expected: %s", expected);
        TEST_MSG("given:    %s", result.ndjson);
    }
    flb_sds_destroy(result.ndjson);
}

/* Regular wraps every record, with or without its own id, in an operation. */
void flb_test_regular_insert()
{
    const char *records[] = { RECORD_WITH_ID, RECORD_WITHOUT_ID };

    check_format("regular", "insert", records, 2,
                 "{\"insert\":{\"table\":\"logs\",\"doc\":{\"id\":42,\"message\":\"hello\"}}}\n"
                 "{\"insert\":{\"table\":\"logs\",\"doc\":{\"message\":\"no id\"}}}\n");
}

void flb_test_regular_create()
{
    const char *records[] = { RECORD_WITH_ID };

    check_format("regular", "create", records, 1,
                 "{\"create\":{\"table\":\"logs\",\"doc\":{\"id\":42,\"message\":\"hello\"}}}\n");
}

/* Shared sends every record as it is: the table is in the request URI. */
void flb_test_shared()
{
    const char *records[] = { RECORD_WITH_ID, RECORD_WITHOUT_ID };

    check_format("shared", "insert", records, 2,
                 "{\"id\":42,\"message\":\"hello\"}\n"
                 "{\"message\":\"no id\"}\n");
}

/*
 * A bad setting fails the start. The settings are name/value pairs ending
 * with NULL, the bad one last.
 */
static void check_refused(const char **settings)
{
    int i;
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "manticore", NULL);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    for (i = 0; settings[i] != NULL; i += 2) {
        flb_output_set(ctx, out_ffd, settings[i], settings[i + 1], NULL);
    }

    /* A failed start has joined the engine thread already: no flb_stop() then */
    ret = flb_start(ctx);
    if (!TEST_CHECK(ret == -1)) {
        TEST_MSG("started with %s=%s", settings[i - 2], settings[i - 1]);
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

void flb_test_bad_config()
{
    const char *mode[] = { "table", "logs", "mode", "Off", NULL };
    const char *action[] = { "table", "logs", "action", "replace", NULL };
    const char *indexers[] = { "table", "logs", "mode", "shared",
                               "shared_indexers", "-1", NULL };
    const char *no_table[] = { "mode", "shared", "table", "", NULL };

    check_refused(mode);
    check_refused(action);
    check_refused(indexers);
    check_refused(no_table);
}

TEST_LIST = {
    {"regular_insert", flb_test_regular_insert},
    {"regular_create", flb_test_regular_create},
    {"shared",         flb_test_shared},
    {"bad_config",     flb_test_bad_config},
    {NULL, NULL}
};
