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
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

/*
 * Channels that must not exist on the host. The names are deliberately
 * implausible; the tests rely on subscription to them failing with
 * ERROR_EVT_CHANNEL_NOT_FOUND.
 */
#define MISSING_CHANNEL_A "FlbTestMissingChannelA"
#define MISSING_CHANNEL_B "FlbTestMissingChannelB"

/*
 * All channels of the instance are missing and tolerated: the engine must
 * start, survive collection cycles and stop cleanly. Before the fix,
 * ctx->active_channel was NULL and the first collection cycle crashed the
 * process (NULL dereference in mk_list_foreach).
 */
void flb_test_winevtlog_all_channels_missing_ignored(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "winevtlog", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd,
                        "channels", MISSING_CHANNEL_A,
                        "ignore_missing_channels", "true",
                        "interval_sec", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Let at least two collection cycles run (interval_sec=1) */
    flb_time_msleep(2500);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Same as above but with several missing channels in one instance */
void flb_test_winevtlog_multiple_missing_channels_ignored(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "winevtlog", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd,
                        "channels", MISSING_CHANNEL_A "," MISSING_CHANNEL_B,
                        "ignore_missing_channels", "true",
                        "interval_sec", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(2500);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * A mix of one existing channel ('Application' always exists on Windows)
 * and one missing channel: the missing one is skipped, the instance keeps
 * working. This was already the behavior before the fix and must not
 * regress.
 */
void flb_test_winevtlog_mixed_channels_ignored(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "winevtlog", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd,
                        "channels", "Application," MISSING_CHANNEL_A,
                        "ignore_missing_channels", "true",
                        "interval_sec", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_time_msleep(2500);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Without ignore_missing_channels, a missing channel must keep failing
 * initialization (documented behavior: "Subscribe at least one").
 */
void flb_test_winevtlog_missing_channel_fails_without_ignore(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "winevtlog", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd,
                        "channels", MISSING_CHANNEL_A,
                        NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "*", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret != 0);

    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"all_channels_missing_ignored",
     flb_test_winevtlog_all_channels_missing_ignored},
    {"multiple_missing_channels_ignored",
     flb_test_winevtlog_multiple_missing_channels_ignored},
    {"mixed_channels_ignored",
     flb_test_winevtlog_mixed_channels_ignored},
    {"missing_channel_fails_without_ignore",
     flb_test_winevtlog_missing_channel_fails_without_ignore},
    {NULL, NULL}
};
