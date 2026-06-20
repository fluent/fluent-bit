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
#include <fluent-bit/flb_engine.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "flb_tests_runtime.h"

#define SHUTDOWN_TIME_LIMIT_SEC 5   /* grace=2 + safety margin */
#define SHUTDOWN_WATCHDOG_SEC   10

/* Async-signal-safe abort used when flb_stop() hangs on a regression. */
static void timeout_abort(int sig)
{
    static const char msg[] =
        "\nFAIL: flb_test_duplicate_stop_no_spin timed out; "
        "shutdown spin regression likely present.\n";
    (void) sig;
    (void) write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
}

/* Regression: two back-to-back STOPs must not cause a shutdown busy-loop. */
void flb_test_duplicate_stop_no_spin(void)
{
    flb_ctx_t        *ctx;
    int               in_ffd;
    int               out_ffd;
    int64_t           ret;
    time_t            start;
    time_t            elapsed;
    struct sigaction  sa;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    TEST_CHECK(flb_service_set(ctx,
                               "Flush",     "1",
                               "Grace",     "2",
                               "Log_Level", "info",
                               NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "*", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    /* Let the engine enter its main event loop. */
    sleep(1);

    TEST_CHECK(flb_engine_exit(ctx->config) >= 0);

    /* Let the first STOP be processed before the second arrives. */
    usleep(100 * 1000);

    TEST_CHECK(flb_engine_exit(ctx->config) >= 0);

    /* Bound flb_stop() so a regression fails fast. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_abort;
    sigaction(SIGALRM, &sa, NULL);
    alarm(SHUTDOWN_WATCHDOG_SEC);

    start = time(NULL);
    ret = flb_stop(ctx);
    elapsed = time(NULL) - start;

    alarm(0);

    TEST_CHECK_(ret == 0, "flb_stop returned %lld", (long long) ret);
    TEST_CHECK_(elapsed <= SHUTDOWN_TIME_LIMIT_SEC,
                "shutdown took %lds; expected <= %ds (shutdown spin?)",
                (long) elapsed, SHUTDOWN_TIME_LIMIT_SEC);

    if (ctx) {
        flb_destroy(ctx);
    }
}

/* Test list */
TEST_LIST = {
    {"duplicate_stop_no_spin", flb_test_duplicate_stop_no_spin},
    {NULL, NULL}
};
