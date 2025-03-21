/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "flb_tests_runtime.h"

/* Test data*/

/* Test functions*/
void flb_test_engine_wildcard(void);

/* Test list */
TEST_LIST = {
    {"wildcard",    flb_test_engine_wildcard },
    {NULL, NULL}
};

#define MAX_WAIT_TIME 1500
int64_t result_time;
static inline int64_t set_result(int64_t v)
{
    int64_t old = __sync_lock_test_and_set(&result_time, v);
    return old;
}

static inline int64_t get_result(void)
{
    int64_t old = __sync_fetch_and_add(&result_time, 0);

    return old;
}

static inline int64_t time_in_ms()
{
    int ms;
    struct timespec s;
    TEST_CHECK(clock_gettime(CLOCK_MONOTONIC, &s) == 0);
    ms = s.tv_nsec / 1.0e6;
    if (ms >= 1000) {
        ms = 0;
    }
    return 1000 * s.tv_sec + ms;
}

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_lib_free(data);
        set_result(time_in_ms()); /* success */
    }
    return 0;
}

int check_routing(const char* tag,
                  const char* match,
                  const char* match_regex,
                  bool expect)
{
    int in_ffd;
    int out_ffd;
    int64_t ret;
    int64_t start;
    flb_ctx_t    *ctx    = NULL;
    char         *str    = (char*)"[1, {\"key\":\"value\"}]";

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    /* initialize */
    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", tag, NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    if (match) {
        flb_output_set(ctx, out_ffd, "match", match, NULL);
    }
    if (match_regex) {
        flb_output_set(ctx, out_ffd, "match_regex", match_regex, NULL);
    }

    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Daemon", "false", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* start test */
    flb_lib_push(ctx, in_ffd, str, strlen(str));
    set_result(0);
    start = time_in_ms();
    while ( (ret = get_result()) == 0 && (time_in_ms() - start < MAX_WAIT_TIME))
        usleep(10);

    if (expect ? ret == 0 : ret > 0) {
        flb_error("Mismatch: tag:%s, match:%s, match_regex:%s, expect:%s\n",
                    tag,
                    match ? match : "null",
                    match_regex ? match_regex : "null",
                    expect ? "true" : "false");
    }
    TEST_CHECK(expect ? ret > 0 : ret == 0);

    /* finalize */
    flb_stop(ctx);
    flb_destroy(ctx);

    return 0;
}

void flb_test_engine_wildcard(void)
{
    struct test_wildcard_fmt {
        const char* tag;
        const char* match;
        const char* match_regex;
        bool        expect;
    };
    int i = 0;

    struct test_wildcard_fmt checklist[] =
    {
        {"cpu.rpi","cpu.rpi", NULL, true  },
        {"cpu.rpi","cpu.ard", NULL, false },
        {"cpu.rpi","cpu.*",   NULL, true  },
        {"cpu.rpi","*",       NULL, true  },
        {"cpu.rpi","*.*",     NULL, true  },
        {"cpu.rpi","*.rpi",   NULL, true  },
        {"cpu.rpi","mem.*",   NULL, false },
        {"cpu.rpi","*u.r*",   NULL, true  },
        {"cpu.rpi",NULL,      "[a-z]*", true  },
        {"cpu.rpi",NULL,      "[A-Z]*", false },
        {NULL, NULL, NULL, 0}
    };

    while(checklist[i].tag != NULL){
        check_routing(checklist[i].tag,
                      checklist[i].match,
                      checklist[i].match_regex,
                      checklist[i].expect);
        i++;
    }
}
