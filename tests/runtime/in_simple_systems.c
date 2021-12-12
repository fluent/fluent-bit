/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include "flb_tests_runtime.h"


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
        flb_info("[test] flush triggered");
        flb_lib_free(data);
        set_result(time_in_ms()); /* success */
    }
    return 0;
}

void do_test(char *system, ...)
{
    int64_t ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    va_list va;
    char *key;
    char *value;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) system, NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    va_start(va, system);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "test", NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    /* The following test tries to check if an input plugin generates
     * data in a timely manner.
     *
     *    0     1     2     3     4   (sec)
     *    |--F--F--F--C--F--F--F--C--|
     *
     *    F ... Flush (0.5 sec interval)
     *    C ... Condition checks
     *
     * Since CI servers can be sometimes very slow, we wait slightly a
     * little more before checking the condition.
     */

    /* Start test */
    TEST_CHECK(flb_start(ctx) == 0);

    /* 2 sec passed. It must have flushed */
    sleep(2);
    flb_info("[test] check status 1");
    ret = get_result();
    TEST_CHECK(ret > 0);

    /* 4 sec passed. It must have flushed */
    sleep(2);
    flb_info("[test] check status 2");
    ret = get_result();
    TEST_CHECK(ret > 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_in_disk_flush()
{
    do_test("disk",
            "interval_sec", "0",
            "interval_nsec", "500000000",
            NULL);
}
void flb_test_in_proc_flush()
{
    do_test("proc",
            "interval_sec", "0",
            "interval_nsec", "500000000",
            "proc_name", "flb_test_in_proc",
            "alert", "true",
            "mem", "on",
            "fd", "on",
            NULL);
}
void flb_test_in_head_flush()
{
    do_test("head", 
            "interval_sec", "0",
            "interval_nsec", "500000000",
            "File", "/dev/urandom",
            NULL);
}
void flb_test_in_cpu_flush()
{
    do_test("cpu", NULL);
}
void flb_test_in_random_flush()
{
    do_test("random", NULL);
}
void flb_test_in_dummy_flush()
{
    do_test("dummy", NULL);
}
void flb_test_in_mem_flush()
{
    do_test("mem", NULL);
}

#ifdef in_proc
void flb_test_in_proc_absent_process(void)
{
    int ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "proc", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test",
                  "interval_sec", "1", "proc_name", "-",
                  "alert", "true", "mem", "on", "fd", "on", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    flb_service_set(ctx, "Flush", "2", "Grace", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0); // error occurs but return value is true

    flb_stop(ctx);
    flb_destroy(ctx);
}
#endif

/* Test list */
TEST_LIST = {
#ifdef in_disk
    {"disk_flush",    flb_test_in_disk_flush},
#endif
#ifdef in_proc
    {"proc_flush",    flb_test_in_proc_flush},
    {"proc_absent_process",     flb_test_in_proc_absent_process},
#endif
#ifdef in_head
    {"head_flush",    flb_test_in_head_flush},
#endif
#ifdef in_cpu
    {"cpu_flush",     flb_test_in_cpu_flush},
#endif
#ifdef in_random
    {"random_flush",  flb_test_in_random_flush},
#endif
#ifdef in_dummy
    {"dummy_flush",   flb_test_in_dummy_flush},
#endif
#ifdef in_mem
    {"mem_flush",     flb_test_in_mem_flush},
#endif
    {NULL, NULL}
};

