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

/* Test data */

/* Test functions */
void flb_test_in_head_flush_2s_2times(void);

/* Test list */
TEST_LIST = {
    {"flush_2s_2times",    flb_test_in_head_flush_2s_2times },
    {NULL, NULL}
};


pthread_mutex_t result_mutex;
bool result;

void set_result(bool val)
{
    pthread_mutex_lock(&result_mutex);
    result = val;
    pthread_mutex_unlock(&result_mutex);
}

bool get_result(void)
{
    bool val;

    pthread_mutex_lock(&result_mutex);
    val = result;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_lib_free(data);
        set_result(true); /* success */
    }
    return 0;
}

void flb_test_in_head_flush_2s_2times(void)
{
    int           ret    = 0;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    char  path[] = "/dev/urandom";

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    /* initialize */
    ret = pthread_mutex_init(&result_mutex, NULL);
    TEST_CHECK(ret == 0);
    set_result(false);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "head", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test",
                  "Interval_Sec", "1", "File", path,NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    flb_service_set(ctx, "Flush", "2", "Grace", "1", NULL);

    flb_info("[test] read %s",path);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* start test */
    ret = get_result(); /* No data should be flushed */
    TEST_CHECK(ret == false);

    sleep(2);
    ret = get_result(); /* 2sec passed, data should be flushed */
    TEST_CHECK(ret == true);
    set_result(false); /* clear flag */

    sleep(1);
    ret = get_result(); /* 1sec passed, no data should be flushed */
    TEST_CHECK(ret == false);

    sleep(1);
    ret = get_result(); /* 1sec passed, data should be flushed */
    TEST_CHECK(ret == true);

    /* finalize */
    flb_stop(ctx);
    flb_destroy(ctx);

    ret = pthread_mutex_destroy(&result_mutex);
    TEST_CHECK(ret == 0);
}
