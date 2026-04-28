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

static void cb_check_record_hostname(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    flb_sds_t out_js = res_data;

    TEST_CHECK(res_ret == 0);
    TEST_CHECK(out_js != NULL);
    TEST_CHECK(strstr(out_js, "\"hostname\":\"record-host\"") != NULL);

    flb_sds_destroy(out_js);
}

static void cb_check_default_hostname(void *ctx, int ffd,
                                      int res_ret, void *res_data, size_t res_size,
                                      void *data)
{
    flb_sds_t out_js = res_data;

    TEST_CHECK(res_ret == 0);
    TEST_CHECK(out_js != NULL);
    TEST_CHECK(strstr(out_js, "\"hostname\":\"config-host\"") != NULL);

    flb_sds_destroy(out_js);
}

void flb_test_record_hostname_field()
{
    int ret;
    int size = sizeof("[12345678, {\"hostname\":\"record-host\",\"message\":\"hello\"}]") - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "dummy-api-key",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_record_hostname,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) "[12345678, {\"hostname\":\"record-host\",\"message\":\"hello\"}]",
                 size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_default_hostname_field()
{
    int ret;
    int size = sizeof("[12345678, {\"message\":\"hello\"}]") - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "dummy-api-key",
                   "hostname", "config-host",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_default_hostname,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) "[12345678, {\"message\":\"hello\"}]",
                 size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
    {"record_hostname_field", flb_test_record_hostname_field},
    {"default_hostname_field", flb_test_default_hostname_field},
    {NULL, NULL}
};
