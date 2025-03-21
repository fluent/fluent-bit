/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_sds.h>
#include <stdio.h>
#include <stdlib.h>
#include "flb_tests_internal.h"

/* https://github.com/fluent/fluent-bit/issues/6313 */
void test_translate_long_env()
{
    struct flb_env *env;
    flb_sds_t buf = NULL;
    char *long_env = "ABC_APPLICATION_TEST_TEST_ABC_FLUENT_BIT_SECRET_FLUENTD_HTTP_HOST";
    char long_env_ra[4096] = {0};
    char *env_val = "aaaaa";
    char putenv_arg[4096] = {0};
    size_t ret_size;
    int ret;

    ret_size = snprintf(&long_env_ra[0], sizeof(long_env_ra), "${%s}", long_env);
    if (!TEST_CHECK(ret_size < sizeof(long_env_ra))) {
        TEST_MSG("long_env_ra size error");
        exit(1);
    }
    ret_size = snprintf(&putenv_arg[0], sizeof(putenv_arg), "%s=%s", long_env, env_val);
    if (!TEST_CHECK(ret_size < sizeof(long_env_ra))) {
        TEST_MSG("putenv_arg size error");
        exit(1);
    }

    env = flb_env_create();
    if (!TEST_CHECK(env != NULL)) {
        TEST_MSG("flb_env_create failed");
        exit(1);
    }
#ifndef FLB_SYSTEM_WINDOWS
    ret = putenv(&putenv_arg[0]);
#else
    ret = _putenv(&putenv_arg[0]);
#endif
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("setenv failed");
        flb_env_destroy(env);
        exit(1);
    }

    buf = flb_env_var_translate(env, &long_env_ra[0]);
    if (!TEST_CHECK(buf != NULL)) {
        TEST_MSG("flb_env_var_translate failed");
#ifndef FLB_SYSTEM_WINDOWS
        unsetenv(long_env);
#endif
        flb_env_destroy(env);
        exit(1);
    }

    if (!TEST_CHECK(strlen(buf) == strlen(env_val) && 0 == strcmp(buf, env_val))) {
        TEST_MSG("mismatch. Got=%s expect=%s", buf, env_val);
    }
    flb_sds_destroy(buf);
#ifndef FLB_SYSTEM_WINDOWS
    unsetenv(long_env);
#endif
    flb_env_destroy(env);
}


TEST_LIST = {
    { "translate_long_env"           , test_translate_long_env},
    { NULL, NULL }
};
