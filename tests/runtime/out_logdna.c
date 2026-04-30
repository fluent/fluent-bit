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
#include <fluent-bit/flb_time.h>
#include <pthread.h>
#include "flb_tests_runtime.h"

/* Thread-safe callback invocation tracking */
static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int num_output = 0;

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);
    return ret;
}

static void clear_output_num()
{
    set_output_num(0);
}

/*
 * Test: primary keys (meta, level, app) are promoted to top-level fields
 * and excluded from the "line" JSON string (no duplication).
 */
#define JSON_WITH_PRIMARY_KEYS \
    "[12345678, {\"message\":\"hello world\"," \
    "\"meta\":{\"source\":\"test\",\"env\":\"dev\"}," \
    "\"level\":\"info\"," \
    "\"app\":\"myapp\"}]"

static void cb_check_non_duplication(void *ctx, int ffd, int res_ret,
                                     void *res_data, size_t res_size,
                                     void *data)
{
    flb_sds_t json = res_data;

    /* Primary keys promoted at top level (unescaped) */
    if (!TEST_CHECK(strstr(json, "\"meta\":") != NULL)) {
        TEST_MSG("missing top-level meta: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"level\":") != NULL)) {
        TEST_MSG("missing top-level level: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"app\":") != NULL)) {
        TEST_MSG("missing top-level app: %s", json);
    }

    /* Primary keys must NOT appear inside the line value (escaped) */
    if (!TEST_CHECK(strstr(json, "\\\"meta\\\":") == NULL)) {
        TEST_MSG("meta duplicated in line: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"level\\\":") == NULL)) {
        TEST_MSG("level duplicated in line: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"app\\\":") == NULL)) {
        TEST_MSG("app duplicated in line: %s", json);
    }

    /* Non-primary key must be in line value (escaped) */
    if (!TEST_CHECK(strstr(json, "\\\"message\\\":") != NULL)) {
        TEST_MSG("message missing from line: %s", json);
    }

    set_output_num(get_output_num() + 1);
    flb_sds_destroy(json);
}

void flb_test_non_duplication()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    clear_output_num();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "test-key",
                   "exclude_promoted_keys", "true",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_non_duplication, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_WITH_PRIMARY_KEYS,
                 sizeof(JSON_WITH_PRIMARY_KEYS) - 1);

    sleep(2);

    if (!TEST_CHECK(get_output_num() > 0)) {
        TEST_MSG("formatter callback was not invoked");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: all non-primary keys are preserved in the "line" body;
 * all primary keys are promoted. No data is lost.
 */
#define JSON_ALL_KEYS \
    "[12345678, {\"message\":\"hello\"," \
    "\"meta\":{\"foo\":\"bar\"}," \
    "\"level\":\"info\"," \
    "\"app\":\"myapp\"," \
    "\"file\":\"test.log\"," \
    "\"host\":\"server1\"," \
    "\"custom\":\"data\"}]"

static void cb_check_data_completeness(void *ctx, int ffd, int res_ret,
                                       void *res_data, size_t res_size,
                                       void *data)
{
    flb_sds_t json = res_data;

    /* All primary keys promoted at top level */
    if (!TEST_CHECK(strstr(json, "\"meta\":") != NULL)) {
        TEST_MSG("missing top-level meta: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"level\":") != NULL)) {
        TEST_MSG("missing top-level level: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"app\":") != NULL)) {
        TEST_MSG("missing top-level app: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"file\":") != NULL)) {
        TEST_MSG("missing top-level file: %s", json);
    }

    /* All non-primary keys in line body (escaped) */
    if (!TEST_CHECK(strstr(json, "\\\"message\\\":") != NULL)) {
        TEST_MSG("message missing from line: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"host\\\":") != NULL)) {
        TEST_MSG("host missing from line: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"custom\\\":") != NULL)) {
        TEST_MSG("custom missing from line: %s", json);
    }

    /* Primary keys not duplicated in line body */
    if (!TEST_CHECK(strstr(json, "\\\"meta\\\":") == NULL)) {
        TEST_MSG("meta duplicated in line: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"file\\\":") == NULL)) {
        TEST_MSG("file duplicated in line: %s", json);
    }

    set_output_num(get_output_num() + 1);
    flb_sds_destroy(json);
}

void flb_test_data_completeness()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    clear_output_num();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "test-key",
                   "exclude_promoted_keys", "true",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_data_completeness, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_ALL_KEYS,
                 sizeof(JSON_ALL_KEYS) - 1);

    sleep(2);

    if (!TEST_CHECK(get_output_num() > 0)) {
        TEST_MSG("formatter callback was not invoked");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: "severity" key is promoted as "level" in the output.
 */
#define JSON_SEVERITY \
    "[12345678, {\"message\":\"hello\",\"severity\":\"warning\"}]"

static void cb_check_severity(void *ctx, int ffd, int res_ret,
                               void *res_data, size_t res_size,
                               void *data)
{
    flb_sds_t json = res_data;

    /* severity should be promoted as "level" */
    if (!TEST_CHECK(strstr(json, "\"level\":\"warning\"") != NULL)) {
        TEST_MSG("severity not promoted as level: %s", json);
    }

    /* severity should not appear in line body */
    if (!TEST_CHECK(strstr(json, "\\\"severity\\\":") == NULL)) {
        TEST_MSG("severity duplicated in line: %s", json);
    }

    set_output_num(get_output_num() + 1);
    flb_sds_destroy(json);
}

void flb_test_severity_promoted_as_level()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    clear_output_num();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "test-key",
                   "exclude_promoted_keys", "true",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_severity, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_SEVERITY,
                 sizeof(JSON_SEVERITY) - 1);

    sleep(2);

    if (!TEST_CHECK(get_output_num() > 0)) {
        TEST_MSG("formatter callback was not invoked");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: record with both "level" and "severity" — only first is promoted,
 * neither appears in line body, and no msgpack corruption occurs.
 */
#define JSON_LEVEL_AND_SEVERITY \
    "[12345678, {\"message\":\"hello\"," \
    "\"level\":\"info\"," \
    "\"severity\":\"warning\"," \
    "\"host\":\"server1\"}]"

static void cb_check_level_and_severity(void *ctx, int ffd, int res_ret,
                                        void *res_data, size_t res_size,
                                        void *data)
{
    flb_sds_t json = res_data;

    /* First level/severity key promoted as "level" */
    if (!TEST_CHECK(strstr(json, "\"level\":\"info\"") != NULL)) {
        TEST_MSG("level not promoted: %s", json);
    }

    /* Neither level nor severity in line body */
    if (!TEST_CHECK(strstr(json, "\\\"level\\\":") == NULL)) {
        TEST_MSG("level duplicated in line: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"severity\\\":") == NULL)) {
        TEST_MSG("severity duplicated in line: %s", json);
    }

    /* Non-primary keys preserved in line */
    if (!TEST_CHECK(strstr(json, "\\\"message\\\":") != NULL)) {
        TEST_MSG("message missing from line: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"host\\\":") != NULL)) {
        TEST_MSG("host missing from line: %s", json);
    }

    set_output_num(get_output_num() + 1);
    flb_sds_destroy(json);
}

void flb_test_level_and_severity()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    clear_output_num();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "test-key",
                   "exclude_promoted_keys", "true",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_level_and_severity, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_LEVEL_AND_SEVERITY,
                 sizeof(JSON_LEVEL_AND_SEVERITY) - 1);

    sleep(2);

    if (!TEST_CHECK(get_output_num() > 0)) {
        TEST_MSG("formatter callback was not invoked");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: default app name is set when record has no "app" key.
 */
#define JSON_NO_APP \
    "[12345678, {\"message\":\"hello\"}]"

static void cb_check_default_app(void *ctx, int ffd, int res_ret,
                                  void *res_data, size_t res_size,
                                  void *data)
{
    flb_sds_t json = res_data;

    if (!TEST_CHECK(strstr(json, "\"app\":\"Fluent Bit\"") != NULL)) {
        TEST_MSG("default app not set: %s", json);
    }

    set_output_num(get_output_num() + 1);
    flb_sds_destroy(json);
}

void flb_test_default_app()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    clear_output_num();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "test-key",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_default_app, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_NO_APP,
                 sizeof(JSON_NO_APP) - 1);

    sleep(2);

    if (!TEST_CHECK(get_output_num() > 0)) {
        TEST_MSG("formatter callback was not invoked");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: record with no primary keys — all fields go into line,
 * only default app appears at top level.
 */
#define JSON_NO_PRIMARY_KEYS \
    "[12345678, {\"message\":\"hello\",\"host\":\"server1\"}]"

static void cb_check_no_primary_keys(void *ctx, int ffd, int res_ret,
                                      void *res_data, size_t res_size,
                                      void *data)
{
    flb_sds_t json = res_data;

    /* Default app at top level */
    if (!TEST_CHECK(strstr(json, "\"app\":\"Fluent Bit\"") != NULL)) {
        TEST_MSG("default app not set: %s", json);
    }

    /* All keys in line body */
    if (!TEST_CHECK(strstr(json, "\\\"message\\\":") != NULL)) {
        TEST_MSG("message missing from line: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"host\\\":") != NULL)) {
        TEST_MSG("host missing from line: %s", json);
    }

    /* No meta or level at top level (they aren't in the record) */
    if (!TEST_CHECK(strstr(json, "\"meta\":") == NULL)) {
        TEST_MSG("unexpected meta at top level: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"level\":") == NULL)) {
        TEST_MSG("unexpected level at top level: %s", json);
    }

    set_output_num(get_output_num() + 1);
    flb_sds_destroy(json);
}

void flb_test_no_primary_keys()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    clear_output_num();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "test-key",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_no_primary_keys, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_NO_PRIMARY_KEYS,
                 sizeof(JSON_NO_PRIMARY_KEYS) - 1);

    sleep(2);

    if (!TEST_CHECK(get_output_num() > 0)) {
        TEST_MSG("formatter callback was not invoked");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: basic payload structure contains required fields.
 */
static void cb_check_payload_structure(void *ctx, int ffd, int res_ret,
                                        void *res_data, size_t res_size,
                                        void *data)
{
    flb_sds_t json = res_data;

    if (!TEST_CHECK(strstr(json, "\"lines\":") != NULL)) {
        TEST_MSG("missing lines array: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"line\":") != NULL)) {
        TEST_MSG("missing line field: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"timestamp\":") != NULL)) {
        TEST_MSG("missing timestamp field: %s", json);
    }

    set_output_num(get_output_num() + 1);
    flb_sds_destroy(json);
}

void flb_test_payload_structure()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    clear_output_num();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "test-key",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_payload_structure, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_NO_APP,
                 sizeof(JSON_NO_APP) - 1);

    sleep(2);

    if (!TEST_CHECK(get_output_num() > 0)) {
        TEST_MSG("formatter callback was not invoked");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: backward compatibility — when exclude_promoted_keys is not set
 * (default false), promoted keys ARE present in the line body.
 */
static void cb_check_backward_compat(void *ctx, int ffd, int res_ret,
                                      void *res_data, size_t res_size,
                                      void *data)
{
    flb_sds_t json = res_data;

    /* Primary keys at top level */
    if (!TEST_CHECK(strstr(json, "\"meta\":") != NULL)) {
        TEST_MSG("missing top-level meta: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"level\":") != NULL)) {
        TEST_MSG("missing top-level level: %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\"app\":") != NULL)) {
        TEST_MSG("missing top-level app: %s", json);
    }

    /* Primary keys ALSO in line body (escaped) — original behavior */
    if (!TEST_CHECK(strstr(json, "\\\"meta\\\":") != NULL)) {
        TEST_MSG("meta should be in line (backward compat): %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"level\\\":") != NULL)) {
        TEST_MSG("level should be in line (backward compat): %s", json);
    }
    if (!TEST_CHECK(strstr(json, "\\\"app\\\":") != NULL)) {
        TEST_MSG("app should be in line (backward compat): %s", json);
    }

    set_output_num(get_output_num() + 1);
    flb_sds_destroy(json);
}

void flb_test_backward_compat()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    clear_output_num();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "logdna", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "api_key", "test-key",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_backward_compat, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_WITH_PRIMARY_KEYS,
                 sizeof(JSON_WITH_PRIMARY_KEYS) - 1);

    sleep(2);

    if (!TEST_CHECK(get_output_num() > 0)) {
        TEST_MSG("formatter callback was not invoked");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Test: repeated start/push/stop/destroy cycles to verify
 * proper resource cleanup (no crashes from leaks or double-free).
 */
static void cb_lifecycle_noop(void *ctx, int ffd, int res_ret,
                              void *res_data, size_t res_size,
                              void *data)
{
    flb_sds_t json = res_data;
    flb_sds_destroy(json);
}

void flb_test_lifecycle()
{
    int i;
    int ret;
    flb_ctx_t *ctx;
    int in_ffd, out_ffd;

    for (i = 0; i < 3; i++) {
        ctx = flb_create();
        flb_service_set(ctx, "flush", "1", "grace", "1",
                        "log_level", "error", NULL);

        in_ffd = flb_input(ctx, (char *) "lib", NULL);
        TEST_CHECK(in_ffd >= 0);
        flb_input_set(ctx, in_ffd, "tag", "test", NULL);

        out_ffd = flb_output(ctx, (char *) "logdna", NULL);
        TEST_CHECK(out_ffd >= 0);
        flb_output_set(ctx, out_ffd,
                       "match", "test",
                       "api_key", "test-key",
                       NULL);

        flb_output_set_test(ctx, out_ffd, "formatter",
                            cb_lifecycle_noop, NULL, NULL);

        ret = flb_start(ctx);
        TEST_CHECK(ret == 0);

        flb_lib_push(ctx, in_ffd,
                     (char *) JSON_WITH_PRIMARY_KEYS,
                     sizeof(JSON_WITH_PRIMARY_KEYS) - 1);

        sleep(1);
        flb_stop(ctx);
        flb_destroy(ctx);
    }
}

TEST_LIST = {
    {"non_duplication",            flb_test_non_duplication},
    {"data_completeness",          flb_test_data_completeness},
    {"severity_promoted_as_level", flb_test_severity_promoted_as_level},
    {"level_and_severity",         flb_test_level_and_severity},
    {"default_app",                flb_test_default_app},
    {"no_primary_keys",            flb_test_no_primary_keys},
    {"payload_structure",          flb_test_payload_structure},
    {"backward_compat",            flb_test_backward_compat},
    {"lifecycle",                  flb_test_lifecycle},
    {NULL, NULL}
};
