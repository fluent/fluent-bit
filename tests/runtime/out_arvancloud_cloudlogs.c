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

#include <stdarg.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#include "flb_tests_runtime.h"

/*
 * The ArvanCloud CloudLogs output plugin formats events as a JSON object:
 *
 *   {
 *     "logs": [
 *       {
 *         "logType":   "<string>",
 *         "timestamp": "<RFC3339 UTC>",
 *         "severity":  "INFO",
 *         "resource":  { "type": "general" },
 *         "payload":   { ...original record... }
 *         (optional)   "<tag_key>": "<tag>"   if include_tag_key=true
 *       },
 *       ...
 *     ]
 *   }
 *
 * Tests use the formatter test mode (cb_check_*) to intercept the formatted
 * JSON payload before any HTTP request is sent. This means we don't need a
 * live endpoint to validate the plugin's behavior.
 */

#define JSON_BASIC \
    "[1448403340, {\"key\":\"value\",\"foo\":\"bar\"}]"

#define JSON_WITH_LOG_TYPE \
    "[1448403340, {\"key\":\"value\",\"category\":\"security\"}]"

#define JSON_WITH_TIMESTAMP \
    "[1448403340, {\"key\":\"value\",\"ts\":\"2024-01-15T10:30:45Z\"}]"

/*
 * Convert a formatted JSON payload into msgpack and validate that the value
 * referenced by `key_accessor` equals `val`.
 *
 * Returns FLB_TRUE on match, FLB_FALSE otherwise.
 */
static int mp_kv_cmp(char *json_data, size_t json_len,
                     char *key_accessor, char *val)
{
    int ret;
    int type;
    char *mp_buf = NULL;
    size_t mp_size;
    size_t off = 0;
    msgpack_object map;
    msgpack_unpacked result;
    struct flb_ra_value *rval = NULL;
    struct flb_record_accessor *ra = NULL;

    ret = flb_pack_json((const char *) json_data, json_len, &mp_buf, &mp_size,
                        &type, NULL);
    TEST_CHECK(ret != -1);

    ret = FLB_FALSE;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, mp_buf, mp_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    map = result.data;

    ra = flb_ra_create(key_accessor, FLB_TRUE);
    if (!ra) {
        flb_error("invalid record accessor key '%s', aborting test",
                  key_accessor);
        goto out;
    }

    rval = flb_ra_get_value_object(ra, map);
    TEST_CHECK(rval != NULL);
    msgpack_unpacked_destroy(&result);
    if (!rval) {
        goto out;
    }

    TEST_CHECK(rval->type == FLB_RA_STRING);
    if (rval->type == FLB_RA_STRING && strcmp(rval->val.string, val) == 0) {
        ret = FLB_TRUE;
    }

 out:
    if (rval) {
        flb_ra_key_value_destroy(rval);
    }
    if (ra) {
        flb_ra_destroy(ra);
    }
    if (mp_buf) {
        flb_free(mp_buf);
    }
    return ret;
}

/*
 * Basic shape check: the payload must contain the expected top-level keys
 * (`logs` array) and per-record fields (`logType`, `timestamp`, `severity`,
 * `resource`, `payload`).
 */
static void cb_check_basic_shape(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    flb_sds_t out_js = res_data;

    /* Top-level "logs" array */
    if (!TEST_CHECK(strstr(out_js, "\"logs\":[") != NULL)) {
        TEST_MSG("missing top-level \"logs\" array. Given:%s", out_js);
    }

    /* Required per-record fields */
    if (!TEST_CHECK(strstr(out_js, "\"logType\":") != NULL)) {
        TEST_MSG("missing logType. Given:%s", out_js);
    }
    if (!TEST_CHECK(strstr(out_js, "\"timestamp\":") != NULL)) {
        TEST_MSG("missing timestamp. Given:%s", out_js);
    }
    if (!TEST_CHECK(strstr(out_js, "\"severity\":\"INFO\"") != NULL)) {
        TEST_MSG("missing severity. Given:%s", out_js);
    }
    if (!TEST_CHECK(strstr(out_js, "\"resource\":{\"type\":\"general\"}") != NULL)) {
        TEST_MSG("missing/wrong resource. Given:%s", out_js);
    }
    if (!TEST_CHECK(strstr(out_js, "\"payload\":") != NULL)) {
        TEST_MSG("missing payload. Given:%s", out_js);
    }

    /* Original record fields must be preserved verbatim inside payload */
    if (!TEST_CHECK(strstr(out_js, "\"key\":\"value\"") != NULL)) {
        TEST_MSG("original record key not preserved. Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/* Default log_type is "fluentbit" when not configured. */
static void cb_check_default_log_type(void *ctx, int ffd,
                                      int res_ret, void *res_data, size_t res_size,
                                      void *data)
{
    int ret;
    flb_sds_t out_js = res_data;

    /* res_data is a JSON map: { "logs": [ {...} ] } */
    ret = mp_kv_cmp((char *) out_js, res_size,
                    "$logs[0]['logType']", "fluentbit");
    if (!TEST_CHECK(ret == FLB_TRUE)) {
        TEST_MSG("expected default logType=fluentbit. Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/* When log_type is configured, it must override the default. */
static void cb_check_configured_log_type(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    int ret;
    flb_sds_t out_js = res_data;

    ret = mp_kv_cmp((char *) out_js, res_size,
                    "$logs[0]['logType']", "myapp");
    if (!TEST_CHECK(ret == FLB_TRUE)) {
        TEST_MSG("expected logType=myapp. Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/*
 * When log_type_key is configured and the referenced field exists in the
 * record, it takes priority over the static log_type value.
 */
static void cb_check_log_type_key(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    int ret;
    flb_sds_t out_js = res_data;

    ret = mp_kv_cmp((char *) out_js, res_size,
                    "$logs[0]['logType']", "security");
    if (!TEST_CHECK(ret == FLB_TRUE)) {
        TEST_MSG("expected logType extracted from record. Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/*
 * If log_type_key is configured but the field is missing from the record,
 * the plugin must fall back to the configured/default log_type.
 */
static void cb_check_log_type_key_fallback(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    int ret;
    flb_sds_t out_js = res_data;

    ret = mp_kv_cmp((char *) out_js, res_size,
                    "$logs[0]['logType']", "fallback");
    if (!TEST_CHECK(ret == FLB_TRUE)) {
        TEST_MSG("expected fallback logType. Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/* With include_tag_key=true, the tag must appear under the configured key. */
static void cb_check_include_tag_key(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    flb_sds_t out_js = res_data;

    if (!TEST_CHECK(strstr(out_js, "\"fluentbit_tag\":\"test\"") != NULL)) {
        TEST_MSG("expected tag included with custom key. Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/*
 * When timestamp_key + timestamp_format are configured, the value from the
 * record must be parsed and re-emitted in canonical RFC3339 UTC form with
 * microseconds.
 */
static void cb_check_timestamp_from_record(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    int ret;
    flb_sds_t out_js = res_data;

    ret = mp_kv_cmp((char *) out_js, res_size,
                    "$logs[0]['timestamp']",
                    "2024-01-15T10:30:45.000000Z");
    if (!TEST_CHECK(ret == FLB_TRUE)) {
        TEST_MSG("expected normalized RFC3339 timestamp. Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/*
 * Helper: create a fluent-bit context wired to the arvancloud_cloudlogs
 * output in formatter test mode. The caller provides any additional
 * key/value config pairs (terminated by NULL).
 *
 * Returns a started context, plus *in_ffd_out for the lib input handle.
 */
static flb_ctx_t *create_ctx(int *in_ffd_out,
                             void (*cb)(void *, int, int, void *, size_t, void *),
                             ...)
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    va_list ap;
    const char *k;
    const char *v;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "arvancloud_cloudlogs", NULL);

    /* Required: apikey. Match all events tagged "test". */
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "apikey", "test-api-key",
                   NULL);

    /* Apply caller-provided extra config pairs. */
    va_start(ap, cb);
    while ((k = va_arg(ap, const char *)) != NULL) {
        v = va_arg(ap, const char *);
        flb_output_set(ctx, out_ffd, k, v, NULL);
    }
    va_end(ap);

    ret = flb_output_set_test(ctx, out_ffd, "formatter", cb, NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    *in_ffd_out = in_ffd;
    return ctx;
}

void flb_test_basic_shape()
{
    int in_ffd;
    flb_ctx_t *ctx;

    ctx = create_ctx(&in_ffd, cb_check_basic_shape, NULL);

    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, sizeof(JSON_BASIC) - 1);
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_default_log_type()
{
    int in_ffd;
    flb_ctx_t *ctx;

    ctx = create_ctx(&in_ffd, cb_check_default_log_type, NULL);

    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, sizeof(JSON_BASIC) - 1);
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_configured_log_type()
{
    int in_ffd;
    flb_ctx_t *ctx;

    ctx = create_ctx(&in_ffd, cb_check_configured_log_type,
                     "log_type", "myapp",
                     NULL);

    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, sizeof(JSON_BASIC) - 1);
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_log_type_key()
{
    int in_ffd;
    flb_ctx_t *ctx;

    ctx = create_ctx(&in_ffd, cb_check_log_type_key,
                     "log_type", "should-be-overridden",
                     "log_type_key", "$category",
                     NULL);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_WITH_LOG_TYPE,
                 sizeof(JSON_WITH_LOG_TYPE) - 1);
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_log_type_key_fallback()
{
    int in_ffd;
    flb_ctx_t *ctx;

    /* The record has no "missing_field"; expect fallback to log_type. */
    ctx = create_ctx(&in_ffd, cb_check_log_type_key_fallback,
                     "log_type", "fallback",
                     "log_type_key", "$missing_field",
                     NULL);

    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, sizeof(JSON_BASIC) - 1);
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_include_tag_key()
{
    int in_ffd;
    flb_ctx_t *ctx;

    ctx = create_ctx(&in_ffd, cb_check_include_tag_key,
                     "include_tag_key", "true",
                     "tag_key", "fluentbit_tag",
                     NULL);

    flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, sizeof(JSON_BASIC) - 1);
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_timestamp_from_record()
{
    int in_ffd;
    flb_ctx_t *ctx;

    ctx = create_ctx(&in_ffd, cb_check_timestamp_from_record,
                     "timestamp_key", "$ts",
                     "timestamp_format", "%Y-%m-%dT%H:%M:%SZ",
                     NULL);

    flb_lib_push(ctx, in_ffd,
                 (char *) JSON_WITH_TIMESTAMP,
                 sizeof(JSON_WITH_TIMESTAMP) - 1);
    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
    { "basic_shape",            flb_test_basic_shape },
    { "default_log_type",       flb_test_default_log_type },
    { "configured_log_type",    flb_test_configured_log_type },
    { "log_type_key",           flb_test_log_type_key },
    { "log_type_key_fallback",  flb_test_log_type_key_fallback },
    { "include_tag_key",        flb_test_include_tag_key },
    { "timestamp_from_record",  flb_test_timestamp_from_record },
    { NULL, NULL }
};
