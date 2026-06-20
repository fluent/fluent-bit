/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#include "flb_tests_runtime.h"

/* JSON payload example */
#include "data/datadog/json.h"

/*
 * Fluent Bit Datadog plugin, always set as payload a JSON strings contained in a
 * 'sds'. Since we want to validate specific keys and it values we expose here some
 * helper functions to make testing easier.
 *
 * The approach is:
 *
 * - Convert formatter JSON to msgpack
 * - use the helper function to check keys and values
 *
 * it returns FLB_TRUE if expected 'key/val' matches or FLB_FALSE if 'key' no exists
 * or if there is a mismatch.
 */
static int mp_kv_cmp(char *json_data, size_t json_len, char *key_accessor, char *val)
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

    /* Convert JSON to msgpack */
    ret = flb_pack_json((const char *) json_data, json_len, &mp_buf, &mp_size,
                        &type, NULL);
    TEST_CHECK(ret != -1);

    /* Set return status */
    ret = FLB_FALSE;

    /* Unpack msgpack and reference the main 'map' */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, mp_buf, mp_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    map = result.data;

    /* Create a record_accessor context */
    ra = flb_ra_create(key_accessor, FLB_TRUE);
    if (!ra) {
        flb_error("invalid record accessor key, aborting test");
        goto out;
    }

    rval = flb_ra_get_value_object(ra, map);
    TEST_CHECK(rval != NULL);
    msgpack_unpacked_destroy(&result);
    if (!rval) {
        goto out;
    }

    /* We only validate strings, feel free to expand it as needed */
    TEST_CHECK(rval->type == FLB_RA_STRING);
    if (strcmp(rval->val.string, val) == 0) {
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

static void cb_check_dd_properties(void *ctx, int ffd,
                                   int res_ret, void *res_data, size_t res_size,
                                   void *data)
{
    int ret;

    /* source */
    ret = mp_kv_cmp((char *) res_data + 1, res_size - 2, "$ddsource", "my-app");
    TEST_CHECK(ret == FLB_TRUE);

    /* service */
    ret = mp_kv_cmp((char *) res_data + 1, res_size - 2, "$service", "my-app-service");
    TEST_CHECK(ret == FLB_TRUE);

    /* ddtags */
    ret = mp_kv_cmp((char *) res_data + 1, res_size - 2, "$ddtags", "project:dev");
    TEST_CHECK(ret == FLB_TRUE);

    flb_sds_destroy(res_data);
}

void flb_test_dd_properties()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Datadog output */
    out_ffd = flb_output(ctx, (char *) "datadog", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "provider", "ecs",
                   "dd_service", "my-app-service",
                   "dd_source", "my-app",
                   "dd_tags",   "project:dev",
                   "apikey", "abc",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_dd_properties,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(1);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON, sizeof(JSON) - 1);

    sleep(2);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    { "dd_properties", flb_test_dd_properties },
    { NULL, NULL}
};
