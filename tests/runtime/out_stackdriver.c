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

/* Local 'test' credentials file */
#define SERVICE_CREDENTIALS \
    FLB_TESTS_DATA_PATH "/data/stackdriver/stackdriver-credentials.json"

/* JSON payload example */
#include "data/stackdriver/json.h"

/*
 * Fluent Bit Stackdriver plugin, always set as payload a JSON strings contained in a
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
                        &type);
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

    /* Process map using the record_accessor */
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

static void cb_check_global_resource(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$resource['type']", "global");
    TEST_CHECK(ret == FLB_TRUE);
    flb_sds_destroy(res_data);
}

static void cb_check_gce_instance(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    int ret;

    /* resource type */
    ret = mp_kv_cmp(res_data, res_size, "$resource['type']", "gce_instance");
    TEST_CHECK(ret == FLB_TRUE);

    /* project id */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['project_id']", "111222333");
    TEST_CHECK(ret == FLB_TRUE);

    /* zone */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['zone']", "fluent");
    TEST_CHECK(ret == FLB_TRUE);

    /* instance_id */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['instance_id']", "333222111");
    TEST_CHECK(ret == FLB_TRUE);

    flb_sds_destroy(res_data);
}

void flb_test_resource_global()
{
    int ret;
    int size = sizeof(JSON) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "resource", "global",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_global_resource,
                              NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_gce_instance()
{
    int ret;
    int size = sizeof(JSON) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "resource", "gce_instance",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_gce_instance,
                              NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"resource_global"      , flb_test_resource_global },
    {"resource_gce_instance", flb_test_resource_gce_instance },
    {NULL, NULL}
};
