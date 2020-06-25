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
#include "data/stackdriver/stackdriver_test_operation.h"
#include "data/stackdriver/stackdriver_test_k8s_resource.h"

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

static int mp_kv_cmp_integer(char *json_data, size_t json_len, char *key_accessor, int64_t val)
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

    rval = flb_ra_get_value_object(ra, map);
    TEST_CHECK(rval != NULL);
    msgpack_unpacked_destroy(&result);
    if (!rval) {
        goto out;
    }

    TEST_CHECK(rval->type == FLB_RA_INT);
    if (rval->val.i64 == val) {
        ret = FLB_TRUE;
    }
    else {
        ret = FLB_FALSE;
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

static int mp_kv_cmp_boolean(char *json_data, size_t json_len, char *key_accessor, bool val)
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

    rval = flb_ra_get_value_object(ra, map);
    TEST_CHECK(rval != NULL);
    msgpack_unpacked_destroy(&result);
    if (!rval) {
        goto out;
    }

    TEST_CHECK(rval->type == FLB_RA_BOOL);
    if (rval->val.boolean == val) {
        ret = FLB_TRUE;
    }
    else {
        ret = FLB_FALSE;
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

static int mp_kv_exists(char *json_data, size_t json_len, char *key_accessor)
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

    rval = flb_ra_get_value_object(ra, map);
    msgpack_unpacked_destroy(&result);
    if (rval) {
        ret = FLB_TRUE;
    }
    else {
        ret = FLB_FALSE;
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

static void cb_check_k8s_container_resource(void *ctx, int ffd,
                                            int res_ret, void *res_data, size_t res_size,
                                            void *data)
{
    int ret;

    /* resource type */
    ret = mp_kv_cmp(res_data, res_size, "$resource['type']", "k8s_container");
    TEST_CHECK(ret == FLB_TRUE);

    /* project id */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['project_id']", "fluent-bit");
    TEST_CHECK(ret == FLB_TRUE);

    /* location */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['location']", "test_cluster_location");
    TEST_CHECK(ret == FLB_TRUE);

    /* cluster name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['cluster_name']", "test_cluster_name");
    TEST_CHECK(ret == FLB_TRUE);

    /* namespace name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['namespace_name']", "testnamespace");
    TEST_CHECK(ret == FLB_TRUE);

    /* pod name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['pod_name']", "testpod");
    TEST_CHECK(ret == FLB_TRUE);

    /* container name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['container_name']", "testctr");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `local_resource_id` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size,
                       "$entries[0]['jsonPayload']['logging.googleapis.com/local_resource_id']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_k8s_node_resource(void *ctx, int ffd,
                                       int res_ret, void *res_data, size_t res_size,
                                       void *data)
{
    int ret;

    /* resource type */
    ret = mp_kv_cmp(res_data, res_size, "$resource['type']", "k8s_node");
    TEST_CHECK(ret == FLB_TRUE);

    /* project id */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['project_id']", "fluent-bit");
    TEST_CHECK(ret == FLB_TRUE);

    /* location */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['location']", "test_cluster_location");
    TEST_CHECK(ret == FLB_TRUE);

    /* cluster name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['cluster_name']", "test_cluster_name");
    TEST_CHECK(ret == FLB_TRUE);

    /* node name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['node_name']", "testnode");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `local_resource_id` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size,
                       "$entries[0]['jsonPayload']['logging.googleapis.com/local_resource_id']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_k8s_pod_resource(void *ctx, int ffd,
                                      int res_ret, void *res_data, size_t res_size,
                                      void *data)
{
    int ret;

    /* resource type */
    ret = mp_kv_cmp(res_data, res_size, "$resource['type']", "k8s_pod");
    TEST_CHECK(ret == FLB_TRUE);

    /* project id */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['project_id']", "fluent-bit");
    TEST_CHECK(ret == FLB_TRUE);

    /* location */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['location']", "test_cluster_location");
    TEST_CHECK(ret == FLB_TRUE);

    /* cluster name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['cluster_name']", "test_cluster_name");
    TEST_CHECK(ret == FLB_TRUE);

    /* namespace name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['namespace_name']", "testnamespace");
    TEST_CHECK(ret == FLB_TRUE);

    /* pod name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['pod_name']", "testpod");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `local_resource_id` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size,
                       "$entries[0]['jsonPayload']['logging.googleapis.com/local_resource_id']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_operation_common_case(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    int ret;

    /* operation_id */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['id']", "test_id");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_producer */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['producer']", "test_producer");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_first */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['first']", true);
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_last */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['last']", true);
    TEST_CHECK(ret == FLB_TRUE);

    /* check `operation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/operation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_empty_operation(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    int ret;

    /* operation_id */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['id']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_producer */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['producer']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_first */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['first']", false);
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_last */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['last']", false);
    TEST_CHECK(ret == FLB_TRUE);

    /* check `operation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/operation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_operation_in_string(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    int ret;

    /* 'operation' is not a map, won't be extracted from jsonPayload */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/operation']", "some string");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_exists(res_data, res_size, "$entries[0]['operation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}


static void cb_check_operation_partial_subfields(void *ctx, int ffd,
                                                 int res_ret, void *res_data, size_t res_size,
                                                 void *data)
{
    int ret;

    /* operation_id */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['id']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_producer */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['producer']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_first */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['first']", false);
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_last */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['last']", false);
    TEST_CHECK(ret == FLB_TRUE);

    /* check `operation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/operation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_operation_incorrect_type_subfields(void *ctx, int ffd,
                                                        int res_ret, void *res_data, size_t res_size,
                                                        void *data)
{
    int ret;

    /* operation_id */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['id']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_producer */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['producer']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_first */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['first']", false);
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_last */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['last']", false);
    TEST_CHECK(ret == FLB_TRUE);

    /* check `operation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/operation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_operation_extra_subfields(void *ctx, int ffd,
                                               int res_ret, void *res_data, size_t res_size,
                                               void *data)
{
    int ret;

    /* operation_id */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['id']", "test_id");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_producer */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['operation']['producer']", "test_producer");
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_first */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['first']", true);
    TEST_CHECK(ret == FLB_TRUE);

    /* operation_last */
    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['operation']['last']", true);
    TEST_CHECK(ret == FLB_TRUE);

    /* Preserve extra subfields inside jsonPayload */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/operation']['extra_key1']", "extra_val1");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/operation']['extra_key2']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/operation']['extra_key3']", true);
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
                              NULL, NULL);

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
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_operation_common()
{
    int ret;
    int size = sizeof(OPERATION_COMMON_CASE) - 1;
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
                              cb_check_operation_common_case,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) OPERATION_COMMON_CASE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_empty_operation()
{
    int ret;
    int size = sizeof(EMPTY_OPERATION) - 1;
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
                              cb_check_empty_operation,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) EMPTY_OPERATION, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_operation_in_string()
{
    int ret;
    int size = sizeof(OPERATION_IN_STRING) - 1;
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
                              cb_check_operation_in_string,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) OPERATION_IN_STRING, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_operation_partial_subfields()
{
    int ret;
    int size = sizeof(PARTIAL_SUBFIELDS) - 1;
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
                              cb_check_operation_partial_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) PARTIAL_SUBFIELDS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_operation_incorrect_type_subfields()
{
    int ret;
    int size = sizeof(SUBFIELDS_IN_INCORRECT_TYPE) - 1;
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
                              cb_check_operation_incorrect_type_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) SUBFIELDS_IN_INCORRECT_TYPE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_operation_extra_subfields()
{
    int ret;
    int size = sizeof(EXTRA_SUBFIELDS_EXISTED) - 1;
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
                              cb_check_operation_extra_subfields,
                              NULL, NULL);
    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) EXTRA_SUBFIELDS_EXISTED, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_container_common()
{
    int ret;
    int size = sizeof(K8S_CONTAINER_COMMON) - 1;
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
                   "resource", "k8s_container",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "k8s_cluster_name", "test_cluster_name",
                   "k8s_cluster_location", "test_cluster_location",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_k8s_container_resource,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) K8S_CONTAINER_COMMON, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_node_common()
{
    int ret;
    int size = sizeof(K8S_NODE_COMMON) - 1;
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
                   "resource", "k8s_node",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "k8s_cluster_name", "test_cluster_name",
                   "k8s_cluster_location", "test_cluster_location",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_k8s_node_resource,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) K8S_NODE_COMMON, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_pod_common()
{
    int ret;
    int size = sizeof(K8S_POD_COMMON) - 1;
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
                   "resource", "k8s_pod",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "k8s_cluster_name", "test_cluster_name",
                   "k8s_cluster_location", "test_cluster_location",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_k8s_pod_resource,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) K8S_POD_COMMON, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"resource_global", flb_test_resource_global },
    {"resource_gce_instance", flb_test_resource_gce_instance },
    {"operation_common_case", flb_test_operation_common},
    {"empty_operation", flb_test_empty_operation},
    {"operation_not_a_map", flb_test_operation_in_string},
    {"operation_partial_subfields", flb_test_operation_partial_subfields},
    {"operation_subfields_in_incorrect_type", flb_test_operation_incorrect_type_subfields},
    {"operation_extra_subfields_exist", flb_test_operation_extra_subfields},
    {"resource_k8s_container_common", flb_test_resource_k8s_container_common },
    {"resource_k8s_node_common", flb_test_resource_k8s_node_common },
    {"resource_k8s_pod_common", flb_test_resource_k8s_pod_common },
    {NULL, NULL}
};
