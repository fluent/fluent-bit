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
#define STACKDRIVER_DATA_PATH "/data/stackdriver"

/* JSON payload example */
#include "data/stackdriver/json.h"
#include "data/stackdriver/stackdriver_test_operation.h"
#include "data/stackdriver/stackdriver_test_k8s_resource.h"
#include "data/stackdriver/stackdriver_test_labels.h"
#include "data/stackdriver/stackdriver_test_insert_id.h"
#include "data/stackdriver/stackdriver_test_source_location.h"
#include "data/stackdriver/stackdriver_test_http_request.h"
#include "data/stackdriver/stackdriver_test_timestamp.h"


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

static void cb_check_k8s_container_resource_diff_tag(void *ctx, int ffd,
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
                    "$resource['labels']['namespace_name']", "diffnamespace");
    TEST_CHECK(ret == FLB_TRUE);

    /* pod name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['pod_name']", "diffpod");
    TEST_CHECK(ret == FLB_TRUE);

    /* container name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['container_name']", "diffctr");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `local_resource_id` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size,
                       "$entries[0]['jsonPayload']['logging.googleapis.com/local_resource_id']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_k8s_container_resource_default_regex(void *ctx, int ffd,
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
                    "$resource['labels']['namespace_name']", "default");
    TEST_CHECK(ret == FLB_TRUE);

    /* pod name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['pod_name']", "apache-logs-annotated");
    TEST_CHECK(ret == FLB_TRUE);

    /* container name */
    ret = mp_kv_cmp(res_data, res_size,
                    "$resource['labels']['container_name']", "apache");
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

static void cb_check_insert_id_common_case(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    int ret;

    /* insertId in the entries */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['insertId']", "test_insertId");
    TEST_CHECK(ret == FLB_TRUE);

    /* insertId has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/insertId']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_empty_insert_id(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    TEST_CHECK(res_size == 0);

    flb_sds_destroy(res_data);
}

static void cb_check_insert_id_incorrect_type(void *ctx, int ffd,
                                              int res_ret, void *res_data, size_t res_size,
                                              void *data)
{
    TEST_CHECK(res_size == 0);

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

static void cb_check_default_labels(void *ctx, int ffd,
                                    int res_ret, void *res_data, size_t res_size,
                                    void *data)
{
    int ret;

    /* check 'labels' field has been added to root-level of log entry */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check fields inside 'labels' field */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']['testA']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check field inside 'labels' field */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']['testB']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `labels_key` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/labels']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_custom_labels(void *ctx, int ffd,
                                   int res_ret, void *res_data, size_t res_size,
                                   void *data)
{
    int ret;

    /* check 'labels' field has been added to root-level of log entry */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check fields inside 'labels' field */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']['testA']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check field inside 'labels' field */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']['testB']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `labels_key` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/customlabels']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_default_labels_k8s_resource_type(void *ctx, int ffd,
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

    /* check 'labels' field has been added to root-level of log entry */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check fields inside 'labels' field */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']['testA']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check field inside 'labels' field */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']['testB']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `labels_key` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/labels']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_custom_labels_k8s_resource_type(void *ctx, int ffd,
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

    /* check 'labels' field has been added to root-level of log entry */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check fields inside 'labels' field */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']['testA']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check field inside 'labels' field */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['labels']['testB']");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `labels_key` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/customlabels']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_multi_entries_severity(void *ctx, int ffd,
                                            int res_ret, void *res_data, size_t res_size,
                                            void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['severity']", "INFO");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_exists(res_data, res_size, "$entries[1]['severity']");
    TEST_CHECK(ret == FLB_FALSE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[2]['severity']", "DEBUG");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_exists(res_data, res_size, "$entries[3]['severity']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_source_location_common_case(void *ctx, int ffd,
                                                 int res_ret, void *res_data, size_t res_size,
                                                 void *data)
{
    int ret;

    /* sourceLocation_file */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['file']", "test_file");
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_line */
    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['sourceLocation']['line']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_function */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['function']", "test_function");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `sourceLocation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_source_location_common_case_line_in_string(void *ctx, int ffd,
                                                                int res_ret, void *res_data, size_t res_size,
                                                                void *data)
{
    int ret;

    /* sourceLocation_file */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['file']", "test_file");
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_line */
    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['sourceLocation']['line']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_function */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['function']", "test_function");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `sourceLocation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_empty_source_location(void *ctx, int ffd,
                                           int res_ret, void *res_data, size_t res_size,
                                           void *data)
{
    int ret;

    /* sourceLocation_file */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['file']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_line */
    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['sourceLocation']['line']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_function */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['function']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `sourceLocation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_source_location_in_string(void *ctx, int ffd,
                                               int res_ret, void *res_data, size_t res_size,
                                               void *data)
{
    int ret;

    /* sourceLocation remains in jsonPayload */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']", "some string");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_exists(res_data, res_size, "$entries[0]['sourceLocation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_source_location_partial_subfields(void *ctx, int ffd,
                                                       int res_ret, void *res_data, size_t res_size,
                                                       void *data)
{
    int ret;

    /* sourceLocation_file */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['file']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_line */
    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['sourceLocation']['line']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_function */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['function']", "test_function");
    TEST_CHECK(ret == FLB_TRUE);


    /* check `sourceLocation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_source_location_incorrect_type_subfields(void *ctx, int ffd,
                                                              int res_ret, void *res_data, size_t res_size,
                                                              void *data)
{
    int ret;

    /* sourceLocation_file */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['file']", "");
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_line */
    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['sourceLocation']['line']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_function */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['function']", "");
    TEST_CHECK(ret == FLB_TRUE);


    /* check `sourceLocation` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_source_location_extra_subfields(void *ctx, int ffd,
                                                     int res_ret, void *res_data, size_t res_size,
                                                     void *data)
{
    int ret;

    /* sourceLocation_file */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['file']", "test_file");
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_line */
    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['sourceLocation']['line']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    /* sourceLocation_function */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['sourceLocation']['function']", "test_function");
    TEST_CHECK(ret == FLB_TRUE);

    /* Preserve extra subfields inside jsonPayload */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']['extra_key1']", "extra_val1");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']['extra_key2']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/sourceLocation']['extra_key3']", true);
    TEST_CHECK(ret == FLB_TRUE);

    flb_sds_destroy(res_data);
}

static void cb_check_http_request_common_case(void *ctx, int ffd,
                                             int res_ret, void *res_data, size_t res_size,
                                             void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestMethod']", "test_requestMethod");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestUrl']", "test_requestUrl");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['userAgent']", "test_userAgent");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['remoteIp']", "test_remoteIp");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['serverIp']", "test_serverIp");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['referer']", "test_referer");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['protocol']", "test_protocol");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['latency']", "0s");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['requestSize']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['responseSize']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['status']", 200);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['cacheFillBytes']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheLookup']", true);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheHit']", true);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheValidatedWithOriginServer']", true);
    TEST_CHECK(ret == FLB_TRUE);

    /* check `httpRequest` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_empty_http_request(void *ctx, int ffd,
                                        int res_ret, void *res_data, size_t res_size,
                                        void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestMethod']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestUrl']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['userAgent']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['remoteIp']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['serverIp']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['referer']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['protocol']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_exists(res_data, res_size,  "$entries[0]['httpRequest']['latency']");
    TEST_CHECK(ret == FLB_FALSE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['requestSize']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['responseSize']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['status']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['cacheFillBytes']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheLookup']", false);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheHit']", false);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheValidatedWithOriginServer']", false);
    TEST_CHECK(ret == FLB_TRUE);

    /* check `httpRequest` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_http_request_in_string(void *ctx, int ffd,
                                            int res_ret, void *res_data, size_t res_size,
                                            void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']", "some string");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_exists(res_data, res_size, "$entries[0]['httpRequest']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_http_request_partial_subfields(void *ctx, int ffd,
                                                    int res_ret, void *res_data, size_t res_size,
                                                    void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestMethod']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestUrl']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['userAgent']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['remoteIp']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['serverIp']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['referer']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['protocol']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_exists(res_data, res_size,  "$entries[0]['httpRequest']['latency']");
    TEST_CHECK(ret == FLB_FALSE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['requestSize']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['responseSize']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['status']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['cacheFillBytes']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheLookup']", true);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheHit']", true);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheValidatedWithOriginServer']", true);
    TEST_CHECK(ret == FLB_TRUE);

    /* check `httpRequest` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_http_request_incorrect_type_subfields(void *ctx, int ffd,
                                                           int res_ret, void *res_data, size_t res_size,
                                                           void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestMethod']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestUrl']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['userAgent']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['remoteIp']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['serverIp']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['referer']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['protocol']", "");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_exists(res_data, res_size,  "$entries[0]['httpRequest']['latency']");
    TEST_CHECK(ret == FLB_FALSE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['requestSize']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['responseSize']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['status']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['cacheFillBytes']", 0);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheLookup']", false);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheHit']", false);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheValidatedWithOriginServer']", false);
    TEST_CHECK(ret == FLB_TRUE);

    /* check `httpRequest` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_http_request_extra_subfields(void *ctx, int ffd,
                                                  int res_ret, void *res_data, size_t res_size,
                                                  void *data)
{
     int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestMethod']", "test_requestMethod");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['requestUrl']", "test_requestUrl");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['userAgent']", "test_userAgent");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['remoteIp']", "test_remoteIp");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['serverIp']", "test_serverIp");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['referer']", "test_referer");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['protocol']", "test_protocol");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['latency']", "0s");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['requestSize']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['responseSize']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['status']", 200);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['httpRequest']['cacheFillBytes']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheLookup']", true);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheHit']", true);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['httpRequest']['cacheValidatedWithOriginServer']", true);
    TEST_CHECK(ret == FLB_TRUE);

    /* Preserve extra subfields inside jsonPayload */
    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']['extra_key1']", "extra_val1");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_integer(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']['extra_key2']", 123);
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp_boolean(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']['extra_key3']", true);
    TEST_CHECK(ret == FLB_TRUE);

    flb_sds_destroy(res_data);
}

static void cb_check_http_request_lantency_common_case(void *ctx, int ffd,
                                                       int res_ret, void *res_data, size_t res_size,
                                                       void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['httpRequest']['latency']", "100.00s");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `httpRequest` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_http_request_latency_incorrect_format(void *ctx, int ffd,
                                                           int res_ret, void *res_data, size_t res_size,
                                                           void *data)
{
    int ret;

    ret = mp_kv_exists(res_data, res_size, "$entries[0]['httpRequest']['latency']");
    TEST_CHECK(ret == FLB_FALSE);

    /* check `httpRequest` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['logging.googleapis.com/http_request']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_timestamp_format_object_common_case(void *ctx, int ffd,
                                                         int res_ret, void *res_data, size_t res_size,
                                                         void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['timestamp']", "2020-07-21T16:40:42.000012345Z");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `timestamp` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['timestamp']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_timestamp_format_object_not_a_map(void *ctx, int ffd,
                                                       int res_ret, void *res_data, size_t res_size,
                                                       void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['timestamp']", "2020-07-21T16:40:00.000000000Z");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['timestamp']", "string");
    TEST_CHECK(ret == FLB_TRUE);

    flb_sds_destroy(res_data);
}

static void cb_check_timestamp_format_object_missing_subfield(void *ctx, int ffd,
                                                              int res_ret, void *res_data,
                                                              size_t res_size,
                                                              void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['timestamp']", "2020-07-21T16:40:00.000000000Z");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['timestamp']['nanos']", "12345");
    TEST_CHECK(ret == FLB_TRUE);

    flb_sds_destroy(res_data);
}

static void cb_check_timestamp_format_object_incorrect_subfields(void *ctx, int ffd,
                                                                 int res_ret, void *res_data,
                                                                 size_t res_size,
                                                                 void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['timestamp']", "2020-07-21T16:40:00.000000000Z");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `timestamp` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['timestamp']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_timestamp_format_duo_fields_common_case(void *ctx, int ffd,
                                                             int res_ret, void *res_data, size_t res_size,
                                                             void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['timestamp']", "2020-07-21T16:40:42.000012345Z");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `timestampSeconds` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['timestampSeconds']");
    TEST_CHECK(ret == FLB_FALSE);

    /* check `timestampNanos` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['timestampNanos']");
    TEST_CHECK(ret == FLB_FALSE);

    flb_sds_destroy(res_data);
}

static void cb_check_timestamp_format_duo_fields_missing_nanos(void *ctx, int ffd,
                                                               int res_ret, void *res_data, size_t res_size,
                                                               void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['timestamp']", "2020-07-21T16:40:00.000000000Z");
    TEST_CHECK(ret == FLB_TRUE);

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['jsonPayload']['timestampSeconds']", "1595349642");
    TEST_CHECK(ret == FLB_TRUE);

    flb_sds_destroy(res_data);
}

static void cb_check_timestamp_format_duo_fields_incorrect_type(void *ctx, int ffd,
                                                                int res_ret, void *res_data, size_t res_size,
                                                                void *data)
{
    int ret;

    ret = mp_kv_cmp(res_data, res_size, "$entries[0]['timestamp']", "2020-07-21T16:40:00.000000000Z");
    TEST_CHECK(ret == FLB_TRUE);

    /* check `timestampSeconds` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['timestampSeconds']");
    TEST_CHECK(ret == FLB_FALSE);

    /* check `timestampNanos` has been removed from jsonPayload */
    ret = mp_kv_exists(res_data, res_size, "$entries[0]['jsonPayload']['timestampNanos']");
    TEST_CHECK(ret == FLB_FALSE);

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

void flb_test_resource_global_custom_prefix()
{
    /* configuring tag_prefix for non-k8s resource type should have no effect at all */
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
                   "tag_prefix", "custom_tag.",
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

void flb_test_insert_id_common_case()
{
    int ret;
    int size = sizeof(INSERTID_COMMON_CASE) - 1;
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
                              cb_check_insert_id_common_case,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) INSERTID_COMMON_CASE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_empty_insert_id()
{
    int ret;
    int size = sizeof(EMPTY_INSERTID) - 1;
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
                              cb_check_empty_insert_id,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) EMPTY_INSERTID, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_insert_id_incorrect_type()
{
    int ret;
    int size = sizeof(INSERTID_INCORRECT_TYPE_INT) - 1;
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
                              cb_check_insert_id_incorrect_type,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) INSERTID_INCORRECT_TYPE_INT, size);

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

void flb_test_resource_k8s_container_multi_tag_value()
{
    int ret;
    int size_one = sizeof(K8S_CONTAINER_COMMON) - 1;
    int size_two = sizeof(K8S_CONTAINER_COMMON_DIFF_TAGS) - 1;

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
    flb_lib_push(ctx, in_ffd, (char *) K8S_CONTAINER_COMMON_DIFF_TAGS, size_one);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_k8s_container_resource_diff_tag,
                              NULL, NULL);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) K8S_CONTAINER_COMMON_DIFF_TAGS, size_two);


    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_container_custom_tag_prefix()
{
    int ret;
    int size = sizeof(K8S_CONTAINER_NO_LOCAL_RESOURCE_ID) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "kube_custom_tag.testnamespace.testpod.testctr", NULL);

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "kube_custom_tag.*",
                   "resource", "k8s_container",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "k8s_cluster_name", "test_cluster_name",
                   "k8s_cluster_location", "test_cluster_location",
                   "tag_prefix", "kube_custom_tag.",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_k8s_container_resource,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) K8S_CONTAINER_NO_LOCAL_RESOURCE_ID, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_container_custom_tag_prefix_with_dot()
{
    int ret;
    int size = sizeof(K8S_CONTAINER_NO_LOCAL_RESOURCE_ID) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "kube.custom.tag.testnamespace.testpod.testctr", NULL);

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "kube.custom.tag.*",
                   "resource", "k8s_container",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "k8s_cluster_name", "test_cluster_name",
                   "k8s_cluster_location", "test_cluster_location",
                   "tag_prefix", "kube.custom.tag.",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_k8s_container_resource,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) K8S_CONTAINER_NO_LOCAL_RESOURCE_ID, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_container_default_tag_regex()
{
    int ret;
    int size = sizeof(K8S_CONTAINER_NO_LOCAL_RESOURCE_ID) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag",
                  "kube.var.log.containers.apache-logs-annotated_default_apache-aeeccc7a9f00f6e4e066aeff0434cf80621215071f1b20a51e8340aa7c35eac6.log", NULL);

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "kube.custom.tag.*",
                   "resource", "k8s_container",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "k8s_cluster_name", "test_cluster_name",
                   "k8s_cluster_location", "test_cluster_location",
                   "tag_prefix", "kube.var.log.containers.",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_k8s_container_resource_default_regex,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) K8S_CONTAINER_NO_LOCAL_RESOURCE_ID, size);

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

void flb_test_default_labels()
{
    int ret;
    int size = sizeof(DEFAULT_LABELS) - 1;
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
                   "resource", "global",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_default_labels,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) DEFAULT_LABELS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_custom_labels()
{
    int ret;
    int size = sizeof(CUSTOM_LABELS) - 1;
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
                   "resource", "global",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "labels_key", "logging.googleapis.com/customlabels",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_custom_labels,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) CUSTOM_LABELS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_default_labels_k8s_resource_type()
{
    int ret;
    int size = sizeof(DEFAULT_LABELS_K8S_RESOURCE_TYPE) - 1;
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
                              cb_check_default_labels_k8s_resource_type,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) DEFAULT_LABELS_K8S_RESOURCE_TYPE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_custom_labels_k8s_resource_type()
{
    int ret;
    int size = sizeof(CUSTOM_LABELS_K8S_RESOURCE_TYPE) - 1;
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
                   "labels_key", "logging.googleapis.com/customlabels",
                   "k8s_cluster_name", "test_cluster_name",
                   "k8s_cluster_location", "test_cluster_location",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_custom_labels_k8s_resource_type,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) CUSTOM_LABELS_K8S_RESOURCE_TYPE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_container_no_local_resource_id()
{
    int ret;
    int size = sizeof(K8S_CONTAINER_NO_LOCAL_RESOURCE_ID) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag",
                  "k8s_container.testnamespace.testpod.testctr", NULL);

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "k8s_container.*",
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
    flb_lib_push(ctx, in_ffd, (char *) K8S_CONTAINER_NO_LOCAL_RESOURCE_ID, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_node_no_local_resource_id()
{
    int ret;
    int size = sizeof(K8S_NODE_NO_LOCAL_RESOURCE_ID) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "k8s_node.testnode", NULL);

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "k8s_node.*",
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
    flb_lib_push(ctx, in_ffd, (char *) K8S_NODE_NO_LOCAL_RESOURCE_ID, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_resource_k8s_pod_no_local_resource_id()
{
    int ret;
    int size = sizeof(K8S_POD_NO_LOCAL_RESOURCE_ID) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "k8s_pod.testnamespace.testpod", NULL);

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "k8s_pod.*",
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
    flb_lib_push(ctx, in_ffd, (char *) K8S_POD_NO_LOCAL_RESOURCE_ID, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_multi_entries_severity()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    ret = flb_service_set(ctx, "flush", "1", "grace", "1", NULL);
    TEST_CHECK_(ret == 0, "setting service options");

    /* Tail input mode */
    in_ffd = flb_input(ctx, (char *) "tail", NULL);
    ret = flb_input_set(ctx, in_ffd,
                        "Path", STACKDRIVER_DATA_PATH "/stackdriver_multi_entries_severity.log",
                        "tag", "test",
                        NULL);
    TEST_CHECK_(ret == 0, "setting input options");

    /* Stackdriver output */
    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    ret = flb_output_set(ctx, out_ffd,
                        "match", "test",
                        "resource", "gce_instance",
                        "google_service_credentials", SERVICE_CREDENTIALS,
                        "severity_key", "severity",
                        NULL);
    TEST_CHECK_(ret == 0, "setting output options");

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_multi_entries_severity,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_source_location_common_case()
{
    int ret;
    int size = sizeof(SOURCELOCATION_COMMON_CASE) - 1;
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
                              cb_check_source_location_common_case,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) SOURCELOCATION_COMMON_CASE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_source_location_line_in_string()
{
    int ret;
    int size = sizeof(SOURCELOCATION_COMMON_CASE_LINE_IN_STRING) - 1;
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
                              cb_check_source_location_common_case_line_in_string,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) SOURCELOCATION_COMMON_CASE_LINE_IN_STRING, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_empty_source_location()
{
    int ret;
    int size = sizeof(EMPTY_SOURCELOCATION) - 1;
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
                              cb_check_empty_source_location,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) EMPTY_SOURCELOCATION, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_source_location_in_string()
{
    int ret;
    int size = sizeof(SOURCELOCATION_IN_STRING) - 1;
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
                              cb_check_source_location_in_string,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) SOURCELOCATION_IN_STRING, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_source_location_partial_subfields()
{
    int ret;
    int size = sizeof(PARTIAL_SOURCELOCATION) - 1;
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
                              cb_check_source_location_partial_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) PARTIAL_SOURCELOCATION, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_source_location_incorrect_type_subfields()
{
    int ret;
    int size = sizeof(SOURCELOCATION_SUBFIELDS_IN_INCORRECT_TYPE) - 1;
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
                              cb_check_source_location_incorrect_type_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) SOURCELOCATION_SUBFIELDS_IN_INCORRECT_TYPE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_source_location_extra_subfields()
{
    int ret;
    int size = sizeof(SOURCELOCATION_EXTRA_SUBFIELDS_EXISTED) - 1;
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
                              cb_check_source_location_extra_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) SOURCELOCATION_EXTRA_SUBFIELDS_EXISTED, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_common_case()
{
    int ret;
    int size = sizeof(HTTPREQUEST_COMMON_CASE) - 1;
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
                              cb_check_http_request_common_case,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) HTTPREQUEST_COMMON_CASE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_empty_http_request()
{
    int ret;
    int size = sizeof(EMPTY_HTTPREQUEST) - 1;
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
                              cb_check_empty_http_request,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) EMPTY_HTTPREQUEST, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_in_string()
{
    int ret;
    int size = sizeof(HTTPREQUEST_IN_STRING) - 1;
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
                              cb_check_http_request_in_string,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) HTTPREQUEST_IN_STRING, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_partial_subfields()
{
    int ret;
    int size = sizeof(PARTIAL_HTTPREQUEST) - 1;
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
                              cb_check_http_request_partial_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) PARTIAL_HTTPREQUEST, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_incorrect_type_subfields()
{
    int ret;
    int size = sizeof(HTTPREQUEST_SUBFIELDS_IN_INCORRECT_TYPE) - 1;
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
                              cb_check_http_request_incorrect_type_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) HTTPREQUEST_SUBFIELDS_IN_INCORRECT_TYPE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_extra_subfields()
{
    int ret;
    int size = sizeof(HTTPREQUEST_EXTRA_SUBFIELDS_EXISTED) - 1;
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
                              cb_check_http_request_extra_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) HTTPREQUEST_EXTRA_SUBFIELDS_EXISTED, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_latency_common_case()
{
    int ret;
    int size = sizeof(HTTPREQUEST_LATENCY_COMMON_CASE) - 1;
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
                              cb_check_http_request_lantency_common_case,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) HTTPREQUEST_LATENCY_COMMON_CASE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_latency_invalid_spaces()
{
    int ret;
    int size = sizeof(HTTPREQUEST_LATENCY_INVALID_SPACES) - 1;
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
                              cb_check_http_request_latency_incorrect_format,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) HTTPREQUEST_LATENCY_INVALID_SPACES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_latency_invalid_string()
{
    int ret;
    int size = sizeof(HTTPREQUEST_LATENCY_INVALID_STRING) - 1;
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
                              cb_check_http_request_latency_incorrect_format,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) HTTPREQUEST_LATENCY_INVALID_STRING, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_http_request_latency_invalid_end()
{
    int ret;
    int size = sizeof(HTTPREQUEST_LATENCY_INVALID_END) - 1;
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
                              cb_check_http_request_latency_incorrect_format,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) HTTPREQUEST_LATENCY_INVALID_END, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_timestamp_format_object_common()
{
    int ret;
    int size = sizeof(TIMESTAMP_FORMAT_OBJECT_COMMON_CASE) - 1;
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
                              cb_check_timestamp_format_object_common_case,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) TIMESTAMP_FORMAT_OBJECT_COMMON_CASE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_timestamp_format_object_not_a_map()
{
    int ret;
    int size = sizeof(TIMESTAMP_FORMAT_OBJECT_NOT_A_MAP) - 1;
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
                              cb_check_timestamp_format_object_not_a_map,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) TIMESTAMP_FORMAT_OBJECT_NOT_A_MAP, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_timestamp_format_object_missing_subfield()
{
    int ret;
    int size = sizeof(TIMESTAMP_FORMAT_OBJECT_MISSING_SUBFIELD) - 1;
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
                              cb_check_timestamp_format_object_missing_subfield,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) TIMESTAMP_FORMAT_OBJECT_MISSING_SUBFIELD, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_timestamp_format_object_incorrect_subfields()
{
    int ret;
    int size = sizeof(TIMESTAMP_FORMAT_OBJECT_INCORRECT_TYPE_SUBFIELDS) - 1;
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
                              cb_check_timestamp_format_object_incorrect_subfields,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) TIMESTAMP_FORMAT_OBJECT_INCORRECT_TYPE_SUBFIELDS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_timestamp_format_duo_fields_common_case()
{
    int ret;
    int size = sizeof(TIMESTAMP_FORMAT_DUO_FIELDS_COMMON_CASE) - 1;
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
                              cb_check_timestamp_format_duo_fields_common_case,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) TIMESTAMP_FORMAT_DUO_FIELDS_COMMON_CASE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_timestamp_format_duo_fields_missing_nanos()
{
    int ret;
    int size = sizeof(TIMESTAMP_FORMAT_DUO_FIELDS_MISSING_NANOS) - 1;
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
                              cb_check_timestamp_format_duo_fields_missing_nanos,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) TIMESTAMP_FORMAT_DUO_FIELDS_MISSING_NANOS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_timestamp_format_duo_fields_incorrect_type()
{
    int ret;
    int size = sizeof(TIMESTAMP_FORMAT_DUO_FIELDS_INCORRECT_TYPE) - 1;
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
                              cb_check_timestamp_format_duo_fields_incorrect_type,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) TIMESTAMP_FORMAT_DUO_FIELDS_INCORRECT_TYPE, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"severity_multi_entries", flb_test_multi_entries_severity },
    {"resource_global", flb_test_resource_global },
    {"resource_global_custom_prefix", flb_test_resource_global_custom_prefix },
    {"resource_gce_instance", flb_test_resource_gce_instance },

    /* test insertId */
    {"insertId_common_case", flb_test_insert_id_common_case},
    {"empty_insertId", flb_test_empty_insert_id},
    {"insertId_incorrect_type_int", flb_test_insert_id_incorrect_type},

    /* test operation */
    {"operation_common_case", flb_test_operation_common},
    {"empty_operation", flb_test_empty_operation},
    {"operation_not_a_map", flb_test_operation_in_string},
    {"operation_partial_subfields", flb_test_operation_partial_subfields},
    {"operation_subfields_in_incorrect_type", flb_test_operation_incorrect_type_subfields},
    {"operation_extra_subfields_exist", flb_test_operation_extra_subfields},

    /* test sourceLocation */
    {"sourceLocation_common_case", flb_test_source_location_common_case},
    {"sourceLocation_line_in_string", flb_test_source_location_line_in_string},
    {"empty_sourceLocation", flb_test_empty_source_location},
    {"sourceLocation_not_a_map", flb_test_source_location_in_string},
    {"sourceLocation_partial_subfields", flb_test_source_location_partial_subfields},
    {"sourceLocation_subfields_in_incorrect_type", flb_test_source_location_incorrect_type_subfields},
    {"sourceLocation_extra_subfields_exist", flb_test_source_location_extra_subfields},

    /* test k8s */
    {"resource_k8s_container_common", flb_test_resource_k8s_container_common },
    {"resource_k8s_container_no_local_resource_id", flb_test_resource_k8s_container_no_local_resource_id },
    {"resource_k8s_container_multi_tag_value", flb_test_resource_k8s_container_multi_tag_value } ,
    {"resource_k8s_container_custom_tag_prefix", flb_test_resource_k8s_container_custom_tag_prefix },
    {"resource_k8s_container_custom_tag_prefix_with_dot", flb_test_resource_k8s_container_custom_tag_prefix_with_dot },
    {"resource_k8s_container_default_tag_regex", flb_test_resource_k8s_container_default_tag_regex },
    {"resource_k8s_node_common", flb_test_resource_k8s_node_common },
    {"resource_k8s_node_no_local_resource_id", flb_test_resource_k8s_node_no_local_resource_id },
    {"resource_k8s_pod_common", flb_test_resource_k8s_pod_common },
    {"resource_k8s_pod_no_local_resource_id", flb_test_resource_k8s_pod_no_local_resource_id },
    {"default_labels", flb_test_default_labels },
    {"custom_labels", flb_test_custom_labels },
    {"default_labels_k8s_resource_type", flb_test_default_labels_k8s_resource_type },
    {"custom_labels_k8s_resource_type", flb_test_custom_labels_k8s_resource_type },

    /* test httpRequest */
    {"httpRequest_common_case", flb_test_http_request_common_case},
    {"empty_httpRequest", flb_test_empty_http_request},
    {"httpRequest_not_a_map", flb_test_http_request_in_string},
    {"httpRequest_partial_subfields", flb_test_http_request_partial_subfields},
    {"httpRequest_subfields_in_incorret_type", flb_test_http_request_incorrect_type_subfields},
    {"httpRequest_extra_subfields_exist", flb_test_http_request_extra_subfields},
    {"httpRequest_common_latency", flb_test_http_request_latency_common_case},
    {"httpRequest_latency_incorrect_spaces", flb_test_http_request_latency_invalid_spaces},
    {"httpRequest_latency_incorrect_string", flb_test_http_request_latency_invalid_string},
    {"httpRequest_latency_incorrect_end", flb_test_http_request_latency_invalid_end},

    /* test timestamp */
    {"timestamp_format_object_common_case", flb_test_timestamp_format_object_common},
    {"timestamp_format_object_not_a_map", flb_test_timestamp_format_object_not_a_map},
    {"timestamp_format_object_missing_subfield", flb_test_timestamp_format_object_missing_subfield},
    {"timestamp_format_object_incorrect_type_subfields", flb_test_timestamp_format_object_incorrect_subfields},

    {"timestamp_format_duo_fields_common_case", flb_test_timestamp_format_duo_fields_common_case},
    {"timestamp_format_duo_fields_missing_nanos", flb_test_timestamp_format_duo_fields_missing_nanos},
    {"timestamp_format_duo_fields_incorrect_type", flb_test_timestamp_format_duo_fields_incorrect_type},

    {NULL, NULL}
};
