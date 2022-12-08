/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <fluent-bit.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h" /* JSON_TD */

/* not a real error code, but tests that the code can respond to any error */
#define ERROR_ACCESS_DENIED "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                            <Error>\
                            <Code>AccessDenied</Code>\
                            <Message>Access Denied</Message>\
                            <RequestId>656c76696e6727732072657175657374</RequestId>\
                            <HostId>Uuag1LuByRx9e6j5Onimru9pO4ZVKnJ2Qz7/C1NPcfTWAtRPfTaOFg==</HostId>\
                            </Error>"

/*
 * helper function to validate content of a formatter and expected values with a record
 * accessor pattern.
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

/* check if a 'key' exists in the record by using a record accessor pattern */
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
    if (ret == -1) {
        return FLB_FALSE;
    }

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

void flb_test_s3_multipart_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_s3_putobject_success(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_s3_putobject_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_PUT_OBJECT_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"use_put_object", "true", NULL);
    flb_output_set(ctx, out_ffd,"total_file_size", "5M", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);


    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_PUT_OBJECT_ERROR");

}

void flb_test_s3_create_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_CREATE_MULTIPART_UPLOAD_ERROR");
}

void flb_test_s3_upload_part_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_UPLOAD_PART_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_UPLOAD_PART_ERROR");
}

void flb_test_s3_complete_upload_error(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR", ERROR_ACCESS_DENIED, 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx,in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"Retry_Limit", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD , (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
    unsetenv("TEST_COMPLETE_MULTIPART_UPLOAD_ERROR");
}

static void cb_check_format_json(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    int ret;

    /* check the 'date' key exists with the proper value */
    ret = mp_kv_cmp(res_data, res_size, "date", "2022-12-08T18:19:44.000000Z");
    TEST_CHECK(ret == FLB_TRUE);

    /* content of 'message' */
    ret = mp_kv_cmp(res_data, res_size, "message", "last-entry");
    TEST_CHECK(ret == FLB_TRUE);

    flb_sds_destroy(res_data);
}

static void cb_check_format_json_log_key(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    int ret;

    /* check the key 'abc' don't exists */
    ret = mp_kv_exists(res_data, res_size, "abc");
    TEST_CHECK(ret == FLB_FALSE);

    /* check the whole content equals 'last-entry' */
    ret = strncmp(res_data, "last-entry", res_size);
    TEST_CHECK(ret == 0);

    flb_sds_destroy(res_data);
}


static void cb_check_format_csv(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    int ret;

    /* expected output */
    char *out = "\"timestamp\",\"col1\",\"col2\"\n\"1670523584.0\",\"aa\"\"a\",\"bbb\"\n";

    ret = strncmp(res_data, out, res_size);
    TEST_CHECK(ret == 0);
    flb_sds_destroy(res_data);
}

static void cb_check_format_csv_log_key(void *ctx, int ffd,
                                        int res_ret, void *res_data, size_t res_size,
                                        void *data)
{
    /*
     * we use the same callback for normal CSV since we are testing the same content. The
     * only difference is that the caller put the content inside a 'message' key.
     */
    cb_check_format_csv(ctx, ffd, res_ret, res_data, res_size, data);
}

void flb_test_s3_format_json()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *fmt_json = "[1670523584, {\"message\": \"last-entry\"}]";

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);

    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"retry_limit", "1", NULL);

    /*
     * NOTE: we want the default 'format' value to be 'json', no need to enable it
     * manually.
     */

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_format_json,
                              NULL, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) fmt_json, strlen(fmt_json));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* JSON formatting using 'log_key' property */
void flb_test_s3_format_json_log_key()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *fmt_json = "[1670523584, {\"abc\": \"not found\", \"message\": \"last-entry\"}]";

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);

    flb_output_set(ctx, out_ffd,"match", "*", NULL);
    flb_output_set(ctx, out_ffd,"region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd,"bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd,"retry_limit", "1", NULL);
    flb_output_set(ctx, out_ffd,"log_key", "message", NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_format_json_log_key,
                              NULL, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) fmt_json, strlen(fmt_json));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_s3_format_csv()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *fmt_json = "[1670523584, {\"col1\": \"aa\"a\", \"col2\": \"bbb\"}]";

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);

    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "1", NULL);

    /* format as CSV */
    flb_output_set(ctx, out_ffd, "format", "csv", NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_format_csv,
                              NULL, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) fmt_json, strlen(fmt_json));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}


void flb_test_s3_format_csv_log_key()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *fmt_json = "[1670523584, {\"message\": {\"col1\": \"aa\"a\", \"col2\": \"bbb\"}}]";

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_S3_PLUGIN_UNDER_TEST", "true", 1);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "s3", NULL);
    TEST_CHECK(out_ffd >= 0);

    flb_output_set(ctx, out_ffd, "match", "*", NULL);
    flb_output_set(ctx, out_ffd, "region", "us-west-2", NULL);
    flb_output_set(ctx, out_ffd, "bucket", "fluent", NULL);
    flb_output_set(ctx, out_ffd, "retry_limit", "1", NULL);

    /* format as CSV */
    flb_output_set(ctx, out_ffd, "format", "csv", NULL);

    /* only process the content of key 'message' */
    flb_output_set(ctx, out_ffd,"log_key", "message", NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_format_csv_log_key,
                              NULL, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) fmt_json, strlen(fmt_json));

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"multipart_success", flb_test_s3_multipart_success },
    {"putobject_success", flb_test_s3_putobject_success },
    {"putobject_error", flb_test_s3_putobject_error },
    {"create_upload_error", flb_test_s3_create_upload_error },
    {"upload_part_error", flb_test_s3_upload_part_error },
    {"complete_upload_error", flb_test_s3_complete_upload_error },

    /* formatters */
    {"format_json"        , flb_test_s3_format_json },
    {"format_json_log_key", flb_test_s3_format_json_log_key },
    {"format_csv"         , flb_test_s3_format_csv },
    {"format_csv_log_key" , flb_test_s3_format_csv_log_key },

    {NULL, NULL}
};
