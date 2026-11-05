/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"

#define ERROR_RESPONSE "NOT FOUND"


struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
};

struct filter_test_result {
    char *expected_pattern;     /* string that must occur in output */
    int expected_pattern_index; /* which record to check for the pattern */
    int expected_records;       /* expected number of outputted records */
    int actual_records;         /* actual number of outputted records */
};

/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    struct filter_test_result *expected;
    char *result;

    expected = (struct filter_test_result *) data;
    result = (char *) record;

    if (expected->expected_pattern_index == expected->actual_records) {
        p = strstr(result, expected->expected_pattern);
        TEST_CHECK(p != NULL);

        if (!p) {
            flb_error("Expected to find: '%s' in result '%s'",
                    expected->expected_pattern, result);
        }
        /*
        * If you want to debug your test
        *
        * printf("Expect: '%s' in result '%s'\n", expected->expected_pattern, result);
        */
    }

    expected->actual_records++;

    flb_free(record);
    return 0;
}


struct str_list {
    size_t size; /* size of lists */
    int ignore_min_line_num; /* ignore line if the length is less than this value */
    char **lists; /* string lists */
};


static struct filter_test *filter_test_create(struct flb_lib_out_cb *data,
                                              char *tag)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct filter_test *ctx;

    ctx = flb_malloc(sizeof(struct filter_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    /* filter relies on the tag container 12 char short container ID */
    flb_input_set(ctx->flb, i_ffd, "tag", tag, NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "ecs", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void flb_test_ecs_filter()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "testprefix-79c796ed2a7f");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "ecs_tag_prefix", "testprefix-",
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with metadata added */
    expected.expected_pattern = "cluster_name.e01d58a8-151b-40e8-bc01-22647b9ecfec.nginx";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

/* 
 * First release of ECS filter could crash
 * when saving that it faild to get metadata for a tag
 */
static void flb_test_ecs_filter_mark_tag_failed()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_TASK_ERROR", ERROR_RESPONSE, 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "testprefix-79c796ed2a7f");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "ecs_tag_prefix", "testprefix-",
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 4; /* 4 records with no metadata */
    expected.expected_pattern = "";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1);

    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1);

    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1);

    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(2);

    /* check number of outputted records */
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_ecs_filter_no_prefix()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "79c796ed2a7f");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "ecs_tag_prefix", "",
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with metadata added */
    expected.expected_pattern = "cluster_name.e01d58a8-151b-40e8-bc01-22647b9ecfec.nginx";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_ecs_filter_cluster_metadata_only()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "var.lib.ecs.79c796ed2a7f");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "ecs_tag_prefix", "",
                         "cluster_metadata_only", "on",
                         /* only cluster value will be populated */
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with only cluster metadata values added */
    expected.expected_pattern = "cluster_name..";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_ecs_filter_cluster_error()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_CLUSTER_ERROR", ERROR_RESPONSE, 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "79c796ed2a7f");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "ecs_tag_prefix", "",
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* this test is mainly for leak checking on error, not for checking result record */
    expected.expected_records = 1; /* 1 record with no metadata  */
    expected.expected_pattern = "";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_ecs_filter_task_error()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_TASK_ERROR", ERROR_RESPONSE, 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "79c796ed2a7f");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "ecs_tag_prefix", "",
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* this test is mainly for leak checking on error, not for checking result record */
    expected.expected_records = 1; /* 1 record with no metadata  */
    expected.expected_pattern = "";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_ecs_filter_containerid_field()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "randomtag");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "container_id_field_name", "container_id",
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with metadata added */
    expected.expected_pattern = "cluster_name.e01d58a8-151b-40e8-bc01-22647b9ecfec.nginx";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\",\"container_id\":\"79c796ed2a7f864f485c76f83f3165488097279d296a7c05bd5201a1c69b2920\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_ecs_filter_containerid_field_error_missing()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "randomtag");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "container_id_field_name", "missing_field",
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 1; /* 1 record with metadata added */
    expected.expected_pattern = "cluster_name..";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\",\"container_id\":\"79c796ed2a7f864f485c76f83f3165488097279d296a7c05bd5201a1c69b2920\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

static void flb_test_ecs_filter_containerid_field_error_invalid()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct filter_test_result expected = { 0 };

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_ECS_PLUGIN_UNDER_TEST", "true", 1);

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data, "randomtag");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "container_id_field_name", "container_id",
                         "ADD", "resource $ClusterName.$TaskID.$ECSContainerName",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    expected.expected_records = 2; /* 2 record with metadata added */
    expected.expected_pattern = "cluster_name..";
    expected.expected_pattern_index = 0;
    cb_data.cb = cb_check_result;
    cb_data.data = (void *) &expected;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"log\":\"error: my error\",\"container_id\":\"random\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);
    sleep(1);

    p = "[0, {\"log\":\"error: my error\",\"container_id\":123456789012}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    /* check number of outputted records */
    sleep(2);
    TEST_CHECK(expected.actual_records == expected.expected_records);
    filter_test_destroy(ctx);
}

TEST_LIST = {

    {"flb_test_ecs_filter_mark_tag_failed"  , flb_test_ecs_filter_mark_tag_failed },
    {"flb_test_ecs_filter"  , flb_test_ecs_filter },
    {"flb_test_ecs_filter_no_prefix"  , flb_test_ecs_filter_no_prefix },
    {"flb_test_ecs_filter_cluster_metadata_only"  , flb_test_ecs_filter_cluster_metadata_only },
    {"flb_test_ecs_filter_cluster_error"  , flb_test_ecs_filter_cluster_error },
    {"flb_test_ecs_filter_task_error"  , flb_test_ecs_filter_task_error },
    {"flb_test_ecs_filter_containerid_field"  , flb_test_ecs_filter_containerid_field },
    {"flb_test_ecs_filter_containerid_field_error_missing"  , flb_test_ecs_filter_containerid_field_error_missing },
    {"flb_test_ecs_filter_containerid_field_error_invalid"  , flb_test_ecs_filter_containerid_field_error_invalid },

    {NULL, NULL}
};
