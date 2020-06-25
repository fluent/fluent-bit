/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/es/json_es.h" /* JSON_ES */


static void cb_check_index_type(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"index\":{\"_index\":\"index_test\",\"_type\":\"type_test\"}";

    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);

    flb_free(res_data);
}

static void cb_check_logstash_format(void *ctx, int ffd,
                                     int res_ret, void *res_data, size_t res_size,
                                     void *data)
{
    char *p;
    char *out_js = res_data;
    char *index_line = "{\"index\":{\"_index\":\"prefix-2015-11-24\",\"_type\":\"_doc\"}";

    p = strstr(out_js, index_line);
    TEST_CHECK(p != NULL);
    flb_free(res_data);
}

static void cb_check_tag_key(void *ctx, int ffd,
                             int res_ret, void *res_data, size_t res_size,
                             void *data)
{
    char *p;
    char *out_js = res_data;
    char *record = "\"mytag\":\"test\"";

    p = strstr(out_js, record);
    TEST_CHECK(p != NULL);
    flb_free(res_data);
}

static void cb_check_replace_dots(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    char *p;
    char *out_js = res_data;
    char *record = "\"key_4\":5000";

    printf("%s\n", out_js);
    p = strstr(out_js, record);
    TEST_CHECK(p != NULL);
    flb_free(res_data);
}


void flb_test_index_type()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "index", "index_test",
                   "type", "type_test",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_index_type,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_logstash_format()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "logstash_format", "on",
                   "logstash_prefix", "prefix",
                   "logstash_dateformat", "%Y-%m-%d",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_logstash_format,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_tag_key()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "include_tag_key", "on",
                   "tag_key", "mytag",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_tag_key,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_replace_dots()
{
    int ret;
    int size = sizeof(JSON_ES) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "es", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Override defaults of index and type */
    flb_output_set(ctx, out_ffd,
                   "replace_dots", "on",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_replace_dots,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_ES, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"index_type"     , flb_test_index_type },
    {"logstash_format", flb_test_logstash_format },
    {"tag_key"        , flb_test_tag_key },
    {"replace_dots"   , flb_test_replace_dots },
    {NULL, NULL}
};
