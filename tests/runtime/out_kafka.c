/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_output.h>
#include "flb_tests_runtime.h"

#include "../../plugins/out_kafka/kafka_config.h"

/* Test data */
#include "data/td/json_td.h"


void flb_test_raw_format()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;


    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Kafka output */
    out_ffd = flb_output(ctx, (char *) "kafka", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    /* Switch to raw mode and select a key */
    flb_output_set(ctx, out_ffd, "format", "raw", NULL);
    flb_output_set(ctx, out_ffd, "raw_log_key", "key_0", NULL);
    flb_output_set(ctx, out_ffd, "topics", "test", NULL);
    flb_output_set(ctx, out_ffd, "brokers", "127.0.0.1:111", NULL);
    flb_output_set(ctx, out_ffd, "queue_full_retries", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void test_headers_key_configuration(const char *format,
                                           const char *headers_key,
                                           const char *preserve_headers_key,
                                           size_t expected_headers_key_len,
                                           int expected_preserve_headers_key)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    struct flb_out_kafka *kafka_ctx;
    struct flb_output_instance *out_ins;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "kafka", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "format", format, NULL);
    flb_output_set(ctx, out_ffd, "headers_key", headers_key, NULL);
    flb_output_set(ctx, out_ffd, "preserve_headers_key", preserve_headers_key, NULL);
    flb_output_set(ctx, out_ffd, "topics", "test", NULL);
    flb_output_set(ctx, out_ffd, "brokers", "127.0.0.1:111", NULL);
    flb_output_set(ctx, out_ffd, "queue_full_retries", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    if (ret == 0) {
        out_ins = flb_output_get_instance(ctx->config, out_ffd);
        TEST_CHECK(out_ins != NULL);

        if (out_ins != NULL) {
            kafka_ctx = out_ins->context;
            TEST_CHECK(kafka_ctx != NULL);

            if (kafka_ctx != NULL) {
                TEST_CHECK(kafka_ctx->headers_key_len == expected_headers_key_len);
                TEST_CHECK(kafka_ctx->preserve_headers_key == expected_preserve_headers_key);
            }
        }

        flb_stop(ctx);
    }

    flb_destroy(ctx);
}

void flb_test_empty_headers_key()
{
    test_headers_key_configuration("otlp_json", "", "false", 0, FLB_FALSE);
}

void flb_test_whitespace_headers_key()
{
    test_headers_key_configuration("otlp_json", " \t\r\n\v\f", "true", 0, FLB_TRUE);
}

void flb_test_nonblank_headers_key_is_not_trimmed()
{
    test_headers_key_configuration("json", " headers ", "true", 9, FLB_TRUE);
}

TEST_LIST = {
    { "raw_format", flb_test_raw_format },
    { "empty_headers_key", flb_test_empty_headers_key },
    { "whitespace_headers_key", flb_test_whitespace_headers_key },
    { "nonblank_headers_key_is_not_trimmed", flb_test_nonblank_headers_key_is_not_trimmed },
    { NULL, NULL },
};
