/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/td/json_td.h"


/* ------------------------------------------------------------------ */
/* Original test                                                        */
/* ------------------------------------------------------------------ */

void flb_test_raw_format(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "kafka", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd, "match", "test", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx, out_ffd, "format",             "raw",           NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "raw_log_key",        "key_0",         NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "topics",             "test",          NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "brokers",            "127.0.0.1:111", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "queue_full_retries", "1",             NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* ------------------------------------------------------------------ */
/* Header tests                                                         */
/*                                                                      */
/* All header tests use brokers=127.0.0.1:111 (unreachable) and        */
/* queue_full_retries=1 so that the pipeline exercises the header       */
/* build/produce/destroy paths without requiring a real Kafka broker.   */
/* ------------------------------------------------------------------ */

/*
 * Two static headers: values used verbatim (no '$' prefix).
 * Exercises the static branch of kafka_build_message_headers().
 */
void flb_test_header_static(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "kafka", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match",              "test",
                         "format",             "json",
                         "topics",             "test",
                         "brokers",            "127.0.0.1:111",
                         "queue_full_retries", "1",
                         NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "header", "env production", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_output_set(ctx, out_ffd, "header", "team platform",  NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * One dynamic header: value has a '$' prefix so it is resolved from the
 * log record.  JSON_TD contains "key_0": "val_0", so the header value
 * becomes "val_0".
 * Exercises the dynamic branch of kafka_build_message_headers().
 */
void flb_test_header_dynamic(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "kafka", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match",              "test",
                         "format",             "json",
                         "topics",             "test",
                         "brokers",            "127.0.0.1:111",
                         "queue_full_retries", "1",
                         NULL);
    TEST_CHECK(ret == 0);
    /* "$key_0" resolves to "val_0" from JSON_TD */
    ret = flb_output_set(ctx, out_ffd, "header", "source $key_0", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Dynamic header referencing a field that does not exist in the record.
 * The code should emit a warning and skip that header gracefully.
 * Exercises the missing-field warning path in kafka_build_message_headers().
 */
void flb_test_header_dynamic_missing_field(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "kafka", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match",              "test",
                         "format",             "json",
                         "topics",             "test",
                         "brokers",            "127.0.0.1:111",
                         "queue_full_retries", "1",
                         NULL);
    TEST_CHECK(ret == 0);
    /* "$no_such_field" is absent from JSON_TD → warning logged, header skipped */
    ret = flb_output_set(ctx, out_ffd, "header", "missing $no_such_field", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * Mix of one static and one dynamic header in the same message.
 * Exercises both branches of kafka_build_message_headers() together.
 */
void flb_test_header_mixed(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(ret == 0);

    out_ffd = flb_output(ctx, (char *) "kafka", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match",              "test",
                         "format",             "json",
                         "topics",             "test",
                         "brokers",            "127.0.0.1:111",
                         "queue_full_retries", "1",
                         NULL);
    TEST_CHECK(ret == 0);
    /* Static header */
    ret = flb_output_set(ctx, out_ffd, "header", "app myapp",     NULL);
    TEST_CHECK(ret == 0);
    /* Dynamic: "$key_1" resolves to "val_1" from JSON_TD */
    ret = flb_output_set(ctx, out_ffd, "header", "source $key_1", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_TD, (int) sizeof(JSON_TD) - 1);
    TEST_CHECK(ret > 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
    { "raw_format",                   flb_test_raw_format                   },
    { "header_static",                flb_test_header_static                },
    { "header_dynamic",               flb_test_header_dynamic               },
    { "header_dynamic_missing_field", flb_test_header_dynamic_missing_field },
    { "header_mixed",                 flb_test_header_mixed                 },
    { NULL, NULL },
};
