/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

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

TEST_LIST = {
  { "raw_format", flb_test_raw_format },
  { NULL, NULL },
};
