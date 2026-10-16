/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* @author Rovo Dev (Claude) - co-author */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

#ifdef FLB_TEST_KAFKA_ZSTD
#include "rdkafka.h"
#endif

/* Test data */
#include "data/td/json_td.h"

#ifdef FLB_TEST_KAFKA_ZSTD
/*
 * Ensure librdkafka was compiled with zstd support so Kafka producers can
 * negotiate zstd compression. Setting compression.codec to zstd only succeeds
 * when WITH_ZSTD was enabled at build time, otherwise rd_kafka_conf_set
 * reports the codec as not built in.
 */
void flb_test_zstd_compression_available(void)
{
    rd_kafka_conf_t *conf;
    rd_kafka_conf_res_t res;
    char errstr[512] = {0};

    conf = rd_kafka_conf_new();
    TEST_ASSERT(conf != NULL);

    res = rd_kafka_conf_set(conf, "compression.codec", "zstd",
                            errstr, sizeof(errstr));
    TEST_CHECK(res == RD_KAFKA_CONF_OK);
    TEST_MSG("compression.codec=zstd rejected: %s", errstr);

    rd_kafka_conf_destroy(conf);
}
#endif


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
#ifdef FLB_TEST_KAFKA_ZSTD
  { "zstd_compression_available", flb_test_zstd_compression_available },
#endif
  { "raw_format", flb_test_raw_format },
  { NULL, NULL },
};
