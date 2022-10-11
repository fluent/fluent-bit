/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * Consume with batch + queue interface
 *
 */


static void do_test_consume_batch(void) {
#define topic_cnt 2
        char *topics[topic_cnt];
        const int partition_cnt = 2;
        rd_kafka_t *rk;
        rd_kafka_queue_t *rkq;
        rd_kafka_topic_t *rkts[topic_cnt];
        rd_kafka_resp_err_t err;
        const int msgcnt = test_quick ? 1000 : 10000;
        uint64_t testid;
        int i, p;
        int batch_cnt = 0;
        int remains;

        SUB_TEST();

        testid = test_id_generate();

        /* Produce messages */
        for (i = 0; i < topic_cnt; i++) {
                topics[i] = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                for (p = 0; p < partition_cnt; p++)
                        test_produce_msgs_easy(topics[i], testid, p,
                                               msgcnt / topic_cnt /
                                                   partition_cnt);
        }


        /* Create simple consumer */
        rk = test_create_consumer(NULL, NULL, NULL, NULL);

        /* Create generic consume queue */
        rkq = rd_kafka_queue_new(rk);

        for (i = 0; i < topic_cnt; i++) {
                /* Create topic object */
                rkts[i] = test_create_topic_object(
                    rk, topics[i], "auto.offset.reset", "smallest", NULL);

                /* Start consuming each partition and redirect
                 * messages to queue */

                TEST_SAY("Start consuming topic %s partitions 0..%d\n",
                         rd_kafka_topic_name(rkts[i]), partition_cnt);

                for (p = 0; p < partition_cnt; p++) {
                        err = rd_kafka_consume_start_queue(
                            rkts[i], p, RD_KAFKA_OFFSET_BEGINNING, rkq);
                        if (err)
                                TEST_FAIL("Failed to start consuming: %s\n",
                                          rd_kafka_err2str(err));
                }
        }

        remains = msgcnt;

        /* Consume messages from common queue using batch interface. */
        TEST_SAY("Consume %d messages from queue\n", remains);
        while (remains > 0) {
                rd_kafka_message_t *rkmessage[1000];
                ssize_t r;
                test_timing_t t_batch;

                TIMING_START(&t_batch, "CONSUME.BATCH");
                r = rd_kafka_consume_batch_queue(rkq, 1000, rkmessage, 1000);
                TIMING_STOP(&t_batch);

                TEST_SAY("Batch consume iteration #%d: Consumed %" PRIdsz
                         "/1000 messages\n",
                         batch_cnt, r);

                if (r == -1)
                        TEST_FAIL("Failed to consume messages: %s\n",
                                  rd_kafka_err2str(rd_kafka_last_error()));

                remains -= (int)r;

                for (i = 0; i < r; i++)
                        rd_kafka_message_destroy(rkmessage[i]);

                batch_cnt++;
        }


        TEST_SAY("Stopping consumer\n");
        for (i = 0; i < topic_cnt; i++) {
                for (p = 0; p < partition_cnt; p++) {
                        err = rd_kafka_consume_stop(rkts[i], p);
                        if (err)
                                TEST_FAIL("Failed to stop consuming: %s\n",
                                          rd_kafka_err2str(err));
                }

                rd_kafka_topic_destroy(rkts[i]);
                rd_free(topics[i]);
        }

        rd_kafka_queue_destroy(rkq);

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


#if WITH_SASL_OAUTHBEARER
/**
 * @brief Verify that the oauthbearer_refresh_cb() is triggered
 *        when using consume_batch_queue()  (as opposed to consumer_poll()).
 */

static rd_bool_t refresh_called = rd_false;

static void
refresh_cb(rd_kafka_t *rk, const char *oauthbearer_config, void *opaque) {
        TEST_SAY("Refresh callback called\n");
        TEST_ASSERT(!refresh_called);
        refresh_called = rd_true;
        rd_kafka_oauthbearer_set_token_failure(rk, "Refresh called");
}

static void do_test_consume_batch_oauthbearer_cb(void) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *rkq;
        rd_kafka_message_t *rkms[1];
        ssize_t r;

        SUB_TEST_QUICK();

        refresh_called = rd_false;

        conf = rd_kafka_conf_new();
        test_conf_set(conf, "security.protocol", "sasl_plaintext");
        test_conf_set(conf, "sasl.mechanism", "OAUTHBEARER");
        rd_kafka_conf_set_oauthbearer_token_refresh_cb(conf, refresh_cb);

        /* Create simple consumer */
        rk = test_create_consumer(NULL, NULL, conf, NULL);

        /* Create generic consume queue */
        rkq = rd_kafka_queue_get_main(rk);

        r = rd_kafka_consume_batch_queue(rkq, 1000, rkms, 1);
        TEST_ASSERT(r == 0, "Expected return value 0, not %d", (int)r);

        TEST_SAY("refresh_called = %d\n", refresh_called);
        TEST_ASSERT(refresh_called,
                    "Expected refresh callback to have been called");

        rd_kafka_queue_destroy(rkq);

        rd_kafka_destroy(rk);
}
#endif


int main_0022_consume_batch(int argc, char **argv) {
        do_test_consume_batch();
        return 0;
}


int main_0022_consume_batch_local(int argc, char **argv) {
#if WITH_SASL_OAUTHBEARER
        do_test_consume_batch_oauthbearer_cb();
#else
        TEST_SKIP("No OAUTHBEARER support\n");
#endif
        return 0;
}
