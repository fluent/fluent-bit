/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013, Magnus Edenhill
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

/**
 * Tests that producing to unknown partitions fails.
 * Issue #39
 */

#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


static int msgs_wait = 0; /* bitmask */

/**
 * Delivery report callback.
 * Called for each message once to signal its delivery status.
 */
static void dr_cb(rd_kafka_t *rk,
                  void *payload,
                  size_t len,
                  rd_kafka_resp_err_t err,
                  void *opaque,
                  void *msg_opaque) {
        int msgid = *(int *)msg_opaque;

        free(msg_opaque);

        if (!(msgs_wait & (1 << msgid)))
                TEST_FAIL(
                    "Unwanted delivery report for message #%i "
                    "(waiting for 0x%x)\n",
                    msgid, msgs_wait);

        TEST_SAY("Delivery report for message #%i: %s\n", msgid,
                 rd_kafka_err2str(err));

        msgs_wait &= ~(1 << msgid);

        if (err != RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION)
                TEST_FAIL("Message #%i failed with unexpected error %s\n",
                          msgid, rd_kafka_err2str(err));
}


static void do_test_unkpart(void) {
        int partition = 99; /* non-existent */
        int r;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *topic_conf;
        char msg[128];
        int msgcnt = 10;
        int i;
        int fails = 0;
        const struct rd_kafka_metadata *metadata;

        TEST_SAY(_C_BLU "%s\n" _C_CLR, __FUNCTION__);

        test_conf_init(&conf, &topic_conf, 10);

        /* Set delivery report callback */
        rd_kafka_conf_set_dr_cb(conf, dr_cb);

        /* Create kafka instance */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        rkt = rd_kafka_topic_new(rk, test_mk_topic_name("0002", 0), topic_conf);
        if (!rkt)
                TEST_FAIL("Failed to create topic: %s\n",
                          rd_kafka_err2str(rd_kafka_last_error()));

        /* Request metadata so that we know the cluster is up before producing
         * messages, otherwise erroneous partitions will not fail immediately.*/
        if ((r = rd_kafka_metadata(rk, 0, rkt, &metadata,
                                   tmout_multip(15000))) !=
            RD_KAFKA_RESP_ERR_NO_ERROR)
                TEST_FAIL("Failed to acquire metadata: %s\n",
                          rd_kafka_err2str(r));

        rd_kafka_metadata_destroy(metadata);

        /* Produce a message */
        for (i = 0; i < msgcnt; i++) {
                int *msgidp = malloc(sizeof(*msgidp));
                *msgidp     = i;
                rd_snprintf(msg, sizeof(msg), "%s test message #%i",
                            __FUNCTION__, i);
                r = rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY, msg,
                                     strlen(msg), NULL, 0, msgidp);
                if (r == -1) {
                        if (rd_kafka_last_error() ==
                            RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION)
                                TEST_SAY(
                                    "Failed to produce message #%i: "
                                    "unknown partition: good!\n",
                                    i);
                        else
                                TEST_FAIL(
                                    "Failed to produce message #%i: %s\n", i,
                                    rd_kafka_err2str(rd_kafka_last_error()));
                        free(msgidp);
                } else {
                        if (i > 5) {
                                fails++;
                                TEST_SAY(
                                    "Message #%i produced: "
                                    "should've failed\n",
                                    i);
                        }
                        msgs_wait |= (1 << i);
                }

                /* After half the messages: forcibly refresh metadata
                 * to update the actual partition count:
                 * this will make subsequent produce() calls fail immediately.
                 */
                if (i == 5) {
                        r = test_get_partition_count(
                            rk, rd_kafka_topic_name(rkt), 15000);
                        TEST_ASSERT(r != -1, "failed to get partition count");
                }
        }

        /* Wait for messages to time out */
        rd_kafka_flush(rk, -1);

        if (msgs_wait != 0)
                TEST_FAIL("Still waiting for messages: 0x%x\n", msgs_wait);


        if (fails > 0)
                TEST_FAIL("See previous error(s)\n");

        /* Destroy topic */
        rd_kafka_topic_destroy(rkt);

        /* Destroy rdkafka instance */
        TEST_SAY("Destroying kafka instance %s\n", rd_kafka_name(rk));
        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "%s PASSED\n" _C_CLR, __FUNCTION__);
}


/**
 * @brief Test message timeouts for messages produced to unknown partitions
 *        when there is no broker connection, which makes the messages end
 *        up in the UA partition.
 *        This verifies the UA partitions are properly scanned for timeouts.
 *
 *        This test is a copy of confluent-kafka-python's
 *        test_Producer.test_basic_api() test that surfaced this issue.
 */
static void do_test_unkpart_timeout_nobroker(void) {
        const char *topic = test_mk_topic_name("0002_unkpart_tmout", 0);
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        rd_kafka_resp_err_t err;
        int remains = 0;

        TEST_SAY(_C_BLU "%s\n" _C_CLR, __FUNCTION__);

        test_conf_init(NULL, NULL, 10);

        conf = rd_kafka_conf_new();
        test_conf_set(conf, "debug", "topic");
        test_conf_set(conf, "message.timeout.ms", "10");
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        test_curr->exp_dr_err = RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;

        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = rd_kafka_topic_new(rk, topic, NULL);

        err = rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                               NULL, 0, NULL, 0, &remains);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));
        remains++;

        err = rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                               "hi", 2, "hello", 5, &remains);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));
        remains++;

        err = rd_kafka_produce(rkt, 9 /* explicit, but unknown, partition */,
                               RD_KAFKA_MSG_F_COPY, "three", 5, NULL, 0,
                               &remains);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));
        remains++;

        rd_kafka_poll(rk, 1);
        rd_kafka_poll(rk, 2);
        TEST_SAY("%d messages in queue\n", rd_kafka_outq_len(rk));
        rd_kafka_flush(rk, -1);

        TEST_ASSERT(rd_kafka_outq_len(rk) == 0,
                    "expected no more messages in queue, got %d",
                    rd_kafka_outq_len(rk));

        TEST_ASSERT(remains == 0, "expected no messages remaining, got %d",
                    remains);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "%s PASSED\n" _C_CLR, __FUNCTION__);
}


int main_0002_unkpart(int argc, char **argv) {
        do_test_unkpart();
        do_test_unkpart_timeout_nobroker();
        return 0;
}
