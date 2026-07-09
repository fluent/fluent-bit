/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
 *               2025, Confluent Inc.
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

#include "rdkafka.h"
#include "../src/rdkafka_protocol.h"

#include <stdarg.h>

static int
is_fatal_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err, const char *reason) {
        /* Ignore connectivity errors since we'll be bringing down
         * .. connectivity.
         * SASL auther will think a connection-down even in the auth
         * state means the broker doesn't support SASL PLAIN. */
        TEST_SAY("is_fatal?: %s: %s\n", rd_kafka_err2str(err), reason);
        if (err == RD_KAFKA_RESP_ERR__TRANSPORT ||
            err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN ||
            err == RD_KAFKA_RESP_ERR__AUTHENTICATION ||
            err == RD_KAFKA_RESP_ERR__TIMED_OUT)
                return 0;
        return 1;
}

static int msg_dr_cnt      = 0;
static int msg_dr_fail_cnt = 0;

static void
dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
        msg_dr_cnt++;
        if (rkmessage->err != RD_KAFKA_RESP_ERR__MSG_TIMED_OUT)
                TEST_FAIL_LATER(
                    "Expected message to fail with MSG_TIMED_OUT, "
                    "got: %s",
                    rd_kafka_err2str(rkmessage->err));
        else {
                TEST_ASSERT_LATER(rd_kafka_message_status(rkmessage) ==
                                      RD_KAFKA_MSG_STATUS_POSSIBLY_PERSISTED,
                                  "Message should have status "
                                  "PossiblyPersisted (%d), not %d",
                                  RD_KAFKA_MSG_STATUS_POSSIBLY_PERSISTED,
                                  rd_kafka_message_status(rkmessage));
                msg_dr_fail_cnt++;
        }
}



int main_0068_produce_timeout(int argc, char **argv) {
        rd_kafka_t *rk;
        const char *topic = test_mk_topic_name("0068_produce_timeout", 1);
        uint64_t testid;
        const int msgcnt = 10;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        int msgcounter = 0;
        const char *bootstraps;

        TEST_SKIP_MOCK_CLUSTER(0);

        rd_kafka_mock_cluster_t *mcluster =
            test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 3);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

        test_curr->is_fatal_cb = is_fatal_cb;

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);
        /* message timeout should be less that rtt */
        rkt = test_create_producer_topic(rk, topic, "message.timeout.ms",
                                         "2000", NULL);

        TEST_SAY("Auto-creating topic %s\n", topic);
        test_auto_create_topic_rkt(rk, rkt, tmout_multip(5000));

        TEST_SAY("Producing %d messages that should timeout\n", msgcnt);
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_Produce, 1, RD_KAFKA_RESP_ERR_NO_ERROR,
            6000);

        test_produce_msgs_nowait(rk, rkt, testid, 0, 0, msgcnt, NULL, 0, 0,
                                 &msgcounter);

        TEST_SAY("Flushing..\n");
        rd_kafka_flush(rk, 10000);

        TEST_SAY("%d/%d delivery reports, where of %d with proper error\n",
                 msg_dr_cnt, msgcnt, msg_dr_fail_cnt);

        TEST_ASSERT(msg_dr_cnt == msgcnt, "expected %d, got %d", msgcnt,
                    msg_dr_cnt);
        TEST_ASSERT(msg_dr_fail_cnt == msgcnt, "expected %d, got %d", msgcnt,
                    msg_dr_fail_cnt);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();

        return 0;
}
