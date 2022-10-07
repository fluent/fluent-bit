/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020, Magnus Edenhill
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

/**
 * Issue #2933: Offset commit on revoke would cause hang.
 */

static rd_kafka_t *c1, *c2;


static void rebalance_cb(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *parts,
                         void *opaque) {

        TEST_SAY("Rebalance for %s: %s: %d partition(s)\n", rd_kafka_name(rk),
                 rd_kafka_err2name(err), parts->cnt);

        if (err == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS) {
                TEST_CALL_ERR__(rd_kafka_assign(rk, parts));

        } else if (err == RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS) {
                rd_kafka_resp_err_t commit_err;

                TEST_CALL_ERR__(rd_kafka_position(rk, parts));

                TEST_CALL_ERR__(rd_kafka_assign(rk, NULL));

                if (rk == c1)
                        return;

                /* Give the closing consumer some time to handle the
                 * unassignment and leave so that the coming commit fails. */
                rd_sleep(5);

                /* Committing after unassign will trigger an
                 * Illegal generation error from the broker, which would
                 * previously cause the cgrp to not properly transition
                 * the next assigned state to fetching.
                 * The closing consumer's commit is denied by the consumer
                 * since it will have started to shut down after the assign
                 * call. */
                TEST_SAY("%s: Committing\n", rd_kafka_name(rk));
                commit_err = rd_kafka_commit(rk, parts, 0 /*sync*/);
                TEST_SAY("%s: Commit result: %s\n", rd_kafka_name(rk),
                         rd_kafka_err2name(commit_err));

                TEST_ASSERT(commit_err,
                            "Expected closing consumer %s's commit to "
                            "fail, but got %s",
                            rd_kafka_name(rk), rd_kafka_err2name(commit_err));

        } else {
                TEST_FAIL("Unhandled event: %s", rd_kafka_err2name(err));
        }
}


int main_0118_commit_rebalance(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_conf_t *conf;
        const int msgcnt = 1000;

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);

        test_produce_msgs_easy_v(topic, 0, RD_KAFKA_PARTITION_UA, 0, msgcnt, 10,
                                 NULL);

        c1 = test_create_consumer(topic, rebalance_cb, rd_kafka_conf_dup(conf),
                                  NULL);
        c2 = test_create_consumer(topic, rebalance_cb, conf, NULL);

        test_consumer_subscribe(c1, topic);
        test_consumer_subscribe(c2, topic);


        test_consumer_poll("C1.PRE", c1, 0, -1, -1, 10, NULL);
        test_consumer_poll("C2.PRE", c2, 0, -1, -1, 10, NULL);

        /* Trigger rebalance */
        test_consumer_close(c2);
        rd_kafka_destroy(c2);

        /* Since no offsets were successfully committed the remaining consumer
         * should be able to receive all messages. */
        test_consumer_poll("C1.POST", c1, 0, -1, -1, msgcnt, NULL);

        rd_kafka_destroy(c1);

        return 0;
}
