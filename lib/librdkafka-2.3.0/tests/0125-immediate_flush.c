/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
 *               2023, Confluent Inc.
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
 * Verify that flush() overrides the linger.ms time.
 *
 */
void do_test_flush_overrides_linger_ms_time() {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        const char *topic = test_mk_topic_name("0125_immediate_flush", 1);
        const int msgcnt  = 100;
        int remains       = 0;
        test_timing_t t_time;

        test_conf_init(&conf, NULL, 30);

        test_conf_set(conf, "linger.ms", "10000");
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        test_create_topic(rk, topic, 1, 1);

        /* Produce half set of messages without waiting for delivery. */
        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, msgcnt / 2, NULL, 50,
                                  &remains);

        TIMING_START(&t_time, "NO_FLUSH");
        do {
                rd_kafka_poll(rk, 1000);
        } while (remains > 0);
        TIMING_ASSERT(&t_time, 10000, 15000);

        /* Produce remaining messages without waiting for delivery. */
        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, msgcnt / 2, NULL, 50,
                                  &remains);

        /* The linger time should be overriden when flushing */
        TIMING_START(&t_time, "FLUSH");
        TEST_CALL_ERR__(rd_kafka_flush(rk, 2000));
        TIMING_ASSERT(&t_time, 0, 2500);

        rd_kafka_destroy(rk);


        /* Verify messages were actually produced by consuming them back. */
        test_consume_msgs_easy(topic, topic, 0, 1, msgcnt, NULL);
}

/**
 * @brief Tests if the first metadata call is able to update leader for the
 * topic or not. If it is not able to update the leader for some partitions,
 * flush call waits for 1s to refresh the leader and then flush is completed.
 * Ideally, it should update in the first call itself.
 *
 * Number of brokers in the cluster should be more than the number of
 * brokers in the bootstrap.servers list for this test case to work correctly
 *
 */
void do_test_first_flush_immediate() {
        rd_kafka_mock_cluster_t *mock_cluster;
        rd_kafka_t *produce_rk;
        const char *brokers;
        char *bootstrap_server;
        test_timing_t t_time;
        size_t i;
        rd_kafka_conf_t *conf = NULL;
        const char *topic     = test_mk_topic_name("0125_immediate_flush", 1);
        size_t partition_cnt  = 9;
        int remains           = 0;

        mock_cluster = test_mock_cluster_new(3, &brokers);

        for (i = 0; brokers[i]; i++)
                if (brokers[i] == ',' || brokers[i] == ' ')
                        break;
        bootstrap_server = rd_strndup(brokers, i);

        test_conf_init(&conf, NULL, 30);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        test_conf_set(conf, "bootstrap.servers", bootstrap_server);
        free(bootstrap_server);

        rd_kafka_mock_topic_create(mock_cluster, topic, partition_cnt, 1);

        produce_rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        for (i = 0; i < partition_cnt; i++) {
                test_produce_msgs2_nowait(produce_rk, topic, 0, i, 0, 1, NULL,
                                          0, &remains);
        }

        TIMING_START(&t_time, "FLUSH");
        TEST_CALL_ERR__(rd_kafka_flush(produce_rk, 5000));
        TIMING_ASSERT(&t_time, 0, 999);

        rd_kafka_destroy(produce_rk);
        test_mock_cluster_destroy(mock_cluster);
}

int main_0125_immediate_flush(int argc, char **argv) {

        do_test_flush_overrides_linger_ms_time();

        return 0;
}

int main_0125_immediate_flush_mock(int argc, char **argv) {

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_first_flush_immediate();

        return 0;
}
