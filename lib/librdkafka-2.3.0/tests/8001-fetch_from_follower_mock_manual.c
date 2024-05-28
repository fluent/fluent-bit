/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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

#include "../src/rdkafka_proto.h"

/**
 * @brief Test that the #4195 segfault doesn't happen when preferred replica
 *        lease expires and the rktp is in fetch state
 *        RD_KAFKA_TOPPAR_FETCH_OFFSET_WAIT.
 */
static void do_test_fetch_from_follower_offset_retry(void) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        rd_kafka_t *c;
        const char *topic = "test";
        rd_kafka_topic_partition_t *rktpar;
        rd_kafka_topic_partition_list_t *seek;
        int i;

        SUB_TEST_QUICK();
        test_timeout_set(600);

        mcluster = test_mock_cluster_new(3, &bootstraps);
        /* Set partition leader to broker 1. */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_mock_partition_set_follower(mcluster, topic, 0, 2);

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "client.rack", "myrack");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "fetch.error.backoff.ms", "1000");
        test_conf_set(conf, "fetch.message.max.bytes", "10");
        test_conf_set(conf, "session.timeout.ms", "600000");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "600000");

        c = test_create_consumer("mygroup", NULL, conf, NULL);

        test_consumer_assign_partition(
            "do_test_fetch_from_follower_offset_retry", c, topic, 0,
            RD_KAFKA_OFFSET_INVALID);

        /* Since there are no messages, this poll only waits for metadata, and
         * then sets the preferred replica after the first fetch request.
         * Subsequent polls are for waiting up to 5 minutes. */
        for (i = 0; i < 7; i++) {
                test_consumer_poll_no_msgs(
                    "initial metadata and preferred replica set", c, 0, 40000);
        }


        /* Seek to end to trigger ListOffsets */
        seek           = rd_kafka_topic_partition_list_new(1);
        rktpar         = rd_kafka_topic_partition_list_add(seek, topic, 0);
        rktpar->offset = RD_KAFKA_OFFSET_END;

        /* Increase RTT for this ListOffsets */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 2, RD_KAFKAP_ListOffsets, 1, RD_KAFKA_RESP_ERR_NO_ERROR,
            40 * 1000);

        rd_kafka_seek_partitions(c, seek, -1);
        rd_kafka_topic_partition_list_destroy(seek);

        /* Wait lease expiry */
        rd_sleep(50);

        test_consumer_close(c);

        rd_kafka_destroy(c);

        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


int main_8001_fetch_from_follower_mock_manual(int argc, char **argv) {

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_fetch_from_follower_offset_retry();

        return 0;
}
