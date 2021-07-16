/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
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
 * @name Fetch from follower tests using the mock broker.
 */


/**
 * @brief Test offset reset when fetching from replica.
 *        Since the highwatermark is in sync with the leader the
 *        ERR_OFFSETS_OUT_OF_RANGE is trusted by the consumer and
 *        a reset is performed. See do_test_offset_reset_lag()
 *        for the case where the replica is lagging and can't be trusted.
 */
static void do_test_offset_reset (const char *auto_offset_reset) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        rd_kafka_t *c;
        const char *topic = "test";
        const int msgcnt = 1000;
        const size_t msgsize = 1000;

        TEST_SAY(_C_MAG "[ Test FFF auto.offset.reset=%s ]\n",
                 auto_offset_reset);

        mcluster = test_mock_cluster_new(3, &bootstraps);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, 0, 0, 0, msgcnt, msgsize,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "10",
                                 NULL);

        /* Set partition leader to broker 1, follower to broker 2 */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_mock_partition_set_follower(mcluster, topic, 0, 2);

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "client.rack", "myrack");
        test_conf_set(conf, "auto.offset.reset", auto_offset_reset);
        /* Make sure we don't consume the entire partition in one Fetch */
        test_conf_set(conf, "fetch.message.max.bytes", "100");

        c = test_create_consumer("mygroup", NULL, conf, NULL);

        /* The first fetch will go to the leader which will redirect
         * the consumer to the follower, the second and sub-sequent fetches
         * will go to the follower. We want the third fetch, second one on
         * the follower, to fail and trigger an offset reset. */
        rd_kafka_mock_push_request_errors(
                mcluster,
                1/*FetchRequest*/,
                3,
                RD_KAFKA_RESP_ERR_NO_ERROR /*leader*/,
                RD_KAFKA_RESP_ERR_NO_ERROR /*follower*/,
                RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE /*follower: fail*/);

        test_consumer_assign_partition(auto_offset_reset, c, topic, 0,
                                       RD_KAFKA_OFFSET_INVALID);

        if (!strcmp(auto_offset_reset, "latest"))
                test_consumer_poll_no_msgs(auto_offset_reset, c, 0, 5000);
        else
                test_consumer_poll(auto_offset_reset, c, 0, 1, 0,
                                   msgcnt, NULL);

        test_consumer_close(c);

        rd_kafka_destroy(c);

        test_mock_cluster_destroy(mcluster);

        TEST_SAY(_C_GRN "[ Test FFF auto.offset.reset=%s PASSED ]\n",
                 auto_offset_reset);
}


/**
 * @brief Test offset reset when fetching from a lagging replica
 *        who's high-watermark is behind the leader, which means
 *        an offset reset should not be triggered.
 */
static void do_test_offset_reset_lag (void) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        rd_kafka_t *c;
        const char *topic = "test";
        const int msgcnt = 10;
        const int lag = 3;
        const size_t msgsize = 1000;

        TEST_SAY(_C_MAG "[ Test lagging FFF offset reset ]\n");

        mcluster = test_mock_cluster_new(3, &bootstraps);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, 0, 0, 0, msgcnt, msgsize,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "1",
                                 NULL);

        /* Set broker rack */
        /* Set partition leader to broker 1, follower to broker 2 */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_mock_partition_set_follower(mcluster, topic, 0, 2);

        /* Make follower lag by some messages
         * ( .. -1 because offsets start at 0) */
        rd_kafka_mock_partition_set_follower_wmarks(mcluster, topic, 0,
                                                    -1, msgcnt - lag - 1);

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "client.rack", "myrack");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        /* Make sure we don't consume the entire partition in one Fetch */
        test_conf_set(conf, "fetch.message.max.bytes", "100");

        c = test_create_consumer("mygroup", NULL, conf, NULL);

        test_consumer_assign_partition("lag", c, topic, 0,
                                       RD_KAFKA_OFFSET_INVALID);

        /* Should receive all messages up to the followers hwmark */
        test_consumer_poll("up to wmark", c, 0, 0, 0, msgcnt - lag, NULL);

        /* And then nothing.. as the consumer waits for the replica to
         * catch up. */
        test_consumer_poll_no_msgs("no msgs", c, 0, 3000);

        /* Catch up the replica, consumer should now get the
         * remaining messages */
        rd_kafka_mock_partition_set_follower_wmarks(mcluster, topic, 0, -1, -1);
        test_consumer_poll("remaining", c, 0, 1, msgcnt - lag, lag, NULL);

        test_consumer_close(c);

        rd_kafka_destroy(c);

        test_mock_cluster_destroy(mcluster);

        TEST_SAY(_C_GRN "[ Test lagging FFF offset reset PASSED ]\n");
}


/**
 * @brief Test delegating consumer to a follower that does not exist,
 *        the consumer should not be able to consume any messages (which
 *        is questionable but for a later PR). Then change to a valid
 *        replica and verify messages can be consumed.
 */
static void do_test_unknown_follower (void) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        rd_kafka_t *c;
        const char *topic = "test";
        const int msgcnt = 1000;
        const size_t msgsize = 1000;
        test_msgver_t mv;

        TEST_SAY(_C_MAG "[ Test unknown follower ]\n");

        mcluster = test_mock_cluster_new(3, &bootstraps);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, 0, 0, 0, msgcnt, msgsize,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "10",
                                 NULL);

        /* Set partition leader to broker 1, follower
         * to non-existent broker 19 */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_mock_partition_set_follower(mcluster, topic, 0, 19);

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "client.rack", "myrack");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        /* Make sure we don't consume the entire partition in one Fetch */
        test_conf_set(conf, "fetch.message.max.bytes", "100");

        c = test_create_consumer("mygroup", NULL, conf, NULL);

        test_consumer_assign_partition("unknown follower", c, topic, 0,
                                       RD_KAFKA_OFFSET_INVALID);

        test_consumer_poll_no_msgs("unknown follower", c, 0, 5000);

        /* Set a valid follower (broker 3) */
        rd_kafka_mock_partition_set_follower(mcluster, topic, 0, 3);
        test_msgver_init(&mv, 0);
        test_consumer_poll("proper follower", c, 0, 1, 0, msgcnt, &mv);
        /* Verify messages were indeed received from broker 3 */
        test_msgver_verify0(__FUNCTION__, __LINE__, "broker_id",
                            &mv, TEST_MSGVER_BY_BROKER_ID,
                            (struct test_mv_vs){ .msg_base = 0,
                                            .exp_cnt = msgcnt,
                                            .broker_id = 3 });
        test_msgver_clear(&mv);

        test_consumer_close(c);

        rd_kafka_destroy(c);

        test_mock_cluster_destroy(mcluster);

        TEST_SAY(_C_GRN "[ Test unknown follower PASSED ]\n");
}


/**
 * @brief Issue #2955: Verify that fetch does not stall until next
 *        periodic metadata timeout when leader broker is no longer
 *        a replica.
 */
static void do_test_replica_not_available (void) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        rd_kafka_t *c;
        const char *topic = "test";
        const int msgcnt = 1000;

        TEST_SAY(_C_MAG "[ Test REPLICA_NOT_AVAIALBLE ]\n");

        mcluster = test_mock_cluster_new(3, &bootstraps);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, 0, 0, 0, msgcnt, 1000,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "10",
                                 NULL);

        /* Set partition leader to broker 1. */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "client.rack", "myrack");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "60000");
        test_conf_set(conf, "fetch.error.backoff.ms", "1000");

        c = test_create_consumer("mygroup", NULL, conf, NULL);

        rd_kafka_mock_broker_push_request_error_rtts(
                mcluster,
                1/*Broker 1*/,
                1/*FetchRequest*/,
                10,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0,
                RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE, 0);


        test_consumer_assign_partition("REPLICA_NOT_AVAIALBLE", c, topic, 0,
                                       RD_KAFKA_OFFSET_INVALID);

        test_consumer_poll_no_msgs("Wait initial metadata", c, 0, 2000);

        /* Switch leader to broker 2 so that metadata is updated,
         * causing the consumer to start fetching from the new leader. */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);

        test_consumer_poll("Consume", c, 0, 1, 0, msgcnt, NULL);

        test_consumer_close(c);

        rd_kafka_destroy(c);

        test_mock_cluster_destroy(mcluster);

        TEST_SAY(_C_GRN "[ Test REPLICA_NOT_AVAIALBLE PASSED ]\n");
}


int main_0104_fetch_from_follower_mock (int argc, char **argv) {

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_offset_reset("earliest");
        do_test_offset_reset("latest");

        do_test_offset_reset_lag();

        do_test_unknown_follower();

        do_test_replica_not_available();

        return 0;
}
