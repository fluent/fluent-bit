/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019-2022, Magnus Edenhill
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
 * @name Verify that the builtin mock cluster works by producing to a topic
 *       and then consuming from it.
 */



/**
 * @brief Test rd_kafka_mock_topic_delete().
 *
 * Create a topic, produce to it, delete it, then verify that
 * a subsequent fetch receives UNKNOWN_TOPIC_OR_PARTITION.
 */
static void do_test_topic_delete(void) {
        const char *topic = test_mk_topic_name("0009_topic_delete", 1);
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_t *p, *c;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        rd_kafka_resp_err_t err;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *parts;
        rd_kafka_message_t *rkm;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(3, &bootstraps);

        /* Create topic explicitly so auto-create doesn't interfere
         * after deletion. */
        TEST_CALL_ERR__(rd_kafka_mock_topic_create(mcluster, topic, 1, 1));

        test_conf_init(&conf, NULL, 30);

        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "allow.auto.create.topics", "false");

        /* Producer */
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        p = test_create_handle(RD_KAFKA_PRODUCER, rd_kafka_conf_dup(conf));

        rkt = test_create_producer_topic(p, topic, NULL);

        /* Produce */
        test_produce_msgs(p, rkt, 0, 0, 0, 10, NULL, 0);
        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(p);

        /* Delete the topic */
        TEST_CALL_ERR__(rd_kafka_mock_topic_delete(mcluster, topic));

        /* Verify deleting a non-existent topic returns error */
        err = rd_kafka_mock_topic_delete(mcluster, topic);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
                    "Expected UNKNOWN_TOPIC_OR_PART, got %s",
                    rd_kafka_err2str(err));

        /* Consumer */
        test_conf_set(conf, "auto.offset.reset", "earliest");
        c = test_create_consumer(topic, NULL, conf, NULL);

        /* Assign */
        parts = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(parts, topic, 0);
        test_consumer_assign("CONSUME_DELETED", c, parts);
        rd_kafka_topic_partition_list_destroy(parts);

        /* Consume - expect no data messages since topic is deleted */
        rkm = rd_kafka_consumer_poll(c, 5000);
        if (rkm) {
                TEST_ASSERT(rkm != NULL &&
                                rkm->err != RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Expected error from deleted topic");
                rd_kafka_message_destroy(rkm);
        }

        rd_kafka_destroy(c);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


/**
 * @brief Test rd_kafka_mock_partition_delete_records().
 *
 * Produce messages, delete records before an offset, then verify that:
 * 1. Consuming from the beginning starts at the new start offset.
 * 2. The API returns errors for invalid inputs.
 */
static void do_test_partition_delete_records(void) {
        const char *topic = test_mk_topic_name("0009_delete_records", 1);
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_t *p, *c;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        rd_kafka_resp_err_t err;
        const char *bootstraps;
        const int msgcnt            = 100;
        const int64_t delete_before = 50;
        rd_kafka_topic_partition_list_t *parts;
        rd_kafka_message_t *rkm;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(3, &bootstraps);

        /* Create topic with 1 partition */
        TEST_CALL_ERR__(rd_kafka_mock_topic_create(mcluster, topic, 1, 1));

        test_conf_init(&conf, NULL, 30);

        test_conf_set(conf, "bootstrap.servers", bootstraps);

        /* Producer */
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        p = test_create_handle(RD_KAFKA_PRODUCER, rd_kafka_conf_dup(conf));

        rkt = test_create_producer_topic(p, topic, NULL);

        /* Produce */
        test_produce_msgs(p, rkt, 0, 0, 0, msgcnt, NULL, 0);
        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(p);

        /* Delete records before offset 50 */
        TEST_CALL_ERR__(rd_kafka_mock_partition_delete_records(
            mcluster, topic, 0, delete_before));

        /* Verify error for non-existent topic */
        err = rd_kafka_mock_partition_delete_records(mcluster, "no_such_topic",
                                                     0, 10);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
                    "Expected UNKNOWN_TOPIC_OR_PART for bad topic, got %s",
                    rd_kafka_err2str(err));

        /* Verify error for non-existent partition */
        err = rd_kafka_mock_partition_delete_records(mcluster, topic, 99, 10);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
                    "Expected UNKNOWN_TOPIC_OR_PART for bad partition, got %s",
                    rd_kafka_err2str(err));

        /* Verify error for offset beyond end */
        err = rd_kafka_mock_partition_delete_records(mcluster, topic, 0,
                                                     msgcnt + 100);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE,
                    "Expected OFFSET_OUT_OF_RANGE, got %s",
                    rd_kafka_err2str(err));

        /* Consumer */
        test_conf_set(conf, "auto.offset.reset", "earliest");
        c = test_create_consumer(topic, NULL, conf, NULL);

        /* Assign */
        parts = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(parts, topic, 0);
        test_consumer_assign("CONSUME_AFTER_DELETE", c, parts);
        rd_kafka_topic_partition_list_destroy(parts);

        /* Consume - first message should be at offset >= delete_before */
        rkm = rd_kafka_consumer_poll(c, 10000);
        TEST_ASSERT(rkm != NULL, "Expected message, got NULL");
        TEST_ASSERT(rkm->err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected success, got %s", rd_kafka_err2str(rkm->err));
        TEST_ASSERT(rkm->offset >= delete_before,
                    "Expected first message offset >= %" PRId64
                    ", got %" PRId64,
                    delete_before, rkm->offset);
        TEST_SAY("First message after delete_records: offset %" PRId64 "\n",
                 rkm->offset);
        rd_kafka_message_destroy(rkm);

        rd_kafka_destroy(c);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


int main_0009_mock_cluster(int argc, char **argv) {
        const char *topic = test_mk_topic_name("0009_mock_cluster", 1);
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_t *p, *c;
        rd_kafka_topic_t *rkt;
        rd_kafka_conf_t *conf;
        const int msgcnt = 100;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *parts;

        TEST_SKIP_MOCK_CLUSTER(0);

        mcluster = test_mock_cluster_new(3, &bootstraps);


        test_conf_init(&conf, NULL, 30);

        test_conf_set(conf, "bootstrap.servers", bootstraps);

        /* Producer */
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        p = test_create_handle(RD_KAFKA_PRODUCER, rd_kafka_conf_dup(conf));

        /* Consumer */
        test_conf_set(conf, "auto.offset.reset", "earliest");
        c = test_create_consumer(topic, NULL, conf, NULL);

        rkt = test_create_producer_topic(p, topic, NULL);
        test_wait_topic_exists(p, topic, 5000);

        /* Produce */
        test_produce_msgs(p, rkt, 0, RD_KAFKA_PARTITION_UA, 0, msgcnt, NULL, 0);

        /* Produce tiny messages */
        test_produce_msgs(p, rkt, 0, RD_KAFKA_PARTITION_UA, 0, msgcnt, "hello",
                          5);

        rd_kafka_topic_destroy(rkt);

        /* Assign */
        parts = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(parts, topic, 0);
        rd_kafka_topic_partition_list_add(parts, topic, 1);
        rd_kafka_topic_partition_list_add(parts, topic, 2);
        rd_kafka_topic_partition_list_add(parts, topic, 3);
        test_consumer_assign("CONSUME", c, parts);
        rd_kafka_topic_partition_list_destroy(parts);


        /* Consume */
        test_consumer_poll("CONSUME", c, 0, -1, 0, msgcnt, NULL);

        rd_kafka_destroy(c);
        rd_kafka_destroy(p);

        test_mock_cluster_destroy(mcluster);

        do_test_topic_delete();
        do_test_partition_delete_records();

        return 0;
}
