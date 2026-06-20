/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2024, Confluent Inc.
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
#include "../src/rdkafka_proto.h"

#include <stdarg.h>

/**
 * Verify that no duplicate message are consumed after an unnecessary
 * resume, ensuring the fetch version isn't bumped, leading to
 * using a stale next fetch start.
 *
 * @param partition_assignment_strategy Assignment strategy to test.
 */
static void test_no_duplicate_messages_unnecessary_resume(
    const char *partition_assignment_strategy) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *tconf;
        rd_kafka_t *rk;
        test_msgver_t mv;
        rd_kafka_topic_partition_list_t *tlist;
        char *topic =
            rd_strdup(test_mk_topic_name("0050_unnecessary_resume_1", 1));
        uint64_t testid = test_id_generate();
        int msgcnt      = 100;

        SUB_TEST("%s", partition_assignment_strategy);

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        TEST_SAY("Seed the topic with messages\n");
        test_produce_msgs_easy_v(topic, testid, RD_KAFKA_PARTITION_UA, 0,
                                 msgcnt, 1000, "bootstrap.servers", bootstraps,
                                 NULL);

        test_conf_init(&conf, &tconf, 60);
        test_topic_conf_set(tconf, "auto.offset.reset", "smallest");
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "partition.assignment.strategy",
                      partition_assignment_strategy);

        TEST_SAY("Subscribe to topic\n");
        tlist = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(tlist, topic, RD_KAFKA_PARTITION_UA);

        rk = test_create_consumer("mygroup", NULL, conf, tconf);
        TEST_CALL_ERR__(rd_kafka_subscribe(rk, tlist));

        TEST_SAY("Consume and verify messages\n");
        test_msgver_init(&mv, testid);
        test_consumer_poll("consume", rk, testid, -1, 0, msgcnt, &mv);

        TEST_SAY("Unnecessary resume\n");
        tlist->elems[0].partition = 0; /* Resume the only partition */
        TEST_CALL_ERR__(rd_kafka_resume_partitions(rk, tlist));

        TEST_SAY("Ensure no duplicate messages\n");
        test_consumer_poll_no_msgs("consume", rk, testid, (int)(3000));

        test_msgver_verify("consume", &mv, TEST_MSGVER_ORDER | TEST_MSGVER_DUP,
                           0, msgcnt);

        test_msgver_clear(&mv);

        rd_kafka_topic_partition_list_destroy(tlist);
        rd_kafka_consumer_close(rk);
        rd_kafka_destroy(rk);

        test_mock_cluster_destroy(mcluster);

        rd_free(topic);

        SUB_TEST_PASS();
}

int main_0145_pause_resume_mock(int argc, char **argv) {
        if (test_needs_auth()) {
                TEST_SAY("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        test_no_duplicate_messages_unnecessary_resume("range");

        test_no_duplicate_messages_unnecessary_resume("roundrobin");

        test_no_duplicate_messages_unnecessary_resume("cooperative-sticky");

        return 0;
}
