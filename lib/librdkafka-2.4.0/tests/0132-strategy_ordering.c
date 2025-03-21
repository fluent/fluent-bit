/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2022, Magnus Edenhill
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


#define _PART_CNT 4

static void verify_roundrobin_assignment(rd_kafka_t *c[]) {
        rd_kafka_topic_partition_list_t *assignment1;
        rd_kafka_topic_partition_list_t *assignment2;

        TEST_CALL_ERR__(rd_kafka_assignment(c[0], &assignment1));

        TEST_ASSERT(assignment1->cnt == _PART_CNT / 2,
                    "Roundrobin: Assignment partitions for %s"
                    "is %d, but the expected is %d\n",
                    rd_kafka_name(c[0]), assignment1->cnt, _PART_CNT / 2);

        TEST_ASSERT(assignment1->elems[0].partition == 0,
                    "Roundrobin: First assignment partition for %s"
                    "is %d, but the expectation is %d\n",
                    rd_kafka_name(c[0]), assignment1->elems[0].partition, 0);
        TEST_ASSERT(assignment1->elems[1].partition == 2,
                    "Roundrobin: Second assignment partition for %s"
                    "is %d, but the expectation is %d\n",
                    rd_kafka_name(c[0]), assignment1->elems[1].partition, 2);

        TEST_CALL_ERR__(rd_kafka_assignment(c[1], &assignment2));
        TEST_ASSERT(assignment2->cnt == _PART_CNT / 2,
                    "Roundrobin: Assignment partitions for %s"
                    "is %d, but the expected is %d\n",
                    rd_kafka_name(c[1]), assignment2->cnt, _PART_CNT / 2);

        TEST_ASSERT(assignment2->elems[0].partition == 1,
                    "Roundrobin: First assignment partition for %s"
                    "is %d, but the expectation is %d\n",
                    rd_kafka_name(c[1]), assignment2->elems[0].partition, 1);
        TEST_ASSERT(assignment2->elems[1].partition == 3,
                    "Roundrobin: Second assignment partition for %s"
                    "is %d, but the expectation is %d\n",
                    rd_kafka_name(c[1]), assignment2->elems[1].partition, 3);

        rd_kafka_topic_partition_list_destroy(assignment1);
        rd_kafka_topic_partition_list_destroy(assignment2);
}

static void verify_range_assignment(rd_kafka_t *c[]) {
        rd_kafka_topic_partition_list_t *assignment1;
        rd_kafka_topic_partition_list_t *assignment2;

        TEST_CALL_ERR__(rd_kafka_assignment(c[0], &assignment1));

        TEST_ASSERT(assignment1->cnt == _PART_CNT / 2,
                    "Range: Assignment partition for %s"
                    "is %d, but the expected is %d\n",
                    rd_kafka_name(c[0]), assignment1->cnt, _PART_CNT / 2);

        TEST_ASSERT(assignment1->elems[0].partition == 0,
                    "Range: First assignment partition for %s"
                    "is %d, but the expectation is %d\n",
                    rd_kafka_name(c[0]), assignment1->elems[0].partition, 0);
        TEST_ASSERT(assignment1->elems[1].partition == 1,
                    "Range: Second assignment partition for %s"
                    "is %d, but the expectation is %d\n",
                    rd_kafka_name(c[0]), assignment1->elems[1].partition, 1);

        TEST_CALL_ERR__(rd_kafka_assignment(c[1], &assignment2));
        TEST_ASSERT(assignment2->cnt == _PART_CNT / 2,
                    "Range: Assignment partition for %s"
                    "is %d, but the expected is %d\n",
                    rd_kafka_name(c[1]), assignment2->cnt, _PART_CNT / 2);

        TEST_ASSERT(assignment2->elems[0].partition == 2,
                    "Range: First assignment partition for %s"
                    "is %d, but the expectation is %d\n",
                    rd_kafka_name(c[1]), assignment2->elems[0].partition, 2);
        TEST_ASSERT(assignment2->elems[1].partition == 3,
                    "Range: Second assignment partition for %s"
                    "is %d, but the expectation is %d\n",
                    rd_kafka_name(c[1]), assignment2->elems[1].partition, 3);

        rd_kafka_topic_partition_list_destroy(assignment1);
        rd_kafka_topic_partition_list_destroy(assignment2);
}

static void do_test_stragety_ordering(const char *assignor,
                                      const char *expected_assignor) {
        rd_kafka_conf_t *conf;
#define _C_CNT 2
        rd_kafka_t *c[_C_CNT];

        const char *topic;
        const int msgcnt = 100;
        int i;
        uint64_t testid;

        SUB_TEST("partition.assignment.strategy = %s", assignor);

        testid = test_id_generate();

        topic = test_mk_topic_name("0132-strategy_ordering", 1);
        test_create_topic(NULL, topic, _PART_CNT, 1);
        test_produce_msgs_easy(topic, testid, RD_KAFKA_PARTITION_UA, msgcnt);

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "partition.assignment.strategy", assignor);

        for (i = 0; i < _C_CNT; i++) {
                char name[16];

                rd_snprintf(name, sizeof(name), "c%d", i);
                test_conf_set(conf, "client.id", name);

                c[i] = test_create_consumer(assignor, NULL,
                                            rd_kafka_conf_dup(conf), NULL);

                test_consumer_subscribe(c[i], topic);
        }

        rd_kafka_conf_destroy(conf);

        /* Await assignments for all consumers */
        for (i = 0; i < _C_CNT; i++) {
                test_consumer_wait_assignment(c[i], rd_true);
        }

        if (!strcmp(expected_assignor, "range"))
                verify_range_assignment(c);
        else
                verify_roundrobin_assignment(c);

        for (i = 0; i < _C_CNT; i++) {
                test_consumer_close(c[i]);
                rd_kafka_destroy(c[i]);
        }

        SUB_TEST_PASS();
}


int main_0132_strategy_ordering(int argc, char **argv) {
        do_test_stragety_ordering("roundrobin,range", "roundrobin");
        do_test_stragety_ordering("range,roundrobin", "range");
        return 0;
}
