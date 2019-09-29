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

/**
 * Issue #1371:
 * Run two consumers in the same group for a 2-partition topic,
 * alter the topic to have 4 partitions, kill off the first consumer,
 * the second consumer will segfault.
 */

#include "rdkafka.h"


static rd_kafka_t *c1, *c2;
static rd_kafka_resp_err_t state1, state2;

static void rebalance_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                          rd_kafka_topic_partition_list_t *parts, void *opaque) {
        rd_kafka_resp_err_t *statep = NULL;

        if (rk == c1)
                statep = &state1;
        else if (rk == c2)
                statep = &state2;
        else
                TEST_FAIL("Invalid rk %p", rk);

        TEST_SAY("Rebalance for %s: %s:\n", rd_kafka_name(rk), rd_kafka_err2str(err));
        test_print_partition_list(parts);

        if (err == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS)
                rd_kafka_assign(rk, parts);
        else if (err == RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS)
                rd_kafka_assign(rk, NULL);

        *statep = err;
}


int main_0069_consumer_add_parts (int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__ + 5, 1);
        int64_t ts_start;
        int wait_sec;

        test_conf_init(NULL, NULL, 60);

        TEST_SAY("Creating 2 consumers\n");
        c1 = test_create_consumer(topic, rebalance_cb, NULL, NULL);
        c2 = test_create_consumer(topic, rebalance_cb, NULL, NULL);

        TEST_SAY("Creating topic %s with 2 partitions\n", topic);
        test_create_topic(c1, topic, 2, 1);

        TEST_SAY("Subscribing\n");
        test_consumer_subscribe(c1, topic);
        test_consumer_subscribe(c2, topic);


        TEST_SAY("Waiting for initial assignment for both consumers\n");
        while (state1 != RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS ||
               state2 != RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS) {
                test_consumer_poll_no_msgs("wait-rebalance", c1, 0, 1000);
                test_consumer_poll_no_msgs("wait-rebalance", c2, 0, 1000);
        }


        TEST_SAY("Changing partition count for topic %s\n", topic);
        test_create_partitions(NULL, topic, 4);

        TEST_SAY("Closing consumer 1 (to quickly trigger rebalance with new partitions)\n");
        test_consumer_close(c1);
        rd_kafka_destroy(c1);

        TEST_SAY("Wait 10 seconds for consumer 2 not to crash\n");
        wait_sec = test_quick ? 5 : 10;
        ts_start = test_clock();
        do {
                test_consumer_poll_no_msgs("wait-stable", c2, 0, 1000);
        } while (test_clock() < ts_start + (wait_sec * 1000000));

        TEST_ASSERT(state2 == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                    "Expected consumer 2 to have assignment, not in state %s",
                    rd_kafka_err2str(state2));

        test_consumer_close(c2);
        rd_kafka_destroy(c2);

        return 0;
}
