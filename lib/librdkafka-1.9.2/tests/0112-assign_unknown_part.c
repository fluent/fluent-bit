/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2020, Magnus Edenhill
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

/**
 * Assign consumer to single partition topic and consume a message.
 * Then add a new partition to the topic (i.e., one that will not
 * be in the consumer's metadata) and assign the consumer to it.
 * Verify that partition 0 is not incorrectly reported as missing.
 * See #2915.
 */

int main_0112_assign_unknown_part(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__ + 5, 1);
        int64_t offset    = RD_KAFKA_OFFSET_BEGINNING;
        uint64_t testid   = test_id_generate();
        rd_kafka_t *c;
        rd_kafka_topic_partition_list_t *tpl;
        int r;

        test_conf_init(NULL, NULL, 60);

        TEST_SAY("Creating consumer\n");
        c = test_create_consumer(topic, NULL, NULL, NULL);

        TEST_SAY("Creating topic %s with 1 partition\n", topic);
        test_create_topic(c, topic, 1, 1);
        test_wait_topic_exists(c, topic, 10 * 1000);

        TEST_SAY("Producing message to partition 0\n");
        test_produce_msgs_easy(topic, testid, 0, 1);

        TEST_SAY("Assigning partition 0\n");
        tpl = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(tpl, topic, 0)->offset = offset;
        test_consumer_assign("ASSIGN", c, tpl);

        TEST_SAY("Waiting for message\n");
        test_consumer_poll("CONSUME 0", c, testid, -1, 0, 1, NULL);

        TEST_SAY("Changing partition count for topic %s\n", topic);
        test_create_partitions(NULL, topic, 2);

        /* FIXME: The new partition might not have propagated through the
         *        cluster by the time the producer tries to produce to it
         *        which causes the produce to fail.
         *        Loop until the partition count is correct. */
        while ((r = test_get_partition_count(c, topic, 5000)) != 2) {
                TEST_SAY(
                    "Waiting for %s partition count to reach 2, "
                    "currently %d\n",
                    topic, r);
                rd_sleep(1);
        }

        TEST_SAY("Producing message to partition 1\n");
        test_produce_msgs_easy(topic, testid, 1, 1);

        TEST_SAY("Assigning partitions 1\n");
        rd_kafka_topic_partition_list_add(tpl, topic, 1)->offset = offset;
        test_consumer_assign("ASSIGN", c, tpl);

        TEST_SAY("Waiting for messages\n");
        test_consumer_poll("CONSUME", c, testid, -1, 0, 2, NULL);

        rd_kafka_topic_partition_list_destroy(tpl);
        test_consumer_close(c);
        rd_kafka_destroy(c);

        return 0;
}
