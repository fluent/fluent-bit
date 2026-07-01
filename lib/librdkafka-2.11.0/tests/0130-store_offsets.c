/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020-2022, Magnus Edenhill
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
 * Verify that offsets_store() commits the right offsets and metadata,
 * and is not allowed for unassigned partitions.
 */
static void do_test_store_unassigned(void) {
        const char *topic = test_mk_topic_name("0130_store_unassigned", 1);
        rd_kafka_conf_t *conf;
        rd_kafka_t *c;
        rd_kafka_topic_partition_list_t *parts;
        rd_kafka_resp_err_t err;
        rd_kafka_message_t *rkmessage;
        char metadata[]             = "metadata";
        const int64_t proper_offset = 900, bad_offset = 300;

        SUB_TEST_QUICK();

        test_produce_msgs_easy(topic, 0, 0, 1000);

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.offset.store", "false");
        test_conf_set(conf, "enable.partition.eof", "true");

        c = test_create_consumer(topic, NULL, conf, NULL);

        parts = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(parts, topic, 0);
        TEST_CALL_ERR__(rd_kafka_assign(c, parts));

        TEST_SAY("Consume one message\n");
        test_consumer_poll_once(c, NULL, tmout_multip(3000));

        parts->elems[0].offset        = proper_offset;
        parts->elems[0].metadata_size = sizeof metadata;
        parts->elems[0].metadata      = malloc(parts->elems[0].metadata_size);
        memcpy(parts->elems[0].metadata, metadata,
               parts->elems[0].metadata_size);
        TEST_SAY("Storing offset %" PRId64
                 " with metadata while assigned: should succeed\n",
                 parts->elems[0].offset);
        TEST_CALL_ERR__(rd_kafka_offsets_store(c, parts));

        TEST_SAY("Committing\n");
        TEST_CALL_ERR__(rd_kafka_commit(c, NULL, rd_false /*sync*/));

        TEST_SAY("Unassigning partitions and trying to store again\n");
        TEST_CALL_ERR__(rd_kafka_assign(c, NULL));

        parts->elems[0].offset        = bad_offset;
        parts->elems[0].metadata_size = 0;
        rd_free(parts->elems[0].metadata);
        parts->elems[0].metadata = NULL;
        TEST_SAY("Storing offset %" PRId64 " while unassigned: should fail\n",
                 parts->elems[0].offset);
        err = rd_kafka_offsets_store(c, parts);
        TEST_ASSERT_LATER(err != RD_KAFKA_RESP_ERR_NO_ERROR,
                          "Expected offsets_store() to fail");
        TEST_ASSERT(parts->cnt == 1);

        TEST_ASSERT(parts->elems[0].err == RD_KAFKA_RESP_ERR__STATE,
                    "Expected %s [%" PRId32
                    "] to fail with "
                    "_STATE, not %s",
                    parts->elems[0].topic, parts->elems[0].partition,
                    rd_kafka_err2name(parts->elems[0].err));

        TEST_SAY("Committing: should fail\n");
        err = rd_kafka_commit(c, NULL, rd_false /*sync*/);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__NO_OFFSET,
                    "Expected commit() to fail with NO_OFFSET, not %s",
                    rd_kafka_err2name(err));

        TEST_SAY("Assigning partition again\n");
        parts->elems[0].offset = RD_KAFKA_OFFSET_INVALID; /* Use committed */
        TEST_CALL_ERR__(rd_kafka_assign(c, parts));

        TEST_SAY("Consuming message to verify committed offset\n");
        rkmessage = rd_kafka_consumer_poll(c, tmout_multip(3000));
        TEST_ASSERT(rkmessage != NULL, "Expected message");
        TEST_SAY("Consumed message with offset %" PRId64 "\n",
                 rkmessage->offset);
        TEST_ASSERT(!rkmessage->err, "Expected proper message, not error %s",
                    rd_kafka_message_errstr(rkmessage));
        TEST_ASSERT(rkmessage->offset == proper_offset,
                    "Expected first message to be properly stored "
                    "offset %" PRId64 ", not %" PRId64,
                    proper_offset, rkmessage->offset);

        TEST_SAY(
            "Retrieving committed offsets to verify committed offset "
            "metadata\n");
        rd_kafka_topic_partition_list_t *committed_toppar;
        committed_toppar = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(committed_toppar, topic, 0);
        TEST_CALL_ERR__(
            rd_kafka_committed(c, committed_toppar, tmout_multip(3000)));
        TEST_ASSERT(committed_toppar->elems[0].offset == proper_offset,
                    "Expected committed offset to be %" PRId64 ", not %" PRId64,
                    proper_offset, committed_toppar->elems[0].offset);
        TEST_ASSERT(committed_toppar->elems[0].metadata != NULL,
                    "Expected metadata to not be NULL");
        TEST_ASSERT(strcmp(committed_toppar->elems[0].metadata, metadata) == 0,
                    "Expected metadata to be %s, not %s", metadata,
                    (char *)committed_toppar->elems[0].metadata);

        TEST_SAY("Storing next offset without metadata\n");
        parts->elems[0].offset = proper_offset + 1;
        TEST_CALL_ERR__(rd_kafka_offsets_store(c, parts));

        TEST_SAY("Committing\n");
        TEST_CALL_ERR__(rd_kafka_commit(c, NULL, rd_false /*sync*/));

        TEST_SAY(
            "Retrieving committed offset to verify empty committed offset "
            "metadata\n");
        rd_kafka_topic_partition_list_t *committed_toppar_empty;
        committed_toppar_empty = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(committed_toppar_empty, topic, 0);
        TEST_CALL_ERR__(
            rd_kafka_committed(c, committed_toppar_empty, tmout_multip(3000)));
        TEST_ASSERT(committed_toppar_empty->elems[0].offset ==
                        proper_offset + 1,
                    "Expected committed offset to be %" PRId64 ", not %" PRId64,
                    proper_offset, committed_toppar_empty->elems[0].offset);
        TEST_ASSERT(committed_toppar_empty->elems[0].metadata == NULL,
                    "Expected metadata to be NULL");

        rd_kafka_message_destroy(rkmessage);

        rd_kafka_topic_partition_list_destroy(parts);
        rd_kafka_topic_partition_list_destroy(committed_toppar);
        rd_kafka_topic_partition_list_destroy(committed_toppar_empty);

        rd_kafka_consumer_close(c);
        rd_kafka_destroy(c);

        SUB_TEST_PASS();
}


int main_0130_store_offsets(int argc, char **argv) {

        do_test_store_unassigned();

        return 0;
}
