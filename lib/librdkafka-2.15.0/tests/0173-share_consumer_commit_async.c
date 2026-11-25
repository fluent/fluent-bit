/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2026, Confluent Inc.
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
 * @brief Share consumer rd_kafka_share_commit_async() API tests.
 *
 * Tests the commit_async API in both implicit and explicit ack modes.
 * Verifies that commit_async commits acknowledged records so they are
 * not redelivered, and that it properly extracts acks from the inflight
 * map (preventing consume_batch from re-sending the same acks).
 *
 * Mixed ack types: ACCEPT (~50%), RELEASE (~40%), REJECT (~10%)
 */

#define MAX_MSGS      500
#define CONSUME_ARRAY 10001

/** Common producer reused across all non-mock subtests. */
static rd_kafka_t *common_producer;

/** Common admin client reused across all non-mock subtests. */
static rd_kafka_t *common_admin;


/**
 * @brief Set share.record.lock.duration.ms for a share group.
 */
static void set_group_lock_duration(const char *group_name,
                                    const char *duration_ms) {
        const char *cfg[] = {"share.record.lock.duration.ms", "SET",
                             duration_ms};

        test_IncrementalAlterConfigs_simple(
            common_admin, RD_KAFKA_RESOURCE_GROUP, group_name, cfg, 1);
}


/**
 * @brief Subscribe a share consumer to topics.
 */
static void subscribe_consumer(rd_kafka_share_t *rkshare,
                               const char **topics,
                               int topic_cnt) {
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_resp_err_t err;
        int i;

        subs = rd_kafka_topic_partition_list_new(topic_cnt);
        for (i = 0; i < topic_cnt; i++)
                rd_kafka_topic_partition_list_add(subs, topics[i],
                                                  RD_KAFKA_PARTITION_UA);

        err = rd_kafka_share_subscribe(rkshare, subs);
        TEST_ASSERT(!err, "Subscribe failed: %s", rd_kafka_err2str(err));

        rd_kafka_topic_partition_list_destroy(subs);
}



/**
 * @brief Determine random ack type with distribution:
 *        ACCEPT ~50%, RELEASE ~40%, REJECT ~10%
 */
static rd_kafka_share_AcknowledgeType_t get_random_ack_type(void) {
        int r = jitter(0, 99);
        if (r < 50)
                return RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT;
        else if (r < 90)
                return RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE;
        else
                return RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT;
}


/* ===================================================================
 *  Implicit ack mode — commit_async commits acks independently of
 *  consume_batch piggybacking.
 *
 *  Consumer 1 (implicit) consumes first batch, calls commit_async,
 *  waits, closes. Consumer 2 consumes remaining and verifies no
 *  offset overlap with consumer 1.
 * =================================================================== */
static void do_test_implicit_second_consumer(void) {
        const char *topic;
        const char *group = "commit-async-implicit-second";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        size_t j;
        int consumed1 = 0, consumed2 = 0;
        int attempts = 0;
        int64_t *c1_offsets;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-impl-2nd", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, MAX_MSGS);

        rkshare = test_create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        c1_offsets = rd_calloc(MAX_MSGS, sizeof(*c1_offsets));

        /* Wait for first batch of records */
        while (consumed1 == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                c1_offsets[consumed1++] = rkm->offset;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Consumer 1 consumed %d messages in first batch\n", consumed1);
        TEST_ASSERT(consumed1 > 0, "Consumer 1 got no records");

        /* commit_async without any subsequent consume_batch */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        rd_sleep(3);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Produce 5 verification records */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Second consumer: should only get the 5 verification records.
         * No lock wait needed — implicit mode close tears down the
         * connection and broker releases records immediately. */
        rkshare = test_create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        error = rd_kafka_share_poll(rkshare, 15000, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_SAY("Consumer 2 consume_batch returned: rcvd=%zu, error=%s\n",
                 rcvd, error ? rd_kafka_error_string(error) : "none");
        if (error) {
                rd_kafka_error_destroy(error);
        }

        for (j = 0; j < rcvd; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                if (!rkm->err) {
                        TEST_ASSERT(rd_kafka_message_delivery_count(rkm) == 1,
                                    "Consumer 2 got redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                        consumed2++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumer 2 got %d messages (expected 5)\n", consumed2);
        TEST_ASSERT(consumed2 == 5, "Expected 5 verification records, got %d",
                    consumed2);

        rd_free(c1_offsets);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Explicit ack mode — commit_async commits explicit ACCEPT acks.
 *
 *  Consumer 1 (explicit) consumes first batch, ACCEPTs each record,
 *  calls commit_async, waits, closes. Consumer 2 consumes remaining
 *  and verifies no offset overlap with consumer 1.
 * =================================================================== */
static void do_test_explicit_second_consumer(void) {
        const char *topic;
        const char *group = "commit-async-explicit-second";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        size_t j;
        int consumed1 = 0, consumed2 = 0;
        int attempts = 0;
        int64_t *c1_offsets;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-expl-2nd", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, MAX_MSGS);

        rkshare = test_create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        c1_offsets = rd_calloc(MAX_MSGS, sizeof(*c1_offsets));

        /* Wait for first batch of records */
        while (consumed1 == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                c1_offsets[consumed1++] = rkm->offset;
                                rd_kafka_share_acknowledge(rkshare, rkm);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Consumer 1 consumed %d messages in first batch\n", consumed1);
        TEST_ASSERT(consumed1 > 0, "Consumer 1 got no records");

        /* commit_async without any subsequent consume_batch */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        rd_sleep(3);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Produce 5 verification records */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Second consumer: should only get the 5 verification records.
         * Records are either committed by the last commit_async or
         * released on the broker side when the connection is closed. */
        rkshare = test_create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        error = rd_kafka_share_poll(rkshare, 15000, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_SAY("Consumer 2 consume_batch returned: rcvd=%zu, error=%s\n",
                 rcvd, error ? rd_kafka_error_string(error) : "none");
        if (error) {
                rd_kafka_error_destroy(error);
        }

        for (j = 0; j < rcvd; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                if (!rkm->err) {
                        TEST_ASSERT(rd_kafka_message_delivery_count(rkm) == 1,
                                    "Consumer 2 got redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                        consumed2++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumer 2 got %d messages (expected 5)\n", consumed2);
        TEST_ASSERT(consumed2 == 5, "Expected 5 verification records, got %d",
                    consumed2);

        rd_free(c1_offsets);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Mixed ack types — commit_async with ACCEPT/RELEASE/REJECT.
 *
 *  Consumer 1 (explicit) acks each record randomly (ACCEPT ~50%,
 *  RELEASE ~40%, REJECT ~10%), calls commit_async after each batch.
 *  Redeliveries (delivery_count > 1) are ACCEPT'd. Drain loop
 *  flushes remaining redeliveries. Consumer 2 gets unredelivered
 *  RELEASE'd records.
 * =================================================================== */
static void do_test_mixed_acks_second_consumer(void) {
        const char *topic;
        const char *group = "commit-async-mixed-second";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        size_t j;
        int consumed = 0, redelivered = 0;
        int released_cnt = 0;
        int attempts     = 0;
        int64_t *released_offsets;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-mixed-2nd", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, MAX_MSGS);

        rkshare = test_create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        released_offsets = rd_calloc(MAX_MSGS, sizeof(*released_offsets));

        /* Consume all records and handle redeliveries in the same loop */
        while ((consumed < MAX_MSGS || redelivered < released_cnt) &&
               attempts++ < 100) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                if (rd_kafka_message_delivery_count(rkm) > 1) {
                                        /* Redelivered — verify it was
                                         * RELEASE'd and ACCEPT it */
                                        int k;
                                        rd_bool_t found = rd_false;

                                        for (k = 0; k < released_cnt; k++) {
                                                if (rkm->offset ==
                                                    released_offsets[k]) {
                                                        found = rd_true;
                                                        released_offsets[k] =
                                                            -1;
                                                        break;
                                                }
                                        }
                                        TEST_ASSERT(
                                            found,
                                            "Redelivered offset %" PRId64
                                            " was not RELEASE'd",
                                            rkm->offset);

                                        rd_kafka_share_acknowledge(rkshare,
                                                                   rkm);
                                        redelivered++;
                                } else {
                                        /* New record — ack with random type */
                                        rd_kafka_share_AcknowledgeType_t
                                            ack_type = get_random_ack_type();

                                        if (ack_type ==
                                            RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT) {
                                                rd_kafka_share_acknowledge(
                                                    rkshare, rkm);
                                        } else {
                                                if (ack_type ==
                                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE)
                                                        released_offsets
                                                            [released_cnt++] =
                                                                rkm->offset;
                                                rd_kafka_share_acknowledge_type(
                                                    rkshare, rkm, ack_type);
                                        }
                                        consumed++;
                                }
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;

                error = rd_kafka_share_commit_async(rkshare);
                TEST_ASSERT(!error, "commit_async failed: %s",
                            error ? rd_kafka_error_string(error) : "");
        }

        TEST_SAY("Consumed %d/%d, released %d, redelivered %d/%d\n", consumed,
                 MAX_MSGS, released_cnt, redelivered, released_cnt);
        TEST_ASSERT(consumed == MAX_MSGS, "Expected %d consumed, got %d",
                    MAX_MSGS, consumed);
        TEST_ASSERT(redelivered == released_cnt,
                    "Expected %d redelivered, got %d", released_cnt,
                    redelivered);

        rd_free(released_offsets);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}



/* ===================================================================
 *  Multiple topics x partitions — commit_async across many
 *  topic-partitions.
 *
 *  Creates 10 topics x 5 partitions. Runs 20 rounds: each round
 *  produces messages, consumes them, and calls commit_async.
 * =================================================================== */
static void do_test_multi_topic_partition(void) {
        const int topic_cnt      = 10;
        const int part_cnt       = 5;
        const int total_parts    = topic_cnt * part_cnt;
        const int rounds         = 20;
        const int msgs_per_part  = 10;
        const int msgs_per_round = msgs_per_part * total_parts;
        const char *group        = "commit-async-multi-tp";
        const char *topics[10];
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        int t, p, round;
        int total_consumed = 0;

        SUB_TEST();

        for (t = 0; t < topic_cnt; t++) {
                topics[t] =
                    rd_strdup(test_mk_topic_name("0173-ca-multi-tp", 1));
                test_create_topic_wait_exists(NULL, topics[t], part_cnt, -1,
                                              60 * 1000);
        }

        rkshare = test_create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, topics, topic_cnt);

        for (round = 0; round < rounds; round++) {
                int consumed = 0;
                int attempts = 0;

                for (t = 0; t < topic_cnt; t++) {
                        for (p = 0; p < part_cnt; p++)
                                test_produce_msgs_simple(common_producer,
                                                         topics[t], p,
                                                         msgs_per_part);
                }

                while (consumed < msgs_per_round && attempts++ < 100) {
                        rd_kafka_messages_t *batch = NULL;
                        size_t rcvd;
                        size_t j;

                        error = rd_kafka_share_poll(rkshare, 5000, &batch);
                        if (error) {
                                rd_kafka_error_destroy(error);
                                continue;
                        }
                        rcvd = rd_kafka_messages_count(batch);

                        for (j = 0; j < rcvd; j++) {
                                rd_kafka_message_t *rkm =
                                    rd_kafka_messages_get(batch, j);
                                if (!rkm->err)
                                        consumed++;
                        }
                        rd_kafka_messages_destroy(batch);
                }

                TEST_SAY("Round %d: consumed %d/%d messages\n", round, consumed,
                         msgs_per_round);
                TEST_ASSERT(consumed == msgs_per_round,
                            "Round %d: Expected %d, got %d", round,
                            msgs_per_round, consumed);

                error = rd_kafka_share_commit_async(rkshare);
                TEST_ASSERT(!error, "Round %d: commit_async failed: %s", round,
                            error ? rd_kafka_error_string(error) : "");

                total_consumed += consumed;
        }

        TEST_SAY("Total consumed across %d rounds: %d\n", rounds,
                 total_consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        for (t = 0; t < topic_cnt; t++)
                rd_free((void *)topics[t]);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Produce-consume loop — mixing commit_async and consume_batch
 *  piggybacking.
 *
 *  5 rounds: each round produces N, consumes N. Even rounds use
 *  commit_async, odd rounds let consume_batch handle acks on the
 *  next poll.
 * =================================================================== */
static void do_test_produce_consume_loop(void) {
        const char *topic;
        const char *group = "commit-async-loop";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        int round;
        const int rounds         = 5;
        const int msgs_per_round = MAX_MSGS / rounds;
        int total_consumed       = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-loop", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        rkshare = test_create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        for (round = 0; round < rounds; round++) {
                int consumed = 0;
                int attempts = 0;

                test_produce_msgs_simple(common_producer, topic, 0,
                                         msgs_per_round);
                TEST_SAY("Round %d: produced %d messages\n", round,
                         msgs_per_round);

                while (consumed < msgs_per_round && attempts++ < 100) {
                        rd_kafka_messages_t *batch = NULL;
                        size_t rcvd;
                        size_t j;

                        error = rd_kafka_share_poll(rkshare, 5000, &batch);
                        if (error) {
                                rd_kafka_error_destroy(error);
                                continue;
                        }
                        rcvd = rd_kafka_messages_count(batch);

                        for (j = 0; j < rcvd; j++) {
                                rd_kafka_message_t *rkm =
                                    rd_kafka_messages_get(batch, j);
                                if (!rkm->err)
                                        consumed++;
                        }
                        rd_kafka_messages_destroy(batch);
                }

                TEST_SAY("Round %d: consumed %d/%d messages\n", round, consumed,
                         msgs_per_round);
                TEST_ASSERT(consumed == msgs_per_round,
                            "Round %d: Expected %d, got %d", round,
                            msgs_per_round, consumed);

                if (round % 2 == 0) {
                        error = rd_kafka_share_commit_async(rkshare);
                        TEST_ASSERT(!error, "Round %d: commit_async failed: %s",
                                    round,
                                    error ? rd_kafka_error_string(error) : "");
                        TEST_SAY("Round %d: used commit_async\n", round);
                } else {
                        TEST_SAY(
                            "Round %d: letting consume_batch handle acks\n",
                            round);
                }

                total_consumed += consumed;
        }

        TEST_SAY("Total consumed across %d rounds: %d\n", rounds,
                 total_consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Multi-round mixed acks — per-round produce, consume, and
 *  commit_async with same-consumer redelivery handling.
 *
 *  3 rounds: each round produces msgs_per_round, consumes them,
 *  acks randomly (ACCEPT/RELEASE/REJECT), calls commit_async.
 *  Redeliveries (delivery_count > 1) are ACCEPT'd inline within
 *  the same round. Verifies consumed + redelivered counts per round.
 * =================================================================== */
static void do_test_multi_round_mixed_second_consumer(void) {
        const char *topic;
        const char *group = "commit-async-multi-round-second";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        int round;
        const int rounds         = 3;
        const int msgs_per_round = MAX_MSGS / rounds;
        int total_consumed       = 0;
        int total_released       = 0;
        int total_redelivered    = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-mr-2nd", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        rkshare = test_create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        for (round = 0; round < rounds; round++) {
                test_produce_msgs_simple(common_producer, topic, 0,
                                         msgs_per_round);
                int consumed     = 0;
                int released_cnt = 0;
                int redelivered  = 0;
                int attempts     = 0;

                /* Consume msgs_per_round new records, handling redeliveries
                 * from previous rounds/batches inline */
                while (
                    (consumed < msgs_per_round || redelivered < released_cnt) &&
                    attempts++ < 100) {
                        rd_kafka_messages_t *batch = NULL;
                        size_t rcvd;
                        size_t j;

                        error = rd_kafka_share_poll(rkshare, 5000, &batch);
                        if (error) {
                                rd_kafka_error_destroy(error);
                                continue;
                        }
                        rcvd = rd_kafka_messages_count(batch);

                        for (j = 0; j < rcvd; j++) {
                                rd_kafka_message_t *rkm =
                                    rd_kafka_messages_get(batch, j);
                                if (!rkm->err) {
                                        if (rd_kafka_message_delivery_count(
                                                rkm) > 1) {
                                                rd_kafka_share_acknowledge(
                                                    rkshare, rkm);
                                                redelivered++;
                                        } else {
                                                rd_kafka_share_AcknowledgeType_t
                                                    ack_type =
                                                        get_random_ack_type();

                                                if (ack_type ==
                                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT) {
                                                        rd_kafka_share_acknowledge(
                                                            rkshare, rkm);
                                                } else {
                                                        if (ack_type ==
                                                            RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE)
                                                                released_cnt++;
                                                        rd_kafka_share_acknowledge_type(
                                                            rkshare, rkm,
                                                            ack_type);
                                                }
                                                consumed++;
                                        }
                                }
                        }
                        rd_kafka_messages_destroy(batch);

                        error = rd_kafka_share_commit_async(rkshare);
                        TEST_ASSERT(!error, "Round %d: commit_async failed: %s",
                                    round,
                                    error ? rd_kafka_error_string(error) : "");
                }

                TEST_SAY(
                    "Round %d: consumed %d/%d, released %d, "
                    "redelivered %d/%d\n",
                    round, consumed, msgs_per_round, released_cnt, redelivered,
                    released_cnt);
                TEST_ASSERT(consumed == msgs_per_round,
                            "Round %d: expected %d consumed, got %d", round,
                            msgs_per_round, consumed);
                TEST_ASSERT(redelivered == released_cnt,
                            "Round %d: expected %d redelivered, got %d", round,
                            released_cnt, redelivered);

                total_consumed += consumed;
                total_released += released_cnt;
                total_redelivered += redelivered;
        }

        TEST_SAY("Total: consumed %d, released %d, redelivered %d\n",
                 total_consumed, total_released, total_redelivered);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  commit_async with no pending acks — returns NULL (no error).
 * =================================================================== */
static void do_test_no_pending_acks(void) {
        const char *group = "commit-async-no-pending";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;

        SUB_TEST();

        rkshare = test_create_share_consumer(group, "implicit");

        error = rd_kafka_share_commit_async(rkshare);
        TEST_SAY("commit_async with no acks: error=%s\n",
                 error ? rd_kafka_error_string(error) : "NULL");
        TEST_ASSERT(!error, "Expected NULL when no pending acks, got error: %s",
                    error ? rd_kafka_error_string(error) : "");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Multiple consecutive commit_async calls — verifies no ack
 *  duplication or loss.
 *
 *  Produce first set, consume, produce second set, call commit_async
 *  3 times, then consume and verify count equals second produce amount.
 * =================================================================== */
static void do_test_multiple_commit_async_calls(void) {
        const char *topic;
        const char *group = "commit-async-multiple-calls";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        const int first_produce  = MAX_MSGS / 2;
        const int second_produce = MAX_MSGS / 2;
        int consumed = 0, consumed2 = 0, call;
        int attempts = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-multi-call", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        rkshare = test_create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        test_produce_msgs_simple(common_producer, topic, 0, first_produce);

        while (consumed < first_produce && attempts++ < 100) {
                rd_kafka_messages_t *batch = NULL;
                size_t rcvd;
                size_t j;

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                consumed++;
                }
                rd_kafka_messages_destroy(batch);
        }

        TEST_SAY("First set: consumed %d/%d messages\n", consumed,
                 first_produce);
        TEST_ASSERT(consumed == first_produce, "Expected %d, got %d",
                    first_produce, consumed);

        test_produce_msgs_simple(common_producer, topic, 0, second_produce);

        for (call = 0; call < 10; call++) {
                error = rd_kafka_share_commit_async(rkshare);
                TEST_SAY("commit_async call %d: error=%s\n", call,
                         error ? rd_kafka_error_string(error) : "NULL");
                TEST_ASSERT(!error, "commit_async call %d failed: %s", call,
                            error ? rd_kafka_error_string(error) : "");
        }

        attempts = 0;
        while (consumed2 < second_produce && attempts++ < 100) {
                rd_kafka_messages_t *batch = NULL;
                size_t rcvd;
                size_t j;

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                consumed2++;
                }
                rd_kafka_messages_destroy(batch);
        }

        TEST_SAY("After multiple commits: consumed %d/%d messages\n", consumed2,
                 second_produce);
        TEST_ASSERT(consumed2 == second_produce,
                    "Expected %d (second produce), got %d", second_produce,
                    consumed2);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  commit_async between produce rounds — correctly separates acks.
 *
 *  Produce N, consume N, commit_async, wait for lock timeout,
 *  produce N more, consume N, commit_async. Second consumer verifies
 *  nothing left.
 * =================================================================== */
static void do_test_commit_between_produces(void) {
        const char *topic;
        const char *group = "commit-async-between-produces";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        size_t j;
        const int half = MAX_MSGS / 2;
        int consumed1 = 0, consumed2 = 0, received = 0;
        int attempts = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-between", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        rkshare = test_create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        /* First half: produce, wait for records, commit_async */
        test_produce_msgs_simple(common_producer, topic, 0, half);

        while (consumed1 == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                TEST_ASSERT(
                                    rd_kafka_message_delivery_count(rkm) == 1,
                                    "First half: redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                                consumed1++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("First half: consumed %d messages\n", consumed1);
        TEST_ASSERT(consumed1 == half, "First half: expected %d, got %d", half,
                    consumed1);

        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        /* Wait for acquisition lock timeout (3 s + buffer) so first half's acks
         * are fully committed or released before producing the second
         * half */
        rd_sleep(4);

        /* Second half: produce more, wait for records, commit_async */
        test_produce_msgs_simple(common_producer, topic, 0, half);

        attempts = 0;
        while (consumed2 == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                TEST_ASSERT(
                                    rd_kafka_message_delivery_count(rkm) == 1,
                                    "Second half: redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                                consumed2++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Second half: consumed %d messages\n", consumed2);
        TEST_ASSERT(consumed2 == half, "Second half: expected %d, got %d", half,
                    consumed2);

        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        rd_sleep(3);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Produce 5 verification records */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Second consumer: should only get the 5 verification records.
         * No lock wait needed — implicit mode close tears down the
         * connection and broker releases records immediately. */
        rkshare = test_create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        error = rd_kafka_share_poll(rkshare, 15000, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_SAY("Consumer 2 consume_batch returned: rcvd=%zu, error=%s\n",
                 rcvd, error ? rd_kafka_error_string(error) : "none");
        if (error) {
                rd_kafka_error_destroy(error);
        }

        for (j = 0; j < rcvd; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                if (!rkm->err) {
                        TEST_ASSERT(rd_kafka_message_delivery_count(rkm) == 1,
                                    "Consumer 2 got redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                        received++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumer 2 got %d messages (expected 5)\n", received);
        TEST_ASSERT(received == 5, "Expected 5 verification records, got %d",
                    received);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  All RELEASE — commit_async with all-RELEASE acks causes full
 *  redelivery within the same consumer.
 *
 *  Consumer (explicit) RELEASEs every new record and ACCEPT's
 *  redeliveries (delivery_count > 1). Verifies all original records
 *  are consumed and all redeliveries are received.
 * =================================================================== */
static void do_test_all_release_second_consumer(void) {
        const char *topic;
        const char *group = "commit-async-all-release-second";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        int consumed = 0, redelivered = 0;
        int attempts = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-allrel-2nd", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, MAX_MSGS);

        rkshare = test_create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume all records: RELEASE new records, ACCEPT redeliveries.
         * Loop until all original records are consumed AND all
         * redeliveries are received. */
        while ((consumed < MAX_MSGS || redelivered < consumed) &&
               attempts++ < 200) {
                rd_kafka_messages_t *batch = NULL;
                size_t rcvd;
                size_t j;

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                if (rd_kafka_message_delivery_count(rkm) > 1) {
                                        rd_kafka_share_acknowledge(rkshare,
                                                                   rkm);
                                        redelivered++;
                                } else {
                                        rd_kafka_share_acknowledge_type(
                                            rkshare, rkm,
                                            RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
                                        consumed++;
                                }
                        }
                }
                rd_kafka_messages_destroy(batch);

                error = rd_kafka_share_commit_async(rkshare);
                TEST_ASSERT(!error, "commit_async failed: %s",
                            error ? rd_kafka_error_string(error) : "");
        }

        TEST_SAY("Consumed %d/%d, redelivered %d/%d\n", consumed, MAX_MSGS,
                 redelivered, consumed);
        TEST_ASSERT(consumed == MAX_MSGS, "Expected %d consumed, got %d",
                    MAX_MSGS, consumed);
        TEST_ASSERT(redelivered == consumed, "Expected %d redelivered, got %d",
                    consumed, redelivered);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  All REJECT — commit_async with all-REJECT acks. Records are not
 *  redelivered.
 *
 *  Consumer 1 (explicit) REJECTs every record, calls commit_async.
 *  Consumer 2 verifies 0 messages (REJECT'd records are archived).
 * =================================================================== */
static void do_test_all_reject_second_consumer(void) {
        const char *topic;
        const char *group = "commit-async-all-reject-second";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        size_t j;
        int consumed = 0, received = 0;
        int attempts = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-allrej-2nd", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, MAX_MSGS);

        rkshare = test_create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        while (consumed < MAX_MSGS && attempts++ < 100) {
                size_t rcvd_inner;

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd_inner = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd_inner; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                rd_kafka_share_acknowledge_type(
                                    rkshare, rkm,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;

                error = rd_kafka_share_commit_async(rkshare);
                TEST_ASSERT(!error, "commit_async failed: %s",
                            error ? rd_kafka_error_string(error) : "");
        }

        TEST_SAY("Consumer 1 consumed %d/%d messages\n", consumed, MAX_MSGS);
        TEST_ASSERT(consumed == MAX_MSGS, "Expected %d consumed, got %d",
                    MAX_MSGS, consumed);

        /* Records are either committed by the last commit_async or
         * released on the broker side when the connection is closed.
         * No lock wait needed.
         * TODO KIP-932: When share consumer close is fully implemented,
         * these tests may need to wait for the acquisition lock
         * timeout before closing as close will commit acknowledged
         * records in explicit acknowledgement mode. */

        rd_sleep(3);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Produce 5 verification records */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Second consumer: should only get the 5 verification records.
         * REJECT'd records are archived and not redelivered. */
        rkshare = test_create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        error = rd_kafka_share_poll(rkshare, 15000, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_SAY("Consumer 2 consume_batch returned: rcvd=%zu, error=%s\n",
                 rcvd, error ? rd_kafka_error_string(error) : "none");
        if (error) {
                rd_kafka_error_destroy(error);
        }

        for (j = 0; j < rcvd; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                if (!rkm->err) {
                        TEST_ASSERT(rd_kafka_message_delivery_count(rkm) == 1,
                                    "Consumer 2 got redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                        received++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumer 2 got %d messages (expected 5)\n", received);
        TEST_ASSERT(received == 5, "Expected 5 verification records, got %d",
                    received);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Per-record commit_async — acknowledges each record individually
 *  and calls commit_async after each acknowledgement.
 *
 *  Waits for acquisition lock timeout, then consumer 2 verifies all
 *  records were committed (0 redelivered).
 * =================================================================== */
static void do_test_per_record_commit_async(void) {
        const char *topic;
        const char *group = "commit-async-per-record";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        size_t j;
        int consumed = 0, received = 0;
        int attempts = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-per-rec", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, MAX_MSGS);

        rkshare = test_create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume all records, ACCEPT each individually with
         * commit_async after every record */
        while (consumed < MAX_MSGS && attempts++ < 100) {
                size_t rcvd_inner;

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd_inner = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd_inner; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;

                                error = rd_kafka_share_commit_async(rkshare);
                                TEST_ASSERT(
                                    !error, "commit_async at msg %d failed: %s",
                                    consumed,
                                    error ? rd_kafka_error_string(error) : "");
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Consumed %d/%d messages with per-record commit_async\n",
                 consumed, MAX_MSGS);
        TEST_ASSERT(consumed == MAX_MSGS, "Expected %d, got %d", MAX_MSGS,
                    consumed);

        /* Records are either committed by the last commit_async or
         * released on the broker side when the connection is closed.
         * No lock wait needed.
         * TODO KIP-932: When share consumer close is fully implemented,
         * these tests may need to wait for the acquisition lock
         * timeout before closing as close will commit acknowledged
         * records in explicit acknowledgement mode. */

        /* Wait for async commits to propagate */
        rd_sleep(3);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Produce 5 verification records */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Second consumer: should only get the 5 verification records.
         * All previous records were ACCEPT'd via per-record commit_async. */
        rkshare = test_create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        error = rd_kafka_share_poll(rkshare, 15000, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_SAY("Consumer 2 consume_batch returned: rcvd=%zu, error=%s\n",
                 rcvd, error ? rd_kafka_error_string(error) : "none");
        if (error) {
                rd_kafka_error_destroy(error);
        }

        for (j = 0; j < rcvd; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                if (!rkm->err) {
                        TEST_ASSERT(rd_kafka_message_delivery_count(rkm) == 1,
                                    "Consumer 2 got redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                        received++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumer 2 got %d messages (expected 5)\n", received);
        TEST_ASSERT(received == 5, "Expected 5 verification records, got %d",
                    received);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Mock broker helpers.
 * =================================================================== */

typedef struct test_ctx_s {
        rd_kafka_t *producer;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
} test_ctx_t;

static test_ctx_t test_ctx_new(void) {
        test_ctx_t ctx;
        rd_kafka_conf_t *conf;
        char errstr[512];

        memset(&ctx, 0, sizeof(ctx));

        ctx.mcluster = test_mock_cluster_new(3, &ctx.bootstraps);

        TEST_ASSERT(rd_kafka_mock_set_apiversion(
                        ctx.mcluster, RD_KAFKAP_ShareGroupHeartbeat, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to enable ShareGroupHeartbeat");
        TEST_ASSERT(rd_kafka_mock_set_apiversion(ctx.mcluster,
                                                 RD_KAFKAP_ShareFetch, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to enable ShareFetch");

        /* Set auto.offset.reset=earliest so tests that produce
         * before consuming see all records. */
        rd_kafka_mock_sharegroup_set_auto_offset_reset(ctx.mcluster, 1);

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        ctx.producer =
            rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(ctx.producer != NULL, "Failed to create producer: %s",
                    errstr);

        return ctx;
}

static void test_ctx_destroy(test_ctx_t *ctx) {
        if (ctx->producer)
                rd_kafka_destroy(ctx->producer);
        if (ctx->mcluster)
                test_mock_cluster_destroy(ctx->mcluster);
        memset(ctx, 0, sizeof(*ctx));
}

static rd_kafka_share_t *new_share_consumer(const char *bootstraps,
                                            const char *group_id,
                                            const char *ack_mode) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);
        test_conf_set(conf, "share.acknowledgement.mode", ack_mode);

        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");
        return rkshare;
}

static void count_share_requests(rd_kafka_mock_cluster_t *mcluster,
                                 int *share_fetch_cntp,
                                 int *share_ack_cntp) {
        size_t cnt;
        size_t i;
        rd_kafka_mock_request_t **requests;

        *share_fetch_cntp = 0;
        *share_ack_cntp   = 0;

        requests = rd_kafka_mock_get_requests(mcluster, &cnt);

        for (i = 0; i < cnt; i++) {
                int16_t api_key = rd_kafka_mock_request_api_key(requests[i]);
                if (api_key == RD_KAFKAP_ShareFetch)
                        (*share_fetch_cntp)++;
                else if (api_key == RD_KAFKAP_ShareAcknowledge)
                        (*share_ack_cntp)++;
        }

        rd_kafka_mock_request_destroy_array(requests, cnt);
}


/* ===================================================================
 *  Mock broker — inflight request caching.
 *
 *  Consumes records, acknowledges each individually and calls
 *  commit_async after each acknowledgement. Verifies ShareFetch
 *  request count < commit_async call count, proving acks are cached
 *  when a request is already inflight (rkb_share_fetch_enqueued=true).
 * =================================================================== */
static void do_test_mock_inflight_caching(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        const char *topic = "mock-inflight-cache";
        const char *t     = topic;
        const int msgcnt  = 100;
        int consumed = 0, i = 0;
        int share_fetch_cnt, share_ack_cnt;
        int commit_cnt = 0;

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        rkshare =
            new_share_consumer(ctx.bootstraps, "sg-mock-inflight", "explicit");

        subscribe_consumer(rkshare, &t, 1);

        /* Clear and start tracking requests before the consume+ack+commit
         * loop */
        rd_kafka_mock_start_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);

        /* Consume records batch-by-batch, acknowledging each record
         * individually and calling commit_async after each acknowledgement.
         * Most commit_async calls will find an inflight request and
         * cache the acks in rkb_share_async_ack_details instead of
         * sending a new ShareFetch request. */
        while (consumed < msgcnt && i < 30) {
                rd_kafka_messages_t *batch = NULL;
                size_t rcvd;
                size_t j;

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                i++;
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;

                                error = rd_kafka_share_commit_async(rkshare);
                                TEST_ASSERT(
                                    !error, "commit_async at msg %d failed: %s",
                                    consumed,
                                    error ? rd_kafka_error_string(error) : "");
                                commit_cnt++;
                        }
                }
                rd_kafka_messages_destroy(batch);
        }
        TEST_SAY("Mock: consumed %d/%d\n", consumed, msgcnt);
        TEST_ASSERT(consumed == msgcnt, "Expected %d, got %d", msgcnt,
                    consumed);

        /* Wait for async ops to complete before counting requests */
        rd_sleep(3);

        count_share_requests(ctx.mcluster, &share_fetch_cnt, &share_ack_cnt);
        rd_kafka_mock_stop_request_tracking(ctx.mcluster);

        /* We called commit_async 100 times but the total number of
         * ShareFetch + ShareAcknowledge requests should be much fewer
         * due to inflight caching. Ack-only requests use ShareAcknowledge
         * RPC instead of ShareFetch. */
        TEST_SAY(
            "Mock: commit_async calls=%d, ShareFetch requests=%d, "
            "ShareAcknowledge requests=%d\n",
            commit_cnt, share_fetch_cnt, share_ack_cnt);
        TEST_ASSERT(share_ack_cnt > 0,
                    "Expected at least one ShareAcknowledge request, got %d",
                    share_ack_cnt);
        TEST_ASSERT(share_fetch_cnt + share_ack_cnt < commit_cnt,
                    "Expected fewer total share requests (%d + %d = %d) than "
                    "commit_async calls (%d) due to inflight caching",
                    share_fetch_cnt, share_ack_cnt,
                    share_fetch_cnt + share_ack_cnt, commit_cnt);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Acquisition lock timeout — verify that records are redelivered
 *  to the SAME consumer after lock expiry when not acknowledged.
 *
 *  TODO KIP-932: Move this to 0171 file maybe when admin client
 *  related things are finalized in that test case.
 *
 *  Steps:
 *    1. Produce 10 records.
 *    2. Consume all 10 — verify delivery_count == 1.
 *    3. Do NOT acknowledge or commit.
 *    4. Wait for the 3 s acquisition lock to expire.
 *    5. Consume again — verify the same 10 records arrive with
 *       delivery_count == 2.
 * =================================================================== */
static void do_test_lock_timeout_redelivery(void) {
        const char *topic;
        const char *group = "commit-async-lock-timeout";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        size_t j;
        int consumed1 = 0, consumed2 = 0;
        int attempts;
        const int msg_cnt = 10;

        SUB_TEST("Lock timeout redelivery to same consumer");

        topic = test_mk_topic_name("0173-ca-lock-to", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, msg_cnt);

        rkshare = test_create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        /* First consume: get all records, verify delivery_count == 1.
         * Do NOT call commit_async — records stay ACQUIRED. */
        attempts = 0;
        while (consumed1 == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                TEST_ASSERT(
                                    rd_kafka_message_delivery_count(rkm) == 1,
                                    "First consume: expected delivery_count=1, "
                                    "got %d at offset %" PRId64,
                                    rd_kafka_message_delivery_count(rkm),
                                    rkm->offset);
                                consumed1++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("First consume: got %d/%d records (not acknowledged)\n",
                 consumed1, msg_cnt);
        TEST_ASSERT(consumed1 > 0, "Expected records on first consume, got 0");

        /* Wait for acquisition lock to expire (3 s + buffer) */
        TEST_SAY("Waiting 4 s for acquisition lock to expire...\n");
        rd_sleep(4);

        /* Second consume on the SAME consumer: records should be
         * redelivered with delivery_count == 2. */
        attempts = 0;
        while (consumed2 == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                TEST_ASSERT(
                                    rd_kafka_message_delivery_count(rkm) == 2,
                                    "Second consume: expected "
                                    "delivery_count=2, got %d at "
                                    "offset %" PRId64,
                                    rd_kafka_message_delivery_count(rkm),
                                    rkm->offset);
                                consumed2++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Second consume: got %d/%d redelivered records\n", consumed2,
                 msg_cnt);
        TEST_ASSERT(consumed2 > 0, "Expected redelivered records, got 0");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test: commit_async callback invocation.
 *
 *  Verifies that share_acknowledgement_commit_cb is invoked after
 *  commit_async when acks are piggybacked on ShareFetch.
 * =================================================================== */
static void do_test_commit_async_callback(void) {
        const char *topic;
        const char *group = "commit-async-callback";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        size_t j;
        int consumed              = 0;
        int attempts              = 0;
        test_ack_cb_state_t state = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-callback", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 50);

        rkshare =
            test_create_share_consumer_with_cb(group, "implicit", &state, NULL);
        const char *grp_conf[] = {"share.auto.offset.reset", "SET", "earliest"};
        test_alter_group_configurations(group, grp_conf, 1);
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume some messages */
        while (consumed < 20 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Consumed %d messages\n", consumed);
        TEST_ASSERT(consumed > 0, "Expected to consume some messages");

        /* Call commit_async to trigger callback */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        /* Wait for callback */
        test_wait_for_cb_with_poll(&state, rkshare, 1, 10000);

        TEST_SAY("Callback count=%d, total_offsets=%zu, last_err=%s\n",
                 state.callback_cnt, state.total_offsets,
                 rd_kafka_err2name(test_ack_cb_state_first_err(&state)));

        TEST_ASSERT(state.callback_cnt >= 1,
                    "Expected at least 1 callback, got %d", state.callback_cnt);
        TEST_ASSERT(state.total_offsets > 0,
                    "Expected offsets in callback, got %zu",
                    state.total_offsets);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Partial-batch commit_async semantics.
 *
 *  In explicit mode, the next consume_batch must error while any record
 *  from the previous batch is un-acked. After the remaining records are
 *  acked and a second commit_async is issued, consume_batch can drive
 *  the piggybacked acks and the commit callback fires for all offsets.
 * =================================================================== */
static void do_test_partial_batch_commit_async(void) {
        const char *topic;
        const char *group = "commit-async-partial-batch";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t ack_err;
        rd_kafka_messages_t *batches[CONSUME_ARRAY] = {NULL};
        size_t batch_cnt                            = 0;
        size_t total                                = 0;
        size_t j;
        test_ack_cb_state_t state = {0};
        const int msg_cnt         = 5;
        int attempts              = 0;
        size_t to_ack_first;
        size_t acked                    = 0;
        size_t seen                     = 0;
        int wait_elapsed                = 0;
        rd_kafka_messages_t *wait_batch = NULL;
        rd_kafka_error_t *wait_err      = NULL;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-partial", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, msg_cnt);

        rkshare =
            test_create_share_consumer_with_cb(group, "explicit", &state, NULL);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume all msg_cnt records (may take multiple polls). Keep each
         * returned batch alive so the message pointers remain valid for
         * later acknowledgement. */
        while (total < (size_t)msg_cnt && attempts++ < 30) {
                rd_kafka_messages_t *poll_batch = NULL;

                error = rd_kafka_share_poll(rkshare, 3000, &poll_batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                batches[batch_cnt++] = poll_batch;
                total += rd_kafka_messages_count(poll_batch);
        }
        TEST_ASSERT(total == (size_t)msg_cnt,
                    "Expected exactly %d records, got %zu", msg_cnt, total);

        /* Acknowledge first 3 records across the accumulated batches; leave
         * the remainder un-acked. */
        to_ack_first = 3;
        acked        = 0;
        for (j = 0; j < batch_cnt && acked < to_ack_first; j++) {
                size_t k, n = rd_kafka_messages_count(batches[j]);
                for (k = 0; k < n && acked < to_ack_first; k++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batches[j], k);
                        ack_err = rd_kafka_share_acknowledge_type(
                            rkshare, rkm,
                            RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                        TEST_ASSERT(ack_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                                    "First-half ACCEPT %zu failed: %s", acked,
                                    rd_kafka_err2str(ack_err));
                        acked++;
                }
        }

        /* commit_async itself succeeds — it just schedules. */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "First commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        /* While un-acked records remain in the batch, share_poll must
         * return _STATE rather than proceed. */
        rd_kafka_messages_t *dummy = NULL;
        rd_kafka_error_t *e        = rd_kafka_share_poll(rkshare, 1000, &dummy);
        TEST_ASSERT(e != NULL,
                    "Expected share_poll to return _STATE while "
                    "un-acked records remain, got NULL error");
        TEST_ASSERT(rd_kafka_error_code(e) == RD_KAFKA_RESP_ERR__STATE,
                    "Expected _STATE, got %s",
                    rd_kafka_err2name(rd_kafka_error_code(e)));
        TEST_SAY("Got expected _STATE from share_poll: %s\n",
                 rd_kafka_error_string(e));
        rd_kafka_error_destroy(e);
        rd_kafka_messages_destroy(dummy);

        /* Acknowledge the remaining records across the batches. */
        for (j = 0; j < batch_cnt; j++) {
                size_t k, n = rd_kafka_messages_count(batches[j]);
                for (k = 0; k < n; k++) {
                        rd_kafka_message_t *rkm;
                        if (seen < to_ack_first) {
                                seen++;
                                continue;
                        }
                        rkm     = rd_kafka_messages_get(batches[j], k);
                        ack_err = rd_kafka_share_acknowledge_type(
                            rkshare, rkm,
                            RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                        TEST_ASSERT(ack_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                                    "Second-half ACCEPT %zu (offset=%" PRId64
                                    ") failed: %s",
                                    seen, rkm->offset,
                                    rd_kafka_err2str(ack_err));
                        seen++;
                }
        }

        /* Second commit_async commits the remaining acks */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "Second commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        /* Now share_poll can proceed and drive piggybacked acks. The two
         * commits may surface as one or two callbacks depending on broker
         * coalescing, so wait on total_offsets rather than callback_cnt:
         * the first commit's callback can fire during the _STATE-returning
         * poll above, which would short-circuit a callback_cnt>=1 wait
         * before the second commit lands. */
        while (state.total_offsets < (size_t)total && wait_elapsed < 15000) {
                wait_batch = NULL;
                wait_err   = rd_kafka_share_poll(rkshare, 100, &wait_batch);
                if (wait_err)
                        rd_kafka_error_destroy(wait_err);
                rd_kafka_messages_destroy(wait_batch);
                wait_elapsed += 100;
        }
        TEST_ASSERT(state.callback_cnt >= 1,
                    "Expected ack commit callback to fire after full batch "
                    "ack + commit_async, got %d",
                    state.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&state) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Callback errored: %s",
                    rd_kafka_err2name(test_ack_cb_state_first_err(&state)));
        TEST_ASSERT(state.total_offsets >= (size_t)total,
                    "Expected callback to report %zu offsets, got %zu", total,
                    state.total_offsets);
        TEST_SAY("Partial commit callbacks=%d, total_offsets=%zu\n",
                 state.callback_cnt, state.total_offsets);

        for (j = 0; j < batch_cnt; j++)
                rd_kafka_messages_destroy(batches[j]);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Implicit ack callback fires from next poll's piggybacked acks
 *  without any explicit commit_async call.
 * =================================================================== */
static void do_test_implicit_callback_no_explicit_commit(void) {
        const char *topic;
        const char *group = "commit-async-implicit-no-commit";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd, j;
        test_ack_cb_state_t state = {0};
        const int msg_cnt         = 20;
        int consumed              = 0;
        int attempts              = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-impl-no-commit", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, msg_cnt);

        rkshare =
            test_create_share_consumer_with_cb(group, "implicit", &state, NULL);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* First poll: drain all produced records. share_poll typically
         * returns the whole broker-side RecordBatch (so all msg_cnt records
         * arrive in one call), but the loop tolerates split deliveries. */
        while (consumed < msg_cnt && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 2000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed == msg_cnt,
                    "Expected to consume %d messages, got %d", msg_cnt,
                    consumed);

        /* Subsequent polls without any commit_async — callback should still
         * fire via piggybacked acks on the next ShareFetch. */
        attempts = 10;
        while (attempts-- > 0 && state.callback_cnt == 0) {
                error = rd_kafka_share_poll(rkshare, 2000, &batch);
                if (error)
                        rd_kafka_error_destroy(error);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(state.callback_cnt >= 1,
                    "Expected callback from implicit piggybacked acks (no "
                    "explicit commit), got %d",
                    state.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&state) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Callback errored: %s",
                    rd_kafka_err2name(test_ack_cb_state_first_err(&state)));

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Lock-expiry surfaces an error in the ack commit callback.
 *
 *  Explicit mode + short lock duration: poll a record, acknowledge it,
 *  sleep past the lock expiry, then commit_async. The broker should
 *  reject the stale ack and the error must be reported via the
 *  acknowledgement commit callback.
 * =================================================================== */
static void do_test_lock_expiry_callback_err(void) {
        const char *topic;
        const char *group = "commit-async-lock-expiry-cb";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t ack_err;
        rd_kafka_messages_t *batch = NULL;
        size_t j;
        size_t consumed           = 0;
        int attempts              = 0;
        test_ack_cb_state_t state = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-lock-cb", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 3);

        rkshare =
            test_create_share_consumer_with_cb(group, "explicit", &state, NULL);
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume records (acquires lock) */
        while (consumed == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 2000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                consumed = rd_kafka_messages_count(batch);
        }
        TEST_ASSERT(consumed > 0, "Expected to consume records, got 0");

        /* Acknowledge all consumed records explicitly */
        for (j = 0; j < consumed; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                ack_err                 = rd_kafka_share_acknowledge_type(
                    rkshare, rkm, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                TEST_ASSERT(ack_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "ACCEPT failed: %s", rd_kafka_err2str(ack_err));
        }

        /* Sleep past acquisition-lock expiry (3s + buffer) */
        TEST_SAY("Sleeping 4 s for lock expiry before commit_async...\n");
        rd_sleep(4);

        /* commit_async on stale acks - broker should reject them */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async returned error directly: %s",
                    error ? rd_kafka_error_string(error) : "");

        test_wait_for_cb_with_poll(&state, rkshare, 1, 15000);

        TEST_SAY("Callback count=%d, total_offsets=%zu, last_err=%s\n",
                 state.callback_cnt, state.total_offsets,
                 rd_kafka_err2name(test_ack_cb_state_first_err(&state)));

        TEST_ASSERT(state.callback_cnt >= 1,
                    "Expected callback to fire for stale ack, got %d",
                    state.callback_cnt);
        /* Broker rejects acks against records whose acquisition lock has
         * expired with INVALID_RECORD_STATE. */
        TEST_ASSERT(test_ack_cb_state_first_err(&state) ==
                        RD_KAFKA_RESP_ERR_INVALID_RECORD_STATE,
                    "Expected INVALID_RECORD_STATE in callback after lock "
                    "expiry, got %s",
                    rd_kafka_err2name(test_ack_cb_state_first_err(&state)));

        rd_kafka_messages_destroy(batch);
        batch = NULL;

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state);

        SUB_TEST_PASS();
}


typedef struct {
        test_ack_cb_state_t base;
        int saw_consumer_name;
} k44_state_t;

static void k44_safe_api_cb(rd_kafka_share_t *rkshare,
                            rd_kafka_share_partition_offsets_list_t *partitions,
                            rd_kafka_resp_err_t err,
                            void *opaque) {
        k44_state_t *st = opaque;
        rd_kafka_t *rk;

        /* Reuse base counters via the shared helper */
        test_share_ack_cb(rkshare, partitions, err, &st->base);

        /* Safely read consumer identity from within the callback */
        rk = test_share_consumer_get_rk(rkshare);
        if (rk && rd_kafka_name(rk))
                st->saw_consumer_name = 1;
}

/* ===================================================================
 *  Callback safely reads consumer state and the consumer keeps working
 *  afterwards.
 *
 *  Implicit mode: poll a batch, commit_async to drive piggyback acks,
 *  wait for the ack callback. The callback calls
 *  test_share_consumer_get_rk()+rd_kafka_name() to prove that
 *  consumer-state APIs are safe to invoke from within the callback.
 *  After the callback runs, a second round of consume_batch must still
 *  return records, proving the consumer is not wedged.
 * =================================================================== */
static void do_test_safe_api_from_callback(void) {
        const char *topic;
        const char *group = "commit-async-safe-api-cb";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd, j;
        int consumed     = 0;
        int second_round = 0;
        int attempts     = 0;
        k44_state_t st   = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-safe-api-cb", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 10);

        rkshare = test_create_share_consumer_with_cb(
            group, "implicit", (test_ack_cb_state_t *)&st, k44_safe_api_cb);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* First-round consumption */
        while (consumed < 5 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 2000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Drive piggyback acks - this fires the callback */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async failed");
        test_wait_for_cb_with_poll(&st.base, rkshare, 1, 10000);

        TEST_ASSERT(st.base.callback_cnt >= 1, "Expected callback, got %d",
                    st.base.callback_cnt);
        TEST_ASSERT(st.saw_consumer_name,
                    "Callback should have read consumer name via "
                    "test_share_consumer_get_rk + rd_kafka_name");

        /* After callback has run, the consumer must still function. */
        test_produce_msgs_simple(common_producer, topic, 0, 5);
        attempts = 0;
        while (second_round < 5 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 2000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                second_round++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(second_round > 0,
                    "Consumer stopped working after callback invocation");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&st.base);

        SUB_TEST_PASS();
}


typedef struct {
        test_ack_cb_state_t base;
        int side_effect_runs;
} k45_state_t;

static void
k45_side_effect_cb(rd_kafka_share_t *rkshare,
                   rd_kafka_share_partition_offsets_list_t *partitions,
                   rd_kafka_resp_err_t err,
                   void *opaque) {
        k45_state_t *st = opaque;

        test_share_ack_cb(rkshare, partitions, err, &st->base);

        /* Heavy-ish side effect: simulate user application work. */
        st->side_effect_runs++;
        rd_sleep(0); /* yield - safe no-op time pass */
}

/* ===================================================================
 *  Application-side side effects in the ack callback do not crash or
 *  hang the poll thread.
 *
 *  Implicit mode: poll one batch, commit_async, and wait for the
 *  callback. The callback bumps a side-effect counter and yields
 *  via rd_sleep(0) to simulate user work. We assert the side effect
 *  ran and that the consumer is still healthy on a follow-up
 *  consume_batch / commit_async round.
 * =================================================================== */
static void do_test_callback_side_effects_dont_break(void) {
        const char *topic;
        const char *group = "commit-async-side-effect-cb";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd, j;
        int consumed   = 0;
        int post_count = 0;
        int attempts   = 0;
        k45_state_t st = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0173-ca-side-effect-cb", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 10);

        rkshare = test_create_share_consumer_with_cb(
            group, "implicit", (test_ack_cb_state_t *)&st, k45_side_effect_cb);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume the produced records */
        while (consumed < 10 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 2000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed > 0, "Expected to consume records, got 0");

        /* Drive the side-effect callback at least once via commit_async +
         * wait_for_cb_with_poll. */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        test_wait_for_cb_with_poll(&st.base, rkshare, 1, 10000);

        TEST_ASSERT(st.base.callback_cnt >= 1,
                    "Expected callback to fire at least once, got %d",
                    st.base.callback_cnt);
        TEST_ASSERT(st.side_effect_runs >= 1,
                    "Side-effect did not run inside callback (%d runs vs "
                    "%d callbacks)",
                    st.side_effect_runs, st.base.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&st.base) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Callback err: %s",
                    rd_kafka_err2name(test_ack_cb_state_first_err(&st.base)));
        TEST_SAY("consumed=%d, callbacks=%d, side_effects=%d\n", consumed,
                 st.base.callback_cnt, st.side_effect_runs);

        /* Consumer must still be usable after the side-effect callback ran:
         * produce more records and verify poll still works. */
        test_produce_msgs_simple(common_producer, topic, 0, 5);
        attempts = 0;
        while (post_count == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 2000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                post_count++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(post_count > 0,
                    "Consumer stopped working after side-effect callback");
        TEST_SAY("Post-callback poll returned %d msgs\n", post_count);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&st.base);

        SUB_TEST_PASS();
}

static void do_test_change_callback(void) {
        const char *topic;
        const char *group = "change-callback";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd, j;
        int consumed                = 0;
        int attempts                = 0;
        int cb_a_after              = 0;
        test_ack_cb_state_t state_a = {0};
        test_ack_cb_state_t state_b = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0173-change-callback", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        /* Phase 1: produce first batch of messages */
        test_produce_msgs_simple(common_producer, topic, 0, 20);

        /* Create consumer with callback A registered */
        rkshare = test_create_share_consumer_with_cb(group, "explicit",
                                                     &state_a, NULL);
        /* Set offset reset to earliest */
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* Phase 1: consume the first batch and commit with callback A */
        while (consumed < 20 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                consumed++;
                                rd_kafka_share_acknowledge(rkshare, rkm);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(consumed > 0, "Expected to consume some messages");

        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "First commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        /* Wait for callback A */
        test_wait_for_cb_with_poll(&state_a, rkshare, 1, 10000);
        TEST_ASSERT(state_a.callback_cnt == 1,
                    "Expected callback A to be invoked once, got %d",
                    state_a.callback_cnt);
        TEST_ASSERT(state_b.callback_cnt == 0,
                    "Expected callback B NOT to be invoked yet, got %d",
                    state_b.callback_cnt);
        TEST_SAY("Phase 1: callback A invoked %d times, total offsets=%zu\n",
                 state_a.callback_cnt, state_a.total_offsets);

        /* Phase 2: replace callback A with callback B (different opaque) */
        error = rd_kafka_share_set_acknowledgement_commit_cb(
            rkshare, test_share_ack_cb, &state_b);
        TEST_ASSERT(error == NULL,
                    "Expected to change callback successfully, got %s",
                    rd_kafka_error_string(error));

        /* Remember current callback A count so we can verify it doesn't
         * increase after the swap. */
        cb_a_after = state_a.callback_cnt;

        /* Produce a fresh batch so phase 2 has new messages to consume */
        test_produce_msgs_simple(common_producer, topic, 0, 20);

        /* Consume the fresh batch */
        consumed = 0;
        attempts = 0;
        while (consumed < 20 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                consumed++;
                                rd_kafka_share_acknowledge(rkshare, rkm);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(consumed > 0,
                    "Expected to consume some messages after callback swap");

        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "Second commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        /* Wait for callback B to be invoked */
        test_wait_for_cb_with_poll(&state_b, rkshare, 1, 10000);
        TEST_ASSERT(state_b.callback_cnt == 1,
                    "Expected callback B to be invoked once, got %d",
                    state_b.callback_cnt);

        /* Critical assertion: callback A's count must NOT have increased
         * since the swap - the new callback should be receiving the new
         * results, not the old one. */
        TEST_ASSERT(state_a.callback_cnt == cb_a_after,
                    "Callback A was invoked AFTER swap (was %d, now %d) "
                    "- new callback should have received the results",
                    cb_a_after, state_a.callback_cnt);

        TEST_SAY(
            "Phase 2: callback A unchanged at %d, callback B invoked "
            "%d times, total offsets=%zu\n",
            state_a.callback_cnt, state_b.callback_cnt, state_b.total_offsets);

        /* Phase 3: unregister callback (NULL). After this, no callback
         * should be invoked even when new acks are committed. */
        int cb_a_before_phase3 = state_a.callback_cnt;
        int cb_b_before_phase3 = state_b.callback_cnt;

        error =
            rd_kafka_share_set_acknowledgement_commit_cb(rkshare, NULL, NULL);
        TEST_ASSERT(error == NULL, "Failed to unregister callback: %s",
                    rd_kafka_error_string(error));

        /* Produce a fresh batch to trigger more acknowledgements */
        test_produce_msgs_simple(common_producer, topic, 0, 20);

        /* Consume the fresh batch */
        consumed = 0;
        attempts = 0;
        while (consumed < 20 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                consumed++;
                                rd_kafka_share_acknowledge(rkshare, rkm);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed > 0,
                    "Expected to consume some messages after unregister");

        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "Third commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        /* Poll for a while to give any pending callbacks a chance to fire.
         * We can't use test_wait_for_cb_with_poll because we EXPECT no
         * callback - so we poll manually with a fixed budget. */
        int poll_iters = 20;
        while (poll_iters-- > 0) {
                error = rd_kafka_share_poll(rkshare, 200, &batch);
                if (error)
                        rd_kafka_error_destroy(error);
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                consumed++;
                                rd_kafka_share_acknowledge(rkshare, rkm);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Critical assertion: neither callback should have been invoked
         * after the unregister. */
        TEST_ASSERT(state_a.callback_cnt == cb_a_before_phase3,
                    "Callback A was invoked after unregister (was %d, now %d)",
                    cb_a_before_phase3, state_a.callback_cnt);
        TEST_ASSERT(state_b.callback_cnt == cb_b_before_phase3,
                    "Callback B was invoked after unregister (was %d, now %d)",
                    cb_b_before_phase3, state_b.callback_cnt);

        TEST_SAY(
            "Phase 3: no callbacks invoked after unregister "
            "(A=%d, B=%d unchanged)\n",
            state_a.callback_cnt, state_b.callback_cnt);

        rd_kafka_share_consumer_close(rkshare);
        rd_kafka_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state_a);
        test_ack_cb_state_destroy(&state_b);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test: reentrancy protection - share consumer APIs cannot be called
 *  from within the acknowledgement callback.
 *
 *  Verifies that calling any share consumer API from inside the
 *  registered acknowledgement callback returns RD_KAFKA_RESP_ERR__STATE
 *  (for rd_kafka_resp_err_t APIs) or a STATE-coded error object
 *  (for rd_kafka_error_t APIs).
 * =================================================================== */
typedef struct reentrancy_check_state_s {
        test_ack_cb_state_t base; /**< Must be first - we cast to base */
        int rejections;           /**< Count of correctly rejected calls */
        int failures;             /**< Count of calls that did NOT reject */
        rd_kafka_share_t *rkshare;
} reentrancy_check_state_t;

static void
reentrancy_check_cb(rd_kafka_share_t *rkshare,
                    rd_kafka_share_partition_offsets_list_t *partitions,
                    rd_kafka_resp_err_t err,
                    void *opaque) {
        reentrancy_check_state_t *st = (reentrancy_check_state_t *)opaque;
        rd_kafka_error_t *error_obj;
        rd_kafka_resp_err_t resp_err;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_topic_partition_list_t *subs;

        /* Update base state for callback tracking */
        test_ack_cb_state_push_err(&st->base, err);
        if (partitions) {
                const rd_kafka_share_partition_offsets_t *p =
                    rd_kafka_share_partition_offsets_list_get(partitions, 0);
                if (p)
                        st->base.total_offsets +=
                            rd_kafka_share_partition_offsets_offsets_cnt(p);
        }

        /* Try rd_kafka_share_poll - should fail with _STATE */
        error_obj = rd_kafka_share_poll(rkshare, 100, &batch);
        if (error_obj &&
            rd_kafka_error_code(error_obj) == RD_KAFKA_RESP_ERR__STATE) {
                st->rejections++;
                rd_kafka_error_destroy(error_obj);
        } else {
                st->failures++;
                if (error_obj)
                        rd_kafka_error_destroy(error_obj);
        }
        rd_kafka_messages_destroy(batch);

        /* Try rd_kafka_share_commit_async - should fail with _STATE */
        error_obj = rd_kafka_share_commit_async(rkshare);
        if (error_obj &&
            rd_kafka_error_code(error_obj) == RD_KAFKA_RESP_ERR__STATE) {
                st->rejections++;
                rd_kafka_error_destroy(error_obj);
        } else {
                st->failures++;
                if (error_obj)
                        rd_kafka_error_destroy(error_obj);
        }

        /* Try rd_kafka_share_consumer_close - should fail with _STATE */
        error_obj = rd_kafka_share_consumer_close(rkshare);
        if (error_obj &&
            rd_kafka_error_code(error_obj) == RD_KAFKA_RESP_ERR__STATE) {
                st->rejections++;
                rd_kafka_error_destroy(error_obj);
        } else {
                st->failures++;
                if (error_obj)
                        rd_kafka_error_destroy(error_obj);
        }

        /* Try rd_kafka_share_subscribe - should fail with _STATE */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, "dummy", RD_KAFKA_PARTITION_UA);
        resp_err = rd_kafka_share_subscribe(rkshare, subs);
        if (resp_err == RD_KAFKA_RESP_ERR__STATE)
                st->rejections++;
        else
                st->failures++;
        rd_kafka_topic_partition_list_destroy(subs);

        /* Try rd_kafka_share_unsubscribe - should fail with _STATE */
        resp_err = rd_kafka_share_unsubscribe(rkshare);
        if (resp_err == RD_KAFKA_RESP_ERR__STATE)
                st->rejections++;
        else
                st->failures++;

        /* Try rd_kafka_share_set_acknowledgement_commit_cb - should fail with
         * _STATE because you can't change the callback from within itself */
        error_obj =
            rd_kafka_share_set_acknowledgement_commit_cb(rkshare, NULL, NULL);
        if (error_obj &&
            rd_kafka_error_code(error_obj) == RD_KAFKA_RESP_ERR__STATE)
                st->rejections++;
        else
                st->failures++;
        RD_IF_FREE(error_obj, rd_kafka_error_destroy);
}

static void do_test_reentrancy_protection(void) {
        const char *topic;
        const char *group = "reentrancy-protection";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd, j;
        int consumed                   = 0;
        int attempts                   = 0;
        reentrancy_check_state_t state = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0173-reentrancy", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 50);

        /* Create consumer without callback - we'll set it at runtime */
        rkshare       = test_create_share_consumer(group, "explicit");
        state.rkshare = rkshare;

        /* Register the reentrancy-checking callback at runtime */
        error = rd_kafka_share_set_acknowledgement_commit_cb(
            rkshare, reentrancy_check_cb, &state);
        TEST_ASSERT(error == NULL, "Failed to set callback: %s",
                    rd_kafka_error_string(error));

        /* Set offset reset to earliest */
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume messages to trigger acknowledgement and callback invocation
         */
        while (consumed < 50 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                consumed++;
                                rd_kafka_share_acknowledge(rkshare, rkm);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed > 0, "Expected to consume some messages");

        /* commit_async triggers the callback */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async failed: %s",
                    error ? rd_kafka_error_string(error) : "");

        /* Wait for callback to be invoked at least once */
        test_wait_for_cb_with_poll(&state.base, rkshare, 1, 10000);
        TEST_ASSERT(state.base.callback_cnt == 1,
                    "Expected callback to be invoked, got %d",
                    state.base.callback_cnt);

        TEST_SAY("Callback invoked %d times, rejections=%d, failures=%d\n",
                 state.base.callback_cnt, state.rejections, state.failures);

        /* Every callback invocation tries 6 share consumer APIs, all of
         * which must reject the call from within the callback. */
        TEST_ASSERT(state.failures == 0,
                    "Expected 0 failures (all APIs should reject), got %d",
                    state.failures);
        TEST_ASSERT(state.rejections == 6, "Expected 6 rejections, got %d",
                    state.rejections);

        rd_kafka_share_consumer_close(rkshare);
        rd_kafka_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state.base);

        SUB_TEST_PASS();
}



int main_0173_share_consumer_commit_async(int argc, char **argv) {
        test_timeout_set(120);
        common_producer = test_create_producer();
        common_admin    = test_create_producer();

        do_test_implicit_second_consumer();
        do_test_explicit_second_consumer();
        do_test_mixed_acks_second_consumer();
        do_test_multi_topic_partition();
        do_test_produce_consume_loop();
        do_test_multi_round_mixed_second_consumer();
        do_test_no_pending_acks();
        do_test_multiple_commit_async_calls();
        do_test_commit_between_produces();
        do_test_all_release_second_consumer();
        do_test_all_reject_second_consumer();
        do_test_per_record_commit_async();
        do_test_lock_timeout_redelivery();
        /* Callback test */
        do_test_commit_async_callback();

        /* Partial-batch / callback edge cases */
        do_test_partial_batch_commit_async();
        do_test_implicit_callback_no_explicit_commit();
        do_test_lock_expiry_callback_err();
        do_test_safe_api_from_callback();
        do_test_callback_side_effects_dont_break();

        /* Callback management and reentrancy */
        do_test_change_callback();
        do_test_reentrancy_protection();

        rd_kafka_destroy(common_admin);
        rd_kafka_destroy(common_producer);

        return 0;
}

int main_0173_share_consumer_commit_async_local(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);

        do_test_mock_inflight_caching();

        return 0;
}
