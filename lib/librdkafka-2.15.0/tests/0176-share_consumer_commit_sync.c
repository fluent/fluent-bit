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
 * @brief Share consumer rd_kafka_share_commit_sync() API tests.
 *
 * Tests the commit_sync API in both implicit and explicit ack modes.
 * Verifies that commit_sync synchronously commits acknowledged records
 * and returns per-partition results.
 */

#define CONSUME_ARRAY 10001

/** Common producer reused across all non-mock subtests. */
static rd_kafka_t *common_producer;

/** Common admin client reused across all non-mock subtests. */
static rd_kafka_t *common_admin;


/**
 * @brief Create share consumer with specified ack mode.
 * @param ack_mode "implicit" or "explicit"
 */
static rd_kafka_share_t *create_share_consumer(const char *group_id,
                                               const char *ack_mode) {
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        char errstr[512];

        test_conf_init(&conf, NULL, 0);

        rd_kafka_conf_set(conf, "group.id", group_id, errstr, sizeof(errstr));
        rd_kafka_conf_set(conf, "share.acknowledgement.mode", ack_mode, errstr,
                          sizeof(errstr));

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare, "Failed to create share consumer: %s", errstr);

        return rkshare;
}


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


/* ===================================================================
 *  Test 1: Basic implicit ack mode commit_sync.
 *
 *  Implicit mode auto-ACCEPTs all records from previous poll.
 *  Consumer consumes records, calls commit_sync, verifies
 *  per-partition results show NO_ERROR.
 * =================================================================== */
static void do_test_basic_implicit_commit_sync(void) {
        const char *topic;
        const char *group = "commit-sync-implicit-basic";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed = 0;
        int attempts = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-impl-basic", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        rkshare = create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume records */
        while (consumed == 0 && attempts++ < 30) {
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
        TEST_ASSERT(consumed == 5, "Expected 5 messages, got %d", consumed);

        /* commit_sync should flush implicit acks */
        error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_ASSERT(!error, "commit_sync failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        TEST_ASSERT(partitions != NULL,
                    "Expected per-partition results, got NULL");

        TEST_SAY("commit_sync returned %d partition(s)\n", partitions->cnt);
        TEST_ASSERT(partitions->cnt == 1,
                    "Expected exactly 1 partition result, got %d",
                    partitions->cnt);
        TEST_SAY("  %s [%" PRId32 "]: %s\n", partitions->elems[0].topic,
                 partitions->elems[0].partition,
                 rd_kafka_err2str(partitions->elems[0].err));
        TEST_ASSERT(!strcmp(partitions->elems[0].topic, topic),
                    "Expected topic %s, got %s", topic,
                    partitions->elems[0].topic);
        TEST_ASSERT(partitions->elems[0].partition == 0,
                    "Expected partition 0, got %" PRId32,
                    partitions->elems[0].partition);
        TEST_ASSERT(partitions->elems[0].err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR, got %s",
                    rd_kafka_err2str(partitions->elems[0].err));

        rd_kafka_topic_partition_list_destroy(partitions);

        /* Wait for acquisition lock to expire (3s + 1s buffer) */
        rd_sleep(4);

        /* Produce 5 verification records and consume with the same
         * consumer — should get only these 5 (dc == 1), proving
         * the first batch was committed and not redelivered. */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        consumed = 0;
        attempts = 0;
        while (consumed < 5 && attempts++ < 30) {
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
                                TEST_ASSERT(
                                    rd_kafka_message_delivery_count(rkm) == 1,
                                    "Got redelivered record at offset %" PRId64
                                    " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Verification: got %d messages (expected 5)\n", consumed);
        TEST_ASSERT(consumed == 5, "Expected 5 verification records, got %d",
                    consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 2: Basic explicit ack mode commit_sync.
 *
 *  Explicit mode requires the app to ACCEPT each record via
 *  rd_kafka_share_acknowledge(). Then commit_sync flushes acks
 *  and returns per-partition results.
 * =================================================================== */
static void do_test_basic_explicit_commit_sync(void) {
        const char *topic;
        const char *group = "commit-sync-explicit-basic";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed = 0;
        int attempts = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-expl-basic", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        rkshare = create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        set_group_lock_duration(group, "3000");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume records and explicitly ACCEPT each */
        while (consumed == 0 && attempts++ < 30) {
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
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Consumed and acknowledged %d messages\n", consumed);
        TEST_ASSERT(consumed == 5, "Expected 5 messages, got %d", consumed);

        /* commit_sync should flush explicit acks */
        error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_ASSERT(!error, "commit_sync failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        TEST_ASSERT(partitions != NULL,
                    "Expected per-partition results, got NULL");

        TEST_SAY("commit_sync returned %d partition(s)\n", partitions->cnt);
        TEST_ASSERT(partitions->cnt == 1,
                    "Expected exactly 1 partition result, got %d",
                    partitions->cnt);
        TEST_SAY("  %s [%" PRId32 "]: %s\n", partitions->elems[0].topic,
                 partitions->elems[0].partition,
                 rd_kafka_err2str(partitions->elems[0].err));
        TEST_ASSERT(!strcmp(partitions->elems[0].topic, topic),
                    "Expected topic %s, got %s", topic,
                    partitions->elems[0].topic);
        TEST_ASSERT(partitions->elems[0].partition == 0,
                    "Expected partition 0, got %" PRId32,
                    partitions->elems[0].partition);
        TEST_ASSERT(partitions->elems[0].err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR, got %s",
                    rd_kafka_err2str(partitions->elems[0].err));

        rd_kafka_topic_partition_list_destroy(partitions);

        /* Wait for acquisition lock to expire (3s + 1s buffer) */
        rd_sleep(4);

        /* Produce 5 verification records and consume with the same
         * consumer — should get only these 5 (dc == 1), proving
         * the first batch was committed and not redelivered. */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        consumed = 0;
        attempts = 0;
        while (consumed < 5 && attempts++ < 30) {
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
                                TEST_ASSERT(
                                    rd_kafka_message_delivery_count(rkm) == 1,
                                    "Got redelivered record at offset %" PRId64
                                    " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Verification: got %d messages (expected 5)\n", consumed);
        TEST_ASSERT(consumed == 5, "Expected 5 verification records, got %d",
                    consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 3: No pending acks — commit_sync with nothing to commit.
 *
 *  Subscribe but do not consume any records. commit_sync should
 *  return NULL error and NULL partitions.
 * =================================================================== */
static void do_test_no_pending_acks(void) {
        const char *topic;
        const char *group = "commit-sync-no-pending";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-no-pending", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);

        rkshare = create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* commit_sync with no consumed records */
        error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_ASSERT(!error, "commit_sync failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        TEST_ASSERT(partitions == NULL,
                    "Expected NULL partitions when no acks pending, "
                    "got %d partition(s)",
                    partitions ? partitions->cnt : -1);

        TEST_SAY(
            "commit_sync with no pending acks returned NULL as expected\n");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 4: commit_sync prevents redelivery.
 *
 *  Consumer A consumes and commit_sync's all records, then closes.
 *  Consumer B (same group) should see 0 records since they were
 *  all committed by A.
 * =================================================================== */
static void do_test_commit_sync_prevents_redelivery(void) {
        const char *topic;
        const char *group = "commit-sync-no-redeliver";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed = 0;
        int attempts = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-no-redeliver", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Consumer A: consume all and commit_sync */
        rkshare = create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        while (consumed == 0 && attempts++ < 30) {
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

        TEST_SAY("Consumer A consumed %d messages\n", consumed);
        TEST_ASSERT(consumed == 5, "Expected 5, got %d", consumed);

        error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_ASSERT(!error, "commit_sync failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        RD_IF_FREE(partitions, rd_kafka_topic_partition_list_destroy);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Produce 5 verification records */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Consumer B: should only get the 5 verification records.
         * Close tears down the connection and broker releases
         * records immediately — no lock wait needed. */
        rkshare = create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        error = rd_kafka_share_poll(rkshare, 15000, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_SAY("Consumer B share_poll returned: rcvd=%zu, error=%s\n", rcvd,
                 error ? rd_kafka_error_string(error) : "none");
        if (error)
                rd_kafka_error_destroy(error);

        consumed = 0;
        for (j = 0; j < rcvd; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                if (!rkm->err) {
                        TEST_ASSERT(rd_kafka_message_delivery_count(rkm) == 1,
                                    "Consumer B got redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                        consumed++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumer B got %d messages (expected 5)\n", consumed);
        TEST_ASSERT(consumed == 5, "Expected 5 verification records, got %d",
                    consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 5: Mixed ack types — ACCEPT, RELEASE, REJECT.
 *
 *  Consumer A: ACCEPT first 5, RELEASE next 3, REJECT last 2,
 *  then commit_sync. Consumer B should only receive the 3
 *  RELEASE'd records with delivery_count >= 2.
 * =================================================================== */
static void do_test_mixed_ack_types(void) {
        const char *topic;
        const char *group = "commit-sync-mixed-acks";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed = 0;
        int attempts = 0;
        int64_t released_offsets[3];
        int released_cnt = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-mixed-acks", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 10);

        /* Consumer A: consume all 10 in a single batch, apply mixed ack
         * types */
        rkshare = create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        while (consumed == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                /* Skip partial batches — wait for all 10 in one call */
                if (rcvd < 10) {
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        continue;
                }

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_resp_err_t err;
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);

                        if (rkm->err)
                                continue;

                        if (consumed < 5) {
                                /* ACCEPT first 5 */
                                err = rd_kafka_share_acknowledge_type(
                                    rkshare, rkm,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                        } else if (consumed < 8) {
                                /* RELEASE next 3 */
                                released_offsets[released_cnt++] = rkm->offset;
                                err = rd_kafka_share_acknowledge_type(
                                    rkshare, rkm,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
                        } else {
                                /* REJECT last 2 */
                                err = rd_kafka_share_acknowledge_type(
                                    rkshare, rkm,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
                        }

                        TEST_ASSERT(!err, "acknowledge_type failed: %s",
                                    rd_kafka_err2str(err));
                        consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY(
            "Consumer A consumed %d messages "
            "(5 ACCEPT, 3 RELEASE, 2 REJECT)\n",
            consumed);
        TEST_ASSERT(consumed == 10, "Expected 10, got %d", consumed);
        TEST_ASSERT(released_cnt == 3, "Expected 3 released, got %d",
                    released_cnt);

        error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_ASSERT(!error, "commit_sync failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        TEST_ASSERT(partitions != NULL,
                    "Expected per-partition results, got NULL");
        TEST_ASSERT(partitions->cnt == 1,
                    "Expected exactly 1 partition result, got %d",
                    partitions->cnt);
        TEST_SAY("  %s [%" PRId32 "]: %s\n", partitions->elems[0].topic,
                 partitions->elems[0].partition,
                 rd_kafka_err2str(partitions->elems[0].err));
        TEST_ASSERT(!strcmp(partitions->elems[0].topic, topic),
                    "Expected topic %s, got %s", topic,
                    partitions->elems[0].topic);
        TEST_ASSERT(partitions->elems[0].partition == 0,
                    "Expected partition 0, got %" PRId32,
                    partitions->elems[0].partition);
        TEST_ASSERT(partitions->elems[0].err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR, got %s",
                    rd_kafka_err2str(partitions->elems[0].err));

        rd_kafka_topic_partition_list_destroy(partitions);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Consumer B: should only get the 3 RELEASE'd records */
        rkshare = create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        consumed = 0;
        attempts = 0;
        while (consumed < 3 && attempts++ < 10) {
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
                                int16_t dc;
                                int k;
                                rd_bool_t found = rd_false;

                                dc = rd_kafka_message_delivery_count(rkm);
                                TEST_ASSERT(
                                    dc >= 2,
                                    "Consumer B got record at offset %" PRId64
                                    " with delivery_count=%d, expected >= 2",
                                    rkm->offset, (int)dc);

                                /* Verify it is one of the released offsets */
                                for (k = 0; k < released_cnt; k++) {
                                        if (rkm->offset ==
                                            released_offsets[k]) {
                                                found = rd_true;
                                                break;
                                        }
                                }
                                TEST_ASSERT(found,
                                            "Consumer B got offset %" PRId64
                                            " which was not RELEASE'd",
                                            rkm->offset);

                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Consumer B consumed %d messages (expected 3 RELEASE'd)\n",
                 consumed);
        TEST_ASSERT(consumed == 3,
                    "Consumer B got %d records, expected 3 RELEASE'd",
                    consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 6: Multiple commit_sync calls.
 *
 *  Consume 50 records, ACCEPT 10 at a time and commit_sync after
 *  each batch of 10 (5 commit_sync calls total). After each
 *  commit_sync, immediately call commit_sync again to verify
 *  a no-op commit (no pending acks) returns NULL/NULL cleanly.
 *  Consumer B should get 0 records.
 * =================================================================== */
static void do_test_multiple_commit_sync_calls(void) {
        const char *topic;
        const char *group = "commit-sync-multi-calls";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed                = 0;
        int attempts                = 0;
        int commit_cnt              = 0;
        int acked_since_last_commit = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-multi-calls", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 50);

        rkshare = create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume all 50, commit_sync every 10 records */
        while (consumed < 50 && attempts++ < 60) {
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
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;
                                acked_since_last_commit++;
                        }

                        /* commit_sync every 10 records */
                        if (acked_since_last_commit == 10) {
                                partitions = NULL;
                                error      = rd_kafka_share_commit_sync(
                                    rkshare, 30000, &partitions);
                                commit_cnt++;
                                TEST_ASSERT(
                                    !error, "commit_sync #%d failed: %s",
                                    commit_cnt,
                                    error ? rd_kafka_error_string(error) : "");
                                TEST_ASSERT(
                                    partitions != NULL,
                                    "commit_sync #%d: expected results, "
                                    "got NULL",
                                    commit_cnt);
                                TEST_ASSERT(partitions->cnt == 1,
                                            "commit_sync #%d: expected 1 "
                                            "partition, got %d",
                                            commit_cnt, partitions->cnt);
                                TEST_ASSERT(
                                    !strcmp(partitions->elems[0].topic, topic),
                                    "commit_sync #%d: expected topic "
                                    "%s, got %s",
                                    commit_cnt, topic,
                                    partitions->elems[0].topic);
                                TEST_ASSERT(partitions->elems[0].partition == 0,
                                            "commit_sync #%d: expected "
                                            "partition 0, got %" PRId32,
                                            commit_cnt,
                                            partitions->elems[0].partition);
                                TEST_ASSERT(
                                    partitions->elems[0].err ==
                                        RD_KAFKA_RESP_ERR_NO_ERROR,
                                    "commit_sync #%d: %s [%" PRId32 "] got %s",
                                    commit_cnt, partitions->elems[0].topic,
                                    partitions->elems[0].partition,
                                    rd_kafka_err2str(partitions->elems[0].err));

                                rd_kafka_topic_partition_list_destroy(
                                    partitions);
                                TEST_SAY(
                                    "commit_sync #%d OK "
                                    "(consumed %d so far)\n",
                                    commit_cnt, consumed);
                                acked_since_last_commit = 0;

                                /* Immediately call commit_sync again —
                                 * no pending acks, should return
                                 * NULL/NULL */
                                partitions = NULL;
                                error      = rd_kafka_share_commit_sync(
                                    rkshare, 30000, &partitions);
                                TEST_ASSERT(
                                    !error,
                                    "back-to-back commit_sync after #%d "
                                    "failed: %s",
                                    commit_cnt,
                                    error ? rd_kafka_error_string(error) : "");
                                TEST_ASSERT(
                                    partitions == NULL,
                                    "back-to-back commit_sync after #%d: "
                                    "expected NULL partitions, got %d",
                                    commit_cnt,
                                    partitions ? partitions->cnt : -1);
                                TEST_SAY(
                                    "back-to-back commit_sync after "
                                    "#%d returned NULL as expected\n",
                                    commit_cnt);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Consumer A consumed %d messages, %d commit_sync calls\n",
                 consumed, commit_cnt);
        TEST_ASSERT(consumed == 50, "Expected 50, got %d", consumed);
        TEST_ASSERT(commit_cnt == 5, "Expected 5 commit_sync calls, got %d",
                    commit_cnt);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Produce 5 verification records */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Consumer B: should only get the 5 verification records */
        rkshare = create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        error = rd_kafka_share_poll(rkshare, 15000, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_SAY("Consumer B share_poll returned: rcvd=%zu, error=%s\n", rcvd,
                 error ? rd_kafka_error_string(error) : "none");
        if (error)
                rd_kafka_error_destroy(error);

        consumed = 0;
        for (j = 0; j < rcvd; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                if (!rkm->err) {
                        TEST_ASSERT(rd_kafka_message_delivery_count(rkm) == 1,
                                    "Consumer B got redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                        consumed++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumer B got %d messages (expected 5)\n", consumed);
        TEST_ASSERT(consumed == 5, "Expected 5 verification records, got %d",
                    consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 7: Multi-topic multi-partition commit_sync.
 *
 *  10 topics with 6 partitions each, 10 messages per partition
 *  (600 total). Consume in batches, apply mixed ack types
 *  (ACCEPT ~50%, RELEASE ~30%, REJECT ~20%) and commit_sync
 *  after each consume_batch call.
 *
 *  RELEASE'd records are redelivered. Continue consuming until
 *  accepted + rejected == total_msgs (all records settled).
 *  On delivery_count >= MAX_REDELIVERY_ROUNDS, force ACCEPT.
 *  Verify commit_sync returns NO_ERROR each time and that
 *  delivery_count stays within bounds.
 * =================================================================== */
#define MULTI_TP_TOPICS             10
#define MULTI_TP_PARTITIONS         6
#define MULTI_TP_MSGS_PER_PARTITION 10
#define MAX_REDELIVERY_ROUNDS       4

static rd_kafka_share_AcknowledgeType_t get_ack_type(int index) {
        int r = index % 10;
        if (r < 5)
                return RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT;
        else if (r < 8)
                return RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE;
        else
                return RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT;
}

static void do_test_multi_topic_partition(void) {
        const char *group = "commit-sync-multi-tp";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        char *topics[MULTI_TP_TOPICS];
        size_t rcvd;
        size_t j;
        int total_consumed = 0;
        int accepted = 0, released = 0, rejected = 0;
        int attempts   = 0;
        int commit_cnt = 0;
        int total_msgs =
            MULTI_TP_TOPICS * MULTI_TP_PARTITIONS * MULTI_TP_MSGS_PER_PARTITION;
        int i, p;
        int16_t max_dc_seen = 0;

        SUB_TEST();

        /* Create topics and produce 10 messages per partition */
        for (i = 0; i < MULTI_TP_TOPICS; i++) {
                topics[i] = rd_strdup(test_mk_topic_name("0176-cs-mtp", 1));
                test_create_topic_wait_exists(common_admin, topics[i],
                                              MULTI_TP_PARTITIONS, -1,
                                              60 * 1000);
                for (p = 0; p < MULTI_TP_PARTITIONS; p++)
                        test_produce_msgs_simple(common_producer, topics[i], p,
                                                 MULTI_TP_MSGS_PER_PARTITION);
        }

        rkshare = create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, (const char **)topics, MULTI_TP_TOPICS);

        /* Consume until all records are settled
         * (accepted + rejected == total_msgs) */
        while (accepted + rejected < total_msgs && attempts++ < 200) {
                rd_kafka_topic_partition_list_t *batch_tps;
                int batch_cnt = 0;

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                /* Track unique topic-partitions in this batch */
                batch_tps = rd_kafka_topic_partition_list_new(
                    MULTI_TP_TOPICS * MULTI_TP_PARTITIONS);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_share_AcknowledgeType_t ack_type;
                        rd_kafka_resp_err_t err;
                        int16_t dc;
                        const char *msg_topic;
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);

                        if (rkm->err)
                                continue;

                        msg_topic = rd_kafka_topic_name(rkm->rkt);

                        /* Add to batch TPs if not already present */
                        if (!rd_kafka_topic_partition_list_find(
                                batch_tps, msg_topic, rkm->partition))
                                rd_kafka_topic_partition_list_add(
                                    batch_tps, msg_topic, rkm->partition);

                        dc = rd_kafka_message_delivery_count(rkm);
                        if (dc > max_dc_seen)
                                max_dc_seen = dc;

                        /* On final delivery attempt, force ACCEPT */
                        if (dc >= MAX_REDELIVERY_ROUNDS)
                                ack_type =
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT;
                        else
                                ack_type = get_ack_type(total_consumed);

                        err = rd_kafka_share_acknowledge_type(rkshare, rkm,
                                                              ack_type);
                        TEST_ASSERT(!err, "acknowledge_type failed: %s",
                                    rd_kafka_err2str(err));

                        if (ack_type == RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT)
                                accepted++;
                        else if (ack_type ==
                                 RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE)
                                released++;
                        else
                                rejected++;

                        total_consumed++;
                        batch_cnt++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;

                if (batch_cnt == 0) {
                        rd_kafka_topic_partition_list_destroy(batch_tps);
                        continue;
                }

                /* commit_sync after each batch */
                partitions = NULL;
                error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
                commit_cnt++;
                TEST_ASSERT(!error, "commit_sync #%d failed: %s", commit_cnt,
                            error ? rd_kafka_error_string(error) : "");
                TEST_ASSERT(partitions != NULL,
                            "commit_sync #%d: expected results, got NULL",
                            commit_cnt);

                /* Verify commit_sync returned exactly the TPs we
                 * consumed from in this batch */
                TEST_ASSERT(partitions->cnt == batch_tps->cnt,
                            "commit_sync #%d: expected %d partition(s), got %d",
                            commit_cnt, batch_tps->cnt, partitions->cnt);

                for (i = 0; i < partitions->cnt; i++) {
                        rd_kafka_topic_partition_t *rktpar =
                            &partitions->elems[i];
                        TEST_ASSERT(rktpar->err == RD_KAFKA_RESP_ERR_NO_ERROR,
                                    "commit_sync #%d: %s [%" PRId32 "] got %s",
                                    commit_cnt, rktpar->topic,
                                    rktpar->partition,
                                    rd_kafka_err2str(rktpar->err));
                        TEST_ASSERT(rd_kafka_topic_partition_list_find(
                                        batch_tps, rktpar->topic,
                                        rktpar->partition) != NULL,
                                    "commit_sync #%d: unexpected partition "
                                    "%s [%" PRId32 "] in results",
                                    commit_cnt, rktpar->topic,
                                    rktpar->partition);
                }

                TEST_SAY(
                    "commit_sync #%d OK (%d in batch, %d total, "
                    "settled=%d/%d, %d partition results)\n",
                    commit_cnt, batch_cnt, total_consumed, accepted + rejected,
                    total_msgs, partitions->cnt);

                rd_kafka_topic_partition_list_destroy(partitions);
                rd_kafka_topic_partition_list_destroy(batch_tps);
        }

        TEST_SAY(
            "Total consumed=%d (original=%d), commit_sync calls=%d, "
            "accepted=%d, released=%d, rejected=%d, "
            "max delivery_count=%d\n",
            total_consumed, total_msgs, commit_cnt, accepted, released,
            rejected, (int)max_dc_seen);

        TEST_ASSERT(accepted + rejected == total_msgs,
                    "Expected accepted(%d) + rejected(%d) == %d", accepted,
                    rejected, total_msgs);

        /* Verify redelivery happened */
        TEST_ASSERT(max_dc_seen > 1,
                    "Expected redeliveries (max delivery_count > 1), "
                    "got max=%d",
                    (int)max_dc_seen);

        TEST_ASSERT(max_dc_seen <= MAX_REDELIVERY_ROUNDS,
                    "Max delivery_count=%d exceeds limit=%d", (int)max_dc_seen,
                    MAX_REDELIVERY_ROUNDS);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        for (i = 0; i < MULTI_TP_TOPICS; i++)
                rd_free(topics[i]);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Mock broker infrastructure (same pattern as 0173).
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

static void
mock_produce_messages(rd_kafka_t *producer, const char *topic, int msgcnt) {
        int i;
        for (i = 0; i < msgcnt; i++) {
                char payload[64];
                snprintf(payload, sizeof(payload), "%s-%d", topic, i);
                TEST_ASSERT(rd_kafka_producev(
                                producer, RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_VALUE(payload, strlen(payload)),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_END) == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Produce failed");
        }
        rd_kafka_flush(producer, 5000);
}

/**
 * @brief Create share consumer for mock broker tests.
 *
 * Unlike create_share_consumer() which uses test_conf_init with real
 * broker settings, this uses mock cluster bootstraps.
 */
static rd_kafka_share_t *create_mock_share_consumer(const char *bootstraps,
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

static int count_share_ack_requests(rd_kafka_mock_cluster_t *mcluster) {
        size_t cnt;
        size_t i;
        rd_kafka_mock_request_t **requests;
        int share_ack_cnt = 0;

        requests = rd_kafka_mock_get_requests(mcluster, &cnt);

        for (i = 0; i < cnt; i++) {
                int16_t api_key = rd_kafka_mock_request_api_key(requests[i]);
                if (api_key == RD_KAFKAP_ShareAcknowledge)
                        share_ack_cnt++;
        }

        rd_kafka_mock_request_destroy_array(requests, cnt);
        return share_ack_cnt;
}


/* ===================================================================
 *  Test 8: Mock — verify commit_sync uses ShareAcknowledge RPC.
 *
 *  Consume 50 records, ACCEPT 10 at a time, commit_sync after
 *  each batch. Track ShareAcknowledge requests and verify the
 *  count matches the number of commit_sync calls that returned
 *  at least 1 partition result.
 * =================================================================== */
static void do_test_mock_uses_share_acknowledge(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        const char *topic                           = "mock-cs-share-ack";
        const int msgcnt                            = 50;
        int consumed                                = 0;
        int attempts                                = 0;
        int commit_cnt                              = 0;
        int commit_with_partitions                  = 0;
        int acked_since_last_commit                 = 0;
        int share_ack_cnt;
        int i;

        SUB_TEST_QUICK();

        ctx = test_ctx_new();
        TEST_SAY("Mock cluster ready, bootstraps=%s\n", ctx.bootstraps);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        TEST_SAY("Created mock topic [%s] (1 partition)\n", topic);

        mock_produce_messages(ctx.producer, topic, msgcnt);
        TEST_SAY("Produced %d messages to [%s]\n", msgcnt, topic);

        rkshare = create_mock_share_consumer(ctx.bootstraps, "sg-mock-cs-ack",
                                             "explicit");
        TEST_SAY(
            "Created share consumer (group=sg-mock-cs-ack, "
            "ack=explicit)\n");

        subscribe_consumer(rkshare, &topic, 1);
        TEST_SAY("Subscribed to [%s]\n", topic);

        /* Clear and start tracking requests */
        rd_kafka_mock_start_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);
        TEST_SAY(
            "Started mock request tracking; entering consume loop "
            "(msgcnt=%d, batch=%d)\n",
            msgcnt, CONSUME_ARRAY);

        /* Consume all records, ACCEPT each, commit_sync every 10 */
        while (consumed < msgcnt && attempts++ < 30) {
                rd_kafka_messages_t *batch = NULL;
                size_t rcvd;
                size_t j;

                TEST_SAY(
                    "Iter %d: calling share_poll "
                    "(consumed=%d/%d, acked_since_last=%d)\n",
                    attempts, consumed, msgcnt, acked_since_last_commit);

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        TEST_SAY(
                            "Iter %d: share_poll error: %s "
                            "(rcvd=%zu)\n",
                            attempts, rd_kafka_error_string(error),
                            rd_kafka_messages_count(batch));
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                TEST_SAY("Iter %d: share_poll returned %zu msg(s)\n", attempts,
                         rcvd);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err) {
                                TEST_SAY(
                                    "  ACK %s [%" PRId32 "] @ offset %" PRId64
                                    " (delivery_count=%d)\n",
                                    rd_kafka_topic_name(rkm->rkt),
                                    rkm->partition, rkm->offset,
                                    (int)rd_kafka_message_delivery_count(rkm));
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;
                                acked_since_last_commit++;
                        } else {
                                TEST_SAY(
                                    "  msg #%zu carries error %s on "
                                    "%s [%" PRId32 "] @ %" PRId64 "\n",
                                    j, rd_kafka_err2name(rkm->err),
                                    rkm->rkt ? rd_kafka_topic_name(rkm->rkt)
                                             : "(no-rkt)",
                                    rkm->partition, rkm->offset);
                        }

                        if (acked_since_last_commit == 10) {
                                partitions = NULL;
                                TEST_SAY(
                                    "Calling commit_sync #%d "
                                    "(timeout=30000ms, acked=%d, "
                                    "consumed=%d)\n",
                                    commit_cnt + 1, acked_since_last_commit,
                                    consumed);
                                error = rd_kafka_share_commit_sync(
                                    rkshare, 30000, &partitions);
                                commit_cnt++;
                                TEST_SAY(
                                    "commit_sync #%d returned: "
                                    "error=%s, partitions=%s, "
                                    "partition_cnt=%d\n",
                                    commit_cnt,
                                    error ? rd_kafka_error_string(error)
                                          : "NULL",
                                    partitions ? "non-NULL" : "NULL",
                                    partitions ? partitions->cnt : 0);
                                TEST_ASSERT(
                                    !error, "commit_sync #%d failed: %s",
                                    commit_cnt,
                                    error ? rd_kafka_error_string(error) : "");

                                if (partitions != NULL) {
                                        commit_with_partitions++;
                                        for (i = 0; i < partitions->cnt; i++) {
                                                rd_kafka_topic_partition_t
                                                    *rktpar =
                                                        &partitions->elems[i];
                                                TEST_SAY(
                                                    "  commit_sync #%d "
                                                    "partition[%d]: "
                                                    "%s [%" PRId32
                                                    "] offset=%" PRId64
                                                    " err=%s\n",
                                                    commit_cnt, i,
                                                    rktpar->topic,
                                                    rktpar->partition,
                                                    rktpar->offset,
                                                    rd_kafka_err2name(
                                                        rktpar->err));
                                                TEST_ASSERT(
                                                    rktpar->err ==
                                                        RD_KAFKA_RESP_ERR_NO_ERROR,
                                                    "commit_sync #%d: "
                                                    "%s [%" PRId32 "] got %s",
                                                    commit_cnt, rktpar->topic,
                                                    rktpar->partition,
                                                    rd_kafka_err2str(
                                                        rktpar->err));
                                        }
                                        rd_kafka_topic_partition_list_destroy(
                                            partitions);
                                }

                                TEST_SAY(
                                    "commit_sync #%d OK "
                                    "(consumed %d so far)\n",
                                    commit_cnt, consumed);
                                acked_since_last_commit = 0;
                        }
                }
                rd_kafka_messages_destroy(batch);
        }

        TEST_SAY(
            "Consume loop exited after %d iter(s): "
            "consumed=%d/%d, commit_cnt=%d, with_partitions=%d, "
            "acked_since_last=%d\n",
            attempts, consumed, msgcnt, commit_cnt, commit_with_partitions,
            acked_since_last_commit);
        TEST_ASSERT(consumed == msgcnt, "Expected %d, got %d", msgcnt,
                    consumed);

        /* Wait for async ops to complete before counting requests */
        TEST_SAY(
            "Sleeping 3s for async ops to drain before counting "
            "ShareAcknowledge requests\n");
        rd_sleep(3);

        share_ack_cnt = count_share_ack_requests(ctx.mcluster);
        rd_kafka_mock_stop_request_tracking(ctx.mcluster);

        TEST_SAY(
            "Mock: ShareAcknowledge requests=%d, "
            "commit_sync with partitions=%d\n",
            share_ack_cnt, commit_with_partitions);
        TEST_ASSERT(share_ack_cnt == commit_with_partitions,
                    "Expected ShareAcknowledge count (%d) == commit_sync with "
                    "partitions count (%d)",
                    share_ack_cnt, commit_with_partitions);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        TEST_SAY("Destroying mock test context\n");
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 9: Mock — commit_sync timeout and recovery.
 *
 *  Phase 1: Consume 10 records, ACCEPT all. Set broker RTT to
 *  5000ms and call commit_sync with timeout_ms=2000. The call
 *  should block ~2000ms then return REQUEST_TIMED_OUT (main
 *  thread commit_sync deadline) or _TIMED_OUT (broker thread
 *  socket.timeout.ms) per-partition. The broker still processes
 *  the ack when the delayed response arrives.
 *
 *  TODO KIP-932: Verify and maybe unify the timeout error
 *  returned by commit_sync. librdkafka can return either
 *  REQUEST_TIMED_OUT or _TIMED_OUT depending on which timer
 *  fires first.
 *
 *  Phase 2: Remove RTT, wait 5s for broker to finish processing.
 *  Second consumer should get 0 records (acks were processed).
 *
 *  Phase 3: Produce 10 more, consume and ACCEPT, commit_sync
 *  with normal timeout → succeeds. Verifies recovery.
 * =================================================================== */
static void do_test_mock_commit_sync_timeout(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        const char *topic                           = "mock-cs-timeout";
        const char *t                               = topic;
        const int msgcnt                            = 10;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed;
        int attempts;
        int i;
        rd_bool_t got_timed_out = rd_false;
        rd_ts_t t_start, t_elapsed_ms;

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        mock_produce_messages(ctx.producer, topic, msgcnt);

        rkshare = create_mock_share_consumer(ctx.bootstraps,
                                             "sg-mock-cs-timeout", "explicit");
        subscribe_consumer(rkshare, &t, 1);

        /* Phase 1: Consume all 10 records and ACCEPT */
        consumed = 0;
        attempts = 0;
        while (consumed < msgcnt && attempts++ < 30) {
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
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Phase 1: consumed and acknowledged %d messages\n", consumed);
        TEST_ASSERT(consumed == msgcnt, "Expected %d, got %d", msgcnt,
                    consumed);

        /* Inject 5000ms RTT on all brokers */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, -1, 5000);

        /* commit_sync with 2000ms timeout — should block ~2000ms
         * then time out */
        t_start      = test_clock();
        partitions   = NULL;
        error        = rd_kafka_share_commit_sync(rkshare, 2000, &partitions);
        t_elapsed_ms = (test_clock() - t_start) / 1000;

        TEST_SAY("Phase 1: commit_sync returned after %" PRId64
                 "ms, error=%s, partitions=%s\n",
                 t_elapsed_ms, error ? rd_kafka_error_string(error) : "NULL",
                 partitions ? "non-NULL" : "NULL");

        /* Verify commit_sync blocked for ~2000ms (allow 1500-3000ms) */
        TEST_ASSERT(t_elapsed_ms >= 1500 && t_elapsed_ms <= 3000,
                    "Expected commit_sync to block ~2000ms, "
                    "got %" PRId64 "ms",
                    t_elapsed_ms);

        /* May return top-level error or per-partition timeout error.
         * Accept either:
         * - top-level error: main thread commit_sync deadline fired
         *   first; rd_kafka_error_code(error) can be __TIMED_OUT
         *   (raw — top-level errors are not run through the per-
         *   partition translation funnel).
         * - per-partition REQUEST_TIMED_OUT: broker-thread reply
         *   path stamped __TIMED_OUT on batches, translated to
         *   REQUEST_TIMED_OUT at the app-facing funnel; or the api
         *   timer cb wrote REQUEST_TIMED_OUT directly. */
        if (error) {
                TEST_SAY("Phase 1: top-level error: %s\n",
                         rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
                got_timed_out = rd_true;
        }

        if (partitions) {
                for (i = 0; i < partitions->cnt; i++) {
                        rd_kafka_topic_partition_t *rktpar =
                            &partitions->elems[i];
                        TEST_SAY("Phase 1: %s [%" PRId32 "]: %s\n",
                                 rktpar->topic, rktpar->partition,
                                 rd_kafka_err2str(rktpar->err));
                        if (rktpar->err == RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT)
                                got_timed_out = rd_true;
                }
                rd_kafka_topic_partition_list_destroy(partitions);
        }

        TEST_ASSERT(got_timed_out,
                    "Expected REQUEST_TIMED_OUT or _TIMED_OUT error "
                    "from commit_sync with short timeout");

        /* Phase 2: Remove RTT, wait 5s for broker to finish
         * processing the delayed response */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, -1, 0);
        rd_sleep(5);

        /* Close first consumer */
        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Second consumer: should get 0 records because the broker
         * processed the acks despite client-side timeout */
        rkshare = create_mock_share_consumer(ctx.bootstraps,
                                             "sg-mock-cs-timeout", "implicit");
        subscribe_consumer(rkshare, &t, 1);

        consumed = 0;
        attempts = 0;
        while (attempts++ < 5) {
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

        TEST_SAY("Phase 2: second consumer got %d records (expected 0)\n",
                 consumed);
        TEST_ASSERT(consumed == 0,
                    "Second consumer got %d records, expected 0 "
                    "(broker should have processed acks despite "
                    "client-side timeout)",
                    consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Phase 3: Produce more, consume, commit_sync normally —
         * verify recovery after timeout */
        mock_produce_messages(ctx.producer, topic, msgcnt);

        rkshare = create_mock_share_consumer(ctx.bootstraps,
                                             "sg-mock-cs-timeout", "explicit");
        subscribe_consumer(rkshare, &t, 1);

        consumed = 0;
        attempts = 0;
        while (consumed < msgcnt && attempts++ < 30) {
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
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Phase 3: consumed %d messages\n", consumed);
        TEST_ASSERT(consumed == msgcnt, "Expected %d, got %d", msgcnt,
                    consumed);

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_ASSERT(!error, "Phase 3: commit_sync failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        TEST_ASSERT(partitions != NULL,
                    "Phase 3: expected partition results, got NULL");

        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                TEST_SAY("Phase 3: %s [%" PRId32 "]: %s\n", rktpar->topic,
                         rktpar->partition, rd_kafka_err2str(rktpar->err));
                TEST_ASSERT(rktpar->err == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Phase 3: expected NO_ERROR for %s [%" PRId32
                            "], got %s",
                            rktpar->topic, rktpar->partition,
                            rd_kafka_err2str(rktpar->err));
        }

        rd_kafka_topic_partition_list_destroy(partitions);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 10: Mixed commit types — commit_async and commit_sync.
 *
 *  Produce 50 records. Consume all, ACCEPT each record
 *  individually. For the first 10 records call commit_async,
 *  then call commit_sync for the 11th. Repeat this pattern
 *  (10 async + 1 sync) until all records are committed.
 *
 *  Verify that commit_sync after async commits completes very
 *  quickly (acks already sent by async, so sync has little or
 *  no work to do). Second consumer should get 0 records.
 * =================================================================== */
static void do_test_mixed_commit_types(void) {
        const char *topic;
        const char *group = "commit-sync-mixed-types";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed              = 0;
        int attempts              = 0;
        int async_cnt             = 0;
        int sync_cnt              = 0;
        int acked_since_last_sync = 0;
        int i;
        rd_ts_t t_start, t_elapsed_ms;
        rd_ts_t max_sync_elapsed_ms = 0;

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-mixed-types", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 50);

        rkshare = create_share_consumer(group, "explicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume all 50 records, ACCEPT each, alternate between
         * commit_async (10 times) and commit_sync (1 time) */
        while (consumed < 50 && attempts++ < 60) {
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
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;
                                acked_since_last_sync++;

                                if (acked_since_last_sync <= 10) {
                                        /* commit_async for first 10 */
                                        error = rd_kafka_share_commit_async(
                                            rkshare);
                                        TEST_ASSERT(
                                            !error,
                                            "commit_async #%d failed: %s",
                                            async_cnt + 1,
                                            error ? rd_kafka_error_string(error)
                                                  : "");
                                        async_cnt++;
                                }

                                if (acked_since_last_sync == 11) {
                                        /* commit_sync on the 11th —
                                         * should be fast since most acks
                                         * were already sent by async */
                                        partitions = NULL;
                                        t_start    = test_clock();
                                        error      = rd_kafka_share_commit_sync(
                                            rkshare, 30000, &partitions);
                                        t_elapsed_ms =
                                            (test_clock() - t_start) / 1000;
                                        sync_cnt++;

                                        if (t_elapsed_ms > max_sync_elapsed_ms)
                                                max_sync_elapsed_ms =
                                                    t_elapsed_ms;

                                        TEST_ASSERT(
                                            !error,
                                            "commit_sync #%d failed: %s",
                                            sync_cnt,
                                            error ? rd_kafka_error_string(error)
                                                  : "");

                                        if (partitions) {
                                                for (i = 0; i < partitions->cnt;
                                                     i++) {
                                                        rd_kafka_topic_partition_t
                                                            *rktpar =
                                                                &partitions
                                                                     ->elems[i];
                                                        TEST_ASSERT(
                                                            rktpar->err ==
                                                                RD_KAFKA_RESP_ERR_NO_ERROR,
                                                            "commit_sync #%d: "
                                                            "%s [%" PRId32
                                                            "] got %s",
                                                            sync_cnt,
                                                            rktpar->topic,
                                                            rktpar->partition,
                                                            rd_kafka_err2str(
                                                                rktpar->err));
                                                }
                                                rd_kafka_topic_partition_list_destroy(
                                                    partitions);
                                        }

                                        TEST_SAY(
                                            "commit_sync #%d OK "
                                            "in %" PRId64
                                            "ms (consumed %d, "
                                            "%d async calls)\n",
                                            sync_cnt, t_elapsed_ms, consumed,
                                            async_cnt);
                                        acked_since_last_sync = 0;
                                }
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Final commit_sync for any remaining acks */
        if (acked_since_last_sync > 0) {
                partitions = NULL;
                error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
                sync_cnt++;
                TEST_ASSERT(!error, "final commit_sync failed: %s",
                            error ? rd_kafka_error_string(error) : "");
                RD_IF_FREE(partitions, rd_kafka_topic_partition_list_destroy);
                TEST_SAY("Final commit_sync #%d OK\n", sync_cnt);
        }

        TEST_SAY(
            "Consumed %d, async commits=%d, sync commits=%d, "
            "max sync elapsed=%" PRId64 "ms\n",
            consumed, async_cnt, sync_cnt, max_sync_elapsed_ms);
        TEST_ASSERT(consumed == 50, "Expected 50, got %d", consumed);

        /* Verify commit_sync completed quickly — acks were mostly
         * already sent by commit_async, so sync should not wait long.
         * Allow up to 1000ms to account for broker round-trip. */
        TEST_ASSERT(max_sync_elapsed_ms < 1000,
                    "commit_sync took too long (%" PRId64
                    "ms), expected < 1000ms since acks were "
                    "mostly sent by commit_async",
                    max_sync_elapsed_ms);

        /* Allow time for any in-flight async ack requests to complete
         * before closing the consumer. The final commit_async calls
         * may have dispatched acks that are still awaiting broker
         * response. */
        rd_sleep(3);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Produce 5 verification records */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Second consumer: should only get the 5 verification records */
        rkshare = create_share_consumer(group, "implicit");
        subscribe_consumer(rkshare, &topic, 1);

        error = rd_kafka_share_poll(rkshare, 15000, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_SAY("Consumer B share_poll returned: rcvd=%zu, error=%s\n", rcvd,
                 error ? rd_kafka_error_string(error) : "none");
        if (error)
                rd_kafka_error_destroy(error);

        consumed = 0;
        for (j = 0; j < rcvd; j++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, j);
                if (!rkm->err) {
                        TEST_ASSERT(rd_kafka_message_delivery_count(rkm) == 1,
                                    "Consumer B got redelivered record at "
                                    "offset %" PRId64 " (delivery_count=%d)",
                                    rkm->offset,
                                    rd_kafka_message_delivery_count(rkm));
                        consumed++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumer B got %d messages (expected 5)\n", consumed);
        TEST_ASSERT(consumed == 5, "Expected 5 verification records, got %d",
                    consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test 11: Mock — broker dispatch priority (pending_commit_sync
 *  dispatched before async_ack_details).
 *
 *  Produce 30 messages. Consume all 30 in one batch. Then:
 *  - ACCEPT first 10, commit_async → inflight (push entry 1: 2s RTT)
 *  - ACCEPT next 10, commit_async → cached in async_ack_details
 *  - ACCEPT last 10, commit_sync(5000) → pending_commit_sync
 *
 *  When inflight completes at ~2s, broker dispatches next request.
 *  If pending_commit_sync has priority (correct): sync dispatched
 *  next (push entry 2: 2s RTT), completes at ~4s < 5s → NO_ERROR.
 *  If async_ack_details has priority (wrong): async dispatched
 *  next (2s RTT), then sync (2s RTT), completes at ~6s > 5s →
 *  TIMED_OUT.
 *
 *  Verification:
 *  1. commit_sync returns NO_ERROR and completes in ~4s (3500-4500ms)
 *  2. Per-partition results show NO_ERROR
 *  3. Second consumer gets 0 records (all acks processed)
 * =================================================================== */
static void do_test_mock_broker_dispatch_priority(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        const char *topic                           = "mock-cs-dispatch-prio";
        const char *t                               = topic;
        const int msgcnt                            = 30;
        rd_kafka_messages_t *batch                  = NULL;
        rd_kafka_messages_t *all_batch              = NULL;
        size_t rcvd;
        size_t j;
        int consumed;
        int attempts;
        int i;
        int32_t leader_broker_id = 1;
        rd_ts_t t_start, t_elapsed_ms;

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        rd_kafka_mock_partition_set_leader(ctx.mcluster, topic, 0,
                                           leader_broker_id);

        mock_produce_messages(ctx.producer, topic, msgcnt);

        rkshare = create_mock_share_consumer(ctx.bootstraps, "sg-mock-cs-prio",
                                             "explicit");
        subscribe_consumer(rkshare, &t, 1);

        /* Consume all 30 records in one batch, keep batch alive for
         * later acknowledge calls. */
        consumed = 0;
        attempts = 0;
        while (consumed == 0 && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err && consumed < msgcnt)
                                consumed++;
                }

                if (consumed == 0) {
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                } else {
                        all_batch = batch;
                        batch     = NULL;
                }
        }

        TEST_SAY("Consumed %d/%d messages\n", consumed, msgcnt);
        TEST_ASSERT(consumed == msgcnt, "Expected %d, got %d", msgcnt,
                    consumed);

        /* Push 3 ShareAcknowledge entries with 2000ms RTT each on
         * the leader broker. These are consumed in order:
         *  Entry 1: first commit_async inflight request (~2s)
         *  Entry 2: pending_commit_sync (if priority correct) (~2s)
         *  Entry 3: async_ack_details (dispatched last) (~2s) */
        rd_kafka_mock_broker_push_request_error_rtts(
            ctx.mcluster, leader_broker_id, RD_KAFKAP_ShareAcknowledge, 3,
            RD_KAFKA_RESP_ERR_NO_ERROR, 2000, RD_KAFKA_RESP_ERR_NO_ERROR, 2000,
            RD_KAFKA_RESP_ERR_NO_ERROR, 2000);

        /* ACCEPT first 10, commit_async → sends first
         * ShareAcknowledge (inflight, push entry 1: 2s RTT) */
        for (i = 0; i < 10; i++)
                rd_kafka_share_acknowledge(rkshare,
                                           rd_kafka_messages_get(all_batch, i));

        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async #1 failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        TEST_SAY("commit_async #1 sent (inflight, 2s RTT)\n");

        /* Small delay to ensure async request is dispatched to
         * broker thread before next commit */
        rd_usleep(200 * 1000, NULL);

        /* ACCEPT next 10, commit_async → broker busy,
         * cached in async_ack_details */
        for (i = 10; i < 20; i++)
                rd_kafka_share_acknowledge(rkshare,
                                           rd_kafka_messages_get(all_batch, i));

        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async #2 failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        TEST_SAY("commit_async #2 sent (cached in async_ack_details)\n");

        /* ACCEPT last 10, commit_sync(5000ms) → broker still busy,
         * stored in pending_commit_sync.
         *
         * Timeline if sync has dispatch priority (correct):
         *   t=0s:  inflight request sent
         *   t=2s:  inflight completes, sync dispatched (entry 2)
         *   t=4s:  sync completes → NO_ERROR (4s < 5s timeout)
         *
         * Timeline if async has priority (wrong):
         *   t=0s:  inflight request sent
         *   t=2s:  inflight completes, async dispatched (entry 2)
         *   t=4s:  async completes, sync dispatched (entry 3)
         *   t=5s:  sync timeout fires → TIMED_OUT (5s < 6s) */
        for (i = 20; i < 30; i++)
                rd_kafka_share_acknowledge(rkshare,
                                           rd_kafka_messages_get(all_batch, i));

        TEST_SAY("Calling commit_sync(5000ms)\n");
        t_start      = test_clock();
        partitions   = NULL;
        error        = rd_kafka_share_commit_sync(rkshare, 5000, &partitions);
        t_elapsed_ms = (test_clock() - t_start) / 1000;

        TEST_SAY("commit_sync returned after %" PRId64 "ms, error=%s\n",
                 t_elapsed_ms,
                 error ? rd_kafka_error_string(error) : "NO_ERROR");

        /* Verify no error */
        if (error) {
                TEST_ASSERT(rd_kafka_error_code(error) !=
                                RD_KAFKA_RESP_ERR__TIMED_OUT,
                            "commit_sync TIMED_OUT after %" PRId64
                            "ms — pending_commit_sync was NOT dispatched "
                            "before async_ack_details. "
                            "Dispatch priority is broken.",
                            t_elapsed_ms);
                rd_kafka_error_destroy(error);
        } else {
                TEST_SAY(
                    "commit_sync returned NO_ERROR — dispatch "
                    "priority is correct\n");
        }

        /* Verify timing: should complete in ~4s (2s inflight + 2s sync),
         * not ~6s (2s inflight + 2s async + 2s sync). */
        TEST_ASSERT(t_elapsed_ms >= 3250 && t_elapsed_ms <= 4500,
                    "Expected commit_sync to complete in ~4s (3250-4500ms), "
                    "got %" PRId64 "ms. If >5s, dispatch priority is wrong.",
                    t_elapsed_ms);

        /* Verify per-partition results show NO_ERROR */
        TEST_ASSERT(partitions != NULL,
                    "Expected per-partition results, got NULL");

        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                TEST_SAY("  %s [%" PRId32 "]: %s\n", rktpar->topic,
                         rktpar->partition, rd_kafka_err2str(rktpar->err));
                TEST_ASSERT(rktpar->err == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Expected NO_ERROR for %s [%" PRId32 "], got %s",
                            rktpar->topic, rktpar->partition,
                            rd_kafka_err2str(rktpar->err));
        }

        rd_kafka_topic_partition_list_destroy(partitions);

        /* Destroy the held batch (frees all message handles) */
        rd_kafka_messages_destroy(all_batch);
        all_batch = NULL;

        /* Wait for remaining async to complete */
        rd_sleep(3);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* Second consumer: should get 0 records since all acks
         * were processed successfully */
        rkshare = create_mock_share_consumer(ctx.bootstraps, "sg-mock-cs-prio",
                                             "implicit");
        subscribe_consumer(rkshare, &t, 1);

        consumed = 0;
        attempts = 0;
        while (attempts++ < 5) {
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

        TEST_SAY("Second consumer got %d records (expected 0)\n", consumed);
        TEST_ASSERT(consumed == 0,
                    "Second consumer got %d records, expected 0 "
                    "(all acks should have been processed)",
                    consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* Extended ack callback state with error tracking for sync commit tests */
typedef struct ack_cb_state_s {
        test_ack_cb_state_t base;       /* Base state from test.h */
        rd_kafka_resp_err_t errors[64]; /* Track errors per callback */
        int error_cnt;
} ack_cb_state_t;

static void share_ack_cb(rd_kafka_share_t *rkshare,
                         rd_kafka_share_partition_offsets_list_t *partitions,
                         rd_kafka_resp_err_t err,
                         void *opaque) {
        ack_cb_state_t *state = (ack_cb_state_t *)opaque;
        const rd_kafka_share_partition_offsets_t *entry;
        size_t partition_cnt, offsets_in_entry = 0;

        (void)rkshare;

        partition_cnt = rd_kafka_share_partition_offsets_list_count(partitions);

        entry = rd_kafka_share_partition_offsets_list_get(partitions, 0);
        if (entry)
                offsets_in_entry =
                    rd_kafka_share_partition_offsets_offsets_cnt(entry);

        TEST_SAY("ACK CALLBACK: err=%s (%d), partitions=%zu, offsets=%zu\n",
                 rd_kafka_err2name(err), err, partition_cnt, offsets_in_entry);

        test_ack_cb_state_push_err(&state->base, err);

        /* Track this error in our errors array */
        if (state->error_cnt < 64)
                state->errors[state->error_cnt++] = err;

        if (entry)
                state->base.total_offsets += offsets_in_entry;
}



/* ===================================================================
 *  Test: commit_sync callback invocation.
 *
 *  Verifies that the runtime acknowledgement callback is invoked after
 *  commit_sync when using dedicated ShareAcknowledge request.
 * =================================================================== */
static void do_test_commit_sync_callback(void) {
        const char *topic;
        const char *group = "commit-sync-callback";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        size_t consumed           = 0;
        int attempts              = 0;
        test_ack_cb_state_t state = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-callback", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, 50);

        rkshare =
            test_create_share_consumer_with_cb(group, "explicit", &state, NULL);
        const char *grp_conf[] = {"share.auto.offset.reset", "SET", "earliest"};
        test_alter_group_configurations(group, grp_conf, 1);
        subscribe_consumer(rkshare, &topic, 1);

        /* Consume and acknowledge messages */
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
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_SAY("Consumed and acknowledged %zu messages\n", consumed);
        TEST_ASSERT(consumed > 0, "Expected to consume some messages");

        /* Call commit_sync to trigger callback */
        error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_ASSERT(!error, "commit_sync failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        RD_IF_FREE(partitions, rd_kafka_topic_partition_list_destroy);

        /* Wait for callback */
        test_wait_for_cb_with_poll(&state, rkshare, 1, 10000);

        TEST_SAY("Callback count=%d, total_offsets=%zu\n", state.callback_cnt,
                 state.total_offsets);

        TEST_ASSERT(state.callback_cnt == 1,
                    "Expected callback to be invoked once, got %d",
                    state.callback_cnt);
        TEST_ASSERT(state.total_offsets == consumed,
                    "Expected %zu offsets in callback, got %zu", consumed,
                    state.total_offsets);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state);

        SUB_TEST_PASS();
}

/* ===================================================================
 *  commit_sync after subscribed topic deletion surfaces a per-partition
 *  error.
 *
 *  Produce records, consume them, delete the subscribed topic, then
 *  call commit_sync. The returned per-partition list should include the
 *  deleted topic's partition with an error code (typically
 *  UNKNOWN_TOPIC_OR_PART), not silent success.
 * =================================================================== */
static void do_test_commit_sync_after_topic_deletion(void) {
        const char *topic_name;
        char *topic_dup;
        char *topics_for_delete[1];
        const char *group = "commit-sync-deleted-topic";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        rd_kafka_resp_err_t del_err;
        size_t rcvd;
        size_t j;
        int consumed             = 0;
        int attempts             = 0;
        rd_bool_t topic_err_seen = rd_false;

        SUB_TEST();

        if (!strcmp(test_getenv("TEST_BROKER_OS", ""), "windows")) {
                TEST_SAY(
                    "Skipping commit_sync-after-topic-deletion "
                    "(broker on Windows)\n");
                SUB_TEST_PASS();
                return;
        }

        topic_name = test_mk_topic_name("0176-cs-deleted", 1);
        topic_dup  = rd_strdup(topic_name);
        test_create_topic_wait_exists(common_admin, topic_name, 1, -1,
                                      60 * 1000);
        test_produce_msgs_simple(common_producer, topic_name, 0, 5);

        rkshare = create_share_consumer(group, "implicit");
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic_name, 1);

        /* Consume records (so there's something to commit) */
        while (consumed == 0 && attempts++ < 30) {
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
        TEST_ASSERT(consumed > 0, "Expected to consume records, got 0");

        /* Delete the subscribed topic */
        TEST_SAY("Deleting topic %s\n", topic_name);
        topics_for_delete[0] = topic_dup;
        del_err              = test_DeleteTopics_simple(common_admin, NULL,
                                                        topics_for_delete, 1, NULL);
        TEST_ASSERT(del_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "DeleteTopics failed: %s", rd_kafka_err2str(del_err));

        /* Wait for the topic delete to propagate in the cluster. */
        rd_sleep(3);

        /* commit_sync should return per-partition results — at least one
         * partition's err should indicate the deletion. */
        error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_SAY("commit_sync returned: error=%s, partitions=%p\n",
                 error ? rd_kafka_error_string(error) : "NULL",
                 (void *)partitions);

        if (error)
                rd_kafka_error_destroy(error);

        if (partitions) {
                int i;
                TEST_SAY("commit_sync returned %d partition entries\n",
                         partitions->cnt);
                for (i = 0; i < partitions->cnt; i++) {
                        TEST_SAY("  %s [%" PRId32 "]: %s\n",
                                 partitions->elems[i].topic,
                                 partitions->elems[i].partition,
                                 rd_kafka_err2name(partitions->elems[i].err));
                        if (partitions->elems[i].err !=
                            RD_KAFKA_RESP_ERR_NO_ERROR)
                                topic_err_seen = rd_true;
                }
                rd_kafka_topic_partition_list_destroy(partitions);
        }

        TEST_ASSERT(topic_err_seen,
                    "Expected commit_sync to surface a per-partition error "
                    "after topic deletion");

        rd_free(topic_dup);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Chaos: strict per-record ack / commit interleaving.
 *
 *  Pattern over 30 ACCEPTed records:
 *    Phase A (records 0-14): one commit per ack, alternating
 *                            commit_sync (odd-indexed acks) and
 *                            commit_async (even-indexed acks).
 *    Phase B (records 15-29): one commit per every 2 acks,
 *                             alternating commit_sync / commit_async
 *                             by pair index.
 *  Verifies the library survives tight ack/commit alternation and
 *  that the ack callback fires at least once across the run.
 * =================================================================== */
static void do_test_chaos_111_ack_commit_interleave(void) {
        const char *topic;
        const char *group = "commit-sync-chaos-111";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed         = 0;
        int attempts         = 0;
        int sync_cnt         = 0;
        int async_cnt        = 0;
        const int total_msgs = 30;
        const int phase_a    = 15; /* 1-1 interleave region */
        ack_cb_state_t state = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-chaos-111", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, total_msgs);

        rkshare = test_create_share_consumer_with_cb(group, "explicit",
                                                     &state.base, share_ack_cb);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        while (consumed < total_msgs && attempts++ < 60) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd && consumed < total_msgs; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (rkm->err)
                                continue;

                        rd_kafka_share_acknowledge(rkshare, rkm);
                        consumed++;

                        if (consumed <= phase_a) {
                                /* Phase A: ack 1 -> commit alternates */
                                if (consumed % 2 == 1) {
                                        error = rd_kafka_share_commit_sync(
                                            rkshare, 30000, &partitions);
                                        TEST_ASSERT(
                                            !error,
                                            "phase A commit_sync #%d: %s",
                                            sync_cnt + 1,
                                            error ? rd_kafka_error_string(error)
                                                  : "");
                                        RD_IF_FREE(
                                            partitions,
                                            rd_kafka_topic_partition_list_destroy);
                                        partitions = NULL;
                                        sync_cnt++;
                                } else {
                                        error = rd_kafka_share_commit_async(
                                            rkshare);
                                        TEST_ASSERT(
                                            !error,
                                            "phase A commit_async #%d: %s",
                                            async_cnt + 1,
                                            error ? rd_kafka_error_string(error)
                                                  : "");
                                        async_cnt++;
                                }
                        } else if (consumed % 2 == 0) {
                                /* Phase B: commit every 2 records,
                                 * alternating sync/async by pair index */
                                int pair_idx = (consumed - phase_a) / 2;
                                if (pair_idx % 2 == 1) {
                                        error = rd_kafka_share_commit_async(
                                            rkshare);
                                        TEST_ASSERT(
                                            !error,
                                            "phase B commit_async #%d: %s",
                                            async_cnt + 1,
                                            error ? rd_kafka_error_string(error)
                                                  : "");
                                        async_cnt++;
                                } else {
                                        error = rd_kafka_share_commit_sync(
                                            rkshare, 30000, &partitions);
                                        TEST_ASSERT(
                                            !error,
                                            "phase B commit_sync #%d: %s",
                                            sync_cnt + 1,
                                            error ? rd_kafka_error_string(error)
                                                  : "");
                                        RD_IF_FREE(
                                            partitions,
                                            rd_kafka_topic_partition_list_destroy);
                                        partitions = NULL;
                                        sync_cnt++;
                                }
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(consumed == total_msgs, "Expected %d records, consumed %d",
                    total_msgs, consumed);

        /* Drain any pending async commit callbacks. */
        test_wait_for_cb_with_poll(&state.base, rkshare, sync_cnt + async_cnt,
                                   10000);

        TEST_SAY(
            "chaos 1-1-1: consumed=%d sync=%d async=%d "
            "callbacks=%d offsets=%zu last_err=%s\n",
            consumed, sync_cnt, async_cnt, state.base.callback_cnt,
            state.base.total_offsets,
            rd_kafka_err2name(test_ack_cb_state_first_err(&state.base)));

        TEST_ASSERT(state.base.callback_cnt >= 1,
                    "Expected at least 1 ack callback, got %d",
                    state.base.callback_cnt);
        TEST_ASSERT(
            test_ack_cb_state_first_err(&state.base) ==
                RD_KAFKA_RESP_ERR_NO_ERROR,
            "Ack callback reported err: %s",
            rd_kafka_err2name(test_ack_cb_state_first_err(&state.base)));

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state.base);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Chaos: per-record alternating commit_sync / commit_async.
 *
 *  Consume 40 records and, for every single ACCEPTed record, alternate
 *  between commit_sync and commit_async. Stresses the library's
 *  bookkeeping under the tightest possible commit cadence.
 * =================================================================== */
static void do_test_chaos_alternating_commits(void) {
        const char *topic;
        const char *group = "commit-sync-chaos-alt";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed         = 0;
        int attempts         = 0;
        int sync_cnt         = 0;
        int async_cnt        = 0;
        const int total_msgs = 40;
        ack_cb_state_t state = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-chaos-alt", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, total_msgs);

        rkshare = test_create_share_consumer_with_cb(group, "explicit",
                                                     &state.base, share_ack_cb);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        while (consumed < total_msgs && attempts++ < 60) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd && consumed < total_msgs; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (rkm->err)
                                continue;
                        rd_kafka_share_acknowledge(rkshare, rkm);
                        consumed++;

                        if (consumed % 2 == 1) {
                                error = rd_kafka_share_commit_sync(
                                    rkshare, 30000, &partitions);
                                TEST_ASSERT(
                                    !error, "commit_sync #%d: %s", sync_cnt + 1,
                                    error ? rd_kafka_error_string(error) : "");
                                RD_IF_FREE(
                                    partitions,
                                    rd_kafka_topic_partition_list_destroy);
                                partitions = NULL;
                                sync_cnt++;
                        } else {
                                error = rd_kafka_share_commit_async(rkshare);
                                TEST_ASSERT(!error, "commit_async #%d: %s",
                                            async_cnt + 1,
                                            error ? rd_kafka_error_string(error)
                                                  : "");
                                async_cnt++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(consumed == total_msgs, "Expected %d records, consumed %d",
                    total_msgs, consumed);

        test_wait_for_cb_with_poll(&state.base, rkshare, sync_cnt + async_cnt,
                                   10000);

        TEST_SAY(
            "chaos alt: consumed=%d sync=%d async=%d "
            "callbacks=%d offsets=%zu last_err=%s\n",
            consumed, sync_cnt, async_cnt, state.base.callback_cnt,
            state.base.total_offsets,
            rd_kafka_err2name(test_ack_cb_state_first_err(&state.base)));

        TEST_ASSERT(
            test_ack_cb_state_first_err(&state.base) ==
                RD_KAFKA_RESP_ERR_NO_ERROR,
            "Ack callback reported err: %s",
            rd_kafka_err2name(test_ack_cb_state_first_err(&state.base)));

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state.base);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Chaos: randomized ack types and commit modes (fixed seed).
 *
 *  Seeded PRNG so the sequence is fully reproducible across runs.
 *  For each ACCEPTed/RELEASEd/REJECTed record we may immediately issue
 *  a commit (sync or async), with the choices driven by the PRNG.
 *  Verifies that the lib survives a realistic mixed workload and that
 *  ACCEPT'd offsets eventually flow through the ack callback without
 *  errors.
 * =================================================================== */
static void do_test_chaos_random_ack_random_commit(void) {
        const char *topic;
        const char *group = "commit-sync-chaos-rand";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int processed         = 0;
        int accepted          = 0;
        int released          = 0;
        int rejected          = 0;
        int attempts          = 0;
        int sync_cnt          = 0;
        int async_cnt         = 0;
        const int produce_cnt = 80;
        const int target      = 60; /* stop after this many processed */
        ack_cb_state_t state  = {0};

        SUB_TEST();

        /* Fixed seed: this test must produce the same chaos sequence
         * across runs so a failure can be reproduced deterministically.
         * Seed is set before any rand() call inside this test; no earlier
         * test in main_0176_share_consumer_commit_sync calls rand(). */
        srand(0xC0FFEE);

        topic = test_mk_topic_name("0176-cs-chaos-rand", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, produce_cnt);

        rkshare = test_create_share_consumer_with_cb(group, "explicit",
                                                     &state.base, share_ack_cb);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        while (processed < target && attempts++ < 80) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                /* Drain the entire batch every iteration. Past `target`,
                 * stop driving chaos but still ACCEPT every record so
                 * nothing is left ACQUIRED in the lib's inflight map —
                 * otherwise close/destroy would have to clean it up,
                 * which the share consumer doesn't currently handle. */
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_share_AcknowledgeType_t at;
                        rd_kafka_resp_err_t aerr;
                        int r;
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);

                        if (rkm->err)
                                continue;

                        if (processed >= target) {
                                /* Drain-only path: ACCEPT to release the
                                 * lock without affecting chaos stats. */
                                aerr = rd_kafka_share_acknowledge_type(
                                    rkshare, rkm,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                                TEST_ASSERT(!aerr, "drain ACCEPT failed: %s",
                                            rd_kafka_err2str(aerr));
                                continue;
                        }

                        r = rand() % 6;
                        if (r < 4) {
                                at = RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT;
                                accepted++;
                        } else if (r == 4) {
                                at = RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE;
                                released++;
                        } else {
                                at = RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT;
                                rejected++;
                        }

                        aerr =
                            rd_kafka_share_acknowledge_type(rkshare, rkm, at);
                        TEST_ASSERT(!aerr, "acknowledge_type(%d) failed: %s",
                                    (int)at, rd_kafka_err2str(aerr));
                        processed++;

                        /* ~1 in 3 records: issue a commit. Sync vs async
                         * decided by another PRNG draw. */
                        if (rand() % 3 == 0) {
                                if (rand() % 2 == 0) {
                                        error = rd_kafka_share_commit_sync(
                                            rkshare, 30000, &partitions);
                                        TEST_ASSERT(
                                            !error, "commit_sync #%d: %s",
                                            sync_cnt + 1,
                                            error ? rd_kafka_error_string(error)
                                                  : "");
                                        RD_IF_FREE(
                                            partitions,
                                            rd_kafka_topic_partition_list_destroy);
                                        partitions = NULL;
                                        sync_cnt++;
                                } else {
                                        error = rd_kafka_share_commit_async(
                                            rkshare);
                                        TEST_ASSERT(
                                            !error, "commit_async #%d: %s",
                                            async_cnt + 1,
                                            error ? rd_kafka_error_string(error)
                                                  : "");
                                        async_cnt++;
                                }
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Final flush. */
        error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        TEST_ASSERT(!error, "final commit_sync: %s",
                    error ? rd_kafka_error_string(error) : "");
        RD_IF_FREE(partitions, rd_kafka_topic_partition_list_destroy);
        partitions = NULL;
        sync_cnt++;

        test_wait_for_cb_with_poll(&state.base, rkshare, sync_cnt + async_cnt,
                                   15000);

        TEST_SAY(
            "chaos random: processed=%d accept=%d release=%d reject=%d "
            "sync=%d async=%d callbacks=%d offsets=%zu\n",
            processed, accepted, released, rejected, sync_cnt, async_cnt,
            state.base.callback_cnt, state.base.total_offsets);

        TEST_ASSERT(state.base.callback_cnt >= 1,
                    "Expected at least 1 ack callback, got %d",
                    state.base.callback_cnt);
        TEST_ASSERT(
            test_ack_cb_state_first_err(&state.base) ==
                RD_KAFKA_RESP_ERR_NO_ERROR,
            "Ack callback reported err: %s",
            rd_kafka_err2name(test_ack_cb_state_first_err(&state.base)));

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state.base);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Chaos: burst of back-to-back commit_async then a flushing commit_sync.
 *
 *  Consume 50 records. After every ACCEPT, fire 5 commit_async in a row
 *  followed by 1 commit_sync. Stresses the in-flight async commit queue
 *  and the path where commit_sync drains a backlog of pending acks.
 * =================================================================== */
static void do_test_chaos_burst_commits(void) {
        const char *topic;
        const char *group = "commit-sync-chaos-burst";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed  = 0;
        int attempts  = 0;
        int sync_cnt  = 0;
        int async_cnt = 0;
        int b;
        const int total_msgs = 50;
        const int burst_size = 5;
        ack_cb_state_t state = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-chaos-burst", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, total_msgs);

        rkshare = test_create_share_consumer_with_cb(group, "explicit",
                                                     &state.base, share_ack_cb);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        while (consumed < total_msgs && attempts++ < 60) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd && consumed < total_msgs; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (rkm->err)
                                continue;
                        rd_kafka_share_acknowledge(rkshare, rkm);
                        consumed++;

                        for (b = 0; b < burst_size; b++) {
                                error = rd_kafka_share_commit_async(rkshare);
                                TEST_ASSERT(
                                    !error, "burst commit_async #%d: %s",
                                    async_cnt + 1,
                                    error ? rd_kafka_error_string(error) : "");
                                async_cnt++;
                        }

                        error = rd_kafka_share_commit_sync(rkshare, 30000,
                                                           &partitions);
                        TEST_ASSERT(!error, "burst commit_sync #%d: %s",
                                    sync_cnt + 1,
                                    error ? rd_kafka_error_string(error) : "");
                        RD_IF_FREE(partitions,
                                   rd_kafka_topic_partition_list_destroy);
                        partitions = NULL;
                        sync_cnt++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(consumed == total_msgs, "Expected %d records, consumed %d",
                    total_msgs, consumed);

        test_wait_for_cb_with_poll(&state.base, rkshare, sync_cnt, 15000);

        TEST_SAY(
            "chaos burst: consumed=%d sync=%d async=%d "
            "callbacks=%d offsets=%zu\n",
            consumed, sync_cnt, async_cnt, state.base.callback_cnt,
            state.base.total_offsets);

        TEST_ASSERT(
            test_ack_cb_state_first_err(&state.base) ==
                RD_KAFKA_RESP_ERR_NO_ERROR,
            "Ack callback reported err: %s",
            rd_kafka_err2name(test_ack_cb_state_first_err(&state.base)));

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state.base);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Chaos: callback-driven receipt accounting under varying batch sizes.
 *
 *  Consume 60 records and commit with progressively varying batch sizes
 *  (ack 1 -> commit, ack 2 -> commit, ack 3 -> commit, ...) alternating
 *  between commit_sync and commit_async. After the run, verify the ack
 *  callback received offset counts that account for all ACCEPTed records.
 * =================================================================== */
static void do_test_chaos_callback_receipt_match(void) {
        const char *topic;
        const char *group = "commit-sync-chaos-receipts";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        size_t rcvd;
        size_t j;
        int consumed           = 0;
        int attempts           = 0;
        int acked_since_commit = 0;
        int batch_target       = 1;
        int sync_cnt           = 0;
        int async_cnt          = 0;
        const int total_msgs   = 60;
        ack_cb_state_t state   = {0};

        SUB_TEST();

        topic = test_mk_topic_name("0176-cs-chaos-receipts", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, total_msgs);

        rkshare = test_create_share_consumer_with_cb(group, "explicit",
                                                     &state.base, share_ack_cb);
        test_share_set_auto_offset_reset(group, "earliest");
        subscribe_consumer(rkshare, &topic, 1);

        while (consumed < total_msgs && attempts++ < 60) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                for (j = 0; j < rcvd && consumed < total_msgs; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (rkm->err)
                                continue;
                        rd_kafka_share_acknowledge(rkshare, rkm);
                        consumed++;
                        acked_since_commit++;

                        if (acked_since_commit < batch_target)
                                continue;

                        /* Alternate sync (odd batch idx) / async (even). */
                        if ((sync_cnt + async_cnt) % 2 == 0) {
                                error = rd_kafka_share_commit_sync(
                                    rkshare, 30000, &partitions);
                                TEST_ASSERT(
                                    !error, "receipts commit_sync #%d: %s",
                                    sync_cnt + 1,
                                    error ? rd_kafka_error_string(error) : "");
                                RD_IF_FREE(
                                    partitions,
                                    rd_kafka_topic_partition_list_destroy);
                                partitions = NULL;
                                sync_cnt++;
                        } else {
                                error = rd_kafka_share_commit_async(rkshare);
                                TEST_ASSERT(
                                    !error, "receipts commit_async #%d: %s",
                                    async_cnt + 1,
                                    error ? rd_kafka_error_string(error) : "");
                                async_cnt++;
                        }
                        acked_since_commit = 0;
                        batch_target       = (batch_target % 5) + 1;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Drain any leftover acked-but-not-committed records. */
        if (acked_since_commit > 0) {
                error = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
                TEST_ASSERT(!error, "final commit_sync: %s",
                            error ? rd_kafka_error_string(error) : "");
                RD_IF_FREE(partitions, rd_kafka_topic_partition_list_destroy);
                partitions = NULL;
                sync_cnt++;
        }

        TEST_ASSERT(consumed == total_msgs, "Expected %d records, consumed %d",
                    total_msgs, consumed);

        test_wait_for_cb_with_poll(&state.base, rkshare, sync_cnt + async_cnt,
                                   15000);

        TEST_SAY(
            "chaos receipts: consumed=%d sync=%d async=%d "
            "callbacks=%d offsets=%zu\n",
            consumed, sync_cnt, async_cnt, state.base.callback_cnt,
            state.base.total_offsets);

        TEST_ASSERT(state.base.callback_cnt >= 1,
                    "Expected at least 1 ack callback, got %d",
                    state.base.callback_cnt);
        TEST_ASSERT(state.base.total_offsets >= (size_t)consumed,
                    "Expected callback to surface at least %d offsets, got %zu",
                    consumed, state.base.total_offsets);
        TEST_ASSERT(
            test_ack_cb_state_first_err(&state.base) ==
                RD_KAFKA_RESP_ERR_NO_ERROR,
            "Ack callback reported err: %s",
            rd_kafka_err2name(test_ack_cb_state_first_err(&state.base)));

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state.base);

        SUB_TEST_PASS();
}


int main_0176_share_consumer_commit_sync(int argc, char **argv) {
        test_timeout_set(120);
        common_producer = test_create_producer();
        common_admin    = test_create_producer();

        /* Real broker tests */
        do_test_basic_implicit_commit_sync();
        do_test_basic_explicit_commit_sync();
        do_test_no_pending_acks();
        do_test_commit_sync_prevents_redelivery();
        do_test_mixed_ack_types();
        do_test_multiple_commit_sync_calls();
        do_test_multi_topic_partition();
        do_test_mixed_commit_types();

        /* Callback test */
        do_test_commit_sync_callback();

        /* commit_sync after subscribed topic was deleted */
        do_test_commit_sync_after_topic_deletion();

        /* Chaos: interleaved ack / commit patterns. */
        do_test_chaos_111_ack_commit_interleave();
        do_test_chaos_alternating_commits();
        do_test_chaos_random_ack_random_commit();
        do_test_chaos_burst_commits();
        do_test_chaos_callback_receipt_match();

        rd_kafka_destroy(common_admin);
        rd_kafka_destroy(common_producer);

        return 0;
}

int main_0176_share_consumer_commit_sync_local(int argc, char **argv) {
        /* Mock broker tests only (no real broker needed) */
        TEST_SKIP_MOCK_CLUSTER(0);

        do_test_mock_uses_share_acknowledge();
        do_test_mock_commit_sync_timeout();
        do_test_mock_broker_dispatch_priority();

        return 0;
}