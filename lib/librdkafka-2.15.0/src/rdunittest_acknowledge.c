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

/**
 * @brief Unit tests for Share Consumer acknowledge APIs
 *
 * Tests the following public APIs:
 * 1. rd_kafka_share_acknowledge() - Acknowledge delivered record with ACCEPT
 * 2. rd_kafka_share_acknowledge_type() - Acknowledge delivered record with type
 * 3. rd_kafka_share_acknowledge_offset() - Acknowledge record by offset
 */

#include "rd.h"
#include "rdunittest.h"
#include "rdkafka_int.h"
#include "rdkafka_partition.h"

/* Test topic_id for unit tests (non-zero UUID) */
static const rd_kafka_Uuid_t ut_topic_id_t1 = {.most_significant_bits  = 1,
                                               .least_significant_bits = 1};
static const rd_kafka_Uuid_t ut_topic_id_t2 = {.most_significant_bits  = 2,
                                               .least_significant_bits = 2};

/**
 * @brief Create a rd_kafka_share_t instance for testing using the proper
 * share consumer API with explicit acknowledgement mode.
 */
static rd_kafka_share_t *ut_ack_create_share_consumer(void) {
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        char errstr[128];

        if (rd_kafka_conf_set(conf, "group.id", "ut-share-ack", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                rd_kafka_conf_destroy(conf);
                return NULL;
        }

        /* Enable explicit acknowledgement mode for testing acknowledge APIs */
        if (rd_kafka_conf_set(conf, "share.acknowledgement.mode", "explicit",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                rd_kafka_conf_destroy(conf);
                return NULL;
        }

        rd_kafka_share_t *rkshare =
            rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        /* conf is consumed by rd_kafka_share_consumer_new on success */

        return rkshare;
}

/**
 * @brief Register a topic with the rd_kafka_t instance and set its topic_id.
 *
 * This is needed for rd_kafka_share_acknowledge_offset() to find the topic
 * by name and resolve its topic_id.
 */
static rd_kafka_topic_t *ut_ack_register_topic(rd_kafka_t *rk,
                                               const char *topic,
                                               rd_kafka_Uuid_t topic_id) {
        rd_kafka_topic_t *rkt = rd_kafka_topic_new(rk, topic, NULL);
        if (!rkt)
                return NULL;

        /* Set the topic_id on the registered topic */
        rkt->rkt_topic_id = topic_id;

        return rkt;
}

/**
 * @brief Clear all entries from the inflight acks map.
 *
 * Used between tests to reset state while keeping the same rkshare.
 */
static void ut_ack_clear_inflight_map(rd_kafka_share_t *rkshare) {
        if (!rkshare)
                return;

        /* RD_MAP_CLEAR will call the free functions for keys and values */
        RD_MAP_CLEAR(&rkshare->rkshare_inflight_acks);

        /* Reset unacked count */
        rkshare->rkshare_unacked_cnt = 0;
}

/**
 * @brief Add a partition with acquired offsets to the rkshare inflight map.
 *
 * Creates an entry with all offsets in ACQUIRED state (delivered records).
 * Delivered records can be acknowledged via record-based APIs.
 */
static void ut_ack_add_partition(rd_kafka_share_t *rkshare,
                                 const char *topic,
                                 int32_t partition,
                                 int64_t start_offset,
                                 int64_t end_offset) {
        rd_kafka_topic_partition_private_t *parpriv;
        rd_kafka_share_ack_batches_t *batches = rd_calloc(1, sizeof(*batches));

        batches->rktpar = rd_kafka_topic_partition_new(topic, partition);
        parpriv         = rd_kafka_topic_partition_private_new();
        batches->rktpar->_private = parpriv;

        batches->response_leader_id = 1;

        int64_t size = end_offset - start_offset + 1;
        batches->response_acquired_offsets_count = (int32_t)size;

        rd_list_init(&batches->entries, 1, NULL);

        rd_kafka_share_ack_batch_entry_t *entry = rd_calloc(1, sizeof(*entry));
        entry->start_offset                     = start_offset;
        entry->end_offset                       = end_offset;
        entry->size                             = size;
        entry->types_cnt                        = (int32_t)size;
        entry->types = rd_calloc(size, sizeof(*entry->types));

        /* Initialize all offsets to ACQUIRED */
        for (int64_t i = 0; i < size; i++) {
                entry->types[i] = RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED;
        }

        rd_list_add(&batches->entries, entry);

        /* Mark as sorted */
        batches->entries.rl_flags |= RD_LIST_F_SORTED;

        rd_kafka_topic_partition_t *key =
            rd_kafka_topic_partition_new(topic, partition);
        RD_MAP_SET(&rkshare->rkshare_inflight_acks, key, batches);

        /* Increment unacked count for all ACQUIRED offsets */
        rkshare->rkshare_unacked_cnt += size;
}


/**
 * @brief Set a specific offset as a GAP record.
 */
static void ut_ack_set_gap(rd_kafka_share_t *rkshare,
                           const char *topic,
                           int32_t partition,
                           int64_t offset) {
        rd_kafka_topic_partition_t *lookup_key =
            rd_kafka_topic_partition_new(topic, partition);

        rd_kafka_share_ack_batches_t *batches =
            RD_MAP_GET(&rkshare->rkshare_inflight_acks, lookup_key);
        rd_kafka_topic_partition_destroy(lookup_key);

        if (!batches)
                return;

        rd_kafka_share_ack_batch_entry_t *entry;
        int i;
        RD_LIST_FOREACH(entry, &batches->entries, i) {
                if (offset >= entry->start_offset &&
                    offset <= entry->end_offset) {
                        int64_t idx       = offset - entry->start_offset;
                        entry->types[idx] = RD_KAFKA_SHARE_INTERNAL_ACK_GAP;
                        return;
                }
        }
}

/**
 * @brief Get the ack type for a specific offset in the inflight map.
 */
static rd_kafka_share_internal_acknowledgement_type
ut_ack_get_type(rd_kafka_share_t *rkshare,
                const char *topic,
                int32_t partition,
                int64_t offset) {
        rd_kafka_topic_partition_t *lookup_key =
            rd_kafka_topic_partition_new(topic, partition);

        rd_kafka_share_ack_batches_t *batches =
            RD_MAP_GET(&rkshare->rkshare_inflight_acks, lookup_key);
        rd_kafka_topic_partition_destroy(lookup_key);

        if (!batches)
                return -99; /* Invalid marker */

        rd_kafka_share_ack_batch_entry_t *entry;
        int i;
        RD_LIST_FOREACH(entry, &batches->entries, i) {
                if (offset >= entry->start_offset &&
                    offset <= entry->end_offset) {
                        int64_t idx = offset - entry->start_offset;
                        return entry->types[idx];
                }
        }

        return -99; /* Invalid marker */
}

/**
 * @brief Create a mock rd_kafka_message_t for testing.
 *
 * Uses a properly registered rd_kafka_topic_t to avoid issues with
 * rd_kafka_topic_name() when the acknowledge APIs are called.
 */
static rd_kafka_message_t *ut_ack_create_message(rd_kafka_topic_t *rkt,
                                                 int32_t partition,
                                                 int64_t offset) {
        rd_kafka_message_t *rkmessage = rd_calloc(1, sizeof(*rkmessage));
        rkmessage->rkt                = rkt;
        rkmessage->partition          = partition;
        rkmessage->offset             = offset;
        return rkmessage;
}

/**
 * @brief Destroy a mock rd_kafka_message_t.
 */
static void ut_ack_destroy_message(rd_kafka_message_t *rkmessage) {
        if (rkmessage)
                rd_free(rkmessage);
}

/**
 * @brief Test rd_kafka_share_acknowledge() - Basic ACCEPT acknowledgement.
 *
 * Verifies that rd_kafka_share_acknowledge() correctly updates an offset from
 * ACQUIRED to ACCEPT state, and that adjacent offsets remain unchanged.
 */
static int ut_case_acknowledge_accept(rd_kafka_share_t *rkshare,
                                      rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        /* Add partition with offsets 0-9 in ACQUIRED state */
        ut_ack_add_partition(rkshare, topic, 0, 0, 9);

        /* Create a mock message for offset 5 */
        rd_kafka_message_t *msg = ut_ack_create_message(rkt, 0, 5);

        /* Verify offset 5 is currently ACQUIRED */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
                     "offset 5 should be ACQUIRED before acknowledge");

        /* Call rd_kafka_share_acknowledge */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge(rkshare, msg);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "acknowledge failed: %s", rd_kafka_err2str(err));

        /* Verify offset 5 is now ACCEPT */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 5 should be ACCEPT after acknowledge");

        /* Verify other offsets are still ACQUIRED */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 4) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
                     "offset 4 should still be ACQUIRED");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 6) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
                     "offset 6 should still be ACQUIRED");

        ut_ack_destroy_message(msg);
        ut_ack_clear_inflight_map(rkshare);

        RD_UT_PASS();
}

/**
 * @brief Test rd_kafka_share_acknowledge_type() - Acknowledge with various
 * types.
 *
 * Tests that rd_kafka_share_acknowledge_type() correctly updates the offset
 * to the specified type (REJECT or RELEASE).
 */
static int ut_case_acknowledge_type_reject(rd_kafka_share_t *rkshare,
                                           rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition(rkshare, topic, 0, 0, 9);

        rd_kafka_message_t *msg = ut_ack_create_message(rkt, 0, 3);

        /* Acknowledge with REJECT */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_type(
            rkshare, msg, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "acknowledge_type REJECT failed: %s",
                     rd_kafka_err2str(err));

        /* Verify type changed to REJECT */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 3) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                     "offset 3 should be REJECT");

        ut_ack_destroy_message(msg);
        ut_ack_clear_inflight_map(rkshare);

        RD_UT_PASS();
}

/**
 * @brief Test rd_kafka_share_acknowledge_type() with RELEASE type.
 */
static int ut_case_acknowledge_type_release(rd_kafka_share_t *rkshare,
                                            rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition(rkshare, topic, 0, 0, 9);

        rd_kafka_message_t *msg = ut_ack_create_message(rkt, 0, 7);

        /* Acknowledge with RELEASE */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_type(
            rkshare, msg, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "acknowledge_type RELEASE failed: %s",
                     rd_kafka_err2str(err));

        /* Verify type changed to RELEASE */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 7) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                     "offset 7 should be RELEASE");

        ut_ack_destroy_message(msg);
        ut_ack_clear_inflight_map(rkshare);

        RD_UT_PASS();
}

/**
 * @brief Test re-acknowledgement with record-based APIs.
 *
 * Verifies that re-acknowledging a delivered record with record-based APIs
 * succeeds and updates the type. This is allowed before sending the
 * acknowledgement to the broker.
 */
static int ut_case_reacknowledge_delivered(rd_kafka_share_t *rkshare,
                                           rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition(rkshare, topic, 0, 0, 9);

        rd_kafka_message_t *msg = ut_ack_create_message(rkt, 0, 5);

        /* First acknowledge with ACCEPT */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_type(
            rkshare, msg, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "first acknowledge failed: %s", rd_kafka_err2str(err));
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 5 should be ACCEPT");

        /* Re-acknowledge with REJECT - should succeed  */
        err = rd_kafka_share_acknowledge_type(
            rkshare, msg, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "re-acknowledge should succeed, got %s",
                     rd_kafka_err2str(err));

        /* Verify type changed to REJECT */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                     "offset 5 should be REJECT after re-acknowledge");

        /* Re-acknowledge again with RELEASE */
        err = rd_kafka_share_acknowledge_type(
            rkshare, msg, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "second re-acknowledge should succeed");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                     "offset 5 should be RELEASE after second re-acknowledge");

        ut_ack_destroy_message(msg);
        ut_ack_clear_inflight_map(rkshare);

        RD_UT_PASS();
}

/**
 * @brief Test error case - GAP records cannot be acknowledged.
 *
 * Verifies that GAP records cannot be acknowledged by any API.
 */
static int ut_case_error_gap_record(rd_kafka_share_t *rkshare,
                                    rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition(rkshare, topic, 0, 0, 9);

        /* Set offset 5 as a GAP record */
        ut_ack_set_gap(rkshare, topic, 0, 5);

        rd_kafka_message_t *msg = ut_ack_create_message(rkt, 0, 5);

        /* Try to acknowledge GAP with record-based API - should fail */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge(rkshare, msg);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "expected STATE error for GAP record, got %s",
                     rd_kafka_err2str(err));

        /* Verify GAP record is unchanged */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_GAP,
                     "offset 5 should still be GAP");

        ut_ack_destroy_message(msg);
        ut_ack_clear_inflight_map(rkshare);

        RD_UT_PASS();
}

/**
 * @brief Test error case - Invalid parameters (NULL).
 *
 * Verifies that a NULL rkshare returns RD_KAFKA_RESP_ERR__STATE (rejected
 * by the reentrancy guard), and that NULL message or topic parameters
 * return RD_KAFKA_RESP_ERR__INVALID_ARG.
 */
static int ut_case_error_null_parameters(rd_kafka_share_t *rkshare,
                                         rd_kafka_topic_t *rkt) {
        rd_kafka_message_t *msg = ut_ack_create_message(rkt, 0, 5);

        /* Test NULL rkshare */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge(NULL, msg);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "expected STATE for NULL rkshare, got %s",
                     rd_kafka_err2str(err));

        /* Test NULL message */
        err = rd_kafka_share_acknowledge(rkshare, NULL);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                     "expected INVALID_ARG for NULL message, got %s",
                     rd_kafka_err2str(err));

        /* Test NULL topic in acknowledge_offset */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, NULL, 0, 5, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                     "expected INVALID_ARG for NULL topic, got %s",
                     rd_kafka_err2str(err));

        ut_ack_destroy_message(msg);

        RD_UT_PASS();
}

/**
 * @brief Test error case - Invalid acknowledgement type.
 *
 * Verifies that invalid acknowledgement types (e.g., GAP which is
 * internal-only, or arbitrary values like 99) return
 * RD_KAFKA_RESP_ERR__INVALID_ARG error. Also verifies the offset remains in
 * ACQUIRED state after the failed attempt.
 */
static int ut_case_error_invalid_type(rd_kafka_share_t *rkshare,
                                      rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition(rkshare, topic, 0, 0, 9);

        rd_kafka_message_t *msg = ut_ack_create_message(rkt, 0, 5);

        /* Test invalid type value (e.g., 99) */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_type(
            rkshare, msg, (rd_kafka_share_AcknowledgeType_t)99);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                     "expected INVALID_ARG for invalid type, got %s",
                     rd_kafka_err2str(err));

        /* Test type 0 (GAP - not allowed in public API) */
        err = rd_kafka_share_acknowledge_type(
            rkshare, msg, (rd_kafka_share_AcknowledgeType_t)0);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                     "expected INVALID_ARG for GAP type, got %s",
                     rd_kafka_err2str(err));

        /* Verify offset is still ACQUIRED (not modified) */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
                     "offset 5 should still be ACQUIRED after invalid type");

        ut_ack_destroy_message(msg);
        ut_ack_clear_inflight_map(rkshare);

        RD_UT_PASS();
}

/**
 * @brief Test multiple partitions with record-based APIs.
 *
 * Tests acknowledging delivered records across multiple topics and partitions
 * using record-based APIs. Verifies that each partition's acknowledgements
 * are tracked independently.
 */
static int ut_case_acknowledge_multiple_partitions(rd_kafka_share_t *rkshare,
                                                   rd_kafka_topic_t *rkt_t1,
                                                   rd_kafka_topic_t *rkt_t2) {
        const char *topic1 = rd_kafka_topic_name(rkt_t1);
        const char *topic2 = rd_kafka_topic_name(rkt_t2);

        /* Add multiple partitions with delivered records */
        ut_ack_add_partition(rkshare, topic1, 0, 0, 9);
        ut_ack_add_partition(rkshare, topic1, 1, 100, 109);
        ut_ack_add_partition(rkshare, topic2, 0, 50, 59);

        rd_kafka_message_t *msg1 = ut_ack_create_message(rkt_t1, 0, 5);
        rd_kafka_message_t *msg2 = ut_ack_create_message(rkt_t1, 1, 105);
        rd_kafka_message_t *msg3 = ut_ack_create_message(rkt_t2, 0, 55);

        rd_kafka_resp_err_t err;

        /* Acknowledge across partitions using record-based APIs */
        err = rd_kafka_share_acknowledge_type(
            rkshare, msg1, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "T1-0 offset 5 failed");

        err = rd_kafka_share_acknowledge_type(
            rkshare, msg2, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "T1-1 offset 105 failed");

        err = rd_kafka_share_acknowledge_type(
            rkshare, msg3, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "T2-0 offset 55 failed");

        /* Verify each partition independently */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic1, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "T1-0 offset 5 should be ACCEPT");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic1, 1, 105) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                     "T1-1 offset 105 should be REJECT");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic2, 0, 55) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                     "T2-0 offset 55 should be RELEASE");

        /* Verify other offsets unchanged */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic1, 0, 4) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
                     "T1-0 offset 4 should be ACQUIRED");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic1, 1, 104) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
                     "T1-1 offset 104 should be ACQUIRED");

        ut_ack_destroy_message(msg1);
        ut_ack_destroy_message(msg2);
        ut_ack_destroy_message(msg3);
        ut_ack_clear_inflight_map(rkshare);

        RD_UT_PASS();
}


/**
 * @brief Add a partition with multiple non-contiguous entries for binary search
 * tests.
 *
 * Creates entries at: [0-9], [100-109], [200-209], [500-509]
 * This tests binary search with gaps between entries.
 */
static void ut_ack_add_partition_multiple_entries(rd_kafka_share_t *rkshare,
                                                  const char *topic,
                                                  int32_t partition) {
        rd_kafka_topic_partition_private_t *parpriv;
        rd_kafka_share_ack_batches_t *batches = rd_calloc(1, sizeof(*batches));

        batches->rktpar = rd_kafka_topic_partition_new(topic, partition);
        parpriv         = rd_kafka_topic_partition_private_new();
        batches->rktpar->_private = parpriv;

        batches->response_leader_id              = 1;
        batches->response_acquired_offsets_count = 40;

        rd_list_init(&batches->entries, 4, NULL);

        /* Entry 1: offsets 0-9 */
        rd_kafka_share_ack_batch_entry_t *entry1 =
            rd_calloc(1, sizeof(*entry1));
        entry1->start_offset = 0;
        entry1->end_offset   = 9;
        entry1->size         = 10;
        entry1->types_cnt    = 10;
        entry1->types        = rd_calloc(10, sizeof(*entry1->types));
        for (int i = 0; i < 10; i++)
                entry1->types[i] = RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED;
        rd_list_add(&batches->entries, entry1);

        /* Entry 2: offsets 100-109 */
        rd_kafka_share_ack_batch_entry_t *entry2 =
            rd_calloc(1, sizeof(*entry2));
        entry2->start_offset = 100;
        entry2->end_offset   = 109;
        entry2->size         = 10;
        entry2->types_cnt    = 10;
        entry2->types        = rd_calloc(10, sizeof(*entry2->types));
        for (int i = 0; i < 10; i++)
                entry2->types[i] = RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED;
        rd_list_add(&batches->entries, entry2);

        /* Entry 3: offsets 200-209 */
        rd_kafka_share_ack_batch_entry_t *entry3 =
            rd_calloc(1, sizeof(*entry3));
        entry3->start_offset = 200;
        entry3->end_offset   = 209;
        entry3->size         = 10;
        entry3->types_cnt    = 10;
        entry3->types        = rd_calloc(10, sizeof(*entry3->types));
        for (int i = 0; i < 10; i++)
                entry3->types[i] = RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED;
        rd_list_add(&batches->entries, entry3);

        /* Entry 4: offsets 500-509 */
        rd_kafka_share_ack_batch_entry_t *entry4 =
            rd_calloc(1, sizeof(*entry4));
        entry4->start_offset = 500;
        entry4->end_offset   = 509;
        entry4->size         = 10;
        entry4->types_cnt    = 10;
        entry4->types        = rd_calloc(10, sizeof(*entry4->types));
        for (int i = 0; i < 10; i++)
                entry4->types[i] = RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED;
        rd_list_add(&batches->entries, entry4);

        /* Mark as sorted for binary search */
        batches->entries.rl_flags |= RD_LIST_F_SORTED;

        rd_kafka_topic_partition_t *key =
            rd_kafka_topic_partition_new(topic, partition);
        RD_MAP_SET(&rkshare->rkshare_inflight_acks, key, batches);

        /* Increment unacked count for all ACQUIRED offsets (4 entries × 10) */
        rkshare->rkshare_unacked_cnt += 40;
}

/**
 * @brief Test binary search - find offset in first entry.
 *
 * Tests that rd_list_find correctly finds offsets at the beginning of the list.
 */
static int ut_case_bsearch_first_entry(rd_kafka_share_t *rkshare,
                                       rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition_multiple_entries(rkshare, topic, 0);

        /* Acknowledge offset 5 in first entry [0-9] */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 5, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "first entry offset 5 failed: %s", rd_kafka_err2str(err));

        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 5) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 5 should be ACCEPT");

        /* Also test first offset of first entry */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 0, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "first entry offset 0 failed: %s", rd_kafka_err2str(err));

        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 0) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                     "offset 0 should be REJECT");

        ut_ack_clear_inflight_map(rkshare);
        RD_UT_PASS();
}

/**
 * @brief Test binary search - find offset in last entry.
 *
 * Tests that rd_list_find correctly finds offsets at the end of the list.
 */
static int ut_case_bsearch_last_entry(rd_kafka_share_t *rkshare,
                                      rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition_multiple_entries(rkshare, topic, 0);

        /* Acknowledge offset 505 in last entry [500-509] */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 505, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "last entry offset 505 failed: %s", rd_kafka_err2str(err));

        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 505) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 505 should be ACCEPT");

        /* Also test last offset of last entry */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 509, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "last entry offset 509 failed: %s", rd_kafka_err2str(err));

        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 509) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                     "offset 509 should be RELEASE");

        ut_ack_clear_inflight_map(rkshare);
        RD_UT_PASS();
}

/**
 * @brief Test binary search - find offset in middle entries.
 *
 * Tests that rd_list_find correctly finds offsets in middle entries.
 */
static int ut_case_bsearch_middle_entries(rd_kafka_share_t *rkshare,
                                          rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition_multiple_entries(rkshare, topic, 0);

        /* Acknowledge in second entry [100-109] */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 105, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "second entry offset 105 failed: %s",
                     rd_kafka_err2str(err));

        /* Acknowledge in third entry [200-209] */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 200, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "third entry offset 200 failed: %s",
                     rd_kafka_err2str(err));

        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 105) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 105 should be ACCEPT");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 200) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                     "offset 200 should be REJECT");

        ut_ack_clear_inflight_map(rkshare);
        RD_UT_PASS();
}

/**
 * @brief Test binary search - offset not found (before all entries).
 *
 * Tests that rd_list_find returns NULL for offsets before the first entry.
 * This is a special case where offset < first_entry->start_offset.
 *
 * Note: This test requires a setup where the first entry doesn't start at 0.
 */
static int ut_case_bsearch_not_found_before(rd_kafka_share_t *rkshare,
                                            rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        /* Add entries starting at offset 100 */
        ut_ack_add_partition(rkshare, topic, 0, 100, 109);

        /* Try to acknowledge offset 50 (before all entries) */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 50, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "expected STATE error for offset before entries, got %s",
                     rd_kafka_err2str(err));

        ut_ack_clear_inflight_map(rkshare);
        RD_UT_PASS();
}

/**
 * @brief Test binary search - offset not found (after all entries).
 *
 * Tests that rd_list_find returns NULL for offsets after the last entry.
 */
static int ut_case_bsearch_not_found_after(rd_kafka_share_t *rkshare,
                                           rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition_multiple_entries(rkshare, topic, 0);

        /* Try to acknowledge offset 600 (after last entry [500-509]) */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 600, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "expected STATE error for offset after entries, got %s",
                     rd_kafka_err2str(err));

        ut_ack_clear_inflight_map(rkshare);
        RD_UT_PASS();
}

/**
 * @brief Test binary search - offset not found (in gap between entries).
 *
 * Tests that rd_list_find returns NULL for offsets in gaps between entries.
 * Entries: [0-9], [100-109], [200-209], [500-509]
 * Gaps: 10-99, 110-199, 210-499
 */
static int ut_case_bsearch_not_found_gap(rd_kafka_share_t *rkshare,
                                         rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition_multiple_entries(rkshare, topic, 0);

        /* Try to acknowledge offset 50 (in gap between entry 1 and 2) */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 50, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "expected STATE error for offset 50 in gap, got %s",
                     rd_kafka_err2str(err));

        /* Try to acknowledge offset 150 (in gap between entry 2 and 3) */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 150, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "expected STATE error for offset 150 in gap, got %s",
                     rd_kafka_err2str(err));

        /* Try to acknowledge offset 300 (in gap between entry 3 and 4) */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 300, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "expected STATE error for offset 300 in gap, got %s",
                     rd_kafka_err2str(err));

        ut_ack_clear_inflight_map(rkshare);
        RD_UT_PASS();
}

/**
 * @brief Test binary search - empty entries list.
 *
 * Tests that rd_list_find handles an empty entries list gracefully.
 */
static int ut_case_bsearch_empty_entries(rd_kafka_share_t *rkshare,
                                         rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        /* Create a batches entry with empty entries list */
        rd_kafka_topic_partition_private_t *parpriv;
        rd_kafka_share_ack_batches_t *batches = rd_calloc(1, sizeof(*batches));

        batches->rktpar             = rd_kafka_topic_partition_new(topic, 0);
        parpriv                     = rd_kafka_topic_partition_private_new();
        batches->rktpar->_private   = parpriv;
        batches->response_leader_id = 1;
        batches->response_acquired_offsets_count = 0;

        rd_list_init(&batches->entries, 0, NULL);
        batches->entries.rl_flags |= RD_LIST_F_SORTED;

        rd_kafka_topic_partition_t *key =
            rd_kafka_topic_partition_new(topic, 0);
        RD_MAP_SET(&rkshare->rkshare_inflight_acks, key, batches);

        /* Try to acknowledge any offset */
        rd_kafka_resp_err_t err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 100, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "expected STATE error for empty entries, got %s",
                     rd_kafka_err2str(err));

        ut_ack_clear_inflight_map(rkshare);
        RD_UT_PASS();
}

/**
 * @brief Test binary search - boundary offsets of entries.
 *
 * Tests that rd_list_find correctly handles the exact start and end offsets
 * of each entry (boundary conditions).
 */
static int ut_case_bsearch_boundary_offsets(rd_kafka_share_t *rkshare,
                                            rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);

        ut_ack_add_partition_multiple_entries(rkshare, topic, 0);

        rd_kafka_resp_err_t err;

        /* Test boundary offsets for each entry */
        /* Entry 1: [0-9] - test 0 (start) and 9 (end) */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 0, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "offset 0 failed");

        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 9, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "offset 9 failed");

        /* Entry 2: [100-109] - test 100 (start) and 109 (end) */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 100, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "offset 100 failed");

        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 109, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "offset 109 failed");

        /* Entry 3: [200-209] - test 200 (start) and 209 (end) */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 200, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "offset 200 failed");

        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 209, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "offset 209 failed");

        /* Entry 4: [500-509] - test 500 (start) and 509 (end) */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 500, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "offset 500 failed");

        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 509, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "offset 509 failed");

        /* Verify all boundary offsets are ACCEPT */
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 0) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 0 type");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 9) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 9 type");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 100) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 100 type");
        RD_UT_ASSERT(ut_ack_get_type(rkshare, topic, 0, 109) ==
                         RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "offset 109 type");

        /* Test that offset 10 (just after entry 1) is not found */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 10, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "offset 10 should not be found, got %s",
                     rd_kafka_err2str(err));

        /* Test that offset 99 (just before entry 2) is not found */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 99, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "offset 99 should not be found, got %s",
                     rd_kafka_err2str(err));

        ut_ack_clear_inflight_map(rkshare);
        RD_UT_PASS();
}

/**
 * @brief Test unacked count tracking.
 *
 * Verifies that rkshare_unacked_cnt is properly:
 * - Incremented when ACQUIRED records are added
 * - Decremented when records are acknowledged
 * - Not decremented for GAP records or re-acknowledgements
 */
static int ut_case_unacked_count(rd_kafka_share_t *rkshare,
                                 rd_kafka_topic_t *rkt) {
        const char *topic = rd_kafka_topic_name(rkt);
        rd_kafka_resp_err_t err;

        /* Start with clean state */
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 0,
                     "initial unacked count should be 0, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        /* Add partition with 10 offsets (0-9) - all ACQUIRED */
        ut_ack_add_partition(rkshare, topic, 0, 0, 9);
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 10,
                     "unacked count after adding 10 offsets should be 10, "
                     "got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        /* Acknowledge offset 5 - should decrement count */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 5, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "acknowledge offset 5 failed: %s", rd_kafka_err2str(err));
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 9,
                     "unacked count after acking offset 5 should be 9, "
                     "got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        /* Re-acknowledge same offset - should NOT decrement (already acked) */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 5, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                     "re-acknowledge offset 5 failed: %s",
                     rd_kafka_err2str(err));
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 9,
                     "unacked count after re-acking should still be 9, "
                     "got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        /* Set offset 3 as GAP */
        ut_ack_set_gap(rkshare, topic, 0, 3);

        /* Try to acknowledge GAP - should fail and NOT change count */
        int64_t count_before = rkshare->rkshare_unacked_cnt;
        err                  = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 3, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                     "GAP acknowledge should fail");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == count_before,
                     "unacked count should not change for GAP, "
                     "expected %" PRId64 " got %" PRId64,
                     count_before, rkshare->rkshare_unacked_cnt);

        /* Acknowledge multiple offsets */
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 0, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "ack offset 0 failed");
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 1, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "ack offset 1 failed");
        err = rd_kafka_share_acknowledge_offset(
            rkshare, topic, 0, 2, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
        RD_UT_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "ack offset 2 failed");

        /* 9 - 3 = 6 remaining (offsets 4,6,7,8,9 are ACQUIRED, 3 is GAP) */
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 6,
                     "unacked count after acking 0,1,2 should be 6, "
                     "got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        ut_ack_clear_inflight_map(rkshare);

        /* After clear, count should be 0 */
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 0,
                     "unacked count after clear should be 0, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        RD_UT_PASS();
}


/**
 * @brief Main entry point for Share Consumer acknowledge API unit tests.
 */
int unittest_share_acknowledge(void) {
        rd_kafka_share_t *rkshare;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt_t1, *rkt_t2;

        RD_UT_SAY("===============================================");
        RD_UT_SAY("Share Consumer Acknowledge API Unit Tests");
        RD_UT_SAY("===============================================");

        rkshare = ut_ack_create_share_consumer();
        RD_UT_ASSERT(rkshare != NULL, "Failed to create rd_kafka_share_t");

        rk = rkshare->rkshare_rk;

        /* Register topics T1 and T2 upfront for all tests that need them.
         * These will be destroyed at the end of the test suite. */
        rkt_t1 = ut_ack_register_topic(rk, "T1", ut_topic_id_t1);
        RD_UT_ASSERT(rkt_t1 != NULL, "Failed to register topic T1");
        rkt_t2 = ut_ack_register_topic(rk, "T2", ut_topic_id_t2);
        RD_UT_ASSERT(rkt_t2 != NULL, "Failed to register topic T2");

/* Macro for test cleanup on failure */
#define UT_ACK_CLEANUP_AND_FAIL()                                              \
        do {                                                                   \
                rd_kafka_topic_destroy(rkt_t1);                                \
                rd_kafka_topic_destroy(rkt_t2);                                \
                rd_kafka_share_consumer_close(rkshare);                        \
                rd_kafka_share_destroy(rkshare);                               \
                return 1;                                                      \
        } while (0)

        /* Record-based API tests (delivered records) */
        RD_UT_SAY("Testing rd_kafka_share_acknowledge() (ACCEPT)...");
        if (ut_case_acknowledge_accept(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing rd_kafka_share_acknowledge_type() (REJECT)...");
        if (ut_case_acknowledge_type_reject(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing rd_kafka_share_acknowledge_type() (RELEASE)...");
        if (ut_case_acknowledge_type_release(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        /* Re-acknowledgement tests */
        RD_UT_SAY("Testing re-acknowledgement of delivered records...");
        if (ut_case_reacknowledge_delivered(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        /* Error case tests */
        RD_UT_SAY("Testing error: GAP records cannot be acknowledged...");
        if (ut_case_error_gap_record(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing error: NULL parameters...");
        if (ut_case_error_null_parameters(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing error: invalid type...");
        if (ut_case_error_invalid_type(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        /* Multi-partition test */
        RD_UT_SAY("Testing multiple partitions...");
        if (ut_case_acknowledge_multiple_partitions(rkshare, rkt_t1, rkt_t2))
                UT_ACK_CLEANUP_AND_FAIL();

        /* Binary search tests (multiple entries) */
        RD_UT_SAY("Testing binary search: first entry...");
        if (ut_case_bsearch_first_entry(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing binary search: last entry...");
        if (ut_case_bsearch_last_entry(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing binary search: middle entries...");
        if (ut_case_bsearch_middle_entries(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing binary search: offset before all entries...");
        if (ut_case_bsearch_not_found_before(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing binary search: offset after all entries...");
        if (ut_case_bsearch_not_found_after(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing binary search: offset in gap between entries...");
        if (ut_case_bsearch_not_found_gap(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing binary search: empty entries list...");
        if (ut_case_bsearch_empty_entries(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        RD_UT_SAY("Testing binary search: boundary offsets...");
        if (ut_case_bsearch_boundary_offsets(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

        /* Unacked count tracking test */
        RD_UT_SAY("Testing unacked count tracking...");
        if (ut_case_unacked_count(rkshare, rkt_t1))
                UT_ACK_CLEANUP_AND_FAIL();

#undef UT_ACK_CLEANUP_AND_FAIL

        rd_kafka_topic_destroy(rkt_t1);
        rd_kafka_topic_destroy(rkt_t2);
        rd_kafka_share_consumer_close(rkshare);
        rd_kafka_share_destroy(rkshare);
        RD_UT_PASS();
}
