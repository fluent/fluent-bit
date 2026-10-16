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
 * @name Unit tests for Share Consumer acknowledgement flow
 * @{
 *
 * Tests cover:
 *   - rd_kafka_share_filter_acquired_records_and_update_ack_type()
 *   - rd_kafka_share_build_ack_details()
 *   - rd_kafka_share_build_inflight_acks_map()
 */

#include "rd.h"
#include "rdunittest.h"
#include "rdkafka_int.h"
#include "rdkafka_queue.h"
#include "rdkafka_fetcher.h"
#include "rdkafka_partition.h"
#include "rdkafka_share_acknowledgement.h"


/**
 * @name Test helpers
 * @{
 */

static rd_kafka_t *ut_mock_rk;

static rd_kafka_share_t *ut_create_mock_rkshare(void) {
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        char errstr[128];

        if (rd_kafka_conf_set(conf, "group.id", "ut-share-ack", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                rd_kafka_conf_destroy(conf);
                return NULL;
        }

        rd_kafka_share_t *rkshare =
            rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));

        return rkshare;
}

static void ut_destroy_mock_rkshare(rd_kafka_share_t *rkshare) {
        if (!rkshare)
                return;
        rd_kafka_share_consumer_close(rkshare);
        rd_kafka_share_destroy(rkshare);
}

static rd_kafka_topic_partition_t *
ut_create_rktpar_with_id(const char *topic,
                         int32_t partition,
                         rd_kafka_Uuid_t topic_id) {
        return rd_kafka_topic_partition_new_with_id_and_name(topic_id, topic,
                                                             partition);
}

static void ut_add_batches_to_map(rd_kafka_share_t *rkshare,
                                  rd_kafka_share_ack_batches_t *batches) {
        rd_kafka_topic_partition_t *key = rd_kafka_topic_partition_new(
            batches->rktpar->topic, batches->rktpar->partition);
        /* Mark entries as sorted */
        batches->entries.rl_flags |= RD_LIST_F_SORTED;
        RD_MAP_SET(&rkshare->rkshare_inflight_acks, key, batches);
}

static rd_kafka_q_t *ut_create_mock_queue(void) {
        rd_kafka_q_t *rkq = rd_calloc(1, sizeof(*rkq));
        rd_kafka_q_init(rkq, NULL);
        rkq->rkq_flags |= RD_KAFKA_Q_F_ALLOCATED;
        return rkq;
}

static void ut_destroy_mock_queue(rd_kafka_q_t *rkq) {
        if (!rkq)
                return;
        rd_kafka_q_destroy_owner(rkq);
}

static rd_kafka_op_t *ut_create_fetch_op_with_offset(int64_t offset) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_FETCH);
        rko->rko_u.fetch.rkm.rkm_rkmessage.offset = offset;
        return rko;
}

static void ut_op_destroy_free(void *ptr) {
        rd_kafka_op_destroy((rd_kafka_op_t *)ptr);
}

static rd_kafka_op_t *ut_create_share_fetch_response_rko(void) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_SHARE_FETCH_RESPONSE);
        rko->rko_u.share_fetch_response.inflight_acks = rd_list_new(0, NULL);
        rko->rko_u.share_fetch_response.message_rkos  = rd_list_new(0, NULL);
        return rko;
}

/**
 * @brief Set all entry types to a single uniform value.
 */
static void
ut_set_types_uniform(rd_kafka_share_ack_batch_entry_t *entry,
                     rd_kafka_share_internal_acknowledgement_type t) {
        int i;
        for (i = 0; i < entry->types_cnt; i++)
                entry->types[i] = t;
}

/**
 * @brief Set entry types from an array.
 */
static void
ut_set_types(rd_kafka_share_ack_batch_entry_t *entry,
             const rd_kafka_share_internal_acknowledgement_type *types,
             int cnt) {
        int i;
        for (i = 0; i < cnt; i++)
                entry->types[i] = types[i];
}

/**@}*/


/**
 * @name Tests for rd_kafka_share_filter_acquired_records_and_update_ack_type()
 * @{
 */

/** @brief All messages in contiguous range are acquired with ACQUIRED type. */
static int unittest_filter_all_acquired(void) {
        rd_kafka_q_t *temp_fetchq = ut_create_mock_queue();
        rd_list_t filtered_msgs;
        int64_t FirstOffsets[1]   = {0};
        int64_t LastOffsets[1]    = {4};
        int16_t DeliveryCounts[1] = {1};
        int i;

        rd_list_init(&filtered_msgs, 0, ut_op_destroy_free);

        for (i = 0; i < 5; i++) {
                rd_kafka_op_t *rko = ut_create_fetch_op_with_offset(i);
                rd_kafka_q_enq(temp_fetchq, rko);
        }

        rd_kafka_share_filter_acquired_records_and_update_ack_type(
            temp_fetchq, &filtered_msgs, FirstOffsets, LastOffsets,
            DeliveryCounts, 1);

        RD_UT_ASSERT(rd_list_cnt(&filtered_msgs) == 5,
                     "Expected 5 messages, got %d",
                     rd_list_cnt(&filtered_msgs));

        for (i = 0; i < 5; i++) {
                rd_kafka_op_t *rko  = rd_list_elem(&filtered_msgs, i);
                rd_kafka_msg_t *rkm = &rko->rko_u.fetch.rkm;
                RD_UT_ASSERT(rkm->rkm_u.consumer.ack_type ==
                                 RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
                             "Message %d: expected ACQUIRED ack_type", i);
                RD_UT_ASSERT(rkm->rkm_u.consumer.delivery_count == 1,
                             "Message %d: expected delivery_count=1, got %d", i,
                             rkm->rkm_u.consumer.delivery_count);
        }

        rd_list_destroy(&filtered_msgs);
        ut_destroy_mock_queue(temp_fetchq);

        RD_UT_PASS();
}

/** @brief Only messages within acquired range pass; others filtered out. */
static int unittest_filter_partial_range(void) {
        rd_kafka_q_t *temp_fetchq = ut_create_mock_queue();
        rd_list_t filtered_msgs;
        int64_t FirstOffsets[1]   = {2};
        int64_t LastOffsets[1]    = {5};
        int16_t DeliveryCounts[1] = {1};
        int i;

        rd_list_init(&filtered_msgs, 0, ut_op_destroy_free);

        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = ut_create_fetch_op_with_offset(i);
                rd_kafka_q_enq(temp_fetchq, rko);
        }

        rd_kafka_share_filter_acquired_records_and_update_ack_type(
            temp_fetchq, &filtered_msgs, FirstOffsets, LastOffsets,
            DeliveryCounts, 1);

        RD_UT_ASSERT(rd_list_cnt(&filtered_msgs) == 4,
                     "Expected 4 messages, got %d",
                     rd_list_cnt(&filtered_msgs));

        for (i = 0; i < 4; i++) {
                rd_kafka_op_t *rko = rd_list_elem(&filtered_msgs, i);
                int64_t offset     = rd_kafka_op_get_offset(rko);
                RD_UT_ASSERT(offset == 2 + i,
                             "Message %d: expected offset %d, got %" PRId64, i,
                             2 + i, offset);
        }

        rd_list_destroy(&filtered_msgs);
        ut_destroy_mock_queue(temp_fetchq);

        RD_UT_PASS();
}

/** @brief Multiple disjoint acquired ranges filter correct messages. */
static int unittest_filter_disjoint_ranges(void) {
        rd_kafka_q_t *temp_fetchq = ut_create_mock_queue();
        rd_list_t filtered_msgs;
        int64_t FirstOffsets[3]   = {1, 5, 9};
        int64_t LastOffsets[3]    = {2, 6, 9};
        int16_t DeliveryCounts[3] = {1, 2, 3};
        int i;
        int64_t expected_offsets[] = {1, 2, 5, 6, 9};

        rd_list_init(&filtered_msgs, 0, ut_op_destroy_free);

        for (i = 0; i < 10; i++) {
                rd_kafka_op_t *rko = ut_create_fetch_op_with_offset(i);
                rd_kafka_q_enq(temp_fetchq, rko);
        }

        rd_kafka_share_filter_acquired_records_and_update_ack_type(
            temp_fetchq, &filtered_msgs, FirstOffsets, LastOffsets,
            DeliveryCounts, 3);

        RD_UT_ASSERT(rd_list_cnt(&filtered_msgs) == 5,
                     "Expected 5 messages, got %d",
                     rd_list_cnt(&filtered_msgs));

        for (i = 0; i < 5; i++) {
                rd_kafka_op_t *rko = rd_list_elem(&filtered_msgs, i);
                int64_t offset     = rd_kafka_op_get_offset(rko);
                RD_UT_ASSERT(offset == expected_offsets[i],
                             "Message %d: expected offset %" PRId64
                             ", got %" PRId64,
                             i, expected_offsets[i], offset);
        }

        rd_list_destroy(&filtered_msgs);
        ut_destroy_mock_queue(temp_fetchq);

        RD_UT_PASS();
}

/** @brief Empty queue returns no messages. */
static int unittest_filter_empty_queue(void) {
        rd_kafka_q_t *temp_fetchq = ut_create_mock_queue();
        rd_list_t filtered_msgs;
        int64_t FirstOffsets[1]   = {0};
        int64_t LastOffsets[1]    = {10};
        int16_t DeliveryCounts[1] = {1};

        rd_list_init(&filtered_msgs, 0, ut_op_destroy_free);

        rd_kafka_share_filter_acquired_records_and_update_ack_type(
            temp_fetchq, &filtered_msgs, FirstOffsets, LastOffsets,
            DeliveryCounts, 1);

        RD_UT_ASSERT(rd_list_cnt(&filtered_msgs) == 0,
                     "Expected 0 messages, got %d",
                     rd_list_cnt(&filtered_msgs));

        rd_list_destroy(&filtered_msgs);
        ut_destroy_mock_queue(temp_fetchq);

        RD_UT_PASS();
}

/** @brief No acquired ranges means all messages filtered out. */
static int unittest_filter_no_ranges(void) {
        rd_kafka_q_t *temp_fetchq = ut_create_mock_queue();
        rd_list_t filtered_msgs;
        int i;

        rd_list_init(&filtered_msgs, 0, ut_op_destroy_free);

        for (i = 0; i < 5; i++) {
                rd_kafka_op_t *rko = ut_create_fetch_op_with_offset(i);
                rd_kafka_q_enq(temp_fetchq, rko);
        }

        rd_kafka_share_filter_acquired_records_and_update_ack_type(
            temp_fetchq, &filtered_msgs, NULL, NULL, NULL, 0);

        RD_UT_ASSERT(rd_list_cnt(&filtered_msgs) == 0,
                     "Expected 0 messages, got %d",
                     rd_list_cnt(&filtered_msgs));

        rd_list_destroy(&filtered_msgs);
        ut_destroy_mock_queue(temp_fetchq);

        RD_UT_PASS();
}

/** @brief Non-sequential offsets in queue; only matching ones pass. */
static int unittest_filter_sparse_offsets(void) {
        rd_kafka_q_t *temp_fetchq = ut_create_mock_queue();
        rd_list_t filtered_msgs;
        int64_t FirstOffsets[1]   = {5};
        int64_t LastOffsets[1]    = {25};
        int16_t DeliveryCounts[1] = {1};
        int64_t sparse_offsets[]  = {0, 10, 20, 30};
        int i;
        int64_t expected_offsets[] = {10, 20};

        rd_list_init(&filtered_msgs, 0, ut_op_destroy_free);

        for (i = 0; i < 4; i++) {
                rd_kafka_op_t *rko =
                    ut_create_fetch_op_with_offset(sparse_offsets[i]);
                rd_kafka_q_enq(temp_fetchq, rko);
        }

        rd_kafka_share_filter_acquired_records_and_update_ack_type(
            temp_fetchq, &filtered_msgs, FirstOffsets, LastOffsets,
            DeliveryCounts, 1);

        RD_UT_ASSERT(rd_list_cnt(&filtered_msgs) == 2,
                     "Expected 2 messages, got %d",
                     rd_list_cnt(&filtered_msgs));

        for (i = 0; i < 2; i++) {
                rd_kafka_op_t *rko = rd_list_elem(&filtered_msgs, i);
                int64_t offset     = rd_kafka_op_get_offset(rko);
                RD_UT_ASSERT(offset == expected_offsets[i],
                             "Message %d: expected offset %" PRId64
                             ", got %" PRId64,
                             i, expected_offsets[i], offset);
        }

        rd_list_destroy(&filtered_msgs);
        ut_destroy_mock_queue(temp_fetchq);

        RD_UT_PASS();
}

/** @brief Acquired range beyond all queue messages returns empty. */
static int unittest_filter_range_beyond_messages(void) {
        rd_kafka_q_t *temp_fetchq = ut_create_mock_queue();
        rd_list_t filtered_msgs;
        int64_t FirstOffsets[1]   = {100};
        int64_t LastOffsets[1]    = {200};
        int16_t DeliveryCounts[1] = {1};
        int i;

        rd_list_init(&filtered_msgs, 0, ut_op_destroy_free);

        for (i = 0; i < 5; i++) {
                rd_kafka_op_t *rko = ut_create_fetch_op_with_offset(i);
                rd_kafka_q_enq(temp_fetchq, rko);
        }

        rd_kafka_share_filter_acquired_records_and_update_ack_type(
            temp_fetchq, &filtered_msgs, FirstOffsets, LastOffsets,
            DeliveryCounts, 1);

        RD_UT_ASSERT(rd_list_cnt(&filtered_msgs) == 0,
                     "Expected 0 messages, got %d",
                     rd_list_cnt(&filtered_msgs));

        rd_list_destroy(&filtered_msgs);
        ut_destroy_mock_queue(temp_fetchq);

        RD_UT_PASS();
}

/**@}*/


/**
 * @name Tests for rd_kafka_share_build_ack_details()
 * @{
 */

/** @brief All ACCEPT types extracted as single collated entry. */
static int unittest_ack_details_all_accept(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id  = rd_kafka_Uuid_random();
        rd_list_t *ack_details;
        rd_kafka_share_ack_batches_t *out_batch;
        rd_kafka_share_ack_batch_entry_t *out_entry;

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 5);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 104, 5, 1);
        ut_set_types_uniform(entry, RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT);
        rd_list_add(&batches->entries, entry);

        ut_add_batches_to_map(rkshare, batches);

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details != NULL, "Expected non-NULL ack_details");
        RD_UT_ASSERT(rd_list_cnt(ack_details) == 1, "Expected 1 batch, got %d",
                     rd_list_cnt(ack_details));

        out_batch = rd_list_elem(ack_details, 0);
        RD_UT_ASSERT(rd_list_cnt(&out_batch->entries) == 1,
                     "Expected 1 collated entry, got %d",
                     rd_list_cnt(&out_batch->entries));

        out_entry = rd_list_elem(&out_batch->entries, 0);
        RD_UT_ASSERT(out_entry->start_offset == 100,
                     "Expected start=100, got %" PRId64,
                     out_entry->start_offset);
        RD_UT_ASSERT(out_entry->end_offset == 104,
                     "Expected end=104, got %" PRId64, out_entry->end_offset);
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "Expected ACCEPT type");

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 0,
                     "Expected empty map");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 0,
                     "Expected unacked_cnt=0, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_list_destroy(ack_details);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief All ACQUIRED types returns NULL (nothing to extract). */
static int unittest_ack_details_all_acquired(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id  = rd_kafka_Uuid_random();
        rd_list_t *ack_details;

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 5);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 104, 5, 1);
        ut_set_types_uniform(entry, RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED);
        rd_list_add(&batches->entries, entry);

        ut_add_batches_to_map(rkshare, batches);
        rkshare->rkshare_unacked_cnt = 5;

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details == NULL, "Expected NULL ack_details");
        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 1,
                     "Expected map to still have 1 entry");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 5,
                     "Expected unacked_cnt=5, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Mixed types collated; ACQUIRED offsets remain in map. */
static int unittest_ack_details_mixed_collation(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id  = rd_kafka_Uuid_random();
        rd_list_t *ack_details;
        rd_kafka_share_ack_batches_t *out_batch;
        rd_kafka_share_ack_batch_entry_t *out_entry;
        const rd_kafka_share_internal_acknowledgement_type types[] = {
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
            RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT};

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 10);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 109, 10, 1);
        ut_set_types(entry, types, 10);
        rd_list_add(&batches->entries, entry);

        ut_add_batches_to_map(rkshare, batches);

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details != NULL, "Expected non-NULL ack_details");
        RD_UT_ASSERT(rd_list_cnt(ack_details) == 1, "Expected 1 batch");

        out_batch = rd_list_elem(ack_details, 0);
        RD_UT_ASSERT(rd_list_cnt(&out_batch->entries) == 4,
                     "Expected 4 collated entries, got %d",
                     rd_list_cnt(&out_batch->entries));

        out_entry = rd_list_elem(&out_batch->entries, 0);
        RD_UT_ASSERT(out_entry->start_offset == 100 &&
                         out_entry->end_offset == 101,
                     "Entry 0: expected 100-101");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "Entry 0: expected ACCEPT");

        out_entry = rd_list_elem(&out_batch->entries, 1);
        RD_UT_ASSERT(out_entry->start_offset == 102 &&
                         out_entry->end_offset == 104,
                     "Entry 1: expected 102-104");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                     "Entry 1: expected REJECT");

        out_entry = rd_list_elem(&out_batch->entries, 2);
        RD_UT_ASSERT(out_entry->start_offset == 107 &&
                         out_entry->end_offset == 108,
                     "Entry 2: expected 107-108");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                     "Entry 2: expected RELEASE");

        out_entry = rd_list_elem(&out_batch->entries, 3);
        RD_UT_ASSERT(out_entry->start_offset == 109 &&
                         out_entry->end_offset == 109,
                     "Entry 3: expected 109-109");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "Entry 3: expected ACCEPT");

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 1,
                     "Expected 1 entry remaining in map");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 2,
                     "Expected unacked_cnt=2, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_list_destroy(ack_details);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Alternating types produce separate entries (no collation). */
static int unittest_ack_details_alternating(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id  = rd_kafka_Uuid_random();
        rd_list_t *ack_details;
        rd_kafka_share_ack_batches_t *out_batch;
        const rd_kafka_share_internal_acknowledgement_type types[] = {
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT};

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 5);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 104, 5, 1);
        ut_set_types(entry, types, 5);
        rd_list_add(&batches->entries, entry);

        ut_add_batches_to_map(rkshare, batches);

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details != NULL, "Expected non-NULL ack_details");
        out_batch = rd_list_elem(ack_details, 0);
        RD_UT_ASSERT(rd_list_cnt(&out_batch->entries) == 5,
                     "Expected 5 collated entries, got %d",
                     rd_list_cnt(&out_batch->entries));

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 0,
                     "Expected empty map");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 0,
                     "Expected unacked_cnt=0");

        rd_list_destroy(ack_details);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Multiple partitions with mixed states processed independently. */
static int unittest_ack_details_multi_partition(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id0 = rd_kafka_Uuid_random();
        rd_kafka_Uuid_t topic_id1 = rd_kafka_Uuid_random();
        rd_list_t *ack_details;
        const rd_kafka_share_internal_acknowledgement_type types1[] = {
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT};

        rd_kafka_topic_partition_t *rktpar0 =
            ut_create_rktpar_with_id("test-topic", 0, topic_id0);
        rd_kafka_share_ack_batches_t *batches0 =
            rd_kafka_share_ack_batches_new(rktpar0, 1, 3);
        rd_kafka_share_ack_batch_entry_t *entry0 =
            rd_kafka_share_ack_batch_entry_new(100, 102, 3, 1);
        ut_set_types_uniform(entry0, RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT);
        rd_list_add(&batches0->entries, entry0);
        ut_add_batches_to_map(rkshare, batches0);

        rd_kafka_topic_partition_t *rktpar1 =
            ut_create_rktpar_with_id("test-topic", 1, topic_id1);
        rd_kafka_share_ack_batches_t *batches1 =
            rd_kafka_share_ack_batches_new(rktpar1, 2, 5);
        rd_kafka_share_ack_batch_entry_t *entry1 =
            rd_kafka_share_ack_batch_entry_new(200, 204, 5, 2);
        ut_set_types(entry1, types1, 5);
        rd_list_add(&batches1->entries, entry1);
        ut_add_batches_to_map(rkshare, batches1);

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details != NULL, "Expected non-NULL ack_details");
        RD_UT_ASSERT(rd_list_cnt(ack_details) == 2,
                     "Expected 2 batches, got %d", rd_list_cnt(ack_details));

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 1,
                     "Expected 1 entry in map (partition 1)");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 2,
                     "Expected unacked_cnt=2, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_list_destroy(ack_details);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Empty inflight map returns NULL. */
static int unittest_ack_details_empty_map(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_list_t *ack_details;

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details == NULL, "Expected NULL for empty map");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 0,
                     "Expected unacked_cnt=0");

        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Leader metadata and delivery_count preserved in output. */
static int unittest_ack_details_metadata(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id  = rd_kafka_Uuid_random();
        rd_list_t *ack_details;
        rd_kafka_share_ack_batches_t *out_batch;
        rd_kafka_share_ack_batch_entry_t *out_entry;

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 5, 2);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 101, 2, 3);
        ut_set_types_uniform(entry, RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT);
        rd_list_add(&batches->entries, entry);

        ut_add_batches_to_map(rkshare, batches);

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details != NULL, "Expected non-NULL ack_details");
        out_batch = rd_list_elem(ack_details, 0);
        RD_UT_ASSERT(out_batch->response_leader_id == 5,
                     "Expected leader_id=5, got %d",
                     out_batch->response_leader_id);

        out_entry = rd_list_elem(&out_batch->entries, 0);
        RD_UT_ASSERT(out_entry->delivery_count == 3,
                     "Expected delivery_count=3, got %d",
                     out_entry->delivery_count);

        rd_list_destroy(ack_details);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief GAPs extracted while ACQUIRED offsets remain in map. */
static int unittest_ack_details_gap_acquired(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id  = rd_kafka_Uuid_random();
        rd_list_t *ack_details;
        rd_kafka_share_ack_batches_t *out_batch;
        const rd_kafka_share_internal_acknowledgement_type types[] = {
            RD_KAFKA_SHARE_INTERNAL_ACK_GAP,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_GAP,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_GAP};

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 5);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 104, 5, 1);
        ut_set_types(entry, types, 5);
        rd_list_add(&batches->entries, entry);

        ut_add_batches_to_map(rkshare, batches);
        rkshare->rkshare_unacked_cnt = 2;

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details != NULL, "Expected non-NULL ack_details");
        RD_UT_ASSERT(rd_list_cnt(ack_details) == 1, "Expected 1 batch");

        out_batch = rd_list_elem(ack_details, 0);
        RD_UT_ASSERT(rd_list_cnt(&out_batch->entries) == 3,
                     "Expected 3 GAP entries, got %d",
                     rd_list_cnt(&out_batch->entries));

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 1,
                     "Expected 1 entry remaining in map");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 2,
                     "Expected unacked_cnt=2, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_list_destroy(ack_details);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Multiple batch entries in same partition processed independently. */
static int unittest_ack_details_multi_entry(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id  = rd_kafka_Uuid_random();
        rd_list_t *ack_details;
        rd_kafka_share_ack_batches_t *out_batch;
        rd_kafka_share_ack_batch_entry_t *out_entry;

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 6);

        rd_kafka_share_ack_batch_entry_t *entry1 =
            rd_kafka_share_ack_batch_entry_new(100, 102, 3, 1);
        ut_set_types_uniform(entry1, RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT);
        rd_list_add(&batches->entries, entry1);

        rd_kafka_share_ack_batch_entry_t *entry2 =
            rd_kafka_share_ack_batch_entry_new(200, 202, 3, 2);
        ut_set_types_uniform(entry2, RD_KAFKA_SHARE_INTERNAL_ACK_REJECT);
        rd_list_add(&batches->entries, entry2);

        ut_add_batches_to_map(rkshare, batches);

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details != NULL, "Expected non-NULL ack_details");
        RD_UT_ASSERT(rd_list_cnt(ack_details) == 1, "Expected 1 batch");

        out_batch = rd_list_elem(ack_details, 0);
        RD_UT_ASSERT(rd_list_cnt(&out_batch->entries) == 2,
                     "Expected 2 collated entries, got %d",
                     rd_list_cnt(&out_batch->entries));

        out_entry = rd_list_elem(&out_batch->entries, 0);
        RD_UT_ASSERT(out_entry->start_offset == 100 &&
                         out_entry->end_offset == 102,
                     "Entry 0: expected 100-102");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "Entry 0: expected ACCEPT");

        out_entry = rd_list_elem(&out_batch->entries, 1);
        RD_UT_ASSERT(out_entry->start_offset == 200 &&
                         out_entry->end_offset == 202,
                     "Entry 1: expected 200-202");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                     "Entry 1: expected REJECT");

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 0,
                     "Expected empty map");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 0,
                     "Expected unacked_cnt=0");

        rd_list_destroy(ack_details);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Interleaved ACQUIRED breaks extractable ranges into segments. */
static int unittest_ack_details_interleaved(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id  = rd_kafka_Uuid_random();
        rd_list_t *ack_details;
        rd_kafka_share_ack_batches_t *out_batch;
        rd_kafka_share_ack_batch_entry_t *out_entry;
        const rd_kafka_share_internal_acknowledgement_type types[] = {
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
            RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT};

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 10);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 109, 10, 1);
        ut_set_types(entry, types, 10);
        rd_list_add(&batches->entries, entry);

        ut_add_batches_to_map(rkshare, batches);

        ack_details = rd_kafka_share_build_ack_details(rkshare);

        RD_UT_ASSERT(ack_details != NULL, "Expected non-NULL ack_details");
        out_batch = rd_list_elem(ack_details, 0);
        RD_UT_ASSERT(rd_list_cnt(&out_batch->entries) == 4,
                     "Expected 4 collated entries, got %d",
                     rd_list_cnt(&out_batch->entries));

        out_entry = rd_list_elem(&out_batch->entries, 0);
        RD_UT_ASSERT(out_entry->start_offset == 100 &&
                         out_entry->end_offset == 100,
                     "Entry 0: expected 100-100, got %" PRId64 "-%" PRId64,
                     out_entry->start_offset, out_entry->end_offset);
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "Entry 0: expected ACCEPT");

        out_entry = rd_list_elem(&out_batch->entries, 1);
        RD_UT_ASSERT(out_entry->start_offset == 102 &&
                         out_entry->end_offset == 103,
                     "Entry 1: expected 102-103");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_REJECT,
                     "Entry 1: expected REJECT");

        out_entry = rd_list_elem(&out_batch->entries, 2);
        RD_UT_ASSERT(out_entry->start_offset == 105 &&
                         out_entry->end_offset == 106,
                     "Entry 2: expected 105-106");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE,
                     "Entry 2: expected RELEASE");

        out_entry = rd_list_elem(&out_batch->entries, 3);
        RD_UT_ASSERT(out_entry->start_offset == 108 &&
                         out_entry->end_offset == 109,
                     "Entry 3: expected 108-109");
        RD_UT_ASSERT(out_entry->types[0] == RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT,
                     "Entry 3: expected ACCEPT");

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 1,
                     "Expected 1 entry remaining in map");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 3,
                     "Expected unacked_cnt=3, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_list_destroy(ack_details);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/**@}*/


/**
 * @name Tests for rd_kafka_share_build_inflight_acks_map()
 * @{
 */

/** @brief Single partition with all ACQUIRED mapped correctly. */
static int unittest_ack_mapping_single_partition(void) {
        rd_kafka_share_t *rkshare   = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id    = rd_kafka_Uuid_random();
        rd_kafka_op_t *response_rko = ut_create_share_fetch_response_rko();

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 5);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 104, 5, 1);
        ut_set_types_uniform(entry, RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED);
        rd_list_add(&batches->entries, entry);

        rd_list_add(response_rko->rko_u.share_fetch_response.inflight_acks,
                    batches);

        rd_kafka_share_build_inflight_acks_map(rkshare, response_rko);

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 1,
                     "Expected 1 map entry, got %d",
                     (int)RD_MAP_CNT(&rkshare->rkshare_inflight_acks));

        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 5,
                     "Expected unacked_cnt=5, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_kafka_op_destroy(response_rko);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Multiple partitions create separate map entries. */
static int unittest_ack_mapping_multi_partition(void) {
        rd_kafka_share_t *rkshare   = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id0   = rd_kafka_Uuid_random();
        rd_kafka_Uuid_t topic_id1   = rd_kafka_Uuid_random();
        rd_kafka_op_t *response_rko = ut_create_share_fetch_response_rko();

        rd_kafka_topic_partition_t *rktpar0 =
            ut_create_rktpar_with_id("test-topic", 0, topic_id0);
        rd_kafka_share_ack_batches_t *batches0 =
            rd_kafka_share_ack_batches_new(rktpar0, 1, 3);
        rd_kafka_share_ack_batch_entry_t *entry0 =
            rd_kafka_share_ack_batch_entry_new(100, 102, 3, 1);
        ut_set_types_uniform(entry0, RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED);
        rd_list_add(&batches0->entries, entry0);
        rd_list_add(response_rko->rko_u.share_fetch_response.inflight_acks,
                    batches0);

        rd_kafka_topic_partition_t *rktpar1 =
            ut_create_rktpar_with_id("test-topic", 1, topic_id1);
        rd_kafka_share_ack_batches_t *batches1 =
            rd_kafka_share_ack_batches_new(rktpar1, 2, 2);
        rd_kafka_share_ack_batch_entry_t *entry1 =
            rd_kafka_share_ack_batch_entry_new(200, 201, 2, 1);
        ut_set_types_uniform(entry1, RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED);
        rd_list_add(&batches1->entries, entry1);
        rd_list_add(response_rko->rko_u.share_fetch_response.inflight_acks,
                    batches1);

        rd_kafka_share_build_inflight_acks_map(rkshare, response_rko);

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 2,
                     "Expected 2 map entries, got %d",
                     (int)RD_MAP_CNT(&rkshare->rkshare_inflight_acks));

        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 5,
                     "Expected unacked_cnt=5, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_kafka_op_destroy(response_rko);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief GAP types not counted in unacked_cnt; only ACQUIRED counted. */
static int unittest_ack_mapping_gaps(void) {
        rd_kafka_share_t *rkshare   = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id    = rd_kafka_Uuid_random();
        rd_kafka_op_t *response_rko = ut_create_share_fetch_response_rko();
        const rd_kafka_share_internal_acknowledgement_type types[] = {
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_GAP,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED,
            RD_KAFKA_SHARE_INTERNAL_ACK_GAP,
            RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED};

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 5);

        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(100, 104, 5, 1);
        ut_set_types(entry, types, 5);
        rd_list_add(&batches->entries, entry);

        rd_list_add(response_rko->rko_u.share_fetch_response.inflight_acks,
                    batches);

        rd_kafka_share_build_inflight_acks_map(rkshare, response_rko);

        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 3,
                     "Expected unacked_cnt=3, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_kafka_op_destroy(response_rko);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Empty inflight_acks list leaves map empty. */
static int unittest_ack_mapping_empty(void) {
        rd_kafka_share_t *rkshare   = ut_create_mock_rkshare();
        rd_kafka_op_t *response_rko = ut_create_share_fetch_response_rko();

        rd_kafka_share_build_inflight_acks_map(rkshare, response_rko);

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 0,
                     "Expected empty map");

        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 0,
                     "Expected unacked_cnt=0");

        rd_kafka_op_destroy(response_rko);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Multiple entries per partition stored in single map entry. */
static int unittest_ack_mapping_multi_entry(void) {
        rd_kafka_share_t *rkshare   = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id    = rd_kafka_Uuid_random();
        rd_kafka_op_t *response_rko = ut_create_share_fetch_response_rko();

        rd_kafka_topic_partition_t *rktpar =
            ut_create_rktpar_with_id("test-topic", 0, topic_id);
        rd_kafka_share_ack_batches_t *batches =
            rd_kafka_share_ack_batches_new(rktpar, 1, 7);

        rd_kafka_share_ack_batch_entry_t *entry1 =
            rd_kafka_share_ack_batch_entry_new(100, 104, 5, 1);
        ut_set_types_uniform(entry1, RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED);
        rd_list_add(&batches->entries, entry1);

        rd_kafka_share_ack_batch_entry_t *entry2 =
            rd_kafka_share_ack_batch_entry_new(200, 201, 2, 2);
        ut_set_types_uniform(entry2, RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED);
        rd_list_add(&batches->entries, entry2);

        rd_list_add(response_rko->rko_u.share_fetch_response.inflight_acks,
                    batches);

        rd_kafka_share_build_inflight_acks_map(rkshare, response_rko);

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 1,
                     "Expected 1 map entry");

        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 7,
                     "Expected unacked_cnt=7, got %" PRId64,
                     rkshare->rkshare_unacked_cnt);

        rd_kafka_op_destroy(response_rko);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/** @brief Multiple calls accumulate partitions in map. */
static int unittest_ack_mapping_cumulative(void) {
        rd_kafka_share_t *rkshare = ut_create_mock_rkshare();
        rd_kafka_Uuid_t topic_id0 = rd_kafka_Uuid_random();
        rd_kafka_Uuid_t topic_id1 = rd_kafka_Uuid_random();
        rd_kafka_op_t *response_rko1, *response_rko2;

        response_rko1 = ut_create_share_fetch_response_rko();
        rd_kafka_topic_partition_t *rktpar0 =
            ut_create_rktpar_with_id("test-topic", 0, topic_id0);
        rd_kafka_share_ack_batches_t *batches0 =
            rd_kafka_share_ack_batches_new(rktpar0, 1, 3);
        rd_kafka_share_ack_batch_entry_t *entry0 =
            rd_kafka_share_ack_batch_entry_new(100, 102, 3, 1);
        ut_set_types_uniform(entry0, RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED);
        rd_list_add(&batches0->entries, entry0);
        rd_list_add(response_rko1->rko_u.share_fetch_response.inflight_acks,
                    batches0);

        rd_kafka_share_build_inflight_acks_map(rkshare, response_rko1);

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 1,
                     "After 1st call: expected 1 map entry");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 3,
                     "After 1st call: expected unacked_cnt=3");

        response_rko2 = ut_create_share_fetch_response_rko();
        rd_kafka_topic_partition_t *rktpar1 =
            ut_create_rktpar_with_id("test-topic", 1, topic_id1);
        rd_kafka_share_ack_batches_t *batches1 =
            rd_kafka_share_ack_batches_new(rktpar1, 2, 2);
        rd_kafka_share_ack_batch_entry_t *entry1 =
            rd_kafka_share_ack_batch_entry_new(200, 201, 2, 1);
        ut_set_types_uniform(entry1, RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED);
        rd_list_add(&batches1->entries, entry1);
        rd_list_add(response_rko2->rko_u.share_fetch_response.inflight_acks,
                    batches1);

        rd_kafka_share_build_inflight_acks_map(rkshare, response_rko2);

        RD_UT_ASSERT(RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 2,
                     "After 2nd call: expected 2 map entries");
        RD_UT_ASSERT(rkshare->rkshare_unacked_cnt == 5,
                     "After 2nd call: expected unacked_cnt=5");

        rd_kafka_op_destroy(response_rko1);
        rd_kafka_op_destroy(response_rko2);
        ut_destroy_mock_rkshare(rkshare);

        RD_UT_PASS();
}

/**@}*/


/**
 * @name Main test entry point
 * @{
 */

int unittest_fetcher_share_filter_forward(void) {
        int fails = 0;
        const struct {
                const char *name;
                int (*call)(void);
        } tests[] = {
            /* filter tests */
            {"filter_all_acquired", unittest_filter_all_acquired},
            {"filter_partial_range", unittest_filter_partial_range},
            {"filter_disjoint_ranges", unittest_filter_disjoint_ranges},
            {"filter_empty_queue", unittest_filter_empty_queue},
            {"filter_no_ranges", unittest_filter_no_ranges},
            {"filter_sparse_offsets", unittest_filter_sparse_offsets},
            {"filter_range_beyond", unittest_filter_range_beyond_messages},
            /* ack_details tests */
            {"ack_details_all_accept", unittest_ack_details_all_accept},
            {"ack_details_all_acquired", unittest_ack_details_all_acquired},
            {"ack_details_mixed_collation",
             unittest_ack_details_mixed_collation},
            {"ack_details_alternating", unittest_ack_details_alternating},
            {"ack_details_multi_partition",
             unittest_ack_details_multi_partition},
            {"ack_details_empty_map", unittest_ack_details_empty_map},
            {"ack_details_metadata", unittest_ack_details_metadata},
            {"ack_details_gap_acquired", unittest_ack_details_gap_acquired},
            {"ack_details_multi_entry", unittest_ack_details_multi_entry},
            {"ack_details_interleaved", unittest_ack_details_interleaved},
            /* ack_mapping tests */
            {"ack_mapping_single_partition",
             unittest_ack_mapping_single_partition},
            {"ack_mapping_multi_partition",
             unittest_ack_mapping_multi_partition},
            {"ack_mapping_gaps", unittest_ack_mapping_gaps},
            {"ack_mapping_empty", unittest_ack_mapping_empty},
            {"ack_mapping_multi_entry", unittest_ack_mapping_multi_entry},
            {"ack_mapping_cumulative", unittest_ack_mapping_cumulative},
            {NULL}};
        int i;

        ut_mock_rk = rd_calloc(1, sizeof(*ut_mock_rk));

        for (i = 0; tests[i].name; i++) {
                int f = tests[i].call();
                RD_UT_SAY("  %s: %s", tests[i].name,
                          f ? "\033[31mFAIL\033[0m" : "\033[32mPASS\033[0m");
                fails += f;
        }

        rd_free(ut_mock_rk);
        ut_mock_rk = NULL;

        if (fails > 0) {
                RD_UT_SAY("%d test(s) failed", fails);
                return 1;
        }

        RD_UT_PASS();
}

/**@}*/
