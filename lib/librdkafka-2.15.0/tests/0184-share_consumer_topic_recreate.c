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
#include "testshared.h"
#include "rdkafka.h"
#include "../src/rdkafka_proto.h"

#define PARTITION_CNT      3
#define MSGS_PER_PARTITION 10
#define MSGS_PER_PHASE     (PARTITION_CNT * MSGS_PER_PARTITION)
#define BATCH_SIZE         1024


static rd_kafka_t *common_producer;
static rd_kafka_t *common_admin;

/****************************************************************************
 * Helpers
 ****************************************************************************/

/**
 * @brief Produce MSGS_PER_PARTITION framework-encoded messages (NULL
 *        payload => librdkafka test helper auto-encodes
 *        testid+partition+msgid into payload and key) to each of the
 *        first \p partition_cnt partitions of \p topic.
 *
 * Per-partition msgids run [0, MSGS_PER_PARTITION), so msgver_verify_part
 * can later assert exact-range coverage independently per partition.
 */
static void
produce_phase(const char *topic, uint64_t testid, int32_t partition_cnt) {
        int32_t p;
        for (p = 0; p < partition_cnt; p++) {
                test_produce_msgs2(common_producer, topic, testid, p,
                                   0 /*msg_base*/, MSGS_PER_PARTITION,
                                   NULL /*payload*/, 0);
        }
}

/**
 * @brief Fetch the broker-assigned topic_id for \p topic via the
 *        DescribeTopics admin API.
 *
 * @returns A newly-allocated Uuid that the caller must destroy with
 *          rd_kafka_Uuid_destroy().
 *
 * On any failure (topic missing, admin timeout, etc.) the test is failed.
 */
static rd_kafka_Uuid_t *fetch_topic_id(const char *topic) {
        rd_kafka_queue_t *q;
        rd_kafka_TopicCollection_t *tc;
        rd_kafka_event_t *rkev;
        const rd_kafka_DescribeTopics_result_t *res;
        const rd_kafka_TopicDescription_t **descs;
        rd_kafka_Uuid_t *topic_id;
        size_t desc_cnt = 0;
        const char *topics_arr[1];

        topics_arr[0] = topic;

        q  = rd_kafka_queue_new(common_admin);
        tc = rd_kafka_TopicCollection_of_topic_names(topics_arr, 1);

        rd_kafka_DescribeTopics(common_admin, tc, NULL /*options*/, q);

        rkev = rd_kafka_queue_poll(q, 30 * 1000);
        TEST_ASSERT(rkev != NULL, "DescribeTopics(%s) timed out", topic);
        TEST_ASSERT(rd_kafka_event_error(rkev) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "DescribeTopics(%s) failed: %s", topic,
                    rd_kafka_event_error_string(rkev));

        res   = rd_kafka_event_DescribeTopics_result(rkev);
        descs = rd_kafka_DescribeTopics_result_topics(res, &desc_cnt);
        TEST_ASSERT(desc_cnt == 1, "Expected 1 topic description, got %zu",
                    desc_cnt);
        TEST_ASSERT(
            rd_kafka_error_code(rd_kafka_TopicDescription_error(descs[0])) ==
                RD_KAFKA_RESP_ERR_NO_ERROR,
            "Topic %s description error: %s", topic,
            rd_kafka_error_string(rd_kafka_TopicDescription_error(descs[0])));

        topic_id =
            rd_kafka_Uuid_copy(rd_kafka_TopicDescription_topic_id(descs[0]));

        rd_kafka_event_destroy(rkev);
        rd_kafka_TopicCollection_destroy(tc);
        rd_kafka_queue_destroy(q);

        return topic_id;
}

/**
 * @brief Assert that \p id_before and \p id_after represent two different
 *        topic instances; fail the test otherwise.
 */
static void assert_topic_id_changed(const rd_kafka_Uuid_t *id_before,
                                    const rd_kafka_Uuid_t *id_after) {
        TEST_ASSERT(strcmp(rd_kafka_Uuid_base64str(id_before),
                           rd_kafka_Uuid_base64str(id_after)) != 0,
                    "Recreated topic_id (%s) matches the original; "
                    "broker did not actually recreate the topic",
                    rd_kafka_Uuid_base64str(id_before));
}

/**
 * @brief Consume from a share consumer into \p mv until \p exp_cnt messages
 *        matching mv->testid have been collected, or \p timeout_ms elapses.
 *
 * Every consumed message is ACCEPT-ack'd. On every message we assert that
 * delivery_count == 1 (no broker-side redelivery occurred for this run).
 *
 * @returns the count of matching messages collected into \p mv.
 */
static int consume_into_msgver(rd_kafka_share_t *rkshare,
                               test_msgver_t *mv,
                               int exp_cnt,
                               int timeout_ms) {
        rd_kafka_messages_t *batch = NULL;
        rd_ts_t deadline           = test_clock() + (rd_ts_t)timeout_ms * 1000;
        rd_kafka_t *rk             = test_share_consumer_get_rk(rkshare);

        while (mv->msgcnt < exp_cnt && test_clock() < deadline) {
                rd_kafka_error_t *err;
                size_t rcvd = 0;
                size_t i;

                err = rd_kafka_share_poll(rkshare, 500, &batch);
                if (err) {
                        TEST_SAY("share_poll error: %s\n",
                                 rd_kafka_error_string(err));
                        rd_kafka_error_destroy(err);
                        continue;
                }

                rcvd = rd_kafka_messages_count(batch);

                for (i = 0; i < rcvd; i++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, i);

                        if (m->err) {
                                TEST_SAY(
                                    "Consumer event: %s "
                                    "(topic=%s partition=%" PRId32 ")\n",
                                    rd_kafka_err2str(m->err),
                                    m->rkt ? rd_kafka_topic_name(m->rkt)
                                           : "(none)",
                                    m->partition);
                                continue;
                        }

                        TEST_ASSERT(
                            rd_kafka_message_delivery_count(m) == 1,
                            "Unexpected redelivery: delivery_count=%d on "
                            "topic=%s partition=%" PRId32 " offset=%" PRId64,
                            rd_kafka_message_delivery_count(m),
                            rd_kafka_topic_name(m->rkt), m->partition,
                            m->offset);

                        /* msgver auto-filters by mv->testid; messages from
                         * the other phase (or untagged) are silently
                         * dropped. */
                        test_msgver_add_msg(rk, mv, m);
                        rd_kafka_share_acknowledge(rkshare, m);
                }

                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        return mv->msgcnt;
}

/**
 * @brief Delete a topic, wait for the deletion to settle, then recreate
 *        with the same name and \p partition_cnt partitions. The new
 *        instance will have a fresh topic_id on the broker.
 */
static void recreate_topic(const char *topic, int partition_cnt) {
        TEST_SAY("Deleting topic %s\n", topic);
        test_delete_topic(common_admin, topic);

        /* DeleteTopics is async on the broker; the controller may still
         * be removing log segments when we issue CreateTopics. Without
         * this pause, the broker frequently lets the CreateTopics request
         * sit until DeleteTopics finishes, which can blow past the
         * admin-op timeout. The same 5s pause pattern is used by
         * 0107-topic_recreate. */
        rd_sleep(5);

        TEST_SAY("Recreating topic %s with %d partition(s)\n", topic,
                 partition_cnt);
        test_create_topic_wait_exists(common_admin, topic, partition_cnt, -1,
                                      60 * 1000);
}

/**
 * @brief Build a share consumer such that the periodic metadata refresh
 *        is the dominant channel for discovering topic_id changes:
 *          - topic.metadata.refresh.interval.ms is set to 500ms, well
 *            below the broker-dictated ShareGroupHeartbeat interval
 *            (typically 5s), so the refresh timer is virtually
 *            guaranteed to fire between heartbeats during the
 *            delete/recreate window;
 */
static rd_kafka_share_t *create_consumer_md_first(const char *group_id) {
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        char errstr[512];

        test_conf_init(&conf, NULL, 0);

        test_conf_set(conf, "group.id", group_id);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "500");

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare, "Failed to create share consumer: %s", errstr);

        return rkshare;
}

/**
 * @brief Build a share consumer such that the ShareGroupHeartbeat is
 *        the dominant channel for discovering topic_id changes; the
 *        default topic.metadata.refresh.interval.ms is 5min, so the
 *        periodic MD refresh effectively does not fire during a test.
 *
 * Same signature as create_consumer_md_first so both can be passed to
 * do_test_recreate_two_phase as a builder function pointer.
 */
static rd_kafka_share_t *create_consumer_hb_first(const char *group_id) {
        return test_create_share_consumer(group_id, "explicit");
}

/**
 * @brief Background-thread payload that deletes and recreates a topic
 *        on a mock cluster after a short sleep.
 *
 * Used by recreate-during-close mock tests so the recreate lands in the
 * middle of an artificially-delayed broker request on the main thread.
 */
struct recreate_thread_args {
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic;
        int32_t partition_cnt;
        int sleep_ms;
};

static int recreate_thread_main(void *p) {
        struct recreate_thread_args *args = p;
        rd_usleep((int64_t)args->sleep_ms * 1000, NULL);
        TEST_SAY("[recreate-thread] Deleting topic %s\n", args->topic);
        TEST_ASSERT(rd_kafka_mock_topic_delete(args->mcluster, args->topic) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "[recreate-thread] mock_topic_delete failed");
        TEST_SAY("[recreate-thread] Recreating topic %s with %" PRId32
                 " partition(s)\n",
                 args->topic, args->partition_cnt);
        TEST_ASSERT(rd_kafka_mock_topic_create(args->mcluster, args->topic,
                                               args->partition_cnt,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "[recreate-thread] mock_topic_create failed");
        return 0;
}

/**
 * @brief Background producer thread: produces one record every
 *        producer_period_ms with payload "<phase>:<seq>", where
 *        phase is whatever the controlling thread has most recently
 *        written into args->phase. Tolerates produce errors (the
 *        topic may not exist mid-test).
 *
 *
 * Used by the survives-delete-and-recreate test to keep produce
 * activity steady through the delete window.
 */
struct producer_thread_args {
        rd_kafka_t *producer;
        const char *topic;
        int period_ms;
        char phase[16]; /* "before" / "during" / "after" */
        rd_bool_t stop;
};

static int producer_thread_main(void *p) {
        struct producer_thread_args *args = p;
        int seq                           = 0;
        while (!args->stop) {
                char payload[64];
                rd_snprintf(payload, sizeof(payload), "%s:%d", args->phase,
                            seq++);
                /* Errors during the delete window are expected; the
                 * test tolerates them silently. */
                (void)rd_kafka_producev(
                    args->producer, RD_KAFKA_V_TOPIC(args->topic),
                    RD_KAFKA_V_VALUE(payload, strlen(payload)),
                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY), RD_KAFKA_V_END);
                rd_usleep((int64_t)args->period_ms * 1000, NULL);
        }
        return 0;
}

/****************************************************************************
 * Test Cases
 ****************************************************************************/

/**
 * @brief Generic two-phase recreate test: produce + consume + verify
 *        a "before" phase, recreate the topic (possibly with a different
 *        partition count), then produce + consume + verify an "after"
 *        phase against the new topic instance.
 *
 *   1. Subscribe; produce MSGS_PER_PHASE framework-encoded messages
 *      tagged with testid_before; consume them all via a "before" msgver
 *      and assert exact range coverage and zero redelivery.
 *   2. Delete + recreate the topic with \p after_partition_cnt partitions.
 *      The broker assigns a fresh topic_id. Whichever of (HB, periodic
 *      metadata refresh) the \p ctor builder favors will carry the
 *      change to the client first.
 *   3. Produce after_partition_cnt * MSGS_PER_PARTITION records tagged
 *      with testid_after; consume them all via an "after" msgver and
 *      assert exact range coverage, zero redelivery, and (implicitly
 *      via testid filtering) zero stale "before" messages.
 */
static void do_test_recreate_two_phase(const char *label,
                                       const char *group_id,
                                       rd_kafka_share_t *(*ctor)(const char *),
                                       int32_t after_partition_cnt) {
        const char *topic;
        rd_kafka_share_t *rkshare;
        test_msgver_t mv_before, mv_after;
        uint64_t testid_before, testid_after;
        rd_kafka_Uuid_t *id_before, *id_after;
        int got;
        int32_t p;
        const int msgs_per_phase_after =
            after_partition_cnt * MSGS_PER_PARTITION;

        SUB_TEST_QUICK("%s", label);

        testid_before = test_id_generate();
        testid_after  = test_id_generate();

        topic = test_mk_topic_name(label, 1);

        test_create_topic_wait_exists(common_admin, topic, PARTITION_CNT, -1,
                                      60 * 1000);

        id_before = fetch_topic_id(topic);
        TEST_SAY("Initial topic_id: %s\n", rd_kafka_Uuid_base64str(id_before));

        test_share_set_auto_offset_reset(group_id, "earliest");

        rkshare = ctor(group_id);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* ---- Phase 1: pre-recreate ---- */
        TEST_SAY(
            "Phase 1: producing %d msgs/partition x %d partitions "
            "(testid=%" PRIu64 ")\n",
            MSGS_PER_PARTITION, PARTITION_CNT, testid_before);
        produce_phase(topic, testid_before, PARTITION_CNT);

        test_msgver_init(&mv_before, testid_before);
        got =
            consume_into_msgver(rkshare, &mv_before, MSGS_PER_PHASE, 30 * 1000);
        TEST_ASSERT(got == MSGS_PER_PHASE,
                    "Phase 1: expected %d msgs matching testid_before, "
                    "got %d",
                    MSGS_PER_PHASE, got);
        for (p = 0; p < PARTITION_CNT; p++)
                test_msgver_verify_part("phase1-before-part", &mv_before,
                                        TEST_MSGVER_ALL_PART, topic, p,
                                        0 /*msg_base*/, MSGS_PER_PARTITION);
        test_msgver_clear(&mv_before);

        /* ---- Recreate ---- */
        recreate_topic(topic, after_partition_cnt);

        id_after = fetch_topic_id(topic);
        TEST_SAY("Recreated topic_id: %s\n", rd_kafka_Uuid_base64str(id_after));
        assert_topic_id_changed(id_before, id_after);

        /* ---- Phase 2: post-recreate ---- */
        TEST_SAY("Phase 2: producing %d msgs/partition x %" PRId32
                 " partitions on recreated topic (testid=%" PRIu64 ")\n",
                 MSGS_PER_PARTITION, after_partition_cnt, testid_after);
        produce_phase(topic, testid_after, after_partition_cnt);

        test_msgver_init(&mv_after, testid_after);
        got = consume_into_msgver(rkshare, &mv_after, msgs_per_phase_after,
                                  60 * 1000);
        TEST_ASSERT(got == msgs_per_phase_after,
                    "Phase 2: expected %d msgs matching testid_after, "
                    "got %d (post-recreate)",
                    msgs_per_phase_after, got);
        for (p = 0; p < after_partition_cnt; p++)
                test_msgver_verify_part("phase2-after-part", &mv_after,
                                        TEST_MSGVER_ALL_PART, topic, p,
                                        0 /*msg_base*/, MSGS_PER_PARTITION);
        test_msgver_clear(&mv_after);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        rd_kafka_Uuid_destroy(id_before);
        rd_kafka_Uuid_destroy(id_after);

        SUB_TEST_PASS();
}

/**
 * @brief Stress test: many rapid topic recreations interleaved with
 *        random produce activity and varying partition counts.
 *
 * Each chaos cycle picks (uniformly at random):
 *   - A short pre-recreate sleep in [200, 1500] ms, to let the
 *     consumer's state advance unpredictably between cycles.
 *   - Whether to produce 0..5 records to each partition of the
 *     current topic instance before the recreate; if any are
 *     produced, they use a per-cycle testid that the test does not
 *     track (we don't require these records to be received).
 *   - A new partition count from {2, 3, 4} for the recreated topic,
 *     exercising shrink, no-change, and grow paths from one cycle to
 *     the next.
 *
 * After chaos_cycles iterations the test produces a final batch of
 * MSGS_PER_PARTITION records to every partition of whatever topic
 * instance is currently live (partition count is whatever chaos left
 * it at) and asserts:
 *   - The final batch is fully consumed (per-partition exact-range).
 *   - All final-batch records have delivery_count == 1.
 *   - The broker-assigned topic_id changed end-to-end.
 */
static void do_test_recreate_chaos(void) {
        const int chaos_cycles                  = 10;
        const int chaos_sleep_min_ms            = 200;
        const int chaos_sleep_max_ms            = 1500;
        const int chaos_max_records_per_part    = 5;
        const int32_t chaos_partition_choices[] = {2, 3, 4};
        const int chaos_partition_choices_cnt =
            sizeof(chaos_partition_choices) /
            sizeof(chaos_partition_choices[0]);
        const char *topic;
        const char *group_id = "0184-share-recreate-chaos";
        rd_kafka_share_t *rkshare;
        test_msgver_t mv_warmup, mv_final;
        uint64_t testid_warmup, testid_final, seed_testid;
        rd_kafka_Uuid_t *id_initial, *id_final;
        int32_t current_partition_cnt = PARTITION_CNT;
        int cycle;
        int got;
        int32_t p;
        int final_msgs;

        SUB_TEST_QUICK();

        seed_testid = test_id_generate();
        srand((unsigned)seed_testid);
        TEST_SAY("Chaos seed (from testid): %" PRIu64 "\n", seed_testid);

        testid_warmup = test_id_generate();
        testid_final  = test_id_generate();

        topic = test_mk_topic_name("0184-recreate-chaos", 1);

        test_create_topic_wait_exists(common_admin, topic, PARTITION_CNT, -1,
                                      60 * 1000);
        id_initial = fetch_topic_id(topic);
        TEST_SAY("Initial topic_id: %s\n", rd_kafka_Uuid_base64str(id_initial));

        test_share_set_auto_offset_reset(group_id, "earliest");

        /* HB-first regime: long MD refresh so HB drives discovery
         * across recreate cycles. */
        rkshare = test_create_share_consumer(group_id, "explicit");

        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Warmup: drive the consumer to a fully-active state before
         * chaos begins. Produces MSGS_PER_PARTITION to every
         * partition; consumes them all. */
        TEST_SAY(
            "Warmup: producing %d msgs/partition x %d partitions "
            "(testid=%" PRIu64 ")\n",
            MSGS_PER_PARTITION, PARTITION_CNT, testid_warmup);
        produce_phase(topic, testid_warmup, PARTITION_CNT);

        test_msgver_init(&mv_warmup, testid_warmup);
        got =
            consume_into_msgver(rkshare, &mv_warmup, MSGS_PER_PHASE, 30 * 1000);
        TEST_ASSERT(got == MSGS_PER_PHASE, "Warmup: expected %d msgs, got %d",
                    MSGS_PER_PHASE, got);
        test_msgver_clear(&mv_warmup);

        /* Chaos loop. */
        for (cycle = 0; cycle < chaos_cycles; cycle++) {
                int sleep_ms;
                int32_t next_partition_cnt;
                int do_produce;
                int n_per_part;

                sleep_ms =
                    chaos_sleep_min_ms +
                    (rand() % (chaos_sleep_max_ms - chaos_sleep_min_ms + 1));
                next_partition_cnt =
                    chaos_partition_choices[rand() %
                                            chaos_partition_choices_cnt];
                do_produce = rand() % 2;
                n_per_part = do_produce
                                 ? (rand() % (chaos_max_records_per_part + 1))
                                 : 0;

                TEST_SAY(
                    "[chaos cycle %d/%d] sleep=%dms, produce=%d "
                    "msg(s)/partition (cur_partitions=%" PRId32
                    "), next_partition_cnt=%" PRId32 "\n",
                    cycle + 1, chaos_cycles, sleep_ms, n_per_part,
                    current_partition_cnt, next_partition_cnt);

                rd_usleep((int64_t)sleep_ms * 1000, NULL);

                /* Optional mid-cycle produce. Uses a throwaway testid
                 * so these records are silently ignored on consume —
                 * they may or may not arrive depending on what state
                 * the consumer is in. */
                if (n_per_part > 0) {
                        uint64_t cycle_testid = test_id_generate();
                        int32_t cp;
                        for (cp = 0; cp < current_partition_cnt; cp++) {
                                test_produce_msgs2(common_producer, topic,
                                                   cycle_testid, cp,
                                                   0 /*msg_base*/, n_per_part,
                                                   NULL /*payload*/, 0);
                        }
                }

                recreate_topic(topic, next_partition_cnt);
                current_partition_cnt = next_partition_cnt;

                /* Force a producer-side metadata refresh
                 * so its view matches the broker before we try to
                 * produce again. */
                test_wait_topic_exists(common_producer, topic, 60 * 1000);
        }

        /* Settle: produce a final batch we will require to be fully
         * consumed, against whatever topic instance chaos left us
         * with. */
        TEST_SAY("Settle: producing %d msgs/partition x %" PRId32
                 " partitions (testid=%" PRIu64 ")\n",
                 MSGS_PER_PARTITION, current_partition_cnt, testid_final);
        produce_phase(topic, testid_final, current_partition_cnt);

        final_msgs = current_partition_cnt * MSGS_PER_PARTITION;

        test_msgver_init(&mv_final, testid_final);
        got = consume_into_msgver(rkshare, &mv_final, final_msgs, 60 * 1000);
        TEST_ASSERT(got == final_msgs,
                    "Settle: expected %d msgs matching testid_final, "
                    "got %d after %d chaos cycles",
                    final_msgs, got, chaos_cycles);
        for (p = 0; p < current_partition_cnt; p++)
                test_msgver_verify_part("chaos-final-part", &mv_final,
                                        TEST_MSGVER_ALL_PART, topic, p,
                                        0 /*msg_base*/, MSGS_PER_PARTITION);
        test_msgver_clear(&mv_final);

        /* Verify chaos actually moved the topic_id. */
        id_final = fetch_topic_id(topic);
        TEST_SAY("Final topic_id: %s\n", rd_kafka_Uuid_base64str(id_final));
        assert_topic_id_changed(id_initial, id_final);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        rd_kafka_Uuid_destroy(id_initial);
        rd_kafka_Uuid_destroy(id_final);

        SUB_TEST_PASS();
}

/**
 * @brief Subscribed consumer survives topic delete + recreate-with-
 *        different-partition-count while a producer is actively
 *        producing across the whole window.
 *
 * Differs from the other recreate tests in that this one keeps a
 * concurrent producer thread running through the entire delete window.
 *
 * Assertions:
 *   - At least one "before" record consumed (consumer was healthy).
 *   - At least one "after" record consumed (consumer recovered).
 *   - "During" records may or may not be consumed; no assertion.
 *   - Final topic_id differs from the initial topic_id (broker
 *     actually recreated the topic).
 */
static void do_test_recreate_survives_concurrent_producer(void) {
        const char *topic;
        const char *group_id = "0184-share-recreate-concurrent-producer";
        const int32_t partition_cnt_a = 3;
        const int32_t partition_cnt_b = 5;
        const int producer_period_ms  = 100; /* ~10 msgs/sec */
        const int phase_duration_ms   = 10000;
        rd_kafka_share_t *rkshare;
        rd_kafka_messages_t *batch = NULL;
        struct producer_thread_args producer_args;
        thrd_t producer_thrd;
        rd_kafka_Uuid_t *id_initial, *id_final;
        int before_cnt = 0, during_cnt = 0, after_cnt = 0;
        rd_ts_t consume_deadline;

        SUB_TEST_QUICK();

        topic = test_mk_topic_name("0184-recreate-concurrent-producer", 1);

        test_create_topic_wait_exists(common_admin, topic, partition_cnt_a, -1,
                                      60 * 1000);
        id_initial = fetch_topic_id(topic);
        TEST_SAY("Initial topic_id: %s (partition_cnt=%" PRId32 ")\n",
                 rd_kafka_Uuid_base64str(id_initial), partition_cnt_a);

        test_share_set_auto_offset_reset(group_id, "earliest");

        rkshare = test_create_share_consumer(group_id, "implicit");

        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Start background producer in "before" phase. */
        producer_args.producer  = common_producer;
        producer_args.topic     = topic;
        producer_args.period_ms = producer_period_ms;
        producer_args.stop      = rd_false;
        rd_snprintf(producer_args.phase, sizeof(producer_args.phase), "before");

        TEST_ASSERT(thrd_create(&producer_thrd, producer_thread_main,
                                &producer_args) == thrd_success,
                    "thrd_create failed");

        /* --- Phase: BEFORE.
         * Consume for a few seconds while producer thread feeds the
         * topic. Count "before:" records to confirm the pipeline is
         * live. */
        consume_deadline = test_clock() + (rd_ts_t)phase_duration_ms * 1000;
        while (test_clock() < consume_deadline) {
                rd_kafka_error_t *err;
                size_t rcvd = 0;
                size_t i;
                err = rd_kafka_share_poll(rkshare, 200, &batch);
                if (err) {
                        TEST_SAY(
                            "Phase BEFORE: share_poll error: "
                            "%s\n",
                            rd_kafka_error_string(err));
                        rd_kafka_error_destroy(err);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (i = 0; i < rcvd; i++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, i);
                        if (!m->err && m->payload && m->len >= 7 &&
                            !strncmp((const char *)m->payload, "before:", 7))
                                before_cnt++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_SAY("Phase BEFORE: consumed %d \"before:\" record(s)\n",
                 before_cnt);

        /* --- Transition: enter DURING. Delete the topic but keep the
         * producer running. Most produces in this window will fail with
         * Unknown topic-type errors; that's expected. */
        TEST_SAY("Phase transition: entering DURING (delete topic)\n");
        rd_snprintf(producer_args.phase, sizeof(producer_args.phase), "during");
        test_delete_topic(common_admin, topic);

        /* Drain the consumer briefly during the delete window. Most
         * fetches will return errors. We don't track "during:" counts
         * for an assertion; just log. */
        consume_deadline = test_clock() + (rd_ts_t)phase_duration_ms * 1000;
        while (test_clock() < consume_deadline) {
                rd_kafka_error_t *err;
                size_t rcvd = 0;
                size_t i;
                err = rd_kafka_share_poll(rkshare, 200, &batch);
                if (err) {
                        TEST_SAY(
                            "Phase DURING: share_poll error: "
                            "%s\n",
                            rd_kafka_error_string(err));
                        rd_kafka_error_destroy(err);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (i = 0; i < rcvd; i++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, i);
                        if (!m->err && m->payload && m->len >= 7 &&
                            !strncmp((const char *)m->payload, "during:", 7))
                                during_cnt++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_SAY(
            "Phase DURING: consumed %d \"during:\" record(s) "
            "(no assertion on this count)\n",
            during_cnt);

        /* --- Transition: recreate with a different partition count
         * and switch producer to "after". */
        TEST_SAY("Recreating topic with partition_cnt=%" PRId32 " (was %" PRId32
                 ")\n",
                 partition_cnt_b, partition_cnt_a);
        rd_sleep(5); /* let delete settle on the broker */
        test_create_topic_wait_exists(common_admin, topic, partition_cnt_b, -1,
                                      60 * 1000);

        id_final = fetch_topic_id(topic);
        TEST_SAY("Recreated topic_id: %s (partition_cnt=%" PRId32 ")\n",
                 rd_kafka_Uuid_base64str(id_final), partition_cnt_b);

        /* Force the producer to refresh its metadata for the recreated
         * topic.
         */
        test_wait_topic_exists(common_producer, topic, 60 * 1000);

        rd_snprintf(producer_args.phase, sizeof(producer_args.phase), "after");

        /* --- Phase: AFTER.
         * Consume for a longer window to give the consumer time to
         * reconcile the new topic_id and start delivering "after:"
         * records. */
        consume_deadline = test_clock() + 60 * 1000 * 1000;
        while (after_cnt == 0 && test_clock() < consume_deadline) {
                rd_kafka_error_t *err;
                size_t rcvd = 0;
                size_t i;
                err = rd_kafka_share_poll(rkshare, 500, &batch);
                if (err) {
                        TEST_SAY(
                            "Phase AFTER: share_poll error: "
                            "%s\n",
                            rd_kafka_error_string(err));
                        rd_kafka_error_destroy(err);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (i = 0; i < rcvd; i++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, i);
                        if (!m->err && m->payload && m->len >= 6 &&
                            !strncmp((const char *)m->payload, "after:", 6))
                                after_cnt++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_SAY("Phase AFTER: consumed %d \"after:\" record(s)\n", after_cnt);

        /* Stop and join the producer thread before any assertion
         * runs.
         */
        producer_args.stop = rd_true;
        thrd_join(producer_thrd, NULL);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        TEST_ASSERT(before_cnt > 0,
                    "Expected at least one \"before:\" record to be "
                    "consumed");
        assert_topic_id_changed(id_initial, id_final);
        TEST_ASSERT(after_cnt > 0,
                    "Consumer did not recover after recreate: zero "
                    "\"after:\" records seen within 60s");

        rd_kafka_Uuid_destroy(id_initial);
        rd_kafka_Uuid_destroy(id_final);

        SUB_TEST_PASS();
}

/**
 * @brief Topic ID changes server-side while the consumer is in
 *        the middle of close(); verify close completes cleanly.
 *
 * Assertions:
 *   - close() completes within a reasonable time
 */
static void test_recreate_during_close(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        const char *topic  = "0184-recreate-during-close";
        const char *group  = "0184-share-recreate-during-close";
        const int n_msgs   = 10;
        const int delay_ms = 5000;
        rd_kafka_message_t *rkmessages[64];
        rd_kafka_messages_t *batches[64];
        size_t batches_cnt = 0;
        struct recreate_thread_args thread_args;
        thrd_t recreate_thrd;
        rd_kafka_conf_t *conf;
        size_t rcvd     = 0;
        int attempts    = 0;
        int max_attempt = 30;
        int i;
        rd_ts_t t_start, t_elapsed_ms;
        const int64_t close_upper_bound_ms = delay_ms + 2000;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        TEST_SAY("Producing %d messages to topic %s\n", n_msgs, topic);
        test_produce_msgs_easy_v(topic, 0, 0, 0, n_msgs, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        TEST_SAY("Creating share consumer with explicit ack mode\n");
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "500");
        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");

        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        TEST_SAY("Consuming up to %d messages\n", n_msgs);
        while (rcvd < (size_t)n_msgs && attempts < max_attempt) {
                rd_kafka_messages_t *batch = NULL;
                size_t batch_rcvd;
                size_t k;
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        TEST_SAY("Consume attempt %d: %s\n", attempts,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        attempts++;
                        continue;
                }
                batch_rcvd = rd_kafka_messages_count(batch);
                if (batch_rcvd > 0 &&
                    batches_cnt < sizeof(batches) / sizeof(batches[0]) &&
                    rcvd + batch_rcvd <=
                        sizeof(rkmessages) / sizeof(rkmessages[0])) {
                        for (k = 0; k < batch_rcvd; k++)
                                rkmessages[rcvd + k] =
                                    rd_kafka_messages_get(batch, k);
                        rcvd += batch_rcvd;
                        batches[batches_cnt++] = batch;
                } else {
                        rd_kafka_messages_destroy(batch);
                }
                attempts++;
        }
        TEST_ASSERT(rcvd == (size_t)n_msgs,
                    "Expected to consume %d messages, got %zu", n_msgs, rcvd);

        TEST_SAY("Staging acks for all %zu messages\n", rcvd);
        for (i = 0; i < (int)rcvd; i++) {
                rd_kafka_resp_err_t ack_err =
                    rd_kafka_share_acknowledge(rkshare, rkmessages[i]);
                TEST_ASSERT(ack_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "ack %d failed: %s", i, rd_kafka_err2str(ack_err));
        }

        TEST_SAY("Injecting %dms delay on the next ShareAcknowledge response\n",
                 delay_ms);
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        mcluster, 1, RD_KAFKAP_ShareAcknowledge, 1,
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                        delay_ms) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to inject ShareAcknowledge delay");

        thread_args.mcluster      = mcluster;
        thread_args.topic         = topic;
        thread_args.partition_cnt = 1;
        thread_args.sleep_ms      = 1000;
        TEST_ASSERT(thrd_create(&recreate_thrd, recreate_thread_main,
                                &thread_args) == thrd_success,
                    "thrd_create failed");

        TEST_SAY(
            "Calling close(); broker will hold ack for %dms while "
            "background thread recreates the topic\n",
            delay_ms);
        t_start      = test_clock();
        error        = rd_kafka_share_consumer_close(rkshare);
        t_elapsed_ms = (test_clock() - t_start) / 1000;
        TEST_SAY("close() returned in %" PRId64 " ms\n", t_elapsed_ms);

        if (error) {
                TEST_SAY("close() returned error: %s\n",
                         rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
        }

        TEST_ASSERT(t_elapsed_ms <= close_upper_bound_ms,
                    "close() took %" PRId64 " ms, expected <= %" PRId64
                    " ms (broker delay + overhead)",
                    t_elapsed_ms, close_upper_bound_ms);

        thrd_join(recreate_thrd, NULL);

        for (i = 0; i < (int)batches_cnt; i++)
                rd_kafka_messages_destroy(batches[i]);

        test_share_destroy(rkshare);
        test_mock_cluster_destroy(mcluster);
        SUB_TEST_PASS();
}

/* ===================================================================
 *  Log callback: counts the "no partitions are assigned" fetch-stall
 *  log emitted while the share consumer's assignment is empty.
 * =================================================================== */
static void recreate_stall_log_cb(const rd_kafka_t *rk,
                                  int level,
                                  const char *fac,
                                  const char *buf) {
        rd_atomic32_t *cnt = rd_kafka_opaque(rk);
        if (cnt && !strcmp(fac, "FETCHMORE") &&
            strstr(buf, "no partitions are assigned"))
                rd_atomic32_add(cnt, 1);
}

/**
 * @brief Delete the consumer's only topic so the broker revokes its
 *        assignment to empty, verify the consumer reports the
 *        no-partitions fetch stall, then recreate the topic and verify
 *        records flow again.
 *
 * Reproduces the observed delete/recreate latency: with no partitions
 * assigned the consumer keeps wanting to fetch and emits the
 * rate-limited "Fetch stalled: ... no partitions are assigned" log
 * until the recreated topic (fresh topic_id) is reassigned.
 */
static void do_test_recreate_stall_then_recover(void) {
        const char *topic;
        const char *group = "0184-share-recreate-stall";
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        rd_atomic32_t stall_cnt;
        test_msgver_t mv_before, mv_after;
        uint64_t testid_before, testid_after;
        rd_kafka_Uuid_t *id_before, *id_after;
        rd_kafka_messages_t *batch = NULL;
        rd_ts_t deadline;
        int got, stalls;
        char errstr[512];

        SUB_TEST_QUICK();

        rd_atomic32_init(&stall_cnt, 0);
        testid_before = test_id_generate();
        testid_after  = test_id_generate();

        topic = test_mk_topic_name("0184-recreate-stall", 1);
        test_create_topic_wait_exists(common_admin, topic, PARTITION_CNT, -1,
                                      60 * 1000);

        id_before = fetch_topic_id(topic);
        test_share_set_auto_offset_reset(group, "earliest");

        /* Fast metadata refresh + debug=consumer so the no-partitions
         * stall log is emitted and observable via the log callback. */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "500");
        test_conf_set(conf, "debug", "consumer");
        rd_kafka_conf_set_log_cb(conf, recreate_stall_log_cb);
        rd_kafka_conf_set_opaque(conf, &stall_cnt);
        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare, "Failed to create share consumer: %s", errstr);

        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* ---- Phase 1: consume the original generation ---- */
        produce_phase(topic, testid_before, PARTITION_CNT);
        test_msgver_init(&mv_before, testid_before);
        got =
            consume_into_msgver(rkshare, &mv_before, MSGS_PER_PHASE, 30 * 1000);
        TEST_ASSERT(got == MSGS_PER_PHASE, "Phase 1: expected %d msgs, got %d",
                    MSGS_PER_PHASE, got);
        test_msgver_clear(&mv_before);

        /* ---- Delete: the broker revokes the assignment to empty ---- */
        TEST_SAY("Deleting topic %s; expecting a no-partitions fetch stall\n",
                 topic);
        test_delete_topic(common_admin, topic);

        /* Poll until the no-partitions stall is logged. The log is
         * rate-limited, so a single occurrence confirms the path. */
        deadline = test_clock() + (rd_ts_t)60 * 1000 * 1000;
        while (rd_atomic32_get(&stall_cnt) < 1 && test_clock() < deadline) {
                rd_kafka_error_t *error =
                    rd_kafka_share_poll(rkshare, 500, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                } else {
                        /* Ack any straggler so the next poll can proceed
                         * in explicit mode. */
                        size_t i, n = rd_kafka_messages_count(batch);
                        for (i = 0; i < n; i++)
                                rd_kafka_share_acknowledge(
                                    rkshare, rd_kafka_messages_get(batch, i));
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        stalls = rd_atomic32_get(&stall_cnt);
        TEST_SAY("\"no partitions assigned\" stall log count: %d\n", stalls);
        TEST_ASSERT(stalls >= 1,
                    "expected the no-partitions stall to be logged, got %d",
                    stalls);

        /* ---- Recreate (fresh topic_id): the broker reassigns ---- */
        rd_sleep(5); /* let DeleteTopics settle, as in recreate_topic() */
        test_create_topic_wait_exists(common_admin, topic, PARTITION_CNT, -1,
                                      60 * 1000);
        id_after = fetch_topic_id(topic);
        assert_topic_id_changed(id_before, id_after);

        /* ---- Phase 2: records flow again ---- */
        produce_phase(topic, testid_after, PARTITION_CNT);
        test_msgver_init(&mv_after, testid_after);
        got =
            consume_into_msgver(rkshare, &mv_after, MSGS_PER_PHASE, 60 * 1000);
        TEST_ASSERT(got == MSGS_PER_PHASE,
                    "Phase 2: expected %d msgs after recreate, got %d",
                    MSGS_PER_PHASE, got);
        test_msgver_clear(&mv_after);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        rd_kafka_Uuid_destroy(id_before);
        rd_kafka_Uuid_destroy(id_after);

        SUB_TEST_PASS();
}

int main_0184_share_consumer_topic_recreate(int argc, char **argv) {
        /* Topic deletion is not supported against Windows brokers. */
        if (!strcmp(test_getenv("TEST_BROKER_OS", ""), "windows")) {
                TEST_SKIP("Topic deletion not supported on Windows brokers\n");
                return 0;
        }

        test_timeout_set(300);

        common_producer = test_create_producer();
        common_admin    = test_create_producer();

        do_test_recreate_two_phase("0184-recreate-hb-first",
                                   "0184-share-recreate-hb-first",
                                   create_consumer_hb_first, PARTITION_CNT);
        do_test_recreate_two_phase("0184-recreate-md-first",
                                   "0184-share-recreate-md-first",
                                   create_consumer_md_first, PARTITION_CNT);
        do_test_recreate_two_phase("0184-recreate-shrink-hb-first",
                                   "0184-share-recreate-shrink-hb-first",
                                   create_consumer_hb_first, 2);
        do_test_recreate_two_phase("0184-recreate-shrink-md-first",
                                   "0184-share-recreate-shrink-md-first",
                                   create_consumer_md_first, 2);
        do_test_recreate_chaos();
        do_test_recreate_survives_concurrent_producer();
        do_test_recreate_stall_then_recover();

        rd_kafka_destroy(common_admin);
        rd_kafka_destroy(common_producer);

        return 0;
}

/**
 * @brief Same-name topic recreate where a single consumer owns the same
 *        (name, partition) tuples in both generations.
 *
 * The cooperative-assignment reconciler in rd_kafka_cgrp.c builds set
 * subtraction maps keyed by (topic_name, partition), so OLD-id and
 * NEW-id entries for the same (name, partition) collide in the diff.
 * When a single consumer owns every partition of a same-name recreated
 * topic, no partition lands in newly_added, no PARTITION_JOIN ->
 * share_session_toppar_add fires for the NEW rktp, and ShareFetch
 * never asks for the NEW generation.
 *
 * To deterministically expose the bug we need the consumer's heartbeat
 * to deliver a direct OLD-id -> NEW-id target transition with no
 * intermediate empty assignment. The mock cluster's heartbeat handler
 * normally only recalculates assignments on member events (join,
 * leave, subscription change) -- not on topic delete/recreate -- so a
 * naive delete + recreate would leave the mock emitting the stale
 * OLD-id assignment forever, never reaching the reconciler bug
 * condition. Instead, the test uses
 * rd_kafka_mock_sharegroup_target_assignment to manually inject the
 * NEW-id assignment after the recreate. The mock resolves the
 * partition list's topic name to the NEW topic_id at assignment-set
 * time, so the consumer's next heartbeat carries
 * (NEW-id, partition) tuples while its current assignment still holds
 * the (OLD-id, partition) tuples from PHASE 1 -- exactly the input
 * that triggers the (topic_name, partition) hash collision.
 *
 * Pre-fix: PHASE 2 times out with zero NEW records consumed.
 * Post-fix: PHASE 2 consumes all NEW records.
 */
static void do_test_recreate_same_name_partition_collision(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        rd_kafka_conf_t *producer_conf;
        rd_kafka_t *producer;
        const char *topic          = "0184-recreate-collision";
        const char *group          = "0184-share-recreate-collision";
        const int n_partitions     = 3;
        const int n_msgs_per_part  = 10;
        const int total_per_phase  = n_partitions * n_msgs_per_part;
        rd_kafka_messages_t *batch = NULL;
        int old_got                = 0;
        int new_got                = 0;
        rd_ts_t deadline;
        int32_t p;
        char **member_ids;
        size_t member_cnt;
        size_t mi;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *new_assignment;
        rd_kafka_topic_partition_list_t *member_assignments[1];
        const char *member_id_arr[1];

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        /* Short heartbeat keeps the post-injection latency tight; the
         * consumer's next heartbeat after the manual assignment-set
         * delivers the NEW-id target within ~1s. */
        rd_kafka_mock_sharegroup_set_heartbeat_interval(mcluster, 1000);

        /* Persistent producer for the whole test. The mock cluster
         * destroys every share-group session on the broker when any
         * client connection closes (see
         * rd_kafka_mock_sharegrps_node_connection_closed in
         * rdkafka_mock_sharegrp.c), so spinning up a fresh producer
         * instance per produce call would invalidate the consumer's
         * session as collateral damage and break PHASE 2's fetch.
         * Keeping one producer alive end-to-end avoids that. */
        test_conf_init(&producer_conf, NULL, 0);
        test_conf_set(producer_conf, "bootstrap.servers", bootstraps);
        rd_kafka_conf_set_dr_msg_cb(producer_conf, test_dr_msg_cb);
        producer = test_create_handle(RD_KAFKA_PRODUCER, producer_conf);
        TEST_ASSERT(producer != NULL, "producer create failed");

        /* Initial topic generation. */
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, n_partitions,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "mock_topic_create (initial) failed");

        /* Produce n_msgs_per_part records to every partition of the
         * initial generation so PHASE 1 has something to drain. */
        for (p = 0; p < n_partitions; p++)
                test_produce_msgs2(producer, topic, 0 /*testid*/, p,
                                   0 /*msg_base*/, n_msgs_per_part,
                                   NULL /*payload*/, 0);

        /* Long topic.metadata.refresh.interval.ms forces the heartbeat
         * to be the channel that carries topic_id changes, which is
         * what the reconciler bug rides on. */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "300000");
        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "share_consumer_new failed");

        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* ---- PHASE 1: drain the OLD generation ----
         * Single consumer in the share group => it owns every
         * partition in this generation. Explicit-ack each record so
         * the next consume_batch can proceed. */
        TEST_SAY("PHASE 1: draining %d OLD-generation record(s)\n",
                 total_per_phase);
        deadline = test_clock() + (rd_ts_t)30 * 1000 * 1000;
        while (old_got < total_per_phase && test_clock() < deadline) {
                rd_kafka_error_t *error;
                size_t cnt;
                size_t i;

                error = rd_kafka_share_poll(rkshare, 500, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        continue;
                }
                cnt = rd_kafka_messages_count(batch);
                for (i = 0; i < cnt; i++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, i);
                        if (!m->err) {
                                old_got++;
                                rd_kafka_share_acknowledge(rkshare, m);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(old_got == total_per_phase,
                    "PHASE 1: expected %d OLD records, got %d", total_per_phase,
                    old_got);

        /* Capture the consumer's member id so we can pin a target
         * assignment for it after the recreate. */
        err = rd_kafka_mock_sharegroup_get_member_ids(mcluster, group,
                                                      &member_ids, &member_cnt);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "mock_sharegroup_get_member_ids failed: %s",
                    rd_kafka_err2str(err));
        TEST_ASSERT(member_cnt == 1,
                    "expected exactly 1 member in share group, got %zu",
                    member_cnt);

        /* ---- Delete + recreate ----
         * Mock generates a fresh topic_id for the recreated topic. The
         * existing share-group member's stored assignment still
         * references the destroyed OLD topic; we override it below. */
        TEST_SAY("Recreating topic same name, same partition count\n");
        TEST_ASSERT(rd_kafka_mock_topic_delete(mcluster, topic) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "mock_topic_delete failed");
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, n_partitions,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "mock_topic_create (recreate) failed");

        /* Pin the member's target assignment to the recreated topic.
         * mock_sharegroup_target_assignment resolves the topic name
         * to the current mtopic's id at set-time, so the partition
         * list ends up carrying the NEW topic_id. The mock bumps the
         * member epoch on set so the consumer's next heartbeat
         * receives this assignment. From the consumer's point of
         * view: current rkcg_group_assignment still has the OLD-id
         * partitions from PHASE 1; the next HB target carries the
         * NEW-id partitions. That is the precise input that triggers
         * the reconciler's (topic_name, partition) hash collision. */
        new_assignment = rd_kafka_topic_partition_list_new(n_partitions);
        for (p = 0; p < n_partitions; p++)
                rd_kafka_topic_partition_list_add(new_assignment, topic, p);
        member_id_arr[0]      = member_ids[0];
        member_assignments[0] = new_assignment;
        rd_kafka_mock_sharegroup_target_assignment(
            mcluster, group, member_id_arr, member_assignments, 1);
        rd_kafka_topic_partition_list_destroy(new_assignment);

        /* Produce records to every partition of the recreated topic.
         * Pre-fix these never reach the consumer. */
        for (p = 0; p < n_partitions; p++)
                test_produce_msgs2(producer, topic, 0 /*testid*/, p,
                                   0 /*msg_base*/, n_msgs_per_part,
                                   NULL /*payload*/, 0);

        /* ---- PHASE 2: drain the NEW generation ----
         * Generous deadline so the heartbeat has time to deliver the
         * NEW target, metadata to resolve for the new topic_id, and
         * the share session to start fetching when the fix is in
         * place. Pre-fix the reconciler diff collapses
         * (name, partition) so the NEW rktps are never added to the
         * share session; this loop hits the deadline at zero. */
        TEST_SAY("PHASE 2: draining %d NEW-generation record(s)\n",
                 total_per_phase);
        deadline = test_clock() + (rd_ts_t)10 * 1000 * 1000;
        while (new_got < total_per_phase && test_clock() < deadline) {
                rd_kafka_error_t *error;
                size_t cnt;
                size_t i;

                error = rd_kafka_share_poll(rkshare, 500, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        continue;
                }
                cnt = rd_kafka_messages_count(batch);
                for (i = 0; i < cnt; i++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, i);
                        if (!m->err) {
                                new_got++;
                                rd_kafka_share_acknowledge(rkshare, m);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(new_got == total_per_phase,
                    "PHASE 2: expected %d NEW records after same-name "
                    "recreate, got %d. Cooperative reconciler likely "
                    "suppressed the NEW rktp adds because (name, partition) "
                    "collided with OLD-id entries in rkcg_group_assignment.",
                    total_per_phase, new_got);

        for (mi = 0; mi < member_cnt; mi++)
                rd_free(member_ids[mi]);
        rd_free(member_ids);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        rd_kafka_destroy(producer);
        test_mock_cluster_destroy(mcluster);
        SUB_TEST_PASS();
}

int main_0184_share_consumer_topic_recreate_local(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);
        test_timeout_set(180);
        test_recreate_during_close();
        do_test_recreate_same_name_partition_collision();
        return 0;
}