/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2025, Confluent Inc.
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
 * @name Share Acknowledgement (implicit ack) mock broker tests.
 *
 * Exercises the implicit ack flow via mock broker: records acquired
 * by a ShareFetch are acknowledged on the next ShareFetch, which
 * causes the mock broker to archive them and advance SPSO.
 */

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

        /* Create a producer targeting the mock cluster */
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
                                            const char *group_id) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *consumer;

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);

        consumer = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(consumer != NULL, "Failed to create share consumer");
        return consumer;
}

static void subscribe_topics(rd_kafka_share_t *consumer,
                             const char **topics,
                             int topic_cnt) {
        rd_kafka_topic_partition_list_t *tpl =
            rd_kafka_topic_partition_list_new(topic_cnt);
        for (int i = 0; i < topic_cnt; i++) {
                rd_kafka_topic_partition_list_add(tpl, topics[i],
                                                  RD_KAFKA_PARTITION_UA);
        }
        TEST_ASSERT(!rd_kafka_share_subscribe(consumer, tpl),
                    "Subscribe failed");
        rd_kafka_topic_partition_list_destroy(tpl);
}



/* ===================================================================
 *  Positive test scenarios
 * =================================================================== */

/**
 * @brief Basic implicit ack prevents re-delivery.
 *
 * 1. Produce 5 messages.
 * 2. Consume all 5 (first ShareFetch acquires them).
 * 3. Poll again — the next ShareFetch carries AcknowledgementBatches
 *    (ACCEPT) for the 5 records.  The mock broker archives them and
 *    advances SPSO.
 * 4. Subsequent polls should return 0 records (no re-delivery).
 */
static void do_test_implicit_ack_no_redelivery(void) {
        const char *topic = "kip932_ack_no_redeliver";
        const int msgcnt  = 5;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed, extra;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-noredeliver");
        subscribe_topics(consumer, &topic, 1);

        /* Consume all records. */
        consumed = test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("ack_no_redelivery: consumed %d/%d\n", consumed, msgcnt);

        /* Poll again to trigger the implicit ack (piggybacked on the
         * next ShareFetch).  Expect 0 new records. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_no_redelivery: extra %d/0 (should be 0)\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt && extra == 0,
                    "Expected consumed=%d extra=0, got consumed=%d extra=%d",
                    msgcnt, consumed, extra);
        SUB_TEST_PASS();
}

/**
 * @brief After implicit ack, only newly-produced records are delivered.
 *
 * 1. Produce batch A (3 messages).
 * 2. Consumer A consumes batch A and triggers implicit ack.
 * 3. Consumer A closes.
 * 4. Produce batch B (3 messages).
 * 5. Consumer B (same group) consumes — should receive only batch B
 *    because batch A was acked (ARCHIVED, SPSO advanced).
 */
static void do_test_implicit_ack_with_new_records(void) {
        const char *topic = "kip932_ack_new_records";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b, extra;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        /* Batch A */
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 3);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-newrecords");
        subscribe_topics(consumer, &topic, 1);

        consumed_a = test_share_consume_msgs(consumer, 3, 40, 500, NULL, 0);
        TEST_SAY("ack_new_records: A consumed %d/3\n", consumed_a);

        /* Trigger implicit ack for batch A. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_new_records: A extra %d/0 (ack sent)\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Batch B */
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 3);

        /* Consumer B: same group — batch A is archived, should get
         * only batch B. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-newrecords");
        subscribe_topics(consumer, &topic, 1);

        consumed_b = test_share_consume_msgs(consumer, 3, 40, 500, NULL, 0);
        TEST_SAY("ack_new_records: B consumed %d/3 (batch B only)\n",
                 consumed_b);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == 3 && extra == 0 && consumed_b == 3,
                    "Expected A=3 extra=0 B=3, got A=%d extra=%d B=%d",
                    consumed_a, extra, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Acked records are not visible to a different consumer that
 *        joins the same share group afterwards.
 *
 * 1. Consumer A consumes all records and triggers implicit ack.
 * 2. Consumer A closes.
 * 3. Consumer B joins the same group — should see 0 records because
 *    the records are ARCHIVED and SPSO has advanced.
 */
static void do_test_implicit_ack_cross_consumer(void) {
        const char *topic = "kip932_ack_cross_consumer";
        const int msgcnt  = 5;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer_a, *consumer_b;
        int consumed_a, consumed_b, extra;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A: consume and ack. */
        consumer_a = new_share_consumer(ctx.bootstraps, "sg-ack-cross");
        subscribe_topics(consumer_a, &topic, 1);

        consumed_a =
            test_share_consume_msgs(consumer_a, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("ack_cross_consumer: A consumed %d/%d\n", consumed_a, msgcnt);

        /* Trigger implicit ack. */
        extra = test_share_consume_msgs(consumer_a, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_cross_consumer: A extra %d/0\n", extra);

        test_share_consumer_close(consumer_a);
        test_share_destroy(consumer_a);

        /* Consumer B: same group, should see nothing. */
        consumer_b = new_share_consumer(ctx.bootstraps, "sg-ack-cross");
        subscribe_topics(consumer_b, &topic, 1);

        consumed_b = test_share_consume_msgs(consumer_b, 1, 15, 500, NULL, 0);
        TEST_SAY("ack_cross_consumer: B consumed %d/0 (should be 0)\n",
                 consumed_b);

        test_share_consumer_close(consumer_b);
        test_share_destroy(consumer_b);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && extra == 0 && consumed_b == 0,
                    "Expected A=%d extra=0 B=0, got A=%d extra=%d B=%d", msgcnt,
                    consumed_a, extra, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Implicit ack works across multiple partitions.
 *
 * 1. Create a 2-partition topic.
 * 2. Produce messages (distributed across partitions by the partitioner).
 * 3. Consume all messages.
 * 4. Trigger implicit ack.
 * 5. Poll again — should get 0 (acked from all partitions).
 */
static void do_test_implicit_ack_multi_partition(void) {
        const char *topic = "kip932_ack_multi_part";
        const int msgcnt  = 6;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed, extra;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 2, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-multipart");
        subscribe_topics(consumer, &topic, 1);

        consumed = test_share_consume_msgs(consumer, msgcnt, 60, 500, NULL, 0);
        TEST_SAY("ack_multi_partition: consumed %d/%d\n", consumed, msgcnt);

        /* Trigger implicit ack. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_multi_partition: extra %d/0\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt && extra == 0,
                    "Expected consumed=%d extra=0, got consumed=%d extra=%d",
                    msgcnt, consumed, extra);
        SUB_TEST_PASS();
}

/**
 * @brief Multiple rounds of produce -> consume -> ack with new consumers.
 *
 * Each round:
 *   1. Produce N messages.
 *   2. New consumer joins the same share group.
 *   3. Consumer should get exactly the N new records (records from
 *      previous rounds were acked and SPSO advanced).
 *   4. Consumer triggers implicit ack and closes.
 *
 * This verifies that SPSO advancement from acks in earlier rounds
 * persists correctly across consumer lifetimes.
 */
static void do_test_implicit_ack_multiple_rounds(void) {
        const char *topic   = "kip932_ack_multi_round";
        const int per_round = 2;
        const int rounds    = 3;
        test_ctx_t ctx      = test_ctx_new();
        int total_consumed  = 0;
        int round_ok        = 1;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        for (int r = 0; r < rounds; r++) {
                rd_kafka_share_t *consumer;
                int got, extra;

                test_produce_msgs_simple(ctx.producer, topic,
                                         RD_KAFKA_PARTITION_UA, per_round);

                consumer =
                    new_share_consumer(ctx.bootstraps, "sg-ack-multiround");
                subscribe_topics(consumer, &topic, 1);

                got = test_share_consume_msgs(consumer, per_round, 40, 500,
                                              NULL, 0);
                TEST_SAY("ack_multiple_rounds: round %d consumed %d/%d\n",
                         r + 1, got, per_round);
                total_consumed += got;
                if (got != per_round)
                        round_ok = 0;

                /* Trigger implicit ack. */
                extra = test_share_consume_msgs(consumer, 1, 5, 500, NULL, 0);
                if (extra != 0) {
                        TEST_SAY(
                            "ack_multiple_rounds: round %d extra %d "
                            "(expected 0)\n",
                            r + 1, extra);
                        round_ok = 0;
                }

                test_share_consumer_close(consumer);
                test_share_destroy(consumer);
        }

        TEST_SAY("ack_multiple_rounds: total %d/%d\n", total_consumed,
                 per_round * rounds);

        test_ctx_destroy(&ctx);

        TEST_ASSERT(round_ok && total_consumed == per_round * rounds,
                    "Expected %d total, got %d (round_ok=%d)",
                    per_round * rounds, total_consumed, round_ok);
        SUB_TEST_PASS();
}

/**
 * @brief Implicit ack with a single record (boundary case).
 *
 * Produce exactly 1 message, consume it, trigger implicit ack,
 * verify no re-delivery.  Tests the minimum-batch-size edge case for
 * AcquiredRecords ranges and SPSO advancement.
 */
static void do_test_implicit_ack_single_record(void) {
        const char *topic = "kip932_ack_single";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed, extra;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 1);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-single");
        subscribe_topics(consumer, &topic, 1);

        consumed = test_share_consume_msgs(consumer, 1, 40, 500, NULL, 0);
        TEST_SAY("ack_single_record: consumed %d/1\n", consumed);

        /* Trigger implicit ack. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_single_record: extra %d/0 (should be 0)\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 1 && extra == 0,
                    "Expected consumed=1 extra=0, got consumed=%d extra=%d",
                    consumed, extra);
        SUB_TEST_PASS();
}

/**
 * @brief Implicit ack with a large batch of records.
 *
 * Produce 100 messages, consume all, trigger implicit ack, verify 0
 * on subsequent polls.  Tests ack handling at scale — many records
 * in a single AcquiredRecords range and SPSO advancement over a
 * large offset span.
 */
static void do_test_implicit_ack_large_batch(void) {
        const char *topic = "kip932_ack_large";
        const int msgcnt  = 100;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed, extra;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-large");
        subscribe_topics(consumer, &topic, 1);

        consumed = test_share_consume_msgs(consumer, msgcnt, 80, 500, NULL, 0);
        TEST_SAY("ack_large_batch: consumed %d/%d\n", consumed, msgcnt);

        /* Trigger implicit ack. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_large_batch: extra %d/0 (should be 0)\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt && extra == 0,
                    "Expected consumed=%d extra=0, got consumed=%d extra=%d",
                    msgcnt, consumed, extra);
        SUB_TEST_PASS();
}

/**
 * @brief Implicit ack across multiple topics in the same share group.
 *
 * 1. Create 2 topics, produce messages to both.
 * 2. Subscribe a single consumer to both topics via the same group.
 * 3. Consume all messages from both topics.
 * 4. Trigger implicit ack.
 * 5. Consumer B joins the same group — should see 0 records from
 *    either topic (both acked independently).
 */
static void do_test_implicit_ack_multi_topic(void) {
        const char *topic_a = "kip932_ack_mtopic_a";
        const char *topic_b = "kip932_ack_mtopic_b";
        const char *both[]  = {topic_a, topic_b};
        test_ctx_t ctx      = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed, extra, consumed_b;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_a, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic A");
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_b, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic B");

        test_produce_msgs_simple(ctx.producer, topic_a, RD_KAFKA_PARTITION_UA,
                                 3);
        test_produce_msgs_simple(ctx.producer, topic_b, RD_KAFKA_PARTITION_UA,
                                 3);

        /* Consumer A: subscribe to both, consume all 6, ack. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-mtopic");
        subscribe_topics(consumer, both, 2);

        consumed = test_share_consume_msgs(consumer, 6, 60, 500, NULL, 0);
        TEST_SAY("ack_multi_topic: consumed %d/6 from both\n", consumed);

        /* Trigger implicit ack. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_multi_topic: extra %d/0\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Consumer B: same group — should see 0 from either topic. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-mtopic");
        subscribe_topics(consumer, both, 2);

        consumed_b = test_share_consume_msgs(consumer, 1, 15, 500, NULL, 0);
        TEST_SAY("ack_multi_topic: B consumed %d/0 (should be 0)\n",
                 consumed_b);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 6 && extra == 0 && consumed_b == 0,
                    "Expected consumed=6 extra=0 B=0, got %d %d %d", consumed,
                    extra, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Implicit ack with records from separate message sets.
 *
 * Produce records one at a time with a flush in between, creating
 * separate msgsets on the mock partition.  Then consume all, ack,
 * and verify 0 on subsequent polls.
 *
 * This validates that the ack machinery handles records spanning
 * multiple RecordBatch wire objects.
 */
static void do_test_implicit_ack_multi_msgset(void) {
        const char *topic = "kip932_ack_multi_msgset";
        const int msgcnt  = 5;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed, extra;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        /* Produce each message individually with a flush in between,
         * guaranteeing separate msgsets on the mock partition. */
        for (int i = 0; i < msgcnt; i++) {
                char payload[64];
                snprintf(payload, sizeof(payload), "msgset-%d", i);
                TEST_ASSERT(rd_kafka_producev(
                                ctx.producer, RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_VALUE(payload, strlen(payload)),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_END) == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Produce failed");
                rd_kafka_flush(ctx.producer, 5000);
        }

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-multimsgset");
        subscribe_topics(consumer, &topic, 1);

        consumed = test_share_consume_msgs(consumer, msgcnt, 60, 500, NULL, 0);
        TEST_SAY("ack_multi_msgset: consumed %d/%d\n", consumed, msgcnt);

        /* Trigger implicit ack. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_multi_msgset: extra %d/0 (should be 0)\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt && extra == 0,
                    "Expected consumed=%d extra=0, got consumed=%d extra=%d",
                    msgcnt, consumed, extra);
        SUB_TEST_PASS();
}

/* ===================================================================
 *  Negative test scenarios
 * =================================================================== */

/**
 * @brief Crash (no ack) -> records re-delivered after lock expiry.
 *
 * Consumer A consumes records but is destroyed without closing and
 * without sending a subsequent ShareFetch that would carry the ack.
 * After the acquisition lock expires, Consumer B should receive the
 * same records.
 */
static void do_test_crash_before_ack_redelivery(void) {
        const char *topic = "kip932_ack_crash_redeliver";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Short lock so the test doesn't wait too long. */
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A: acquire records, then crash (no close, no ack). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-crash-redeliver");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("crash_before_ack: A consumed %d/%d\n", consumed_a, msgcnt);
        test_share_destroy(consumer); /* crash — no close */

        /* Wait for lock expiry (session_timeout=500ms + margin). */
        rd_usleep(1500 * 1000, NULL);

        /* Consumer B: should get the same records (re-delivered). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-crash-redeliver");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("crash_before_ack: B consumed %d/%d (re-delivered)\n",
                 consumed_b, msgcnt);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt,
                    "Expected A=%d B=%d, got A=%d B=%d", msgcnt, msgcnt,
                    consumed_a, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Crash -> re-delivery -> ack stops further re-delivery.
 *
 * 1. Consumer A consumes records but crashes (no ack).
 * 2. Locks expire, records become AVAILABLE again.
 * 3. Consumer B consumes the re-delivered records and triggers an
 *    implicit ack via the next poll.
 * 4. Consumer C joins — should see 0 records (acked by B).
 */
static void do_test_crash_then_ack_stops_redelivery(void) {
        const char *topic = "kip932_ack_crash_then_ack";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b, consumed_c, extra;

        SUB_TEST();
        ctx = test_ctx_new();

        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A: acquire and crash. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-crash-then-ack");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("crash_then_ack: A consumed %d/%d (will crash)\n", consumed_a,
                 msgcnt);
        test_share_destroy(consumer);
        rd_usleep(1500 * 1000, NULL); /* wait for lock expiry */

        /* Consumer B: re-delivery, then ack via next poll. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-crash-then-ack");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("crash_then_ack: B consumed %d/%d (re-delivered)\n",
                 consumed_b, msgcnt);

        /* Trigger implicit ack. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("crash_then_ack: B extra %d/0\n", extra);
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Consumer C: should see 0 — records were acked by B. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-crash-then-ack");
        subscribe_topics(consumer, &topic, 1);
        consumed_c = test_share_consume_msgs(consumer, 1, 15, 500, NULL, 0);
        TEST_SAY("crash_then_ack: C consumed %d/0 (should be 0)\n", consumed_c);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt &&
                        extra == 0 && consumed_c == 0,
                    "Expected A=%d B=%d extra=0 C=0, got A=%d B=%d extra=%d "
                    "C=%d",
                    msgcnt, msgcnt, consumed_a, consumed_b, extra, consumed_c);
        SUB_TEST_PASS();
}

/**
 * @brief Session expiry via heartbeat failure causes pending ack to be lost.
 *
 * 1. Consumer A acquires records normally.
 * 2. Push many SGHB errors -> heartbeats fail -> member is evicted.
 * 3. Consumer A is destroyed (crash, no ack delivered).
 * 4. The broker releases A's locks upon eviction.
 * 5. Consumer B joins -> gets the same records (re-delivered).
 */
static void do_test_session_expiry_invalidates_ack(void) {
        const char *topic = "kip932_ack_session_expire";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Short session timeout so eviction happens quickly. */
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A: consume records (acquires them). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-session-expire");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("session_expiry: A consumed %d/%d\n", consumed_a, msgcnt);

        /* Block SGHB so heartbeats fail -> member evicted. */
        rd_kafka_mock_push_request_errors(
            ctx.mcluster, RD_KAFKAP_ShareGroupHeartbeat, 20,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE);

        /* Wait for member eviction (session_timeout=500ms + margin). */
        rd_usleep(1500 * 1000, NULL);

        /* Crash consumer A without acking. */
        test_share_destroy(consumer);

        /* Consumer B: records should be re-delivered (locks released
         * when A's membership was evicted). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-session-expire");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("session_expiry: B consumed %d/%d (re-delivered)\n",
                 consumed_b, msgcnt);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt,
                    "Expected A=%d B=%d, got A=%d B=%d", msgcnt, msgcnt,
                    consumed_a, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Records archived by max_delivery_count without any ack.
 *
 * 1. Set max_delivery_attempts=2.
 * 2. Consumer A acquires records and crashes (delivery 1).
 * 3. Consumer B acquires same records and crashes (delivery 2 = max).
 * 4. Consumer C joins — should see 0 records because the broker
 *    archived them after the delivery count was exhausted.
 */
static void do_test_max_delivery_without_ack(void) {
        const char *topic = "kip932_ack_maxdel_noack";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b, consumed_c;

        SUB_TEST();
        ctx = test_ctx_new();

        rd_kafka_mock_sharegroup_set_max_delivery_attempts(ctx.mcluster, 2);
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Delivery 1: Consumer A acquires and crashes. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-maxdel-noack");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("max_delivery_no_ack: A consumed %d/%d (delivery 1)\n",
                 consumed_a, msgcnt);
        test_share_destroy(consumer);
        rd_usleep(1500 * 1000, NULL); /* wait for lock expiry */

        /* Delivery 2 = max: Consumer B acquires and crashes. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-maxdel-noack");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("max_delivery_no_ack: B consumed %d/%d (delivery 2)\n",
                 consumed_b, msgcnt);
        test_share_destroy(consumer);
        rd_usleep(1500 * 1000, NULL); /* wait for lock expiry + archival */

        /* Delivery 3 attempt: records should be archived (delivery
         * count exhausted). Consumer C sees 0. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-maxdel-noack");
        subscribe_topics(consumer, &topic, 1);
        consumed_c = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("max_delivery_no_ack: C consumed %d/0 (archived)\n",
                 consumed_c);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt &&
                        consumed_c == 0,
                    "Expected A=%d B=%d C=0, got A=%d B=%d C=%d", msgcnt,
                    msgcnt, consumed_a, consumed_b, consumed_c);
        SUB_TEST_PASS();
}

/**
 * @brief ShareFetch error injection prevents ack from being processed.
 *
 * 1. Consumer A acquires records.
 * 2. Inject ShareFetch transport errors on all brokers so the next
 *    ShareFetch (carrying the ack) causes a disconnect.
 * 3. Consumer A is destroyed (crash — ack was never processed).
 * 4. Wait for locks to expire.
 * 5. Consumer B joins — should get the same records (re-delivered).
 */
static void do_test_sharefetch_error_drops_ack(void) {
        const char *topic = "kip932_ack_sf_error";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b;

        SUB_TEST();
        ctx = test_ctx_new();

        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A acquires records. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-sf-error");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("sf_error_drops_ack: A consumed %d/%d\n", consumed_a, msgcnt);

        /* Inject ShareFetch transport errors — the next ShareFetch
         * (which would carry acks) will cause a disconnect. */
        rd_kafka_mock_push_request_errors(
            ctx.mcluster, RD_KAFKAP_ShareFetch, 10,
            RD_KAFKA_RESP_ERR__TRANSPORT, RD_KAFKA_RESP_ERR__TRANSPORT,
            RD_KAFKA_RESP_ERR__TRANSPORT, RD_KAFKA_RESP_ERR__TRANSPORT,
            RD_KAFKA_RESP_ERR__TRANSPORT, RD_KAFKA_RESP_ERR__TRANSPORT,
            RD_KAFKA_RESP_ERR__TRANSPORT, RD_KAFKA_RESP_ERR__TRANSPORT,
            RD_KAFKA_RESP_ERR__TRANSPORT, RD_KAFKA_RESP_ERR__TRANSPORT);

        /* Crash consumer A (ack never delivered). */
        test_share_destroy(consumer);
        rd_usleep(1500 * 1000, NULL); /* wait for lock expiry */

        /* Clear any remaining errors. */
        rd_kafka_mock_clear_request_errors(ctx.mcluster, RD_KAFKAP_ShareFetch);

        /* Consumer B should get re-delivered records. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-sf-error");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("sf_error_drops_ack: B consumed %d/%d (re-delivered)\n",
                 consumed_b, msgcnt);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt,
                    "Expected A=%d B=%d, got A=%d B=%d", msgcnt, msgcnt,
                    consumed_a, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Un-acked records from a forgotten topic remain available.
 *
 * 1. Subscribe to topic_a and topic_b, consume from both.
 * 2. Crash consumer immediately (no ack for either topic).
 * 3. Wait for lock expiry so records become AVAILABLE.
 * 4. Consumer B subscribes to topic_a only, consumes and acks topic_a.
 * 5. Consumer C subscribes to topic_b only — should see topic_b's
 *    records (they were never acked, only released by lock expiry).
 */
static void do_test_forgotten_topic_releases_not_acks(void) {
        const char *topic_a = "kip932_ack_forget_a";
        const char *topic_b = "kip932_ack_forget_b";
        const char *both[]  = {topic_a, topic_b};
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_both, consumed_a, consumed_b, extra;

        SUB_TEST();
        ctx = test_ctx_new();

        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 2000);
        rd_kafka_mock_sharegroup_set_heartbeat_interval(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_a, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic A");
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_b, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic B");

        test_produce_msgs_simple(ctx.producer, topic_a, RD_KAFKA_PARTITION_UA,
                                 2);
        test_produce_msgs_simple(ctx.producer, topic_b, RD_KAFKA_PARTITION_UA,
                                 2);

        /* Consumer A: subscribe to both, consume all 4, then crash. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-forget");
        subscribe_topics(consumer, both, 2);

        consumed_both = test_share_consume_msgs(consumer, 4, 60, 500, NULL, 0);
        TEST_SAY("forgotten_releases: consumed %d/4 from both\n",
                 consumed_both);

        /* Crash — no ack for either topic. */
        test_share_destroy(consumer);
        rd_usleep(3000 * 1000, NULL); /* wait for session + lock expiry */

        /* Consumer B: subscribe to topic_a only, consume and ack. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-forget");
        subscribe_topics(consumer, &topic_a, 1);

        consumed_a = test_share_consume_msgs(consumer, 2, 40, 500, NULL, 0);
        TEST_SAY("forgotten_releases: B consumed %d/2 from topic_a\n",
                 consumed_a);

        /* Trigger implicit ack for topic_a. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Consumer C: subscribe to topic_b only.
         * Topic_b's records were never acked — should be available. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-forget");
        subscribe_topics(consumer, &topic_b, 1);

        consumed_b = test_share_consume_msgs(consumer, 2, 40, 500, NULL, 0);
        TEST_SAY(
            "forgotten_releases: C consumed %d/2 from topic_b "
            "(should be re-delivered)\n",
            consumed_b);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        (void)extra;
        TEST_ASSERT(consumed_both >= 4 && consumed_a == 2 && consumed_b == 2,
                    "Expected both>=4 A=2 B=2, got both=%d A=%d B=%d",
                    consumed_both, consumed_a, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Multiple consumers crash sequentially without acking.
 *
 * A, B, C each acquire the same records and crash without acking.
 * Each re-delivery round hands the same records to the next consumer
 * after lock expiry.  This validates that without any ack, records
 * cycle through ACQUIRED->AVAILABLE indefinitely (bounded by
 * max_delivery_count, which we set high here).
 */
static void do_test_multi_consumer_cascade_crash(void) {
        const char *topic = "kip932_ack_cascade_crash";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b, consumed_c;

        SUB_TEST();
        ctx = test_ctx_new();

        /* High max delivery so records don't get archived. */
        rd_kafka_mock_sharegroup_set_max_delivery_attempts(ctx.mcluster, 10);
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A: acquire and crash. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-cascade-crash");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("cascade_crash: A consumed %d/%d\n", consumed_a, msgcnt);
        test_share_destroy(consumer);
        rd_usleep(1500 * 1000, NULL);

        /* Consumer B: re-acquire and crash. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-cascade-crash");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("cascade_crash: B consumed %d/%d\n", consumed_b, msgcnt);
        test_share_destroy(consumer);
        rd_usleep(1500 * 1000, NULL);

        /* Consumer C: re-acquire and crash. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-cascade-crash");
        subscribe_topics(consumer, &topic, 1);
        consumed_c =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("cascade_crash: C consumed %d/%d\n", consumed_c, msgcnt);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt &&
                        consumed_c == msgcnt,
                    "Expected A=%d B=%d C=%d, got A=%d B=%d C=%d", msgcnt,
                    msgcnt, msgcnt, consumed_a, consumed_b, consumed_c);
        SUB_TEST_PASS();
}

/**
 * @brief Lock expires before the ack-carrying ShareFetch arrives.
 *
 * 1. Set a very short record lock duration (200ms).
 * 2. Consumer A acquires records.
 * 3. Inject high RTT on broker 1 so the next ShareFetch (carrying
 *    the ack) is delayed beyond the lock duration.
 * 4. Lock expires -> records become AVAILABLE.
 * 5. Consumer A is destroyed.
 * 6. Consumer B should be able to get the same records.
 */
static void do_test_lock_expiry_before_ack(void) {
        const char *topic = "kip932_ack_lock_expire";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Very short lock, long session timeout. */
        rd_kafka_mock_sharegroup_set_record_lock_duration(ctx.mcluster, 200);
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 10000);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A acquires records. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-lockexpire");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("lock_expiry_before_ack: A consumed %d/%d\n", consumed_a,
                 msgcnt);

        /* Inject high RTT on all brokers so the next ShareFetch
         * (carrying the ack) is delayed well past lock expiry. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 1, 3000);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 2, 3000);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 3, 3000);

        /* Wait for lock to expire (200ms + margin), then crash. */
        rd_usleep(800 * 1000, NULL);
        test_share_destroy(consumer);

        /* Clear RTT so consumer B can operate normally. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 1, 0);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 2, 0);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 3, 0);

        /* Consumer B should get the records — locks expired before
         * A's ack could be delivered. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-lockexpire");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("lock_expiry_before_ack: B consumed %d/%d\n", consumed_b,
                 msgcnt);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt,
                    "Expected A=%d B=%d, got A=%d B=%d", msgcnt, msgcnt,
                    consumed_a, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Empty topic produces no ack side effects.
 *
 * 1. Subscribe to an empty topic, poll several times (no records,
 *    no AcquiredRecords, no acks sent).
 * 2. Produce messages.
 * 3. Consumer should consume them normally.
 * 4. Ack them normally (implicit ack via next poll).
 * 5. Verify 0 after ack.
 */
static void do_test_empty_topic_no_ack_side_effects(void) {
        const char *topic = "kip932_ack_empty_topic";
        const int msgcnt  = 3;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed_empty, consumed, extra;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-empty-topic");
        subscribe_topics(consumer, &topic, 1);

        /* Phase 1: Poll empty topic — no records, no acks. */
        consumed_empty = test_share_consume_msgs(consumer, 1, 5, 500, NULL, 0);
        TEST_SAY("empty_topic: phase1 consumed %d/0 (should be 0)\n",
                 consumed_empty);

        /* Phase 2: Produce messages, then close this consumer and
         * open a new one to avoid incremental session issues. */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-empty-topic");
        subscribe_topics(consumer, &topic, 1);

        consumed = test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("empty_topic: phase2 consumed %d/%d\n", consumed, msgcnt);

        /* Phase 3: Trigger implicit ack, verify 0. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("empty_topic: phase3 extra %d/0 (should be 0)\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_empty == 0 && consumed == msgcnt && extra == 0,
                    "Expected empty=0 consumed=%d extra=0, got %d %d %d",
                    msgcnt, consumed_empty, consumed, extra);
        SUB_TEST_PASS();
}

/**
 * @brief Coordinator failover — consumer recovers and acks new records.
 *
 * 1. Consumer A consumes and acks records (happy path).
 * 2. Push SGHB errors -> member evicted.
 * 3. Clear errors -> member re-joins.
 * 4. Produce new records.
 * 5. Consumer (new instance, same group) consumes and acks new records.
 * 6. Consumer C joins — should see 0 (everything acked).
 */
static void do_test_coordinator_failover_ack_recovery(void) {
        const char *topic = "kip932_ack_coord_failover";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b, consumed_c, extra;

        SUB_TEST();
        ctx = test_ctx_new();

        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        /* Phase 1: Consumer A consumes and acks normally. */
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-coord-failover");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("coord_failover: A consumed %d/%d\n", consumed_a, msgcnt);

        /* Trigger implicit ack. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("coord_failover: A extra %d/0\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Phase 2: Temporarily push SGHB errors (simulating coordinator
         * failover). Any consumer joining now will fail heartbeats. */
        rd_kafka_mock_push_request_errors(
            ctx.mcluster, RD_KAFKAP_ShareGroupHeartbeat, 10,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE);

        /* Wait for errors to start draining, then produce new records. */
        rd_usleep(1000 * 1000, NULL);
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Phase 3: Errors drain, new consumer B joins and consumes
         * the newly produced records (A's records are already acked). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-coord-failover");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 60, 500, NULL, 0);
        TEST_SAY("coord_failover: B consumed %d/%d\n", consumed_b, msgcnt);

        /* Trigger implicit ack for B's records. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("coord_failover: B extra %d/0\n", extra);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Phase 4: Consumer C — everything is acked, should see 0. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-coord-failover");
        subscribe_topics(consumer, &topic, 1);
        consumed_c = test_share_consume_msgs(consumer, 1, 15, 500, NULL, 0);
        TEST_SAY("coord_failover: C consumed %d/0 (should be 0)\n", consumed_c);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt &&
                        consumed_c == 0,
                    "Expected A=%d B=%d C=0, got A=%d B=%d C=%d", msgcnt,
                    msgcnt, consumed_a, consumed_b, consumed_c);
        SUB_TEST_PASS();
}

/**
 * @brief Test that ack validation returns INVALID_RECORD_STATE when the
 *        record's lock has expired and was re-acquired by another consumer.
 *
 * Consumer A acquires records, locks expire, consumer B re-acquires and
 * successfully acks.  The records should not be redelivered a third time
 * (consumer B's ack succeeded because the mock broker now correctly
 * reports INVALID_RECORD_STATE for stale acks and honours valid ones).
 */
static void do_test_ack_after_lock_expiry_redelivers(void) {
        const char *topic = "kip932_ack_invalid_state";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer_a, *consumer_b, *consumer_c;
        int consumed_a, consumed_b, consumed_c;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Short lock duration so locks expire quickly. */
        rd_kafka_mock_sharegroup_set_record_lock_duration(ctx.mcluster, 200);
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 10000);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A acquires records. */
        consumer_a = new_share_consumer(ctx.bootstraps, "sg-ack-invalid-state");
        subscribe_topics(consumer_a, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer_a, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("ack_invalid_state: A consumed %d/%d\n", consumed_a, msgcnt);

        /* Inject RTT so A's ack is delayed past lock expiry. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 1, 3000);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 2, 3000);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 3, 3000);

        /* Wait for lock to expire. */
        rd_usleep(800 * 1000, NULL);

        /* Destroy A without close — ack never delivered. */
        rd_kafka_share_destroy(consumer_a);

        /* Clear RTT. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 1, 0);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 2, 0);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 3, 0);

        /* Consumer B re-acquires (locks expired) and acks implicitly
         * by doing a second poll (which piggybacks the ack on the next
         * ShareFetch). */
        consumer_b = new_share_consumer(ctx.bootstraps, "sg-ack-invalid-state");
        subscribe_topics(consumer_b, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer_b, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("ack_invalid_state: B consumed %d/%d\n", consumed_b, msgcnt);

        /* Second poll triggers implicit ack for B's records. */
        test_share_consume_msgs(consumer_b, 1, 3, 500, NULL, 0);

        rd_kafka_share_consumer_close(consumer_b);
        rd_kafka_share_destroy(consumer_b);

        /* Consumer C should get 0 records — B's ack succeeded. */
        consumer_c = new_share_consumer(ctx.bootstraps, "sg-ack-invalid-state");
        subscribe_topics(consumer_c, &topic, 1);
        consumed_c = test_share_consume_msgs(consumer_c, 1, 5, 500, NULL, 0);
        TEST_SAY("ack_invalid_state: C consumed %d (expected 0)\n", consumed_c);

        rd_kafka_share_consumer_close(consumer_c);
        rd_kafka_share_destroy(consumer_c);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt, "A: expected %d consumed, got %d",
                    msgcnt, consumed_a);
        TEST_ASSERT(consumed_b == msgcnt, "B: expected %d consumed, got %d",
                    msgcnt, consumed_b);
        TEST_ASSERT(consumed_c == 0, "C: expected 0 consumed (B acked), got %d",
                    consumed_c);
        SUB_TEST_PASS();
}

/**
 * @brief Test that two consumers can sequentially acquire, ack, and
 *        advance SPSO without interference.
 *
 * Consumer A acquires records 0-2 and acks them (implicit ack via
 * second poll).  Consumer B then gets records 3-5 (not 0-2, since
 * those were acked and SPSO advanced).  Validates that the ack
 * error handling doesn't interfere with normal ack flow.
 */
static void do_test_ack_success_advances_spso(void) {
        const char *topic = "kip932_ack_spso_advance";
        const int msgcnt  = 6;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b;

        SUB_TEST();
        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A acquires first batch. MaxRecords in the client
         * defaults to a large value, so it will get all 6.  We use
         * the max_record_locks limit to cap acquisition at 3. */
        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 3);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-spso");
        subscribe_topics(consumer, &topic, 1);
        consumed_a = test_share_consume_msgs(consumer, 3, 30, 500, NULL, 0);
        TEST_SAY("ack_spso: A consumed %d/3\n", consumed_a);

        /* Second poll triggers implicit ack for A's records. */
        test_share_consume_msgs(consumer, 1, 3, 500, NULL, 0);

        /* Close A cleanly. */
        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);

        /* Remove lock limit so B can get remaining records. */
        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 0);

        /* Consumer B should get records 3-5 (SPSO advanced past 0-2). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-spso");
        subscribe_topics(consumer, &topic, 1);
        consumed_b = test_share_consume_msgs(consumer, 3, 30, 500, NULL, 0);
        TEST_SAY("ack_spso: B consumed %d/3\n", consumed_b);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == 3, "A: expected 3 consumed, got %d",
                    consumed_a);
        TEST_ASSERT(consumed_b == 3, "B: expected 3 consumed, got %d",
                    consumed_b);
        SUB_TEST_PASS();
}


/**
 * @brief epoch=-1 (final fetch) must not acquire new records.
 *
 * Consumer A acquires two batches (max_record_locks=3 caps each),
 * then closes.  The close sends epoch=-1 which releases A's
 * un-acked records but must not acquire anything new.
 * Consumer B picks up the released records; consumer C sees 0.
 */
static void do_test_final_fetch_no_acquisition(void) {
        const char *topic = "kip932_final_fetch_no_acq";
        const int msgcnt  = 6;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer, *consumer_c;
        int consumed_a, consumed_a2, consumed_b, consumed_c, extra;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Limit acquisition to 3 records at a time. */
        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 3);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-final-no-acq");
        subscribe_topics(consumer, &topic, 1);

        consumed_a = test_share_consume_msgs(consumer, 3, 40, 500, NULL, 0);
        TEST_SAY("final_fetch_no_acq: A batch1 consumed %d/3\n", consumed_a);

        /* Implicit ack for batch1, acquires batch2. */
        consumed_a2 = test_share_consume_msgs(consumer, 3, 40, 500, NULL, 0);
        TEST_SAY("final_fetch_no_acq: A batch2 consumed %d/3\n", consumed_a2);

        /* Close sends epoch=-1; batch2 records released. */
        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);

        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 0);

        /* B picks up the released batch2 records. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-final-no-acq");
        subscribe_topics(consumer, &topic, 1);

        consumed_b = test_share_consume_msgs(consumer, 3, 40, 500, NULL, 0);
        TEST_SAY("final_fetch_no_acq: B consumed %d/3\n", consumed_b);

        extra = test_share_consume_msgs(consumer, 1, 5, 500, NULL,
                                        0); /* ack B's records */

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);

        /* C should see nothing — everything acked. */
        consumer_c = new_share_consumer(ctx.bootstraps, "sg-final-no-acq");
        subscribe_topics(consumer_c, &topic, 1);
        consumed_c = test_share_consume_msgs(consumer_c, 1, 10, 500, NULL, 0);
        TEST_SAY("final_fetch_no_acq: C consumed %d/0 (should be 0)\n",
                 consumed_c);
        rd_kafka_share_consumer_close(consumer_c);
        rd_kafka_share_destroy(consumer_c);

        TEST_ASSERT(consumed_c == 0, "C: expected 0 consumed, got %d",
                    consumed_c);

        test_ctx_destroy(&ctx);

        (void)extra;
        TEST_ASSERT(consumed_a == 3 && consumed_a2 == 3 && consumed_b == 3,
                    "Expected A1=3 A2=3 B=3, got A1=%d A2=%d B=%d", consumed_a,
                    consumed_a2, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Ack for records past SPSO (log retention) succeeds silently.
 *
 * Consumer A acquires 5 records, then log retention moves
 * start_offset past the first 3.  The implicit ack covers all 5,
 * including the 3 that are now below SPSO.  Those must be silently
 * accepted rather than returning INVALID_RECORD_STATE.
 * Consumer B should see 0.
 */
static void do_test_ack_after_log_retention_silent(void) {
        const char *topic = "kip932_ack_log_retention_silent";
        const int msgcnt  = 5;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b, extra;

        SUB_TEST();
        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-log-ret-silent");
        subscribe_topics(consumer, &topic, 1);

        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("ack_log_retention_silent: A consumed %d/%d\n", consumed_a,
                 msgcnt);

        /* Move start_offset past first 3 records (simulates retention). */
        rd_kafka_mock_partition_set_follower_wmarks(ctx.mcluster, topic, 0, 3,
                                                    -1);

        /* Implicit ack covers all 5; offsets 0-2 are below SPSO now. */
        extra = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_log_retention_silent: A extra %d/0\n", extra);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);

        /* B should see nothing. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-log-ret-silent");
        subscribe_topics(consumer, &topic, 1);
        consumed_b = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_log_retention_silent: B consumed %d/0 (should be 0)\n",
                 consumed_b);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == 0,
                    "Expected A=%d B=0, got A=%d B=%d", msgcnt, consumed_a,
                    consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Ack atomicity — expired locks cause full batch rejection.
 *
 * Consumer A acquires records but its locks expire before the ack
 * arrives (RTT delay).  Because acks are atomic per partition, the
 * entire batch is rejected rather than partially applied.
 * Consumer B re-acquires, acks, and consumer C sees 0.
 */
static void do_test_ack_atomicity_lock_expiry(void) {
        const char *topic = "kip932_ack_atomicity";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b, consumed_c;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Very short lock so it expires before A can ack. */
        rd_kafka_mock_sharegroup_set_record_lock_duration(ctx.mcluster, 200);
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 10000);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-atomicity");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("ack_atomicity: A consumed %d/%d\n", consumed_a, msgcnt);

        /* Delay A's next ShareFetch past lock expiry. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 1, 3000);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 2, 3000);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 3, 3000);

        rd_usleep(800 * 1000, NULL);      /* locks expire */
        rd_kafka_share_destroy(consumer); /* crash */

        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 1, 0);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 2, 0);
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 3, 0);

        /* B re-acquires everything (A's ack was rejected atomically). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-atomicity");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("ack_atomicity: B consumed %d/%d (re-delivered)\n", consumed_b,
                 msgcnt);

        test_share_consume_msgs(consumer, 1, 5, 500, NULL,
                                0); /* ack B's records */
        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);

        /* C sees nothing. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-ack-atomicity");
        subscribe_topics(consumer, &topic, 1);
        consumed_c = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("ack_atomicity: C consumed %d/0 (should be 0)\n", consumed_c);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt &&
                        consumed_c == 0,
                    "Expected A=%d B=%d C=0, got A=%d B=%d C=%d", msgcnt,
                    msgcnt, consumed_a, consumed_b, consumed_c);
        SUB_TEST_PASS();
}

/**
 * @brief Leader change mid-session -> client redirects.
 *
 * Consumer fetches from broker 1, then we move the partition leader
 * to broker 2.  The next ShareFetch to broker 1 gets
 * NOT_LEADER_OR_FOLLOWER; the client refreshes metadata and
 * continues from broker 2.
 */
static void do_test_not_leader_or_follower_redirect(void) {
        const char *topic = "kip932_not_leader";
        const int msgcnt  = 6;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Two fetch rounds: 3 records each. */
        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 3);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        rd_kafka_mock_partition_set_leader(ctx.mcluster, topic, 0, 1);
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-not-leader");
        subscribe_topics(consumer, &topic, 1);

        consumed = test_share_consume_msgs(consumer, 3, 40, 500, NULL, 0);
        TEST_SAY("not_leader: consumed %d/3 from broker 1\n", consumed);

        /* Move leader to broker 2 between fetches. */
        rd_kafka_mock_partition_set_leader(ctx.mcluster, topic, 0, 2);
        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 0);

        /* Client should handle the redirect transparently. */
        consumed += test_share_consume_msgs(consumer, 3, 60, 500, NULL, 0);
        TEST_SAY("not_leader: total consumed %d/6\n", consumed);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt, "Expected consumed=%d, got %d", msgcnt,
                    consumed);
        SUB_TEST_PASS();
}

/* ===================================================================
 *  Test runner
 * =================================================================== */

int main_0157_share_consumer_ack_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);
        test_timeout_set(200);

        /* Positive scenarios */
        do_test_implicit_ack_no_redelivery();
        do_test_implicit_ack_with_new_records();
        do_test_implicit_ack_cross_consumer();
        do_test_implicit_ack_multi_partition();
        do_test_implicit_ack_multiple_rounds();
        do_test_implicit_ack_single_record();
        do_test_implicit_ack_large_batch();
        do_test_implicit_ack_multi_topic();
        do_test_implicit_ack_multi_msgset();

        /* Negative scenarios */
        do_test_crash_before_ack_redelivery();
        do_test_crash_then_ack_stops_redelivery();
        do_test_session_expiry_invalidates_ack();
        do_test_max_delivery_without_ack();
        do_test_sharefetch_error_drops_ack();
        do_test_forgotten_topic_releases_not_acks();
        do_test_multi_consumer_cascade_crash();
        do_test_lock_expiry_before_ack();
        do_test_empty_topic_no_ack_side_effects();
        do_test_coordinator_failover_ack_recovery();

        /* Ack validation */
        do_test_ack_after_lock_expiry_redelivers();
        do_test_ack_success_advances_spso();

        do_test_final_fetch_no_acquisition();
        do_test_ack_after_log_retention_silent();
        do_test_ack_atomicity_lock_expiry();
        do_test_not_leader_or_follower_redirect();

        return 0;
}
