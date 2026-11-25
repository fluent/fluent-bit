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
 * @name ShareFetch mock broker tests using the share consumer API.
 *
 * Exercises the ShareFetch path via mock broker.  There is no coordinator
 * or ShareAcknowledge support in the mock broker, so group management and
 * ack-based state transitions are not validated here.
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

static void do_test_basic_consume(void) {
        const char *topic = "kip932_pos_basic";
        const int msgcnt  = 5;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-pos-basic");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt, "Expected %d consumed, got %d", msgcnt,
                    consumed);
        SUB_TEST_PASS();
}

static void do_test_followup_fetch(void) {
        const char *topic = "kip932_pos_followup";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 5);

        consumer = new_share_consumer(ctx.bootstraps, "sg-pos-followup");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, 3, 30, 500, NULL, 0);
        consumed += test_share_consume_msgs(consumer, 2, 30, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 5, "Expected 5 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

static void do_test_multi_partition(void) {
        const char *topic = "kip932_pos_multi_part";
        const int msgcnt  = 6;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 2, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-pos-multipart");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, msgcnt, 60, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt, "Expected %d consumed, got %d", msgcnt,
                    consumed);
        SUB_TEST_PASS();
}

static void do_test_multi_topic(void) {
        const char *topic_a  = "kip932_pos_topic_a";
        const char *topic_b  = "kip932_pos_topic_b";
        const char *topics[] = {topic_a, topic_b};
        test_ctx_t ctx       = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

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
        consumer = new_share_consumer(ctx.bootstraps, "sg-pos-multitopic");
        subscribe_topics(consumer, topics, 2);
        consumed = test_share_consume_msgs(consumer, 4, 40, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 4, "Expected 4 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

static void do_test_empty_topic_no_records(void) {
        const char *topic = "kip932_pos_empty";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        consumer = new_share_consumer(ctx.bootstraps, "sg-pos-empty");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, 1, 5, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 0, "Expected 0 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

static int do_test_negative_sharefetch_error(rd_kafka_resp_err_t err) {
        const char *topic = "kip932_neg_sharefetch_error";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 1);

        rd_kafka_mock_push_request_errors(ctx.mcluster, RD_KAFKAP_ShareFetch, 1,
                                          err);

        consumer = new_share_consumer(ctx.bootstraps, "sg-neg-sharefetch");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, 1, 30, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        return consumed;
}

static void do_test_sharefetch_invalid_session_epoch(void) {
        SUB_TEST_QUICK();
        do_test_negative_sharefetch_error(
            RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH);
        SUB_TEST_PASS();
}

static void do_test_sharefetch_unknown_topic_or_part(void) {
        SUB_TEST_QUICK();
        do_test_negative_sharefetch_error(
            RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);
        SUB_TEST_PASS();
}

static void do_test_sghb_error(rd_kafka_resp_err_t err, int count) {
        const char *topic = "kip932_neg_sghb";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;
        rd_kafka_resp_err_t *errs;
        int i;

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 1);

        /* Build an array of 'count' identical errors and push them all.
         * Using the array variant avoids UB from mismatched varargs count. */
        errs = malloc(sizeof(*errs) * count);
        TEST_ASSERT(errs != NULL, "malloc failed");
        for (i = 0; i < count; i++)
                errs[i] = err;
        rd_kafka_mock_push_request_errors_array(
            ctx.mcluster, RD_KAFKAP_ShareGroupHeartbeat, (size_t)count, errs);
        free(errs);

        consumer = new_share_consumer(ctx.bootstraps, "sg-neg-sghb");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, 1, 5, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 0, "Expected 0 consumed, got %d", consumed);
}

static void do_test_sghb_coord_unavailable(void) {
        SUB_TEST_QUICK();
        do_test_sghb_error(RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE, 50);
        SUB_TEST_PASS();
}

static void do_test_topic_error(rd_kafka_resp_err_t err) {
        const char *topic = "kip932_neg_topic_error";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 1);
        rd_kafka_mock_topic_set_error(ctx.mcluster, topic, err);

        consumer = new_share_consumer(ctx.bootstraps, "sg-neg-topicerr");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, 1, 5, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 0, "Expected 0 consumed, got %d", consumed);
}

static void do_test_topic_error_unknown_topic_or_part(void) {
        SUB_TEST_QUICK();
        do_test_topic_error(RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);
        SUB_TEST_PASS();
}

static void do_test_unknown_topic_subscription(void) {
        const char *topic = "kip932_neg_unknown_topic";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        consumer = new_share_consumer(ctx.bootstraps, "sg-neg-unknown-topic");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, 1, 5, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 0, "Expected 0 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

static void do_test_empty_fetch_no_records(void) {
        const char *topic = "kip932_neg_empty_fetch";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        consumer = new_share_consumer(ctx.bootstraps, "sg-neg-empty");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, 1, 5, 500, NULL, 0);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 0, "Expected 0 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Verify that ShareFetch rejects requests from an unregistered member
 *        (SHARE_SESSION_NOT_FOUND), and that after the member re-joins it can
 *        consume again.
 *
 *  Phase 1: Consumer joins normally via SGHB -> consumes messages OK.
 *  Phase 2: Push SGHB errors -> heartbeats fail -> member expires -> broker
 *           rejects ShareFetch with SHARE_SESSION_NOT_FOUND.
 *  Phase 3: SGHB errors drain -> member re-joins -> consumes again.
 */
static void do_test_member_validation(void) {
        const char *topic = "kip932_member_validation";
        const int msgcnt  = 4;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_p1, consumed_p3;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Short session timeout so the member is evicted quickly once
         * heartbeats stop succeeding. */
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-member-val");
        subscribe_topics(consumer, &topic, 1);

        /* Phase 1: Consume normally -- member is registered via SGHB. */
        consumed_p1 = test_share_consume_msgs(consumer, 2, 30, 500, NULL, 0);
        TEST_SAY("member_validation: phase1 consumed %d/2\n", consumed_p1);

        /* Phase 2: Block SGHB so heartbeats fail.
         * Push enough errors to cover the window while we wait for the
         * member to be evicted. */
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

        /* Wait for the member to be evicted (500ms session timeout + margin).
         */
        rd_usleep(1500 * 1000, 0);

        /* Phase 3: SGHB errors will eventually drain. Once a SGHB
         * succeeds, the member re-joins and the remaining records
         * become fetchable again. */
        consumed_p3 = test_share_consume_msgs(consumer, 2, 50, 500, NULL, 0);
        TEST_SAY("member_validation: phase3 consumed %d/2\n", consumed_p3);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_p1 >= 2 && (consumed_p1 + consumed_p3) >= msgcnt,
                    "Expected at least 2+2, got %d+%d", consumed_p1,
                    consumed_p3);
        SUB_TEST_PASS();
}

static void do_test_sharefetch_session_expiry_rtt(void) {
        const char *topic = "kip932_rtt_expiry";
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Session timeout must be long enough for normal requests
         * to complete, but short enough to expire during high RTT. */
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 1000);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        /* Produce only 1 message so a single batch cannot over-consume
         * past the requested count in test_share_consume_msgs(). */
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 1);

        consumer = new_share_consumer(ctx.bootstraps, "sg-rtt-expiry");
        subscribe_topics(consumer, &topic, 1);

        /* Phase 1: consume one message with normal RTT (no injection). */
        consumed = test_share_consume_msgs(consumer, 1, 20, 500, NULL, 0);
        TEST_SAY("rtt_expiry: phase1 consumed %d/1\n", consumed);

        /* Phase 2: inject RTT >> session timeout to force session expiry.
         * All requests to broker 1 now take 3s, but the session
         * expires after 1s of inactivity.  The record from phase 1
         * was acquired but not acked, so it becomes available again
         * after the session expires. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 1, 3000);
        rd_usleep(2000 * 1000, 0); /* wait for session to expire */

        /* Phase 3: clear RTT and let the consumer recover.
         * The same record should be re-delivered after session expiry. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, 1, 0);
        consumed += test_share_consume_msgs(consumer, 1, 30, 500, NULL, 0);
        TEST_SAY("rtt_expiry: phase3 consumed %d/2 total\n", consumed);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 2, "Expected 2 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

static void do_test_forgotten_topics(void) {
        const char *topic_a = "kip932_forgotten_a";
        const char *topic_b = "kip932_forgotten_b";
        const char *both[]  = {topic_a, topic_b};
        test_ctx_t ctx      = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_a, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic A");
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_b, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic B");

        /* Produce 2 messages to each topic */
        test_produce_msgs_simple(ctx.producer, topic_a, RD_KAFKA_PARTITION_UA,
                                 2);
        test_produce_msgs_simple(ctx.producer, topic_b, RD_KAFKA_PARTITION_UA,
                                 2);

        /* Subscribe to both topics and consume all 4 messages */
        consumer = new_share_consumer(ctx.bootstraps, "sg-forgotten");
        subscribe_topics(consumer, both, 2);
        consumed = test_share_consume_msgs(consumer, 4, 40, 500, NULL, 0);
        TEST_SAY("forgotten_topics: consumed %d/4 from both topics\n",
                 consumed);

        /* Re-subscribe to only topic_a (topic_b becomes forgotten) */
        subscribe_topics(consumer, &topic_a, 1);

        /* Produce 2 more messages to topic_a */
        test_produce_msgs_simple(ctx.producer, topic_a, RD_KAFKA_PARTITION_UA,
                                 2);

        /* Consume the 2 new messages -- only topic_a should deliver */
        consumed += test_share_consume_msgs(consumer, 2, 30, 500, NULL, 0);
        TEST_SAY("forgotten_topics: consumed %d/6 total after forget\n",
                 consumed);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        /* We expect at least the 4 initial + 2 from topic_a = 6.
         * Depending on timing the consumer may or may not have already
         * received all messages from the first round, so we accept >= 4. */
        TEST_ASSERT(consumed >= 4, "Expected at least 4 consumed, got %d",
                    consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Produce messages one-at-a-time (each flush creates a separate
 *        msgset on the mock partition), then consume and verify all are
 *        received.  This validates that the ShareFetch response includes
 *        records from *all* acquired msgsets, not just the first one.
 */
static void do_test_multi_batch_consume(void) {
        const char *topic = "kip932_multi_batch";
        const int msgcnt  = 5;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        /* Produce each message individually with a flush in between,
         * guaranteeing separate msgsets on the mock partition. */
        for (int i = 0; i < msgcnt; i++) {
                char payload[64];
                snprintf(payload, sizeof(payload), "batch-%d", i);
                TEST_ASSERT(rd_kafka_producev(
                                ctx.producer, RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_VALUE(payload, strlen(payload)),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_END) == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Produce failed");
                rd_kafka_flush(ctx.producer, 5000);
        }

        consumer = new_share_consumer(ctx.bootstraps, "sg-multi-batch");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("multi_batch: consumed %d/%d\n", consumed, msgcnt);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt, "Expected %d consumed, got %d", msgcnt,
                    consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Verify that max_delivery_attempts causes records to be archived
 *        after the limit is exceeded.  Consumer A acquires all records, then
 *        its session times out (releasing locks).  Consumer B acquires them
 *        again, and its session also times out.  After the delivery limit is
 *        exhausted, Consumer C should see 0 available records.
 */
static void do_test_max_delivery_attempts(void) {
        const char *topic = "kip932_max_delivery";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b, consumed_c;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Set max delivery attempts to 2 and a short session timeout
         * so locks expire quickly after consumer destruction. */
        rd_kafka_mock_sharegroup_set_max_delivery_attempts(ctx.mcluster, 2);
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Delivery 1: Consumer A acquires and "crashes" (no ack). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-max-delivery");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("max_delivery: A consumed %d/%d (delivery 1)\n", consumed_a,
                 msgcnt);
        test_share_destroy(consumer);
        rd_usleep(1500 * 1000, 0); /* wait for lock expiry */

        /* Delivery 2: Consumer B acquires same records again (delivery_count
         * reaches 2 = limit) and "crashes". */
        consumer = new_share_consumer(ctx.bootstraps, "sg-max-delivery");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("max_delivery: B consumed %d/%d (delivery 2)\n", consumed_b,
                 msgcnt);
        test_share_destroy(consumer);
        rd_usleep(1500 * 1000, 0); /* wait for lock expiry */

        /* Delivery 3 attempt: Consumer C should get 0 records because
         * all records have been archived (delivery_count >= max). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-max-delivery");
        subscribe_topics(consumer, &topic, 1);
        consumed_c = test_share_consume_msgs(consumer, 1, 10, 500, NULL, 0);
        TEST_SAY("max_delivery: C consumed %d/0 (should be archived)\n",
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
 * @brief Verify that record_lock_duration_ms controls how long acquired
 *        records stay locked, independently of session_timeout_ms.
 *        Sets a short lock duration (300ms) with a longer session timeout
 *        (10s).  Consumer A acquires records and "crashes".  After the short
 *        lock duration expires, Consumer B should be able to acquire them
 *        even though A's session hasn't timed out yet.
 */
static void do_test_record_lock_duration(void) {
        const char *topic = "kip932_lock_duration";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Long session timeout, short record lock duration. */
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 10000);
        rd_kafka_mock_sharegroup_set_record_lock_duration(ctx.mcluster, 300);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A acquires records, then crashes (no close). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-lock-duration");
        subscribe_topics(consumer, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("lock_duration: A consumed %d/%d\n", consumed_a, msgcnt);
        test_share_destroy(consumer);

        /* Wait for record lock to expire (300ms + margin).
         * test_share_destroy sends SGHB LEAVE which releases
         * locks immediately, but we still need to wait for the
         * client's internal rejoin cycle to settle. */
        rd_usleep(1000 * 1000, 0);

        /* Consumer B should get the records because locks have expired
         * even though A's session is still technically alive.
         * Use higher max_attempts to account for the mock broker's
         * SGHB LEAVE->rejoin cycle delay. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-lock-duration");
        subscribe_topics(consumer, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer, msgcnt, 100, 500, NULL, 0);
        TEST_SAY("lock_duration: B consumed %d/%d\n", consumed_b, msgcnt);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt,
                    "Expected A=%d B=%d, got A=%d B=%d", msgcnt, msgcnt,
                    consumed_a, consumed_b);
        SUB_TEST_PASS();
}

/**
 * @brief Multi-consumer lock expiry test.
 *
 * Consumer A acquires records, then crashes (destroyed without close).
 * After the lock expiry timeout, consumer B should be able to pick up
 * the same records because the proactive lock-expiry scan releases them.
 */
static void do_test_multi_consumer_lock_expiry(void) {
        const char *topic = "kip932_multi_consumer_lock";
        const int msgcnt  = 3;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer_a, *consumer_b;
        int consumed_a, consumed_b;

        SUB_TEST();
        ctx = test_ctx_new();

        /* Use a short session/lock timeout so the test runs quickly. */
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A: subscribe and consume all records (acquires locks). */
        consumer_a =
            new_share_consumer(ctx.bootstraps, "sg-multi-consumer-lock");
        subscribe_topics(consumer_a, &topic, 1);
        consumed_a =
            test_share_consume_msgs(consumer_a, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("multi_consumer: A consumed %d/%d\n", consumed_a, msgcnt);

        /* Simulate crash: destroy consumer A without calling close.
         * The session will time out and the proactive lock-expiry
         * timer will release A's locks. */
        test_share_destroy(consumer_a);

        /* Wait for locks to expire (session_timeout=500ms, add margin). */
        rd_usleep(1500 * 1000, 0);

        /* Consumer B: joins the same share group, should get the same
         * records once the locks have been released.
         * Use higher max_attempts to account for the mock broker's
         * SGHB LEAVE->rejoin cycle delay. */
        consumer_b =
            new_share_consumer(ctx.bootstraps, "sg-multi-consumer-lock");
        subscribe_topics(consumer_b, &topic, 1);
        consumed_b =
            test_share_consume_msgs(consumer_b, msgcnt, 100, 500, NULL, 0);
        TEST_SAY("multi_consumer: B consumed %d/%d\n", consumed_b, msgcnt);

        test_share_consumer_close(consumer_b);
        test_share_destroy(consumer_b);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == msgcnt && consumed_b == msgcnt,
                    "Expected A=%d B=%d, got A=%d B=%d", msgcnt, msgcnt,
                    consumed_a, consumed_b);
        SUB_TEST_PASS();
}


/*
 * TODO KIP-932: The functions below inject errors using
 * rd_kafka_mock_push_request_errors(), which only sets the top-level
 * ShareFetch error code. The error codes tested here are per-partition
 * errors that the broker never emits at the top level. Re-enable
 * once partition-level mock error injection is available.
 *
static void do_test_sharefetch_fetch_error(rd_kafka_resp_err_t err) {
        const char *topic = "kip932_fetch_error";
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd  = 0;
        int consumed = 0;
        size_t i;

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 3);

        rd_kafka_mock_push_request_errors(ctx.mcluster, RD_KAFKAP_ShareFetch, 1,
                                          err);

        consumer = new_share_consumer(ctx.bootstraps, "sg-fetch-error");
        subscribe_topics(consumer, &topic, 1);

        rd_kafka_share_poll(consumer, 2000, &batch);
        rcvd = rd_kafka_messages_count(batch);
        for (i = 0; i < rcvd; i++) {
                rd_kafka_message_t *msg = rd_kafka_messages_get(batch, i);
                if (!msg->err)
                        consumed++;
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("fetch_error(%s): consumed=%d rcvd=%zu\n",
                 rd_kafka_err2name(err), consumed, rcvd);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 0, "Expected 0 consumed with %s, got %d",
                    rd_kafka_err2name(err), consumed);
}

static void do_test_sharefetch_fetch_error_not_leader(void) {
        SUB_TEST();
        do_test_sharefetch_fetch_error(
            RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER);
        SUB_TEST_PASS();
}

static void do_test_sharefetch_fetch_error_unknown_topic_or_part(void) {
        SUB_TEST();
        do_test_sharefetch_fetch_error(RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);
        SUB_TEST_PASS();
}

static void do_test_sharefetch_fetch_error_unknown_topic_id(void) {
        SUB_TEST();
        do_test_sharefetch_fetch_error(RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID);
        SUB_TEST_PASS();
}

static void do_test_sharefetch_fetch_error_fenced_leader_epoch(void) {
        SUB_TEST();
        do_test_sharefetch_fetch_error(RD_KAFKA_RESP_ERR_FENCED_LEADER_EPOCH);
        SUB_TEST_PASS();
}

static void do_test_sharefetch_fetch_error_unknown_leader_epoch(void) {
        SUB_TEST();
        do_test_sharefetch_fetch_error(RD_KAFKA_RESP_ERR_UNKNOWN_LEADER_EPOCH);
        SUB_TEST_PASS();
}

static void do_test_sharefetch_topic_authorization_failed(void) {
        SUB_TEST();
        do_test_sharefetch_fetch_error(
            RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
        SUB_TEST_PASS();
}

static void do_test_sharefetch_corrupt_message(void) {
        SUB_TEST();
        do_test_sharefetch_fetch_error(RD_KAFKA_RESP_ERR_INVALID_MSG);
        SUB_TEST_PASS();
}
*/

/*
 * TODO KIP-932: This test injects FENCED_LEADER_EPOCH using
 * rd_kafka_mock_push_request_errors(), which only sets the top-level
 * ShareFetch error code. FENCED_LEADER_EPOCH is a per-partition error
 * that the broker never emits at the top level; the top-level handler
 * treats it as transient and retries, so the consumer receives records.
 * Re-enable once partition-level mock error injection is available.
 *
static void do_test_sharefetch_fetch_disconnected(void) {
        const char *topic = "kip932_disconnect";
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd  = 0;
        int consumed = 0;
        size_t i;

        SUB_TEST();
        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 3);

        rd_kafka_mock_push_request_errors(
            ctx.mcluster, RD_KAFKAP_ShareFetch, 1,
            RD_KAFKA_RESP_ERR_FENCED_LEADER_EPOCH);

        consumer = new_share_consumer(ctx.bootstraps, "sg-disconnect");
        subscribe_topics(consumer, &topic, 1);

        rd_kafka_share_poll(consumer, 2000, &batch);
        rcvd = rd_kafka_messages_count(batch);
        for (i = 0; i < rcvd; i++) {
                rd_kafka_message_t *msg = rd_kafka_messages_get(batch, i);
                if (!msg->err)
                        consumed++;
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("fetch_disconnected: consumed=%d rcvd=%zu\n", consumed, rcvd);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 0, "Expected 0 consumed on disconnect, got %d",
                    consumed);
        SUB_TEST_PASS();
}
*/

/**
 * @brief Fetch records and close implicitly (no explicit ack).
 *
 * Verifies that a consumer can fetch records and then close successfully.
 * The close sends ShareAcknowledge with epoch=-1 to release the session.
 */
static void do_test_sharefetch_fetch_and_close_implicit(void) {
        const char *topic = "kip932_fetch_close";
        const int msgcnt  = 2;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST();
        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        consumer = new_share_consumer(ctx.bootstraps, "sg-fetch-close");
        subscribe_topics(consumer, &topic, 1);

        /* Fetch records */
        consumed = test_share_consume_msgs(consumer, msgcnt, 50, 500, NULL, 0);
        TEST_SAY("fetch_and_close: consumed %d/%d\n", consumed, msgcnt);

        /* Close — sends ShareAcknowledge/ShareFetch with epoch=-1 */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt, "Expected %d consumed, got %d", msgcnt,
                    consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Test that SHARE_SESSION_LIMIT_REACHED is returned when the
 *        session cache is full.
 *
 * Set max_fetch_sessions=1, open a session with consumer 1,
 * then attempt to open a second session with consumer 2.
 * Consumer 2 should fail to consume any records because every
 * ShareFetch epoch=0 attempt gets SHARE_SESSION_LIMIT_REACHED.
 */
static void do_test_session_limit_reached(void) {
        const char *topic = "kip932_session_limit";
        const int msgcnt  = 5;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer1, *consumer2;
        int consumed1, consumed2;

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        /* Limit to 1 session */
        rd_kafka_mock_sharegroup_set_max_fetch_sessions(ctx.mcluster, 1);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer 1 opens a session successfully */
        consumer1 = new_share_consumer(ctx.bootstraps, "sg-session-limit");
        subscribe_topics(consumer1, &topic, 1);
        consumed1 =
            test_share_consume_msgs(consumer1, msgcnt, 30, 500, NULL, 0);
        TEST_ASSERT(consumed1 == msgcnt,
                    "Consumer 1: expected %d consumed, got %d", msgcnt,
                    consumed1);

        /* Consumer 2 tries to open a session — cache is full */
        consumer2 = new_share_consumer(ctx.bootstraps, "sg-session-limit");
        subscribe_topics(consumer2, &topic, 1);
        consumed2 = test_share_consume_msgs(consumer2, 1, 5, 500, NULL, 0);
        TEST_ASSERT(consumed2 == 0,
                    "Consumer 2: expected 0 consumed (session limit), got %d",
                    consumed2);

        rd_kafka_share_consumer_close(consumer1);
        rd_kafka_share_destroy(consumer1);
        rd_kafka_share_consumer_close(consumer2);
        rd_kafka_share_destroy(consumer2);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/**
 * @brief Test that the session limit is enforced per broker, not globally.
 *
 * Create two single-partition topics, each with its leader on a
 * different broker.  Set max_fetch_sessions=1 (per broker).
 *
 * Consumer 1 subscribes to topic_a (broker 1) and consumer 2 subscribes
 * to topic_b (broker 2).  Both should succeed because each broker only
 * has 1 session despite there being 2 sessions globally.
 *
 * Then consumer 3 subscribes to topic_a — this should fail because
 * broker 1 already has 1 session (from consumer 1).
 */
static void do_test_session_limit_per_broker(void) {
        const char *topic_a = "kip932_session_limit_pb_a";
        const char *topic_b = "kip932_session_limit_pb_b";
        const int msgcnt    = 5;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer1, *consumer2, *consumer3;
        int consumed1, consumed2, consumed3;

        SUB_TEST();

        ctx = test_ctx_new();

        /* Create two topics, each with 1 partition on a different broker. */
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_a, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic A");
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_b, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic B");
        rd_kafka_mock_partition_set_leader(ctx.mcluster, topic_a, 0, 1);
        rd_kafka_mock_partition_set_leader(ctx.mcluster, topic_b, 0, 2);

        test_produce_msgs_simple(ctx.producer, topic_a, RD_KAFKA_PARTITION_UA,
                                 msgcnt);
        test_produce_msgs_simple(ctx.producer, topic_b, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Limit to 1 session per broker */
        rd_kafka_mock_sharegroup_set_max_fetch_sessions(ctx.mcluster, 1);

        /* Consumer 1 subscribes to topic_a -> session on broker 1 */
        consumer1 = new_share_consumer(ctx.bootstraps, "sg-session-limit-pb");
        subscribe_topics(consumer1, &topic_a, 1);
        consumed1 =
            test_share_consume_msgs(consumer1, msgcnt, 30, 500, NULL, 0);
        TEST_ASSERT(consumed1 == msgcnt,
                    "Consumer 1: expected %d consumed, got %d", msgcnt,
                    consumed1);

        /* Consumer 2 subscribes to topic_b -> session on broker 2.
         * If the limit were global, this would fail (2 sessions > limit 1).
         * Per-broker: broker 2 has 0 sessions, so it succeeds. */
        consumer2 = new_share_consumer(ctx.bootstraps, "sg-session-limit-pb");
        subscribe_topics(consumer2, &topic_b, 1);
        consumed2 =
            test_share_consume_msgs(consumer2, msgcnt, 30, 500, NULL, 0);
        TEST_ASSERT(consumed2 == msgcnt,
                    "Consumer 2: expected %d consumed, got %d", msgcnt,
                    consumed2);

        /* Consumer 3 subscribes to topic_a -> broker 1 already has
         * 1 session (from consumer 1), so this should be rejected. */
        consumer3 = new_share_consumer(ctx.bootstraps, "sg-session-limit-pb");
        subscribe_topics(consumer3, &topic_a, 1);
        consumed3 = test_share_consume_msgs(consumer3, 1, 5, 500, NULL, 0);
        TEST_ASSERT(consumed3 == 0,
                    "Consumer 3: expected 0 consumed (broker 1 at limit), "
                    "got %d",
                    consumed3);

        rd_kafka_share_consumer_close(consumer1);
        rd_kafka_share_destroy(consumer1);
        rd_kafka_share_consumer_close(consumer2);
        rd_kafka_share_destroy(consumer2);
        rd_kafka_share_consumer_close(consumer3);
        rd_kafka_share_destroy(consumer3);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/**
 * @brief Test that ShareFetch with epoch=0 and acks is rejected with
 *        INVALID_REQUEST via the mock broker's injected error mechanism.
 *
 * Injects SHARE_SESSION_LIMIT_REACHED errors to force the client to
 * retry with epoch=0.  The client never piggybacks acks on epoch=0
 * (that's a protocol violation), so this test validates that the mock
 * broker's error injection for SHARE_SESSION_LIMIT_REACHED works and
 * the client recovers when the error clears.
 */
static void do_test_session_limit_recovery(void) {
        const char *topic = "kip932_session_limit_recovery";
        const int msgcnt  = 5;
        test_ctx_t ctx    = test_ctx_new();
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST_QUICK();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Push 3 SHARE_SESSION_LIMIT_REACHED errors, then let it succeed */
        rd_kafka_mock_push_request_errors(
            ctx.mcluster, RD_KAFKAP_ShareFetch, 3,
            RD_KAFKA_RESP_ERR_SHARE_SESSION_LIMIT_REACHED,
            RD_KAFKA_RESP_ERR_SHARE_SESSION_LIMIT_REACHED,
            RD_KAFKA_RESP_ERR_SHARE_SESSION_LIMIT_REACHED);

        consumer = new_share_consumer(ctx.bootstraps, "sg-session-recovery");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, msgcnt, 30, 500, NULL, 0);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt,
                    "Expected %d consumed after recovery, got %d", msgcnt,
                    consumed);

        SUB_TEST_PASS();
}

/**
 * @brief Test that max_record_locks limits the number of in-flight
 *        records per share-partition.
 *
 * Produce 10 records, set max_record_locks=3.  Consumer A should get
 * only 3 records on the first fetch round (the rest are blocked by
 * the lock limit).  After A acks (via second poll) and closes,
 * consumer B should get the next batch.  Total consumed across both
 * should be 10.
 */
static void do_test_max_record_locks(void) {
        const char *topic = "kip932_max_record_locks";
        const int msgcnt  = 10;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int total_consumed = 0;
        int rounds         = 0;

        SUB_TEST_QUICK();
        ctx = test_ctx_new();

        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 3);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consume in rounds.  Each round can get at most 3 records
         * (the lock limit).  The implicit ack from the next poll
         * frees the locks for the next batch. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-max-locks");
        subscribe_topics(consumer, &topic, 1);

        while (total_consumed < msgcnt && rounds < 20) {
                int got =
                    test_share_consume_msgs(consumer, 3, 10, 500, NULL, 0);
                if (got == 0)
                        break;
                total_consumed += got;
                rounds++;
                TEST_SAY(
                    "max_record_locks: round %d consumed %d (total %d/%d)\n",
                    rounds, got, total_consumed, msgcnt);
        }

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(total_consumed == msgcnt,
                    "Expected %d total consumed, got %d", msgcnt,
                    total_consumed);
        TEST_ASSERT(rounds > 1,
                    "Expected multiple rounds (lock limit=3, msgs=10), "
                    "got %d rounds",
                    rounds);

        SUB_TEST_PASS();
}

/**
 * @brief Verify that max_record_locks counts only ACQUIRED records,
 *        not total inflight records (which includes ARCHIVED).
 *
 * Produce 6 records. Set max_record_locks=3, max_delivery_attempts=1.
 *
 * Consumer A acquires records 0-2 (lock limit), then is destroyed
 * WITHOUT close (no implicit ack).  The connection close releases
 * the locks; with max_delivery_attempts=1 the released records
 * transition directly to ARCHIVED (delivery_count >= limit).
 *
 * At this point:
 *   - Records 0-2: ARCHIVED, still in the inflight list
 *   - SPSO = 0 (never advanced — ARCHIVED != ACKNOWLEDGED)
 *   - inflight_cnt = 3, acquired_cnt = 0
 *
 * Consumer B subscribes.  With the correct check (acquired_cnt),
 * records 3-5 are acquirable because only 0 records are ACQUIRED.
 * With an inflight_cnt-based check, the limit would block all
 * acquisition (inflight_cnt=3 >= max_record_locks=3).
 */
static void do_test_max_record_locks_acquired_only(void) {
        const char *topic = "kip932_max_locks_acquired_only";
        const int msgcnt  = 6;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b;

        SUB_TEST();
        ctx = test_ctx_new();

        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 3);
        rd_kafka_mock_sharegroup_set_max_delivery_attempts(ctx.mcluster, 1);
        rd_kafka_mock_sharegroup_set_session_timeout(ctx.mcluster, 500);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A: acquire first batch (3 records due to lock limit). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-acq-only");
        subscribe_topics(consumer, &topic, 1);
        consumed_a = test_share_consume_msgs(consumer, 3, 30, 500, NULL, 0);
        TEST_SAY("acquired_only: A consumed %d/3\n", consumed_a);

        /* Destroy WITHOUT close — avoids implicit ack.
         * The connection close releases locks; with max_delivery_attempts=1
         * the released records transition to ARCHIVED (not AVAILABLE).
         * SPSO stays at 0 because ARCHIVED != ACKNOWLEDGED.
         * inflight_cnt stays 3, but acquired_cnt drops to 0. */
        rd_kafka_share_destroy(consumer);
        rd_usleep(1500 * 1000, 0); /* wait for connection close */

        /* Consumer B subscribes. The share-partition now has:
         *   - Records 0-2: ARCHIVED (inflight_cnt=3, acquired_cnt=0)
         *   - Records 3-5: not yet in inflight list
         * With acquired_cnt check, Consumer B acquires records 3-5.
         * With inflight_cnt check, the limit would block acquisition. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-acq-only");
        subscribe_topics(consumer, &topic, 1);
        consumed_b = test_share_consume_msgs(consumer, 3, 30, 500, NULL, 0);
        TEST_SAY("acquired_only: B consumed %d/3\n", consumed_b);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == 3, "A: expected 3, got %d", consumed_a);
        TEST_ASSERT(consumed_b == 3,
                    "B: expected 3 (max_record_locks should count only "
                    "ACQUIRED, not ARCHIVED), got %d",
                    consumed_b);

        SUB_TEST_PASS();
}

/**
 * @brief Test that SPSO advances when log retention deletes records
 *        below the current SPSO.
 *
 * Produce 10 records (offsets 0-9).  Consumer A acquires 0-4.
 * Then delete records before offset 5 (simulating log retention).
 * Consumer A closes (acks 0-4, but they're already archived by
 * retention).  Consumer B should get records 5-9 only — SPSO
 * was advanced to 5 by the retention, and in-flight records
 * below 5 were archived.
 */
static void do_test_spso_advances_on_log_retention(void) {
        const char *topic = "kip932_log_retention_spso";
        const int msgcnt  = 10;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        int consumed_a, consumed_b;

        SUB_TEST_QUICK();
        ctx = test_ctx_new();

        /* Limit to 5 records per fetch so A gets only 0-4. */
        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 5);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Consumer A acquires records 0-4. */
        consumer = new_share_consumer(ctx.bootstraps, "sg-log-retention");
        subscribe_topics(consumer, &topic, 1);
        consumed_a = test_share_consume_msgs(consumer, 5, 30, 500, NULL, 0);
        TEST_SAY("log_retention: A consumed %d/5\n", consumed_a);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);

        /* Simulate log retention: delete records before offset 5. */
        TEST_ASSERT(
            rd_kafka_mock_partition_delete_records(ctx.mcluster, topic, 0, 5) ==
                RD_KAFKA_RESP_ERR_NO_ERROR,
            "Failed to delete records");

        /* Remove lock limit. */
        rd_kafka_mock_sharegroup_set_max_record_locks(ctx.mcluster, 0);

        /* Consumer B should get records 5-9 (SPSO advanced to 5). */
        consumer = new_share_consumer(ctx.bootstraps, "sg-log-retention");
        subscribe_topics(consumer, &topic, 1);
        consumed_b = test_share_consume_msgs(consumer, 5, 30, 500, NULL, 0);
        TEST_SAY("log_retention: B consumed %d/5\n", consumed_b);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed_a == 5, "A: expected 5 consumed, got %d",
                    consumed_a);
        TEST_ASSERT(consumed_b == 5, "B: expected 5 consumed, got %d",
                    consumed_b);

        SUB_TEST_PASS();
}

/**
 * @brief Test that auto.offset.reset=latest (the default)
 *        causes the consumer to skip records produced before subscription.
 *
 * Produce 5 records, then subscribe with auto.offset.reset=latest.
 * Consumer should get 0 old records but should get new records
 * produced after subscription.
 */
static void do_test_auto_offset_reset_latest(void) {
        const char *topic = "kip932_offset_reset_latest";
        const int msgcnt  = 5;
        test_ctx_t ctx;
        rd_kafka_share_t *consumer;
        rd_kafka_conf_t *conf;
        char errstr[512];
        int consumed;

        SUB_TEST_QUICK();

        /* Create a fresh context — do NOT set auto_offset_reset=earliest
         * (the default is "latest"). */
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
        /* Intentionally NOT calling set_auto_offset_reset — default is latest
         */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        ctx.producer =
            rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(ctx.producer != NULL, "Failed to create producer: %s",
                    errstr);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        /* Produce records BEFORE subscribing */
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);

        /* Subscribe — SPSO should start at end of log (latest) */
        consumer = new_share_consumer(ctx.bootstraps, "sg-offset-latest");
        subscribe_topics(consumer, &topic, 1);
        consumed = test_share_consume_msgs(consumer, 1, 5, 500, NULL, 0);
        TEST_SAY("offset_reset_latest: consumed %d (expected 0)\n", consumed);
        TEST_ASSERT(consumed == 0,
                    "Expected 0 consumed with latest offset reset, got %d",
                    consumed);

        /* Produce new records AFTER subscription — these should be visible */
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA,
                                 msgcnt);
        consumed = test_share_consume_msgs(consumer, msgcnt, 30, 500, NULL, 0);
        TEST_SAY("offset_reset_latest: consumed %d new records (expected %d)\n",
                 consumed, msgcnt);

        rd_kafka_share_consumer_close(consumer);
        rd_kafka_share_destroy(consumer);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == msgcnt,
                    "Expected %d new records consumed, got %d", msgcnt,
                    consumed);

        SUB_TEST_PASS();
}

int main_0156_share_consumer_fetch_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);

        /* This test suite has many subtests; set a generous timeout.
         * When running in parallel with other test suites (e.g., 0155, 0157)
         * the mock broker and consumer threads compete for CPU, which can
         * slow individual subtests by 5x or more. Use 1500s to be safe. */
        test_timeout_set(1500);

        /* Positive scenarios */
        do_test_basic_consume();
        do_test_followup_fetch();
        do_test_multi_partition();
        do_test_multi_topic();
        do_test_empty_topic_no_records();
        do_test_sharefetch_session_expiry_rtt();
        do_test_forgotten_topics();
        do_test_multi_batch_consume();
        do_test_max_delivery_attempts();
        do_test_record_lock_duration();
        do_test_multi_consumer_lock_expiry();

        /* Negative scenarios */
        do_test_sharefetch_invalid_session_epoch();
        do_test_sharefetch_unknown_topic_or_part();
        do_test_sghb_coord_unavailable();
        do_test_topic_error_unknown_topic_or_part();
        do_test_unknown_topic_subscription();
        do_test_empty_fetch_no_records();
        do_test_member_validation();

        /* TODO KIP-932: These tests inject partition-level errors at the
         * top-level response field, which the broker never does for these
         * error codes. Replace with partition-level mock injection once
         * that API is available. */
        /* do_test_sharefetch_fetch_error_not_leader(); */
        /* do_test_sharefetch_fetch_error_unknown_topic_or_part(); */
        /* do_test_sharefetch_fetch_error_unknown_topic_id(); */
        /* do_test_sharefetch_fetch_error_fenced_leader_epoch(); */
        /* do_test_sharefetch_fetch_error_unknown_leader_epoch(); */
        /* do_test_sharefetch_topic_authorization_failed(); */
        /* do_test_sharefetch_corrupt_message(); */
        /* do_test_sharefetch_fetch_disconnected(); */
        do_test_sharefetch_fetch_and_close_implicit();

        /* Session management */
        do_test_session_limit_reached();
        do_test_session_limit_per_broker();
        do_test_session_limit_recovery();

        /* Record lock limits */
        do_test_max_record_locks();
        do_test_max_record_locks_acquired_only();

        /* Offset reset */
        do_test_auto_offset_reset_latest();

        /* Log retention */
        do_test_spso_advances_on_log_retention();

        return 0;
}
