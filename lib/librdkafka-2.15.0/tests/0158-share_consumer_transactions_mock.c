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

#include "rdkafka.h"

#include "../src/rdkafka_proto.h"

/**
 * @name Share Group Transactions mock broker tests.
 *
 * Exercises transactional produce + share consume via mock broker
 * for both read_uncommitted and read_committed isolation levels.
 */

typedef struct test_ctx_s {
        rd_kafka_t *producer;
        rd_kafka_t *txn_producer;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
} test_ctx_t;

static test_ctx_t test_ctx_new(const char *txn_id) {
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

        /* Non-transactional producer */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        ctx.producer =
            rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(ctx.producer != NULL, "Failed to create producer: %s",
                    errstr);

        /* Transactional producer */
        if (txn_id) {
                test_conf_init(&conf, NULL, 0);
                test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
                test_conf_set(conf, "transactional.id", txn_id);
                rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
                ctx.txn_producer = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr,
                                                sizeof(errstr));
                TEST_ASSERT(ctx.txn_producer != NULL,
                            "Failed to create txn producer: %s", errstr);
                TEST_CALL_ERROR__(
                    rd_kafka_init_transactions(ctx.txn_producer, 10000));
        }

        return ctx;
}

static void test_ctx_destroy(test_ctx_t *ctx) {
        if (ctx->producer)
                rd_kafka_destroy(ctx->producer);
        if (ctx->txn_producer)
                rd_kafka_destroy(ctx->txn_producer);
        if (ctx->mcluster)
                test_mock_cluster_destroy(ctx->mcluster);
        memset(ctx, 0, sizeof(*ctx));
}

static void produce_txn_messages(rd_kafka_t *txn_producer,
                                 const char *topic,
                                 int msgcnt,
                                 rd_bool_t commit) {
        int i;

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(txn_producer));

        for (i = 0; i < msgcnt; i++) {
                char payload[64];
                snprintf(payload, sizeof(payload), "txn-%s-%d", topic, i);
                TEST_ASSERT(rd_kafka_producev(
                                txn_producer, RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_VALUE(payload, strlen(payload)),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_END) == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Txn produce failed");
        }

        rd_kafka_flush(txn_producer, 5000);

        if (commit)
                TEST_CALL_ERROR__(
                    rd_kafka_commit_transaction(txn_producer, 10000));
        else
                TEST_CALL_ERROR__(
                    rd_kafka_abort_transaction(txn_producer, 10000));
}

static rd_kafka_share_t *create_share_consumer(const char *bootstraps,
                                               const char *group_id) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        char errstr[512];

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);
        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer: %s",
                    errstr);
        return rkshare;
}

static void subscribe_topics(rd_kafka_share_t *share_c,
                             const char **topics,
                             int topic_cnt) {
        rd_kafka_topic_partition_list_t *tpl =
            rd_kafka_topic_partition_list_new(topic_cnt);
        int i;
        for (i = 0; i < topic_cnt; i++)
                rd_kafka_topic_partition_list_add(tpl, topics[i],
                                                  RD_KAFKA_PARTITION_UA);
        TEST_ASSERT(!rd_kafka_share_subscribe(share_c, tpl),
                    "Subscribe failed");
        rd_kafka_topic_partition_list_destroy(tpl);
}



/**
 * @brief Committed txn data is delivered in read_uncommitted mode.
 */
static void do_test_txn_committed_read_uncommitted(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        test_ctx_t ctx;
        rd_kafka_share_t *share_c;
        int consumed;

        SUB_TEST_QUICK();
        ctx = test_ctx_new("txn-committed-ru");

        TEST_CALL_ERR__(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1));

        produce_txn_messages(ctx.txn_producer, topic, 3, rd_true);

        share_c = create_share_consumer(ctx.bootstraps, "sg-txn-committed-ru");
        subscribe_topics(share_c, &topic, 1);
        consumed = test_share_consume_msgs(share_c, 3, 50, 500, NULL, 0);
        TEST_ASSERT(consumed == 3, "Expected 3 consumed, got %d", consumed);
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/**
 * @brief Aborted txn data is also delivered in read_uncommitted mode.
 *
 * In read_uncommitted, the broker does NOT filter aborted data.
 */
static void do_test_txn_aborted_read_uncommitted(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        test_ctx_t ctx;
        rd_kafka_share_t *share_c;
        int consumed;

        SUB_TEST_QUICK();
        ctx = test_ctx_new("txn-aborted-ru");

        TEST_CALL_ERR__(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1));

        produce_txn_messages(ctx.txn_producer, topic, 3, rd_false);

        share_c = create_share_consumer(ctx.bootstraps, "sg-txn-aborted-ru");
        subscribe_topics(share_c, &topic, 1);

        consumed = test_share_consume_msgs(share_c, 3, 50, 500, NULL, 0);

        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 3,
                    "Expected 3 consumed (read_uncommitted sees aborted), "
                    "got %d",
                    consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Mixed non-txn + committed txn data in read_uncommitted.
 */
static void do_test_txn_mixed_read_uncommitted(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        test_ctx_t ctx;
        rd_kafka_share_t *share_c;
        int consumed;

        SUB_TEST_QUICK();
        ctx = test_ctx_new("txn-mixed-ru");

        TEST_CALL_ERR__(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1));

        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 2);
        produce_txn_messages(ctx.txn_producer, topic, 3, rd_true);

        share_c = create_share_consumer(ctx.bootstraps, "sg-txn-mixed-ru");
        subscribe_topics(share_c, &topic, 1);

        consumed = test_share_consume_msgs(share_c, 5, 50, 500, NULL, 0);

        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 5, "Expected 5 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Committed txn data is delivered in read_committed mode.
 */
static void do_test_txn_committed_read_committed(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        test_ctx_t ctx;
        rd_kafka_share_t *share_c;
        int consumed;

        SUB_TEST_QUICK();
        ctx = test_ctx_new("txn-committed-rc");

        rd_kafka_mock_sharegroup_set_isolation_level(ctx.mcluster, 1);

        TEST_CALL_ERR__(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1));

        produce_txn_messages(ctx.txn_producer, topic, 3, rd_true);

        share_c = create_share_consumer(ctx.bootstraps, "sg-txn-committed-rc");
        subscribe_topics(share_c, &topic, 1);

        consumed = test_share_consume_msgs(share_c, 3, 50, 500, NULL, 0);

        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 3, "Expected 3 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Aborted txn data is filtered in read_committed mode.
 *
 * Share share_c should receive 0 records.
 */
static void do_test_txn_aborted_read_committed(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        test_ctx_t ctx;
        rd_kafka_share_t *share_c;
        int consumed;

        SUB_TEST_QUICK();
        ctx = test_ctx_new("txn-aborted-rc");

        rd_kafka_mock_sharegroup_set_isolation_level(ctx.mcluster, 1);

        TEST_CALL_ERR__(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1));

        produce_txn_messages(ctx.txn_producer, topic, 3, rd_false);

        share_c = create_share_consumer(ctx.bootstraps, "sg-txn-aborted-rc");
        subscribe_topics(share_c, &topic, 1);

        consumed = test_share_consume_msgs(share_c, 0, 15, 500, NULL, 0);

        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 0,
                    "Expected 0 consumed (aborted data filtered), got %d",
                    consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Mixed committed + aborted + non-txn in read_committed mode.
 *
 * 2 non-txn + 3 committed + 3 aborted + 2 non-txn.
 * Expected: 7 (2 non-txn + 3 committed data + 2 trailing non-txn).
 * Aborted data is filtered/archived, control records are skipped via
 * GAP(0) ack, so the trailing non-txn records are now reachable.
 */
static void do_test_txn_mixed_read_committed(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        test_ctx_t ctx;
        rd_kafka_share_t *share_c;
        int consumed;

        SUB_TEST_QUICK();
        ctx = test_ctx_new("txn-mixed-rc");

        rd_kafka_mock_sharegroup_set_isolation_level(ctx.mcluster, 1);

        TEST_CALL_ERR__(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1));

        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 2);
        produce_txn_messages(ctx.txn_producer, topic, 3, rd_true);
        produce_txn_messages(ctx.txn_producer, topic, 3, rd_false);
        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 2);

        share_c = create_share_consumer(ctx.bootstraps, "sg-txn-mixed-rc");
        subscribe_topics(share_c, &topic, 1);

        consumed = test_share_consume_msgs(share_c, 7, 60, 500, NULL, 0);

        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 7,
                    "Expected 7 consumed (2 non-txn + 3 committed + "
                    "2 trailing non-txn), got %d",
                    consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Non-txn only data in read_committed mode works normally.
 *
 * No transactions involved — LSO = end_offset, no filtering.
 */
static void do_test_txn_nontxn_read_committed(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        test_ctx_t ctx;
        rd_kafka_share_t *share_c;
        int consumed;

        SUB_TEST_QUICK();
        ctx = test_ctx_new(NULL);

        rd_kafka_mock_sharegroup_set_isolation_level(ctx.mcluster, 1);

        TEST_CALL_ERR__(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1));

        test_produce_msgs_simple(ctx.producer, topic, RD_KAFKA_PARTITION_UA, 5);

        share_c = create_share_consumer(ctx.bootstraps, "sg-txn-nontxn-rc");
        subscribe_topics(share_c, &topic, 1);

        consumed = test_share_consume_msgs(share_c, 5, 50, 500, NULL, 0);

        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 5, "Expected 5 consumed, got %d", consumed);
        SUB_TEST_PASS();
}

/**
 * @brief Abort then commit in read_committed.
 *
 * Log layout:
 *   offset 0-2: aborted data -> ARCHIVED by broker
 *   offset 3:   ABORT control -> skipped via GAP(0) ack
 *   offset 4-6: committed data -> delivered
 *   offset 7:   COMMIT control -> skipped via GAP(0) ack
 *
 * Consumer skips control records via GAP(0) ack and receives the
 * 3 committed data records.
 */
static void do_test_txn_abort_then_commit_read_committed(void) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        test_ctx_t ctx;
        rd_kafka_share_t *share_c;
        int consumed;

        SUB_TEST_QUICK();
        ctx = test_ctx_new("txn-abort-commit-rc");

        rd_kafka_mock_sharegroup_set_isolation_level(ctx.mcluster, 1);

        TEST_CALL_ERR__(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1));

        produce_txn_messages(ctx.txn_producer, topic, 3, rd_false);
        produce_txn_messages(ctx.txn_producer, topic, 3, rd_true);

        share_c =
            create_share_consumer(ctx.bootstraps, "sg-txn-abort-commit-rc");
        subscribe_topics(share_c, &topic, 1);

        consumed = test_share_consume_msgs(share_c, 3, 50, 500, NULL, 0);

        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_ctx_destroy(&ctx);

        TEST_ASSERT(consumed == 3,
                    "Expected 3 consumed (committed data after abort), "
                    "got %d",
                    consumed);
        SUB_TEST_PASS();
}


int main_0158_share_consumer_transactions_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);

        test_timeout_set(1500);

        do_test_txn_committed_read_uncommitted();

        do_test_txn_aborted_read_uncommitted();

        do_test_txn_mixed_read_uncommitted();

        do_test_txn_committed_read_committed();

        do_test_txn_aborted_read_committed();

        do_test_txn_mixed_read_committed();

        do_test_txn_nontxn_read_committed();

        do_test_txn_abort_then_commit_read_committed();

        return 0;
}
