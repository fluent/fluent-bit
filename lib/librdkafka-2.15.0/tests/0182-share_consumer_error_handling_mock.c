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
 * @brief Share consumer top-level error propagation through ShareAcknowledge.
 *
 * Verifies that a top-level err on a ShareAcknowledge response reaches
 * the per-partition rktpar->err that commit_sync reads, with no
 * _IN_PROGRESS sentinel leaking to the caller. The broker-thread helper
 * (rd_kafka_share_fetch_op_reply_with_err) sets err on each batch in
 * ack_details; the main reply handler copies batch->rktpar->err into
 * rkcg_commit_sync_request.results.
 *
 * Out of scope here (need mock enhancements not yet available):
 *   - Per-partition AcknowledgementErrorCode injection (mock only supports
 *     top-level err push)
 *   - Partition missing from ShareAcknowledge response (no mock API to
 *     drop a partition from response)
 */

#define CONSUME_ARRAY 1024

/* ===================================================================
 *  Mock broker infrastructure (same pattern as 0176).
 * =================================================================== */
typedef struct test_ctx_s {
        rd_kafka_t *producer;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
} test_ctx_t;

static test_ctx_t test_ctx_new_n(int nbrok) {
        test_ctx_t ctx;
        rd_kafka_conf_t *conf;
        char errstr[512];

        memset(&ctx, 0, sizeof(ctx));

        ctx.mcluster = test_mock_cluster_new(nbrok, &ctx.bootstraps);

        TEST_ASSERT(rd_kafka_mock_set_apiversion(
                        ctx.mcluster, RD_KAFKAP_ShareGroupHeartbeat, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to enable ShareGroupHeartbeat");
        TEST_ASSERT(rd_kafka_mock_set_apiversion(ctx.mcluster,
                                                 RD_KAFKAP_ShareFetch, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to enable ShareFetch");

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

static test_ctx_t test_ctx_new(void) {
        return test_ctx_new_n(1);
}

static void test_ctx_destroy(test_ctx_t *ctx) {
        if (ctx->producer)
                rd_kafka_destroy(ctx->producer);
        if (ctx->mcluster)
                test_mock_cluster_destroy(ctx->mcluster);
        memset(ctx, 0, sizeof(*ctx));
}

static rd_kafka_share_t *
create_mock_share_consumer(const char *bootstraps,
                           const char *group_id,
                           const char *ack_mode,
                           test_ack_cb_state_t *cb_state,
                           void (*cb)(rd_kafka_share_t *,
                                      rd_kafka_share_partition_offsets_list_t *,
                                      rd_kafka_resp_err_t,
                                      void *)) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);
        test_conf_set(conf, "share.acknowledgement.mode", ack_mode);

        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");

        /* Register acknowledgement callback at runtime */
        if (cb && cb_state) {
                rd_kafka_error_t *error =
                    rd_kafka_share_set_acknowledgement_commit_cb(rkshare, cb,
                                                                 cb_state);
                TEST_ASSERT(error == NULL,
                            "Failed to set acknowledgement commit callback: "
                            "%s",
                            rd_kafka_error_string(error));
        }
        return rkshare;
}

static void mock_produce(rd_kafka_t *producer, const char *topic, int msgcnt) {
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

static void mock_produce_partition(rd_kafka_t *producer,
                                   const char *topic,
                                   int32_t partition,
                                   int msgcnt) {
        int i;
        for (i = 0; i < msgcnt; i++) {
                char payload[64];
                snprintf(payload, sizeof(payload), "%s-p%d-%d", topic,
                         (int)partition, i);
                TEST_ASSERT(rd_kafka_producev(
                                producer, RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_PARTITION(partition),
                                RD_KAFKA_V_VALUE(payload, strlen(payload)),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_END) == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Produce to partition %d failed", (int)partition);
        }
        rd_kafka_flush(producer, 5000);
}

/**
 * @brief Consume up to msgcnt records and ACCEPT each, returning count
 *        actually acknowledged.
 */
static int consume_and_ack_all(rd_kafka_share_t *rkshare, int msgcnt) {
        rd_kafka_messages_t *batch = NULL;
        int acked                  = 0;
        int attempts               = 0;

        while (acked < msgcnt && attempts++ < 30) {
                size_t rcvd = 0;
                size_t j;
                rd_kafka_error_t *error =
                    rd_kafka_share_poll(rkshare, 3000, &batch);
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
                                acked++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        return acked;
}

/* ===================================================================
 *  Parameterized helper: inject one top-level err on next
 *  ShareAcknowledge response and verify commit_sync result carries
 *  that err on every partition.
 *
 *  This exercises the broker-thread helper
 *  (rd_kafka_share_fetch_op_reply_with_err) + the main reply handler
 *  defensive _IN_PROGRESS sentinel together: regardless of which
 *  layer writes batch->rktpar->err, the commit_sync caller must see
 *  the top-level err for every partition that was sent to the broker.
 * =================================================================== */
static void
do_test_commit_sync_top_level_err(const char *test_name,
                                  rd_kafka_resp_err_t injected_err) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_error_t *error;
        char topic[64];
        char group[64];
        const int msgcnt = 10;
        int acked;
        int i;
        test_ack_cb_state_t cb_state = {0};

        SUB_TEST_QUICK("%s -> %s", test_name, rd_kafka_err2name(injected_err));

        ctx = test_ctx_new();

        rd_snprintf(topic, sizeof(topic), "0182-%s", test_name);
        rd_snprintf(group, sizeof(group), "sg-0182-%s", test_name);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        mock_produce(ctx.producer, topic, msgcnt);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             &cb_state, test_share_ack_cb);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        acked = consume_and_ack_all(rkshare, msgcnt);
        TEST_ASSERT(acked == msgcnt, "expected %d acked, got %d", msgcnt,
                    acked);

        /* Inject the top-level err on the next ShareAcknowledge
         * response from broker 1 (only broker in cluster). */
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        ctx.mcluster, 1, RD_KAFKAP_ShareAcknowledge, 1,
                        injected_err, 0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push error");

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);

        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "expected non-NULL partition results "
                    "(top-level err must surface per-partition, "
                    "not as _IN_PROGRESS leak)");

        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                TEST_SAY("%s [%" PRId32 "]: %s\n", rktpar->topic,
                         rktpar->partition, rd_kafka_err2name(rktpar->err));
                TEST_ASSERT(rktpar->err == injected_err, "expected %s, got %s",
                            rd_kafka_err2name(injected_err),
                            rd_kafka_err2name(rktpar->err));
        }

        rd_kafka_topic_partition_list_destroy(partitions);

        /* Verify callback was invoked with the error */
        TEST_ASSERT(cb_state.callback_cnt == 1, "expected 1 callback, got %d",
                    cb_state.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&cb_state) == injected_err,
                    "expected callback err %s, got %s",
                    rd_kafka_err2name(injected_err),
                    rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));
        TEST_ASSERT(cb_state.total_offsets == msgcnt,
                    "expected callback total_offsets %d, got %zu", msgcnt,
                    cb_state.total_offsets);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&cb_state);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/* Top-level session error: SHARE_SESSION_NOT_FOUND on ShareAcknowledge
 * is propagated to every partition in commit_sync results (no
 * _IN_PROGRESS leak). */
static void test_commit_sync_share_session_not_found(void) {
        do_test_commit_sync_top_level_err(
            "session-not-found", RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND);
}

/* Same path with a different session error code — confirms
 * propagation isn't tied to a specific err. */
static void test_commit_sync_invalid_share_session_epoch(void) {
        do_test_commit_sync_top_level_err(
            "invalid-session-epoch",
            RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH);
}

/* commit_sync surfaces a top-level SHARE_SESSION_LIMIT_REACHED from
 * ShareAcknowledge without any client-side special handling. */
static void test_commit_sync_share_session_limit_reached(void) {
        do_test_commit_sync_top_level_err(
            "session-limit-reached",
            RD_KAFKA_RESP_ERR_SHARE_SESSION_LIMIT_REACHED);
}

/* GROUP_AUTHORIZATION_FAILED on ShareAcknowledge propagates through
 * the default-case path (previously hit `default: break` with no ack
 * propagation). */
static void test_commit_sync_group_authorization_failed(void) {
        do_test_commit_sync_top_level_err(
            "group-auth-failed", RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED);
}

/* Same default-case path as group-auth-failed with a different err. */
static void test_commit_sync_topic_authorization_failed(void) {
        do_test_commit_sync_top_level_err(
            "topic-auth-failed", RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
}

/* Generic protocol error to confirm unknown / fatal codes also
 * propagate through the default-case path. */
static void test_commit_sync_invalid_request(void) {
        do_test_commit_sync_top_level_err("invalid-request",
                                          RD_KAFKA_RESP_ERR_INVALID_REQUEST);
}

/* ===================================================================
 *  Test — top-level error is propagated to all partitions in
 *         multi-partition acknowledgement.
 *
 *  Creates a topic with multiple partitions, consumes and acknowledges
 *  records from all partitions, injects a top-level error on
 *  ShareAcknowledge, and verifies that commit_sync returns the error
 *  for EVERY partition that was part of the acknowledgement request.
 *
 *  This ensures the error propagation logic correctly applies the
 *  top-level error to all partitions in the ack_details list, not
 *  just the first one.
 * =================================================================== */
static void test_commit_sync_multi_partition_top_level_error(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_error_t *error;
        const char *topic            = "0182-multi-partition-error";
        const char *group            = "sg-0182-multi-partition-error";
        const int partition_cnt      = 3;
        const int msgs_per_partition = 5;
        const int total_msgs         = partition_cnt * msgs_per_partition;
        rd_kafka_resp_err_t injected_err =
            RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH;
        rd_kafka_messages_t *batches[CONSUME_ARRAY] = {0};
        int batch_cnt                               = 0;
        int total_consumed                          = 0;
        int acked                                   = 0;
        int attempts                                = 0;
        int i;
        test_ack_cb_state_t cb_state = {0};

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        /* Create topic with multiple partitions */
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic,
                                               partition_cnt,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic with %d partitions", partition_cnt);

        /* Produce messages to all partitions explicitly */
        for (i = 0; i < partition_cnt; i++)
                mock_produce_partition(ctx.producer, topic, i,
                                       msgs_per_partition);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             &cb_state, test_share_ack_cb);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Consume messages from all partitions */
        while (total_consumed < total_msgs && attempts++ < 50) {
                rd_kafka_messages_t *batch = NULL;
                size_t rcvd                = 0;
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                if (rcvd == 0) {
                        rd_kafka_messages_destroy(batch);
                        continue;
                }
                TEST_ASSERT(batch_cnt < CONSUME_ARRAY, "batch buffer overflow");
                batches[batch_cnt++] = batch;
                total_consumed += (int)rcvd;
        }

        TEST_ASSERT(total_consumed == total_msgs,
                    "expected to consume %d messages from %d partitions, "
                    "got %d",
                    total_msgs, partition_cnt, total_consumed);

        /* Acknowledge all messages */
        for (i = 0; i < batch_cnt; i++) {
                size_t j;
                size_t rcvd = rd_kafka_messages_count(batches[i]);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batches[i], j);
                        if (!rkm->err) {
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                acked++;
                        }
                }
        }

        TEST_ASSERT(acked == total_msgs, "expected to ack %d messages, got %d",
                    total_msgs, acked);

        /* Inject top-level error on next ShareAcknowledge */
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        ctx.mcluster, 1, RD_KAFKAP_ShareAcknowledge, 1,
                        injected_err, 0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push error");

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);

        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL, "expected non-NULL partition results");

        /* Verify ALL partitions have the injected error */
        TEST_ASSERT(partitions->cnt == partition_cnt,
                    "expected results for %d partitions, got %d", partition_cnt,
                    partitions->cnt);

        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                TEST_SAY("%s [%" PRId32 "]: %s\n", rktpar->topic,
                         rktpar->partition, rd_kafka_err2name(rktpar->err));
                TEST_ASSERT(rktpar->err == injected_err,
                            "partition [%" PRId32 "]: expected %s, got %s",
                            rktpar->partition, rd_kafka_err2name(injected_err),
                            rd_kafka_err2name(rktpar->err));
        }

        rd_kafka_topic_partition_list_destroy(partitions);

        /* Verify callback was invoked with the error.
         * Callback is invoked once per partition, so we expect
         * partition_cnt callbacks. */
        TEST_ASSERT(cb_state.callback_cnt == partition_cnt,
                    "expected %d callbacks (one per partition), got %d",
                    partition_cnt, cb_state.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&cb_state) == injected_err,
                    "expected callback err %s, got %s",
                    rd_kafka_err2name(injected_err),
                    rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));
        TEST_ASSERT(cb_state.total_offsets == total_msgs,
                    "expected callback total_offsets %d, got %zu", total_msgs,
                    cb_state.total_offsets);

        for (i = 0; i < batch_cnt; i++)
                rd_kafka_messages_destroy(batches[i]);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&cb_state);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/* ===================================================================
 *  Test — top-level error on ShareFetch with piggybacked acks is
 *         propagated to callback for all partitions.
 *
 *  Uses implicit mode where acks are piggybacked on ShareFetch.
 *  Creates a topic with multiple partitions, consumes messages in
 *  implicit mode (auto-acknowledge), then injects a top-level error
 *  on the next ShareFetch request (which carries piggybacked acks).
 *
 *  Verifies that the acknowledgement callback is invoked with the
 *  error for all partitions that had piggybacked acks.
 * =================================================================== */
static void test_consume_batch_multi_partition_top_level_error(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        const char *topic            = "0182-consume-multi-partition-error";
        const char *group            = "sg-0182-consume-multi-partition-error";
        const int partition_cnt      = 3;
        const int msgs_per_partition = 5;
        const int total_msgs         = partition_cnt * msgs_per_partition;
        rd_kafka_resp_err_t injected_err =
            RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND;
        rd_kafka_messages_t *batch = NULL;
        int total_consumed         = 0;
        int attempts               = 0;
        int i;
        test_ack_cb_state_t cb_state = {0};

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        /* Create topic with multiple partitions */
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic,
                                               partition_cnt,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic with %d partitions", partition_cnt);

        /* Produce messages to all partitions explicitly */
        for (i = 0; i < partition_cnt; i++)
                mock_produce_partition(ctx.producer, topic, i,
                                       msgs_per_partition);

        /* Use implicit mode - acks are piggybacked on ShareFetch */
        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "implicit",
                                             &cb_state, test_share_ack_cb);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* First consume batch - establishes session, consumes messages */
        while (total_consumed < total_msgs && attempts++ < 50) {
                size_t rcvd = 0;
                error       = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                total_consumed += (int)rcvd;
                /* Destroy messages - in implicit mode they're
                 * auto-acknowledged */
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(total_consumed == total_msgs,
                    "expected to consume %d messages from %d partitions, "
                    "got %d",
                    total_msgs, partition_cnt, total_consumed);

        /* Produce more messages to trigger another ShareFetch with
         * piggybacked acks from the previous consume */
        for (i = 0; i < partition_cnt; i++)
                mock_produce_partition(ctx.producer, topic, i,
                                       msgs_per_partition);

        /* Inject top-level error on next ShareFetch (which will carry
         * piggybacked acks from the previous consume_batch) */
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        ctx.mcluster, 1, RD_KAFKAP_ShareFetch, 1, injected_err,
                        0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push error on ShareFetch");

        /* Next consume_batch triggers ShareFetch with piggybacked acks.
         * The error should trigger the callback for the piggybacked acks. */
        total_consumed = 0;
        attempts       = 0;
        while (total_consumed < total_msgs && attempts++ < 50) {
                size_t rcvd = 0;
                size_t j;
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        /* May get errors due to injected error */
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                total_consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                /* Break after we've given the callback a chance to fire */
                if (cb_state.callback_cnt > 0)
                        break;
        }

        /* Verify callback was invoked with the error for piggybacked acks.
         * The callback should have been invoked for the acks that were
         * piggybacked on the ShareFetch that got the error. */
        TEST_ASSERT(cb_state.callback_cnt >= 1,
                    "expected at least 1 callback for piggybacked acks, got %d",
                    cb_state.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&cb_state) == injected_err,
                    "expected callback err %s, got %s",
                    rd_kafka_err2name(injected_err),
                    rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));
        /* In implicit mode, we expect the callback to be invoked for the
         * first batch of messages that were piggybacked */
        TEST_ASSERT(cb_state.total_offsets > 0,
                    "expected callback total_offsets > 0, got %zu",
                    cb_state.total_offsets);

        TEST_SAY(
            "Callback invoked %d times with %zu total offsets, first_err=%s\n",
            cb_state.callback_cnt, cb_state.total_offsets,
            rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&cb_state);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/* ===================================================================
 *  Test — commit_sync at session epoch 0 returns
 *         INVALID_SHARE_SESSION_EPOCH without sending a
 *         ShareAcknowledge request.
 *
 *  When the broker session epoch is 0 (new consumer or post-reset)
 *  there is no session state to acknowledge against, so the client
 *  must fail acks locally.
 *
 *  Two-phase test:
 *    Phase 1: Trigger session reset by injecting
 *             SHARE_SESSION_NOT_FOUND on the first ShareAcknowledge.
 *             commit_sync surfaces SHARE_SESSION_NOT_FOUND for the
 *             partition; broker thread resets epoch to 0.
 *    Phase 2: Acknowledge remaining records and call commit_sync
 *             again. With epoch 0 the client fails acks locally: no
 *             ShareAcknowledge is sent, commit_sync returns
 *             INVALID_SHARE_SESSION_EPOCH for the partition.
 * =================================================================== */
static rd_bool_t is_share_ack_request(rd_kafka_mock_request_t *request,
                                      void *opaque) {
        return rd_kafka_mock_request_api_key(request) ==
               RD_KAFKAP_ShareAcknowledge;
}

static void
test_commit_sync_at_epoch_zero_returns_invalid_session_epoch_error(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_error_t *error;
        const char *topic = "0182-epoch-zero-ack";
        const char *group = "sg-0182-epoch-zero-ack";
        const int msgcnt  = 10;
        rd_kafka_message_t *rkmessages[CONSUME_ARRAY];
        rd_kafka_messages_t *batches[CONSUME_ARRAY] = {0};
        int batch_cnt                               = 0;
        int total_consumed                          = 0;
        int attempts                                = 0;
        size_t share_ack_cnt;
        int i;
        test_ack_cb_state_t cb_state = {0};

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        mock_produce(ctx.producer, topic, msgcnt);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             &cb_state, test_share_ack_cb);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Phase 0: consume all 10 records. Hold message handles for
         * acknowledge in phase 1 and phase 2. */
        while (total_consumed < msgcnt && attempts++ < 30) {
                rd_kafka_messages_t *batch = NULL;
                size_t rcvd                = 0;
                size_t j;
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                if (rcvd == 0) {
                        rd_kafka_messages_destroy(batch);
                        continue;
                }
                /* Flatten message handles into rkmessages for the
                 * phase-1/phase-2 partial-ack indexing pattern. */
                for (j = 0; j < rcvd && total_consumed < CONSUME_ARRAY; j++)
                        rkmessages[total_consumed++] =
                            rd_kafka_messages_get(batch, j);
                TEST_ASSERT(batch_cnt < CONSUME_ARRAY, "batch buffer overflow");
                batches[batch_cnt++] = batch;
        }
        TEST_ASSERT(total_consumed == msgcnt,
                    "Phase 0: expected %d records, got %d", msgcnt,
                    total_consumed);

        /* Phase 1: ACCEPT first 5 records, inject SHARE_SESSION_NOT_FOUND
         * on next ShareAcknowledge, call commit_sync and verify the err
         * propagates. The buf reply handler resets the broker session
         * epoch to 0 on this error. */
        for (i = 0; i < 5; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        rd_kafka_mock_start_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);

        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        ctx.mcluster, 1, RD_KAFKAP_ShareAcknowledge, 1,
                        RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND,
                        0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push SHARE_SESSION_NOT_FOUND");

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 1000, &partitions);
        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "Phase 1: expected non-NULL partition results");
        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *p = &partitions->elems[i];
                TEST_SAY("Phase 1 %s [%" PRId32 "]: %s\n", p->topic,
                         p->partition, rd_kafka_err2name(p->err));
                TEST_ASSERT(p->err == RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND,
                            "Phase 1: expected SHARE_SESSION_NOT_FOUND, "
                            "got %s",
                            rd_kafka_err2name(p->err));
        }
        rd_kafka_topic_partition_list_destroy(partitions);

        share_ack_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_ack_request, NULL);
        TEST_ASSERT(share_ack_cnt == 1,
                    "Phase 1: expected 1 ShareAck request, got %" PRIusz,
                    share_ack_cnt);

        /* Verify Phase 1 callback was invoked with SHARE_SESSION_NOT_FOUND */
        TEST_ASSERT(cb_state.callback_cnt == 1,
                    "Phase 1: expected 1 callback, got %d",
                    cb_state.callback_cnt);
        TEST_ASSERT(
            test_ack_cb_state_first_err(&cb_state) ==
                RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND,
            "Phase 1: expected callback err SHARE_SESSION_NOT_FOUND, got %s",
            rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));
        TEST_ASSERT(cb_state.total_offsets == 5,
                    "Phase 1: expected 5 offsets in callback, got %zu",
                    cb_state.total_offsets);

        /* Reset callback state for Phase 2 */
        test_ack_cb_state_destroy(&cb_state);

        /* Phase 2: ACCEPT remaining 5 records and call commit_sync
         * again. Broker epoch is 0 (session reset by phase 1). B4a
         * must fire: no ShareAck request sent, commit_sync returns
         * INVALID_SHARE_SESSION_EPOCH per partition. */
        rd_kafka_mock_clear_requests(ctx.mcluster);

        for (i = 5; i < msgcnt; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 1000, &partitions);
        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "Phase 2: expected non-NULL partition results");
        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *p = &partitions->elems[i];
                TEST_SAY("Phase 2 %s [%" PRId32 "]: %s\n", p->topic,
                         p->partition, rd_kafka_err2name(p->err));
                TEST_ASSERT(p->err ==
                                RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH,
                            "Phase 2: expected INVALID_SHARE_SESSION_EPOCH, "
                            "got %s",
                            rd_kafka_err2name(p->err));
        }
        rd_kafka_topic_partition_list_destroy(partitions);

        share_ack_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_ack_request, NULL);
        TEST_ASSERT(share_ack_cnt == 0,
                    "Phase 2: expected 0 ShareAck requests "
                    "(local epoch-0 fail should have prevented send), "
                    "got %" PRIusz,
                    share_ack_cnt);

        /* Verify Phase 2 callback was invoked with INVALID_SHARE_SESSION_EPOCH
         * (local fail because session epoch is 0) */
        TEST_ASSERT(cb_state.callback_cnt == 1,
                    "Phase 2: expected 1 callback, got %d",
                    cb_state.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&cb_state) ==
                        RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH,
                    "Phase 2: expected callback err "
                    "INVALID_SHARE_SESSION_EPOCH, got %s",
                    rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));
        TEST_ASSERT(cb_state.total_offsets == 5,
                    "Phase 2: expected 5 offsets in callback, got %zu",
                    cb_state.total_offsets);

        rd_kafka_mock_stop_request_tracking(ctx.mcluster);

        for (i = 0; i < batch_cnt; i++)
                rd_kafka_messages_destroy(batches[i]);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&cb_state);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/* ===================================================================
 *  Test — consume_batch with session epoch 0 strips piggybacked
 *         acks from the ShareFetch wire request.
 *
 *  Same shape as test_commit_sync_at_epoch_zero_..._error but Phase
 *  2 calls consume_batch (which triggers a FANOUT -> ShareFetch
 *  with should_fetch=true) instead of commit_sync. With session
 *  epoch == 0 and any cached piggyback acks attached, the strip
 *  path in broker_share_rpc fires: acks are pre-set with
 *  INVALID_SHARE_SESSION_EPOCH and detached from rko before
 *  ShareFetch is built, so the wire request goes out with no ack
 *  data section.
 *
 *  Asserts (per-partition):
 *    - Wire-level: ShareFetch is sent (>= 1), no extra ShareAck
 *      requests fire.
 *    - Acknowledgement callback fires with
 *      INVALID_SHARE_SESSION_EPOCH for each stripped batch (the
 *      session-establish ShareFetch's response would normally cause
 *      the parser to write the broker's per-partition
 *      AcknowledgementErrorCode, but the parser conditional preserves
 *      our pre-set).
 *
 *  To verify the strip path manually, run with:
 *    TEST_DEBUG=fetch,broker,cgrp TESTS=0182 \
 *        SUBTESTS=test_consume_batch_at_epoch_zero make
 *  and look for the "Stripping N piggybacked ack batches" SHAREFETCH
 *  log line in stderr.
 * =================================================================== */
static rd_bool_t is_share_fetch_request(rd_kafka_mock_request_t *request,
                                        void *opaque) {
        return rd_kafka_mock_request_api_key(request) == RD_KAFKAP_ShareFetch;
}

static void test_consume_batch_at_epoch_zero_strips_piggyback_acks(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_error_t *error;
        const char *topic = "0182-epoch-zero-piggyback";
        const char *group = "sg-0182-epoch-zero-piggyback";
        const int msgcnt  = 10;
        rd_kafka_message_t *rkmessages[CONSUME_ARRAY];
        rd_kafka_messages_t *phase0_batch = NULL;
        rd_kafka_messages_t *phase2_batch = NULL;
        int attempts                      = 0;
        size_t rcvd                       = 0;
        size_t share_ack_cnt;
        size_t share_fetch_cnt;
        int i;
        test_ack_cb_state_t cb_state = {0};

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        mock_produce(ctx.producer, topic, msgcnt);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             &cb_state, test_share_ack_cb);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Phase 0: consume all msgcnt records in a single consume_batch
         * call (with retry-on-empty for transient cases). Explicit-mode
         * contract requires every record from a previous consume_batch
         * to be acknowledged before the next call, so we must not loop
         * and accumulate without acking each batch first. msgcnt is far
         * below max.poll.records (default 500), so a non-empty call
         * returns the full set. */
        while (rcvd == 0 && attempts++ < 30) {
                rd_kafka_messages_destroy(phase0_batch);
                phase0_batch = NULL;
                error = rd_kafka_share_poll(rkshare, 3000, &phase0_batch);
                if (error)
                        rd_kafka_error_destroy(error);
                rcvd = rd_kafka_messages_count(phase0_batch);
        }
        TEST_ASSERT(rcvd == (size_t)msgcnt,
                    "Phase 0: expected %d records in single batch, "
                    "got %" PRIusz,
                    msgcnt, rcvd);
        for (i = 0; i < msgcnt; i++)
                rkmessages[i] = rd_kafka_messages_get(phase0_batch, i);

        /* Phase 1: ACCEPT first 5 records, inject SHARE_SESSION_NOT_FOUND
         * on next ShareAcknowledge, call commit_sync to trigger session
         * reset on the broker (epoch -> 0). */
        for (i = 0; i < 5; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        rd_kafka_mock_start_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);

        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        ctx.mcluster, 1, RD_KAFKAP_ShareAcknowledge, 1,
                        RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND,
                        0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push SHARE_SESSION_NOT_FOUND");

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 1000, &partitions);
        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "Phase 1: expected non-NULL partition results");
        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *p = &partitions->elems[i];
                TEST_SAY("Phase 1 %s [%" PRId32 "]: %s\n", p->topic,
                         p->partition, rd_kafka_err2name(p->err));
                TEST_ASSERT(p->err == RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND,
                            "Phase 1: expected SHARE_SESSION_NOT_FOUND, "
                            "got %s",
                            rd_kafka_err2name(p->err));
        }
        rd_kafka_topic_partition_list_destroy(partitions);

        share_ack_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_ack_request, NULL);
        TEST_ASSERT(share_ack_cnt == 1,
                    "Phase 1: expected 1 ShareAck request, got %" PRIusz,
                    share_ack_cnt);

        /* Verify Phase 1 callback was invoked with SHARE_SESSION_NOT_FOUND */
        TEST_ASSERT(cb_state.callback_cnt == 1,
                    "Phase 1: expected 1 callback, got %d",
                    cb_state.callback_cnt);
        TEST_ASSERT(
            test_ack_cb_state_first_err(&cb_state) ==
                RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND,
            "Phase 1: expected callback err SHARE_SESSION_NOT_FOUND, got %s",
            rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));

        /* Reset callback state for Phase 2 */
        test_ack_cb_state_destroy(&cb_state);

        /* Phase 2: ACCEPT remaining 5 records and call consume_batch
         * (NOT commit_sync). This triggers a FANOUT -> ShareFetch with
         * should_fetch=true. Broker epoch is 0 (reset in phase 1). If
         * any piggyback acks are attached when broker_share_rpc runs,
         * the strip path fires and pre-sets each batch's err to
         * INVALID_SHARE_SESSION_EPOCH. ShareFetch goes out with no ack
         * data section.
         *
         * Wire-level assertions:
         *   - At least 1 new ShareFetch request was sent (session
         *     re-establishment).
         *   - 0 new ShareAck requests (strip prevented send if any
         *     piggyback acks were present; ack-only path also doesn't
         *     fire because we did not call commit_sync). */
        rd_kafka_mock_clear_requests(ctx.mcluster);

        for (i = 5; i < msgcnt; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        /* Single consume_batch triggers the strip-mode FANOUT.
         * Records here may be re-deliveries after lock expiry — we
         * don't assert on contents, only on wire-level counts.
         * test_wait_for_cb_with_poll below tolerates the explicit-mode
         * __STATE the next consume_batch may return for these
         * un-acknowledged records (rcvd stays 0). */
        error = rd_kafka_share_poll(rkshare, 1000, &phase2_batch);
        if (error)
                rd_kafka_error_destroy(error);
        rd_kafka_messages_destroy(phase2_batch);
        phase2_batch = NULL;

        share_fetch_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_fetch_request, NULL);
        share_ack_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_ack_request, NULL);

        TEST_SAY("Phase 2 wire counts: ShareFetch=%" PRIusz
                 ", ShareAck=%" PRIusz "\n",
                 share_fetch_cnt, share_ack_cnt);

        TEST_ASSERT(share_fetch_cnt >= 1,
                    "Phase 2: expected >= 1 ShareFetch (session "
                    "re-establish), got %" PRIusz,
                    share_fetch_cnt);
        TEST_ASSERT(share_ack_cnt == 0,
                    "Phase 2: expected 0 ShareAck "
                    "(strip should have prevented any piggyback ack "
                    "send and no ack-only path fired), got %" PRIusz,
                    share_ack_cnt);

        /* Wait for the per-partition acknowledgement callback to fire
         * (dispatched on rk_rep when the SHARE_FETCH op reply reaches
         * the main thread). */
        TEST_ASSERT(test_wait_for_cb_with_poll(&cb_state, rkshare, 1, 5000),
                    "Phase 2: timed out waiting for ack callback");

        /* The strip path pre-set INVALID_SHARE_SESSION_EPOCH on each
         * batch in ack_details. The session-establish ShareFetch
         * succeeds and the broker echoes the added partition in its
         * response, so the parser would normally write the broker's
         * AcknowledgementErrorCode (NO_ERROR) onto the batch — the
         * parser conditional (override only _IN_PROGRESS) preserves
         * the pre-set instead. The callback fires with the pre-set
         * err. */
        TEST_ASSERT(cb_state.callback_cnt == 1,
                    "Phase 2: expected 1 callback, got %d",
                    cb_state.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&cb_state) ==
                        RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH,
                    "Phase 2: expected callback err "
                    "INVALID_SHARE_SESSION_EPOCH, got %s",
                    rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));
        TEST_ASSERT(cb_state.total_offsets == 5,
                    "Phase 2: expected 5 acked offsets in callback, "
                    "got %" PRIusz,
                    cb_state.total_offsets);

        rd_kafka_mock_stop_request_tracking(ctx.mcluster);

        rd_kafka_messages_destroy(phase0_batch);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&cb_state);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/* ===================================================================
 *  Test — strip + ShareFetch response top-level err: callback err
 *         remains INVALID_SHARE_SESSION_EPOCH (not the response err).
 *
 *  Same flow as test_consume_batch_at_epoch_zero_strips_piggyback_acks
 *  but in Phase 2 we ALSO inject a top-level err on the
 *  session-establish ShareFetch response. The buf-callback's helper
 *  (rd_kafka_share_fetch_op_reply_with_err) will be called with that
 *  err — its conditional override (only _IN_PROGRESS) must NOT
 *  clobber the pre-set INVALID_SHARE_SESSION_EPOCH on the stripped
 *  batches.
 *
 *  Asserts (per-partition via callback):
 *    - Wire-level: ShareFetch is sent, no ShareAck.
 *    - Acknowledgement callback fires with
 *      INVALID_SHARE_SESSION_EPOCH (NOT the injected response err)
 *      for each stripped batch.
 * =================================================================== */
static void test_strip_pre_set_survives_sharefetch_err(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_error_t *error;
        const char *topic = "0182-epoch-zero-piggyback-fetch-err";
        const char *group = "sg-0182-epoch-zero-piggyback-fetch-err";
        const int msgcnt  = 10;
        rd_kafka_message_t *rkmessages[CONSUME_ARRAY];
        rd_kafka_messages_t *phase0_batch = NULL;
        rd_kafka_messages_t *phase2_batch = NULL;
        int attempts                      = 0;
        size_t rcvd                       = 0;
        size_t share_ack_cnt;
        size_t share_fetch_cnt;
        int i;
        test_ack_cb_state_t cb_state = {0};

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        mock_produce(ctx.producer, topic, msgcnt);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             &cb_state, test_share_ack_cb);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Phase 0: consume all msgcnt records in a single consume_batch
         * call (with retry-on-empty for transient cases). Explicit-mode
         * contract requires every record from a previous consume_batch
         * to be acknowledged before the next call, so we must not loop
         * and accumulate without acking each batch first. msgcnt is far
         * below max.poll.records (default 500), so a non-empty call
         * returns the full set. */
        while (rcvd == 0 && attempts++ < 30) {
                rd_kafka_messages_destroy(phase0_batch);
                phase0_batch = NULL;
                error = rd_kafka_share_poll(rkshare, 3000, &phase0_batch);
                if (error)
                        rd_kafka_error_destroy(error);
                rcvd = rd_kafka_messages_count(phase0_batch);
        }
        TEST_ASSERT(rcvd == (size_t)msgcnt,
                    "Phase 0: expected %d records in single batch, "
                    "got %" PRIusz,
                    msgcnt, rcvd);
        for (i = 0; i < msgcnt; i++)
                rkmessages[i] = rd_kafka_messages_get(phase0_batch, i);

        /* Phase 1: ACCEPT first 5 records, inject SHARE_SESSION_NOT_FOUND
         * on next ShareAcknowledge, call commit_sync to trigger session
         * reset on the broker (epoch -> 0). */
        for (i = 0; i < 5; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        rd_kafka_mock_start_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);

        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        ctx.mcluster, 1, RD_KAFKAP_ShareAcknowledge, 1,
                        RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND,
                        0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push SHARE_SESSION_NOT_FOUND");

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 1000, &partitions);
        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "Phase 1: expected non-NULL partition results");
        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *p = &partitions->elems[i];
                TEST_ASSERT(p->err == RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND,
                            "Phase 1: expected SHARE_SESSION_NOT_FOUND, "
                            "got %s",
                            rd_kafka_err2name(p->err));
        }
        rd_kafka_topic_partition_list_destroy(partitions);

        /* Reset callback state for Phase 2 */
        test_ack_cb_state_destroy(&cb_state);

        /* Phase 2: ACCEPT remaining 5 records. Inject
         * SHARE_SESSION_LIMIT_REACHED on the next ShareFetch — this is
         * the strip-mode ShareFetch (epoch 0, with stripped piggyback
         * acks) that goes out from consume_batch. The buf-callback's
         * helper is then called with SHARE_SESSION_LIMIT_REACHED on a
         * batch already pre-set to INVALID_SHARE_SESSION_EPOCH; the
         * helper conditional (only override _IN_PROGRESS) must
         * preserve the pre-set. */
        rd_kafka_mock_clear_requests(ctx.mcluster);

        for (i = 5; i < msgcnt; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        ctx.mcluster, 1, RD_KAFKAP_ShareFetch, 1,
                        RD_KAFKA_RESP_ERR_SHARE_SESSION_LIMIT_REACHED,
                        0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push SHARE_SESSION_LIMIT_REACHED on next ShareFetch");

        /* Single consume_batch triggers the strip-mode FANOUT.
         * Records here may be re-deliveries after lock expiry — we
         * don't assert on contents, only on wire-level counts.
         * test_wait_for_cb_with_poll below tolerates the explicit-mode
         * __STATE the next consume_batch may return for these
         * un-acknowledged records (rcvd stays 0). */
        error = rd_kafka_share_poll(rkshare, 1000, &phase2_batch);
        if (error)
                rd_kafka_error_destroy(error);
        rd_kafka_messages_destroy(phase2_batch);
        phase2_batch = NULL;

        share_fetch_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_fetch_request, NULL);
        share_ack_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_ack_request, NULL);

        TEST_SAY("Phase 2 wire counts: ShareFetch=%" PRIusz
                 ", ShareAck=%" PRIusz "\n",
                 share_fetch_cnt, share_ack_cnt);

        TEST_ASSERT(share_fetch_cnt >= 1,
                    "Phase 2: expected >= 1 ShareFetch, got %" PRIusz,
                    share_fetch_cnt);
        TEST_ASSERT(share_ack_cnt == 0,
                    "Phase 2: expected 0 ShareAck (strip), got %" PRIusz,
                    share_ack_cnt);

        /* Wait for the per-partition acknowledgement callback. */
        TEST_ASSERT(test_wait_for_cb_with_poll(&cb_state, rkshare, 1, 5000),
                    "Phase 2: timed out waiting for ack callback");

        /* The injected ShareFetch top-level err
         * (SHARE_SESSION_LIMIT_REACHED) reached the
         * rd_kafka_share_fetch_op_reply_with_err helper. The helper's
         * conditional override (only _IN_PROGRESS) must NOT clobber
         * the pre-set INVALID_SHARE_SESSION_EPOCH. */
        TEST_ASSERT(cb_state.callback_cnt == 1,
                    "Phase 2: expected 1 callback, got %d",
                    cb_state.callback_cnt);
        TEST_ASSERT(test_ack_cb_state_first_err(&cb_state) ==
                        RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH,
                    "Phase 2: expected callback err "
                    "INVALID_SHARE_SESSION_EPOCH (pre-set preserved), "
                    "got %s",
                    rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));
        TEST_ASSERT(cb_state.total_offsets == 5,
                    "Phase 2: expected 5 acked offsets in callback, "
                    "got %" PRIusz,
                    cb_state.total_offsets);

        rd_kafka_mock_stop_request_tracking(ctx.mcluster);

        rd_kafka_messages_destroy(phase0_batch);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&cb_state);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}

/* ===================================================================
 *  Wire-level socket timeout matrix.
 *
 *  Exercises commit_sync under a socket-timeout-induced connection
 *  teardown. The two timer layers in the share-acknowledge path are
 *  intentionally decoupled:
 *
 *    - The app-visible commit_sync(timeout_ms) deadline drives the
 *      timeout cb that stamps REQUEST_TIMED_OUT on the per-partition
 *      results.
 *    - The wire RPC carries the broker connection's socket.timeout.ms
 *      and tears the connection down (default socket.max.fails = 1)
 *      when it fires.
 *
 *  Three (api_timeout_ms, socket_timeout_ms, rtt_ms) triples cover
 *  the cases where api > socket, api == socket, and api < socket. In
 *  all three, rtt_ms > socket_timeout_ms so the wire eventually times
 *  out and the connection is torn down (broker drops the session as
 *  a result of the TCP close).
 *
 *  Two flow variants build on the same setup:
 *
 *    full_ack_then_more   — Phase 1 commits all consumed records.
 *      Phase 2 produces and consumes new records on a fresh session
 *      and expects NO_ERROR on the second commit_sync.
 *
 *    partial_ack_then_remaining — Phase 1 commits only half. The
 *      records left in the local inflight map were ACQUIRED on the
 *      now-dropped session, so Phase 2's commit_sync surfaces an
 *      INVALID_RECORD_STATE / SHARE_SESSION_NOT_FOUND /
 *      INVALID_SHARE_SESSION_EPOCH-class error (when session-err
 *      translation lands at the app-facing boundary this narrows
 *      to INVALID_RECORD_STATE).
 *
 *  TODO KIP-932: add multi-broker variants once the single-broker
 *  matrix is stable. Multi-broker exercises the case where only one
 *  broker is slow — partitions on other brokers should commit
 *  immediately without waiting for the slow broker's socket timer.
 * =================================================================== */

#define SOCKET_TIMEOUT_MATRIX_RECORD_LOCK_MS     600000
#define SOCKET_TIMEOUT_MATRIX_PARTITIONS         3
#define SOCKET_TIMEOUT_MATRIX_MSGS_PER_PARTITION 10

/**
 * @brief Create a share consumer with a custom socket.timeout.ms.
 */
static rd_kafka_share_t *create_share_consumer_socket_timeout(
    const char *bootstraps,
    const char *group_id,
    const char *ack_mode,
    int socket_timeout_ms,
    test_ack_cb_state_t *cb_state,
    void (*cb)(rd_kafka_share_t *,
               rd_kafka_share_partition_offsets_list_t *,
               rd_kafka_resp_err_t,
               void *)) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        char buf[32];

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);
        test_conf_set(conf, "share.acknowledgement.mode", ack_mode);

        rd_snprintf(buf, sizeof(buf), "%d", socket_timeout_ms);
        test_conf_set(conf, "socket.timeout.ms", buf);

        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");

        if (cb && cb_state) {
                rd_kafka_error_t *error =
                    rd_kafka_share_set_acknowledgement_commit_cb(rkshare, cb,
                                                                 cb_state);
                TEST_ASSERT(error == NULL,
                            "Failed to set acknowledgement commit callback: "
                            "%s",
                            rd_kafka_error_string(error));
        }
        return rkshare;
}

/**
 * @brief Consume up to \p expected records (across one or more
 *        share_poll calls), acknowledging the first \p ack_first.
 *
 * Caller owns the returned batch via \p *out_batch and must
 * rd_kafka_messages_destroy() it. The flattened \p rkmessages array
 * is populated with pointers borrowed from the batch (lifetime tied
 * to the batch). Asserts that exactly \p expected records were
 * received within the polling budget. Used both for the pre-stage
 * Phase 1 consume (broker has all records ready, typically arrives
 * in a single batch) and for the post-teardown Phase 2 consume
 * (records may trickle in across multiple batches as the new
 * session warms up).
 */
static void consume_first_batch(rd_kafka_share_t *rkshare,
                                rd_kafka_message_t **rkmessages,
                                int expected,
                                rd_kafka_messages_t **out_batch) {
        size_t rcvd  = 0;
        int attempts = 0;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        int j;

        /* Spin until the first non-empty batch arrives. The test
         * pre-stages the broker with all \p expected records so the
         * batch we receive will contain exactly that many. */
        while (rcvd == 0 && attempts++ < 30) {
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        TEST_SAY("consume_first_batch: err=%s\n",
                                 rd_kafka_err2name(rd_kafka_error_code(error)));
                        rd_kafka_error_destroy(error);
                }
                rcvd = rd_kafka_messages_count(batch);
        }

        TEST_ASSERT((int)rcvd == expected,
                    "Expected %d records in first batch, got %zu", expected,
                    rcvd);

        for (j = 0; j < (int)rcvd; j++) {
                rkmessages[j] = rd_kafka_messages_get(batch, j);
                TEST_ASSERT(!rkmessages[j]->err,
                            "Unexpected per-record err: %s",
                            rd_kafka_err2str(rkmessages[j]->err));
        }

        *out_batch = batch;
}

/**
 * @brief Drain pending ack callbacks via commit_async until at least
 *        \p min_callbacks have been observed, or \p timeout_ms elapses.
 *
 * commit_async's first step drains rk_rep for callbacks. With no
 * pending acks to commit, the remainder is a no-op.
 *
 * @returns rd_true if min_callbacks observed within timeout.
 */
static rd_bool_t drain_callbacks_via_commit_async(rd_kafka_share_t *rkshare,
                                                  test_ack_cb_state_t *cb_state,
                                                  int min_callbacks,
                                                  int timeout_ms) {
        int elapsed_ms = 0;

        while (elapsed_ms < timeout_ms) {
                if (cb_state->callback_cnt >= min_callbacks)
                        return rd_true;
                rd_kafka_error_t *err = rd_kafka_share_commit_async(rkshare);
                if (err)
                        rd_kafka_error_destroy(err);
                rd_usleep(50 * 1000, NULL);
                elapsed_ms += 50;
        }
        return cb_state->callback_cnt >= min_callbacks;
}

/**
 * @brief Test commit_sync under a wire-level socket timeout, then
 *        consume + commit a fresh batch.
 *
 *  The three timer layers (api timeout A, RTT R, socket.timeout.ms S)
 *  determine which event wins:
 *    - A smallest: commit_sync timeout cb stamps REQUEST_TIMED_OUT
 *      on results and returns at t=A. Wire request continues in
 *      flight until either R completes or S fires; late callback
 *      reflects the actual wire outcome (NO_ERROR if R < S,
 *      __TIMED_OUT if S < R).
 *    - S smallest: wire torn down at t=S. Reply handler stamps
 *      __TIMED_OUT on batches and results; commit_sync returns at
 *      ~t=S with __TIMED_OUT and callbacks fire with __TIMED_OUT.
 *    - R smallest: broker reply arrives normally; commit_sync
 *      returns NO_ERROR. Not exercised by this matrix.
 *
 *  Phase 1 measures the wait between commit_sync return and all ack
 *  callbacks landing. That wait equals max(0, min(R, S) -
 *  min(A, R, S)) and is asserted with tolerance.
 *
 *  Phase 2 produces N new records, consumes + acks + commits on the
 *  (possibly reconnected) consumer. Expects NO_ERROR for every
 *  partition and a fresh set of NO_ERROR callbacks.
 *
 *  TODO KIP-932: add multi-broker variant once single-broker matrix
 *  is stable. Multi-broker exercises the case where only one broker
 *  is slow.
 *
 *  TODO KIP-932: add partial-ack variant — Phase 1 acks only half
 *  the records, Phase 2 acks the remaining. With session drop on
 *  connection tear-down, the remaining records reference a dropped
 *  session and Phase 2's commit_sync surfaces INVALID_RECORD_STATE.
 */
static void do_test_socket_timeout_full_ack_then_more(int api_timeout_ms,
                                                      int socket_timeout_ms,
                                                      int rtt_ms) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_error_t *error;
        char topic[128];
        char group[128];
        const int partitions_total = SOCKET_TIMEOUT_MATRIX_PARTITIONS;
        const int msgcnt =
            partitions_total * SOCKET_TIMEOUT_MATRIX_MSGS_PER_PARTITION;
        rd_kafka_message_t **rkmessages;
        rd_kafka_messages_t *phase1_batch = NULL;
        rd_kafka_messages_t *phase2_batch = NULL;
        test_ack_cb_state_t cb_state      = {0};
        rd_ts_t t_p1_end_us, t_callbacks_done_us;
        int actual_wait_ms, expected_wait_ms;
        int min_between_rtt_ms_socket_timeout_ms;
        int min_between_api_timeout_ms_rtt_ms_socket_timeout_ms;
        rd_kafka_resp_err_t expected_phase1_commit_err;
        rd_kafka_resp_err_t expected_phase1_callback_err;
        int prev_callback_cnt;
        int i;
        /* Valgrind serializes threads and slows wall-clock-bound paths;
         * widen the tolerance to avoid flaky over-budget failures. */
        const int wait_tolerance_ms =
            !strcmp(test_mode, "valgrind") ? 2000 : 500;

        SUB_TEST_QUICK("api_timeout_ms=%d socket_timeout_ms=%d rtt_ms=%d",
                       api_timeout_ms, socket_timeout_ms, rtt_ms);

        /* Derive expected outcomes from the ordering of three timers:
         *
         *   api_timeout_ms    -> commit_sync API's deadline parameter;
         *                        upper bound on how long commit_sync
         *                        can block before returning
         *                        REQUEST_TIMED_OUT.
         *   rtt_ms            -> mock-injected broker round-trip-time;
         *                        time after which the broker's
         *                        ShareAcknowledge response is allowed
         *                        to leave the broker side (records are
         *                        applied broker-side immediately on
         *                        request receive — see
         *                        rdkafka_mock_handlers.c:3811-3840).
         *   socket_timeout_ms -> wire-level socket.timeout.ms; after
         *                        this the connection is torn down and
         *                        any in-flight request fails with
         *                        __TIMED_OUT (default socket.max.fails
         *                        of 1 makes a single failure terminal).
         *
         * The expected wait between commit_sync returning and the last
         * ack callback landing equals
         *   max(0, min_between(rtt_ms, socket_timeout_ms)
         *          - min_between(api_timeout_ms, rtt_ms,
         *                        socket_timeout_ms))
         *
         * The reasoning:
         *
         *   - commit_sync returns at
         *     t_p1_end = min_between(api_timeout_ms, rtt_ms,
         *                            socket_timeout_ms):
         *       api_timeout_ms smallest: api timer cb fires, stamps
         *         REQUEST_TIMED_OUT on the per-partition results;
         *         send_response wakes commit_sync at ~t=api_timeout_ms.
         *       socket_timeout_ms smallest: wire socket.timeout.ms
         *         fires, broker thread reply path runs with
         *         rko_err=__TIMED_OUT, callbacks dispatched, results
         *         stamped via apply_result, commit_sync returns at
         *         ~t=socket_timeout_ms.
         *       rtt_ms smallest: broker reply arrives normally,
         *         callbacks dispatched with broker's per-partition err,
         *         results stamped, commit_sync returns at ~t=rtt_ms
         *         (NO_ERROR for this happy path — not in our matrix).
         *
         *   - All Phase 1 callbacks have landed by
         *     t_callbacks_done = min_between(rtt_ms, socket_timeout_ms):
         *       When the wire request resolves the broker-thread reply
         *       handler dispatches the per-partition callbacks. That
         *       happens when broker actually replies (t=rtt_ms) OR
         *       when socket.timeout.ms fires (t=socket_timeout_ms),
         *       whichever comes first. For
         *       api_timeout_ms < (rtt_ms, socket_timeout_ms) the
         *       callbacks fire AFTER commit_sync returned; for
         *       (rtt_ms or socket_timeout_ms) < api_timeout_ms the
         *       callbacks already fired BEFORE commit_sync returned
         *       and the wait is 0.
         *
         *   - Wait = t_callbacks_done - t_p1_end
         *          = min_between(rtt_ms, socket_timeout_ms)
         *            - min_between(api_timeout_ms, rtt_ms,
         *                          socket_timeout_ms).
         *
         * The expected callback err depends on which layer resolved
         * the wire:
         *   - rtt_ms < socket_timeout_ms: broker actually replied —
         *     callback gets broker's per-partition result (NO_ERROR,
         *     the records were applied).
         *   - socket_timeout_ms < rtt_ms: wire torn down before broker
         *     could reply — helper stamps __TIMED_OUT on batches; the
         *     app-facing funnel translates it to REQUEST_TIMED_OUT
         *     before the callback fires.
         *
         * The expected commit_sync result err comes from which layer
         * stamped results first:
         *   - api_timeout_ms < min_between(rtt_ms, socket_timeout_ms):
         *     api timer cb wrote REQUEST_TIMED_OUT into results.
         *   - socket_timeout_ms <= api_timeout_ms: broker-thread reply
         *     path wrote __TIMED_OUT into results via apply_result;
         *     the funnel translates it to REQUEST_TIMED_OUT. */
        min_between_rtt_ms_socket_timeout_ms =
            socket_timeout_ms < rtt_ms ? socket_timeout_ms : rtt_ms;
        min_between_api_timeout_ms_rtt_ms_socket_timeout_ms = api_timeout_ms;
        if (rtt_ms < min_between_api_timeout_ms_rtt_ms_socket_timeout_ms)
                min_between_api_timeout_ms_rtt_ms_socket_timeout_ms = rtt_ms;
        if (socket_timeout_ms <
            min_between_api_timeout_ms_rtt_ms_socket_timeout_ms)
                min_between_api_timeout_ms_rtt_ms_socket_timeout_ms =
                    socket_timeout_ms;
        expected_wait_ms = min_between_rtt_ms_socket_timeout_ms -
                           min_between_api_timeout_ms_rtt_ms_socket_timeout_ms;

        if (rtt_ms < api_timeout_ms && rtt_ms < socket_timeout_ms) {
                /* rtt_ms smaller than both other timers: broker reply
                 * lands before either timer fires. commit_sync sees
                 * the broker's per-partition success and callbacks
                 * fire with NO_ERROR. Happy path — included for
                 * matrix completeness, not exercising any timeout
                 * layer. */
                expected_phase1_commit_err   = RD_KAFKA_RESP_ERR_NO_ERROR;
                expected_phase1_callback_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        } else if (socket_timeout_ms < api_timeout_ms) {
                /* socket_timeout_ms < api_timeout_ms (and rtt_ms is
                 * NOT strictly smallest by the first branch): socket
                 * fires before api can. (At api == socket the race
                 * outcome is non-deterministic across runs; that
                 * boundary case is not in the matrix.)
                 *
                 * __TIMED_OUT from the broker-thread socket timer is
                 * translated to REQUEST_TIMED_OUT at the app-facing
                 * funnel. */
                expected_phase1_commit_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
                expected_phase1_callback_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
        } else if (rtt_ms < socket_timeout_ms) {
                /* api wins (api <= socket AND rtt < socket; api
                 * fires no later than broker reply at rtt). Late
                 * broker reply at rtt brings actual per-partition
                 * outcome (NO_ERROR — broker did apply the ack) to
                 * the callback. */
                expected_phase1_commit_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
                expected_phase1_callback_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        } else {
                /* api wins (api <= socket AND rtt >= socket). Socket
                 * fires before broker can reply, wire torn down; the
                 * late wire-failure err is __TIMED_OUT, translated to
                 * REQUEST_TIMED_OUT at the app-facing funnel. */
                expected_phase1_commit_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
                expected_phase1_callback_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
        }

        ctx = test_ctx_new();
        rd_kafka_mock_sharegroup_set_record_lock_duration(
            ctx.mcluster, SOCKET_TIMEOUT_MATRIX_RECORD_LOCK_MS);

        rd_snprintf(topic, sizeof(topic), "0182-fullack-a%d-s%d",
                    api_timeout_ms, socket_timeout_ms);
        rd_snprintf(group, sizeof(group), "sg-0182-fullack-a%d-s%d",
                    api_timeout_ms, socket_timeout_ms);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic,
                                               partitions_total,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        for (i = 0; i < partitions_total; i++)
                mock_produce_partition(
                    ctx.producer, topic, i,
                    SOCKET_TIMEOUT_MATRIX_MSGS_PER_PARTITION);

        rkshare = create_share_consumer_socket_timeout(
            ctx.bootstraps, group, "explicit", socket_timeout_ms, &cb_state,
            test_share_ack_cb);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        rkmessages = rd_calloc(msgcnt, sizeof(*rkmessages));

        /* Phase 1: consume the first batch (all msgcnt records
         * given the small partition count and broker readiness),
         * acknowledge everyone, then inject RTT and commit_sync. */
        consume_first_batch(rkshare, rkmessages, msgcnt, &phase1_batch);
        for (i = 0; i < msgcnt; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        rd_kafka_mock_broker_set_rtt(ctx.mcluster, -1, rtt_ms);

        partitions = NULL;
        error =
            rd_kafka_share_commit_sync(rkshare, api_timeout_ms, &partitions);
        t_p1_end_us = test_clock();

        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "Phase 1: expected non-NULL partition results");
        TEST_ASSERT(partitions->cnt == partitions_total,
                    "Phase 1: expected %d partition results, got %d",
                    partitions_total, partitions->cnt);

        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                TEST_SAY("Phase 1 commit_sync: %s [%" PRId32 "]: %s\n",
                         rktpar->topic, rktpar->partition,
                         rd_kafka_err2name(rktpar->err));
                TEST_ASSERT(rktpar->err == expected_phase1_commit_err,
                            "Phase 1: expected %s, got %s",
                            rd_kafka_err2name(expected_phase1_commit_err),
                            rd_kafka_err2name(rktpar->err));
        }
        rd_kafka_topic_partition_list_destroy(partitions);

        /* Drain ack callbacks via commit_async until we observe one
         * per partition. For socket_timeout_ms-smallest orderings the
         * callbacks fired before commit_sync returned so this returns
         * immediately. For api_timeout_ms-smallest orderings the
         * callbacks fire when the wire resolves (broker reply at
         * t=rtt_ms OR socket timer at t=socket_timeout_ms). */
        TEST_ASSERT(drain_callbacks_via_commit_async(rkshare, &cb_state,
                                                     partitions_total, 30000),
                    "Phase 1: expected %d ack callbacks within 30s, got %d",
                    partitions_total, cb_state.callback_cnt);
        t_callbacks_done_us = test_clock();

        TEST_ASSERT(test_ack_cb_state_first_err(&cb_state) ==
                        expected_phase1_callback_err,
                    "Phase 1: expected callback err %s, got %s",
                    rd_kafka_err2name(expected_phase1_callback_err),
                    rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));

        actual_wait_ms = (int)((t_callbacks_done_us - t_p1_end_us) / 1000);
        TEST_SAY(
            "Phase 1 wait t_callbacks_done - t_p1_end = %dms "
            "(expected ~%dms, tolerance %dms)\n",
            actual_wait_ms, expected_wait_ms, wait_tolerance_ms);
        TEST_ASSERT(actual_wait_ms >= expected_wait_ms - wait_tolerance_ms &&
                        actual_wait_ms <= expected_wait_ms + wait_tolerance_ms,
                    "Phase 1 wait %dms outside expected %dms +/- %dms",
                    actual_wait_ms, expected_wait_ms, wait_tolerance_ms);

        prev_callback_cnt = cb_state.callback_cnt;

        /* Phase 2: clear RTT (so Phase 2's broker response isn't
         * delayed), produce more, consume + ack + commit. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, -1, 0);

        for (i = 0; i < partitions_total; i++)
                mock_produce_partition(
                    ctx.producer, topic, i,
                    SOCKET_TIMEOUT_MATRIX_MSGS_PER_PARTITION);

        /* Free phase-1 messages. */
        rd_kafka_messages_destroy(phase1_batch);
        phase1_batch = NULL;
        memset(rkmessages, 0, msgcnt * sizeof(*rkmessages));

        consume_first_batch(rkshare, rkmessages, msgcnt, &phase2_batch);
        for (i = 0; i < msgcnt; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 5000, &partitions);
        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "Phase 2: expected non-NULL partition results");

        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                TEST_SAY("Phase 2: %s [%" PRId32 "]: %s\n", rktpar->topic,
                         rktpar->partition, rd_kafka_err2name(rktpar->err));
                TEST_ASSERT(rktpar->err == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Phase 2: expected NO_ERROR on a fresh "
                            "session, got %s",
                            rd_kafka_err2name(rktpar->err));
        }
        TEST_ASSERT(partitions->cnt == partitions_total,
                    "Phase 2: expected %d partition results, got %d",
                    partitions_total, partitions->cnt);
        rd_kafka_topic_partition_list_destroy(partitions);

        TEST_ASSERT(cb_state.callback_cnt > prev_callback_cnt,
                    "Phase 2: expected new ack callbacks; before=%d "
                    "after=%d",
                    prev_callback_cnt, cb_state.callback_cnt);

        rd_kafka_messages_destroy(phase2_batch);
        rd_free(rkmessages);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);
        test_ack_cb_state_destroy(&cb_state);

        SUB_TEST_PASS();
}

/**
 * @brief Same Phase 1 as do_test_socket_timeout_full_ack_then_more, but
 *        Phase 1 acks only half the consumed records. Phase 2 then
 *        acks the remaining half (still in the client's local inflight
 *        map) and runs commit_sync on those.
 *
 *  After the Phase 1 drain-callbacks step we clear RTT, so Phase 2's
 *  commit_sync gets a prompt broker response (no second wire-level
 *  timer to race).
 *
 *  Phase 2 outcome depends on whether the connection was torn down
 *  during Phase 1, which is equivalent to socket_timeout_ms < rtt_ms:
 *
 *    Connection alive (rtt_ms < socket_timeout_ms): broker session
 *      preserved; the remaining 15 records are still ACQUIRED for
 *      this member on the same session. Phase 2's ShareAck advances
 *      the session epoch normally; broker returns NO_ERROR per
 *      partition.
 *
 *    Connection killed (socket_timeout_ms < rtt_ms): broker dropped
 *      the session on TCP close. The remaining 15 records' ACQUIRED
 *      state was released to AVAILABLE by `release_member_locks`.
 *      Phase 2's broker-thread reconnects and sends ShareAck with
 *      session epoch reset to 0 client-side. Broker rejects with
 *      INVALID_SHARE_SESSION_EPOCH at top-level (no active session
 *      for this member at epoch 0 outside of a ShareFetch). The
 *      top-level err propagates to all partitions via the existing
 *      `rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err`
 *      helper.
 *
 *  TODO KIP-932: when SHARE_SESSION_NOT_FOUND /
 *  INVALID_SHARE_SESSION_EPOCH are translated to
 *  INVALID_RECORD_STATE at the app-facing boundary,
 *  expected_phase2_commit_err for the killed branch becomes
 *  INVALID_RECORD_STATE.
 */
static void
do_test_socket_timeout_partial_ack_then_remaining(int api_timeout_ms,
                                                  int socket_timeout_ms,
                                                  int rtt_ms) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_error_t *error;
        char topic[128];
        char group[128];
        const int partitions_total = SOCKET_TIMEOUT_MATRIX_PARTITIONS;
        const int msgcnt =
            partitions_total * SOCKET_TIMEOUT_MATRIX_MSGS_PER_PARTITION;
        rd_kafka_message_t **rkmessages;
        rd_kafka_messages_t *phase1_batch = NULL;
        test_ack_cb_state_t cb_state      = {0};
        rd_ts_t t_p1_end_us, t_callbacks_done_us;
        int actual_wait_ms, expected_wait_ms;
        int min_between_rtt_ms_socket_timeout_ms;
        int min_between_api_timeout_ms_rtt_ms_socket_timeout_ms;
        rd_kafka_resp_err_t expected_phase1_commit_err;
        rd_kafka_resp_err_t expected_phase1_callback_err;
        rd_kafka_resp_err_t expected_phase2_commit_err;
        rd_bool_t connection_killed;
        int prev_callback_cnt;
        int phase1_partition_cnt;
        int i;
        /* See do_test_socket_timeout_full_ack_then_more for the Valgrind
         * tolerance rationale. */
        const int wait_tolerance_ms =
            !strcmp(test_mode, "valgrind") ? 2000 : 500;

        SUB_TEST_QUICK("api_timeout_ms=%d socket_timeout_ms=%d rtt_ms=%d",
                       api_timeout_ms, socket_timeout_ms, rtt_ms);

        /* Phase 1 expected outcomes — same derivation as
         * do_test_socket_timeout_full_ack_then_more. See the comment
         * there for the full reasoning. */
        min_between_rtt_ms_socket_timeout_ms =
            socket_timeout_ms < rtt_ms ? socket_timeout_ms : rtt_ms;
        min_between_api_timeout_ms_rtt_ms_socket_timeout_ms = api_timeout_ms;
        if (rtt_ms < min_between_api_timeout_ms_rtt_ms_socket_timeout_ms)
                min_between_api_timeout_ms_rtt_ms_socket_timeout_ms = rtt_ms;
        if (socket_timeout_ms <
            min_between_api_timeout_ms_rtt_ms_socket_timeout_ms)
                min_between_api_timeout_ms_rtt_ms_socket_timeout_ms =
                    socket_timeout_ms;
        expected_wait_ms = min_between_rtt_ms_socket_timeout_ms -
                           min_between_api_timeout_ms_rtt_ms_socket_timeout_ms;

        if (rtt_ms < api_timeout_ms && rtt_ms < socket_timeout_ms) {
                expected_phase1_commit_err   = RD_KAFKA_RESP_ERR_NO_ERROR;
                expected_phase1_callback_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        } else if (socket_timeout_ms < api_timeout_ms) {
                /* __TIMED_OUT from the broker-thread socket timer is
                 * translated to REQUEST_TIMED_OUT at the app-facing
                 * funnel. */
                expected_phase1_commit_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
                expected_phase1_callback_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
        } else if (rtt_ms < socket_timeout_ms) {
                expected_phase1_commit_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
                expected_phase1_callback_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        } else {
                /* Late wire-failure callback err __TIMED_OUT is
                 * translated to REQUEST_TIMED_OUT at the app-facing
                 * funnel. */
                expected_phase1_commit_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
                expected_phase1_callback_err =
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
        }

        /* Connection torn down iff socket fires before broker reply.
         *
         * TODO KIP-932: when SHARE_SESSION_NOT_FOUND /
         * INVALID_SHARE_SESSION_EPOCH are translated to
         * INVALID_RECORD_STATE at the app-facing boundary, the
         * killed-branch expected err becomes INVALID_RECORD_STATE. */
        connection_killed = socket_timeout_ms < rtt_ms;
        expected_phase2_commit_err =
            connection_killed ? RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH
                              : RD_KAFKA_RESP_ERR_NO_ERROR;

        ctx = test_ctx_new();
        rd_kafka_mock_sharegroup_set_record_lock_duration(
            ctx.mcluster, SOCKET_TIMEOUT_MATRIX_RECORD_LOCK_MS);

        rd_snprintf(topic, sizeof(topic), "0182-partial-a%d-s%d-r%d",
                    api_timeout_ms, socket_timeout_ms, rtt_ms);
        rd_snprintf(group, sizeof(group), "sg-0182-partial-a%d-s%d-r%d",
                    api_timeout_ms, socket_timeout_ms, rtt_ms);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic,
                                               partitions_total,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        for (i = 0; i < partitions_total; i++)
                mock_produce_partition(
                    ctx.producer, topic, i,
                    SOCKET_TIMEOUT_MATRIX_MSGS_PER_PARTITION);

        rkshare = create_share_consumer_socket_timeout(
            ctx.bootstraps, group, "explicit", socket_timeout_ms, &cb_state,
            test_share_ack_cb);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        rkmessages = rd_calloc(msgcnt, sizeof(*rkmessages));

        /* Phase 1: consume the first batch (all msgcnt records),
         * then ack the first half of the batch in receive order.
         * The exact set of partitions covered depends on broker-side
         * record ordering; the assertions below adapt to whatever
         * partitions appear in commit_sync's results. */
        consume_first_batch(rkshare, rkmessages, msgcnt, &phase1_batch);
        for (i = 0; i < msgcnt / 2; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        rd_kafka_mock_broker_set_rtt(ctx.mcluster, -1, rtt_ms);

        partitions = NULL;
        error =
            rd_kafka_share_commit_sync(rkshare, api_timeout_ms, &partitions);
        t_p1_end_us = test_clock();

        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "Phase 1: expected non-NULL partition results");

        /* The number of partitions reflects whichever ones had records
         * in the first half of the batch — depends on broker-side
         * record ordering. We assert each partition's err matches the
         * expected code, and drain that many callbacks. */
        phase1_partition_cnt = partitions->cnt;
        TEST_ASSERT(phase1_partition_cnt > 0,
                    "Phase 1: expected at least one partition result");

        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                TEST_SAY("Phase 1 commit_sync: %s [%" PRId32 "]: %s\n",
                         rktpar->topic, rktpar->partition,
                         rd_kafka_err2name(rktpar->err));
                TEST_ASSERT(rktpar->err == expected_phase1_commit_err,
                            "Phase 1: expected %s, got %s",
                            rd_kafka_err2name(expected_phase1_commit_err),
                            rd_kafka_err2name(rktpar->err));
        }
        rd_kafka_topic_partition_list_destroy(partitions);

        TEST_ASSERT(drain_callbacks_via_commit_async(
                        rkshare, &cb_state, phase1_partition_cnt, 30000),
                    "Phase 1: expected %d ack callbacks within 30s, got %d",
                    phase1_partition_cnt, cb_state.callback_cnt);
        t_callbacks_done_us = test_clock();

        TEST_ASSERT(test_ack_cb_state_first_err(&cb_state) ==
                        expected_phase1_callback_err,
                    "Phase 1: expected callback err %s, got %s",
                    rd_kafka_err2name(expected_phase1_callback_err),
                    rd_kafka_err2name(test_ack_cb_state_first_err(&cb_state)));

        actual_wait_ms = (int)((t_callbacks_done_us - t_p1_end_us) / 1000);
        TEST_SAY(
            "Phase 1 wait t_callbacks_done - t_p1_end = %dms "
            "(expected ~%dms, tolerance %dms)\n",
            actual_wait_ms, expected_wait_ms, wait_tolerance_ms);
        TEST_ASSERT(actual_wait_ms >= expected_wait_ms - wait_tolerance_ms &&
                        actual_wait_ms <= expected_wait_ms + wait_tolerance_ms,
                    "Phase 1 wait %dms outside expected %dms +/- %dms",
                    actual_wait_ms, expected_wait_ms, wait_tolerance_ms);

        prev_callback_cnt = cb_state.callback_cnt;

        /* Phase 2: clear RTT and ack the remaining records (still in
         * the local inflight map from Phase 1's consume — the second
         * half per partition). No new consume_batch in this variant.
         *
         * Small settle delay so the consumer's broker thread can
         * finish post-teardown bookkeeping (reconnect, session
         * reset, broker decommission cleanup) before Phase 2's
         * commit_sync probes the state. Without this perm 5/6/boundary
         * cases racing the post-teardown handling can return
         * __STATE from the FANOUT op instead of the expected
         * INVALID_SHARE_SESSION_EPOCH from the local epoch-0 check. */
        rd_kafka_mock_broker_set_rtt(ctx.mcluster, -1, 0);
        rd_sleep(1);

        /* Ack the remaining half of the batch in receive order. */
        for (i = msgcnt / 2; i < msgcnt; i++)
                rd_kafka_share_acknowledge(rkshare, rkmessages[i]);

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 5000, &partitions);
        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL,
                    "Phase 2: expected non-NULL partition results");

        /* As in Phase 1, the partition count reflects whichever
         * partitions had records in the second half. Some partitions
         * may appear in both phases (e.g., partition that had its
         * first 5 records acked in Phase 1 and last 5 in Phase 2). */
        TEST_ASSERT(partitions->cnt > 0,
                    "Phase 2: expected at least one partition result");

        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                TEST_SAY("Phase 2 commit_sync: %s [%" PRId32 "]: %s\n",
                         rktpar->topic, rktpar->partition,
                         rd_kafka_err2name(rktpar->err));
                TEST_ASSERT(rktpar->err == expected_phase2_commit_err,
                            "Phase 2: expected %s, got %s",
                            rd_kafka_err2name(expected_phase2_commit_err),
                            rd_kafka_err2name(rktpar->err));
        }
        TEST_ASSERT(
            drain_callbacks_via_commit_async(
                rkshare, &cb_state, prev_callback_cnt + partitions->cnt, 10000),
            "Phase 2: expected %d new ack callbacks; before=%d "
            "after=%d",
            partitions->cnt, prev_callback_cnt, cb_state.callback_cnt);
        rd_kafka_topic_partition_list_destroy(partitions);

        TEST_ASSERT(
            cb_state.errs[cb_state.callback_cnt - 1] ==
                expected_phase2_commit_err,
            "Phase 2: expected last callback err %s, got %s",
            rd_kafka_err2name(expected_phase2_commit_err),
            rd_kafka_err2name(cb_state.errs[cb_state.callback_cnt - 1]));

        rd_kafka_messages_destroy(phase1_batch);
        rd_free(rkmessages);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);
        test_ack_cb_state_destroy(&cb_state);

        SUB_TEST_PASS();
}

/* ===================================================================
 *  Topic-level metadata error tests.
 *
 *  Verify that a share consumer surfaces topic-level errors from
 *  metadata responses to the application as rd_kafka_error_t via
 *  consume_batch. Only TOPIC_EXCEPTION and TOPIC_AUTHORIZATION_FAILED
 *  reach the app; transient codes (UNKNOWN_TOPIC, UNKNOWN_TOPIC_OR_PART,
 *  UNKNOWN_TOPIC_ID, UNKNOWN_PARTITION) are not delivered. Repeats of
 *  the same (topic, err) are deduped; recovery, unsubscribe, and
 *  re-subscribe each have well-defined behaviour exercised below.
 *
 *  These scenarios are hard to reproduce on a real broker — the mock
 *  cluster lets us inject the exact per-topic error byte in a metadata
 *  response on demand.
 * =================================================================== */

/* Drive at least one successful consume_batch so the share assignment
 * is fully materialised before the test injects an error. Records are
 * ACKed inline because the consumer is in explicit-ack mode. */
static void share_topic_err_prime_assignment(rd_kafka_share_t *rkshare) {
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        size_t rcvd;
        size_t j;
        int attempts;
        rd_bool_t got_any = rd_false;

        for (attempts = 0; attempts < 20; attempts++) {
                error = rd_kafka_share_poll(rkshare, 1000, &batch);
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
                        if (!rkm->err) {
                                rd_kafka_share_acknowledge(rkshare, rkm);
                                got_any = rd_true;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                if (got_any)
                        return;
        }
        TEST_FAIL(
            "Pre-condition: expected to consume a batch before "
            "injecting the metadata error");
}

/* Force a metadata refresh on the share consumer's underlying rk so
 * the injected per-topic err is observed. */
static void share_topic_err_force_metadata(rd_kafka_share_t *rkshare) {
        const rd_kafka_metadata_t *md = NULL;
        rd_kafka_t *rk;

        rk = test_share_consumer_get_rk(rkshare);
        (void)rd_kafka_metadata(rk, 1 /*all_topics*/, NULL, &md, 5000);
        if (md)
                rd_kafka_metadata_destroy(md);
}

/* Drain consume_batch until either the expected err code surfaces (then
 * return rd_true) or `max_attempts` calls go by without it (return
 * rd_false). Records that arrive are destroyed. */
static rd_bool_t share_topic_err_wait_for_err(rd_kafka_share_t *rkshare,
                                              rd_kafka_resp_err_t expected,
                                              int max_attempts) {
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        size_t rcvd;
        size_t j;
        int attempts;

        for (attempts = 0; attempts < max_attempts; attempts++) {
                error = rd_kafka_share_poll(rkshare, 500, &batch);
                if (error) {
                        rd_kafka_resp_err_t code = rd_kafka_error_code(error);
                        TEST_SAY("share_poll returned %s: %s\n",
                                 rd_kafka_err2name(code),
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        if (code == expected)
                                return rd_true;
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                /* Ack received records so the next share_poll can
                 * proceed past the explicit-mode "previous poll
                 * unacked" gate. */
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                rd_kafka_share_acknowledge(rkshare, rkm);
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        return rd_false;
}

/* Run `n_attempts` consume_batch calls and fail the test if any of them
 * returns an rd_kafka_error_t — used for the negative-assertion tests
 * (transient-code log-only paths must not surface). */
static void share_topic_err_assert_no_err(rd_kafka_share_t *rkshare,
                                          int n_attempts,
                                          const char *context) {
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        size_t rcvd;
        size_t j;
        int attempts;

        for (attempts = 0; attempts < n_attempts; attempts++) {
                error = rd_kafka_share_poll(rkshare, 200, &batch);
                if (error) {
                        rd_kafka_resp_err_t code = rd_kafka_error_code(error);
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        TEST_FAIL(
                            "[%s] unexpected error from share_poll: "
                            "%s",
                            context, rd_kafka_err2name(code));
                }
                rcvd = rd_kafka_messages_count(batch);
                /* Ack received records so the next share_poll can
                 * proceed past the explicit-mode "previous poll
                 * unacked" gate. */
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                rd_kafka_share_acknowledge(rkshare, rkm);
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
}

/* Run one share-topic-err scenario: assign, inject `inject_err`,
 * verify consume_batch surfaces `expect_err` (or fails). */
static void do_test_share_topic_err_surfaces(const char *topic_suffix,
                                             rd_kafka_resp_err_t inject_err,
                                             rd_kafka_resp_err_t expect_err) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        char topic[64];
        char group[64];

        SUB_TEST_QUICK("inject=%s expect=%s", rd_kafka_err2name(inject_err),
                       rd_kafka_err2name(expect_err));

        ctx = test_ctx_new();
        rd_snprintf(topic, sizeof(topic), "0182-%s", topic_suffix);
        rd_snprintf(group, sizeof(group), "sg-0182-%s", topic_suffix);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");
        mock_produce(ctx.producer, topic, 5);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);
        share_topic_err_prime_assignment(rkshare);

        rd_kafka_mock_topic_set_error(ctx.mcluster, topic, inject_err);
        share_topic_err_force_metadata(rkshare);

        TEST_ASSERT(share_topic_err_wait_for_err(rkshare, expect_err, 30),
                    "Expected consume_batch to surface %s within 30 attempts",
                    rd_kafka_err2name(expect_err));

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


static void test_share_consumer_surfaces_topic_exception(void) {
        do_test_share_topic_err_surfaces("surfaces-topic-exception",
                                         RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION,
                                         RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION);
}


static void test_share_consumer_surfaces_topic_authorization_failed(void) {
        do_test_share_topic_err_surfaces(
            "surfaces-topic-auth-failed",
            RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED,
            RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
}


/* A topic with N partitions failing in a single metadata cycle must
 * surface exactly one op for that topic, not one per partition.
 *
 * share_toppar_enq_error keys its accumulator on topic_id and
 * dedups-on-add, so the per-rktp calls from partition_cnt_update and
 * propagate_notexists (2N total) collapse to a single entry in
 * rkcg_errored_topics — and hence a single rd_kafka_consumer_err. */
static void test_share_consumer_multi_partition_single_op_per_cycle(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        const char *topic          = "0182-multipart-single-op";
        const char *group          = "sg-0182-multipart-single-op";
        const int partition_cnt    = 5;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        size_t rcvd, j;
        int err_count = 0;
        int attempts;

        SUB_TEST();

        ctx = test_ctx_new();
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic,
                                               partition_cnt,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic with %d partitions", partition_cnt);
        mock_produce(ctx.producer, topic, partition_cnt * 3);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);
        share_topic_err_prime_assignment(rkshare);

        /* Inject AUTH_FAILED on the topic; partition_cnt_update +
         * propagate_notexists will each fire enq_error per rktp. */
        rd_kafka_mock_topic_set_error(
            ctx.mcluster, topic, RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
        share_topic_err_force_metadata(rkshare);

        /* Drain a short window immediately after the synchronous
         * force_metadata. By the time it returns, propagate has emitted
         * the (single) op for this cycle. The window is intentionally
         * short to keep it within one heartbeat interval and count just
         * what this cycle produced. */
        for (attempts = 0; attempts < 3; attempts++) {
                error = rd_kafka_share_poll(rkshare, 200, &batch);
                if (error) {
                        rd_kafka_resp_err_t code = rd_kafka_error_code(error);
                        const char *errstr       = rd_kafka_error_string(error);
                        if (code ==
                                RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED &&
                            errstr && strstr(errstr, topic))
                                err_count++;
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);
                        if (!rkm->err)
                                rd_kafka_share_acknowledge(rkshare, rkm);
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(err_count == 1,
                    "expected exactly 1 AUTH_FAILED op for a %d-partition "
                    "topic in a single metadata cycle, got %d",
                    partition_cnt, err_count);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* The same topic failing with a different error code must surface a
 * fresh op for the new code rather than being deduped against the
 * previous one. */
static void test_share_consumer_re_emits_when_err_code_changes(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        const char *topic = "0182-err-code-change";
        const char *group = "sg-0182-err-code-change";

        SUB_TEST();

        ctx = test_ctx_new();
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");
        mock_produce(ctx.producer, topic, 5);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);
        share_topic_err_prime_assignment(rkshare);

        /* First err: AUTH_FAILED. */
        rd_kafka_mock_topic_set_error(
            ctx.mcluster, topic, RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
        share_topic_err_force_metadata(rkshare);
        TEST_ASSERT(
            share_topic_err_wait_for_err(
                rkshare, RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED, 30),
            "First AUTH_FAILED must surface");

        /* Second err for the same topic: TOPIC_EXCEPTION (different
         * code) — must surface, dedup must NOT swallow it. */
        rd_kafka_mock_topic_set_error(ctx.mcluster, topic,
                                      RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION);
        share_topic_err_force_metadata(rkshare);
        TEST_ASSERT(share_topic_err_wait_for_err(
                        rkshare, RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION, 30),
                    "TOPIC_EXCEPTION must surface after AUTH_FAILED "
                    "(err code change must bypass dedup)");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* A topic that surfaces AUTH_FAILED, then recovers, then fails again
 * with the same code must surface the error a second time. */
static void test_share_consumer_re_surfaces_after_recovery(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        const char *topic = "0182-re-surface-after-recovery";
        const char *group = "sg-0182-re-surface-after-recovery";

        SUB_TEST();

        ctx = test_ctx_new();
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");
        mock_produce(ctx.producer, topic, 5);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);
        share_topic_err_prime_assignment(rkshare);

        /* Phase 1: fail — first surface. */
        rd_kafka_mock_topic_set_error(
            ctx.mcluster, topic, RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
        share_topic_err_force_metadata(rkshare);
        TEST_ASSERT(
            share_topic_err_wait_for_err(
                rkshare, RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED, 30),
            "First AUTH_FAILED must surface");

        /* Phase 2: recover — no error must reach the app. */
        rd_kafka_mock_topic_set_error(ctx.mcluster, topic,
                                      RD_KAFKA_RESP_ERR_NO_ERROR);
        share_topic_err_force_metadata(rkshare);
        share_topic_err_assert_no_err(rkshare, 5,
                                      "no error must surface while recovered");

        /* Phase 3: fail again with the same code — must surface a
         * second time. */
        rd_kafka_mock_topic_set_error(
            ctx.mcluster, topic, RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
        share_topic_err_force_metadata(rkshare);
        TEST_ASSERT(
            share_topic_err_wait_for_err(
                rkshare, RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED, 30),
            "AUTH_FAILED must surface a second time after recovery");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* A topic that surfaces TOPIC_EXCEPTION, then recovers, then fails
 * again with the same code must surface the error a second time. */
static void
test_share_consumer_re_surfaces_after_recovery_topic_exception(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        const char *topic = "0182-re-surface-topic-exception";
        const char *group = "sg-0182-re-surface-topic-exception";

        SUB_TEST();

        ctx = test_ctx_new();
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");
        mock_produce(ctx.producer, topic, 5);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);
        share_topic_err_prime_assignment(rkshare);

        /* Phase 1: fail. */
        rd_kafka_mock_topic_set_error(ctx.mcluster, topic,
                                      RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION);
        share_topic_err_force_metadata(rkshare);
        TEST_ASSERT(share_topic_err_wait_for_err(
                        rkshare, RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION, 30),
                    "first TOPIC_EXCEPTION must surface");

        /* Phase 2: recover. */
        rd_kafka_mock_topic_set_error(ctx.mcluster, topic,
                                      RD_KAFKA_RESP_ERR_NO_ERROR);
        share_topic_err_force_metadata(rkshare);
        share_topic_err_assert_no_err(
            rkshare, 5, "no error must surface while topic is recovered");

        /* Phase 3: re-fail with the same code — must surface again. */
        rd_kafka_mock_topic_set_error(ctx.mcluster, topic,
                                      RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION);
        share_topic_err_force_metadata(rkshare);
        TEST_ASSERT(share_topic_err_wait_for_err(
                        rkshare, RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION, 30),
                    "TOPIC_EXCEPTION must surface a second time after "
                    "recovery");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* A topic surfaces TOPIC_EXCEPTION, gets unsubscribed (no surface),
 * and is then re-subscribed while still failing. The error must
 * surface again on re-subscribe — not be permanently suppressed. */
static void test_share_consumer_resubscribe_re_emits_persistent_failure(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        const char *topic = "0182-resubscribe-re-emit";
        const char *group = "sg-0182-resubscribe-re-emit";

        SUB_TEST();

        ctx = test_ctx_new();
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");
        mock_produce(ctx.producer, topic, 5);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);
        share_topic_err_prime_assignment(rkshare);

        /* Phase 1: subscribe + fail + surface. */
        rd_kafka_mock_topic_set_error(ctx.mcluster, topic,
                                      RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION);
        share_topic_err_force_metadata(rkshare);
        TEST_ASSERT(share_topic_err_wait_for_err(
                        rkshare, RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION, 30),
                    "first TOPIC_EXCEPTION must surface");

        /* Phase 2: unsubscribe. */
        TEST_ASSERT(rd_kafka_share_unsubscribe(rkshare) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "unsubscribe");

        /* Phase 3: re-subscribe to the same still-failing topic; the
         * error must surface again. Re-force metadata across the wait
         * loop so the request happens after the share-assignment
         * heartbeat re-populates the partition list. */
        test_share_consumer_subscribe_multi(rkshare, 1, topic);
        rd_bool_t saw_err = rd_false;
        int outer;
        for (outer = 0; outer < 10 && !saw_err; outer++) {
                share_topic_err_force_metadata(rkshare);
                if (share_topic_err_wait_for_err(
                        rkshare, RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION, 3))
                        saw_err = rd_true;
        }
        TEST_ASSERT(saw_err,
                    "TOPIC_EXCEPTION must surface again after "
                    "re-subscribing to a still-failing topic");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* UNKNOWN_TOPIC_OR_PART is debug-logged only and must not reach the
 * app via consume_batch. */
static void test_share_consumer_does_not_surface_unknown_topic_or_part(void) {
        test_ctx_t ctx;
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        const char *topic = "0182-no-surface-unknown-tp";
        const char *group = "sg-0182-no-surface-unknown-tp";

        SUB_TEST();

        ctx = test_ctx_new();
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");
        mock_produce(ctx.producer, topic, 5);

        /* Custom consumer with the metadata propagation defer window
         * disabled so the no-surface path is exercised on the first
         * metadata refresh rather than 30 s later. */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        test_conf_set(conf, "topic.metadata.propagation.max.ms", "0");
        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");

        test_share_consumer_subscribe_multi(rkshare, 1, topic);
        share_topic_err_prime_assignment(rkshare);

        rd_kafka_mock_topic_set_error(ctx.mcluster, topic,
                                      RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);
        share_topic_err_force_metadata(rkshare);

        share_topic_err_assert_no_err(
            rkshare, 20,
            "UNKNOWN_TOPIC_OR_PART must be logged only, not surfaced");

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Log callback shared by the two select_broker STATE_UP guard tests
 *  below. Counts the broker-thread short-circuit log emitted at
 *  src/rdkafka_broker.c when a SHARE_FETCH op is served against a
 *  broker whose rkb_state is not STATE_UP.
 * =================================================================== */
static void no_bounce_loop_log_cb(const rd_kafka_t *rk,
                                  int level,
                                  const char *fac,
                                  const char *buf) {
        rd_atomic32_t *cnt = rd_kafka_opaque(rk);
        if (cnt && !strcmp(fac, "SHAREFETCH") && strstr(buf, "broker not up"))
                rd_atomic32_add(cnt, 1);
}

/* ===================================================================
 *  do_test_no_bounce_loop_on_down_broker
 *
 *  Steady-state DOWN: the consumer is idle when the broker is taken
 *  down, sleeps long enough for the broker thread to settle rkb_state
 *  to !UP, then drives consume_batch for ~1s. Every FANOUT must skip
 *  the DOWN leader via the select_broker STATE_UP guard, so no
 *  "broker not up" log line should fire.
 *
 *  Wire never sees a ShareFetch on the DOWN broker (broker thread
 *  rejects the internal op before any RPC is built), so we assert on
 *  the count of the broker-thread short-circuit debug log instead of
 *  on mock_get_requests.
 * =================================================================== */
static void do_test_no_bounce_loop_on_down_broker(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        rd_atomic32_t broker_not_up_cnt;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *batch = NULL;
        const char *topic          = "0182-no_bounce_loop";
        const char *group          = "sg-0182-no-bounce-loop";
        const int msgcnt_phase1    = 5;
        const int msgcnt_phase2    = 5;
        int acked, cnt;
        size_t rcvd;
        size_t share_fetch_cnt_before_drain;
        size_t share_fetch_cnt_after_drain;
        rd_ts_t end_ts;

        SUB_TEST_QUICK();

        /* Taking the only broker down legitimately raises
         * __ALL_BROKERS_DOWN and __TRANSPORT on producer + consumer
         * error callbacks. None of these should fail the test. */
        test_curr->is_fatal_cb = test_error_is_not_fatal_cb;

        ctx = test_ctx_new();
        rd_kafka_mock_start_request_tracking(ctx.mcluster);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        mock_produce(ctx.producer, topic, msgcnt_phase1);

        rd_atomic32_init(&broker_not_up_cnt, 0);
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        test_conf_set(conf, "debug", "broker");
        /* Cap reconnect backoff so the consumer recovers quickly after
         * set_up. The default max (10s) extends past the recovery
         * sleep below, causing the post-recovery ShareFetch not to
         * land in time. */
        test_conf_set(conf, "reconnect.backoff.ms", "100");
        test_conf_set(conf, "reconnect.backoff.max.ms", "500");
        rd_kafka_conf_set_log_cb(conf, no_bounce_loop_log_cb);
        rd_kafka_conf_set_opaque(conf, &broker_not_up_cnt);

        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");

        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        acked = consume_and_ack_all(rkshare, msgcnt_phase1);
        TEST_ASSERT(acked == msgcnt_phase1, "phase1: expected %d acked, got %d",
                    msgcnt_phase1, acked);

        /* Flush any acks still cached in rkb_share_async_ack_details
         * before taking the broker down. Otherwise the next FANOUT
         * after set_down would dispatch an ack-only op to the DOWN
         * broker (the FANOUT iteration must always deliver cached
         * acks so the broker thread can surface the error), and the
         * broker thread would legitimately log "broker not up" once.
         * That log is unrelated to the select_broker guard. */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async error: %s",
                    error ? rd_kafka_error_string(error) : "NULL");

        /* Phase-2 records sit in the partition log; the post-recovery
         * consume below drains them. */
        mock_produce(ctx.producer, topic, msgcnt_phase2);

        TEST_SAY("Taking broker 1 down\n");
        rd_kafka_mock_broker_set_down(ctx.mcluster, 1);

        /* Settle: let the client's broker thread detect TCP close and
         * transition rkb_state to !UP before we start counting. After
         * this point every select_broker reads DOWN — no race window. */
        rd_sleep(1);
        rd_atomic32_set(&broker_not_up_cnt, 0);

        end_ts = test_clock() + 1000 * 1000;
        while (test_clock() < end_ts) {
                error = rd_kafka_share_poll(rkshare, 100, &batch);
                TEST_ASSERT(!error,
                            "unexpected error from share_poll while "
                            "broker is down: %s",
                            error ? rd_kafka_error_string(error) : "NULL");
                rcvd = rd_kafka_messages_count(batch);
                TEST_ASSERT(rcvd == 0,
                            "expected 0 records while broker is down, "
                            "got %zu",
                            rcvd);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        cnt = rd_atomic32_get(&broker_not_up_cnt);
        TEST_SAY("\"broker not up\" log count: %d (expected 0)\n", cnt);
        TEST_ASSERT(cnt == 0,
                    "select_broker should skip the DOWN leader on every "
                    "FANOUT once rkb_state has settled; got %d "
                    "\"broker not up\" log lines",
                    cnt);

        TEST_SAY("Bringing broker 1 back up\n");
        rd_kafka_mock_broker_set_up(ctx.mcluster, 1);

        /* The main-thread retrigger keeps calling select_broker. As
         * soon as broker 1 reaches STATE_UP the next select_broker
         * returns it and a ShareFetch fires automatically — records
         * land on the consumer queue without any consume_batch call
         * driving the fetch. */
        rd_sleep(3);

        share_fetch_cnt_before_drain = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_fetch_request, NULL);
        TEST_SAY("ShareFetch count after recovery (pre-drain): %" PRIusz "\n",
                 share_fetch_cnt_before_drain);
        TEST_ASSERT(share_fetch_cnt_before_drain >= 1,
                    "expected >= 1 ShareFetch via internal retry after "
                    "set_up, got %" PRIusz,
                    share_fetch_cnt_before_drain);

        /* Drain the pre-fetched records. They're already on the
         * consumer queue, so share_poll returns them directly
         * without enqueueing a FANOUT and no new ShareFetch fires. */
        error                       = rd_kafka_share_poll(rkshare, 100, &batch);
        rcvd                        = rd_kafka_messages_count(batch);
        share_fetch_cnt_after_drain = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_fetch_request, NULL);
        /* Destroy the batch before asserting so a failed assert can't
         * leak it (TEST_FAIL longjmps past any later destroy). */
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_ASSERT(!error, "post-recovery share_poll error: %s",
                    error ? rd_kafka_error_string(error) : "NULL");
        TEST_ASSERT(rcvd == (size_t)msgcnt_phase2,
                    "expected %d records from queue, got %" PRIusz,
                    msgcnt_phase2, rcvd);
        TEST_ASSERT(share_fetch_cnt_after_drain == share_fetch_cnt_before_drain,
                    "share_poll should drain the queue without firing "
                    "a new ShareFetch; pre=%" PRIusz " post=%" PRIusz,
                    share_fetch_cnt_before_drain, share_fetch_cnt_after_drain);

        rd_kafka_mock_clear_requests(ctx.mcluster);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}

/* ===================================================================
 *  do_test_one_log_on_broker_down_during_active_empty_poll
 *
 *  Race-window companion to do_test_no_bounce_loop_on_down_broker.
 *
 *  With an empty topic the consumer's FANOUT->ShareFetch->Step 6
 *  empty-poll loop fires continuously. We rapidly flip the broker
 *  up/down across N cycles while that loop is hot. Each set_down
 *  has a narrow window between the mock TCP close and the client
 *  broker thread updating rkb_state, in which select_broker can
 *  read stale STATE_UP and enqueue one more op — the broker thread
 *  (rkb_state has caught up by then) logs "broker not up" at most
 *  once and replies ERR__STATE. The next Step 6 re-select reads
 *  DOWN and skips, closing the loop until the next set_down.
 *
 *  Total log count is therefore bounded by N (one slip per
 *  set_down). Without the select_broker guard, each set_down would
 *  produce hundreds of logs per second for the duration of the
 *  down window — unbounded across cycles.
 * =================================================================== */
static void do_test_one_log_on_broker_down_during_active_empty_poll(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        rd_atomic32_t broker_not_up_cnt;
        const char *topic             = "0182-race_bounce";
        const char *group             = "sg-0182-race-bounce";
        const int msgcnt_recovery     = 5;
        const int n_cycles            = 10;
        const int max_allowed_log_cnt = n_cycles;
        rd_kafka_messages_t *batch    = NULL;
        size_t rcvd;
        rd_kafka_error_t *error;
        int i, cnt, acked;

        SUB_TEST_QUICK();

        /* Taking the only broker down legitimately raises
         * __ALL_BROKERS_DOWN and __TRANSPORT on producer + consumer
         * error callbacks. None of these should fail the test. */
        test_curr->is_fatal_cb = test_error_is_not_fatal_cb;

        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        rd_atomic32_init(&broker_not_up_cnt, 0);
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        test_conf_set(conf, "debug", "broker");
        /* Cap reconnect backoff so each set_up reconnects quickly
         * across the chaos cycles. */
        test_conf_set(conf, "reconnect.backoff.ms", "100");
        test_conf_set(conf, "reconnect.backoff.max.ms", "500");
        rd_kafka_conf_set_log_cb(conf, no_bounce_loop_log_cb);
        rd_kafka_conf_set_opaque(conf, &broker_not_up_cnt);

        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");

        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Prime with one record so the share group has joined and the
         * partition is assigned by the time we take the broker down.
         * Without this guarantee, select_broker would return NULL
         * (no toppars) and the bounce loop wouldn't fire at all,
         * making the test pass for the wrong reason. */
        mock_produce(ctx.producer, topic, 1);
        acked = consume_and_ack_all(rkshare, 1);
        TEST_ASSERT(acked == 1, "prime: expected 1 acked, got %d", acked);

        /* Flush the prime ack still cached in rkb_share_async_ack_details
         * before taking the broker down. Otherwise the next FANOUT
         * iteration would dispatch an ack-only op to the DOWN broker
         * and produce a "broker not up" log unrelated to the
         * select_broker race we're measuring. */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async error: %s",
                    error ? rd_kafka_error_string(error) : "NULL");

        /* Reset to drop any noise from cgrp/connection bring-up. */
        rd_atomic32_set(&broker_not_up_cnt, 0);

        /* Kickstart the empty-poll loop: one share_poll on the now
         * empty topic starts the FANOUT->Step 6 cycle which keeps
         * firing on the main thread until share_poll returns. */
        error = rd_kafka_share_poll(rkshare, 500, &batch);
        TEST_ASSERT(!error, "kickstart share_poll error: %s",
                    error ? rd_kafka_error_string(error) : "NULL");
        rcvd = rd_kafka_messages_count(batch);
        TEST_ASSERT(rcvd == 0, "expected 0 records, got %zu", rcvd);
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        /* Chaos: rapidly flip the broker up/down across n_cycles
         * while the consumer's empty-poll loop is hot. Each set_down
         * may admit one race-window slip; total log count must stay
         * bounded by n_cycles. */
        for (i = 0; i < n_cycles; i++) {
                TEST_SAY("Cycle %d/%d: taking broker 1 down\n", i + 1,
                         n_cycles);
                rd_kafka_mock_broker_set_down(ctx.mcluster, 1);
                error = rd_kafka_share_poll(rkshare, 200, &batch);
                TEST_ASSERT(!error, "cycle %d down: share_poll error: %s",
                            i + 1,
                            error ? rd_kafka_error_string(error) : "NULL");
                rcvd = rd_kafka_messages_count(batch);
                TEST_ASSERT(rcvd == 0,
                            "cycle %d down: expected 0 records, got %zu", i + 1,
                            rcvd);
                rd_kafka_messages_destroy(batch);
                batch = NULL;

                TEST_SAY("Cycle %d/%d: bringing broker 1 back up\n", i + 1,
                         n_cycles);
                rd_kafka_mock_broker_set_up(ctx.mcluster, 1);
                error = rd_kafka_share_poll(rkshare, 200, &batch);
                TEST_ASSERT(!error, "cycle %d up: share_poll error: %s", i + 1,
                            error ? rd_kafka_error_string(error) : "NULL");
                rcvd = rd_kafka_messages_count(batch);
                TEST_ASSERT(rcvd == 0,
                            "cycle %d up: expected 0 records, got %zu", i + 1,
                            rcvd);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        cnt = rd_atomic32_get(&broker_not_up_cnt);
        TEST_SAY("\"broker not up\" log count after %d cycles: %d (max %d)\n",
                 n_cycles, cnt, max_allowed_log_cnt);
        TEST_ASSERT(cnt <= max_allowed_log_cnt,
                    "race-window slips must be bounded to %d (one per "
                    "set_down across %d cycles); got %d log lines",
                    max_allowed_log_cnt, n_cycles, cnt);

        /* Recovery: broker is left UP at the end of the chaos loop.
         * Produce records and verify the consumer drains them. */
        mock_produce(ctx.producer, topic, msgcnt_recovery);

        acked = consume_and_ack_all(rkshare, msgcnt_recovery);
        TEST_ASSERT(acked == msgcnt_recovery,
                    "post-recovery: expected %d acked, got %d", msgcnt_recovery,
                    acked);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Log callback for do_test_fetch_stall_logged_on_no_broker. Counts
 *  the main-thread "Fetch stalled: no eligible broker" debug log.
 * =================================================================== */
static void fetch_stall_log_cb(const rd_kafka_t *rk,
                               int level,
                               const char *fac,
                               const char *buf) {
        rd_atomic32_t *cnt = rd_kafka_opaque(rk);
        if (cnt && !strcmp(fac, "FETCHMORE") &&
            strstr(buf, "Fetch stalled: no eligible broker"))
                rd_atomic32_add(cnt, 1);
}

/* ===================================================================
 *  do_test_fetch_stall_logged_on_no_broker
 *
 *  With a partition assigned but the only broker down, the main-thread
 *  re-trigger loop wants to fetch (share_fetch_more_records set, no op
 *  in-flight) yet select_broker returns NULL. Verify it emits the
 *  rate-limited "Fetch stalled: no eligible broker" log: at least once
 *  (the stall is reported) and bounded (the throttle prevents a flood
 *  while the empty-poll loop is hot).
 * =================================================================== */
static void do_test_fetch_stall_logged_on_no_broker(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        rd_atomic32_t stall_cnt;
        const char *topic          = "0182-fetch-stall";
        const char *group          = "sg-0182-fetch-stall";
        const int msgcnt_recovery  = 5;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        size_t rcvd;
        int acked, cnt;

        SUB_TEST_QUICK();

        /* Taking the only broker down raises __ALL_BROKERS_DOWN /
         * __TRANSPORT on the callbacks; none should fail the test. */
        test_curr->is_fatal_cb = test_error_is_not_fatal_cb;

        ctx = test_ctx_new();

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        rd_atomic32_init(&stall_cnt, 0);
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        /* The stall log is emitted on the CONSUMER debug context. */
        test_conf_set(conf, "debug", "consumer");
        test_conf_set(conf, "reconnect.backoff.ms", "100");
        test_conf_set(conf, "reconnect.backoff.max.ms", "500");
        rd_kafka_conf_set_log_cb(conf, fetch_stall_log_cb);
        rd_kafka_conf_set_opaque(conf, &stall_cnt);

        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");

        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Prime so the share group joins and the partition is assigned —
         * otherwise the stall reason would be "no partitions assigned". */
        mock_produce(ctx.producer, topic, 1);
        acked = consume_and_ack_all(rkshare, 1);
        TEST_ASSERT(acked == 1, "prime: expected 1 acked, got %d", acked);

        /* Flush the primed ack so the down broker doesn't get an
         * ack-only op unrelated to the stall we're measuring. */
        error = rd_kafka_share_commit_async(rkshare);
        TEST_ASSERT(!error, "commit_async error: %s",
                    error ? rd_kafka_error_string(error) : "NULL");

        /* Kickstart a poll while the broker is still up so the primed ack
         * is flushed to the broker — otherwise it is redelivered after
         * recovery and inflates the post-recovery count. */
        error = rd_kafka_share_poll(rkshare, 500, &batch);
        TEST_ASSERT(!error, "kickstart share_poll error: %s",
                    error ? rd_kafka_error_string(error) : "NULL");
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        /* Reset to drop any bring-up noise. */
        rd_atomic32_set(&stall_cnt, 0);

        /* Take the only broker down, then poll. With the partition still
         * assigned and no broker reachable, the main-thread loop keeps
         * wanting to fetch but select_broker returns NULL. The 2s poll
         * stays inside the throttle window. */
        rd_kafka_mock_broker_set_down(ctx.mcluster, 1);

        error = rd_kafka_share_poll(rkshare, 2000, &batch);
        TEST_ASSERT(!error, "down share_poll error: %s",
                    error ? rd_kafka_error_string(error) : "NULL");
        rcvd = rd_kafka_messages_count(batch);
        TEST_ASSERT(rcvd == 0, "expected 0 records, got %zu", rcvd);
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        cnt = rd_atomic32_get(&stall_cnt);
        TEST_SAY("\"Fetch stalled: no eligible broker\" log count: %d\n", cnt);
        TEST_ASSERT(cnt >= 1,
                    "expected the stall to be logged at least once, got %d",
                    cnt);
        /* Throttled: a 2s hot loop must not flood. Allow a small margin
         * for a race-window reset + re-log around set_down. */
        TEST_ASSERT(cnt <= 3,
                    "stall log must be throttled (<=3 in a 2s window), got %d",
                    cnt);

        /* Recovery: bring the broker back and confirm the consumer
         * drains. */
        rd_kafka_mock_broker_set_up(ctx.mcluster, 1);
        mock_produce(ctx.producer, topic, msgcnt_recovery);
        acked = consume_and_ack_all(rkshare, msgcnt_recovery);
        TEST_ASSERT(acked == msgcnt_recovery,
                    "post-recovery: expected %d acked, got %d", msgcnt_recovery,
                    acked);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Partition-level error injection: API basics.
 * =================================================================== */
static void test_partition_error_injection_general(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        char topic[64];
        char group[64];
        const int msgcnt = 3;
        int acked;

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        rd_snprintf(topic, sizeof(topic), "0182-part_err_general");
        rd_snprintf(group, sizeof(group), "sg-0182-part_err_general");

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        /* Unknown topics are auto-created. */
        TEST_ASSERT(rd_kafka_mock_partition_push_request_errors(
                        ctx.mcluster, "0182-no-such-topic", 0,
                        RD_KAFKAP_ShareFetch, 1,
                        RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push to unknown topic");

        /* Out-of-range partition is rejected. */
        TEST_ASSERT(rd_kafka_mock_partition_push_request_errors(
                        ctx.mcluster, topic, 99, RD_KAFKAP_ShareFetch, 1,
                        RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR) ==
                        RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
                    "push to unknown partition");

        TEST_ASSERT(rd_kafka_mock_partition_push_request_errors(
                        ctx.mcluster, topic, 0, RD_KAFKAP_ShareFetch, 1,
                        RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push partition error");

        mock_produce_partition(ctx.producer, topic, 0, msgcnt);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* The injected error is transient: all records are delivered
         * once it has been consumed off the stack. */
        acked = consume_and_ack_all(rkshare, msgcnt);
        TEST_ASSERT(acked == msgcnt, "expected %d acked, got %d", msgcnt,
                    acked);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  ShareFetch partition error injection: errors on one partition
 *  must not affect the other, and the partition recovers once the
 *  error stack drains.
 * =================================================================== */
static void test_partition_error_injection_share_fetch(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        char topic[64];
        char group[64];
        const int msgs_per_part = 5;
        int acked;

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        rd_snprintf(topic, sizeof(topic), "0182-part_err_sharefetch");
        rd_snprintf(group, sizeof(group), "sg-0182-part_err_sharefetch");

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 2, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        mock_produce_partition(ctx.producer, topic, 0, msgs_per_part);
        mock_produce_partition(ctx.producer, topic, 1, msgs_per_part);

        TEST_ASSERT(rd_kafka_mock_partition_push_request_errors(
                        ctx.mcluster, topic, 1, RD_KAFKAP_ShareFetch, 2,
                        RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER,
                        RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push partition errors");

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        /* Partition 0 is unaffected and partition 1 recovers after
         * the two errored fetches: nothing is lost. */
        acked = consume_and_ack_all(rkshare, 2 * msgs_per_part);
        TEST_ASSERT(acked == 2 * msgs_per_part, "expected %d acked, got %d",
                    2 * msgs_per_part, acked);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  ShareAcknowledge partition error injection: the injected error
 *  surfaces in commit_sync results for that partition only.
 * =================================================================== */
static void test_partition_error_injection_share_ack(void) {
        test_ctx_t ctx;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_error_t *error;
        char topic[64];
        char group[64];
        const int msgs_per_part = 5;
        const rd_kafka_resp_err_t injected_err =
            RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR;
        int acked;
        int i;

        SUB_TEST_QUICK();

        ctx = test_ctx_new();

        rd_snprintf(topic, sizeof(topic), "0182-part_err_shareack");
        rd_snprintf(group, sizeof(group), "sg-0182-part_err_shareack");

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 2, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        mock_produce_partition(ctx.producer, topic, 0, msgs_per_part);
        mock_produce_partition(ctx.producer, topic, 1, msgs_per_part);

        rkshare = create_mock_share_consumer(ctx.bootstraps, group, "explicit",
                                             NULL, NULL);
        test_share_consumer_subscribe_multi(rkshare, 1, topic);

        acked = consume_and_ack_all(rkshare, 2 * msgs_per_part);
        TEST_ASSERT(acked == 2 * msgs_per_part, "expected %d acked, got %d",
                    2 * msgs_per_part, acked);

        TEST_ASSERT(rd_kafka_mock_partition_push_request_errors(
                        ctx.mcluster, topic, 0, RD_KAFKAP_ShareAcknowledge, 1,
                        injected_err) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push partition error");

        partitions = NULL;
        error      = rd_kafka_share_commit_sync(rkshare, 30000, &partitions);
        if (error)
                rd_kafka_error_destroy(error);

        TEST_ASSERT(partitions != NULL, "expected non-NULL partition results");
        TEST_ASSERT(partitions->cnt == 2,
                    "expected results for 2 partitions, got %d",
                    partitions->cnt);

        /* Partition 0 carries the injected error, partition 1 is
         * unaffected. */
        for (i = 0; i < partitions->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
                rd_kafka_resp_err_t exp_err        = rktpar->partition == 0
                                                         ? injected_err
                                                         : RD_KAFKA_RESP_ERR_NO_ERROR;

                TEST_SAY("%s [%" PRId32 "]: %s\n", rktpar->topic,
                         rktpar->partition, rd_kafka_err2name(rktpar->err));
                TEST_ASSERT(rktpar->err == exp_err,
                            "partition [%" PRId32 "]: expected %s, got %s",
                            rktpar->partition, rd_kafka_err2name(exp_err),
                            rd_kafka_err2name(rktpar->err));
        }

        rd_kafka_topic_partition_list_destroy(partitions);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


int main_0182_share_consumer_error_handling_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);

        test_timeout_set(120);

        test_commit_sync_share_session_not_found();
        test_commit_sync_invalid_share_session_epoch();
        test_commit_sync_share_session_limit_reached();
        test_commit_sync_group_authorization_failed();
        test_commit_sync_topic_authorization_failed();
        test_commit_sync_invalid_request();
        test_commit_sync_multi_partition_top_level_error();
        test_consume_batch_multi_partition_top_level_error();
        test_commit_sync_at_epoch_zero_returns_invalid_session_epoch_error();
        test_consume_batch_at_epoch_zero_strips_piggyback_acks();
        test_strip_pre_set_survives_sharefetch_err();

        /* Topic-level metadata err surface */
        test_share_consumer_surfaces_topic_exception();
        test_share_consumer_surfaces_topic_authorization_failed();
        test_share_consumer_multi_partition_single_op_per_cycle();
        test_share_consumer_re_emits_when_err_code_changes();
        test_share_consumer_re_surfaces_after_recovery();
        test_share_consumer_re_surfaces_after_recovery_topic_exception();
        test_share_consumer_resubscribe_re_emits_persistent_failure();
        test_share_consumer_does_not_surface_unknown_topic_or_part();

        /* Socket timeout matrix (single broker).
         *
         * Each call corresponds to a different ordering of the three
         * timer layers (api_timeout_ms, socket_timeout_ms, rtt_ms).
         * See the comment in do_test_socket_timeout_full_ack_then_more
         * for the full analysis of what each ordering exercises.
         * Arguments are (api_timeout_ms, socket_timeout_ms, rtt_ms). */

        /* All 6 strict-inequality permutations. */
        do_test_socket_timeout_full_ack_then_more(
            1000, 5000, 3000); /* api < rtt < socket  */
        do_test_socket_timeout_full_ack_then_more(
            1000, 3000, 5000); /* api < socket < rtt  */
        do_test_socket_timeout_full_ack_then_more(
            3000, 5000, 1000); /* rtt < api < socket  */
        do_test_socket_timeout_full_ack_then_more(
            5000, 3000, 1000); /* rtt < socket < api  */
        do_test_socket_timeout_full_ack_then_more(
            3000, 1000, 5000); /* socket < api < rtt  */
        do_test_socket_timeout_full_ack_then_more(
            5000, 1000, 3000); /* socket < rtt < api  */
        /* Boundary api == socket is intentionally skipped: the race
         * between the api timer cb and the wire socket timer is
         * non-deterministic in practice — both outcomes are
         * observed across runs. */

        /* Partial-ack variant of the matrix. Phase 1 acks only half
         * the consumed records; Phase 2 acks the remaining half (still
         * in client's inflight map). Phase 2 commit_sync surfaces
         * INVALID_SHARE_SESSION_EPOCH when the session was dropped
         * by the Phase 1 socket teardown (socket < rtt), NO_ERROR
         * otherwise. */
        do_test_socket_timeout_partial_ack_then_remaining(
            1000, 5000, 3000); /* api < rtt < socket  */
        do_test_socket_timeout_partial_ack_then_remaining(
            1000, 3000, 5000); /* api < socket < rtt  */
        do_test_socket_timeout_partial_ack_then_remaining(
            3000, 5000, 1000); /* rtt < api < socket  */
        do_test_socket_timeout_partial_ack_then_remaining(
            5000, 3000, 1000); /* rtt < socket < api  */
        do_test_socket_timeout_partial_ack_then_remaining(
            3000, 1000, 5000); /* socket < api < rtt  */
        do_test_socket_timeout_partial_ack_then_remaining(
            5000, 1000, 3000); /* socket < rtt < api  */
        /* Boundary api == socket skipped — see comment above. */

        /* select_broker STATE_UP guard: steady-state DOWN and
         * race-window flavours. */
        do_test_no_bounce_loop_on_down_broker();
        do_test_one_log_on_broker_down_during_active_empty_poll();
        do_test_fetch_stall_logged_on_no_broker();


        /* Partition-level error injection. */
        test_partition_error_injection_general();
        test_partition_error_injection_share_fetch();
        test_partition_error_injection_share_ack();
        return 0;
}
