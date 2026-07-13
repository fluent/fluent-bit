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
 * @brief Share consumer leader change tests.
 *
 * Verifies that per-partition leader-change errors on ShareAcknowledge
 * trigger metadata refresh and that unnecessary RPCs are avoided once
 * the client discovers the new leader.
 */

#define CONSUME_ARRAY 1024

/* ===================================================================
 *  Mock broker infrastructure.
 * =================================================================== */
typedef struct test_ctx_s {
        rd_kafka_t *producer;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
} test_ctx_t;

static test_ctx_t test_ctx_new(int nbrok) {
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

static void test_ctx_destroy(test_ctx_t *ctx) {
        if (ctx->producer)
                rd_kafka_destroy(ctx->producer);
        if (ctx->mcluster)
                test_mock_cluster_destroy(ctx->mcluster);
        memset(ctx, 0, sizeof(*ctx));
}

static void subscribe_topics(rd_kafka_share_t *rkshare,
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
        TEST_ASSERT(!err, "subscribe failed: %s", rd_kafka_err2str(err));
        rd_kafka_topic_partition_list_destroy(subs);
}

static void subscribe_one(rd_kafka_share_t *rkshare, const char *topic) {
        subscribe_topics(rkshare, &topic, 1);
}

static int mock_produce(rd_kafka_t *producer,
                        const char *topic,
                        int32_t partition,
                        int msgcnt) {
        int i;
        for (i = 0; i < msgcnt; i++) {
                char payload[64];
                snprintf(payload, sizeof(payload), "%s-p%" PRId32 "-%d", topic,
                         partition, i);
                TEST_ASSERT(rd_kafka_producev(
                                producer, RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_PARTITION(partition),
                                RD_KAFKA_V_VALUE(payload, strlen(payload)),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_END) == RD_KAFKA_RESP_ERR_NO_ERROR,
                            "Produce to %s [%" PRId32 "] failed", topic,
                            partition);
        }
        rd_kafka_flush(producer, 5000);
        return msgcnt;
}

static rd_bool_t is_share_ack_request(rd_kafka_mock_request_t *request,
                                      void *opaque) {
        return rd_kafka_mock_request_api_key(request) ==
               RD_KAFKAP_ShareAcknowledge;
}

static rd_bool_t is_share_fetch_request(rd_kafka_mock_request_t *request,
                                        void *opaque) {
        return rd_kafka_mock_request_api_key(request) == RD_KAFKAP_ShareFetch;
}

static rd_bool_t is_metadata_request(rd_kafka_mock_request_t *request,
                                     void *opaque) {
        return rd_kafka_mock_request_api_key(request) == RD_KAFKAP_Metadata;
}


/* ===================================================================
 *  Test — ShareAcknowledge per-partition NOT_LEADER_OR_FOLLOWER
 *         should trigger metadata refresh and avoid redundant RPCs.
 *
 *  Setup:
 *    - 2 brokers, 1 topic, 1 partition on broker 1
 *    - Explicit ack mode, background metadata refresh disabled
 *    - Produce 10 records, consume one batch (expect all 10)
 *    - Move leader to broker 2
 *
 *  Loop (5 iterations):
 *    - Acknowledge 2 records from the held batch
 *    - commit_sync → attempts to route the batch to the cached
 *      leader. Round 1 routes to broker 1 (cache is stale);
 *      rounds 2-5 are short-circuited locally (see Expected
 *      behavior below).
 *
 *  Expected behavior with this PR:
 *    - The first commit_sync sends a ShareAcknowledge to broker 1
 *      (cache still says broker 1 is leader). The response carries
 *      NOT_LEADER_OR_FOLLOWER plus a CurrentLeader hint and
 *      NodeEndpoints; the inline metadata update applies the new
 *      leader to the cache without a separate Metadata RPC.
 *    - Rounds 2-5 are caught by the local leader-stale short-circuit
 *      in rd_kafka_share_ack_batch_resolve_leader_or_fail_acks and
 *      fail without sending an RPC.
 *    - All 5 commit_sync return NOT_LEADER_OR_FOLLOWER.
 *    - 1 ShareAcknowledge RPC total, 0 Metadata RPCs.
 * =================================================================== */
static void test_shareack_leader_change_reduces_rpcs(void) {
        test_ctx_t ctx;
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        const char *topic          = "0183-shareack-nlof";
        const char *group          = "sg-0183-shareack-nlof";
        const int broker1          = 1;
        const int broker2          = 2;
        const int msgcnt           = 10;
        const int acks_per_commit  = 2;
        const int commit_rounds    = msgcnt / acks_per_commit;
        rd_kafka_messages_t *batch = NULL;
        int round;
        size_t rcvd         = 0;
        size_t consumed_idx = 0;
        size_t share_ack_cnt;
        size_t metadata_cnt;

        SUB_TEST_QUICK();

        ctx = test_ctx_new(2);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        TEST_ASSERT(rd_kafka_mock_partition_set_leader(ctx.mcluster, topic, 0,
                                                       broker1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "set initial leader to broker %d", broker1);

        mock_produce(ctx.producer, topic, RD_KAFKA_PARTITION_UA, msgcnt);

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "explicit");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "-1");
        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");
        subscribe_one(rkshare, topic);

        /* Consume one batch — expect all 10 records in a single call. */
        error = rd_kafka_share_poll(rkshare, 10000, &batch);
        TEST_ASSERT(!error, "share_poll failed: %s",
                    error ? rd_kafka_error_string(error) : "");
        rcvd = rd_kafka_messages_count(batch);
        TEST_ASSERT(rcvd == (size_t)msgcnt,
                    "expected %d records in first batch, got %" PRIusz, msgcnt,
                    rcvd);

        /* Move leader to broker 2 before acknowledging. */
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(ctx.mcluster, topic, 0,
                                                       broker2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "set leader to broker %d", broker2);

        rd_kafka_mock_start_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);

        /* 5 rounds: acknowledge 2 records, commitSync each time.
         * Each commitSync should get NOT_LEADER_OR_FOLLOWER. */
        for (round = 0; round < commit_rounds; round++) {
                rd_kafka_topic_partition_list_t *results = NULL;
                int k;

                for (k = 0;
                     k < acks_per_commit && consumed_idx < (size_t)msgcnt;
                     k++, consumed_idx++) {
                        rd_kafka_resp_err_t ack_err;
                        ack_err = rd_kafka_share_acknowledge(
                            rkshare,
                            rd_kafka_messages_get(batch, consumed_idx));
                        TEST_ASSERT(ack_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                                    "round %d: acknowledge failed: %s", round,
                                    rd_kafka_err2str(ack_err));
                }

                error = rd_kafka_share_commit_sync(rkshare, 500, &results);

                TEST_SAY("round %d: commit_sync returned %s\n", round,
                         error ? rd_kafka_error_string(error) : "success");

                TEST_ASSERT(results != NULL && results->cnt > 0,
                            "round %d: expected results from commit_sync",
                            round);

                for (k = 0; k < results->cnt; k++) {
                        TEST_SAY("  round %d: partition %s [%" PRId32
                                 "] err=%s\n",
                                 round, results->elems[k].topic,
                                 results->elems[k].partition,
                                 rd_kafka_err2name(results->elems[k].err));
                        TEST_ASSERT(
                            results->elems[k].err ==
                                RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER,
                            "round %d: expected NOT_LEADER_OR_FOLLOWER, "
                            "got %s",
                            round, rd_kafka_err2name(results->elems[k].err));
                }

                rd_kafka_topic_partition_list_destroy(results);

                if (error)
                        rd_kafka_error_destroy(error);
        }

        share_ack_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_ack_request, NULL);
        metadata_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_metadata_request, NULL);

        TEST_SAY("ShareAcknowledge requests after leader change: %" PRIusz "\n",
                 share_ack_cnt);
        TEST_SAY("Metadata requests after leader change: %" PRIusz "\n",
                 metadata_cnt);

        /* The first commit_sync sends a ShareAcknowledge RPC to the
         * stale broker; the response carries CurrentLeader and
         * NodeEndpoints which update the metadata cache inline.
         * Rounds 2-5 are caught by the local leader-stale check and
         * fail without sending an RPC. No separate Metadata RPC is
         * needed because the cache update is inline. */
        TEST_ASSERT(share_ack_cnt == 1,
                    "expected 1 ShareAcknowledge RPC, got %" PRIusz,
                    share_ack_cnt);
        TEST_ASSERT(metadata_cnt == 0,
                    "expected 0 Metadata RPCs (inline cache update), "
                    "got %" PRIusz,
                    metadata_cnt);

        rd_kafka_mock_stop_request_tracking(ctx.mcluster);

        /* Clean up held message handles. */
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/* ===================================================================
 *  Test — per-partition NOT_LEADER_OR_FOLLOWER on ShareFetch is
 *         handled silently: no OP_CONSUMER_ERR, consumer recovers
 *         and continues reading from the new leader.
 *
 *  Two-broker mock cluster. Phase 1 produces and consumes records
 *  from broker1. The partition leader is moved to broker2. Phase 2
 *  verifies the consumer silently recovers and reads new records
 *  from broker2.
 *
 *  Wire-level verification: at least 1 Metadata request is triggered
 *  (error handler fired metadata refresh) and ShareFetch count stays
 *  below 10 (no retry storm).  The NOT_LEADER_OR_FOLLOWER response
 *  may arrive before or after request tracking starts, so a >= 2
 *  ShareFetch lower bound is not reliable; >= 1 is the meaningful
 *  minimum.
 *
 *  TODO KIP-932: Add a real-broker companion test that triggers a
 *  leader change on a multi-broker cluster.
 * =================================================================== */
static void test_partition_not_leader_or_follower_silent(void) {
        test_ctx_t ctx;
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        const char *topic          = "0183-nlof-silent";
        const char *group          = "sg-0183-nlof-silent";
        const int broker1          = 1;
        const int broker2          = 2;
        const int msgcnt           = 5;
        rd_kafka_messages_t *batch = NULL;
        int phase1_consumed        = 0;
        int phase2_consumed        = 0;
        int error_cnt              = 0;
        int attempts               = 0;
        size_t rcvd                = 0;
        size_t share_fetch_cnt;
        size_t metadata_cnt;
        size_t j;

        SUB_TEST_QUICK();

        ctx = test_ctx_new(2);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        /* Explicitly set the initial leader (do not assume a default). */
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(ctx.mcluster, topic, 0,
                                                       broker1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "set initial leader to broker %d", broker1);

        /* Phase 1: produce and consume records from broker1.
         * auto.offset.reset=earliest (set by test_ctx_new) so the
         * share group starts from the beginning of the log. */
        mock_produce(ctx.producer, topic, RD_KAFKA_PARTITION_UA, msgcnt);

        /* Disable background metadata refresh so that the only metadata
         * refresh that fires is the one triggered by the per-partition
         * NOT_LEADER_OR_FOLLOWER error.  This makes the >= 2 ShareFetch
         * assertion deterministic: background refresh would otherwise
         * silently update the cached leader before Phase 2 starts. */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", "implicit");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "-1");
        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");
        subscribe_one(rkshare, topic);

        while (phase1_consumed < msgcnt && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, j);
                        if (m && !m->err)
                                phase1_consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(phase1_consumed == msgcnt,
                    "Phase 1: expected %d records from broker %d, got %d",
                    msgcnt, broker1, phase1_consumed);

        /* Start request tracking before the leader change to capture
         * ShareFetch requests sent after it. */
        rd_kafka_mock_start_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);

        /* Move the partition leader to broker2. The consumer's next
         * ShareFetch to broker1 will get NOT_LEADER_OR_FOLLOWER per
         * partition, which triggers a silent metadata refresh and
         * reconnect to broker2. */
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(ctx.mcluster, topic, 0,
                                                       broker2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "set leader to broker %d", broker2);

        /* Produce records that will be available on broker2. mock_produce
         * flushes before returning, so all records are committed to
         * broker2 before Phase 2 begins. */
        mock_produce(ctx.producer, topic, RD_KAFKA_PARTITION_UA, msgcnt);

        /* Phase 2: consume records after recovery. OP_CONSUMER_ERR
         * surfaces as a non-NULL return from consume_batch; silent
         * handling must keep that return NULL throughout recovery. */
        attempts = 0;
        while (phase2_consumed < msgcnt && attempts++ < 30) {
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        error_cnt++;
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, j);
                        if (m && !m->err)
                                phase2_consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(phase2_consumed >= msgcnt,
                    "Phase 2: expected >= %d records from broker %d after "
                    "recovery, got %d",
                    msgcnt, broker2, phase2_consumed);
        TEST_ASSERT(error_cnt == 0,
                    "expected 0 OP_CONSUMER_ERR (NOT_LEADER_OR_FOLLOWER "
                    "must be silently handled), got %d",
                    error_cnt);

        /* Verify the error handler fired (metadata refresh triggered) and
         * did not cause a retry storm.  The NOT_LEADER_OR_FOLLOWER response
         * may be processed before or after request tracking starts, so only
         * a Metadata lower bound (not a >= 2 ShareFetch) is reliable. */
        share_fetch_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_share_fetch_request, NULL);
        metadata_cnt = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_metadata_request, NULL);
        TEST_SAY("ShareFetch requests after leader change: %" PRIusz "\n",
                 share_fetch_cnt);
        TEST_SAY("Metadata requests after leader change: %" PRIusz "\n",
                 metadata_cnt);
        TEST_ASSERT(metadata_cnt >= 1,
                    "expected >= 1 Metadata request after leader change "
                    "(error handler must have triggered metadata refresh), "
                    "got %" PRIusz,
                    metadata_cnt);
        TEST_ASSERT(share_fetch_cnt >= 1,
                    "expected >= 1 ShareFetch request after leader change, "
                    "got %" PRIusz,
                    share_fetch_cnt);
        TEST_ASSERT(share_fetch_cnt < 10,
                    "expected < 10 ShareFetch requests (no retry storm), "
                    "got %" PRIusz,
                    share_fetch_cnt);

        rd_kafka_mock_stop_request_tracking(ctx.mcluster);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);

        SUB_TEST_PASS();
}


/**
 * @brief Drive a consume loop until \p expected records have been read
 *        or the attempt budget is exhausted. In implicit mode an extra
 *        zero-timeout consume_batch flushes the last batch's auto-ack
 *        before returning.
 */
static int consume_phase(rd_kafka_share_t *rkshare,
                         rd_bool_t explicit_mode,
                         rd_bool_t use_commit_sync,
                         int expected,
                         int post_first_batch_settle_ms,
                         const char *phase_name) {
        int consumed                                   = 0;
        int attempts                                   = 0;
        int max_attempts                               = expected * 3 + 60;
        rd_kafka_messages_t *batch                     = NULL;
        rd_kafka_topic_partition_list_t *flush_results = NULL;
        rd_kafka_error_t *flush_err;
        rd_bool_t first_batch = rd_true;
        int ri;

        while (consumed < expected && attempts++ < max_attempts) {
                size_t rcvd = 0;
                rd_kafka_error_t *error;
                size_t j;

                error = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (error) {
                        TEST_SAY("%s: share_poll err %s\n", phase_name,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        continue;
                }

                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *m = rd_kafka_messages_get(batch, j);
                        if (m && !m->err) {
                                consumed++;
                                TEST_SAY("%s: record #%d: %s [%" PRId32
                                         "] offset %" PRId64 "\n",
                                         phase_name, consumed,
                                         rd_kafka_topic_name(m->rkt),
                                         m->partition, m->offset);
                                if (explicit_mode)
                                        rd_kafka_share_acknowledge(rkshare, m);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;

                if (explicit_mode && rcvd > 0) {
                        if (use_commit_sync) {
                                rd_kafka_topic_partition_list_t *results = NULL;
                                rd_kafka_error_t *cerr;
                                TEST_SAY(
                                    "%s: calling commit_sync "
                                    "(consumed %d)\n",
                                    phase_name, consumed);
                                cerr = rd_kafka_share_commit_sync(rkshare, 5000,
                                                                  &results);
                                if (cerr) {
                                        TEST_SAY("%s: commit_sync error: %s\n",
                                                 phase_name,
                                                 rd_kafka_error_string(cerr));
                                        rd_kafka_error_destroy(cerr);
                                }
                                RD_IF_FREE(
                                    results,
                                    rd_kafka_topic_partition_list_destroy);
                        } else {
                                rd_kafka_error_t *cerr =
                                    rd_kafka_share_commit_async(rkshare);
                                if (cerr) {
                                        TEST_SAY("%s: commit_async error: %s\n",
                                                 phase_name,
                                                 rd_kafka_error_string(cerr));
                                        rd_kafka_error_destroy(cerr);
                                }
                        }
                }

                /* After the first consume_batch call, let any pending
                 * metadata refresh and per-broker session
                 * reconciliation triggered by the leader change settle
                 * before the next consume_batch picks the next broker
                 * in round-robin. Without this wait the next broker's
                 * session is still stale, producing a redundant
                 * NOT_LEADER_FOR_PARTITION and metadata refresh. */
                if (first_batch && post_first_batch_settle_ms > 0) {
                        rd_usleep(post_first_batch_settle_ms * 1000, NULL);
                        first_batch = rd_false;
                }
        }

        /* Flush before exiting: commit_sync auto-acks for implicit
         * mode (via acknowledge_all_if_implicit) and drains pending
         * acks for explicit mode. Using commit_sync for both modes
         * avoids re-arming share_fetch_more_records via another
         * consume_batch, which would keep the main-thread fetch loop
         * spinning between phases. */
        TEST_SAY("%s: calling commit_sync flush (consumed %d/%d)\n", phase_name,
                 consumed, expected);
        flush_err = rd_kafka_share_commit_sync(rkshare, 5000, &flush_results);
        if (flush_err) {
                TEST_SAY("%s: commit_sync flush error: %s\n", phase_name,
                         rd_kafka_error_string(flush_err));
                rd_kafka_error_destroy(flush_err);
        } else {
                TEST_SAY("%s: commit_sync flush succeeded\n", phase_name);
        }
        if (flush_results) {
                for (ri = 0; ri < flush_results->cnt; ri++) {
                        rd_kafka_topic_partition_t *rp =
                            &flush_results->elems[ri];
                        TEST_SAY("%s: commit_sync result: %s [%" PRId32
                                 "]: %s\n",
                                 phase_name, rp->topic, rp->partition,
                                 rd_kafka_err2str(rp->err));
                }
                rd_kafka_topic_partition_list_destroy(flush_results);
                flush_results = NULL;
        }

        TEST_SAY("%s: consumed %d (expected == %d) in %d attempts\n",
                 phase_name, consumed, expected, attempts);
        return consumed;
}


/* ===================================================================
 *  Test — produce / consume / leader-change / produce / consume on a
 *         multi-topic, multi-partition mock cluster. Verifies that
 *         the share consumer picks up the new leader either via the
 *         Share RPC error path (refresh disabled) or via background
 *         metadata refresh (refresh enabled).
 *
 *  Setup:
 *    - 3 brokers, 2 topics ("recovery-a" with 2 partitions,
 *      "recovery-b" with 5 partitions). Initial leaders round-robin.
 *
 *  Phase 1:
 *    - Produce a random 10-20 records per partition.
 *    - Consume them all, ack/commit per variant.
 *
 *  Leader change:
 *    - Each partition's leader is rotated to a different broker
 *      (chosen randomly).
 *    - If \p wait_for_metadata_refresh is true the test sleeps long
 *      enough for the configured 500 ms background refresh to fire.
 *
 *  Phase 2:
 *    - Produce a random 10-20 records per partition.
 *    - Consume them all.
 *    - Assert the consumed count equals the Phase 2 production.
 *
 *  TODO KIP-932: once the ShareFetch response's per-partition
 *  CurrentLeader / NodeEndpoints hints are applied inline to the
 *  metadata cache (same approach as the ShareAcknowledge path), the
 *  refresh-disabled variant must see 0 Metadata RPCs after the
 *  leader change and the refresh-enabled variant must see >= 1
 *  (background refresh). Today both variants see >= 1 because the
 *  ShareFetch error path forces a metadata refresh RPC until the
 *  inline update lands.
 * =================================================================== */
static void
do_test_leader_change_consume_recovery(rd_bool_t explicit_mode,
                                       rd_bool_t use_commit_sync,
                                       rd_bool_t wait_for_metadata_refresh,
                                       const char *variant_name) {
        test_ctx_t ctx;
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        char *topic_a;
        char *topic_b;
        const char *topics[2];
        const int part_a    = 2;
        const int part_b    = 5;
        const char *group   = "sg-0183-recovery";
        int phase1_total    = 0;
        int phase2_total    = 0;
        int phase1_consumed = 0;
        int phase2_consumed = 0;
        int leader_before_a[2];
        int leader_before_b[5];
        size_t metadata_window1;
        size_t metadata_window2;
        int i;
        int cnt;

        SUB_TEST_QUICK("%s", variant_name);

        topic_a   = rd_strdup(test_mk_topic_name("0183-recovery-a", 1));
        topic_b   = rd_strdup(test_mk_topic_name("0183-recovery-b", 1));
        topics[0] = topic_a;
        topics[1] = topic_b;

        ctx = test_ctx_new(3);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_a, part_a,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic a");
        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic_b, part_b,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic b");

        for (i = 0; i < part_a; i++) {
                leader_before_a[i] = (i % 3) + 1;
                TEST_ASSERT(rd_kafka_mock_partition_set_leader(
                                ctx.mcluster, topic_a, i, leader_before_a[i]) ==
                                RD_KAFKA_RESP_ERR_NO_ERROR,
                            "set leader a[%d] -> %d", i, leader_before_a[i]);
        }
        for (i = 0; i < part_b; i++) {
                leader_before_b[i] = (i % 3) + 1;
                TEST_ASSERT(rd_kafka_mock_partition_set_leader(
                                ctx.mcluster, topic_b, i, leader_before_b[i]) ==
                                RD_KAFKA_RESP_ERR_NO_ERROR,
                            "set leader b[%d] -> %d", i, leader_before_b[i]);
        }

        srand(42);

        for (i = 0; i < part_a; i++) {
                cnt = 10 + (rand() % 11);
                phase1_total += mock_produce(ctx.producer, topic_a, i, cnt);
                TEST_SAY(
                    "%s: Phase 1 produce: %s [%d] = %d records "
                    "(offsets 0..%d)\n",
                    variant_name, topic_a, i, cnt, cnt - 1);
        }
        for (i = 0; i < part_b; i++) {
                cnt = 10 + (rand() % 11);
                phase1_total += mock_produce(ctx.producer, topic_b, i, cnt);
                TEST_SAY(
                    "%s: Phase 1 produce: %s [%d] = %d records "
                    "(offsets 0..%d)\n",
                    variant_name, topic_b, i, cnt, cnt - 1);
        }

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode",
                      explicit_mode ? "explicit" : "implicit");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms",
                      wait_for_metadata_refresh ? "10000" : "-1");
        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "create share consumer");
        subscribe_topics(rkshare, topics, 2);

        phase1_consumed = consume_phase(rkshare, explicit_mode, use_commit_sync,
                                        phase1_total, 0, "Phase 1");
        TEST_ASSERT(phase1_consumed == phase1_total,
                    "Phase 1: expected %d records, got %d", phase1_total,
                    phase1_consumed);

        /* Let initial offset queries (ListOffsetsRequest from the
         * share consumer's reused fetch-state machine on partition
         * assignment) complete before changing leaders. Without this
         * settle window, an in-flight ListOffsets response could race
         * with the leader change and bring in an extra metadata
         * refresh that pollutes Window 1.
         * TODO KIP-932: this wait can be removed once the share
         * consumer no longer issues ListOffsetsRequests. */
        rd_usleep(2000 * 1000, NULL);

        /* Window 1 — track Metadata RPCs from the leader change
         * through the wait sleep. Captures any background metadata
         * refresh fired while the consumer was idle. */
        rd_kafka_mock_start_request_tracking(ctx.mcluster);

        for (i = 0; i < part_a; i++) {
                int new_leader = leader_before_a[i];
                while (new_leader == leader_before_a[i])
                        new_leader = 1 + (rand() % 3);
                TEST_SAY("%s: leader change: %s [%d]: B%d -> B%d\n",
                         variant_name, topic_a, i, leader_before_a[i],
                         new_leader);
                TEST_ASSERT(rd_kafka_mock_partition_set_leader(
                                ctx.mcluster, topic_a, i, new_leader) ==
                                RD_KAFKA_RESP_ERR_NO_ERROR,
                            "set leader a[%d] -> %d", i, new_leader);
        }
        for (i = 0; i < part_b; i++) {
                int new_leader = leader_before_b[i];
                while (new_leader == leader_before_b[i])
                        new_leader = 1 + (rand() % 3);
                TEST_SAY("%s: leader change: %s [%d]: B%d -> B%d\n",
                         variant_name, topic_b, i, leader_before_b[i],
                         new_leader);
                TEST_ASSERT(rd_kafka_mock_partition_set_leader(
                                ctx.mcluster, topic_b, i, new_leader) ==
                                RD_KAFKA_RESP_ERR_NO_ERROR,
                            "set leader b[%d] -> %d", i, new_leader);
        }

        if (wait_for_metadata_refresh)
                rd_usleep(11000 * 1000, NULL);

        metadata_window1 = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_metadata_request, NULL);
        TEST_SAY(
            "%s: Window 1 (post leader change, pre Phase 2) "
            "Metadata: %" PRIusz "\n",
            variant_name, metadata_window1);

        /* Pause tracking around Phase 2 produce so producer-driven
         * metadata refreshes do not pollute the Window 2 count. */
        rd_kafka_mock_stop_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);

        for (i = 0; i < part_a; i++) {
                cnt = 10 + (rand() % 11);
                phase2_total += mock_produce(ctx.producer, topic_a, i, cnt);
                TEST_SAY(
                    "%s: Phase 2 produce: %s [%d] = %d records "
                    "(Phase 2 starts at offset after Phase 1)\n",
                    variant_name, topic_a, i, cnt);
        }
        for (i = 0; i < part_b; i++) {
                cnt = 10 + (rand() % 11);
                phase2_total += mock_produce(ctx.producer, topic_b, i, cnt);
                TEST_SAY(
                    "%s: Phase 2 produce: %s [%d] = %d records "
                    "(Phase 2 starts at offset after Phase 1)\n",
                    variant_name, topic_b, i, cnt);
        }

        /* Ensure all produces and their triggered metadata refreshes
         * have settled before measuring Phase 2 consume. */
        rd_kafka_flush(ctx.producer, 5000);

        /* Window 2 — track Metadata RPCs strictly around Phase 2
         * consume. Excludes producer activity from Phase 2 produce. */
        rd_kafka_mock_start_request_tracking(ctx.mcluster);

        phase2_consumed = consume_phase(rkshare, explicit_mode, use_commit_sync,
                                        phase2_total, 1000, "Phase 2");
        TEST_ASSERT(phase2_consumed == phase2_total,
                    "Phase 2: expected %d records after leader change, "
                    "got %d",
                    phase2_total, phase2_consumed);

        metadata_window2 = test_mock_get_matching_request_cnt(
            ctx.mcluster, is_metadata_request, NULL);
        TEST_SAY("%s: Window 2 (Phase 2 consume) Metadata: %" PRIusz "\n",
                 variant_name, metadata_window2);

        rd_kafka_mock_stop_request_tracking(ctx.mcluster);
        rd_kafka_mock_clear_requests(ctx.mcluster);

        /* TODO KIP-932: the share consumer still runs the regular
         * consumer's offset-query path. On leader change, the failed
         * ListOffsets requests trigger extra metadata refreshes that
         * inflate the wait-refresh window1 count and the no-refresh
         * window2 count beyond the single refresh those windows are
         * meant to capture. Once the offset-query path is removed
         * from the share consumer, tighten the >= 1 checks below to
         * == 1.
         *
         * TODO KIP-932: revisit these assertions when the ShareFetch
         * response handler applies its per-partition CurrentLeader
         * and NodeEndpoints hints inline to the metadata cache (same
         * approach already taken for the ShareAcknowledge path). At
         * that point the no-refresh variant must see 0 Metadata RPCs
         * during Phase 2 consume — the cache is updated from the
         * Share response, no separate Metadata RPC is needed — and
         * the wait-refresh expectations stay as today. */
        if (wait_for_metadata_refresh) {
                TEST_ASSERT(metadata_window1 >= 1,
                            "%s: expected >= 1 Metadata RPC during the "
                            "wait window (background refresh), got %" PRIusz,
                            variant_name, metadata_window1);
                TEST_ASSERT(metadata_window2 == 0,
                            "%s: expected 0 Metadata RPCs during Phase 2 "
                            "consume (cache already updated, no error path), "
                            "got %" PRIusz,
                            variant_name, metadata_window2);
        } else {
                TEST_ASSERT(metadata_window1 == 0,
                            "%s: expected 0 Metadata RPCs before Phase 2 "
                            "(background refresh disabled, no error yet), "
                            "got %" PRIusz,
                            variant_name, metadata_window1);
                TEST_ASSERT(metadata_window2 >= 1,
                            "%s: expected >= 1 Metadata RPC during Phase 2 "
                            "consume (ShareFetch error path triggered "
                            "refresh), got %" PRIusz,
                            variant_name, metadata_window2);
        }

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);
        rd_free(topic_a);
        rd_free(topic_b);

        SUB_TEST_PASS();
}


// /* ===================================================================
//  *  Test — per-partition UNKNOWN_TOPIC_OR_PARTITION on ShareFetch is
//  *         handled silently: no OP_CONSUMER_ERR is delivered after the
//  *         topic is deleted.
//  *
//  *  Single-broker mock cluster. Phase 1 produces and consumes records
//  *  to establish a share session. The topic is deleted. Phase 2 polls
//  *  several times and verifies no error is surfaced to the application.
//  *
//  *  Wire-level verification: ShareFetch count is between 1 and 9
//  *  (lower bound: error path fired; upper bound: no retry storm).
//  *
//  *  TODO KIP-932: Add a real-broker companion test that deletes a
//  *  live topic and verifies the same silent behaviour.
//  * =================================================================== */
// static void test_partition_unknown_topic_silent(void) {
//         test_ctx_t ctx;
//         rd_kafka_conf_t *conf;
//         rd_kafka_share_t *rkshare;
//         rd_kafka_error_t *error;
//         const char *topic = "0183-utp-silent";
//         const char *group = "sg-0183-utp-silent";
//         const int msgcnt  = 5;
//         rd_kafka_message_t *rkmessages[CONSUME_ARRAY];
//         int phase1_consumed = 0;
//         int error_cnt       = 0;
//         int attempts        = 0;
//         int poll_cnt        = 0;
//         size_t rcvd         = 0;
//         size_t share_fetch_cnt;
//         size_t metadata_cnt;
//         size_t j;

//         SUB_TEST_QUICK();

//         ctx = test_ctx_new(1);

//         TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, 1, 1) ==
//                         RD_KAFKA_RESP_ERR_NO_ERROR,
//                     "create topic");

//         /* Phase 1: produce and consume records to establish a share
//          * session. auto.offset.reset=earliest (set by test_ctx_new) so
//          * the share group starts from the beginning of the log. */
//         mock_produce(ctx.producer, topic, RD_KAFKA_PARTITION_UA, msgcnt);

//         /* Disable auto-create so the metadata handler does not recreate
//          * the deleted topic, and disable the propagation wait so the
//          * toppar is removed from the session immediately when metadata
//          * confirms the topic is gone (instead of waiting 30 s). */
//         test_conf_init(&conf, NULL, 0);
//         test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
//         test_conf_set(conf, "group.id", group);
//         test_conf_set(conf, "share.acknowledgement.mode", "implicit");
//         test_conf_set(conf, "allow.auto.create.topics", "false");
//         test_conf_set(conf, "topic.metadata.propagation.max.ms", "0");
//         rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
//         TEST_ASSERT(rkshare != NULL, "Failed to create share consumer");
//         subscribe_one(rkshare, topic);

//         while (phase1_consumed < msgcnt && attempts++ < 30) {
//                 rcvd  = 0;
//                 error = rd_kafka_share_poll(rkshare, 3000,
//                 rkmessages,
//                                                      &rcvd);
//                 if (error) {
//                         rd_kafka_error_destroy(error);
//                         continue;
//                 }
//                 for (j = 0; j < rcvd; j++) {
//                         if (!rkmessages[j]->err)
//                                 phase1_consumed++;
//                         rd_kafka_message_destroy(rkmessages[j]);
//                 }
//         }
//         TEST_ASSERT(phase1_consumed == msgcnt,
//                     "Phase 1: expected %d records, got %d", msgcnt,
//                     phase1_consumed);

//         /* Start request tracking before topic deletion to capture
//          * ShareFetch requests that get UNKNOWN_TOPIC_OR_PARTITION. */
//         rd_kafka_mock_start_request_tracking(ctx.mcluster);
//         rd_kafka_mock_clear_requests(ctx.mcluster);

//         /* Delete the topic. The consumer's next ShareFetch will receive
//          * UNKNOWN_TOPIC_OR_PARTITION per partition, which must be handled
//          * silently (metadata refresh, no OP_CONSUMER_ERR). */
//         TEST_ASSERT(rd_kafka_mock_topic_delete(ctx.mcluster, topic) ==
//                         RD_KAFKA_RESP_ERR_NO_ERROR,
//                     "delete topic");

//         /* Phase 2: poll several times. OP_CONSUMER_ERR surfaces as a
//          * non-NULL return from consume_batch; count any such return as
//          * an error (silent handling requires zero). */
//         while (poll_cnt++ < 5) {
//                 rcvd  = 0;
//                 error = rd_kafka_share_poll(rkshare, 1000,
//                 rkmessages,
//                                                      &rcvd);
//                 if (error) {
//                         error_cnt++;
//                         rd_kafka_error_destroy(error);
//                         continue;
//                 }
//                 for (j = 0; j < rcvd; j++)
//                         rd_kafka_message_destroy(rkmessages[j]);
//         }
//         TEST_ASSERT(error_cnt == 0,
//                     "expected 0 OP_CONSUMER_ERR after topic delete "
//                     "(UNKNOWN_TOPIC_OR_PARTITION must be silently handled), "
//                     "got %d",
//                     error_cnt);

//         /* Verify the error path fired. The background "keep fetching" loop
//          * may send additional empty ShareFetch requests after the partition
//          * leaves the session, so only a lower bound is meaningful here. */
//         share_fetch_cnt = test_mock_get_matching_request_cnt(
//             ctx.mcluster, is_share_fetch_request, NULL);
//         TEST_SAY("ShareFetch requests after topic delete: %" PRIusz "\n",
//                  share_fetch_cnt);
//         TEST_ASSERT(share_fetch_cnt >= 1,
//                     "expected >= 1 ShareFetch after topic delete "
//                     "(error path must have fired), got %" PRIusz,
//                     share_fetch_cnt);

//         /* Verify a metadata refresh was triggered by the error. */
//         metadata_cnt = test_mock_get_matching_request_cnt(
//             ctx.mcluster, is_metadata_request, NULL);
//         TEST_SAY("Metadata requests after topic delete: %" PRIusz "\n",
//                  metadata_cnt);
//         TEST_ASSERT(metadata_cnt >= 1,
//                     "expected >= 1 Metadata request after topic delete "
//                     "(metadata refresh must fire), got %" PRIusz,
//                     metadata_cnt);

//         rd_kafka_mock_stop_request_tracking(ctx.mcluster);

//         test_share_consumer_close(rkshare);
//         test_share_destroy(rkshare);
//         test_ctx_destroy(&ctx);

//         SUB_TEST_PASS();
// }

/* ===================================================================
 *  Regression test: records survive a leader-less partition transit.
 * -------------------------------------------------------------------
 *  Trigger: a partition becomes leader-less between two leader
 *  changes (leader -> -1 -> new_leader). The leader-less period
 *  makes the client briefly delegate the toppar to the :0/internal
 *  pseudo-broker. Previously, that pseudo-broker thread ran the
 *  regular-consumer fetch_decide path on the share-consumer rktp,
 *  promoting rktp_fetch_version above 0. Subsequent share-fetch
 *  parsing then stamped every parsed message rko with that
 *  promoted version, after which the version-outdated filter
 *  dropped them silently (because rktp_version had been bumped by
 *  the initial fetch_start barrier).
 *
 *  Repro shape:
 *    1. leader=1; produce phase 1; consume phase 1.
 *    2. set leader=-1; consume again briefly so the consumer
 *       processes the metadata change and migrates the toppar to
 *       :0/internal. This is the step that historically promoted
 *       rktp_fetch_version on the share-consumer rktp.
 *    3. wait 3 s for the bad state to settle.
 *    4. set leader=2 but DO NOT consume yet — let the migration
 *       to broker 2 happen quietly.
 *    5. produce phase 2 on the new leader.
 *    6. consume phase 2 and verify every produced record reaches
 *       the application.
 *
 *  Pre-fix: phase 2 consumed < phase 2 produced (parsed records
 *  dropped by the version filter). Post-fix: phase 2 fully drained.
 * =================================================================== */
static void
do_test_records_survive_leaderless_transit(rd_bool_t explicit_mode) {
        test_ctx_t ctx;
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        rd_kafka_messages_t *drain_batch = NULL;
        size_t drain_rcvd                = 0;
        char *topic;
        const int part_cnt  = 1;
        const char *group   = "sg-0183-leaderless-transit";
        int phase1_total    = 0;
        int phase2_total    = 0;
        int phase1_consumed = 0;
        int phase2_consumed = 0;
        int i;

        SUB_TEST_QUICK("%s", explicit_mode ? "explicit" : "implicit");

        topic = rd_strdup(test_mk_topic_name("0183-leaderless-transit", 1));

        ctx = test_ctx_new(3);

        TEST_ASSERT(rd_kafka_mock_topic_create(ctx.mcluster, topic, part_cnt,
                                               1) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");

        /* All partitions start on broker 1. */
        for (i = 0; i < part_cnt; i++)
                TEST_ASSERT(rd_kafka_mock_partition_set_leader(ctx.mcluster,
                                                               topic, i, 1) ==
                                RD_KAFKA_RESP_ERR_NO_ERROR,
                            "set initial leader [%d] -> 1", i);

        srand(42);
        for (i = 0; i < part_cnt; i++)
                phase1_total +=
                    mock_produce(ctx.producer, topic, i, 20 + (rand() % 11));

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", ctx.bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode",
                      explicit_mode ? "explicit" : "implicit");
        /* Short refresh interval so leader-change notifications
         * land quickly. */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "2000");
        rkshare = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(rkshare != NULL, "create share consumer");
        subscribe_one(rkshare, topic);

        /* Phase 1: consume initial batch from broker 1. This warms
         * up the consumer's view of leader=1 for every partition. */
        phase1_consumed = consume_phase(rkshare, explicit_mode, rd_true,
                                        phase1_total, 0, "Phase 1");
        TEST_ASSERT(phase1_consumed == phase1_total,
                    "Phase 1: expected %d, got %d", phase1_total,
                    phase1_consumed);

        /* First leader change: every partition becomes leader-less.
         * The next consume call drives the share-fetch loop, which
         * will hit broker 1, get NOT_LEADER_OR_FOLLOWER, refresh
         * metadata, see leader_id=-1, and delegate the toppar to the
         * :0/internal pseudo-broker — the exact bug-trigger. */
        for (i = 0; i < part_cnt; i++)
                TEST_ASSERT(rd_kafka_mock_partition_set_leader(ctx.mcluster,
                                                               topic, i, -1) ==
                                RD_KAFKA_RESP_ERR_NO_ERROR,
                            "set leader [%d] -> -1 (leader-less)", i);

        /* Mid consume_batch: drive the internal fetch cycle so the
         * consumer hits broker 1 with SHAREFETCH, gets
         * NOT_LEADER_OR_FOLLOWER, refreshes metadata, sees
         * leader_id=-1, and delegates the rktp to the :0/internal
         * pseudo-broker. No records expected (leader-less). */
        TEST_ASSERT(!rd_kafka_share_poll(rkshare, 500, &drain_batch),
                    "mid share_poll unexpected err");
        drain_rcvd = rd_kafka_messages_count(drain_batch);
        TEST_ASSERT(drain_rcvd == 0,
                    "mid share_poll expected 0 records during the "
                    "leader-less window, got %" PRIusz,
                    drain_rcvd);
        rd_kafka_messages_destroy(drain_batch);
        drain_batch = NULL;

        /* Settle: pre-fix, :0/internal's broker_internal_serve loop
         * runs consumer_toppars_serve here, which calls fetch_decide
         * on the share-consumer rktp and promotes
         * rktp_fetch_version. After this point, any parsed
         * share-fetch message gets stamped with the promoted
         * version and dropped by the version-outdated filter. */
        rd_usleep(3000 * 1000, NULL);

        /* Second leader change: leader=2. The fast-query timer
         * armed by the NOT_LEADER response is still active and will
         * fire within ~1s (capped by retry_backoff_max_ms), find
         * leader=2, and clear LEADER_UNAVAIL. No consume here — let
         * the metadata refresh happen on its own. */
        for (i = 0; i < part_cnt; i++)
                TEST_ASSERT(rd_kafka_mock_partition_set_leader(ctx.mcluster,
                                                               topic, i, 2) ==
                                RD_KAFKA_RESP_ERR_NO_ERROR,
                            "set leader [%d] -> 2", i);

        /* Produce Phase 2 records on the new leader. */
        for (i = 0; i < part_cnt; i++)
                phase2_total +=
                    mock_produce(ctx.producer, topic, i, 20 + (rand() % 11));
        rd_kafka_flush(ctx.producer, 5000);

        /* Phase 2: every record produced post-transit must reach the
         * application. Pre-fix this assertion failed because parsed
         * SHAREFETCH messages were stamped with the promoted
         * fetch_version and then dropped by the version-outdated
         * filter against the bumped rktp_version. */
        phase2_consumed = consume_phase(rkshare, explicit_mode, rd_true,
                                        phase2_total, 1500, "Phase 2");
        TEST_ASSERT(phase2_consumed == phase2_total,
                    "Phase 2: expected %d records after leader-less "
                    "transit + new leader, got %d. If pre-fix: parsed "
                    "records were silently dropped by the "
                    "rktp_version filter on the share-consumer path.",
                    phase2_total, phase2_consumed);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ctx_destroy(&ctx);
        rd_free(topic);

        SUB_TEST_PASS();
}


int main_0183_share_consumer_leader_change_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);
        test_timeout_set(120);

        test_shareack_leader_change_reduces_rpcs();
        test_partition_not_leader_or_follower_silent();
        /* test_partition_unknown_topic_silent(); */

        do_test_records_survive_leaderless_transit(rd_false);
        do_test_records_survive_leaderless_transit(rd_true);

        do_test_leader_change_consume_recovery(rd_false, rd_false, rd_false,
                                               "implicit-no-refresh");
        do_test_leader_change_consume_recovery(rd_false, rd_false, rd_true,
                                               "implicit-wait-refresh");
        do_test_leader_change_consume_recovery(rd_true, rd_false, rd_false,
                                               "explicit-async-no-refresh");
        do_test_leader_change_consume_recovery(rd_true, rd_false, rd_true,
                                               "explicit-async-wait-refresh");
        do_test_leader_change_consume_recovery(rd_true, rd_true, rd_false,
                                               "explicit-sync-no-refresh");
        do_test_leader_change_consume_recovery(rd_true, rd_true, rd_true,
                                               "explicit-sync-wait-refresh");
        return 0;
}