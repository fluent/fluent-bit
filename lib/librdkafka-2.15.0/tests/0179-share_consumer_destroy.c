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
#include "../src/rdkafka.h"
#include "../src/rdkafka_proto.h"

#define CONSUME_ARRAY        1000
#define TEST_MSGS            100
#define MAX_CONSUME_ATTEMPTS 30
#define MAX_PARTITIONS       32

/* Shared producer/admin handles for real-broker tests. Created in
 * main_0179_share_consumer_destroy and reused across sub-tests. */
static rd_kafka_t *common_producer;
static rd_kafka_t *common_admin;


/****************************************************************************
 * Acknowledgement Callback Tracking Helpers
 ****************************************************************************/

/**
 * @brief Create a share consumer for the mock-broker tests in this file.
 *
 *        Points at the supplied mock bootstraps (test_create_share_consumer
 *        cannot, since it reads the real-broker bootstrap globals), sets
 *        a fast topic.metadata.refresh.interval.ms (500) so the client
 *        observes mock metadata changes quickly, and conditionally enables
 *        explicit ack mode.
 */
/**
 * @brief One per-partition entry from a share-ack callback invocation.
 *        Each callback may report N partition entries; we record one
 *        ack_receipt_t per (topic, partition) entry, carrying the
 *        callback-level err and the offsets count for that partition.
 */
typedef struct {
        char *topic;
        int32_t partition;
        int offset_cnt;
        rd_kafka_resp_err_t err;
} ack_receipt_t;

typedef struct {
        ack_receipt_t *receipts;
        int receipt_cnt;
        int receipt_capacity;
        int callback_invocations;
} ack_receipts_t;

static void ack_receipts_init(ack_receipts_t *r) {
        memset(r, 0, sizeof(*r));
}

static void ack_receipts_destroy(ack_receipts_t *r) {
        int i;
        for (i = 0; i < r->receipt_cnt; i++)
                rd_free(r->receipts[i].topic);
        if (r->receipts)
                rd_free(r->receipts);
}

static void ack_receipts_add(ack_receipts_t *r,
                             const char *topic,
                             int32_t partition,
                             int offset_cnt,
                             rd_kafka_resp_err_t err) {
        if (r->receipt_cnt == r->receipt_capacity) {
                int new_cap =
                    r->receipt_capacity ? r->receipt_capacity * 2 : 16;
                r->receipts =
                    rd_realloc(r->receipts, new_cap * sizeof(*r->receipts));
                r->receipt_capacity = new_cap;
        }
        r->receipts[r->receipt_cnt].topic      = rd_strdup(topic);
        r->receipts[r->receipt_cnt].partition  = partition;
        r->receipts[r->receipt_cnt].offset_cnt = offset_cnt;
        r->receipts[r->receipt_cnt].err        = err;
        r->receipt_cnt++;
}

/**
 * @brief Share-ack callback that funnels each partition entry into
 *        the provided ack_receipts_t (passed as opaque).
 */
static void record_share_ack_cb(rd_kafka_share_t *rkshare,
                                rd_kafka_share_partition_offsets_list_t *parts,
                                rd_kafka_resp_err_t err,
                                void *opaque) {
        ack_receipts_t *r = opaque;
        size_t pcnt, p;

        (void)rkshare;

        r->callback_invocations++;

        pcnt = rd_kafka_share_partition_offsets_list_count(parts);
        TEST_SAY("ack_cb invocation #%d: err=%s partitions=%zu\n",
                 r->callback_invocations, rd_kafka_err2name(err), pcnt);

        for (p = 0; p < pcnt; p++) {
                const rd_kafka_share_partition_offsets_t *entry =
                    rd_kafka_share_partition_offsets_list_get(parts, p);
                const rd_kafka_topic_partition_t *tp;
                int ocnt;
                if (!entry)
                        continue;
                tp   = rd_kafka_share_partition_offsets_partition(entry);
                ocnt = rd_kafka_share_partition_offsets_offsets_cnt(entry);
                TEST_SAY("  %s [%" PRId32 "] offsets=%d err=%s\n", tp->topic,
                         tp->partition, ocnt, rd_kafka_err2name(err));
                ack_receipts_add(r, tp->topic, tp->partition, ocnt, err);
        }
}

/**
 * @brief One expected (topic, partition, err) group. The assertion
 *        is: across all recorded receipts whose
 *        (topic, partition, err) match this entry, the sum of
 *        offset_cnt equals expected_offset_cnt. Multiple receipts
 *        for the same (topic, partition, err) — possible if the
 *        callback fires more than once for the same partition — are
 *        summed.
 *
 *        Receipts that don't match any expected group cause a test
 *        failure.
 */
typedef struct {
        const char *topic;
        int32_t partition;
        rd_kafka_resp_err_t err;
        int expected_offset_cnt;
} expected_ack_t;

static void verify_ack_receipts(ack_receipts_t *r,
                                const expected_ack_t *expected,
                                int expected_cnt,
                                const char *label) {
        int i, j;

        TEST_SAY(
            "Verifying ack receipts (%s): %d receipts from %d "
            "invocation(s), %d expected (topic, partition, err) group(s)\n",
            label, r->receipt_cnt, r->callback_invocations, expected_cnt);

        /* Assert each expected group is satisfied. */
        for (j = 0; j < expected_cnt; j++) {
                int observed_offset_cnt = 0;
                int matching_receipts   = 0;

                for (i = 0; i < r->receipt_cnt; i++) {
                        if (r->receipts[i].partition == expected[j].partition &&
                            r->receipts[i].err == expected[j].err &&
                            strcmp(r->receipts[i].topic, expected[j].topic) ==
                                0) {
                                observed_offset_cnt +=
                                    r->receipts[i].offset_cnt;
                                matching_receipts++;
                        }
                }

                if (observed_offset_cnt != expected[j].expected_offset_cnt) {
                        TEST_FAIL(
                            "ack receipts (%s): expected %d offsets for "
                            "%s [%" PRId32
                            "] with err=%s, got %d (across "
                            "%d receipt(s))",
                            label, expected[j].expected_offset_cnt,
                            expected[j].topic, expected[j].partition,
                            rd_kafka_err2name(expected[j].err),
                            observed_offset_cnt, matching_receipts);
                }

                TEST_SAY("  OK: %s [%" PRId32
                         "] err=%s -> %d offsets across %d receipt(s)\n",
                         expected[j].topic, expected[j].partition,
                         rd_kafka_err2name(expected[j].err),
                         observed_offset_cnt, matching_receipts);
        }

        /* Flag any receipt that didn't match any expected group. */
        for (i = 0; i < r->receipt_cnt; i++) {
                rd_bool_t matched = rd_false;
                for (j = 0; j < expected_cnt; j++) {
                        if (r->receipts[i].partition == expected[j].partition &&
                            r->receipts[i].err == expected[j].err &&
                            strcmp(r->receipts[i].topic, expected[j].topic) ==
                                0) {
                                matched = rd_true;
                                break;
                        }
                }
                if (!matched) {
                        TEST_FAIL(
                            "ack receipts (%s): unexpected receipt for "
                            "%s [%" PRId32 "] err=%s offsets=%d",
                            label, r->receipts[i].topic,
                            r->receipts[i].partition,
                            rd_kafka_err2name(r->receipts[i].err),
                            r->receipts[i].offset_cnt);
                }
        }
}

/**
 * @brief Drain pending ack callbacks from rk_rep by polling.
 *
 * Polls in 1s ticks for up to \p max_seconds. Stops early if
 * the callback invocation counter advances past
 * \p expected_invocations.
 */
static void drain_ack_callbacks(rd_kafka_share_t *rkshare) {
        int max_seconds = 10;
        rd_kafka_t *rk  = test_share_consumer_get_rk(rkshare);
        int waited;
        for (waited = 0; waited < max_seconds; waited++) {
                rd_kafka_poll(rk, 0);
                rd_sleep(1);
        }
        /* One final poll for any callback that fired during the
         * last sleep. */
        rd_kafka_poll(rk, 0);
}

/****************************************************************************
 * General Helpers
 ****************************************************************************/

static rd_kafka_share_t *
new_share_consumer_for_mock_test(const char *bootstraps,
                                 const char *group_id,
                                 rd_bool_t explicit_ack,
                                 ack_receipts_t *receipts) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *consumer;

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "500");
        if (explicit_ack)
                test_conf_set(conf, "share.acknowledgement.mode", "explicit");

        consumer = rd_kafka_share_consumer_new(conf, NULL, 0);
        TEST_ASSERT(consumer != NULL, "Failed to create share consumer");

        if (receipts) {
                rd_kafka_error_t *error =
                    rd_kafka_share_set_acknowledgement_commit_cb(
                        consumer, record_share_ack_cb, receipts);
                TEST_ASSERT(error == NULL,
                            "Failed to set acknowledgement commit callback: "
                            "%s",
                            rd_kafka_error_string(error));
        }
        return consumer;
}


/**
 * @brief Create a share consumer for the real-broker tests in this file.
 *
 *        Like test_create_share_consumer but additionally wires the
 *        ack-callback (record_share_ack_cb) when @p receipts is
 *        non-NULL.
 */
static rd_kafka_share_t *
new_share_consumer_for_real_test(const char *group_id,
                                 const char *ack_mode,
                                 ack_receipts_t *receipts) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *consumer;
        char errstr[512];

        test_conf_init(&conf, NULL, 0);
        rd_kafka_conf_set(conf, "group.id", group_id, errstr, sizeof(errstr));
        rd_kafka_conf_set(conf, "share.acknowledgement.mode", ack_mode, errstr,
                          sizeof(errstr));

        consumer = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(consumer, "Failed to create share consumer: %s", errstr);

        if (receipts) {
                rd_kafka_error_t *error =
                    rd_kafka_share_set_acknowledgement_commit_cb(
                        consumer, record_share_ack_cb, receipts);
                TEST_ASSERT(error == NULL,
                            "Failed to set acknowledgement commit callback: "
                            "%s",
                            rd_kafka_error_string(error));
        }
        return consumer;
}

/**
 * @brief Subscribe to topics.
 */
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


/**
 * @brief Acknowledge messages in [start, end) and log each result.
 */
static void ack_range_logged(rd_kafka_share_t *rkshare,
                             rd_kafka_messages_t *batch,
                             int start,
                             int end,
                             int rcvd) {
        int i;
        for (i = start; i < end && i < rcvd; i++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(batch, i);
                rd_kafka_resp_err_t ack_err;
                if (!rkm)
                        continue;
                ack_err = rd_kafka_share_acknowledge(rkshare, rkm);
                TEST_SAY("  ack msg[%d] %s[%" PRId32 "]@%" PRId64 " -> %s\n", i,
                         rd_kafka_topic_name(rkm->rkt), rkm->partition,
                         rkm->offset, rd_kafka_err2str(ack_err));
        }
}

/**
 * @brief Destroy a share consumer, using flags variant when non-zero.
 */
static void destroy_share_consumer(rd_kafka_share_t *rkshare,
                                   int destroy_flags) {
        TEST_SAY("Calling destroy with flags 0x%x\n", destroy_flags);
        if (destroy_flags)
                rd_kafka_share_destroy_flags(rkshare, destroy_flags);
        else
                rd_kafka_share_destroy(rkshare);
        TEST_SAY("Successfully destroyed share consumer\n");
}

/* Per-thread argument for destroy_watchdog_thread. Atomic `done` lets the
 * main thread poll for completion without locking. */
typedef struct destroy_watchdog_arg_s {
        rd_kafka_share_t *rkshare;
        int destroy_flags;
        rd_atomic32_t done;
} destroy_watchdog_arg_t;

static int destroy_watchdog_thread(void *p) {
        destroy_watchdog_arg_t *a = p;
        if (a->destroy_flags)
                rd_kafka_share_destroy_flags(a->rkshare, a->destroy_flags);
        else
                rd_kafka_share_destroy(a->rkshare);
        rd_atomic32_set(&a->done, 1);
        return 0;
}

/**
 * @brief is_fatal_cb hook for test_broker_decommission_with_commit_sync.
 *
 * The decommission of a broker mid-flight produces __TRANSPORT and
 * __ALL_BROKERS_DOWN errors as the connection is dropped and the client
 * tries to reconnect. These are expected and should not fail the test.
 */
static int decommission_is_fatal_cb(rd_kafka_t *rk,
                                    rd_kafka_resp_err_t err,
                                    const char *reason) {
        if (err == RD_KAFKA_RESP_ERR__TRANSPORT ||
            err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN) {
                TEST_SAY("Ignoring expected error: %s: %s\n",
                         rd_kafka_err2name(err), reason);
                return 0;
        }
        return 1;
}

/****************************************************************************
 * Test Cases
 ****************************************************************************/

/**
 * @brief This test uses mock brokers to simulate delayed broker responses and
 * makes commit* calls causing acknowledgements to get cached. Eventually, calls
 * destroy() to validate that it does not hang.
 * @param destroy_flags 0 for normal destroy,
 * RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE to skip consumer close.
 *
 * In case of RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE, a __DESTROY error is
 * expected to be returned from the broker thread having requests in-flight
 */
static void
test_destroy_with_cached_acks_and_delayed_broker(int destroy_flags) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *rkmessages                = NULL;
        rd_kafka_topic_partition_list_t *commit_result = NULL;
        const char *topic         = "0179-destroy-cached-acks-delayed-broker";
        const char *group         = "0179-destroy-cached-acks";
        const int broker_delay_ms = 5000;
        size_t rcvd               = 0;
        int attempts              = 0;
        int i;
        rd_ts_t t_start, t_elapsed_ms;
        ack_receipts_t receipts;

        ack_receipts_init(&receipts);

        SUB_TEST_QUICK("destroy_flags=0x%x", destroy_flags);

        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        TEST_SAY("Producing %d messages to topic %s\n", TEST_MSGS, topic);
        test_produce_msgs_easy_v(topic, 0, 0, 0, TEST_MSGS, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        TEST_SAY("Creating share consumer with explicit ack\n");
        rkshare = new_share_consumer_for_mock_test(bootstraps, group, rd_true,
                                                   &receipts);
        subscribe_topics(rkshare, &topic, 1);

        TEST_SAY("Consuming messages (up to %d attempts)\n",
                 MAX_CONSUME_ATTEMPTS);
        while (rcvd < 10 && attempts < MAX_CONSUME_ATTEMPTS) {
                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);

                if (error) {
                        TEST_SAY("Attempt %d: consume error: %s\n", attempts,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                } else {
                        rcvd = rd_kafka_messages_count(rkmessages);
                        if (rcvd > 0)
                                TEST_SAY("Attempt %d: consumed %d messages\n",
                                         attempts, (int)rcvd);
                }
                attempts++;
        }

        TEST_ASSERT(rcvd >= 10,
                    "Expected at least 10 messages after %d attempts, got %d",
                    MAX_CONSUME_ATTEMPTS, (int)rcvd);
        TEST_SAY("Successfully consumed %d messages\n", (int)rcvd);

        /* Inject %dms delay on the next 3 ShareAcknowledge responses on
         * broker 1 (the only broker in this mock cluster). */
        TEST_SAY(
            "Injecting %dms delay on the next 3 ShareAcknowledge "
            "responses on broker 1\n",
            broker_delay_ms);
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        mcluster, 1, RD_KAFKAP_ShareAcknowledge, 3,
                        RD_KAFKA_RESP_ERR_NO_ERROR, broker_delay_ms,
                        RD_KAFKA_RESP_ERR_NO_ERROR, broker_delay_ms,
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                        broker_delay_ms) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to inject ShareAcknowledge delay");

        /* Step 1: Acknowledge first 2 messages and commit async */
        TEST_SAY(
            "Step 1: Acknowledging messages 0-1 and calling commit_async\n");
        ack_range_logged(rkshare, rkmessages, 0, 2, (int)rcvd);
        /* The below call should keep the broker busy */
        rd_kafka_share_commit_async(rkshare);

        /* Step 2: Acknowledge next 4 messages and commit async */
        TEST_SAY(
            "Step 2: Acknowledging messages 2-5 and calling commit_async "
            "(should cache)\n");
        ack_range_logged(rkshare, rkmessages, 2, 6, (int)rcvd);
        rd_kafka_share_commit_async(rkshare);

        /* Step 3: Acknowledge next 4 messages and commit sync */
        TEST_SAY(
            "Step 3: Acknowledging messages 6-9 and calling "
            "commit_sync (should cache)\n");
        ack_range_logged(rkshare, rkmessages, 6, 10, (int)rcvd);

        rd_kafka_share_commit_sync(rkshare, 1000, &commit_result);
        TEST_ASSERT(commit_result != NULL,
                    "Expected non-NULL commit_sync result");
        TEST_SAY("commit_sync returned %d partition result(s)\n",
                 commit_result->cnt);
        for (i = 0; i < commit_result->cnt; i++) {
                rd_kafka_topic_partition_t *p = &commit_result->elems[i];
                TEST_SAY("  result[%d] %s [%" PRId32 "] err=%s\n", i, p->topic,
                         p->partition, rd_kafka_err2str(p->err));
                TEST_ASSERT(p->err == RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
                            "Expected REQUEST_TIMED_OUT for %s [%" PRId32
                            "], got %s",
                            p->topic, p->partition, rd_kafka_err2str(p->err));
        }
        rd_kafka_topic_partition_list_destroy(commit_result);

        /* Destroy all consumed messages */
        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;

        TEST_SAY("Calling destroy with flags 0x%x\n", destroy_flags);
        t_start = test_clock();
        destroy_share_consumer(rkshare, destroy_flags);
        t_elapsed_ms = (test_clock() - t_start) / 1000;
        TEST_SAY("Destroy completed in %" PRId64 " ms\n", t_elapsed_ms);

        if (destroy_flags & RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE) {
                /* NO_CONSUMER_CLOSE: destroy must NOT wait for the
                 * delayed broker. */
                TEST_ASSERT(t_elapsed_ms < 2000,
                            "Destroy(NO_CONSUMER_CLOSE) took %" PRId64
                            " ms, expected < 2000 ms",
                            t_elapsed_ms);
                verify_ack_receipts(&receipts, NULL, 0,
                                    "cached-acks NO_CONSUMER_CLOSE");
        } else {
                /* Full close: destroy waits for the existing commit
                 * async request and the session-leave request. Expect
                 * roughly 2 * broker_delay_ms plus small overhead. */
                int64_t expected_max_ms = 2 * broker_delay_ms + 2000;
                TEST_ASSERT(t_elapsed_ms <= expected_max_ms,
                            "Destroy took %" PRId64 " ms, expected <= %" PRId64
                            " ms",
                            t_elapsed_ms, expected_max_ms);
                expected_ack_t expected[] = {
                    {topic, 0, RD_KAFKA_RESP_ERR_NO_ERROR, 10},
                };
                verify_ack_receipts(&receipts, expected, 1,
                                    "cached-acks full close");
        }

        ack_receipts_destroy(&receipts);

        test_mock_cluster_destroy(mcluster);
        SUB_TEST_PASS();
}

/**
 * @brief Stage a deterministic broker decommission so the next request
 *        sent to \p target_broker_id (on ApiKey \p blocked_api_key) is
 *        stamped with __DESTROY_BROKER.
 *
 *        Caller invariants when calling this:
 *          - Cluster has at least target_broker_id and surviving_broker_id.
 *          - target_partition's leader in the mock is target_broker_id.
 *          - No \p blocked_api_key request is currently in flight to
 *            target_broker_id (the injected delay is consumed by the
 *            NEXT one).
 *
 *        After this returns:
 *          - Mock state has target_partition's leader migrated to
 *            surviving_broker_id and target_broker_id removed from
 *            metadata.
 *          - A 2s delay is queued on the next MetadataResponse from
 *            BOTH brokers — the client has NOT yet observed the
 *            topology change.
 *          - A long (30s) delay is queued on the next
 *            blocked_api_key response from target_broker_id.
 *          - We've slept past one refresh tick, so the periodic
 *            MetadataRequest is in flight (held by the mock).
 *
 *        Now when the caller invokes the action under test (which
 *        will ship a blocked_api_key request to target_broker_id),
 *        the timeline is:
 *          - The request lands on target_broker_id and parks (30s).
 *          - The held MetadataResponse fires (2s in), the client
 *            sees target_broker_id is gone, runs
 *            rd_kafka_broker_decommission(target_broker_id).
 *          - target_broker_id's termination path runs
 *            bufq_timeout_scan over its outbufs/waitresps and stamps
 *            the parked request with __DESTROY_BROKER.
 *
 *        Implementation detail: the Metadata RTT injection only takes
 *        effect because of the rd_kafka_mock_next_request_error() call
 *        we added to the Metadata handler in rdkafka_mock_handlers.c.
 *        Without that call, the mock ignores Metadata RTT injections.
 */
static void stage_broker_decommission(rd_kafka_mock_cluster_t *mcluster,
                                      const char *topic,
                                      int32_t target_partition,
                                      int32_t target_broker_id,
                                      int32_t surviving_broker_id,
                                      int16_t blocked_api_key) {
        const int metadata_delay_ms    = 2000;
        const int blocked_api_delay_ms = 30000;
        const int refresh_settle_ms    = 700; /* > 500ms refresh interval */

        TEST_SAY("Staging decommission: target broker=%" PRId32
                 ", surviving broker=%" PRId32 ", target partition=%" PRId32
                 ", blocked ApiKey=%hd\n",
                 target_broker_id, surviving_broker_id, target_partition,
                 blocked_api_key);

        /* Delay metadata responses from both brokers so the client
         * doesn't observe the topology change until AFTER the caller's
         * action has shipped its request to the target broker. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, target_broker_id, RD_KAFKAP_Metadata, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, metadata_delay_ms);
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, surviving_broker_id, RD_KAFKAP_Metadata, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, metadata_delay_ms);

        /* Delay the blocked-API response on the target broker so the
         * caller's request stays parked until decommission fires. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, target_broker_id, blocked_api_key, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, blocked_api_delay_ms);

        /* Migrate the target partition's leader, then remove the
         * target broker from metadata. Target broker's TCP connections
         * stay alive; in-flight requests remain parked. */
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(
                        mcluster, topic, target_partition,
                        surviving_broker_id) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to migrate partition %" PRId32 " leader",
                    target_partition);
        TEST_ASSERT(rd_kafka_mock_broker_remove_from_metadata(
                        mcluster, target_broker_id) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to remove broker %" PRId32 " from metadata",
                    target_broker_id);

        /* Sleep past one refresh tick so the next periodic refresh
         * fires (and parks behind the metadata delay we just injected). */
        rd_usleep(refresh_settle_ms * 1000, NULL);
}

/**
 * @brief Test that commit_sync returns __DESTROY_BROKER for partitions
 *        whose broker is decommissioned mid-flight.
 *
 *        Setup: 2-broker mock cluster, 2-partition topic with p0 led
 *        by broker 1 and p1 led by broker 2.
 *
 *        Flow:
 *          1. Drain both partitions. The last batch's partition tells
 *             us which broker is currently holding unacked records —
 *             that's the broker we'll decommission.
 *          2. Inject a 2s delay on the target broker's NEXT
 *             MetadataResponse.
 *          3. Synchronously update mock state: migrate target
 *             partition's leader to the surviving broker, and remove
 *             the target broker from metadata. Connection stays alive.
 *          4. Sleep > topic.metadata.refresh.interval.ms (500ms) so the
 *             periodic refresh tick fires and queues a MetadataRequest
 *             on some broker. If it lands on the target broker, the
 *             request sits in front of any subsequent ShareAck on the
 *             same connection (response is held 2s by the injection).
 *             If it lands on the surviving broker, the response comes
 *             back quickly. Either way, the parsed response sees the
 *             target broker missing and fires
 *             rd_kafka_broker_decommission() against it.
 *          5. commit_sync ships the unacked batch's ShareAck to the
 *             target broker. The decommission's OP_TERMINATE handler
 *             stamps the in-flight ShareAck with __DESTROY_BROKER.
 *
 *        Assertion: commit_sync result has 1 entry for the target
 *        partition with err == __DESTROY_BROKER.
 */
static void test_broker_decommission_with_commit_sync(int destroy_flags,
                                                      rd_bool_t explicit_ack) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *rkmessages         = NULL;
        rd_kafka_topic_partition_list_t *result = NULL;
        const char *topic;
        const char *group           = "0179-decommission-commit-sync";
        int32_t target_broker_id    = -1;
        int32_t surviving_broker_id = -1;
        int32_t target_partition    = -1;
        size_t rcvd                 = 0;
        int attempts                = 0;
        int i;

        SUB_TEST_QUICK("destroy_flags=0x%x ack_mode=%s", destroy_flags,
                       explicit_ack ? "explicit" : "implicit");

        /* Suppress expected __TRANSPORT / __ALL_BROKERS_DOWN errors that
         * fire when the target broker connection is dropped. */
        test_curr->is_fatal_cb = decommission_is_fatal_cb;

        /* 2-broker mock cluster */
        mcluster = test_mock_cluster_new(2, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        /* 2-partition topic: p0 led by broker 1, p1 led by broker 2.
         * Consuming + acking from both partitions establishes UP
         * connections to both brokers. */
        topic = test_mk_topic_name("0179-decommission-commit-sync", 1);
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 2, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set partition 0 leader to broker 1");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set partition 1 leader to broker 2");

        /* Produce TEST_MSGS/2 messages to each partition. */
        TEST_SAY("Producing %d messages to each partition of topic %s\n",
                 TEST_MSGS / 2, topic);
        test_produce_msgs_easy_v(topic, 0, 0, 0, TEST_MSGS / 2, 16,
                                 "bootstrap.servers", bootstraps, NULL);
        test_produce_msgs_easy_v(topic, 0, 1, 0, TEST_MSGS / 2, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        TEST_SAY("Creating share consumer (%s ack)\n",
                 explicit_ack ? "explicit" : "implicit");
        rkshare = new_share_consumer_for_mock_test(bootstraps, group,
                                                   explicit_ack, NULL);
        subscribe_topics(rkshare, &topic, 1);

        TEST_SAY("Consuming up to %d messages (max %d attempts)\n", TEST_MSGS,
                 MAX_CONSUME_ATTEMPTS);
        while (rcvd < TEST_MSGS && attempts < MAX_CONSUME_ATTEMPTS) {
                size_t batch_rcvd;

                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);

                if (error) {
                        TEST_SAY("Attempt %d: consume error: %s\n", attempts,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        attempts++;
                        continue;
                }

                batch_rcvd = rd_kafka_messages_count(rkmessages);
                if (batch_rcvd > 0) {
                        TEST_SAY("Attempt %d: consumed %d messages\n", attempts,
                                 (int)batch_rcvd);
                        rcvd += batch_rcvd;

                        if (explicit_ack) {
                                size_t k;
                                for (k = 0; k < batch_rcvd; k++) {
                                        rd_kafka_message_t *rkm =
                                            rd_kafka_messages_get(rkmessages,
                                                                  k);
                                        if (rkm)
                                                rd_kafka_share_acknowledge(
                                                    rkshare, rkm);
                                }
                        }
                }
                attempts++;
        }
        TEST_ASSERT(rcvd == TEST_MSGS,
                    "Expected %d messages, got %d after %d attempts", TEST_MSGS,
                    (int)rcvd, attempts);
        TEST_SAY("Consumed %d msgs total in %d attempts\n", (int)rcvd,
                 attempts);

        /* The last message of the last batch tells us which broker
         * holds the unacked records that commit_sync will ship to. */
        {
                size_t _last_cnt = rd_kafka_messages_count(rkmessages);
                rd_kafka_message_t *_last_rkm =
                    _last_cnt > 0
                        ? rd_kafka_messages_get(rkmessages, _last_cnt - 1)
                        : NULL;
                TEST_ASSERT(_last_rkm != NULL,
                            "Expected last batch to be non-empty");
                target_partition = _last_rkm->partition;
        }
        target_broker_id    = (target_partition == 0) ? 1 : 2;
        surviving_broker_id = (target_broker_id == 1) ? 2 : 1;
        TEST_SAY("Target partition = %" PRId32 ", target broker = %" PRId32
                 ", surviving broker = %" PRId32 "\n",
                 target_partition, target_broker_id, surviving_broker_id);

        stage_broker_decommission(mcluster, topic, target_partition,
                                  target_broker_id, surviving_broker_id,
                                  RD_KAFKAP_ShareAcknowledge);

        TEST_SAY("Calling commit_sync (timeout 60s)\n");
        error = rd_kafka_share_commit_sync(rkshare, 60000, &result);

        if (error) {
                TEST_SAY("commit_sync returned error: %s\n",
                         rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
        }

        TEST_ASSERT(result != NULL,
                    "Expected commit_sync to return a non-NULL results list");
        TEST_SAY("commit_sync returned %d partition result(s)\n", result->cnt);

        /* Only the last batch's acks reach commit_sync, so we expect
         * exactly one partition result: the target partition. */
        TEST_ASSERT(result->cnt == 1,
                    "Expected 1 partition result (partition %" PRId32
                    " only), got %d",
                    target_partition, result->cnt);

        for (i = 0; i < result->cnt; i++) {
                rd_kafka_topic_partition_t *p = &result->elems[i];
                TEST_SAY("  result[%d] %s [%" PRId32 "] err=%s\n", i, p->topic,
                         p->partition, rd_kafka_err2str(p->err));
                TEST_ASSERT(p->partition == target_partition,
                            "Expected partition %" PRId32
                            " in result, got %" PRId32,
                            target_partition, p->partition);
                /* __DESTROY_BROKER from the broker-thread decommission
                 * path is translated to __TRANSPORT at the app-facing
                 * funnel (rd_kafka_share_commit_sync_apply_result), to
                 * match the Java NetworkException/DisconnectException
                 * terminal surface. */
                TEST_ASSERT(p->err == RD_KAFKA_RESP_ERR__TRANSPORT,
                            "Expected __TRANSPORT for partition %" PRId32
                            " (broker %" PRId32 ", decommissioned), got %s",
                            target_partition, target_broker_id,
                            rd_kafka_err2str(p->err));
        }

        rd_kafka_topic_partition_list_destroy(result);

        /* Cleanup */
        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;

        destroy_share_consumer(rkshare, destroy_flags);
        test_mock_cluster_destroy(mcluster);

        /* Restore the default fatal-error handler. */
        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}


/**
 * @brief Test that a broker decommissioned while a piggybacked
 *        ShareAck is in flight is handled gracefully: no app-visible
 *        error surfaces from consume_batch.
 *
 *        Setup mirrors test_broker_decommission_with_commit_sync —
 *        2-broker mock cluster, 2-partition topic with RF=2, drain
 *        both partitions in implicit-ack mode. The last batch's
 *        records stay ACQUIRED on whichever broker served them
 *        (target broker, picked dynamically from the last batch's
 *        partition). The next consume_batch piggybacks an implicit
 *        ShareAck onto a ShareFetch sent to the target broker — that
 *        request is what we want stamped __DESTROY_BROKER.
 *
 *        After staging the decommission, we call consume_batch again.
 *        The fanout sends ShareFetch (with piggybacked ack) to the
 *        target broker — parked behind the injected ShareAck delay.
 *        When the metadata response triggers the decommission, the
 *        parked request is stamped __DESTROY_BROKER via
 *        bufq_timeout_scan. consume_batch returns no error and no
 *        messages.
 */
static void test_broker_decommission_with_consume_batch(int destroy_flags) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *rkmessages = NULL;
        const char *topic;
        const char *group           = "0179-decommission-consume-batch";
        int32_t target_broker_id    = -1;
        int32_t surviving_broker_id = -1;
        int32_t target_partition    = -1;
        size_t rcvd                 = 0;
        size_t fetch_rcvd           = 0;
        int attempts                = 0;
        int32_t surviving_part;
        expected_ack_t expected[2];
        ack_receipts_t receipts;

        ack_receipts_init(&receipts);

        SUB_TEST_QUICK();

        /* Suppress expected __TRANSPORT / __ALL_BROKERS_DOWN errors that
         * fire when the target broker connection is dropped. */
        test_curr->is_fatal_cb = decommission_is_fatal_cb;

        /* 2-broker mock cluster */
        mcluster = test_mock_cluster_new(2, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        /* 2-partition topic, RF=2: p0 led by broker 1, p1 led by broker 2. */
        topic = test_mk_topic_name("0179-decommission-consume-batch", 1);
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 2, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set partition 0 leader to broker 1");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set partition 1 leader to broker 2");

        /* Produce TEST_MSGS/2 messages to each partition. */
        TEST_SAY("Producing %d messages to each partition of topic %s\n",
                 TEST_MSGS / 2, topic);
        test_produce_msgs_easy_v(topic, 0, 0, 0, TEST_MSGS / 2, 16,
                                 "bootstrap.servers", bootstraps, NULL);
        test_produce_msgs_easy_v(topic, 0, 1, 0, TEST_MSGS / 2, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        TEST_SAY("Creating share consumer (implicit ack) with ack_cb\n");
        rkshare = new_share_consumer_for_mock_test(bootstraps, group, rd_false,
                                                   &receipts);
        subscribe_topics(rkshare, &topic, 1);

        /* Drain both partitions in implicit-ack mode. No trailing-empty
         * flush — the last batch's records stay ACQUIRED on whichever
         * broker served them. */
        TEST_SAY("Consuming up to %d messages (max %d attempts)\n", TEST_MSGS,
                 MAX_CONSUME_ATTEMPTS);
        while (rcvd < TEST_MSGS && attempts < MAX_CONSUME_ATTEMPTS) {
                size_t batch_rcvd;

                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);

                if (error) {
                        TEST_SAY("Attempt %d: consume error: %s\n", attempts,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        attempts++;
                        continue;
                }

                batch_rcvd = rd_kafka_messages_count(rkmessages);
                if (batch_rcvd > 0) {
                        TEST_SAY("Attempt %d: consumed %d messages\n", attempts,
                                 (int)batch_rcvd);
                        rcvd += batch_rcvd;
                }
                attempts++;
        }
        TEST_ASSERT(rcvd == TEST_MSGS,
                    "Expected %d messages, got %d after %d attempts", TEST_MSGS,
                    (int)rcvd, attempts);
        TEST_SAY("Consumed %d msgs total in %d attempts\n", (int)rcvd,
                 attempts);

        /* The last message of the last batch tells us which broker
         * holds the unacked records — that's the broker the next
         * consume_batch's piggybacked ShareAck will target. */
        {
                size_t _last_cnt = rd_kafka_messages_count(rkmessages);
                rd_kafka_message_t *_last_rkm =
                    _last_cnt > 0
                        ? rd_kafka_messages_get(rkmessages, _last_cnt - 1)
                        : NULL;
                TEST_ASSERT(_last_rkm != NULL,
                            "Expected last batch to be non-empty");
                target_partition = _last_rkm->partition;
        }
        target_broker_id    = (target_partition == 0) ? 1 : 2;
        surviving_broker_id = (target_broker_id == 1) ? 2 : 1;
        TEST_SAY("Target partition = %" PRId32 ", target broker = %" PRId32
                 ", surviving broker = %" PRId32 "\n",
                 target_partition, target_broker_id, surviving_broker_id);

        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;
        rcvd       = 0;

        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, target_broker_id, RD_KAFKAP_ShareFetch, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, 30000);

        stage_broker_decommission(mcluster, topic, target_partition,
                                  target_broker_id, surviving_broker_id,
                                  RD_KAFKAP_ShareAcknowledge);

        /* Call consume_batch — whichever request lands on the target
         * broker (ShareFetch with piggybacked ack OR standalone
         * ShareAcknowledge) parks behind its injected delay; when the
         * metadata response triggers the decommission, the parked
         * request is stamped __DESTROY_BROKER. The surviving broker
         * has no new messages, so consume_batch times out cleanly
         * with 0 messages and no app-visible error. */
        TEST_SAY(
            "Calling consume_batch — expecting no messages and no "
            "app-visible error\n");
        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;
        error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);
        fetch_rcvd = rd_kafka_messages_count(rkmessages);

        TEST_ASSERT(error == NULL,
                    "Expected consume_batch to return NULL error, got %s",
                    error ? rd_kafka_error_string(error) : "(null)");
        TEST_ASSERT(fetch_rcvd == 0,
                    "Expected 0 messages from consume_batch (target broker "
                    "decommissioned, surviving broker has no new "
                    "messages), got %d",
                    (int)fetch_rcvd);

        drain_ack_callbacks(rkshare);

        /* Assert ack callback receipts.
         *
         *   Drain loop: each batch from the SURVIVING partition gets
         *   implicitly acked when the next ShareFetch on the surviving
         *   broker piggybacks the ack — those records appear in the
         *   callback with NO_ERROR. The TARGET partition's last batch
         *   stays ACQUIRED (no further piggyback happens on that
         *   broker before we stage the decommission).
         *
         *   Second consume_batch: the piggybacked ShareAck for the
         *   target partition's ACQUIRED batch parks on the target
         *   broker and gets stamped __DESTROY_BROKER when the
         *   decommission fires; __DESTROY_BROKER is translated to
         *   __TRANSPORT at the app-facing funnel.
         *
         *   surviving_partition: TEST_MSGS/2 offsets, NO_ERROR
         *   target_partition:    TEST_MSGS/2 offsets, __TRANSPORT */
        surviving_part = (target_partition == 0) ? 1 : 0;
        expected[0]    = (expected_ack_t) {
            topic, surviving_part, RD_KAFKA_RESP_ERR_NO_ERROR, TEST_MSGS / 2};
        expected[1] =
            (expected_ack_t) {topic, target_partition,
                              RD_KAFKA_RESP_ERR__TRANSPORT, TEST_MSGS / 2};
        verify_ack_receipts(&receipts, expected, 2, "consume_batch");

        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;

        destroy_share_consumer(rkshare, destroy_flags);
        test_mock_cluster_destroy(mcluster);

        ack_receipts_destroy(&receipts);

        /* Restore the default fatal-error handler. */
        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}


/**
 * @brief Test that rd_kafka_share_consumer_close() completes gracefully
 *        when one of the brokers it ships acks/leaves to is decommissioned
 *        mid-call.
 *
 *        Setup mirrors test_broker_decommission_with_commit_sync —
 *        2-broker mock cluster, 2-partition topic with RF=2, fast
 *        metadata refresh. close() will then ship a ShareAck
 *        for those records to whichever broker served them,
 *        plus session-leave requests to both brokers.
 *
 *        The target broker (the one holding the unacked batch) gets a
 *        5s ShareAck rtt delay. While that ShareAck is parked, the
 *        background thread removes the broker from mock metadata; the
 *        client decommissions it; the in-flight ShareAck is purged
 *        with __DESTROY_BROKER.
 *
 *        Expectation: rd_kafka_share_consumer_close() returns NULL (no
 *        error) and does not hang. destroy() afterwards also completes.
 */
static void test_broker_decommission_during_close(int destroy_flags,
                                                  rd_bool_t explicit_ack) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *rkmessages = NULL;
        const char *topic;
        const char *group           = "0179-decommission-close";
        int32_t target_broker_id    = -1;
        int32_t surviving_broker_id = -1;
        int32_t target_partition    = -1;
        size_t rcvd                 = 0;
        int attempts                = 0;
        int32_t surviving_part;
        expected_ack_t expected[2];
        ack_receipts_t receipts;

        ack_receipts_init(&receipts);

        SUB_TEST_QUICK("destroy_flags=0x%x ack_mode=%s", destroy_flags,
                       explicit_ack ? "explicit" : "implicit");

        /* Suppress expected __TRANSPORT / __ALL_BROKERS_DOWN errors that
         * fire when the target broker connection is dropped. */
        test_curr->is_fatal_cb = decommission_is_fatal_cb;

        /* 2-broker mock cluster */
        mcluster = test_mock_cluster_new(2, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        /* 2-partition topic, RF=2: p0 led by broker 1, p1 led by broker 2. */
        topic = test_mk_topic_name("0179-decommission-close", 1);
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 2, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set partition 0 leader to broker 1");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set partition 1 leader to broker 2");

        /* Produce TEST_MSGS/2 messages to each partition. */
        TEST_SAY("Producing %d messages to each partition of topic %s\n",
                 TEST_MSGS / 2, topic);
        test_produce_msgs_easy_v(topic, 0, 0, 0, TEST_MSGS / 2, 16,
                                 "bootstrap.servers", bootstraps, NULL);
        test_produce_msgs_easy_v(topic, 0, 1, 0, TEST_MSGS / 2, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        TEST_SAY("Creating share consumer (%s ack)\n",
                 explicit_ack ? "explicit" : "implicit");
        rkshare = new_share_consumer_for_mock_test(bootstraps, group,
                                                   explicit_ack, &receipts);
        subscribe_topics(rkshare, &topic, 1);

        /* Drain both partitions WITHOUT a trailing empty flush — the
         * last batch's records remain ACQUIRED (unacked). close() will
         * ship a ShareAck for those records to whichever broker served
         * them. */
        TEST_SAY("Consuming up to %d messages (max %d attempts)\n", TEST_MSGS,
                 MAX_CONSUME_ATTEMPTS);
        while (rcvd < TEST_MSGS && attempts < MAX_CONSUME_ATTEMPTS) {
                size_t batch_rcvd;

                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);

                if (error) {
                        TEST_SAY("Attempt %d: consume error: %s\n", attempts,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        attempts++;
                        continue;
                }

                batch_rcvd = rd_kafka_messages_count(rkmessages);
                if (batch_rcvd > 0) {
                        TEST_SAY("Attempt %d: consumed %d messages\n", attempts,
                                 (int)batch_rcvd);
                        rcvd += batch_rcvd;

                        if (explicit_ack) {
                                size_t k;
                                for (k = 0; k < batch_rcvd; k++) {
                                        rd_kafka_message_t *rkm =
                                            rd_kafka_messages_get(rkmessages,
                                                                  k);
                                        if (rkm)
                                                rd_kafka_share_acknowledge(
                                                    rkshare, rkm);
                                }
                        }
                }
                attempts++;
        }
        TEST_ASSERT(rcvd == TEST_MSGS,
                    "Expected %d messages, got %d after %d attempts", TEST_MSGS,
                    (int)rcvd, attempts);
        TEST_SAY("Consumed %d msgs total in %d attempts\n", (int)rcvd,
                 attempts);

        drain_ack_callbacks(rkshare);
        /* The last message of the last batch tells us which broker
         * holds the unacked records — that's the broker close()'s
         * ShareAck will target. Decommission that broker; the other
         * survives. */
        {
                size_t _last_cnt = rd_kafka_messages_count(rkmessages);
                rd_kafka_message_t *_last_rkm =
                    _last_cnt > 0
                        ? rd_kafka_messages_get(rkmessages, _last_cnt - 1)
                        : NULL;
                TEST_ASSERT(_last_rkm != NULL,
                            "Expected last batch to be non-empty");
                target_partition = _last_rkm->partition;
        }
        target_broker_id    = (target_partition == 0) ? 1 : 2;
        surviving_broker_id = (target_broker_id == 1) ? 2 : 1;
        TEST_SAY("Target partition = %" PRId32 ", target broker = %" PRId32
                 ", surviving broker = %" PRId32 "\n",
                 target_partition, target_broker_id, surviving_broker_id);

        stage_broker_decommission(mcluster, topic, target_partition,
                                  target_broker_id, surviving_broker_id,
                                  RD_KAFKAP_ShareAcknowledge);

        /* Call close(). It ships a ShareAck session leave
         * request for the unacked batch to the target broker.
         * The target broker's ShareAck is stamped __DESTROY_BROKER
         * when the decommission fires; close() must not surface this to the
         * app. */
        TEST_SAY(
            "Calling rd_kafka_share_consumer_close() — expecting "
            "NULL error\n");
        error = rd_kafka_share_consumer_close(rkshare);

        TEST_ASSERT(error == NULL,
                    "Expected close() to return NULL error, got %s",
                    error ? rd_kafka_error_string(error) : "(null)");

        /* Assert ack callback receipts.
         *
         * The first batch on each broker was piggyback-acked on the
         * next ShareFetch during drain — those records appear in the
         * callback with NO_ERROR. The LAST batch on each broker is
         * still ACQUIRED at close time; close ships those acks
         * differently in implicit vs explicit mode:
         *
         * Implicit ack: the close path only flushes already-converted
         * (non-ACQUIRED) entries. ACQUIRED records on the last batch
         * are silently dropped — no ShareAck for them goes on the
         * wire, so no callback fires for target_partition's last
         * batch (which would have been stamped __DESTROY_BROKER).
         * Expectation: only surviving_partition NO_ERROR.
         *
         * Explicit ack: the drain loop explicitly acked every record.
         * Those explicit acks are queued and shipped during close.
         * The target broker's ack request parks behind the injected
         * delay; when the decommission fires, the parked request is
         * stamped __DESTROY_BROKER, which the app-facing funnel
         * translates to __TRANSPORT before the callback fires.
         * surviving_partition records that weren't piggyback-acked
         * during drain are also shipped at close and succeed with
         * NO_ERROR.
         */
        surviving_part = (target_partition == 0) ? 1 : 0;
        expected[0]    = (expected_ack_t) {
            topic, surviving_part, RD_KAFKA_RESP_ERR_NO_ERROR, TEST_MSGS / 2};
        if (explicit_ack) {
                expected[1] = (expected_ack_t) {topic, target_partition,
                                                RD_KAFKA_RESP_ERR__TRANSPORT,
                                                TEST_MSGS / 2};
                verify_ack_receipts(&receipts, expected, 2, "close explicit");
        } else {
                verify_ack_receipts(&receipts, expected, 1, "close implicit");
        }

        /* Cleanup */
        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;

        destroy_share_consumer(rkshare, destroy_flags);
        test_mock_cluster_destroy(mcluster);

        ack_receipts_destroy(&receipts);

        /* Restore the default fatal-error handler. */
        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}


/**
 * @brief Test that rd_kafka_share_commit_async() does not hang when the
 *        broker it ships acks to is decommissioned mid-flight.
 *
 *        Setup mirrors test_broker_decommission_during_close — drain both
 *        partitions without a trailing flush so the last batch's records
 *        stay ACQUIRED. commit_async() then ships a ShareAck for those
 *        records to whichever broker served them. The target broker has a
 *        5s ShareAck rtt delay; while the request is parked, the
 *        background thread removes the broker from mock metadata and the
 *        client decommissions it, purging the in-flight ShareAck with
 *        __DESTROY_BROKER.
 *
 *        Expectation: rd_kafka_share_commit_async() returns NULL (no
 *        error) and does not block on the in-flight ack.
 *        destroy() afterwards completes cleanly.
 */
static void test_broker_decommission_with_commit_async(int destroy_flags,
                                                       rd_bool_t explicit_ack) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *rkmessages = NULL;
        const char *topic;
        const char *group           = "0179-decommission-commit-async";
        int32_t target_broker_id    = -1;
        int32_t surviving_broker_id = -1;
        int32_t target_partition    = -1;
        size_t rcvd                 = 0;
        int attempts                = 0;
        int32_t surviving_part;
        expected_ack_t expected[2];
        ack_receipts_t receipts;

        ack_receipts_init(&receipts);

        SUB_TEST_QUICK("destroy_flags=0x%x ack_mode=%s", destroy_flags,
                       explicit_ack ? "explicit" : "implicit");

        /* Suppress expected __TRANSPORT / __ALL_BROKERS_DOWN errors that
         * fire when the target broker connection is dropped. */
        test_curr->is_fatal_cb = decommission_is_fatal_cb;

        /* 2-broker mock cluster */
        mcluster = test_mock_cluster_new(2, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        /* 2-partition topic, RF=2: p0 led by broker 1, p1 led by broker 2. */
        topic = test_mk_topic_name("0179-decommission-commit-async", 1);
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 2, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set partition 0 leader to broker 1");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set partition 1 leader to broker 2");

        /* Produce TEST_MSGS/2 messages to each partition. */
        TEST_SAY("Producing %d messages to each partition of topic %s\n",
                 TEST_MSGS / 2, topic);
        test_produce_msgs_easy_v(topic, 0, 0, 0, TEST_MSGS / 2, 16,
                                 "bootstrap.servers", bootstraps, NULL);
        test_produce_msgs_easy_v(topic, 0, 1, 0, TEST_MSGS / 2, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        /* Implicit-ack share consumer with fast metadata refresh so the
         * client picks up the target broker's removal during the 5s
         * ShareAck delay. */
        TEST_SAY("Creating share consumer (%s ack) with ack_cb\n",
                 explicit_ack ? "explicit" : "implicit");
        rkshare = new_share_consumer_for_mock_test(bootstraps, group,
                                                   explicit_ack, &receipts);
        subscribe_topics(rkshare, &topic, 1);

        /* Drain both partitions WITHOUT a trailing empty flush — the
         * last batch's records remain ACQUIRED (unacked).
         * commit_async() will ship a ShareAck for those records to
         * whichever broker served them. */
        TEST_SAY("Consuming up to %d messages (max %d attempts)\n", TEST_MSGS,
                 MAX_CONSUME_ATTEMPTS);
        while (rcvd < TEST_MSGS && attempts < MAX_CONSUME_ATTEMPTS) {
                size_t batch_rcvd;

                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);

                if (error) {
                        TEST_SAY("Attempt %d: consume error: %s\n", attempts,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        attempts++;
                        continue;
                }

                batch_rcvd = rd_kafka_messages_count(rkmessages);
                if (batch_rcvd > 0) {
                        TEST_SAY("Attempt %d: consumed %d messages\n", attempts,
                                 (int)batch_rcvd);
                        rcvd += batch_rcvd;

                        if (explicit_ack) {
                                size_t k;
                                for (k = 0; k < batch_rcvd; k++) {
                                        rd_kafka_message_t *rkm =
                                            rd_kafka_messages_get(rkmessages,
                                                                  k);
                                        if (rkm)
                                                rd_kafka_share_acknowledge(
                                                    rkshare, rkm);
                                }
                        }
                }
                attempts++;
        }
        TEST_ASSERT(rcvd == TEST_MSGS,
                    "Expected %d messages, got %d after %d attempts", TEST_MSGS,
                    (int)rcvd, attempts);
        TEST_SAY("Consumed %d msgs total in %d attempts\n", (int)rcvd,
                 attempts);

        drain_ack_callbacks(rkshare);
        /* The last message of the last batch tells us which broker
         * holds the unacked records — that's the broker the
         * commit_async ShareAck will target. Decommission that broker;
         * the other survives. */
        {
                size_t _last_cnt = rd_kafka_messages_count(rkmessages);
                rd_kafka_message_t *_last_rkm =
                    _last_cnt > 0
                        ? rd_kafka_messages_get(rkmessages, _last_cnt - 1)
                        : NULL;
                TEST_ASSERT(_last_rkm != NULL,
                            "Expected last batch to be non-empty");
                target_partition = _last_rkm->partition;
        }
        target_broker_id    = (target_partition == 0) ? 1 : 2;
        surviving_broker_id = (target_broker_id == 1) ? 2 : 1;
        TEST_SAY("Target partition = %" PRId32 ", target broker = %" PRId32
                 ", surviving broker = %" PRId32 "\n",
                 target_partition, target_broker_id, surviving_broker_id);

        stage_broker_decommission(mcluster, topic, target_partition,
                                  target_broker_id, surviving_broker_id,
                                  RD_KAFKAP_ShareAcknowledge);

        /* Call commit_async(). It should return immediately without
         * blocking on the in-flight ack. The parked ShareAck on the
         * target broker will be stamped __DESTROY_BROKER when the
         * decommission fires shortly after. */
        TEST_SAY(
            "Calling rd_kafka_share_commit_async() — expecting "
            "NULL error and no hang\n");
        error = rd_kafka_share_commit_async(rkshare);

        TEST_ASSERT(error == NULL,
                    "Expected commit_async() to return NULL error, got %s",
                    error ? rd_kafka_error_string(error) : "(null)");

        /* Cleanup messages before destroy. */
        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;

        destroy_share_consumer(rkshare, destroy_flags);
        test_mock_cluster_destroy(mcluster);

        /* Assert ack callback receipts.
         *
         * Full close (destroy_flags=0): destroy waits for in-flight
         * requests. The metadata-driven decommission fires within ~2s,
         * stamping the parked ShareAck with __DESTROY_BROKER.
         *
         * NO_CONSUMER_CLOSE (destroy_flags=0x8): destroy short-
         * circuits without waiting for the parked ShareAck. No
         * callback fires for the target partition's records. Only the
         * surviving partition's ack — which completed before —
         * surfaces. */
        surviving_part = (target_partition == 0) ? 1 : 0;
        expected[0]    = (expected_ack_t) {
            topic, surviving_part, RD_KAFKA_RESP_ERR_NO_ERROR, TEST_MSGS / 2};
        if (destroy_flags & RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE) {
                verify_ack_receipts(&receipts, expected, 1,
                                    "commit_async NO_CONSUMER_CLOSE");
        } else {
                /* __DESTROY_BROKER stamped on parked acks is translated
                 * to __TRANSPORT at the app-facing funnel. */
                expected[1] = (expected_ack_t) {topic, target_partition,
                                                RD_KAFKA_RESP_ERR__TRANSPORT,
                                                TEST_MSGS / 2};
                verify_ack_receipts(&receipts, expected, 2,
                                    "commit_async full close");
        }

        ack_receipts_destroy(&receipts);

        /* Restore the default fatal-error handler. */
        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}

static void test_leader_migration_mid_session_destroy(int destroy_flags) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *rkmessages = NULL;
        const char *topic               = "0179-leader-migration-mid-session";
        const char *group               = "0179-leader-migration-mid-session";
        const int msgs_per_round        = 5;
        size_t rcvd                     = 0;
        int attempts                    = 0;

        SUB_TEST_QUICK("destroy_flags=0x%x", destroy_flags);

        mcluster = test_mock_cluster_new(2, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        /* 1 partition, RF=2 so both brokers know about it. Initial
         * leader = broker 1. */
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 1, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to set initial leader to broker 1");

        /* Produce a first batch so the consumer can fetch from broker 1. */
        TEST_SAY("Producing %d messages to broker 1\n", msgs_per_round);
        test_produce_msgs_easy_v(topic, 0, 0, 0, msgs_per_round, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        rkshare = new_share_consumer_for_mock_test(
            bootstraps, group, rd_false /* implicit */, NULL);
        subscribe_topics(rkshare, &topic, 1);

        /* Round 1: consume from broker 1. After this, the toppar is in
         * broker 1's toppars_in_session. */
        TEST_SAY("Round 1: consume from broker 1 (initial leader)\n");
        while (rcvd < (size_t)msgs_per_round &&
               attempts++ < MAX_CONSUME_ATTEMPTS) {
                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);
                if (error)
                        rd_kafka_error_destroy(error);
                else
                        rcvd += rd_kafka_messages_count(rkmessages);
        }
        TEST_ASSERT(rcvd >= (size_t)msgs_per_round,
                    "Round 1: expected %d msgs, got %d", msgs_per_round,
                    (int)rcvd);
        TEST_SAY("Round 1: consumed %d messages\n", (int)rcvd);

        /* Migrate the partition leader to broker 2. */
        TEST_SAY("Migrating partition leader from broker 1 to broker 2\n");
        TEST_ASSERT(rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to migrate leader to broker 2");

        /* Produce a second batch so the consumer has something to fetch
         * from the new leader. */
        TEST_SAY("Producing %d more messages (now under broker 2)\n",
                 msgs_per_round);
        test_produce_msgs_easy_v(topic, 0, 0, 0, msgs_per_round, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        /* Round 2: consume from broker 2. The first ShareFetch reply
         * from broker 2 will add the toppar into broker
         * 2's toppars_in_session. With the fix, broker 1's list
         * is cleared by PARTITION_LEAVE before this happens. */
        TEST_SAY("Round 2: consume from broker 2 (new leader)\n");
        attempts = 0;
        while (rcvd < (size_t)(2 * msgs_per_round) &&
               attempts++ < MAX_CONSUME_ATTEMPTS) {
                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);
                if (error)
                        rd_kafka_error_destroy(error);
                else
                        rcvd += rd_kafka_messages_count(rkmessages);
        }
        TEST_ASSERT(rcvd >= (size_t)(2 * msgs_per_round),
                    "Round 2: expected %d total msgs, got %d",
                    2 * msgs_per_round, (int)rcvd);
        TEST_SAY("Round 2: consumed %d total messages\n", (int)rcvd);

        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;

        /* Close + destroy. Without the leader-migration fix, broker 1's
         * destroy_final would assert on non-empty toppars_in_session. */
        TEST_SAY("Calling destroy (flags 0x%x)\n", destroy_flags);
        destroy_share_consumer(rkshare, destroy_flags);

        test_mock_cluster_destroy(mcluster);
        SUB_TEST_PASS();
}

/**
 * @brief Destroy while the consumer's cgrp is mid-rebalance.
 *
 * Drives the cgrp into an intermediate join-state by:
 *   1. Subscribing and consuming at least one batch (cgrp now in steady
 *      state with a live assignment).
 *   2. Injecting a long RTT delay on ShareGroupHeartbeat so the next
 *      heartbeat sent by the cgrp will be stuck in-flight.
 *   3. Calling unsubscribe, which drives the cgrp into
 *      wait-unassign-call -> wait-incr-unassign-to-complete and ends up
 *      waiting on the (now-blocked) leave heartbeat.
 *   4. Calling destroy with the given flags. Destroy must NOT wait the
 *      full injected RTT.
 */
static void test_destroy_during_rebalance(int destroy_flags) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *rkmessages = NULL;
        const char *topic               = "0179-destroy-during-rebalance";
        const char *group               = "0179-destroy-during-rebalance";
        const int heartbeat_delay_ms    = 10000;
        size_t rcvd                     = 0;
        int attempts                    = 0;
        rd_ts_t t_start, t_elapsed_ms;

        SUB_TEST_QUICK("destroy_flags=0x%x", destroy_flags);

        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        /* Produce so the consumer's first consume_batch returns a real
         * message, guaranteeing the cgrp reached up/steady with a live
         * assignment. */
        test_produce_msgs_easy_v(topic, 0, 0, 0, 10, 16, "bootstrap.servers",
                                 bootstraps, NULL);

        rkshare = new_share_consumer_for_mock_test(
            bootstraps, group, rd_false /* implicit ack */, NULL);
        subscribe_topics(rkshare, &topic, 1);

        TEST_SAY("Waiting for first batch (signals assignment is live)\n");
        while (rcvd == 0 && attempts++ < MAX_CONSUME_ATTEMPTS) {
                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);
                if (error)
                        rd_kafka_error_destroy(error);
                else
                        rcvd = rd_kafka_messages_count(rkmessages);
        }
        TEST_ASSERT(rcvd > 0,
                    "Expected at least 1 msg before forcing rebalance; "
                    "got %d after %d attempts",
                    (int)rcvd, attempts);
        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;

        /* Block all subsequent ShareGroupHeartbeats. The next heartbeat
         * sent by the cgrp (including the leave-group heartbeat) will be
         * stuck in flight for heartbeat_delay_ms. */
        TEST_SAY("Injecting %dms RTT delay on ShareGroupHeartbeat\n",
                 heartbeat_delay_ms);
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                        heartbeat_delay_ms) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to inject heartbeat delay");

        /* Drive the cgrp into the leave-flow. */
        TEST_SAY("Calling unsubscribe to drive cgrp into wait-incr-unassign\n");
        TEST_ASSERT(!rd_kafka_share_unsubscribe(rkshare), "unsubscribe failed");

        /* Give the cgrp main thread time to process the unsubscribe op
         * and transition into the intermediate join-state. */
        rd_sleep(1);

        TEST_SAY("Calling destroy mid-rebalance (flags 0x%x)\n", destroy_flags);
        t_start = test_clock();
        destroy_share_consumer(rkshare, destroy_flags);
        t_elapsed_ms = (test_clock() - t_start) / 1000;
        TEST_SAY("Destroy completed in %" PRId64 " ms\n", t_elapsed_ms);

        if (destroy_flags & RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE) {
                /* No-close: destroy must skip the cgrp leave flow and
                 * return promptly, regardless of the heartbeat delay. */
                TEST_ASSERT(t_elapsed_ms < 2000,
                            "Destroy(NO_CONSUMER_CLOSE) took %" PRId64
                            " ms, expected < 2000 ms",
                            t_elapsed_ms);
        } else {
                /* Full close: destroy waits for the cgrp to finish its
                 * leave flow, which is blocked on the heartbeat. It must
                 * still complete in roughly heartbeat_delay_ms (plus
                 * small overhead) and never wait indefinitely. */
                TEST_ASSERT(t_elapsed_ms < heartbeat_delay_ms + 5000,
                            "Destroy took %" PRId64 " ms, expected < %d ms",
                            t_elapsed_ms, heartbeat_delay_ms + 5000);
        }

        test_mock_cluster_destroy(mcluster);
        SUB_TEST_PASS();
}

/**
 * @brief Test destroying a share consumer after a fatal error.
 *
 * Drives the consumer to steady state, acks half the consumed batch,
 * then injects a 30s RTT delay on the next ShareAcknowledge so a real
 * close path would have to wait that long. Trigger a fatal error
 * (which causes destroy_app to promote flags to NO_CONSUMER_CLOSE,
 * then call destroy.
 *
 * Destroy must short-circuit the close path and complete promptly
 * regardless of the supplied destroy_flags — the delayed ShareAck
 * never gets sent, and broker threads must exit without waiting.
 *
 * @param destroy_flags Destroy flags (0 or
 *                      RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE). Both
 *                      must complete fast under fatal-error promotion.
 */
static void test_destroy_with_fatal_error(int destroy_flags) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_t *rk;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        rd_kafka_messages_t *rkmessages = NULL;
        const char *topic               = "0179-destroy-fatal-error";
        const char *group               = "0179-destroy-fatal-error";
        const int total_msgs            = 10;
        const int share_ack_delay_ms    = 30000;
        size_t rcvd                     = 0;
        int attempts                    = 0;
        size_t i;
        rd_ts_t t_start, t_elapsed_ms;

        SUB_TEST_QUICK("destroy_flags=0x%x", destroy_flags);

        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to create mock topic");

        test_produce_msgs_easy_v(topic, 0, 0, 0, total_msgs, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        rkshare = new_share_consumer_for_mock_test(
            bootstraps, group, rd_true /* explicit */, NULL);
        rk = test_share_consumer_get_rk(rkshare);
        subscribe_topics(rkshare, &topic, 1);

        TEST_SAY("Consuming %d msgs\n", total_msgs);
        while (rcvd < (size_t)total_msgs && attempts++ < MAX_CONSUME_ATTEMPTS) {
                rd_kafka_messages_destroy(rkmessages);
                rkmessages = NULL;
                error      = rd_kafka_share_poll(rkshare, 3000, &rkmessages);
                if (error)
                        rd_kafka_error_destroy(error);
                else
                        rcvd = rd_kafka_messages_count(rkmessages);
        }
        TEST_ASSERT(rcvd >= (size_t)total_msgs,
                    "Expected %d msgs, got %d after %d attempts", total_msgs,
                    (int)rcvd, attempts);

        TEST_SAY("Acknowledging %d/%d messages (no commit)\n", (int)(rcvd / 2),
                 (int)rcvd);
        for (i = 0; i < rcvd / 2; i++) {
                rd_kafka_message_t *rkm = rd_kafka_messages_get(rkmessages, i);
                if (rkm)
                        rd_kafka_share_acknowledge(rkshare, rkm);
        }

        /* Inject a long delay on the next ShareAcknowledge so a normal
         * close path would block on it. The fatal-error path must NOT
         * wait. */
        TEST_SAY("Injecting %dms RTT delay on ShareAcknowledge\n",
                 share_ack_delay_ms);
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        mcluster, 1, RD_KAFKAP_ShareAcknowledge, 1,
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                        share_ack_delay_ms) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Failed to inject ShareAcknowledge delay");

        TEST_SAY("Injecting fatal error\n");
        err = rd_kafka_test_fatal_error(
            rk, RD_KAFKA_RESP_ERR__FATAL,
            "0179: injected fatal error before destroy");
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "test_fatal_error returned %s", rd_kafka_err2name(err));

        /* Destroy all consumed messages before share_destroy. */
        rd_kafka_messages_destroy(rkmessages);
        rkmessages = NULL;

        TEST_SAY("Calling destroy with flags 0x%x (fatal-error path)\n",
                 destroy_flags);
        t_start = test_clock();
        destroy_share_consumer(rkshare, destroy_flags);
        t_elapsed_ms = (test_clock() - t_start) / 1000;
        TEST_SAY("Destroy completed in %" PRId64 " ms\n", t_elapsed_ms);

        /* Fatal error short-circuits close regardless of supplied flag,
         * so destroy must be prompt and never wait the injected RTT. */
        TEST_ASSERT(t_elapsed_ms < 2000,
                    "Destroy took %" PRId64 " ms, expected < 2000 ms",
                    t_elapsed_ms);

        test_mock_cluster_destroy(mcluster);
        SUB_TEST_PASS();
}


/**
 * @brief Test destroying share consumer with explicit-ack mode.
 *
 * Consumes a batch of messages, explicitly acknowledges some/all of
 * them (no commit), then destroys the consumer. Verifies that destroy
 * handles pending acks correctly.
 *
 * @param destroy_flags Destroy flags (0 or
 *                      RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE).
 * @param ack_half      If true, ack only the first half of the
 *                      consumed batch (the rest are left unacked). If
 *                      false, ack the full batch.
 */
static void do_test_destroy_with_explicit_ack(int destroy_flags,
                                              rd_bool_t ack_half) {
        const char *topic;
        const char *group = "0179-destroy-explicit-ack";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *first_batch  = NULL;
        rd_kafka_messages_t *second_batch = NULL;
        size_t rcvd                       = 0;
        size_t first_batch_cnt            = 0;
        int32_t first_batch_part          = -1;
        int32_t second_batch_part         = -1;
        int attempts                      = 0;
        int ack_cnt;
        expected_ack_t expected[2];
        int second_part_cnt;
        ack_receipts_t receipts;

        ack_receipts_init(&receipts);

        SUB_TEST("destroy_flags=0x%x ack_half=%s", destroy_flags,
                 ack_half ? "true" : "false");

        topic = test_mk_topic_name("0179-destroy-explicit-ack", 1);
        TEST_SAY("Creating 2-partition topic %s\n", topic);
        test_create_topic_wait_exists(common_admin, topic, 2, -1, 60 * 1000);

        TEST_SAY("Producing %d messages to each partition of topic %s\n",
                 TEST_MSGS / 2, topic);
        test_produce_msgs_simple(common_producer, topic, 0, TEST_MSGS / 2);
        test_produce_msgs_simple(common_producer, topic, 1, TEST_MSGS / 2);

        test_share_set_auto_offset_reset(group, "earliest");

        TEST_SAY("Creating share consumer (explicit ack mode) with ack_cb\n");
        rkshare =
            new_share_consumer_for_real_test(group, "explicit", &receipts);
        subscribe_topics(rkshare, &topic, 1);

        /* Consume + ack loop. Explicit ack mode requires acking the
         * prior batch before the next consume_batch (otherwise it
         * errors), so we ack inside the loop.
         *
         * 2-partition setup with TEST_MSGS/2 per partition: each
         * non-empty consume_batch returns one partition's full
         * payload (TEST_MSGS/2 records). The 1st non-empty batch is
         * always acked in full; we break out once we've consumed all
         * TEST_MSGS records (i.e., after the 2nd batch arrives —
         * which we then ack outside the loop based on ack_half). */
        TEST_SAY("Consuming %d messages (up to %d attempts)\n", TEST_MSGS,
                 MAX_CONSUME_ATTEMPTS);
        while (rcvd < TEST_MSGS && attempts < MAX_CONSUME_ATTEMPTS) {
                rd_kafka_messages_t *batch = NULL;
                size_t batch_rcvd;
                error = rd_kafka_share_poll(rkshare, 3000, &batch);

                if (error) {
                        TEST_SAY("Attempt %d: consume error: %s\n", attempts,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        attempts++;
                        continue;
                }

                batch_rcvd = rd_kafka_messages_count(batch);
                if (batch_rcvd > 0) {
                        TEST_SAY("Attempt %d: consumed %d messages\n", attempts,
                                 (int)batch_rcvd);
                        if (first_batch == NULL) {
                                size_t k;
                                /* First non-empty batch: ack ALL. The
                                 * next consume_batch will piggyback
                                 * this ack on a ShareFetch. */
                                first_batch     = batch;
                                first_batch_cnt = batch_rcvd;
                                for (k = 0; k < batch_rcvd; k++) {
                                        rd_kafka_message_t *rkm =
                                            rd_kafka_messages_get(batch, k);
                                        if (rkm)
                                                rd_kafka_share_acknowledge(
                                                    rkshare, rkm);
                                }
                        } else {
                                /* Second non-empty batch — keep it for
                                 * out-of-loop acks below. */
                                rd_kafka_messages_destroy(second_batch);
                                second_batch = batch;
                        }
                        rcvd += batch_rcvd;
                } else {
                        rd_kafka_messages_destroy(batch);
                }
                attempts++;
        }

        TEST_ASSERT(rcvd == TEST_MSGS,
                    "Expected %d messages after %d attempts, got %d", TEST_MSGS,
                    MAX_CONSUME_ATTEMPTS, (int)rcvd);
        TEST_ASSERT(first_batch_cnt == TEST_MSGS / 2,
                    "Expected first batch == TEST_MSGS/2 (%d), got %d",
                    TEST_MSGS / 2, (int)first_batch_cnt);
        TEST_ASSERT(second_batch != NULL, "Expected a non-NULL second batch");

        drain_ack_callbacks(rkshare);
        {
                rd_kafka_message_t *first_rkm =
                    rd_kafka_messages_get(first_batch, 0);
                TEST_ASSERT(first_rkm != NULL,
                            "Expected non-NULL first batch message");
                first_batch_part = first_rkm->partition;
        }
        second_batch_part = (first_batch_part == 0) ? 1 : 0;
        TEST_SAY("Consumed %d messages (first batch on partition %" PRId32
                 ", second batch on partition %" PRId32 ")\n",
                 (int)rcvd, first_batch_part, second_batch_part);

        /* Ack the second batch:
         *   ack_half=false: ack all TEST_MSGS/2 records.
         *   ack_half=true:  ack TEST_MSGS/4 records (the first half).
         * These acks won't be piggyback-flushed close runs — which is
         * exactly what destroy_share_consumer does (with destroy_flags=0).
         * With destroy_flags=0x8 these acks are dropped. */
        {
                int second_to_ack =
                    ack_half ? (TEST_MSGS / 4) : (TEST_MSGS / 2);
                int k;
                for (k = 0; k < second_to_ack; k++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(second_batch, k);
                        if (rkm)
                                rd_kafka_share_acknowledge(rkshare, rkm);
                }
                ack_cnt = (int)first_batch_cnt + second_to_ack;
                TEST_SAY(
                    "Acked first batch (%d) + second batch (%d) = %d / "
                    "%d total\n",
                    (int)first_batch_cnt, second_to_ack, ack_cnt, (int)rcvd);
        }

        /* Destroy all consumed messages (acked and unacked alike). */
        rd_kafka_messages_destroy(first_batch);
        first_batch = NULL;
        rd_kafka_messages_destroy(second_batch);
        second_batch = NULL;

        destroy_share_consumer(rkshare, destroy_flags);

        /* Assert ack callback receipts.
         *
         * Acks fired:
         *   - First batch: always all TEST_MSGS/2 records on
         *     first_batch_part (acked inside the loop, piggybacked on
         *     the next ShareFetch — delivered before destroy).
         *   - Second batch: TEST_MSGS/2 (if !ack_half) or TEST_MSGS/4
         *     (if ack_half) records on second_batch_part. These acks
         *     are queued internally and only flushed during close.
         *
         *   destroy_flags=0 (full close): close flushes the second
         *   batch's acks. Both partitions appear.
         *
         *   destroy_flags=0x8 (NO_CONSUMER_CLOSE): destroy short-
         *   circuits, so second-batch acks are dropped. Only
         *   first_batch_part appears with TEST_MSGS/2. */
        expected[0] = (expected_ack_t) {
            topic, first_batch_part, RD_KAFKA_RESP_ERR_NO_ERROR, TEST_MSGS / 2};
        if (destroy_flags & RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE) {
                verify_ack_receipts(&receipts, expected, 1,
                                    "explicit-ack NO_CONSUMER_CLOSE");
        } else {
                second_part_cnt = ack_half ? (TEST_MSGS / 4) : (TEST_MSGS / 2);
                expected[1]     = (expected_ack_t) {topic, second_batch_part,
                                                    RD_KAFKA_RESP_ERR_NO_ERROR,
                                                    second_part_cnt};
                verify_ack_receipts(&receipts, expected, 2,
                                    "explicit-ack full close");
        }

        ack_receipts_destroy(&receipts);

        SUB_TEST_PASS();
}


/**
 * @brief Test destroying share consumer with implicit-ack mode.
 *
 * Consumes a batch of messages in implicit-ack mode but never makes a
 * follow-up poll (which is what would trigger the implicit ack), then
 * destroys the consumer directly. Verifies that destroy handles
 * un-acked records gracefully.
 *
 * @param destroy_flags Destroy flags (0 or
 *                      RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE).
 */
static void do_test_destroy_with_implicit_ack(int destroy_flags) {
        const char *topic;
        const char *group = "0179-destroy-implicit-ack";
        rd_kafka_share_t *rkshare;
        rd_kafka_error_t *error;
        rd_kafka_messages_t *first_batch  = NULL;
        rd_kafka_messages_t *second_batch = NULL;
        size_t rcvd                       = 0;
        size_t first_batch_cnt            = 0;
        int32_t first_batch_part          = -1;
        int32_t second_batch_part         = -1;
        int attempts                      = 0;
        expected_ack_t expected[1];
        ack_receipts_t receipts;

        ack_receipts_init(&receipts);

        SUB_TEST("destroy_flags=0x%x", destroy_flags);

        topic = test_mk_topic_name("0179-destroy-implicit-ack", 1);
        TEST_SAY("Creating 2-partition topic %s\n", topic);
        test_create_topic_wait_exists(common_admin, topic, 2, -1, 60 * 1000);

        /* Explicit produce: TEST_MSGS/2 to each partition. */
        TEST_SAY("Producing %d messages to each partition of topic %s\n",
                 TEST_MSGS / 2, topic);
        test_produce_msgs_simple(common_producer, topic, 0, TEST_MSGS / 2);
        test_produce_msgs_simple(common_producer, topic, 1, TEST_MSGS / 2);

        test_share_set_auto_offset_reset(group, "earliest");

        TEST_SAY("Creating share consumer (implicit ack mode) with ack_cb\n");
        rkshare =
            new_share_consumer_for_real_test(group, "implicit", &receipts);
        subscribe_topics(rkshare, &topic, 1);

        /* Consume loop. Implicit ack mode: records are auto-acked by
         * the consumer when the next consume_batch's ShareFetch
         * piggybacks them. The 2-partition setup with TEST_MSGS/2 per
         * partition means each non-empty consume_batch returns one
         * partition's full payload. After the 2nd consume_batch
         * returns, we've consumed all TEST_MSGS records and the 1st
         * batch's records' implicit-acks have already been
         * piggybacked. The 2nd batch's records are still ACQUIRED. */
        TEST_SAY("Consuming %d messages (up to %d attempts)\n", TEST_MSGS,
                 MAX_CONSUME_ATTEMPTS);
        while (rcvd < TEST_MSGS && attempts < MAX_CONSUME_ATTEMPTS) {
                rd_kafka_messages_t *batch = NULL;
                size_t batch_rcvd;
                error = rd_kafka_share_poll(rkshare, 3000, &batch);

                if (error) {
                        TEST_SAY("Attempt %d: consume error: %s\n", attempts,
                                 rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(batch);
                        attempts++;
                        continue;
                }

                batch_rcvd = rd_kafka_messages_count(batch);
                if (batch_rcvd > 0) {
                        TEST_SAY("Attempt %d: consumed %d messages\n", attempts,
                                 (int)batch_rcvd);
                        if (first_batch == NULL) {
                                first_batch     = batch;
                                first_batch_cnt = batch_rcvd;
                        } else {
                                rd_kafka_messages_destroy(second_batch);
                                second_batch = batch;
                        }
                        rcvd += batch_rcvd;
                } else {
                        rd_kafka_messages_destroy(batch);
                }
                attempts++;
        }

        TEST_ASSERT(rcvd == TEST_MSGS,
                    "Expected %d messages after %d attempts, got %d", TEST_MSGS,
                    MAX_CONSUME_ATTEMPTS, (int)rcvd);
        TEST_ASSERT(first_batch_cnt == TEST_MSGS / 2,
                    "Expected first batch == TEST_MSGS/2 (%d), got %d",
                    TEST_MSGS / 2, (int)first_batch_cnt);
        {
                rd_kafka_message_t *first_rkm =
                    rd_kafka_messages_get(first_batch, 0);
                TEST_ASSERT(first_rkm != NULL,
                            "Expected non-NULL first batch message");
                first_batch_part = first_rkm->partition;
        }
        second_batch_part = (first_batch_part == 0) ? 1 : 0;
        TEST_SAY("Consumed %d messages (first batch on partition %" PRId32
                 ", second batch on partition %" PRId32 ")\n",
                 (int)rcvd, first_batch_part, second_batch_part);

        /* Drain pending ack callbacks: the first batch's piggybacked
         * acks may still be in flight. */
        drain_ack_callbacks(rkshare);

        /* Destroy all consumed messages before share_destroy. */
        rd_kafka_messages_destroy(first_batch);
        first_batch = NULL;
        rd_kafka_messages_destroy(second_batch);
        second_batch = NULL;

        destroy_share_consumer(rkshare, destroy_flags);

        /* Assert ack callback receipts.
         *
         * In implicit-ack mode, the 2nd batch's records stay ACQUIRED
         * at close/destroy time and are NOT shipped by either close
         * path (full or NO_CONSUMER_CLOSE) — so they never surface
         * in the callback. Only the 1st batch's piggybacked acks
         * (flushed via the 2nd consume_batch's ShareFetch) reach the
         * callback. Expectation is identical for both destroy_flags
         * variants: TEST_MSGS/2 NO_ERROR on first_batch_part only. */
        (void)second_batch_part;
        expected[0] = (expected_ack_t) {
            topic, first_batch_part, RD_KAFKA_RESP_ERR_NO_ERROR, TEST_MSGS / 2};
        verify_ack_receipts(
            &receipts, expected, 1,
            (destroy_flags & RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE)
                ? "implicit-ack NO_CONSUMER_CLOSE"
                : "implicit-ack full close");

        ack_receipts_destroy(&receipts);

        SUB_TEST_PASS();
}


/**
 * @brief Test destroying share consumer after subscribe/unsubscribe.
 *
 * This test creates a share consumer, optionally subscribes to topics,
 * optionally unsubscribes, then destroys it without consuming any messages.
 * Tests various combinations similar to 0116-kafkaconsumer_close.
 *
 * @param do_subscribe Whether to subscribe to topics
 * @param do_unsubscribe Whether to unsubscribe before destroy
 * @param destroy_flags Destroy flags (0 or
 * RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE)
 */
static void do_test_destroy_with_subscribe_unsubscribe(int do_subscribe,
                                                       int do_unsubscribe,
                                                       int destroy_flags) {
        rd_kafka_share_t *consumer;
        rd_kafka_topic_partition_list_t *topics;
        const char *topic = "0179-test-destroy-sub-unsub";
        rd_kafka_resp_err_t err;

        SUB_TEST("subscribe=%d, unsubscribe=%d, destroy_flags=0x%x",
                 do_subscribe, do_unsubscribe, destroy_flags);

        TEST_SAY("Creating share consumer\n");
        consumer = test_create_share_consumer("0179-sub-unsub-destroy-test",
                                              "explicit");

        if (do_subscribe) {
                TEST_SAY("Subscribing to topic: %s\n", topic);
                topics = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(topics, topic,
                                                  RD_KAFKA_PARTITION_UA);
                err = rd_kafka_share_subscribe(consumer, topics);
                TEST_ASSERT(!err, "Subscribe failed: %s",
                            rd_kafka_err2str(err));
                rd_kafka_topic_partition_list_destroy(topics);
        }

        if (do_unsubscribe) {
                TEST_SAY("Unsubscribing from all topics\n");
                err = rd_kafka_share_unsubscribe(consumer);
                TEST_ASSERT(!err, "Unsubscribe failed: %s",
                            rd_kafka_err2str(err));
        }

        destroy_share_consumer(consumer, destroy_flags);
        SUB_TEST_PASS();
}


/**
 * @brief Destroy a consumer that drove a mixed-ack chaos workload —
 *        ACCEPT/RELEASE/REJECT round-robin acks, with commit_async every
 *        5 acks and commit_sync every 10 acks. destroy runs on a
 *        watchdog thread so a hung destroy fails the test loudly instead
 *        of wedging the binary.
 */
static void do_test_destroy_with_mixed_acks_and_commits(int destroy_flags) {
        const char *topic;
        const char *group = "0179-destroy-mixed";
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_messages_t *batch                  = NULL;
        rd_kafka_error_t *close_err;
        thrd_t destroy_thr;
        destroy_watchdog_arg_t arg;
        ack_receipts_t receipts;
        const int produce_cnt         = 40;
        const int target              = 30;
        const int DESTROY_DEADLINE_MS = 15000;
        rd_ts_t t_start;
        int64_t t_close_ms = 0;
        int64_t t_destroy_ms;
        size_t rcvd;
        size_t j;
        int acked     = 0;
        int sync_cnt  = 0;
        int async_cnt = 0;
        int attempts  = 0;
        int wait_ok;
        rd_bool_t do_close =
            !(destroy_flags & RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);

        SUB_TEST("destroy_flags=0x%x", destroy_flags);

        ack_receipts_init(&receipts);

        topic = test_mk_topic_name("0179-destroy-mixed", 1);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_produce_msgs_simple(common_producer, topic, 0, produce_cnt);

        test_share_set_auto_offset_reset(group, "earliest");
        rkshare =
            new_share_consumer_for_real_test(group, "explicit", &receipts);
        subscribe_topics(rkshare, &topic, 1);

        /* Drive chaos: round-robin ACCEPT/RELEASE/REJECT acks with
         * interleaved commits. Past `target` we drop each batch's
         * message handles without acking — close/destroy must cope
         * with whatever inflight state that leaves the lib in. */
        while (acked < target && attempts++ < 80) {
                rd_kafka_error_t *err;
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                err   = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_share_AcknowledgeType_t at;
                        rd_kafka_resp_err_t aerr;
                        rd_kafka_error_t *cerr;
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(batch, j);

                        if (!rkm)
                                continue;

                        if (rkm->err)
                                continue;

                        if (acked >= target)
                                continue;

                        switch (acked % 3) {
                        case 0:
                                at = RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT;
                                break;
                        case 1:
                                at = RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE;
                                break;
                        default:
                                at = RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT;
                                break;
                        }

                        aerr =
                            rd_kafka_share_acknowledge_type(rkshare, rkm, at);
                        TEST_ASSERT(!aerr, "acknowledge_type(%d) failed: %s",
                                    (int)at, rd_kafka_err2str(aerr));
                        acked++;

                        if (acked % 5 == 0) {
                                cerr = rd_kafka_share_commit_async(rkshare);
                                TEST_ASSERT(!cerr, "commit_async: %s",
                                            cerr ? rd_kafka_error_string(cerr)
                                                 : "");
                                async_cnt++;
                        }
                        if (acked % 10 == 0) {
                                cerr = rd_kafka_share_commit_sync(
                                    rkshare, 30000, &partitions);
                                TEST_ASSERT(!cerr, "commit_sync: %s",
                                            cerr ? rd_kafka_error_string(cerr)
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
        TEST_ASSERT(acked >= target, "expected to ack %d records, got %d",
                    target, acked);
        TEST_SAY(
            "acked=%d sync=%d async=%d ack_cb_invocations=%d. "
            "Calling close.\n",
            acked, sync_cnt, async_cnt, receipts.callback_invocations);

        if (do_close) {
                t_start    = test_clock();
                close_err  = rd_kafka_share_consumer_close(rkshare);
                t_close_ms = (test_clock() - t_start) / 1000;
                TEST_SAY("close returned in %" PRId64
                         " ms (err=%s) "
                         "ack_cb_invocations=%d\n",
                         t_close_ms,
                         close_err ? rd_kafka_error_string(close_err) : "NULL",
                         receipts.callback_invocations);
                if (close_err)
                        rd_kafka_error_destroy(close_err);
        } else {
                TEST_SAY(
                    "Skipping consumer_close (destroy_flags has "
                    "NO_CONSUMER_CLOSE)\n");
        }

        /* Run destroy on the watchdog thread; fail if it hangs past
         * DESTROY_DEADLINE_MS instead of wedging the binary. */
        arg.rkshare       = rkshare;
        arg.destroy_flags = destroy_flags;
        rd_atomic32_init(&arg.done, 0);

        TEST_ASSERT(thrd_create(&destroy_thr, destroy_watchdog_thread, &arg) ==
                        thrd_success,
                    "Failed to spawn destroy watchdog thread");

        t_start = test_clock();
        wait_ok = 1;
        while (!rd_atomic32_get(&arg.done)) {
                if ((test_clock() - t_start) / 1000 >= DESTROY_DEADLINE_MS) {
                        wait_ok = 0;
                        break;
                }
                rd_usleep(100 * 1000, NULL);
        }
        t_destroy_ms = (test_clock() - t_start) / 1000;

        if (!wait_ok) {
                /* Detach so the OS reaps the still-running thread at
                 * process exit (rkshare permanently leaked). */
                thrd_detach(destroy_thr);
                TEST_FAIL(
                    "rd_kafka_share_destroy hung past %d ms after close "
                    "(close took %" PRId64
                    " ms). acked=%d sync=%d async=%d "
                    "ack_cb_invocations=%d (expected >= %d).",
                    DESTROY_DEADLINE_MS, t_close_ms, acked, sync_cnt, async_cnt,
                    receipts.callback_invocations, async_cnt + sync_cnt);
        }

        thrd_join(destroy_thr, NULL);

        TEST_SAY("destroy returned in %" PRId64 " ms (close was %" PRId64
                 " ms); final ack_cb_invocations=%d\n",
                 t_destroy_ms, t_close_ms, receipts.callback_invocations);

        ack_receipts_destroy(&receipts);

        SUB_TEST_PASS();
}


int main_0179_share_consumer_destroy(int argc, char **argv) {
        /* Real broker tests */
        test_timeout_set(120);

        common_producer = test_create_producer();
        common_admin    = test_create_producer();

        do_test_destroy_with_subscribe_unsubscribe(0, 0, 0);
        do_test_destroy_with_subscribe_unsubscribe(
            1, 0, 0); /* subscribe, no unsubscribe */
        do_test_destroy_with_subscribe_unsubscribe(
            1, 1, 0); /* subscribe then unsubscribe */
        do_test_destroy_with_explicit_ack(0, rd_false /* ack all */);
        do_test_destroy_with_explicit_ack(0, rd_true /* ack half */);
        do_test_destroy_with_implicit_ack(0);

        do_test_destroy_with_subscribe_unsubscribe(
            1, 0, RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);
        do_test_destroy_with_subscribe_unsubscribe(
            1, 1, RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);
        do_test_destroy_with_subscribe_unsubscribe(
            0, 0, RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);
        do_test_destroy_with_explicit_ack(RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE,
                                          rd_false);
        do_test_destroy_with_explicit_ack(RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE,
                                          rd_true);
        do_test_destroy_with_implicit_ack(RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);

        do_test_destroy_with_mixed_acks_and_commits(0);
        do_test_destroy_with_mixed_acks_and_commits(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);

        rd_kafka_destroy(common_admin);
        rd_kafka_destroy(common_producer);

        return 0;
}

int main_0179_share_consumer_destroy_local(int argc, char **argv) {
        /* Mock broker tests only (no real broker needed) */
        TEST_SKIP_MOCK_CLUSTER(0);
        test_timeout_set(480);

        test_destroy_with_fatal_error(0);
        test_destroy_with_cached_acks_and_delayed_broker(0);
        test_broker_decommission_with_commit_sync(0, rd_false);
        test_broker_decommission_with_commit_sync(0, rd_true);
        test_broker_decommission_with_consume_batch(0);
        test_broker_decommission_during_close(0, rd_false);
        test_broker_decommission_during_close(0, rd_true);
        test_broker_decommission_with_commit_async(0, rd_false);
        test_broker_decommission_with_commit_async(0, rd_true);
        test_destroy_during_rebalance(0);

        test_destroy_with_fatal_error(RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);
        test_destroy_with_cached_acks_and_delayed_broker(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);
        test_broker_decommission_with_commit_sync(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE, rd_false);
        test_broker_decommission_with_commit_sync(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE, rd_true);
        test_broker_decommission_with_consume_batch(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);
        test_broker_decommission_during_close(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE, rd_false);
        test_broker_decommission_during_close(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE, rd_true);
        test_broker_decommission_with_commit_async(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE, rd_false);
        test_broker_decommission_with_commit_async(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE, rd_true);
        test_destroy_during_rebalance(RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);

        test_leader_migration_mid_session_destroy(0);
        test_leader_migration_mid_session_destroy(
            RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);

        return 0;
}
