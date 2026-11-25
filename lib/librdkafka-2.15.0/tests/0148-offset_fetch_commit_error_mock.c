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

#include <stdarg.h>


static mtx_t log_lock;
static cnd_t log_cnd;
static rd_bool_t revocation_done        = rd_false;
static int got_stale_member_epoch_error = 0;
static rd_bool_t trigger_consumer_close = rd_false;
static int ack_target_assignment_count  = 0;

static void
log_cb(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
        if (strstr(buf,
                   "assignment operations done in join-state "
                   "wait-incr-unassign-to-complete")) {
                mtx_lock(&log_lock);
                revocation_done = rd_true;
                cnd_signal(&log_cnd);
                mtx_unlock(&log_lock);
        }
}

/**
 * @brief A stale member error during an OffsetFetch should cause
 *        to retry the operation just after next ConsumerGroupHeartbeat
 *        response.
 *        The offset fetch eventually succeeds and the consumer can
 *        start from the committed offset.
 */
void do_test_OffsetFetch_stale_member_epoch_error(
    rd_kafka_mock_cluster_t *mcluster,
    const char *bootstraps) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_t *producer, *first_consumer, *second_consumer;
        rd_kafka_conf_t *conf, *producer_conf;
        uint64_t testid  = test_id_generate();
        const int msgcnt = 5;
        test_msgver_t mv;

        SUB_TEST_QUICK();

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "bootstrap.servers", bootstraps);

        /* Producer */
        producer_conf = rd_kafka_conf_dup(conf);
        rd_kafka_conf_set_dr_msg_cb(producer_conf, test_dr_msg_cb);
        producer = test_create_handle(RD_KAFKA_PRODUCER, producer_conf);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 2);
        test_produce_msgs2(producer, topic, testid, 0, 0, msgcnt, NULL, 0);
        rd_kafka_flush(producer, -1);

        /* Consumer */
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "group.protocol", "consumer");
        first_consumer =
            test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        test_consumer_subscribe(first_consumer, topic);
        test_consumer_poll("before consume error", first_consumer, testid, -1,
                           0, msgcnt, NULL);
        test_consumer_close(first_consumer);

        /* Produce again */
        test_produce_msgs2(producer, topic, testid, 0, msgcnt, msgcnt, NULL, 0);
        rd_kafka_flush(producer, -1);

        /* Set OffsetFetch errors */
        rd_kafka_mock_push_request_errors(mcluster, RD_KAFKAP_OffsetFetch, 5,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH);

        /* Consume again*/
        test_msgver_init(&mv, testid);
        second_consumer = test_create_consumer(topic, NULL, conf, NULL);
        test_consumer_subscribe(second_consumer, topic);
        test_consumer_poll("receive second batch", second_consumer, testid, -1,
                           msgcnt, msgcnt, &mv);
        test_msgver_verify("verify second batch", &mv, TEST_MSGVER_ALL, msgcnt,
                           msgcnt);
        test_msgver_clear(&mv);
        test_consumer_close(second_consumer);

        /* Destroy */
        rd_kafka_destroy(first_consumer);
        rd_kafka_destroy(second_consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}

typedef enum do_test_OffsetCommit_manual_error_variation_s {
        /** commit stored offsets */
        TEST_MANUAL_COMMIT_ERROR_VARIATION_STORE_OFFSET_AUTOMATICALLY = 0,
        /** commit passed offsets */
        TEST_MANUAL_COMMIT_ERROR_VARIATION_STORE_OFFSET_MANUALLY = 1,
        TEST_MANUAL_COMMIT_ERROR_VARIATION__CNT,
} do_test_OffsetCommit_manual_error_variation_t;

/**
 * @brief Doing a manual commits that returns error \p expected_err
 *        should return the error to the caller, even if the error
 *        is a partition level error.
 *        These errors aren't retried.
 */
void do_test_OffsetCommit_manual_error(
    rd_kafka_mock_cluster_t *mcluster,
    const char *bootstraps,
    rd_kafka_resp_err_t expected_err,
    do_test_OffsetCommit_manual_error_variation_t variation) {
        rd_kafka_t *consumer;
        test_msgver_t mv;
        rd_kafka_conf_t *conf;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        uint64_t testid   = test_id_generate();
        const int msgcnt  = 5;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *to_commit = NULL;

        SUB_TEST_QUICK();

        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "group.protocol", "consumer");

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, testid, 0, 0, msgcnt, 0,
                                 "bootstrap.servers", bootstraps, NULL);

        /* Consume same messages */
        consumer = test_create_consumer(topic, NULL, conf, NULL);
        test_consumer_subscribe(consumer, topic);
        test_msgver_init(&mv, testid);
        test_consumer_poll("receive first batch", consumer, testid, -1, 0,
                           msgcnt, &mv);
        test_msgver_verify("verify first batch", &mv, TEST_MSGVER_ALL, 0,
                           msgcnt);
        test_msgver_clear(&mv);

        /* Set OffsetCommit errors */
        rd_kafka_mock_push_request_errors(mcluster, RD_KAFKAP_OffsetCommit, 1,
                                          expected_err);

        if (variation ==
            TEST_MANUAL_COMMIT_ERROR_VARIATION_STORE_OFFSET_MANUALLY) {
                /* Variation 1: pass offsets to commit */
                to_commit = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(to_commit, topic, 0)->offset =
                    msgcnt;
        }

        /* Sync commit */
        err = rd_kafka_commit(consumer, to_commit, rd_false);
        TEST_ASSERT(err == expected_err, "Expected error %s, got %s",
                    rd_kafka_err2name(expected_err), rd_kafka_err2name(err));

        /* Retry it, this time it should work */
        err = rd_kafka_commit(consumer, to_commit, rd_false);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected error %s, got %s",
                    rd_kafka_err2name(RD_KAFKA_RESP_ERR_NO_ERROR),
                    rd_kafka_err2name(err));

        RD_IF_FREE(to_commit, rd_kafka_topic_partition_list_destroy);

        rd_kafka_destroy(consumer);

        SUB_TEST_PASS();
}

/**
 * Scenarios:
 * during_revocation: the auto-commit is triggered by a revocation,
 *                    otherwise it's triggered by the consumer close.
 * session_times_out: Session times out giving UNKNOWN_MEMBER_ID, otherwise
 *                    commit succeeds after last STALE_MEMBER_EPOCH. When
 *                    session times out the auto-commit fails and messages
 *                    are consumed again.
 */
typedef enum do_test_OffsetCommit_automatic_stale_member_epoch_error_variation_t {
        /** during_revocation=false, session_times_out=false */
        TEST_AUTO_COMMIT_STALE_MEMBER_EPOCH_VARIATION_NO_REVOKE_NO_TIMEOUT = 0,
        /** during_revocation=false, session_times_out=true */
        TEST_AUTO_COMMIT_STALE_MEMBER_EPOCH_VARIATION_NO_REVOKE_WITH_TIMEOUT =
            1,
        /** during_revocation=true, session_times_out=false */
        TEST_AUTO_COMMIT_STALE_MEMBER_EPOCH_VARIATION_REVOKE_NO_TIMEOUT = 2,
        /** during_revocation=true, session_times_out=true */
        TEST_AUTO_COMMIT_STALE_MEMBER_EPOCH_VARIATION_REVOKE_WITH_TIMEOUT = 3,
        TEST_AUTO_COMMIT_STALE_MEMBER_EPOCH_VARIATION__CNT,
} do_test_OffsetCommit_automatic_stale_member_epoch_error_variation_t;

/**
 * @brief When a partition is revoked, with auto-commit enabled,
 *        if the RPC returns STALE_MEMBER_EPOCH for one of the
 *        partitions, it should be retried until the member is
 *        fenced.
 */
void do_test_OffsetCommit_automatic_stale_member_epoch_error(
    rd_kafka_mock_cluster_t *mcluster,
    const char *bootstraps,
    do_test_OffsetCommit_automatic_stale_member_epoch_error_variation_t
        variation) {
        rd_kafka_t *consumer;
        test_msgver_t mv;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_partition_list_t *target_assignment_partitions;
        const char *topic               = test_mk_topic_name(__FUNCTION__, 1);
        uint64_t testid                 = test_id_generate();
        const int msgcnt                = 5;
        const int session_timeout_ms    = 3000;
        const int heartbeat_interval_ms = 1000;
        rd_bool_t during_revocation     = (variation / 2) == 1;
        rd_bool_t session_times_out     = (variation % 2) == 1;
        const char *debug_contexts[2]   = {"cgrp", NULL};

        SUB_TEST_QUICK("during_revocation=%s, session_times_out=%s",
                       RD_STR_ToF(during_revocation),
                       RD_STR_ToF(session_times_out));

        mtx_init(&log_lock, mtx_plain);
        cnd_init(&log_cnd);

        rd_kafka_mock_topic_create(mcluster, topic, 2, 2);
        rd_kafka_mock_coordinator_set(mcluster, "group", topic, 1);
        rd_kafka_mock_set_group_consumer_session_timeout_ms(mcluster,
                                                            session_timeout_ms);
        rd_kafka_mock_set_group_consumer_heartbeat_interval_ms(
            mcluster, heartbeat_interval_ms);

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "true");
        test_conf_set(conf, "auto.commit.interval.ms", "1000");
        test_conf_set(conf, "group.protocol", "consumer");
        test_conf_set_log_interceptor(conf, log_cb, debug_contexts);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, testid, 0, 0, 3, 0, "bootstrap.servers",
                                 bootstraps, NULL);
        test_produce_msgs_easy_v(topic, testid, 1, 0, 2, 0, "bootstrap.servers",
                                 bootstraps, NULL);

        /* Consume same messages */
        consumer =
            test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        test_consumer_subscribe(consumer, topic);
        test_msgver_init(&mv, testid);
        test_consumer_poll_exact("receive first batch", consumer, testid, -1, 0,
                                 msgcnt, rd_true, &mv);
        test_msgver_verify("verify first batch", &mv, TEST_MSGVER_PER_PART, 0,
                           msgcnt);
        test_msgver_clear(&mv);


        rd_kafka_mock_clear_request_errors(mcluster, RD_KAFKAP_OffsetCommit);

        /* First sequence of stale member epoch for 4 s */
        rd_kafka_mock_push_request_errors(mcluster, RD_KAFKAP_OffsetCommit, 4,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH,
                                          RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH);

        if (during_revocation) {
                /* Changing target assignment to partition 0 only,
                 * partition revoked and automatically committed,
                 * but the commit fails. */
                target_assignment_partitions =
                    rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(target_assignment_partitions,
                                                  topic, 0);
                test_mock_cluster_member_assignment(
                    mcluster, 1, consumer, target_assignment_partitions);
                rd_kafka_topic_partition_list_destroy(
                    target_assignment_partitions);

                mtx_lock(&log_lock);
                while (!revocation_done)
                        cnd_timedwait_ms(&log_cnd, &log_lock, 500);
                revocation_done = rd_false;
                mtx_unlock(&log_lock);
        }

        if (session_times_out) {
                /* Simulate a session timeout after that */
                rd_kafka_mock_broker_push_request_error_rtts(
                    mcluster, 1, RD_KAFKAP_OffsetCommit, 1,
                    RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID,
                    session_timeout_ms + heartbeat_interval_ms);
        }

        /* Otherwise partition is committed before leaving the group */
        test_consumer_close(consumer);
        rd_kafka_destroy(consumer);


        /* Reset mock assignor to automatic */
        rd_kafka_mock_cgrp_consumer_target_assignment(mcluster, topic, NULL);

        consumer = test_create_consumer(topic, NULL, conf, NULL);
        test_consumer_subscribe(consumer, topic);

        if (session_times_out) {
                /* Messages are consumed again because the commit failed */
                test_msgver_init(&mv, testid);
                test_consumer_poll_exact("messages consumed again", consumer,
                                         testid, -1, 0, msgcnt, rd_true, &mv);
                test_msgver_verify("messages consumed again", &mv,
                                   TEST_MSGVER_PER_PART, 0, msgcnt);
                test_msgver_clear(&mv);
        } else {
                /* No message should be consumed after the autocommit */
                test_consumer_poll_no_msgs("no messages", consumer, testid,
                                           200);
        }
        test_consumer_close(consumer);
        rd_kafka_destroy(consumer);
        rd_kafka_mock_clear_request_errors(mcluster, RD_KAFKAP_OffsetCommit);

        mtx_destroy(&log_lock);
        cnd_destroy(&log_cnd);

        SUB_TEST_PASS();
}

static void log_cb_closing_issue(const rd_kafka_t *rk,
                                 int level,
                                 const char *fac,
                                 const char *buf) {
        if (strstr(buf, "Acknowledging target assignment")) {
                mtx_lock(&log_lock);
                ack_target_assignment_count++;
                if (ack_target_assignment_count == 2) {
                        trigger_consumer_close = rd_true;
                        cnd_signal(&log_cnd);
                }
                mtx_unlock(&log_lock);
        }
        if (strstr(buf, "unable to OffsetCommit") &&
            strstr(buf, "Broker: The member epoch is stale")) {
                mtx_lock(&log_lock);
                got_stale_member_epoch_error++;
                mtx_unlock(&log_lock);
        }
}

/**
 * @brief This test checks that when a consumer acknowledges revocations and
 * sends a heartbeat just before leaving the group, the heartbeat response may
 * still be in flight while the leave process begins. In this scenario, the
 * heartbeat response must update the member epoch rather than being discarded.
 * Otherwise, subsequent commit requests (which will be required for leaving)
 * may fail with a stale member epoch error.
 *
 * Sequence of events:
 * 1. Consumer is subscribed to topic1 and topic2 and has received messages
 * 2. Consumer changes subscription to only topic1, this triggers revocation of
 *    topic2 partitions.
 * 3. Consumer acknowledges the revocation and sends a heartbeat. The heartbeat
 *    response is delayed (simulated by mock). Due to this, the member epoch on
 *    the broker end is increased but the consumer has not received it yet.
 * 4. Meanwhile, the consumer receives messages from topic1.
 * 5. The consumer is closed, this triggers a leave group which includes an
 *    offset commit request for the received messages.
 * 6. This triggers a stale member epoch error since the consumer is not aware
 *    of the increased member epoch on the broker end.
 * 7. The stale member epoch error triggers ConsumerGroupHeartbeat request
 *    which receives to receive the latest member epoch.
 * 8. The offset commit is retried and succeeds.
 */
void do_test_consumer_inflight_heartbeat_on_leave(
    rd_kafka_mock_cluster_t *mcluster,
    const char *bootstraps) {

        char topic1[256], topic2[256];
        rd_kafka_t *producer, *consumer;
        rd_kafka_conf_t *conf, *producer_conf;
        uint64_t testid  = test_id_generate();
        const int msgcnt = 5;
        test_msgver_t mv;
        const char *debug_contexts[3] = {"cgrp", NULL};
        int64_t close_start, close_end;
        const int session_timeout_ms = 3000;
        const int heartbeat_rtt_ms   = 200;

        SUB_TEST_QUICK();

        mtx_init(&log_lock, mtx_plain);
        cnd_init(&log_cnd);

        strcpy(topic1, test_mk_topic_name("topic1", 1));
        strcpy(topic2, test_mk_topic_name("topic2", 1));

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.protocol", "consumer");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "true");
        test_conf_set(conf, "auto.commit.interval.ms", "2000");
        test_conf_set(conf, "fetch.wait.max.ms", "100");
        test_conf_set_log_interceptor(conf, log_cb_closing_issue,
                                      debug_contexts);

        rd_kafka_mock_coordinator_set(mcluster, "group", topic1, 1);
        rd_kafka_mock_set_group_consumer_session_timeout_ms(mcluster,
                                                            session_timeout_ms);
        rd_kafka_mock_set_group_consumer_heartbeat_interval_ms(mcluster, 500);

        /* Producer Initialization */
        producer_conf = rd_kafka_conf_dup(conf);
        rd_kafka_conf_set_dr_msg_cb(producer_conf, test_dr_msg_cb);
        producer = test_create_handle(RD_KAFKA_PRODUCER, producer_conf);

        /* Create topic1 and produce few messages */
        rd_kafka_mock_topic_create(mcluster, topic1, 1, 1);
        test_produce_msgs2(producer, topic1, testid, 0, 0, msgcnt, NULL, 0);
        rd_kafka_flush(producer, -1);

        /* Create topic2 and produce few messages */
        rd_kafka_mock_topic_create(mcluster, topic2, 1, 1);
        test_produce_msgs2(producer, topic2, testid, 0, 0, msgcnt, NULL, 0);
        rd_kafka_flush(producer, -1);

        /* Consumer: subscribe to both topics */
        TEST_SAY("Group id: %s\n", topic1);
        consumer =
            test_create_consumer(topic1, NULL, rd_kafka_conf_dup(conf), NULL);
        test_consumer_subscribe_multi(consumer, 2, topic1, topic2);

        /* Poll and verify messages produced to both topics */
        test_msgver_init(&mv, testid);
        test_consumer_poll("read from both topics", consumer, testid, -1, 0,
                           2 * msgcnt, &mv);
        test_msgver_clear(&mv);

        /* Change subscription to only topic1 to trigger revocation */
        test_consumer_subscribe(consumer, topic1);

        /* Set ConsumerGroupHeartbeat RTT to heartbeat_rtt_ms */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ConsumerGroupHeartbeat, 2,
            RD_KAFKA_RESP_ERR_NO_ERROR, heartbeat_rtt_ms,
            RD_KAFKA_RESP_ERR_NO_ERROR, heartbeat_rtt_ms);

        /* Produce few more messages to topic1 so that we can trigger
           auto-commit later which will give stale member epoch error */
        test_produce_msgs2(producer, topic1, testid, 0, 0, msgcnt, NULL, 0);
        rd_kafka_flush(producer, -1);

        /* Wait for log callback to trigger consumer close after second
           "Acknowledging target assignment" */
        mtx_lock(&log_lock);
        while (!trigger_consumer_close)
                cnd_timedwait_ms(&log_cnd, &log_lock, 500);
        mtx_unlock(&log_lock);

        /* Poll and verify the produced messages */
        test_msgver_init(&mv, testid);
        test_consumer_poll("read topic1", consumer, testid, -1, 0, msgcnt, &mv);
        test_msgver_clear(&mv);

        /* Close consumer which will trigger leave group and auto-commit
           The auto-commit will get stale member epoch error and will retry
           after receiving the heartbeat response with the latest member
           epoch */
        close_start = test_clock();
        test_consumer_close(consumer);
        close_end = test_clock();

        /* Verify that we got exactly one stale member epoch error */
        mtx_lock(&log_lock);
        TEST_ASSERT(got_stale_member_epoch_error == 1,
                    "Expected 1 stale member epoch error, got %d",
                    got_stale_member_epoch_error);
        mtx_unlock(&log_lock);

        /* Verify that the consumer closed within session timeout, if it reaches
           session timeout which means that the member is kicked out of the
           group. */
        TEST_ASSERT((close_end - close_start) < session_timeout_ms * 1000,
                    "Consumer did not close within 2s, took %" PRId64 " us",
                    (close_end - close_start));

        rd_kafka_destroy(consumer);
        rd_kafka_destroy(producer);

        mtx_destroy(&log_lock);
        cnd_destroy(&log_cnd);

        SUB_TEST_PASS();
}

int main_0148_offset_fetch_commit_error_mock(int argc, char **argv) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        int i;

        TEST_SKIP_MOCK_CLUSTER(0);

        if (test_consumer_group_protocol_classic()) {
                TEST_SKIP(
                    "Test not meaningful with 'classic' consumer group "
                    "protocol\n");
                return 0;
        }

        mcluster = test_mock_cluster_new(3, &bootstraps);

        do_test_OffsetFetch_stale_member_epoch_error(mcluster, bootstraps);

        for (i = 0; i < TEST_MANUAL_COMMIT_ERROR_VARIATION__CNT; i++) {
                do_test_OffsetCommit_manual_error(
                    mcluster, bootstraps, RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH,
                    i);
                do_test_OffsetCommit_manual_error(
                    mcluster, bootstraps, RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID,
                    i);
        }

        for (i = 0; i < TEST_AUTO_COMMIT_STALE_MEMBER_EPOCH_VARIATION__CNT; i++)
                do_test_OffsetCommit_automatic_stale_member_epoch_error(
                    mcluster, bootstraps, i);

        do_test_consumer_inflight_heartbeat_on_leave(mcluster, bootstraps);

        test_mock_cluster_destroy(mcluster);

        return 0;
}
