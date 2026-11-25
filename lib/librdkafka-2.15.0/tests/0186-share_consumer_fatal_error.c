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

#define CONSUME_ARRAY 1024

static rd_bool_t is_share_heartbeat_request(rd_kafka_mock_request_t *request,
                                            void *opaque) {
        return rd_kafka_mock_request_api_key(request) ==
               RD_KAFKAP_ShareGroupHeartbeat;
}

/**
 * @brief Create a share consumer connected to the mock cluster.
 *
 * @param ack_mode "implicit" or "explicit" (NULL for the default).
 * @param cb_state Opaque ack-commit-callback state (NULL to skip the cb).
 */
static rd_kafka_share_t *create_share_consumer(const char *bootstraps,
                                               const char *group_id,
                                               const char *ack_mode,
                                               test_ack_cb_state_t *cb_state) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        char errstr[512];

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);
        if (ack_mode)
                test_conf_set(conf, "share.acknowledgement.mode", ack_mode);

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer: %s",
                    errstr);

        if (cb_state) {
                rd_kafka_error_t *cb_err =
                    rd_kafka_share_set_acknowledgement_commit_cb(
                        rkshare, test_share_ack_cb, cb_state);
                TEST_ASSERT(cb_err == NULL,
                            "Failed to set ack commit callback: %s",
                            rd_kafka_error_string(cb_err));
        }

        return rkshare;
}

/**
 * @brief No more records after the first fatal error, even when records
 *        are available on the broker.
 *
 * 1. Create a topic. Produce 10 messages.
 * 2. Consume them via consume_batch (implicit ack).
 * 3. Inject a fatal error (GROUP_AUTHORIZATION_FAILED) on the next
 *    ShareGroupHeartbeat and poll consume_batch until the fatal error
 *    surfaces. No records are available, so every call returns zero.
 * 4. Produce 10 more messages: these are now available on the broker.
 * 5. Every consume_batch call must still return zero records, since the
 *    consumer is in a fatal state.
 * 6. Close and destroy the consumer.
 */
static void do_test_no_records_after_fatal_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "sg-0186-no-records-after-fatal";
        const rd_kafka_resp_err_t fatal_err =
            RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED;
        const int msgcnt = 10;
        int consumed;
        int attempts;
        rd_bool_t got_fatal = rd_false;
        int i;

        SUB_TEST_QUICK();

        /* 1. Setup mock cluster and a topic, produce 10 messages. */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        test_produce_msgs_easy_v(topic, 0, 0, 0, msgcnt, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        /* Create the share consumer (implicit ack) and subscribe. */
        rkshare = create_share_consumer(bootstraps, group, "implicit", NULL);
        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(rkshare, subscription);
        rd_kafka_topic_partition_list_destroy(subscription);

        /* 2. Consume all messages (implicit ack). */
        consumed = test_share_consume_msgs(rkshare, msgcnt, 30, 3000, NULL, 0);
        TEST_ASSERT(consumed == msgcnt, "expected %d consumed, got %d", msgcnt,
                    consumed);

        /* 3. Inject the fatal error on the next ShareGroupHeartbeat and poll
         *    until it surfaces via consume_batch. No records are available
         *    yet, so every call must return zero records. */
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
                        fatal_err, 0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push fatal error on ShareGroupHeartbeat");

        attempts = 0;
        while (attempts++ < 50) {
                size_t rcvd;
                error = rd_kafka_share_poll(rkshare, 1000, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                TEST_ASSERT(rcvd == 0,
                            "no records expected while waiting for the fatal "
                            "error, got %d",
                            (int)rcvd);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                if (error) {
                        TEST_ASSERT(rd_kafka_error_is_fatal(error),
                                    "expected a fatal error, got non-fatal %s",
                                    rd_kafka_error_name(error));
                        TEST_ASSERT(rd_kafka_error_code(error) == fatal_err,
                                    "expected fatal %s, got %s",
                                    rd_kafka_err2name(fatal_err),
                                    rd_kafka_error_name(error));
                        rd_kafka_error_destroy(error);
                        got_fatal = rd_true;
                        break;
                }
        }
        TEST_ASSERT(got_fatal,
                    "expected a fatal error to surface within timeout");

        /* 4. Produce more messages: they are now available on the broker. */
        test_produce_msgs_easy_v(topic, 0, 0, 0, msgcnt, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        /* 5. Every subsequent consume_batch call must keep returning zero
         *    records, even though new messages are available. */
        for (i = 0; i < 10; i++) {
                size_t rcvd;
                error = rd_kafka_share_poll(rkshare, 500, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                TEST_ASSERT(rcvd == 0,
                            "expected 0 records on post-fatal call %d, got %d",
                            i, (int)rcvd);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                if (error)
                        rd_kafka_error_destroy(error);
        }

        /* 6. Close and destroy. */
        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief close() flushes pending acks but does NOT send a share-group
 *        leave heartbeat when a fatal error was raised naturally.
 *
 * When a fatal error arises from the ShareGroupHeartbeat path the member
 * is no longer in a state to leave the group, so close() must not send a
 * leaving ShareGroupHeartbeat. It must still flush the pending
 * acknowledgements (so the ack commit callback fires without error).
 *
 * 1. Create a 1-partition topic and produce 10 messages.
 * 2. Consume at least one batch (explicit ack), acknowledging every
 *    record so the acks are pending (not yet sent to the broker).
 * 3. Inject GROUP_AUTHORIZATION_FAILED on the next ShareGroupHeartbeat
 *    and wait for a heartbeat so the fatal error is raised naturally.
 * 4. Poll consume_batch until the fatal error surfaces.
 * 5. Start request tracking, then call close().
 * 6. Assert NO ShareGroupHeartbeat (leave) request is sent during close.
 * 7. Destroy, and verify the ack commit callback fired without error.
 */
static void do_test_close_flushes_acks_after_fatal_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "sg-0186-close-no-leave-after-fatal";
        const rd_kafka_resp_err_t fatal_err =
            RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED;
        const int msgcnt             = 10;
        test_ack_cb_state_t cb_state = {0};
        int heartbeats_after_close;
        int consumed        = 0;
        int attempts        = 0;
        rd_bool_t got_fatal = rd_false;

        SUB_TEST_QUICK();

        /* 1. Setup mock cluster and a topic, produce 10 messages. */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        TEST_ASSERT(rd_kafka_mock_topic_create(mcluster, topic, 1, 1) ==
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                    "create topic");
        rd_kafka_mock_sharegroup_set_auto_offset_reset(mcluster, 1);

        test_produce_msgs_easy_v(topic, 0, 0, 0, msgcnt, 16,
                                 "bootstrap.servers", bootstraps, NULL);

        /* Create an explicit-ack share consumer with a commit callback. */
        rkshare =
            create_share_consumer(bootstraps, group, "explicit", &cb_state);
        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(rkshare, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* 2. Consume at least one batch and acknowledge every record.
         *    Break out as soon as we have received some records. */
        while (consumed == 0 && attempts++ < 30) {
                size_t rcvd;
                size_t j;
                error = rd_kafka_share_poll(rkshare, 3000, &batch);
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
                                TEST_CALL_ERR__(
                                    rd_kafka_share_acknowledge(rkshare, rkm));
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed > 0, "expected to consume and ack > 0 records");
        TEST_SAY("Consumed and acknowledged %d records\n", consumed);

        /* 3. Inject the fatal error on the next ShareGroupHeartbeat so the
         *    fatal error gets raised naturally. */
        TEST_ASSERT(rd_kafka_mock_broker_push_request_error_rtts(
                        mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
                        fatal_err, 0) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "push fatal error on ShareGroupHeartbeat");

        /* 4. Poll consume_batch until the fatal error surfaces. The fatal
         *    error is delivered only after a heartbeat has hit the injected
         *    error and the cgrp has processed it (revoking the assignment
         *    and resetting the generation id), so this loop also serves as
         *    the synchronization point for that handling. */
        attempts = 0;
        while (attempts++ < 50) {
                error = rd_kafka_share_poll(rkshare, 1000, &batch);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                if (error) {
                        TEST_ASSERT(rd_kafka_error_is_fatal(error),
                                    "expected a fatal error, got non-fatal %s",
                                    rd_kafka_error_name(error));
                        rd_kafka_error_destroy(error);
                        got_fatal = rd_true;
                        break;
                }
        }
        TEST_ASSERT(got_fatal,
                    "expected a fatal error to surface within timeout");

        /* 5. Reset the tracked-request baseline (start_request_tracking
         *    clears the list), then close(). */
        rd_kafka_mock_start_request_tracking(mcluster);

        error = rd_kafka_share_consumer_close(rkshare);
        if (error)
                rd_kafka_error_destroy(error);

        /* 6. No leaving ShareGroupHeartbeat must be sent during close. The
         *    natural fatal handling already revoked the assignment and reset
         *    the generation id (HAS_JOINED is false), so the group-leave path
         *    is skipped. (The share session is still closed, but via a
         *    ShareAcknowledge with epoch=-1, not a ShareGroupHeartbeat.) */
        heartbeats_after_close = (int)test_mock_get_matching_request_cnt(
            mcluster, is_share_heartbeat_request, NULL);

        rd_kafka_mock_stop_request_tracking(mcluster);

        /* 7. Destroy and verify the ack commit callback fired without error,
         *    confirming the pending acks were flushed during close(). */
        test_share_destroy(rkshare);

        TEST_ASSERT(heartbeats_after_close == 0,
                    "expected no ShareGroupHeartbeat during close, got %d",
                    heartbeats_after_close);
        TEST_ASSERT(cb_state.callback_cnt > 0,
                    "expected the ack commit callback to be invoked, got %d",
                    cb_state.callback_cnt);
        rd_kafka_resp_err_t cb_first_err =
            test_ack_cb_state_first_err(&cb_state);
        TEST_ASSERT(cb_first_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "expected ack callback with no error, got %s",
                    rd_kafka_err2name(cb_first_err));
        TEST_SAY("Ack callback invoked %d time(s), %zu offsets, err=%s\n",
                 cb_state.callback_cnt, cb_state.total_offsets,
                 rd_kafka_err2name(cb_first_err));

        test_ack_cb_state_destroy(&cb_state);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

int main_0186_share_consumer_fatal_error(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);

        do_test_no_records_after_fatal_error();
        do_test_close_flushes_acks_after_fatal_error();

        return 0;
}