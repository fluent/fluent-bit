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

/**
 * @brief Share consumer transaction tests.
 *
 * Tests that share consumers correctly handle transactional messages
 * based on the isolation.level configuration:
 *
 * - read_committed: Only see committed messages, aborted filtered out
 * - read_uncommitted: See ALL messages including aborted ones
 *
 * Both modes are tested to verify correct behavior.
 */

#define BATCH_SIZE 1000

/* Common handles shared across all tests */
static rd_kafka_t *common_admin;
static rd_kafka_t *common_regular_producer;


/**
 * @brief Create a transactional producer.
 */
static rd_kafka_t *create_txn_producer(const char *txn_id) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "transactional.id", txn_id);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        return rk;
}


/**
 * @brief Configure share group settings.
 *
 * Sets share.auto.offset.reset=earliest and share.isolation.level
 * based on the isolation_level parameter.
 *
 * Note: share.isolation.level is a BROKER-SIDE share group configuration.
 * Transaction filtering happens on the broker, not the client.
 */
static void configure_share_group(const char *group,
                                  const char *isolation_level) {
        test_share_set_auto_offset_reset(group, "earliest");
        test_share_set_isolation_level(group, isolation_level);
}


/**
 * @brief Subscribe share consumer to a topic.
 */
static void subscribe_share_consumer(rd_kafka_share_t *rkshare,
                                     const char *topic) {
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_resp_err_t err;

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);

        err = rd_kafka_share_subscribe(rkshare, subs);
        TEST_ASSERT(!err, "Share subscribe failed: %s", rd_kafka_err2str(err));

        rd_kafka_topic_partition_list_destroy(subs);
}


/**
 * @brief Consume messages from share consumer.
 *
 * @returns Number of non-error messages consumed.
 */
static int consume_share_messages(rd_kafka_share_t *rkshare,
                                  int expected_cnt,
                                  int max_attempts,
                                  int poll_timeout_ms) {
        rd_kafka_messages_t *batch = NULL;
        int consumed               = 0;
        int attempts               = max_attempts;

        while (consumed < expected_cnt && attempts-- > 0) {
                size_t rcvd = 0;
                size_t i;
                rd_kafka_error_t *err;

                err = rd_kafka_share_poll(rkshare, poll_timeout_ms, &batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }

                rcvd = rd_kafka_messages_count(batch);
                for (i = 0; i < rcvd; i++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, i);
                        if (!msg->err)
                                consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        return consumed;
}


/**
 * @brief Poll share consumer expecting no messages (for abort verification).
 *
 * @returns Number of messages received (should be 0 for aborted txns
 *          with read_committed).
 */
static int consume_share_no_msgs(rd_kafka_share_t *rkshare,
                                 int poll_attempts,
                                 int poll_timeout_ms) {
        rd_kafka_messages_t *batch = NULL;
        int consumed               = 0;
        int attempts               = poll_attempts;

        while (attempts-- > 0) {
                size_t rcvd = 0;
                size_t i;
                rd_kafka_error_t *err;

                err = rd_kafka_share_poll(rkshare, poll_timeout_ms, &batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }

                rcvd = rd_kafka_messages_count(batch);
                for (i = 0; i < rcvd; i++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, i);
                        if (!msg->err)
                                consumed++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        return consumed;
}


/**
 * @brief Consume messages and verify exact offsets.
 *
 * Consumes messages from the share consumer and verifies that:
 * 1. The number of messages matches expected_msg_cnt
 * 2. The offsets match the expected_offsets array
 * 3. None of the forbidden_offsets appear (e.g., control records)
 *
 * @param rkshare Share consumer instance
 * @param expected_msg_cnt Expected number of messages to consume
 * @param expected_offsets Array of expected offsets in order
 * @param forbidden_offsets Array of offsets that should never appear
 * @param forbidden_cnt Number of forbidden offsets
 * @param isolation_level Isolation level string (for logging)
 */
static void consume_and_verify_offsets(rd_kafka_share_t *rkshare,
                                       int expected_msg_cnt,
                                       const int64_t *expected_offsets,
                                       const int64_t *forbidden_offsets,
                                       int forbidden_cnt,
                                       const char *isolation_level) {
        rd_kafka_messages_t *batch = NULL;
        int attempts               = 50;
        int64_t received_offsets[10];
        int consumed = 0;
        int i, j;

        TEST_SAY("[%s] Consuming messages and verifying offsets:\n",
                 isolation_level);

        /* Consume messages and collect offsets */
        while (consumed < expected_msg_cnt && attempts-- > 0) {
                size_t rcvd = 0;
                rd_kafka_error_t *err;

                err = rd_kafka_share_poll(rkshare, 3000, &batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }

                rcvd = rd_kafka_messages_count(batch);
                for (i = 0; i < (int)rcvd; i++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, i);
                        if (!msg->err && consumed < 10) {
                                received_offsets[consumed] = msg->offset;
                                TEST_SAY("  Message %d: offset=%" PRId64 "\n",
                                         consumed, msg->offset);
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Verify no forbidden offsets were received */
        for (i = 0; i < consumed; i++) {
                for (j = 0; j < forbidden_cnt; j++) {
                        TEST_ASSERT(received_offsets[i] != forbidden_offsets[j],
                                    "[%s] Received forbidden offset %" PRId64
                                    " at position %d - should be filtered!",
                                    isolation_level, forbidden_offsets[j], i);
                }
        }

        /* Verify message count */
        TEST_ASSERT(consumed == expected_msg_cnt,
                    "[%s] Expected %d messages, got %d", isolation_level,
                    expected_msg_cnt, consumed);

        /* Verify exact offsets */
        for (i = 0; i < consumed; i++) {
                TEST_ASSERT(received_offsets[i] == expected_offsets[i],
                            "[%s] Message %d: expected offset %" PRId64
                            ", got %" PRId64,
                            isolation_level, i, expected_offsets[i],
                            received_offsets[i]);
        }

        TEST_SAY(
            "SUCCESS [%s]: All %d offsets verified correctly, "
            "forbidden offsets filtered\n",
            isolation_level, consumed);
}


/**
 * @brief Test committed transaction visibility.
 *
 * Both read_committed and read_uncommitted should see committed messages.
 */
static void do_test_committed_transaction(const char *isolation_level) {
        char topic_suffix[64];
        const char *topic;
        char group[128];
        const char *txn_id = "txn-commit-test";
        const int msg_cnt  = 100;
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        int consumed;

        rd_snprintf(topic_suffix, sizeof(topic_suffix), "0177-txn-commit-%s",
                    isolation_level);
        topic = test_mk_topic_name(topic_suffix, 1);
        rd_snprintf(group, sizeof(group), "share-txn-commit-%s",
                    isolation_level);

        SUB_TEST("isolation.level=%s", isolation_level);

        /* Create topic */
        test_create_topic(NULL, topic, 1, -1);

        /* Create transactional producer */
        producer = create_txn_producer(txn_id);

        /* Create share consumer and set group config */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, isolation_level);
        subscribe_share_consumer(consumer, topic);

        /* Begin transaction */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));

        /* Produce messages */
        TEST_SAY("Producing %d messages in transaction\n", msg_cnt);
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);

        /* Commit transaction */
        TEST_SAY("Committing transaction\n");
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer, 30000));

        /* Consume messages - both modes should receive committed messages */
        TEST_SAY("Consuming messages via share consumer (%s)\n",
                 isolation_level);
        consumed = consume_share_messages(consumer, msg_cnt, 50, 3000);

        TEST_ASSERT(consumed == msg_cnt,
                    "[%s] Expected %d messages from committed transaction, "
                    "got %d",
                    isolation_level, msg_cnt, consumed);

        TEST_SAY(
            "SUCCESS [%s]: Share consumer received %d committed "
            "messages\n",
            isolation_level, consumed);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Test aborted transaction visibility.
 *
 * - read_committed: Should NOT see aborted messages (expect 0)
 * - read_uncommitted: Should see ALL messages (expect msg_cnt)
 */
static void do_test_aborted_transaction(const char *isolation_level) {
        char topic_suffix[64];
        const char *topic;
        char group[128];
        const char *txn_id = "txn-abort-test";
        const int msg_cnt  = 100;
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        int consumed;
        int expected_msgs;
        rd_bool_t is_read_committed =
            !strcmp(isolation_level, "read_committed");

        rd_snprintf(topic_suffix, sizeof(topic_suffix), "0177-txn-abort-%s",
                    isolation_level);
        topic = test_mk_topic_name(topic_suffix, 1);
        rd_snprintf(group, sizeof(group), "share-txn-abort-%s",
                    isolation_level);

        SUB_TEST("isolation.level=%s", isolation_level);

        /* Expected messages depend on isolation level:
         * - read_committed: 0 (aborted messages filtered)
         * - read_uncommitted: msg_cnt (all messages visible) */
        expected_msgs = is_read_committed ? 0 : msg_cnt;

        /* Create topic */
        test_create_topic(NULL, topic, 1, -1);

        /* Create transactional producer */
        producer = create_txn_producer(txn_id);

        /* Create share consumer and set group config */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, isolation_level);
        subscribe_share_consumer(consumer, topic);

        /* Begin transaction */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));

        /* Produce messages */
        TEST_SAY("Producing %d messages in transaction\n", msg_cnt);
        test_curr->ignore_dr_err = rd_true; /* Aborted messages may fail */
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);

        /* Abort transaction */
        TEST_SAY("Aborting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer, 30000));
        test_curr->ignore_dr_err = rd_false;

        /* Consume messages */
        TEST_SAY("Consuming messages via share consumer (%s), expecting %d\n",
                 isolation_level, expected_msgs);

        if (is_read_committed) {
                consumed = consume_share_no_msgs(consumer, 10, 2000);
        } else {
                consumed =
                    consume_share_messages(consumer, expected_msgs, 50, 3000);
        }

        TEST_ASSERT(consumed == expected_msgs,
                    "[%s] Expected %d messages from aborted transaction, "
                    "got %d",
                    isolation_level, expected_msgs, consumed);

        TEST_SAY(
            "SUCCESS [%s]: Share consumer received %d messages "
            "(expected %d)\n",
            isolation_level, consumed, expected_msgs);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Test mixed transactions (some committed, some aborted).
 *
 * - read_committed: Only see committed messages
 * - read_uncommitted: See ALL messages
 */
static void do_test_mixed_transactions(const char *isolation_level) {
        char topic_suffix[64];
        const char *topic;
        char group[128];
        const char *txn_id = "txn-mixed-test";
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        int consumed;
        int i;
        int expected_committed = 0;
        int expected_total     = 0;
        int expected_msgs;
        rd_bool_t is_read_committed =
            !strcmp(isolation_level, "read_committed");

        /* Define transaction scenarios */
        struct {
                const char *desc;
                rd_bool_t commit;
                int msg_cnt;
        } txns[] = {
            {"Commit 50 msgs", rd_true, 50}, {"Abort 50 msgs", rd_false, 50},
            {"Commit 30 msgs", rd_true, 30}, {"Abort 20 msgs", rd_false, 20},
            {"Commit 40 msgs", rd_true, 40},
        };
        const int txn_cnt = sizeof(txns) / sizeof(txns[0]);

        rd_snprintf(topic_suffix, sizeof(topic_suffix), "0177-txn-mixed-%s",
                    isolation_level);
        topic = test_mk_topic_name(topic_suffix, 1);
        rd_snprintf(group, sizeof(group), "share-txn-mixed-%s",
                    isolation_level);

        SUB_TEST("isolation.level=%s", isolation_level);

        /* Create topic */
        test_create_topic(NULL, topic, 1, -1);

        /* Create transactional producer */
        producer = create_txn_producer(txn_id);

        /* Create share consumer and set group config */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, isolation_level);
        subscribe_share_consumer(consumer, topic);

        /* Execute transactions */
        for (i = 0; i < txn_cnt; i++) {
                TEST_SAY("Transaction %d: %s\n", i + 1, txns[i].desc);

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));

                test_curr->ignore_dr_err = !txns[i].commit;
                test_produce_msgs2(producer, topic, test_id_generate(),
                                   RD_KAFKA_PARTITION_UA, 0, txns[i].msg_cnt,
                                   NULL, 0);

                if (txns[i].commit) {
                        TEST_CALL_ERROR__(
                            rd_kafka_commit_transaction(producer, 30000));
                        expected_committed += txns[i].msg_cnt;
                } else {
                        TEST_CALL_ERROR__(
                            rd_kafka_abort_transaction(producer, 30000));
                }
                expected_total += txns[i].msg_cnt;
                test_curr->ignore_dr_err = rd_false;
        }

        /* Expected depends on isolation level */
        expected_msgs = is_read_committed ? expected_committed : expected_total;

        TEST_SAY("Expected messages [%s]: %d (committed=%d, total=%d)\n",
                 isolation_level, expected_msgs, expected_committed,
                 expected_total);

        /* Consume messages */
        consumed = consume_share_messages(consumer, expected_msgs, 100, 3000);

        TEST_ASSERT(consumed == expected_msgs,
                    "[%s] Expected %d messages, got %d", isolation_level,
                    expected_msgs, consumed);

        TEST_SAY("SUCCESS [%s]: Share consumer received %d messages\n",
                 isolation_level, consumed);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Test control records filtering.
 *
 * Control records (abort/commit markers) should never be visible to the
 * application, regardless of isolation level.
 */
static void do_test_control_records_filtered(const char *isolation_level) {
        char topic_suffix[64];
        const char *topic;
        char group[128];
        const char *txn_id = "txn-ctrl-test";
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        int expected_msgs;
        rd_bool_t is_read_committed =
            !strcmp(isolation_level, "read_committed");

        rd_snprintf(topic_suffix, sizeof(topic_suffix), "0177-txn-ctrl-%s",
                    isolation_level);
        topic = test_mk_topic_name(topic_suffix, 1);
        rd_snprintf(group, sizeof(group), "share-txn-ctrl-%s", isolation_level);

        SUB_TEST("isolation.level=%s", isolation_level);

        /* Create topic */
        test_create_topic(NULL, topic, 1, -1);

        /* Create transactional producer */
        producer = create_txn_producer(txn_id);

        /* Create share consumer and set group config */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, isolation_level);
        subscribe_share_consumer(consumer, topic);

        /* Transaction 1: Produce and ABORT (1 msg + 1 abort marker) */
        TEST_SAY("Transaction 1: Produce 1 message, then ABORT\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_curr->ignore_dr_err = rd_true;
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, 1, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer, 30000));
        test_curr->ignore_dr_err = rd_false;

        /* Transaction 2: Produce and COMMIT (5 msgs + 1 commit marker) */
        TEST_SAY("Transaction 2: Produce 5 messages, then COMMIT\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, 5, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer, 30000));

        /*
         * Topic now contains:
         * - Offset 0: aborted message
         * - Offset 1: abort control record
         * - Offset 2-6: committed messages
         * - Offset 7: commit control record
         *
         * read_committed: should see offsets 2,3,4,5,6 (committed only)
         * read_uncommitted: should see offsets 0,2,3,4,5,6 (aborted +
         * committed) Control records (offsets 1 and 7) should NEVER be visible.
         */
        expected_msgs = is_read_committed ? 5 : 6;

        /* Consume and verify exact offsets */
        int64_t expected_offsets_committed[]   = {2, 3, 4, 5, 6};
        int64_t expected_offsets_uncommitted[] = {0, 2, 3, 4, 5, 6};
        int64_t control_record_offsets[]       = {1, 7};
        const int64_t *expected_offsets;

        expected_offsets = is_read_committed ? expected_offsets_committed
                                             : expected_offsets_uncommitted;

        consume_and_verify_offsets(consumer, expected_msgs, expected_offsets,
                                   control_record_offsets, 2, isolation_level);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Test multiple partitions with transactions.
 */
static void do_test_multi_partition_transactions(const char *isolation_level) {
        char topic_suffix[64];
        const char *topic;
        char group[128];
        const char *txn_id           = "txn-multipart-test";
        const int partition_cnt      = 3;
        const int msgs_per_partition = 30;
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        int consumed;
        int expected_committed;
        int expected_total;
        int expected_msgs;
        rd_bool_t is_read_committed =
            !strcmp(isolation_level, "read_committed");

        rd_snprintf(topic_suffix, sizeof(topic_suffix), "0177-txn-multipart-%s",
                    isolation_level);
        topic = test_mk_topic_name(topic_suffix, 1);
        rd_snprintf(group, sizeof(group), "share-txn-multipart-%s",
                    isolation_level);

        SUB_TEST("isolation.level=%s", isolation_level);

        /* Create topic with multiple partitions */
        test_create_topic(NULL, topic, partition_cnt, -1);

        /* Create transactional producer */
        producer = create_txn_producer(txn_id);

        /* Create share consumer and set group config */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, isolation_level);
        subscribe_share_consumer(consumer, topic);

        /* Transaction 1: Produce to all partitions and COMMIT */
        TEST_SAY("Transaction 1: Produce to all partitions, COMMIT\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0,
                           msgs_per_partition * partition_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer, 30000));

        /* Transaction 2: Produce to all partitions and ABORT */
        TEST_SAY("Transaction 2: Produce to all partitions, ABORT\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_curr->ignore_dr_err = rd_true;
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0,
                           msgs_per_partition * partition_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer, 30000));
        test_curr->ignore_dr_err = rd_false;

        /* Transaction 3: Produce to all partitions and COMMIT */
        TEST_SAY("Transaction 3: Produce to all partitions, COMMIT\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0,
                           msgs_per_partition * partition_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer, 30000));

        /* Calculate expected messages */
        expected_committed = 2 * msgs_per_partition * partition_cnt;
        expected_total     = 3 * msgs_per_partition * partition_cnt;
        expected_msgs = is_read_committed ? expected_committed : expected_total;

        TEST_SAY("Expected messages [%s]: %d\n", isolation_level,
                 expected_msgs);

        consumed = consume_share_messages(consumer, expected_msgs, 100, 3000);

        TEST_ASSERT(consumed == expected_msgs,
                    "[%s] Expected %d messages, got %d", isolation_level,
                    expected_msgs, consumed);

        TEST_SAY("SUCCESS [%s]: Share consumer received %d messages\n",
                 isolation_level, consumed);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Test interleaved transactions from multiple producers.
 */
static void do_test_interleaved_producers(const char *isolation_level) {
        char topic_suffix[64];
        const char *topic;
        char group[128];
        const int msg_cnt = 50;
        rd_kafka_t *producer1, *producer2;
        rd_kafka_share_t *consumer;
        int consumed;
        int expected_msgs;
        rd_bool_t is_read_committed =
            !strcmp(isolation_level, "read_committed");

        rd_snprintf(topic_suffix, sizeof(topic_suffix),
                    "0177-txn-interleave-%s", isolation_level);
        topic = test_mk_topic_name(topic_suffix, 1);
        rd_snprintf(group, sizeof(group), "share-txn-interleave-%s",
                    isolation_level);

        SUB_TEST("isolation.level=%s", isolation_level);

        /* Create topic */
        test_create_topic(NULL, topic, 1, -1);

        /* Create two transactional producers */
        producer1 = create_txn_producer("txn-producer-1");
        producer2 = create_txn_producer("txn-producer-2");

        /* Create share consumer and set group config */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, isolation_level);
        subscribe_share_consumer(consumer, topic);

        /* Producer 1: Begin transaction */
        TEST_SAY("Producer 1: Begin transaction\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer1));

        /* Producer 2: Begin transaction */
        TEST_SAY("Producer 2: Begin transaction\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer2));

        /* Producer 1: Produce messages */
        TEST_SAY("Producer 1: Produce %d messages\n", msg_cnt);
        test_produce_msgs2(producer1, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);

        /* Producer 2: Produce messages */
        TEST_SAY("Producer 2: Produce %d messages\n", msg_cnt);
        test_curr->ignore_dr_err = rd_true;
        test_produce_msgs2(producer2, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);

        /* Producer 1: COMMIT */
        TEST_SAY("Producer 1: COMMIT\n");
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer1, 30000));

        /* Producer 2: ABORT */
        TEST_SAY("Producer 2: ABORT\n");
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer2, 30000));
        test_curr->ignore_dr_err = rd_false;

        /* Expected: read_committed sees only producer1's msgs,
         * read_uncommitted sees both */
        expected_msgs = is_read_committed ? msg_cnt : (2 * msg_cnt);

        consumed = consume_share_messages(consumer, expected_msgs, 50, 3000);

        TEST_ASSERT(consumed == expected_msgs,
                    "[%s] Expected %d messages, got %d", isolation_level,
                    expected_msgs, consumed);

        TEST_SAY("SUCCESS [%s]: Share consumer received %d messages\n",
                 isolation_level, consumed);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer1);
        rd_kafka_destroy(producer2);

        SUB_TEST_PASS();
}


/**
 * @brief Test non-transactional and transactional messages mixed.
 */
static void do_test_mixed_txn_non_txn(const char *isolation_level) {
        char topic_suffix[64];
        const char *topic;
        char group[128];
        const char *txn_id        = "txn-mixed-type-test";
        const int non_txn_msgs    = 50;
        const int txn_commit_msgs = 30;
        const int txn_abort_msgs  = 20;
        rd_kafka_t *txn_producer;
        rd_kafka_share_t *consumer;
        int consumed;
        int expected_msgs;
        rd_bool_t is_read_committed =
            !strcmp(isolation_level, "read_committed");

        rd_snprintf(topic_suffix, sizeof(topic_suffix),
                    "0177-txn-mixed-type-%s", isolation_level);
        topic = test_mk_topic_name(topic_suffix, 1);
        rd_snprintf(group, sizeof(group), "share-txn-mixed-type-%s",
                    isolation_level);

        SUB_TEST("isolation.level=%s", isolation_level);

        /* Create topic */
        test_create_topic(NULL, topic, 1, -1);

        /* Create transactional producer */
        txn_producer = create_txn_producer(txn_id);

        /* Create share consumer and set group config */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, isolation_level);
        subscribe_share_consumer(consumer, topic);

        /* Produce non-transactional messages */
        TEST_SAY("Producing %d non-transactional messages\n", non_txn_msgs);
        test_produce_msgs2(common_regular_producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, non_txn_msgs, NULL, 0);

        /* Transactional: Commit */
        TEST_SAY("Producing %d transactional messages (will commit)\n",
                 txn_commit_msgs);
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(txn_producer));
        test_produce_msgs2(txn_producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, txn_commit_msgs, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(txn_producer, 30000));

        /* Transactional: Abort */
        TEST_SAY("Producing %d transactional messages (will abort)\n",
                 txn_abort_msgs);
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(txn_producer));
        test_curr->ignore_dr_err = rd_true;
        test_produce_msgs2(txn_producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, txn_abort_msgs, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(txn_producer, 30000));
        test_curr->ignore_dr_err = rd_false;

        /* Expected:
         * read_committed: non-txn + committed = 50 + 30 = 80
         * read_uncommitted: all = 50 + 30 + 20 = 100 */
        expected_msgs = is_read_committed
                            ? (non_txn_msgs + txn_commit_msgs)
                            : (non_txn_msgs + txn_commit_msgs + txn_abort_msgs);

        TEST_SAY("Expected messages [%s]: %d\n", isolation_level,
                 expected_msgs);

        consumed = consume_share_messages(consumer, expected_msgs, 100, 3000);

        TEST_ASSERT(consumed == expected_msgs,
                    "[%s] Expected %d messages, got %d", isolation_level,
                    expected_msgs, consumed);

        TEST_SAY("SUCCESS [%s]: Share consumer received %d messages\n",
                 isolation_level, consumed);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(txn_producer);

        SUB_TEST_PASS();
}


/**
 * @brief Test dynamic isolation level change (READ_UNCOMMITTED ->
 * READ_COMMITTED).
 *
 * 1. Start with READ_UNCOMMITTED
 * 2. Produce committed txn, consume and acknowledge
 * 3. Produce aborted txn, consume and release
 * 4. Change to READ_COMMITTED
 * 5. Produce more committed/aborted txns
 * 6. Verify only committed txns are now returned
 */
static void do_test_dynamic_uncommitted_to_committed(void) {
        const char *topic;
        const char *group  = "share-dynamic-uc-to-c";
        const char *txn_id = "txn-dynamic-uc-c";
        const int msg_cnt  = 10;
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        int consumed;

        SUB_TEST();

        topic = test_mk_topic_name("0177-dynamic-uc-to-c", 1);

        /* Create topic */
        test_create_topic(NULL, topic, 1, -1);

        /* Create transactional producer */
        producer = create_txn_producer(txn_id);

        /* Create share consumer with READ_UNCOMMITTED */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, "read_uncommitted");
        subscribe_share_consumer(consumer, topic);

        /* Phase 1: Produce and consume committed transaction */
        TEST_SAY("Phase 1: Committed transaction with READ_UNCOMMITTED\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer, 30000));

        consumed = consume_share_messages(consumer, msg_cnt, 50, 3000);
        TEST_ASSERT(consumed == msg_cnt,
                    "Phase 1: Expected %d committed msgs, got %d", msg_cnt,
                    consumed);

        /* Phase 2: Produce aborted transaction - should be visible in
         * READ_UNCOMMITTED */
        TEST_SAY("Phase 2: Aborted transaction with READ_UNCOMMITTED\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_curr->ignore_dr_err = rd_true;
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer, 30000));
        test_curr->ignore_dr_err = rd_false;

        consumed = consume_share_messages(consumer, msg_cnt, 50, 3000);
        TEST_ASSERT(consumed == msg_cnt,
                    "Phase 2: Expected %d aborted msgs (uncommitted mode), "
                    "got %d",
                    msg_cnt, consumed);

        /* Phase 3: Change isolation level to READ_COMMITTED */
        TEST_SAY("Phase 3: Changing isolation level to READ_COMMITTED\n");
        configure_share_group(group, "read_committed");

        /* Phase 4: Produce aborted transaction - should NOT be visible now */
        TEST_SAY("Phase 4: Aborted transaction with READ_COMMITTED\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_curr->ignore_dr_err = rd_true;
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer, 30000));
        test_curr->ignore_dr_err = rd_false;

        consumed = consume_share_no_msgs(consumer, 10, 2000);
        TEST_ASSERT(consumed == 0,
                    "Phase 4: Expected 0 aborted msgs (committed mode), got %d",
                    consumed);

        /* Phase 5: Produce committed transaction - should be visible */
        TEST_SAY("Phase 5: Committed transaction with READ_COMMITTED\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_produce_msgs2(producer, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer, 30000));

        consumed = consume_share_messages(consumer, msg_cnt, 50, 3000);
        TEST_ASSERT(consumed == msg_cnt,
                    "Phase 5: Expected %d committed msgs, got %d", msg_cnt,
                    consumed);

        TEST_SAY(
            "SUCCESS: Dynamic isolation change READ_UNCOMMITTED -> "
            "READ_COMMITTED works correctly\n");

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Test interval-based abort pattern.
 *
 * Produce N transactions where every Kth one is aborted.
 * Verify READ_COMMITTED skips exactly the aborted ones.
 * Verify READ_UNCOMMITTED sees all.
 */
static void do_test_interval_abort_pattern(const char *isolation_level) {
        char topic_suffix[64];
        const char *topic;
        char group[128];
        const char *txn_id       = "txn-interval-abort";
        const int total_txns     = 20;
        const int abort_interval = 5; /* Every 5th transaction is aborted */
        const int msgs_per_txn   = 5;
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        int consumed;
        int i;
        int committed_txns = 0;
        int aborted_txns   = 0;
        int expected_msgs;
        rd_bool_t is_read_committed =
            !strcmp(isolation_level, "read_committed");

        rd_snprintf(topic_suffix, sizeof(topic_suffix), "0177-interval-%s",
                    isolation_level);
        topic = test_mk_topic_name(topic_suffix, 1);
        rd_snprintf(group, sizeof(group), "share-interval-%s", isolation_level);

        SUB_TEST("isolation.level=%s", isolation_level);

        /* Create topic */
        test_create_topic(NULL, topic, 1, -1);

        /* Create transactional producer */
        producer = create_txn_producer(txn_id);

        /* Create share consumer and set group config */
        consumer = test_create_share_consumer(group, NULL);
        configure_share_group(group, isolation_level);
        subscribe_share_consumer(consumer, topic);

        /* Produce transactions with interval-based abort pattern */
        TEST_SAY("Producing %d transactions (every %dth is aborted)\n",
                 total_txns, abort_interval);

        for (i = 1; i <= total_txns; i++) {
                rd_bool_t should_abort = (i % abort_interval == 0);

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));

                if (should_abort)
                        test_curr->ignore_dr_err = rd_true;

                test_produce_msgs2(producer, topic, test_id_generate(),
                                   RD_KAFKA_PARTITION_UA, 0, msgs_per_txn, NULL,
                                   0);

                if (should_abort) {
                        TEST_CALL_ERROR__(
                            rd_kafka_abort_transaction(producer, 30000));
                        test_curr->ignore_dr_err = rd_false;
                        aborted_txns++;
                        TEST_SAY("  Transaction %d: ABORTED\n", i);
                } else {
                        TEST_CALL_ERROR__(
                            rd_kafka_commit_transaction(producer, 30000));
                        committed_txns++;
                }
        }

        TEST_SAY("Produced: %d committed txns, %d aborted txns\n",
                 committed_txns, aborted_txns);

        /* Calculate expected messages */
        if (is_read_committed) {
                expected_msgs = committed_txns * msgs_per_txn;
        } else {
                expected_msgs = total_txns * msgs_per_txn;
        }

        TEST_SAY("[%s] Expected %d messages\n", isolation_level, expected_msgs);

        /* Consume and verify */
        consumed = consume_share_messages(consumer, expected_msgs, 200, 3000);

        TEST_ASSERT(consumed == expected_msgs,
                    "[%s] Expected %d messages, got %d", isolation_level,
                    expected_msgs, consumed);

        /* Verify no extra messages */
        {
                int extra = consume_share_no_msgs(consumer, 5, 2000);
                TEST_ASSERT(extra == 0, "[%s] Unexpected extra messages: %d",
                            isolation_level, extra);
        }

        TEST_SAY(
            "SUCCESS [%s]: Interval abort pattern - received exactly %d "
            "messages (committed=%d, aborted=%d txns)\n",
            isolation_level, consumed, committed_txns, aborted_txns);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Produce exactly one transactional record carrying \p value, then
 *        commit (\p commit=rd_true) or abort the transaction.
 */
static void produce_msg_txn(rd_kafka_t *producer,
                            const char *topic,
                            const char *value,
                            rd_bool_t commit) {
        rd_kafka_resp_err_t err;

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));

        if (!commit)
                test_curr->ignore_dr_err = rd_true;

        err = rd_kafka_producev(producer, RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_VALUE((void *)value, strlen(value)),
                                RD_KAFKA_V_END);
        TEST_ASSERT(!err, "producev failed: %s", rd_kafka_err2name(err));
        rd_kafka_flush(producer, 30000);

        if (commit)
                TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer, 30000));
        else
                TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer, 30000));

        test_curr->ignore_dr_err = rd_false;
}


/**
 * @brief Test: dynamic isolation level change READ_COMMITTED ->
 *        READ_UNCOMMITTED with RELEASE acknowledgement on a committed
 *        record.
 *
 * Phase 1: produce committed Msg1, consume + ACCEPT.
 * Phase 2: produce aborted Msg2 (no records visible in read_committed).
 * Phase 3: produce committed Msg3, consume + RELEASE.
 * Phase 4: produce aborted Msg4. Released Msg3 may reappear; keep RELEASE-ing
 *          it so the broker can advance past the abort marker.
 * Phase 5: alter isolation level to read_uncommitted.
 * Phase 6: produce committed Msg5, aborted Msg6, aborted Msg7, committed Msg8.
 * Phase 7: consume; the released Msg3 (offset 4) plus the four new messages
 *          (offsets 8, 10, 12, 14) should all be visible -> 5 unique offsets.
 *
 * With one record per transaction, the offset layout is:
 *   0  Msg1 (commit marker 1)
 *   2  Msg2 (abort  marker 3)
 *   4  Msg3 (commit marker 5)
 *   6  Msg4 (abort  marker 7)
 *   8  Msg5 (commit marker 9)
 *  10  Msg6 (abort  marker 11)
 *  12  Msg7 (abort  marker 13)
 *  14  Msg8 (commit marker 15)
 */
static void do_test_dynamic_committed_to_uncommitted_with_release(void) {
        const char *topic;
        const char *group  = "share-dynamic-c-to-uc-release";
        const char *txn_id = "txn-dynamic-c-uc-release";
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t ack_err;
        size_t rcvd, j;
        int attempts;
        int consumed;
        rd_bool_t seen[20]               = {0};
        const int64_t expected_offsets[] = {4, 8, 10, 12, 14};
        size_t i;

        SUB_TEST();

        topic = test_mk_topic_name("0177-dyn-c-uc-release", 1);
        test_create_topic(NULL, topic, 1, -1);

        producer = create_txn_producer(txn_id);

        consumer = test_create_share_consumer(group, "explicit");
        configure_share_group(group, "read_committed");
        subscribe_share_consumer(consumer, topic);

        /* Phase 1: committed Msg1 -> ACCEPT */
        TEST_SAY("Phase 1: committed Msg1 with READ_COMMITTED\n");
        produce_msg_txn(producer, topic, "Message 1", rd_true);
        consumed = 0;
        attempts = 0;
        while (consumed == 0 && attempts++ < 30) {
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                TEST_ASSERT(msg->offset == 0,
                                            "Phase 1: expected offset 0, "
                                            "got %" PRId64,
                                            msg->offset);
                                ack_err = rd_kafka_share_acknowledge_type(
                                    consumer, msg,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                                TEST_ASSERT(ack_err ==
                                                RD_KAFKA_RESP_ERR_NO_ERROR,
                                            "Phase 1 ACCEPT failed: %s",
                                            rd_kafka_err2name(ack_err));
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed == 1, "Phase 1: expected 1 record, got %d",
                    consumed);
        error = rd_kafka_share_commit_async(consumer);
        TEST_ASSERT(!error, "Phase 1 commit_async failed");

        /* Phase 2: aborted Msg2 - read_committed should hide the record;
         * the broker eventually advances past the abort marker. */
        TEST_SAY("Phase 2: aborted Msg2 (read_committed hides it)\n");
        produce_msg_txn(producer, topic, "Message 2", rd_false);
        attempts = 10;
        while (attempts-- > 0) {
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 500, &batch);
                if (error)
                        rd_kafka_error_destroy(error);
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        TEST_ASSERT(msg->err || msg->offset != 2,
                                    "Phase 2: aborted Msg2 leaked at "
                                    "offset 2 in read_committed");
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Phase 3: committed Msg3 -> RELEASE */
        TEST_SAY("Phase 3: committed Msg3 -> RELEASE\n");
        produce_msg_txn(producer, topic, "Message 3", rd_true);
        consumed = 0;
        attempts = 0;
        while (consumed == 0 && attempts++ < 30) {
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                TEST_ASSERT(msg->offset == 4,
                                            "Phase 3: expected offset 4 "
                                            "(Msg3), got %" PRId64,
                                            msg->offset);
                                ack_err = rd_kafka_share_acknowledge_type(
                                    consumer, msg,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
                                TEST_ASSERT(ack_err ==
                                                RD_KAFKA_RESP_ERR_NO_ERROR,
                                            "Phase 3 RELEASE failed: %s",
                                            rd_kafka_err2name(ack_err));
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed == 1, "Phase 3: expected 1 record, got %d",
                    consumed);
        error = rd_kafka_share_commit_async(consumer);
        TEST_ASSERT(!error, "Phase 3 commit_async failed");

        /* Phase 4: aborted Msg4. Released Msg3 may re-appear; RELEASE it
         * again so the next poll can advance. Keep this loop short: each
         * RELEASE-and-redeliver bumps Msg3's delivery_count. The default
         * share.delivery.count.limit is 5; Phase 3 already used one
         * delivery and Phase 7's final ACCEPT will need one, so cap
         * Phase 4 at 3 redeliveries to leave headroom and avoid the
         * record being archived. */
        TEST_SAY("Phase 4: aborted Msg4; Msg3 may redeliver -> RELEASE\n");
        produce_msg_txn(producer, topic, "Message 4", rd_false);
        attempts = 3;
        while (attempts-- > 0) {
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 1000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                /* Should only be Msg3 (offset 4) re-delivered;
                                 * Msg4 at offset 6 is aborted in
                                 * read_committed.
                                 */
                                TEST_ASSERT(
                                    msg->offset == 4,
                                    "Phase 4: unexpected offset %" PRId64,
                                    msg->offset);
                                ack_err = rd_kafka_share_acknowledge_type(
                                    consumer, msg,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE);
                                TEST_ASSERT(ack_err ==
                                                RD_KAFKA_RESP_ERR_NO_ERROR,
                                            "Phase 4 RELEASE failed: %s",
                                            rd_kafka_err2name(ack_err));
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                if (rcvd > 0) {
                        error = rd_kafka_share_commit_async(consumer);
                        if (error)
                                rd_kafka_error_destroy(error);
                }
        }

        /* Phase 5: alter isolation level to read_uncommitted */
        TEST_SAY("Phase 5: alter share.isolation.level to read_uncommitted\n");
        test_share_set_isolation_level(group, "read_uncommitted");

        /* Phase 6: produce 4 more transactions */
        TEST_SAY("Phase 6: produce Msg5..Msg8\n");
        produce_msg_txn(producer, topic, "Message 5", rd_true);
        produce_msg_txn(producer, topic, "Message 6", rd_false);
        produce_msg_txn(producer, topic, "Message 7", rd_false);
        produce_msg_txn(producer, topic, "Message 8", rd_true);

        /* Phase 7: expect to see 5 unique offsets: 4 (released Msg3),
         * 8, 10, 12, 14 (Msg5..Msg8). */
        TEST_SAY("Phase 7: consume - expect offsets {4,8,10,12,14}\n");
        attempts = 0;
        while (attempts++ < 60) {
                int new_acks = 0;
                rd_bool_t all_seen;
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 2000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                int64_t off = msg->offset;
                                if (off >= 0 && off < 20)
                                        seen[off] = rd_true;
                                ack_err = rd_kafka_share_acknowledge_type(
                                    consumer, msg,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                                TEST_ASSERT(ack_err ==
                                                RD_KAFKA_RESP_ERR_NO_ERROR,
                                            "Phase 7 ACCEPT failed: %s",
                                            rd_kafka_err2name(ack_err));
                                new_acks++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                if (new_acks > 0) {
                        error = rd_kafka_share_commit_async(consumer);
                        if (error)
                                rd_kafka_error_destroy(error);
                }

                all_seen = rd_true;
                for (i = 0;
                     i < sizeof(expected_offsets) / sizeof(expected_offsets[0]);
                     i++) {
                        if (!seen[expected_offsets[i]]) {
                                all_seen = rd_false;
                                break;
                        }
                }
                if (all_seen)
                        break;
        }

        for (i = 0; i < sizeof(expected_offsets) / sizeof(expected_offsets[0]);
             i++) {
                TEST_ASSERT(seen[expected_offsets[i]],
                            "Phase 7: expected offset %" PRId64
                            " not seen after isolation change",
                            expected_offsets[i]);
        }

        TEST_SAY(
            "SUCCESS: dynamic READ_COMMITTED -> READ_UNCOMMITTED with "
            "RELEASE\n");

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Test: dynamic isolation level change READ_COMMITTED ->
 *        READ_UNCOMMITTED with REJECT acknowledgement on a committed
 *        record.
 *
 * Same setup as the RELEASE variant, except Msg3 is REJECTed instead of
 * RELEASEd. After the isolation level switch, Msg3 must NOT be redelivered;
 * only the four new messages are expected -> 4 unique offsets.
 */
static void do_test_dynamic_committed_to_uncommitted_with_reject(void) {
        const char *topic;
        const char *group  = "share-dynamic-c-to-uc-reject";
        const char *txn_id = "txn-dynamic-c-uc-reject";
        rd_kafka_t *producer;
        rd_kafka_share_t *consumer;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t ack_err;
        size_t rcvd, j;
        int attempts;
        int consumed;
        rd_bool_t seen[20]               = {0};
        const int64_t expected_offsets[] = {8, 10, 12, 14};
        size_t i;

        SUB_TEST();

        topic = test_mk_topic_name("0177-dyn-c-uc-reject", 1);
        test_create_topic(NULL, topic, 1, -1);

        producer = create_txn_producer(txn_id);

        consumer = test_create_share_consumer(group, "explicit");
        configure_share_group(group, "read_committed");
        subscribe_share_consumer(consumer, topic);

        /* Phase 1: committed Msg1 -> ACCEPT */
        TEST_SAY("Phase 1: committed Msg1 with READ_COMMITTED\n");
        produce_msg_txn(producer, topic, "Message 1", rd_true);
        consumed = 0;
        attempts = 0;
        while (consumed == 0 && attempts++ < 30) {
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                TEST_ASSERT(msg->offset == 0,
                                            "Phase 1: expected offset 0, "
                                            "got %" PRId64,
                                            msg->offset);
                                ack_err = rd_kafka_share_acknowledge_type(
                                    consumer, msg,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                                TEST_ASSERT(ack_err ==
                                                RD_KAFKA_RESP_ERR_NO_ERROR,
                                            "Phase 1 ACCEPT failed: %s",
                                            rd_kafka_err2name(ack_err));
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed == 1, "Phase 1: expected 1 record, got %d",
                    consumed);
        error = rd_kafka_share_commit_async(consumer);
        TEST_ASSERT(!error, "Phase 1 commit_async failed");

        /* Phase 2: aborted Msg2 */
        TEST_SAY("Phase 2: aborted Msg2 (read_committed hides it)\n");
        produce_msg_txn(producer, topic, "Message 2", rd_false);
        attempts = 10;
        while (attempts-- > 0) {
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 500, &batch);
                if (error)
                        rd_kafka_error_destroy(error);
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        TEST_ASSERT(msg->err || msg->offset != 2,
                                    "Phase 2: aborted Msg2 leaked at "
                                    "offset 2 in read_committed");
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Phase 3: committed Msg3 -> REJECT */
        TEST_SAY("Phase 3: committed Msg3 -> REJECT\n");
        produce_msg_txn(producer, topic, "Message 3", rd_true);
        consumed = 0;
        attempts = 0;
        while (consumed == 0 && attempts++ < 30) {
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 3000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                TEST_ASSERT(msg->offset == 4,
                                            "Phase 3: expected offset 4 "
                                            "(Msg3), got %" PRId64,
                                            msg->offset);
                                ack_err = rd_kafka_share_acknowledge_type(
                                    consumer, msg,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT);
                                TEST_ASSERT(ack_err ==
                                                RD_KAFKA_RESP_ERR_NO_ERROR,
                                            "Phase 3 REJECT failed: %s",
                                            rd_kafka_err2name(ack_err));
                                consumed++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(consumed == 1, "Phase 3: expected 1 record, got %d",
                    consumed);
        error = rd_kafka_share_commit_async(consumer);
        TEST_ASSERT(!error, "Phase 3 commit_async failed");

        /* Phase 4: aborted Msg4. Msg3 was REJECTed so it should not return.
         * Just poll for a while to let the broker process the abort marker. */
        TEST_SAY("Phase 4: aborted Msg4 (Msg3 was REJECTed)\n");
        produce_msg_txn(producer, topic, "Message 4", rd_false);
        attempts = 20;
        while (attempts-- > 0) {
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 500, &batch);
                if (error)
                        rd_kafka_error_destroy(error);
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                TEST_FAIL(
                                    "Phase 4: unexpected record at "
                                    "offset %" PRId64
                                    " (Msg3 was REJECTed, Msg4 is "
                                    "aborted in read_committed)",
                                    msg->offset);
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        /* Phase 5: alter isolation level to read_uncommitted */
        TEST_SAY("Phase 5: alter share.isolation.level to read_uncommitted\n");
        test_share_set_isolation_level(group, "read_uncommitted");

        /* Phase 6: produce 4 more transactions */
        TEST_SAY("Phase 6: produce Msg5..Msg8\n");
        produce_msg_txn(producer, topic, "Message 5", rd_true);
        produce_msg_txn(producer, topic, "Message 6", rd_false);
        produce_msg_txn(producer, topic, "Message 7", rd_false);
        produce_msg_txn(producer, topic, "Message 8", rd_true);

        /* Phase 7: expect offsets {8, 10, 12, 14}. Msg3 (offset 4) must NOT
         * reappear because it was REJECTed. */
        TEST_SAY("Phase 7: consume - expect offsets {8,10,12,14}, no Msg3\n");
        attempts = 0;
        while (attempts++ < 60) {
                int new_acks = 0;
                rd_bool_t all_seen;
                rcvd  = 0;
                error = rd_kafka_share_poll(consumer, 2000, &batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                int64_t off = msg->offset;
                                TEST_ASSERT(off != 4,
                                            "Phase 7: Msg3 (offset 4) "
                                            "should not be redelivered "
                                            "after REJECT");
                                if (off >= 0 && off < 20)
                                        seen[off] = rd_true;
                                ack_err = rd_kafka_share_acknowledge_type(
                                    consumer, msg,
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                                TEST_ASSERT(ack_err ==
                                                RD_KAFKA_RESP_ERR_NO_ERROR,
                                            "Phase 7 ACCEPT failed: %s",
                                            rd_kafka_err2name(ack_err));
                                new_acks++;
                        }
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                if (new_acks > 0) {
                        error = rd_kafka_share_commit_async(consumer);
                        if (error)
                                rd_kafka_error_destroy(error);
                }

                all_seen = rd_true;
                for (i = 0;
                     i < sizeof(expected_offsets) / sizeof(expected_offsets[0]);
                     i++) {
                        if (!seen[expected_offsets[i]]) {
                                all_seen = rd_false;
                                break;
                        }
                }
                if (all_seen)
                        break;
        }

        for (i = 0; i < sizeof(expected_offsets) / sizeof(expected_offsets[0]);
             i++) {
                TEST_ASSERT(seen[expected_offsets[i]],
                            "Phase 7: expected offset %" PRId64
                            " not seen after isolation change",
                            expected_offsets[i]);
        }
        TEST_ASSERT(!seen[4],
                    "Phase 7: Msg3 (offset 4) appeared but it was REJECTed");

        TEST_SAY(
            "SUCCESS: dynamic READ_COMMITTED -> READ_UNCOMMITTED with "
            "REJECT\n");

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);
        rd_kafka_destroy(producer);

        SUB_TEST_PASS();
}


/**
 * @brief Two share groups, different isolation levels, same topic.
 *
 * share.isolation.level is a BROKER-SIDE group config — consumers in
 * the SAME group cannot have different isolation levels. This test
 * exercises two distinct groups consuming the same topic concurrently
 * with different isolation levels.
 *
 * Producer mix on the topic:
 *   - txn-A committed: 100 records
 *   - txn-B aborted:   100 records
 *   - txn-C committed: 100 records
 *
 * Expected:
 *   - Group G1 (read_committed):   sees 200 records (A+C only)
 *   - Group G2 (read_uncommitted): sees 300 records (A+B+C)
 */
static void do_test_two_groups_different_isolation_levels(void) {
        const char *topic;
        const char *grp_committed   = "share-txn-twogroup-rc";
        const char *grp_uncommitted = "share-txn-twogroup-ru";
        rd_kafka_t *producer_a;
        rd_kafka_t *producer_b;
        rd_kafka_t *producer_c;
        rd_kafka_share_t *c_committed;
        rd_kafka_share_t *c_uncommitted;
        const int msg_cnt     = 100;
        const int expected_rc = 2 * msg_cnt;
        const int expected_ru = 3 * msg_cnt;
        int consumed_rc;
        int consumed_ru;

        SUB_TEST("two groups, different isolation levels");

        topic = test_mk_topic_name("0177-twogroup-iso", 1);
        test_create_topic(NULL, topic, 1, -1);

        producer_a = create_txn_producer("twogroup-iso-A");
        producer_b = create_txn_producer("twogroup-iso-B");
        producer_c = create_txn_producer("twogroup-iso-C");

        /* Subscribe both consumers BEFORE producing so they're ready to
         * consume from the earliest offset. */
        c_committed = test_create_share_consumer(grp_committed, NULL);
        configure_share_group(grp_committed, "read_committed");
        subscribe_share_consumer(c_committed, topic);

        c_uncommitted = test_create_share_consumer(grp_uncommitted, NULL);
        configure_share_group(grp_uncommitted, "read_uncommitted");
        subscribe_share_consumer(c_uncommitted, topic);

        /* txn-A: committed */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer_a));
        test_produce_msgs2(producer_a, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer_a, 30000));

        /* txn-B: aborted */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer_b));
        test_curr->ignore_dr_err = rd_true;
        test_produce_msgs2(producer_b, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer_b, 30000));
        test_curr->ignore_dr_err = rd_false;

        /* txn-C: committed */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer_c));
        test_produce_msgs2(producer_c, topic, test_id_generate(),
                           RD_KAFKA_PARTITION_UA, 0, msg_cnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer_c, 30000));

        /* Both groups consume the same topic concurrently. */
        TEST_SAY("Consuming via read_committed group\n");
        consumed_rc =
            consume_share_messages(c_committed, expected_rc, 80, 3000);
        TEST_SAY("Consuming via read_uncommitted group\n");
        consumed_ru =
            consume_share_messages(c_uncommitted, expected_ru, 80, 3000);

        TEST_SAY(
            "Result: read_committed=%d (expected %d), "
            "read_uncommitted=%d (expected %d)\n",
            consumed_rc, expected_rc, consumed_ru, expected_ru);

        TEST_ASSERT(consumed_rc == expected_rc,
                    "read_committed group expected %d records, got %d",
                    expected_rc, consumed_rc);
        TEST_ASSERT(consumed_ru == expected_ru,
                    "read_uncommitted group expected %d records, got %d",
                    expected_ru, consumed_ru);

        test_share_consumer_close(c_committed);
        test_share_destroy(c_committed);
        test_share_consumer_close(c_uncommitted);
        test_share_destroy(c_uncommitted);
        rd_kafka_destroy(producer_a);
        rd_kafka_destroy(producer_b);
        rd_kafka_destroy(producer_c);

        SUB_TEST_PASS();
}


int main_0177_share_consumer_transactions(int argc, char **argv) {
        /* Test both isolation levels */
        const char *isolation_levels[] = {"read_committed", "read_uncommitted"};
        int i;

        test_timeout_set(200);

        /* Create common handles for all tests */
        common_admin            = test_create_producer();
        common_regular_producer = test_create_producer();

        for (i = 0; i < 2; i++) {
                const char *level = isolation_levels[i];

                TEST_SAY("\n");
                TEST_SAY("========================================\n");
                TEST_SAY("Testing with isolation.level=%s\n", level);
                TEST_SAY("========================================\n");

                /* Basic transaction tests */
                do_test_committed_transaction(level);
                do_test_aborted_transaction(level);
                do_test_mixed_transactions(level);

                /* Control records filtering */
                do_test_control_records_filtered(level);

                /* Multi-partition and multi-producer scenarios */
                do_test_multi_partition_transactions(level);
                do_test_interleaved_producers(level);

                /* Mixed workloads */
                do_test_mixed_txn_non_txn(level);

                /* Interval-based abort pattern */
                do_test_interval_abort_pattern(level);
        }

        /* Dynamic isolation level change tests (run once, not per-level) */
        TEST_SAY("\n");
        TEST_SAY("========================================\n");
        TEST_SAY("Testing dynamic isolation level changes\n");
        TEST_SAY("========================================\n");

        do_test_dynamic_uncommitted_to_committed();
        do_test_dynamic_committed_to_uncommitted_with_release();
        do_test_dynamic_committed_to_uncommitted_with_reject();

        /* Two-groups, different isolation levels on the same topic */
        do_test_two_groups_different_isolation_levels();

        /* Cleanup common handles */
        rd_kafka_destroy(common_admin);
        rd_kafka_destroy(common_regular_producer);

        return 0;
}
