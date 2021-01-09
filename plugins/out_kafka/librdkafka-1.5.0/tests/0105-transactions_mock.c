/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
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
#include "../src/rdunittest.h"

#include <stdarg.h>


/**
 * @name Producer transaction tests using the mock cluster
 *
 */


static int allowed_error;

/**
 * @brief Decide what error_cb's will cause the test to fail.
 */
static int error_is_fatal_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                              const char *reason) {
        if (err == allowed_error) {
                TEST_SAY("Ignoring allowed error: %s: %s\n",
                         rd_kafka_err2name(err), reason);
                return 0;
        }
        return 1;
}



/**
 * @brief Create a transactional producer and a mock cluster.
 *
 * The var-arg list is a NULL-terminated list of
 * (const char *key, const char *value) config properties.
 */
static rd_kafka_t *create_txn_producer (rd_kafka_mock_cluster_t **mclusterp,
                                        const char *transactional_id,
                                        int broker_cnt, ...) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        char numstr[8];
        va_list ap;
        const char *key;

        rd_snprintf(numstr, sizeof(numstr), "%d", broker_cnt);

        test_conf_init(&conf, NULL, 0);

        test_conf_set(conf, "transactional.id", transactional_id);
        test_conf_set(conf, "test.mock.num.brokers", numstr);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        test_curr->ignore_dr_err = rd_false;

        va_start(ap, broker_cnt);
        while ((key = va_arg(ap, const char *)))
                test_conf_set(conf, key, va_arg(ap, const char *));
        va_end(ap);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        if (mclusterp) {
                *mclusterp = rd_kafka_handle_mock_cluster(rk);
                TEST_ASSERT(*mclusterp, "failed to create mock cluster");
        }

        return rk;
}


/**
 * @brief Test recoverable errors using mock broker error injections
 *        and code coverage checks.
 */
static void do_test_txn_recoverable_errors (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        const char *groupid = "myGroupId";
        const char *txnid = "myTxnId";

        TEST_SAY(_C_MAG "[ %s ]\n", __FUNCTION__);

        rk = create_txn_producer(&mcluster, txnid, 3, NULL);

        /* Make sure transaction and group coordinators are different.
         * This verifies that AddOffsetsToTxnRequest isn't sent to the
         * transaction coordinator but the group coordinator. */
        rd_kafka_mock_coordinator_set(mcluster, "group", groupid, 1);
        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid, 2);

        /*
         * Inject som InitProducerId errors that causes retries
         */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_InitProducerId,
                3,
                RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
                RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        (void)RD_UT_COVERAGE_CHECK(0); /* idemp_request_pid_failed(retry) */
        (void)RD_UT_COVERAGE_CHECK(1); /* txn_idemp_state_change(READY) */

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        /*
         * Produce a message, let it first fail on a fatal idempotent error
         * that is retryable by the transaction manager, then let it fail with
         * a non-idempo/non-txn retryable error
         */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_Produce,
                1,
                RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID,
                RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS);

        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2),
                                RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        /* Make sure messages are produced */
        rd_kafka_flush(rk, -1);

        /*
         * Send some arbitrary offsets, first with some failures, then
         * succeed.
         */
        offsets = rd_kafka_topic_partition_list_new(4);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->offset = 12;
        rd_kafka_topic_partition_list_add(offsets, "srctop2", 99)->offset =
                999999111;
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 0)->offset = 999;
        rd_kafka_topic_partition_list_add(offsets, "srctop2", 3499)->offset =
                123456789;

        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_AddPartitionsToTxn,
                1,
                RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);

        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_TxnOffsetCommit,
                2,
                RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(rd_kafka_send_offsets_to_transaction(
                                  rk, offsets,
                                  cgmetadata, -1));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        /*
         * Commit transaction, first with som failures, then succeed.
         */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_EndTxn,
                3,
                RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
                RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, 5000));

        /* All done */

        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "[ %s PASS ]\n", __FUNCTION__);
}


/**
 * @brief Test abortable errors using mock broker error injections
 *        and code coverage checks.
 */
static void do_test_txn_requires_abort_errors (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;

        TEST_SAY(_C_MAG "[ %s ]\n", __FUNCTION__);

        rk = create_txn_producer(&mcluster, "txnid", 3, NULL);

        test_curr->ignore_dr_err = rd_true;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        /*
         * 1. Fail on produce
         */
        TEST_SAY("1. Fail on produce\n");

        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_Produce,
                1,
                RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);

        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2),
                                RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        /* Wait for messages to fail */
        test_flush(rk, 5000);

        /* Any other transactional API should now raise an error */
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->offset = 12;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        error = rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                     cgmetadata, -1);

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);
        TEST_ASSERT(error, "expected error");
        TEST_ASSERT(rd_kafka_error_txn_requires_abort(error),
                    "expected abortable error, not %s",
                    rd_kafka_error_string(error));
        TEST_SAY("Error %s: %s\n",
                 rd_kafka_error_name(error),
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        /*
         * 2. Restart transaction and fail on AddPartitionsToTxn
         */
        TEST_SAY("2. Fail on AddPartitionsToTxn\n");

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_AddPartitionsToTxn,
                1,
                RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);

        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2),
                                RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        error = rd_kafka_commit_transaction(rk, 5000);
        TEST_ASSERT(error, "commit_transaction should have failed");
        TEST_SAY("commit_transaction() error %s: %s\n",
                 rd_kafka_error_name(error),
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        /*
        * 3. Restart transaction and fail on AddOffsetsToTxn
        */
        TEST_SAY("3. Fail on AddOffsetsToTxn\n");

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2),
                                RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_AddOffsetsToTxn,
                1,
                RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED);

        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->offset = 12;
        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        error = rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                     cgmetadata, -1);
        TEST_ASSERT(error, "Expected send_offsets..() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                    RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED,
                    "expected send_offsets_to_transaction() to fail with "
                    "group auth error: not %s",
                    rd_kafka_error_name(error));
        rd_kafka_error_destroy(error);

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);


        error = rd_kafka_commit_transaction(rk, 5000);
        TEST_ASSERT(error, "commit_transaction should have failed");
        rd_kafka_error_destroy(error);

        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        /* All done */

        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "[ %s PASS ]\n", __FUNCTION__);
}


/**
 * @brief Test error handling and recover for when broker goes down during
 *        an ongoing transaction.
 */
static void do_test_txn_broker_down_in_txn (rd_bool_t down_coord) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int32_t coord_id, leader_id, down_id;
        const char *down_what;
        rd_kafka_resp_err_t err;
        const char *topic = "test";
        const char *transactional_id = "txnid";
        int msgcnt = 1000;
        int remains = 0;

        /* Assign coordinator and leader to two different brokers */
        coord_id = 1;
        leader_id = 2;
        if (down_coord) {
                down_id = coord_id;
                down_what = "coordinator";
        } else {
                down_id = leader_id;
                down_what = "leader";
        }

        TEST_SAY(_C_MAG "[ Test %s down ]\n", down_what);

        rk = create_txn_producer(&mcluster, transactional_id, 3, NULL);

        /* Broker down is not a test-failing error */
        allowed_error = RD_KAFKA_RESP_ERR__TRANSPORT;
        test_curr->is_fatal_cb = error_is_fatal_cb;

        err = rd_kafka_mock_topic_create(mcluster, topic, 1, 3);
        TEST_ASSERT(!err, "Failed to create topic: %s", rd_kafka_err2str(err));

        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      coord_id);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, leader_id);

        /* Start transactioning */
        TEST_SAY("Starting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA,
                                  0, msgcnt / 2, NULL, 0, &remains);

        TEST_SAY("Bringing down %s %"PRId32"\n", down_what, down_id);
        rd_kafka_mock_broker_set_down(mcluster, down_id);

        rd_kafka_flush(rk, 3000);

        /* Produce remaining messages */
        test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA,
                                  msgcnt / 2, msgcnt / 2, NULL, 0, &remains);

        rd_sleep(2);

        TEST_SAY("Bringing up %s %"PRId32"\n", down_what, down_id);
        rd_kafka_mock_broker_set_up(mcluster, down_id);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

        TEST_ASSERT(remains == 0,
                    "%d message(s) were not produced\n", remains);

        rd_kafka_destroy(rk);

        test_curr->is_fatal_cb = NULL;

        TEST_SAY(_C_GRN "[ Test %s down: PASS ]\n", down_what);

}



/**
 * @brief Advance the coord_id to the next broker.
 */
static void set_next_coord (rd_kafka_mock_cluster_t *mcluster,
                            const char *transactional_id, int broker_cnt,
                            int32_t *coord_idp) {
        int32_t new_coord_id;

        new_coord_id = 1 + ((*coord_idp) % (broker_cnt));
        TEST_SAY("Changing transaction coordinator from %"PRId32
                 " to %"PRId32"\n", *coord_idp, new_coord_id);
        rd_kafka_mock_coordinator_set(mcluster, "transaction",
                                      transactional_id, new_coord_id);

        *coord_idp = new_coord_id;
}

/**
 * @brief Switch coordinator during a transaction.
 *
 * @remark Currently fails due to insufficient coord switch handling.
 */
static void do_test_txn_switch_coordinator (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int32_t coord_id;
        const char *topic = "test";
        const char *transactional_id = "txnid";
        const int broker_cnt = 5;
        const int iterations = 20;
        int i;

        test_timeout_set(iterations * 10);

        TEST_SAY(_C_MAG "[ Test switching coordinators ]\n");

        rk = create_txn_producer(&mcluster, transactional_id, broker_cnt, NULL);

        coord_id = 1;
        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      coord_id);

        /* Start transactioning */
        TEST_SAY("Starting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        for (i = 0 ; i < iterations ; i++) {
                const int msgcnt = 100;
                int remains = 0;

                set_next_coord(mcluster, transactional_id,
                               broker_cnt, &coord_id);

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                test_produce_msgs2(rk, topic, 0, RD_KAFKA_PARTITION_UA,
                                   0, msgcnt / 2, NULL, 0);

                if (!(i % 3))
                        set_next_coord(mcluster, transactional_id,
                                       broker_cnt, &coord_id);

                /* Produce remaining messages */
                test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA,
                                          msgcnt / 2, msgcnt / 2, NULL, 0,
                                          &remains);

                if ((i & 1) || !(i % 8))
                        set_next_coord(mcluster, transactional_id,
                                       broker_cnt, &coord_id);


                if (!(i % 5)) {
                        test_curr->ignore_dr_err = rd_false;
                        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

                } else {
                        test_curr->ignore_dr_err = rd_true;
                        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));
                }
        }


        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "[ Test switching coordinators: PASS ]\n");
}


/**
 * @brief Test fatal error handling when transactions are not supported
 *        by the broker.
 */
static void do_test_txns_not_supported (void) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;

        TEST_SAY(_C_MAG "[ %s ]\n", __FUNCTION__);

        test_conf_init(&conf, NULL, 10);

        test_conf_set(conf, "transactional.id", "myxnid");
        test_conf_set(conf, "bootstrap.servers", ",");
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* Create mock cluster */
        mcluster = rd_kafka_mock_cluster_new(rk, 3);

        /* Disable InitProducerId */
        rd_kafka_mock_set_apiversion(mcluster, 22/*InitProducerId*/, -1, -1);


        rd_kafka_brokers_add(rk, rd_kafka_mock_cluster_bootstraps(mcluster));



        error = rd_kafka_init_transactions(rk, 5*1000);
        TEST_SAY("init_transactions() returned %s: %s\n",
                 error ? rd_kafka_error_name(error) : "success",
                 error ? rd_kafka_error_string(error) : "success");

        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                    RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE,
                    "Expected init_transactions() to fail with %s, not %s: %s",
                    rd_kafka_err2name(RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE),
                    rd_kafka_error_name(error),
                    rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC("test"),
                                RD_KAFKA_V_KEY("test", 4),
                                RD_KAFKA_V_END);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__FATAL,
                    "Expected producev() to fail with %s, not %s",
                    rd_kafka_err2name(RD_KAFKA_RESP_ERR__FATAL),
                    rd_kafka_err2name(err));

        rd_kafka_mock_cluster_destroy(mcluster);

        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "[ %s: PASS ]\n", __FUNCTION__);
}


/**
 * @brief CONCURRENT_TRANSACTION on AddOffsets.. should be marked as retriable.
 */
static void do_test_txns_send_offsets_concurrent_is_retriable (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;

        TEST_SAY(_C_MAG "[ %s ]\n", __FUNCTION__);

        rk = create_txn_producer(&mcluster, "txnid", 3, NULL);

        test_curr->ignore_dr_err = rd_true;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2),
                                RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        /* Wait for messages to be delivered */
        test_flush(rk, 5000);


        /*
         * Have AddOffsetsToTxn fail.
         */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_AddOffsetsToTxn,
                1+3,/* first request + number of internal retries */
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->offset = 12;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        error = rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                     cgmetadata, -1);

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        TEST_ASSERT(error, "expected error");
        TEST_SAY("Error %s: %s\n",
                 rd_kafka_error_name(error),
                 rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_is_retriable(error),
                    "expected retriable error, not %s",
                    rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        /* Retry */
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->offset = 12;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                               cgmetadata, -1));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);


        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, 5000));

        /* All done */

        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "[ %s PASS ]\n", __FUNCTION__);
}


/**
 * @brief Verify that request timeouts don't cause crash (#2913).
 */
static void do_test_txns_no_timeout_crash (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;

        TEST_SAY(_C_MAG "[ %s ]\n", __FUNCTION__);

        rk = create_txn_producer(&mcluster, "txnid", 3,
                                 "socket.timeout.ms", "1000",
                                 "transaction.timeout.ms", "5000",
                                 NULL);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2),
                                RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        test_flush(rk, -1);

        /* Delay all broker connections */
        if ((err = rd_kafka_mock_broker_set_rtt(mcluster, 1, 2000)) ||
            (err = rd_kafka_mock_broker_set_rtt(mcluster, 2, 2000)) ||
            (err = rd_kafka_mock_broker_set_rtt(mcluster, 3, 2000)))
                TEST_FAIL("Failed to set broker RTT: %s",
                          rd_kafka_err2str(err));

        /* send_offsets..() should now time out */
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->offset = 12;
        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        error = rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                     cgmetadata, -1);
        TEST_ASSERT(error, "Expected send_offsets..() to fail");
        TEST_SAY("send_offsets..() failed with %serror: %s\n",
                 rd_kafka_error_is_retriable(error) ? "retriable " : "",
                 rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_code(error) ==
                    RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "expected send_offsets_to_transaction() to fail with "
                    "timeout, not %s",
                    rd_kafka_error_name(error));
        TEST_ASSERT(rd_kafka_error_is_retriable(error),
                    "expected send_offsets_to_transaction() to fail with "
                    "a retriable error");
        rd_kafka_error_destroy(error);

        /* Reset delay and try again */
        if ((err = rd_kafka_mock_broker_set_rtt(mcluster, 1, 0)) ||
            (err = rd_kafka_mock_broker_set_rtt(mcluster, 2, 0)) ||
            (err = rd_kafka_mock_broker_set_rtt(mcluster, 3, 0)))
                TEST_FAIL("Failed to reset broker RTT: %s",
                          rd_kafka_err2str(err));

        TEST_SAY("Retrying send_offsets..()\n");
        error = rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                     cgmetadata, -1);
        TEST_ASSERT(!error, "Expected send_offsets..() to succeed, got: %s",
                    rd_kafka_error_string(error));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        /* All done */
        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "[ %s PASS ]\n", __FUNCTION__);
}


int main_0105_transactions_mock (int argc, char **argv) {
        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_txn_recoverable_errors();

        do_test_txn_requires_abort_errors();

        /* Bring down the coordinator */
        do_test_txn_broker_down_in_txn(rd_true);

        /* Bring down partition leader */
        do_test_txn_broker_down_in_txn(rd_false);

        do_test_txns_not_supported();

        do_test_txns_send_offsets_concurrent_is_retriable();

        do_test_txns_no_timeout_crash();

        if (!test_quick)
                do_test_txn_switch_coordinator();

        return 0;
}
