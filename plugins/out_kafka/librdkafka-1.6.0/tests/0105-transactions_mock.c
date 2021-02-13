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
#include "../src/rdstring.h"
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

        test_conf_init(&conf, NULL, 60);

        test_conf_set(conf, "transactional.id", transactional_id);
        /* Speed up reconnects */
        test_conf_set(conf, "reconnect.backoff.max.ms", "2000");
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

        SUB_TEST_QUICK();

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

        SUB_TEST_PASS();
}


/**
 * @brief Test EndTxn errors.
 */
static void do_test_txn_endtxn_errors (void) {
        rd_kafka_t *rk = NULL;
        rd_kafka_mock_cluster_t *mcluster = NULL;
        rd_kafka_resp_err_t err;
        struct {
                size_t error_cnt;
                rd_kafka_resp_err_t errors[4];
                rd_kafka_resp_err_t exp_err;
                rd_bool_t exp_retriable;
                rd_bool_t exp_abortable;
                rd_bool_t exp_fatal;
        } scenario[] = {
                /* This list of errors is from the EndTxnResponse handler in
                 * AK clients/.../TransactionManager.java */
                { /* #0 */
                        2,
                        { RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
                          RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE },
                        /* Should auto-recover */
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                },
                { /* #1 */
                        2,
                        { RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                          RD_KAFKA_RESP_ERR_NOT_COORDINATOR },
                        /* Should auto-recover */
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                },
                { /* #2 */
                        1,
                        { RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS },
                        /* Should auto-recover */
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                },
                { /* #3 */
                        3,
                        { RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                          RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                          RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS },
                        /* Should auto-recover */
                        RD_KAFKA_RESP_ERR_NO_ERROR,
                },
                { /* #4 */
                        1,
                        { RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID },
                        RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID,
                        rd_false /* !retriable */,
                        rd_true /* abortable */,
                        rd_false /* !fatal */
                },
                { /* #5 */
                        1,
                        { RD_KAFKA_RESP_ERR_INVALID_PRODUCER_ID_MAPPING },
                        RD_KAFKA_RESP_ERR_INVALID_PRODUCER_ID_MAPPING,
                        rd_false /* !retriable */,
                        rd_true /* abortable */,
                        rd_false /* !fatal */
                },
                { /* #6 */
                        1,
                        { RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH },
                        /* This error is normalized */
                        RD_KAFKA_RESP_ERR__FENCED,
                        rd_false /* !retriable */,
                        rd_false /* !abortable */,
                        rd_true /* fatal */
                },
                { /* #7 */
                        1,
                        { RD_KAFKA_RESP_ERR_PRODUCER_FENCED },
                        /* This error is normalized */
                        RD_KAFKA_RESP_ERR__FENCED,
                        rd_false /* !retriable */,
                        rd_false /* !abortable */,
                        rd_true /* fatal */
                },
                { /* #8 */
                        1,
                        { RD_KAFKA_RESP_ERR_TRANSACTIONAL_ID_AUTHORIZATION_FAILED },
                        RD_KAFKA_RESP_ERR_TRANSACTIONAL_ID_AUTHORIZATION_FAILED,
                        rd_false /* !retriable */,
                        rd_false /* !abortable */,
                        rd_true /* fatal */
                },
                { /* #9 */
                        1,
                        { RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED },
                        RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED,
                        rd_false /* !retriable */,
                        rd_true /* abortable */,
                        rd_false /* !fatal */
                },
                { /* #10 */
                        /* Any other error should raise a fatal error */
                        1,
                        { RD_KAFKA_RESP_ERR_INVALID_MSG_SIZE },
                        RD_KAFKA_RESP_ERR_INVALID_MSG_SIZE,
                        rd_false /* !retriable */,
                        rd_true /* abortable */,
                        rd_false /* !fatal */,
                },
                { 0 },
        };
        int i;

        SUB_TEST_QUICK();

        for (i = 0 ; scenario[i].error_cnt > 0 ; i++) {
                int j;
                /* For each scenario, test:
                 *   commit_transaction()
                 *   flush() + commit_transaction()
                 *   abort_transaction()
                 *   flush() + abort_transaction()
                 */
                for (j = 0 ; j < (2+2) ; j++) {
                        rd_bool_t commit = j < 2;
                        rd_bool_t with_flush = j & 1;
                        const char *commit_str =
                                commit ?
                                (with_flush ? "commit&flush" : "commit") :
                                (with_flush ? "abort&flush" : "abort");
                        rd_kafka_topic_partition_list_t *offsets;
                        rd_kafka_consumer_group_metadata_t *cgmetadata;
                        rd_kafka_error_t *error;

                        TEST_SAY("Testing scenario #%d %s with %"PRIusz
                                 " injected erorrs, expecting %s\n",
                                 i, commit_str,
                                 scenario[i].error_cnt,
                                 rd_kafka_err2name(scenario[i].exp_err));

                        if (!rk) {
                                const char *txnid = "myTxnId";
                                rk = create_txn_producer(&mcluster, txnid,
                                                         3, NULL);
                                TEST_CALL_ERROR__(rd_kafka_init_transactions(
                                                          rk, 5000));
                        }

                        /*
                         * Start transaction
                         */
                        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                        /* Transaction aborts will cause DR errors:
                         * ignore them. */
                        test_curr->ignore_dr_err = !commit;

                        /*
                         * Produce a message.
                         */
                        err = rd_kafka_producev(rk,
                                                RD_KAFKA_V_TOPIC("mytopic"),
                                                RD_KAFKA_V_VALUE("hi", 2),
                                                RD_KAFKA_V_END);
                        TEST_ASSERT(!err, "produce failed: %s",
                                    rd_kafka_err2str(err));

                        if (with_flush)
                                test_flush(rk, -1);

                        /*
                         * Send some arbitrary offsets.
                         */
                        offsets = rd_kafka_topic_partition_list_new(4);
                        rd_kafka_topic_partition_list_add(offsets, "srctopic",
                                                          3)->offset = 12;
                        rd_kafka_topic_partition_list_add(offsets, "srctop2",
                                                          99)->offset = 99999;

                        cgmetadata = rd_kafka_consumer_group_metadata_new(
                                "mygroupid");

                        TEST_CALL_ERROR__(rd_kafka_send_offsets_to_transaction(
                                                  rk, offsets,
                                                  cgmetadata, -1));

                        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
                        rd_kafka_topic_partition_list_destroy(offsets);

                        /*
                         * Commit transaction, first with som failures,
                         * then succeed.
                         */
                        rd_kafka_mock_push_request_errors_array(
                                mcluster,
                                RD_KAFKAP_EndTxn,
                                scenario[i].error_cnt,
                                scenario[i].errors);

                        if (commit)
                                error = rd_kafka_commit_transaction(rk, 5000);
                        else
                                error = rd_kafka_abort_transaction(rk, 5000);

                        if (error)
                                TEST_SAY("Scenario #%d %s failed: %s: %s "
                                         "(retriable=%s, req_abort=%s, "
                                         "fatal=%s)\n",
                                         i, commit_str,
                                         rd_kafka_error_name(error),
                                         rd_kafka_error_string(error),
                                         RD_STR_ToF(rd_kafka_error_is_retriable(error)),
                                         RD_STR_ToF(rd_kafka_error_txn_requires_abort(error)),
                                         RD_STR_ToF(rd_kafka_error_is_fatal(error)));
                        else
                                TEST_SAY("Scenario #%d %s succeeded\n",
                                         i, commit_str);

                        if (!scenario[i].exp_err) {
                                TEST_ASSERT(!error,
                                            "Expected #%d %s to succeed, "
                                            "got %s",
                                            i, commit_str,
                                            rd_kafka_error_string(error));
                                continue;
                        }


                        TEST_ASSERT(error != NULL,
                                    "Expected #%d %s to fail",
                                    i, commit_str);
                        TEST_ASSERT(scenario[i].exp_err ==
                                    rd_kafka_error_code(error),
                                    "Scenario #%d: expected %s, not %s",
                                    i,
                                    rd_kafka_err2name(scenario[i].exp_err),
                                    rd_kafka_error_name(error));
                        TEST_ASSERT(scenario[i].exp_retriable ==
                                    (rd_bool_t)
                                    rd_kafka_error_is_retriable(error),
                                    "Scenario #%d: retriable mismatch",
                                    i);
                        TEST_ASSERT(scenario[i].exp_abortable ==
                                    (rd_bool_t)
                                    rd_kafka_error_txn_requires_abort(error),
                                    "Scenario #%d: abortable mismatch",
                                    i);
                        TEST_ASSERT(scenario[i].exp_fatal ==
                                    (rd_bool_t)rd_kafka_error_is_fatal(error),
                                    "Scenario #%d: fatal mismatch", i);

                        /* Handle errors according to the error flags */
                        if (rd_kafka_error_is_fatal(error)) {
                                TEST_SAY("Fatal error, destroying producer\n");
                                rd_kafka_error_destroy(error);
                                rd_kafka_destroy(rk);
                                rk = NULL; /* Will be re-created on the next
                                            * loop iteration. */

                        } else if (rd_kafka_error_txn_requires_abort(error)) {
                                rd_kafka_error_destroy(error);
                                TEST_SAY("Abortable error, "
                                         "aborting transaction\n");
                                TEST_CALL_ERROR__(
                                        rd_kafka_abort_transaction(rk, -1));

                        } else if (rd_kafka_error_is_retriable(error)) {
                                rd_kafka_error_destroy(error);
                                TEST_SAY("Retriable error, retrying %s once\n",
                                         commit_str);
                                if (commit)
                                        TEST_CALL_ERROR__(
                                                rd_kafka_commit_transaction(
                                                        rk, 5000));
                                else
                                        TEST_CALL_ERROR__(
                                                rd_kafka_abort_transaction(
                                                        rk, 5000));
                        } else {
                                TEST_FAIL("Scenario #%d %s: "
                                          "Permanent error without enough "
                                          "hints to proceed: %s\n",
                                          i, commit_str,
                                          rd_kafka_error_string(error));
                        }
                }
        }

        /* All done */
        if (rk)
                rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Test that the commit/abort works properly with infinite timeout.
 */
static void do_test_txn_endtxn_infinite (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster = NULL;
        const char *txnid = "myTxnId";
        int i;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, NULL);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        for (i = 0 ; i < 2 ; i++) {
                rd_bool_t commit = i == 0;
                const char *commit_str = commit ? "commit" : "abort";
                rd_kafka_error_t *error;
                test_timing_t t_call;

                /* Messages will fail on as the transaction fails,
                 * ignore the DR error */
                test_curr->ignore_dr_err = rd_true;

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                TEST_CALL_ERR__(rd_kafka_producev(rk,
                                                  RD_KAFKA_V_TOPIC("mytopic"),
                                                  RD_KAFKA_V_VALUE("hi", 2),
                                                  RD_KAFKA_V_END));

                /*
                 * Commit/abort transaction, first with som retriable failures,
                 * then success.
                 */
                rd_kafka_mock_push_request_errors(
                        mcluster,
                        RD_KAFKAP_EndTxn,
                        10,
                        RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR);

                rd_sleep(1);

                TIMING_START(&t_call, "%s_transaction()", commit_str);
                if (commit)
                        error = rd_kafka_commit_transaction(rk, -1);
                else
                        error = rd_kafka_abort_transaction(rk, -1);
                TIMING_STOP(&t_call);

                TEST_SAY("%s returned %s\n",
                         commit_str,
                         error ? rd_kafka_error_string(error) : "success");

                TEST_ASSERT(!error,
                            "Expected %s to succeed, got %s",
                            commit_str, rd_kafka_error_string(error));

        }

        /* All done */

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}



/**
 * @brief Test that the commit/abort user timeout is honoured.
 */
static void do_test_txn_endtxn_timeout (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster = NULL;
        const char *txnid = "myTxnId";
        int i;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, NULL);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        for (i = 0 ; i < 2 ; i++) {
                rd_bool_t commit = i == 0;
                const char *commit_str = commit ? "commit" : "abort";
                rd_kafka_error_t *error;
                test_timing_t t_call;

                /* Messages will fail on as the transaction fails,
                 * ignore the DR error */
                test_curr->ignore_dr_err = rd_true;

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                TEST_CALL_ERR__(rd_kafka_producev(rk,
                                                  RD_KAFKA_V_TOPIC("mytopic"),
                                                  RD_KAFKA_V_VALUE("hi", 2),
                                                  RD_KAFKA_V_END));

                /*
                 * Commit/abort transaction, first with som retriable failures
                 * whos retries exceed the user timeout.
                 */
                rd_kafka_mock_push_request_errors(
                        mcluster,
                        RD_KAFKAP_EndTxn,
                        10,
                        RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                        RD_KAFKA_RESP_ERR_NOT_COORDINATOR);

                rd_sleep(1);

                TIMING_START(&t_call, "%s_transaction()", commit_str);
                if (commit)
                        error = rd_kafka_commit_transaction(rk, 100);
                else
                        error = rd_kafka_abort_transaction(rk, 100);
                TIMING_STOP(&t_call);

                TEST_SAY("%s returned %s\n",
                         commit_str,
                         error ? rd_kafka_error_string(error) : "success");

                TEST_ASSERT(error != NULL,
                            "Expected %s to fail", commit_str);

                TEST_ASSERT(rd_kafka_error_code(error) ==
                            RD_KAFKA_RESP_ERR__TIMED_OUT,
                            "Expected %s to fail with timeout, not %s: %s",
                            commit_str,
                            rd_kafka_error_name(error),
                            rd_kafka_error_string(error));

                if (!commit)
                        TEST_ASSERT(!rd_kafka_error_txn_requires_abort(error),
                                    "abort_transaction() failure should raise "
                                    "a txn_requires_abort error");
                else {
                        TEST_ASSERT(rd_kafka_error_txn_requires_abort(error),
                                    "commit_transaction() failure should raise "
                                    "a txn_requires_abort error");
                        TEST_SAY("Aborting transaction as instructed by "
                                 "error flag\n");
                        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));
                }

                rd_kafka_error_destroy(error);

                TIMING_ASSERT(&t_call, 99, 199);
        }

        /* All done */

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Test that EndTxn is properly sent for aborted transactions
 *        even if AddOffsetsToTxnRequest was retried.
 *        This is a check for a txn_req_cnt bug.
 */
static void do_test_txn_req_cnt (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        const char *txnid = "myTxnId";

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, NULL);

        /* Messages will fail on abort(), ignore the DR error */
        test_curr->ignore_dr_err = rd_true;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        /*
         * Send some arbitrary offsets, first with some failures, then
         * succeed.
         */
        offsets = rd_kafka_topic_partition_list_new(2);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->offset = 12;
        rd_kafka_topic_partition_list_add(offsets, "srctop2", 99)->offset =
                999999111;

        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_AddOffsetsToTxn,
                2,
                RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
                RD_KAFKA_RESP_ERR_NOT_COORDINATOR);

        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_TxnOffsetCommit,
                2,
                RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS,
                RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(rd_kafka_send_offsets_to_transaction(
                                  rk, offsets,
                                  cgmetadata, -1));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, 5000));

        /* All done */

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
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
        int r;

        SUB_TEST_QUICK();

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

        /* First refresh proper Metadata to clear the topic's auth error,
         * otherwise the produce() below will fail immediately. */
        r = test_get_partition_count(rk, "mytopic", 5000);
        TEST_ASSERT(r > 0, "Expected topic %s to exist", "mytopic");

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

        SUB_TEST_PASS();
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

        SUB_TEST_QUICK("Test %s down", down_what);

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

        SUB_TEST_PASS();

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

        SUB_TEST("Test switching coordinators");

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

        SUB_TEST_PASS();
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

        SUB_TEST_QUICK();

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

        SUB_TEST_PASS();
}


/**
 * @brief CONCURRENT_TRANSACTION on AddOffsets.. should be retried.
 */
static void do_test_txns_send_offsets_concurrent_is_retried (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;

        SUB_TEST_QUICK();

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
         * Have AddOffsetsToTxn fail but eventually succeed due to
         * infinite retries.
         */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_AddOffsetsToTxn,
                1+5,/* first request + some retries */
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

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

        SUB_TEST_PASS();
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

        SUB_TEST_QUICK();

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

        SUB_TEST_PASS();
}


/**
 * @brief Test auth failure handling.
 */
static void do_test_txn_auth_failure (int16_t ApiKey,
                                      rd_kafka_resp_err_t ErrorCode) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;

        SUB_TEST_QUICK("ApiKey=%s ErrorCode=%s",
                       rd_kafka_ApiKey2str(ApiKey),
                       rd_kafka_err2name(ErrorCode));

        rk = create_txn_producer(&mcluster, "txnid", 3, NULL);

        rd_kafka_mock_push_request_errors(mcluster,
                                          ApiKey,
                                          1,
                                          ErrorCode);

        error = rd_kafka_init_transactions(rk, 5000);
        TEST_ASSERT(error, "Expected init_transactions() to fail");

        TEST_SAY("init_transactions() failed: %s: %s\n",
                 rd_kafka_err2name(rd_kafka_error_code(error)),
                 rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_code(error) == ErrorCode,
                    "Expected error %s, not %s",
                    rd_kafka_err2name(ErrorCode),
                    rd_kafka_err2name(rd_kafka_error_code(error)));
        TEST_ASSERT(rd_kafka_error_is_fatal(error),
                    "Expected error to be fatal");
        TEST_ASSERT(!rd_kafka_error_is_retriable(error),
                    "Expected error to not be retriable");
        rd_kafka_error_destroy(error);

        /* All done */

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Issue #3041: Commit fails due to message flush() taking too long,
 *        eventually resulting in an unabortable error and failure to
 *        re-init the transactional producer.
 */
static void do_test_txn_flush_timeout (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        rd_kafka_error_t *error;
        const char *txnid = "myTxnId";
        const char *topic = "myTopic";
        const int32_t coord_id = 2;
        int msgcounter = 0;
        rd_bool_t is_retry = rd_false;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3,
                                 "message.timeout.ms", "10000",
                                 "transaction.timeout.ms", "10000",
                                 /* Speed up coordinator reconnect */
                                 "reconnect.backoff.max.ms", "1000",
                                 NULL);


        /* Broker down is not a test-failing error */
        test_curr->is_fatal_cb = error_is_fatal_cb;
        allowed_error = RD_KAFKA_RESP_ERR__TRANSPORT;

        rd_kafka_mock_topic_create(mcluster, topic, 2, 3);

        /* Set coordinator so we can disconnect it later */
        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid, coord_id);

        /*
         * Init transactions
         */
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

 retry:
        if (!is_retry) {
                /* First attempt should fail. */

                test_curr->ignore_dr_err = rd_true;
                test_curr->exp_dr_err = RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;

                /* Assign invalid partition leaders for some partitions so
                 * that messages will not be delivered. */
                rd_kafka_mock_partition_set_leader(mcluster, topic, 0, -1);
                rd_kafka_mock_partition_set_leader(mcluster, topic, 1, -1);

        } else {
                /* The retry should succeed */
                test_curr->ignore_dr_err = rd_false;
                test_curr->exp_dr_err = is_retry ? RD_KAFKA_RESP_ERR_NO_ERROR :
                        RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;

                rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
                rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 1);

        }


        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        /*
         * Produce some messages to specific partitions and random.
         */
        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, 100, NULL, 10,
                                  &msgcounter);
        test_produce_msgs2_nowait(rk, topic, 1, 0, 0, 100, NULL, 10,
                                  &msgcounter);
        test_produce_msgs2_nowait(rk, topic, RD_KAFKA_PARTITION_UA,
                                  0, 0, 100, NULL, 10, &msgcounter);


        /*
         * Send some arbitrary offsets.
         */
        offsets = rd_kafka_topic_partition_list_new(4);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->offset = 12;
        rd_kafka_topic_partition_list_add(offsets, "srctop2", 99)->offset =
                999999111;
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 0)->offset = 999;
        rd_kafka_topic_partition_list_add(offsets, "srctop2", 3499)->offset =
                123456789;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(rd_kafka_send_offsets_to_transaction(
                                  rk, offsets,
                                  cgmetadata, -1));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        rd_sleep(2);

        if (!is_retry) {
                /* Now disconnect the coordinator. */
                TEST_SAY("Disconnecting transaction coordinator %"PRId32"\n",
                         coord_id);
                rd_kafka_mock_broker_set_down(mcluster, coord_id);
        }

        /*
         * Start committing.
         */
        error = rd_kafka_commit_transaction(rk, -1);

        if (!is_retry) {
                TEST_ASSERT(error != NULL,
                            "Expected commit to fail");
                TEST_SAY("commit_transaction() failed (expectedly): %s\n",
                         rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);

        } else {
                TEST_ASSERT(!error,
                            "Expected commit to succeed, not: %s",
                            rd_kafka_error_string(error));
        }

        if (!is_retry) {
                /*
                 * Bring the coordinator back up.
                 */
                rd_kafka_mock_broker_set_up(mcluster, coord_id);
                rd_sleep(2);

                /*
                 * Abort, and try again, this time without error.
                 */
                TEST_SAY("Aborting and retrying\n");
                is_retry = rd_true;

                TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, 60000));
                goto retry;
        }

        /* All done */

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


int main_0105_transactions_mock (int argc, char **argv) {
        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_txn_recoverable_errors();

        do_test_txn_endtxn_errors();

        do_test_txn_endtxn_infinite();

        /* Skip tests for non-infinite commit/abort timeouts
         * until they're properly handled by the producer. */
        if (0)
                do_test_txn_endtxn_timeout();

        do_test_txn_req_cnt();

        do_test_txn_requires_abort_errors();

        /* Bring down the coordinator */
        do_test_txn_broker_down_in_txn(rd_true);

        /* Bring down partition leader */
        do_test_txn_broker_down_in_txn(rd_false);

        do_test_txns_not_supported();

        do_test_txns_send_offsets_concurrent_is_retried();

        do_test_txns_no_timeout_crash();

        do_test_txn_auth_failure(
                RD_KAFKAP_InitProducerId,
                RD_KAFKA_RESP_ERR_CLUSTER_AUTHORIZATION_FAILED);

        do_test_txn_auth_failure(
                RD_KAFKAP_FindCoordinator,
                RD_KAFKA_RESP_ERR_CLUSTER_AUTHORIZATION_FAILED);

        do_test_txn_flush_timeout();

        if (!test_quick)
                do_test_txn_switch_coordinator();

        return 0;
}
