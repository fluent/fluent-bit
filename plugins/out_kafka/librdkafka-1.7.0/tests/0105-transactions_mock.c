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
        if (err == allowed_error ||
            /* If transport errors are allowed then it is likely
             * that we'll also see ALL_BROKERS_DOWN. */
            (allowed_error == RD_KAFKA_RESP_ERR__TRANSPORT &&
             err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN)) {
                TEST_SAY("Ignoring allowed error: %s: %s\n",
                         rd_kafka_err2name(err), reason);
                return 0;
        }
        return 1;
}


static rd_kafka_resp_err_t (*on_response_received_cb) (rd_kafka_t *rk,
                                                       int sockfd,
                                                       const char *brokername,
                                                       int32_t brokerid,
                                                       int16_t ApiKey,
                                                       int16_t ApiVersion,
                                                       int32_t CorrId,
                                                       size_t  size,
                                                       int64_t rtt,
                                                       rd_kafka_resp_err_t err,
                                                       void *ic_opaque);

/**
 * @brief Simple on_response_received interceptor that simply calls the
 *        sub-test's on_response_received_cb function, if set.
 */
static rd_kafka_resp_err_t
on_response_received_trampoline (rd_kafka_t *rk,
                                 int sockfd,
                                 const char *brokername,
                                 int32_t brokerid,
                                 int16_t ApiKey,
                                 int16_t ApiVersion,
                                 int32_t CorrId,
                                 size_t  size,
                                 int64_t rtt,
                                 rd_kafka_resp_err_t err,
                                 void *ic_opaque) {
        TEST_ASSERT(on_response_received_cb != NULL, "");
        return on_response_received_cb(rk, sockfd, brokername, brokerid,
                                       ApiKey, ApiVersion,
                                       CorrId, size, rtt, err, ic_opaque);
}


/**
 * @brief on_new interceptor to add an on_response_received interceptor.
 */
static rd_kafka_resp_err_t on_new_producer (rd_kafka_t *rk,
                                            const rd_kafka_conf_t *conf,
                                            void *ic_opaque,
                                            char *errstr, size_t errstr_size) {
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;

        if (on_response_received_cb)
                err = rd_kafka_interceptor_add_on_response_received(
                        rk, "on_response_received",
                        on_response_received_trampoline, ic_opaque);

        return err;
}


/**
 * @brief Create a transactional producer and a mock cluster.
 *
 * The var-arg list is a NULL-terminated list of
 * (const char *key, const char *value) config properties.
 *
 * Special keys:
 *   "on_response_received", "" - enable the on_response_received_cb
 *                                interceptor,
 *                                which must be assigned prior to
 *                                calling create_tnx_producer().
 */
static rd_kafka_t *create_txn_producer (rd_kafka_mock_cluster_t **mclusterp,
                                        const char *transactional_id,
                                        int broker_cnt, ...) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        char numstr[8];
        va_list ap;
        const char *key;
        rd_bool_t add_interceptors = rd_false;

        rd_snprintf(numstr, sizeof(numstr), "%d", broker_cnt);

        test_conf_init(&conf, NULL, 60);

        test_conf_set(conf, "transactional.id", transactional_id);
        /* Speed up reconnects */
        test_conf_set(conf, "reconnect.backoff.max.ms", "2000");
        test_conf_set(conf, "test.mock.num.brokers", numstr);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        test_curr->ignore_dr_err = rd_false;

        va_start(ap, broker_cnt);
        while ((key = va_arg(ap, const char *))) {
                if (!strcmp(key, "on_response_received")) {
                        add_interceptors = rd_true;
                        (void)va_arg(ap, const char *);
                } else {
                        test_conf_set(conf, key, va_arg(ap, const char *));
                }
        }
        va_end(ap);

        /* Add an on_.. interceptors */
        if (add_interceptors)
                rd_kafka_conf_interceptor_add_on_new(
                        conf,
                        "on_new_producer",
                        on_new_producer, NULL);

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
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        const char *groupid = "myGroupId";
        const char *txnid = "myTxnId";

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3,
                                 "batch.num.messages", "1",
                                 NULL);

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


        /* Produce a message without error first */
        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        /*
         * Produce a message, let it fail with a non-idempo/non-txn
         * retryable error
         */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_Produce,
                1,
                RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS);

        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

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
 * @brief KIP-360: Test that fatal idempotence errors triggers abortable
 *        transaction errors and that the producer can recover.
 */
static void do_test_txn_fatal_idempo_errors (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        const char *txnid = "myTxnId";

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3,
                                 "batch.num.messages", "1",
                                 NULL);

        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb = error_is_fatal_cb;
        allowed_error = RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


        /* Produce a message without error first */
        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        /* Produce a message, let it fail with a fatal idempo error. */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_Produce,
                1,
                RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID);

        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        /* Commit the transaction, should fail */
        error = rd_kafka_commit_transaction(rk, -1);
        TEST_ASSERT(error != NULL, "Expected commit_transaction() to fail");

        TEST_SAY("commit_transaction() failed (expectedly): %s\n",
                 rd_kafka_error_string(error));

        TEST_ASSERT(!rd_kafka_error_is_fatal(error),
                    "Did not expect fatal error");
        TEST_ASSERT(rd_kafka_error_txn_requires_abort(error),
                    "Expected abortable error");
        rd_kafka_error_destroy(error);

        /* Abort the transaction */
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        /* Run a new transaction without errors to verify that the
         * producer can recover. */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

        /* All done */

        rd_kafka_destroy(rk);

        allowed_error = RD_KAFKA_RESP_ERR_NO_ERROR;

        SUB_TEST_PASS();
}


/**
 * @brief KIP-360: Test that fatal idempotence errors triggers abortable
 *        transaction errors, but let the broker-side bumping of the
 *        producer PID take longer than the remaining transaction timeout
 *        which should raise a retriable error from abort_transaction().
 *
 * @param with_sleep After the first abort sleep longer than it takes to
 *                   re-init the pid so that the internal state automatically
 *                   transitions.
 */
static void do_test_txn_slow_reinit (rd_bool_t with_sleep) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        int32_t txn_coord = 2;
        const char *txnid = "myTxnId";
        test_timing_t timing;

        SUB_TEST("%s sleep", with_sleep ? "with": "without");

        rk = create_txn_producer(&mcluster, txnid, 3,
                                 "batch.num.messages", "1",
                                 NULL);

        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid,
                                      txn_coord);

        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb = NULL;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


        /* Produce a message without error first */
        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        test_flush(rk, -1);

        /* Set transaction coordinator latency higher than
         * the abort_transaction() call timeout so that the automatic
         * re-initpid takes longer than abort_transaction(). */
        rd_kafka_mock_broker_push_request_error_rtts(
                mcluster,
                txn_coord,
                RD_KAFKAP_InitProducerId,
                1,
                RD_KAFKA_RESP_ERR_NO_ERROR, 10000/*10s*/);

        /* Produce a message, let it fail with a fatal idempo error. */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_Produce,
                1,
                RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID);

        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));


        /* Commit the transaction, should fail */
        TIMING_START(&timing, "commit_transaction(-1)");
        error = rd_kafka_commit_transaction(rk, -1);
        TIMING_STOP(&timing);
        TEST_ASSERT(error != NULL, "Expected commit_transaction() to fail");

        TEST_SAY("commit_transaction() failed (expectedly): %s\n",
                 rd_kafka_error_string(error));

        TEST_ASSERT(!rd_kafka_error_is_fatal(error),
                    "Did not expect fatal error");
        TEST_ASSERT(rd_kafka_error_txn_requires_abort(error),
                    "Expected abortable error");
        rd_kafka_error_destroy(error);

        /* Abort the transaction, should fail with retriable (timeout) error */
        TIMING_START(&timing, "abort_transaction(100)");
        error = rd_kafka_abort_transaction(rk, 100);
        TIMING_STOP(&timing);
        TEST_ASSERT(error != NULL, "Expected abort_transaction() to fail");

        TEST_SAY("First abort_transaction() failed: %s\n",
                 rd_kafka_error_string(error));
        TEST_ASSERT(!rd_kafka_error_is_fatal(error),
                    "Did not expect fatal error");
        TEST_ASSERT(rd_kafka_error_is_retriable(error),
                    "Expected retriable error");
        rd_kafka_error_destroy(error);

        if (with_sleep)
                rd_sleep(12);

        /* Retry abort, should now finish. */
        TEST_SAY("Retrying abort\n");
        TIMING_START(&timing, "abort_transaction(-1)");
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));
        TIMING_STOP(&timing);

        /* Run a new transaction without errors to verify that the
         * producer can recover. */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

        /* All done */

        rd_kafka_destroy(rk);

        allowed_error = RD_KAFKA_RESP_ERR_NO_ERROR;

        SUB_TEST_PASS();
}



/**
 * @brief KIP-360: Test that fatal idempotence errors triggers abortable
 *        transaction errors, but let the broker-side bumping of the
 *        producer PID fail with a fencing error.
 *        Should raise a fatal error.
 */
static void do_test_txn_fenced_reinit (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        int32_t txn_coord = 2;
        const char *txnid = "myTxnId";
        char errstr[512];
        rd_kafka_resp_err_t fatal_err;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3,
                                 "batch.num.messages", "1",
                                 NULL);

        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid,
                                      txn_coord);

        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb = error_is_fatal_cb;
        allowed_error = RD_KAFKA_RESP_ERR__FENCED;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


        /* Produce a message without error first */
        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        test_flush(rk, -1);

        /* Fail the PID reinit */
        rd_kafka_mock_broker_push_request_error_rtts(
                mcluster,
                txn_coord,
                RD_KAFKAP_InitProducerId,
                1,
                RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH, 0);

        /* Produce a message, let it fail with a fatal idempo error. */
        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_Produce,
                1,
                RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID);

        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC("mytopic"),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        test_flush(rk, -1);

        /* Abort the transaction, should fail with a fatal error */
        error = rd_kafka_abort_transaction(rk, -1);
        TEST_ASSERT(error != NULL, "Expected abort_transaction() to fail");

        TEST_SAY("abort_transaction() failed: %s\n",
                 rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_is_fatal(error),
                    "Expected a fatal error");
        rd_kafka_error_destroy(error);

        fatal_err = rd_kafka_fatal_error(rk, errstr, sizeof(errstr));
        TEST_ASSERT(fatal_err,
                    "Expected a fatal error to have been raised");
        TEST_SAY("Fatal error: %s: %s\n",
                 rd_kafka_err2name(fatal_err), errstr);

        /* All done */

        rd_kafka_destroy(rk);

        allowed_error = RD_KAFKA_RESP_ERR_NO_ERROR;

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
                        test_timing_t t_call;

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

                        TIMING_START(&t_call, "%s", commit_str);
                        if (commit)
                                error = rd_kafka_commit_transaction(
                                        rk, tmout_multip(5000));
                        else
                                error = rd_kafka_abort_transaction(
                                        rk, tmout_multip(5000));
                        TIMING_STOP(&t_call);

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


/**
 * @brief ESC-4424: rko is reused in response handler after destroy in coord_req
 *        sender due to bad state.
 *
 * This is somewhat of a race condition so we need to perform a couple of
 * iterations before it hits, usually 2 or 3, so we try at least 15 times.
 */
static void do_test_txn_coord_req_destroy (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int i;
        int errcnt = 0;

        SUB_TEST();

        rk = create_txn_producer(&mcluster, "txnid", 3, NULL);

        test_curr->ignore_dr_err = rd_true;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        for (i = 0 ; i < 15 ; i++) {
                rd_kafka_error_t *error;
                rd_kafka_resp_err_t err;
                rd_kafka_topic_partition_list_t *offsets;
                rd_kafka_consumer_group_metadata_t *cgmetadata;

                test_timeout_set(10);

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                /*
                 * Inject errors to trigger retries
                 */
                rd_kafka_mock_push_request_errors(
                        mcluster,
                        RD_KAFKAP_AddPartitionsToTxn,
                        2,/* first request + number of internal retries */
                        RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                        RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

                rd_kafka_mock_push_request_errors(
                        mcluster,
                        RD_KAFKAP_AddOffsetsToTxn,
                        1,/* first request + number of internal retries */
                        RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

                err = rd_kafka_producev(rk,
                                        RD_KAFKA_V_TOPIC("mytopic"),
                                        RD_KAFKA_V_VALUE("hi", 2),
                                        RD_KAFKA_V_END);
                TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

                rd_kafka_mock_push_request_errors(
                        mcluster,
                        RD_KAFKAP_Produce,
                        4,
                        RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
                        RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
                        RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED,
                        RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
                /* FIXME: When KIP-360 is supported, add this error:
                 *        RD_KAFKA_RESP_ERR_OUT_OF_ORDER_SEQUENCE_NUMBER */

                err = rd_kafka_producev(rk,
                                        RD_KAFKA_V_TOPIC("mytopic"),
                                        RD_KAFKA_V_VALUE("hi", 2),
                                        RD_KAFKA_V_END);
                TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));


                /*
                 * Send offsets to transaction
                 */

                offsets = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->
                        offset = 12;

                cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

                error = rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                             cgmetadata, -1);

                TEST_SAY("send_offsets_to_transaction() #%d: %s\n",
                         i, rd_kafka_error_string(error));

                /* As we can't control the exact timing and sequence
                 * of requests this sometimes fails and sometimes succeeds,
                 * but we run the test enough times to trigger at least
                 * one failure. */
                if (error) {
                        TEST_SAY("send_offsets_to_transaction() #%d "
                                 "failed (expectedly): %s\n",
                                 i, rd_kafka_error_string(error));
                        TEST_ASSERT(rd_kafka_error_txn_requires_abort(error),
                                    "Expected abortable error for #%d", i);
                        rd_kafka_error_destroy(error);
                        errcnt++;
                }

                rd_kafka_consumer_group_metadata_destroy(cgmetadata);
                rd_kafka_topic_partition_list_destroy(offsets);

                /* Allow time for internal retries */
                rd_sleep(2);

                TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, 5000));
        }

        TEST_ASSERT(errcnt > 0,
                    "Expected at least one send_offets_to_transaction() "
                    "failure");

        /* All done */

        rd_kafka_destroy(rk);
}


static rd_atomic32_t multi_find_req_cnt;

static rd_kafka_resp_err_t
multi_find_on_response_received_cb (rd_kafka_t *rk,
                                    int sockfd,
                                    const char *brokername,
                                    int32_t brokerid,
                                    int16_t ApiKey,
                                    int16_t ApiVersion,
                                    int32_t CorrId,
                                    size_t  size,
                                    int64_t rtt,
                                    rd_kafka_resp_err_t err,
                                    void *ic_opaque) {
        rd_kafka_mock_cluster_t *mcluster = rd_kafka_handle_mock_cluster(rk);
        rd_bool_t done = rd_atomic32_get(&multi_find_req_cnt) > 10000;

        if (ApiKey != RD_KAFKAP_AddOffsetsToTxn || done)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        TEST_SAY("on_response_received_cb: %s: %s: brokerid %"PRId32
                 ", ApiKey %hd, CorrId %d, rtt %.2fms, %s: %s\n",
                 rd_kafka_name(rk), brokername, brokerid, ApiKey, CorrId,
                 rtt != -1 ? (float)rtt / 1000.0 : 0.0,
                 done ? "already done" : "not done yet",
                 rd_kafka_err2name(err));


        if (rd_atomic32_add(&multi_find_req_cnt, 1) == 1) {
                /* Trigger a broker down/up event, which in turns
                 * triggers the coord_req_fsm(). */
                rd_kafka_mock_broker_set_down(mcluster, 2);
                rd_kafka_mock_broker_set_up(mcluster, 2);
                return RD_KAFKA_RESP_ERR_NO_ERROR;
        }

        /* Trigger a broker down/up event, which in turns
         * triggers the coord_req_fsm(). */
        rd_kafka_mock_broker_set_down(mcluster, 3);
        rd_kafka_mock_broker_set_up(mcluster, 3);

        /* Clear the downed broker's latency so that it reconnects
         * quickly, otherwise the ApiVersionRequest will be delayed and
         * this will in turn delay the -> UP transition that we need to
         * trigger the coord_reqs. */
        rd_kafka_mock_broker_set_rtt(mcluster, 3, 0);

        /* Only do this down/up once */
        rd_atomic32_add(&multi_find_req_cnt, 10000);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief ESC-4444: multiple FindCoordinatorRequests are sent referencing
 *        the same coord_req_t, but the first one received will destroy
 *        the coord_req_t object and make the subsequent FindCoordingResponses
 *        reference a freed object.
 *
 * What we want to achieve is this sequence:
 *  1. AddOffsetsToTxnRequest + Response which..
 *  2. Triggers TxnOffsetCommitRequest, but the coordinator is not known, so..
 *  3. Triggers a FindCoordinatorRequest
 *  4. FindCoordinatorResponse from 3 is received ..
 *  5. A TxnOffsetCommitRequest is sent from coord_req_fsm().
 *  6. Another broker changing state to Up triggers coord reqs again, which..
 *  7. Triggers a second TxnOffsetCommitRequest from coord_req_fsm().
 *  7. FindCoordinatorResponse from 5 is received, references the destroyed rko
 *     and crashes.
 */
static void do_test_txn_coord_req_multi_find (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        const char *txnid = "txnid", *groupid = "mygroupid", *topic = "mytopic";
        int i;

        SUB_TEST();

        rd_atomic32_init(&multi_find_req_cnt, 0);

        on_response_received_cb = multi_find_on_response_received_cb;
        rk = create_txn_producer(&mcluster, txnid, 3,
                                 /* Need connections to all brokers so we
                                  * can trigger coord_req_fsm events
                                  * by toggling connections. */
                                 "enable.sparse.connections", "false",
                                 /* Set up on_response_received interceptor */
                                 "on_response_received", "", NULL);

        /* Let broker 1 be both txn and group coordinator
         * so that the group coordinator connection is up when it is time
         * send the TxnOffsetCommitRequest. */
        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid, 1);
        rd_kafka_mock_coordinator_set(mcluster, "group", groupid, 1);

        /* Set broker 1, 2, and 3 as leaders for a partition each and
         * later produce to both partitions so we know there's a connection
         * to all brokers. */
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 2);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 2, 3);

        /* Broker down is not a test-failing error */
        allowed_error = RD_KAFKA_RESP_ERR__TRANSPORT;
        test_curr->is_fatal_cb = error_is_fatal_cb;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        for (i = 0 ; i < 3 ; i++) {
                err = rd_kafka_producev(rk,
                                        RD_KAFKA_V_TOPIC(topic),
                                        RD_KAFKA_V_PARTITION(i),
                                        RD_KAFKA_V_VALUE("hi", 2),
                                        RD_KAFKA_V_END);
                TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));
        }

        test_flush(rk, 5000);

        /*
         * send_offsets_to_transaction() will query for the group coordinator,
         * we need to make those requests slow so that multiple requests are
         * sent.
         */
        for (i = 1 ; i <= 3 ; i++)
                rd_kafka_mock_broker_set_rtt(mcluster, (int32_t)i, 4000);

        /*
         * Send offsets to transaction
         */

        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic", 3)->
                offset = 12;

        cgmetadata = rd_kafka_consumer_group_metadata_new(groupid);

        error = rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                     cgmetadata, -1);

        TEST_SAY("send_offsets_to_transaction() %s\n",
                 rd_kafka_error_string(error));
        TEST_ASSERT(!error, "send_offsets_to_transaction() failed: %s",
                    rd_kafka_error_string(error));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        /* Clear delay */
        for (i = 1 ; i <= 3 ; i++)
                rd_kafka_mock_broker_set_rtt(mcluster, (int32_t)i, 0);

        rd_sleep(5);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, 5000));

        /* All done */

        TEST_ASSERT(rd_atomic32_get(&multi_find_req_cnt) > 10000,
                    "on_request_sent interceptor did not trigger properly");

        rd_kafka_destroy(rk);

        on_response_received_cb = NULL;

        SUB_TEST_PASS();
}


/**
 * @brief ESC-4410: adding producer partitions gradually will trigger multiple
 *        AddPartitionsToTxn requests. Due to a bug the third partition to be
 *        registered would hang in PEND_TXN state.
 *
 * Trigger this behaviour by having two outstanding AddPartitionsToTxn requests
 * at the same time, followed by a need for a third:
 *
 * 1. Set coordinator broker rtt high (to give us time to produce).
 * 2. Produce to partition 0, will trigger first AddPartitionsToTxn.
 * 3. Produce to partition 1, will trigger second AddPartitionsToTxn.
 * 4. Wait for second AddPartitionsToTxn response.
 * 5. Produce to partition 2, should trigger AddPartitionsToTxn, but bug
 *    causes it to be stale in pending state.
 */

static rd_atomic32_t multi_addparts_resp_cnt;
static rd_kafka_resp_err_t
multi_addparts_response_received_cb (rd_kafka_t *rk,
                                     int sockfd,
                                     const char *brokername,
                                     int32_t brokerid,
                                     int16_t ApiKey,
                                     int16_t ApiVersion,
                                     int32_t CorrId,
                                     size_t  size,
                                     int64_t rtt,
                                     rd_kafka_resp_err_t err,
                                     void *ic_opaque) {

        if (ApiKey == RD_KAFKAP_AddPartitionsToTxn) {
                TEST_SAY("on_response_received_cb: %s: %s: brokerid %"PRId32
                         ", ApiKey %hd, CorrId %d, rtt %.2fms, count %"PRId32
                         ": %s\n",
                         rd_kafka_name(rk), brokername, brokerid,
                         ApiKey, CorrId,
                         rtt != -1 ? (float)rtt / 1000.0 : 0.0,
                         rd_atomic32_get(&multi_addparts_resp_cnt),
                         rd_kafka_err2name(err));

                rd_atomic32_add(&multi_addparts_resp_cnt, 1);
        }

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static void do_test_txn_addparts_req_multi (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        const char *txnid = "txnid", *topic = "mytopic";
        int32_t txn_coord = 2;

        SUB_TEST();

        rd_atomic32_init(&multi_addparts_resp_cnt, 0);

        on_response_received_cb = multi_addparts_response_received_cb;
        rk = create_txn_producer(&mcluster, txnid, 3,
                                 "linger.ms", "0",
                                 "message.timeout.ms", "9000",
                                 /* Set up on_response_received interceptor */
                                 "on_response_received", "", NULL);

        /* Let broker 1 be txn coordinator. */
        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid,
                                      txn_coord);

        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        /* Set partition leaders to non-txn-coord broker so they wont
         * be affected by rtt delay */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 1);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 2, 1);



        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        /*
         * Run one transaction first to let the client familiarize with
         * the topic, this avoids metadata lookups, etc, when the real
         * test is run.
         */
        TEST_SAY("Running seed transaction\n");
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));
        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC(topic),
                                          RD_KAFKA_V_VALUE("seed", 4),
                                          RD_KAFKA_V_END));
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, 5000));


        /*
         * Now perform test transaction with rtt delays
         */
        TEST_SAY("Running test transaction\n");

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        /* Reset counter */
        rd_atomic32_set(&multi_addparts_resp_cnt, 0);

        /* Add latency to txn coordinator so we can pace our produce() calls */
        rd_kafka_mock_broker_set_rtt(mcluster, txn_coord, 1000);

        /* Produce to partition 0 */
        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC(topic),
                                          RD_KAFKA_V_PARTITION(0),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        rd_usleep(500*1000, NULL);

        /* Produce to partition 1 */
        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC(topic),
                                          RD_KAFKA_V_PARTITION(1),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        TEST_SAY("Waiting for two AddPartitionsToTxnResponse\n");
        while (rd_atomic32_get(&multi_addparts_resp_cnt) < 2)
                rd_usleep(10*1000, NULL);

        TEST_SAY("%"PRId32" AddPartitionsToTxnResponses seen\n",
                 rd_atomic32_get(&multi_addparts_resp_cnt));

        /* Produce to partition 2, this message will hang in
         * queue if the bug is not fixed. */
        TEST_CALL_ERR__(rd_kafka_producev(rk,
                                          RD_KAFKA_V_TOPIC(topic),
                                          RD_KAFKA_V_PARTITION(2),
                                          RD_KAFKA_V_VALUE("hi", 2),
                                          RD_KAFKA_V_END));

        /* Allow some extra time for things to settle before committing
         * transaction. */
        rd_usleep(1000*1000, NULL);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, 10*1000));

        /* All done */
        rd_kafka_destroy(rk);

        on_response_received_cb = NULL;

        SUB_TEST_PASS();
}



/**
 * @brief Test handling of OffsetFetchRequest returning UNSTABLE_OFFSET_COMMIT.
 *
 * There are two things to test;
 *  - OffsetFetch triggered by committed() (and similar code paths)
 *  - OffsetFetch triggered by assign()
 */
static void do_test_unstable_offset_commit (void) {
        rd_kafka_t *rk, *c;
        rd_kafka_conf_t *c_conf;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_topic_partition_list_t *offsets;
        const char *topic = "mytopic";
        const int msgcnt = 100;
        const int64_t offset_to_commit = msgcnt / 2;
        int i;
        int remains = 0;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, "txnid", 3, NULL);

        test_conf_init(&c_conf, NULL, 0);
        test_conf_set(c_conf, "security.protocol", "PLAINTEXT");
        test_conf_set(c_conf, "bootstrap.servers",
                      rd_kafka_mock_cluster_bootstraps(mcluster));
        test_conf_set(c_conf, "enable.partition.eof", "true");
        test_conf_set(c_conf, "auto.offset.reset", "error");
        c = test_create_consumer("mygroup", NULL, c_conf, NULL);

        rd_kafka_mock_topic_create(mcluster, topic, 2, 3);

        /* Produce some messages to the topic so that the consumer has
         * something to read. */
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));
        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, msgcnt,
                                  NULL, 0, &remains);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));


        /* Commit offset */
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, topic, 0)->offset =
                offset_to_commit;
        TEST_CALL_ERR__(rd_kafka_commit(c, offsets, 0/*sync*/));
        rd_kafka_topic_partition_list_destroy(offsets);

        /* Retrieve offsets by calling committed().
         *
         * Have OffsetFetch fail and retry, on the first iteration
         * the API timeout is higher than the amount of time the retries will
         * take and thus succeed, and on the second iteration the timeout
         * will be lower and thus fail. */
        for (i = 0 ; i < 2 ; i++) {
                rd_kafka_resp_err_t err;
                rd_kafka_resp_err_t exp_err = i == 0 ?
                        RD_KAFKA_RESP_ERR_NO_ERROR :
                        RD_KAFKA_RESP_ERR__TIMED_OUT;
                int timeout_ms = exp_err ? 200 : 5*1000;

                rd_kafka_mock_push_request_errors(
                        mcluster,
                        RD_KAFKAP_OffsetFetch,
                        1+5,/* first request + some retries */
                        RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                        RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                        RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                        RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                        RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                        RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT);

                offsets = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(offsets, topic, 0);

                err = rd_kafka_committed(c, offsets, timeout_ms);

                TEST_SAY("#%d: committed() returned %s (expected %s)\n",
                         i,
                         rd_kafka_err2name(err),
                         rd_kafka_err2name(exp_err));

                TEST_ASSERT(err == exp_err,
                            "#%d: Expected committed() to return %s, not %s",
                            i,
                            rd_kafka_err2name(exp_err),
                            rd_kafka_err2name(err));
                TEST_ASSERT(offsets->cnt == 1,
                            "Expected 1 committed offset, not %d",
                            offsets->cnt);
                if (!exp_err)
                        TEST_ASSERT(offsets->elems[0].offset == offset_to_commit,
                                    "Expected committed offset %"PRId64", "
                                    "not %"PRId64,
                                    offset_to_commit,
                                    offsets->elems[0].offset);
                else
                        TEST_ASSERT(offsets->elems[0].offset < 0,
                                    "Expected no committed offset, "
                                    "not %"PRId64,
                                    offsets->elems[0].offset);

                rd_kafka_topic_partition_list_destroy(offsets);
        }

        TEST_SAY("Phase 2: OffsetFetch lookup through assignment\n");
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, topic, 0)->offset =
                RD_KAFKA_OFFSET_STORED;

        rd_kafka_mock_push_request_errors(
                mcluster,
                RD_KAFKAP_OffsetFetch,
                1+5,/* first request + some retries */
                RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT);

        test_consumer_incremental_assign("assign", c, offsets);
        rd_kafka_topic_partition_list_destroy(offsets);

        test_consumer_poll_exact("consume", c, 0,
                                 1/*eof*/, 0, msgcnt/2,
                                 rd_true/*exact counts*/, NULL);

        /* All done */
        rd_kafka_destroy(c);
        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief If a message times out locally before being attempted to send
 *        and commit_transaction() is called, the transaction must not succeed.
 *        https://github.com/confluentinc/confluent-kafka-dotnet/issues/1568
 */
static void do_test_commit_after_msg_timeout (void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int32_t coord_id, leader_id;
        rd_kafka_resp_err_t err;
        rd_kafka_error_t *error;
        const char *topic = "test";
        const char *transactional_id = "txnid";
        int remains = 0;

        SUB_TEST_QUICK();

        /* Assign coordinator and leader to two different brokers */
        coord_id = 1;
        leader_id = 2;

        rk = create_txn_producer(&mcluster, transactional_id, 3,
                                 "message.timeout.ms", "5000",
                                 "transaction.timeout.ms", "10000",
                                 NULL);

        /* Broker down is not a test-failing error */
        allowed_error = RD_KAFKA_RESP_ERR__TRANSPORT;
        test_curr->is_fatal_cb = error_is_fatal_cb;
        test_curr->exp_dr_err = RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;

        err = rd_kafka_mock_topic_create(mcluster, topic, 1, 3);
        TEST_ASSERT(!err, "Failed to create topic: %s", rd_kafka_err2str (err));

        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      coord_id);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, leader_id);

        /* Start transactioning */
        TEST_SAY("Starting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        TEST_SAY("Bringing down %"PRId32"\n", leader_id);
        rd_kafka_mock_broker_set_down(mcluster, leader_id);
        rd_kafka_mock_broker_set_down(mcluster, coord_id);

        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, 1, NULL, 0, &remains);

        error = rd_kafka_commit_transaction(rk, -1);
        TEST_ASSERT(error != NULL, "expected commit_transaciton() to fail");
        TEST_SAY("commit_transaction() failed (as expected): %s\n",
                 rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_txn_requires_abort (error),
                    "Expected txn_requires_abort error");
        rd_kafka_error_destroy(error);

        /* Bring the brokers up so the abort can complete */
        rd_kafka_mock_broker_set_up(mcluster, coord_id);
        rd_kafka_mock_broker_set_up(mcluster, leader_id);

        TEST_SAY("Aborting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        TEST_ASSERT(remains == 0,
                    "%d message(s) were not flushed\n", remains);

        TEST_SAY("Attempting second transaction, which should succeed\n");
        allowed_error = RD_KAFKA_RESP_ERR_NO_ERROR;
        test_curr->is_fatal_cb = error_is_fatal_cb;
        test_curr->exp_dr_err = RD_KAFKA_RESP_ERR_NO_ERROR;

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));
        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, 1, NULL, 0, &remains);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

        TEST_ASSERT(remains == 0,
                    "%d message(s) were not produced\n", remains);

        rd_kafka_destroy(rk);

        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}

int main_0105_transactions_mock (int argc, char **argv) {
        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_txn_recoverable_errors();

        do_test_txn_fatal_idempo_errors();

        do_test_txn_fenced_reinit();

        do_test_txn_req_cnt();

        do_test_txn_requires_abort_errors();

        do_test_txn_slow_reinit(rd_false);
        do_test_txn_slow_reinit(rd_true);

        /* Just do a subset of tests in quick mode */
        if (test_quick)
                return 0;

        do_test_txn_endtxn_errors();

        do_test_txn_endtxn_infinite();

        /* Skip tests for non-infinite commit/abort timeouts
         * until they're properly handled by the producer. */
        if (0)
                do_test_txn_endtxn_timeout();

        /* Bring down the coordinator */
        do_test_txn_broker_down_in_txn(rd_true);

        /* Bring down partition leader */
        do_test_txn_broker_down_in_txn(rd_false);

        do_test_txns_not_supported();

        do_test_txns_send_offsets_concurrent_is_retried();

        do_test_txn_coord_req_destroy();

        do_test_txn_coord_req_multi_find();

        do_test_txn_addparts_req_multi();

        do_test_txns_no_timeout_crash();

        do_test_txn_auth_failure(
                RD_KAFKAP_InitProducerId,
                RD_KAFKA_RESP_ERR_CLUSTER_AUTHORIZATION_FAILED);

        do_test_txn_auth_failure(
                RD_KAFKAP_FindCoordinator,
                RD_KAFKA_RESP_ERR_CLUSTER_AUTHORIZATION_FAILED);

        do_test_txn_flush_timeout();

        do_test_unstable_offset_commit();

        do_test_commit_after_msg_timeout();

        do_test_txn_switch_coordinator();

        return 0;
}
