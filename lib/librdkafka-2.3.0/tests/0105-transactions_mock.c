/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019-2022, Magnus Edenhill
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
static int
error_is_fatal_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err, const char *reason) {
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


static rd_kafka_resp_err_t (*on_response_received_cb)(rd_kafka_t *rk,
                                                      int sockfd,
                                                      const char *brokername,
                                                      int32_t brokerid,
                                                      int16_t ApiKey,
                                                      int16_t ApiVersion,
                                                      int32_t CorrId,
                                                      size_t size,
                                                      int64_t rtt,
                                                      rd_kafka_resp_err_t err,
                                                      void *ic_opaque);

/**
 * @brief Simple on_response_received interceptor that simply calls the
 *        sub-test's on_response_received_cb function, if set.
 */
static rd_kafka_resp_err_t
on_response_received_trampoline(rd_kafka_t *rk,
                                int sockfd,
                                const char *brokername,
                                int32_t brokerid,
                                int16_t ApiKey,
                                int16_t ApiVersion,
                                int32_t CorrId,
                                size_t size,
                                int64_t rtt,
                                rd_kafka_resp_err_t err,
                                void *ic_opaque) {
        TEST_ASSERT(on_response_received_cb != NULL, "");
        return on_response_received_cb(rk, sockfd, brokername, brokerid, ApiKey,
                                       ApiVersion, CorrId, size, rtt, err,
                                       ic_opaque);
}


/**
 * @brief on_new interceptor to add an on_response_received interceptor.
 */
static rd_kafka_resp_err_t on_new_producer(rd_kafka_t *rk,
                                           const rd_kafka_conf_t *conf,
                                           void *ic_opaque,
                                           char *errstr,
                                           size_t errstr_size) {
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;

        if (on_response_received_cb)
                err = rd_kafka_interceptor_add_on_response_received(
                    rk, "on_response_received", on_response_received_trampoline,
                    ic_opaque);

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
static RD_SENTINEL rd_kafka_t *
create_txn_producer(rd_kafka_mock_cluster_t **mclusterp,
                    const char *transactional_id,
                    int broker_cnt,
                    ...) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        char numstr[8];
        va_list ap;
        const char *key;
        rd_bool_t add_interceptors = rd_false;

        rd_snprintf(numstr, sizeof(numstr), "%d", broker_cnt);

        test_conf_init(&conf, NULL, 60);

        test_conf_set(conf, "transactional.id", transactional_id);
        /* When mock brokers are set to down state they're still binding
         * the port, just not listening to it, which makes connection attempts
         * stall until socket.connection.setup.timeout.ms expires.
         * To speed up detection of brokers being down we reduce this timeout
         * to just a couple of seconds. */
        test_conf_set(conf, "socket.connection.setup.timeout.ms", "5000");
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
                rd_kafka_conf_interceptor_add_on_new(conf, "on_new_producer",
                                                     on_new_producer, NULL);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        if (mclusterp) {
                *mclusterp = rd_kafka_handle_mock_cluster(rk);
                TEST_ASSERT(*mclusterp, "failed to create mock cluster");

                /* Create some of the common consumer "input" topics
                 * that we must be able to commit to with
                 * send_offsets_to_transaction().
                 * The number depicts the number of partitions in the topic. */
                TEST_CALL_ERR__(
                    rd_kafka_mock_topic_create(*mclusterp, "srctopic4", 4, 1));
                TEST_CALL_ERR__(rd_kafka_mock_topic_create(
                    *mclusterp, "srctopic64", 64, 1));
        }

        return rk;
}


/**
 * @brief Test recoverable errors using mock broker error injections
 *        and code coverage checks.
 */
static void do_test_txn_recoverable_errors(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        const char *groupid = "myGroupId";
        const char *txnid   = "myTxnId";

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, "batch.num.messages", "1",
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
            mcluster, RD_KAFKAP_InitProducerId, 3,
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
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        rd_kafka_flush(rk, -1);

        /*
         * Produce a message, let it fail with a non-idempo/non-txn
         * retryable error
         */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS);

        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        /* Make sure messages are produced */
        rd_kafka_flush(rk, -1);

        /*
         * Send some arbitrary offsets, first with some failures, then
         * succeed.
         */
        offsets = rd_kafka_topic_partition_list_new(4);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;
        rd_kafka_topic_partition_list_add(offsets, "srctopic64", 39)->offset =
            999999111;
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 0)->offset =
            999;
        rd_kafka_topic_partition_list_add(offsets, "srctopic64", 19)->offset =
            123456789;

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_AddPartitionsToTxn, 1,
            RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_TxnOffsetCommit, 2,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
            RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        /*
         * Commit transaction, first with som failures, then succeed.
         */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_EndTxn, 3,
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
static void do_test_txn_fatal_idempo_errors(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        const char *txnid = "myTxnId";

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, "batch.num.messages", "1",
                                 NULL);

        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb   = error_is_fatal_cb;
        allowed_error            = RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


        /* Produce a message without error first */
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        /* Produce a message, let it fail with a fatal idempo error. */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID);

        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

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

        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

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
static void do_test_txn_slow_reinit(rd_bool_t with_sleep) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        int32_t txn_coord = 2;
        const char *txnid = "myTxnId";
        test_timing_t timing;

        SUB_TEST("%s sleep", with_sleep ? "with" : "without");

        rk = create_txn_producer(&mcluster, txnid, 3, "batch.num.messages", "1",
                                 NULL);

        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid,
                                      txn_coord);

        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb   = NULL;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


        /* Produce a message without error first */
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        test_flush(rk, -1);

        /* Set transaction coordinator latency higher than
         * the abort_transaction() call timeout so that the automatic
         * re-initpid takes longer than abort_transaction(). */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, txn_coord, RD_KAFKAP_InitProducerId, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, 10000 /*10s*/);

        /* Produce a message, let it fail with a fatal idempo error. */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID);

        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));


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

        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

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
 *
 * @param error_code Which error code InitProducerIdRequest should fail with.
 *                   Either RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH (older)
 *                   or RD_KAFKA_RESP_ERR_PRODUCER_FENCED (newer).
 */
static void do_test_txn_fenced_reinit(rd_kafka_resp_err_t error_code) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        int32_t txn_coord = 2;
        const char *txnid = "myTxnId";
        char errstr[512];
        rd_kafka_resp_err_t fatal_err;

        SUB_TEST_QUICK("With error %s", rd_kafka_err2name(error_code));

        rk = create_txn_producer(&mcluster, txnid, 3, "batch.num.messages", "1",
                                 NULL);

        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid,
                                      txn_coord);

        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb   = error_is_fatal_cb;
        allowed_error            = RD_KAFKA_RESP_ERR__FENCED;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


        /* Produce a message without error first */
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        test_flush(rk, -1);

        /* Fail the PID reinit */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, txn_coord, RD_KAFKAP_InitProducerId, 1, error_code, 0);

        /* Produce a message, let it fail with a fatal idempo error. */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID);

        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        test_flush(rk, -1);

        /* Abort the transaction, should fail with a fatal error */
        error = rd_kafka_abort_transaction(rk, -1);
        TEST_ASSERT(error != NULL, "Expected abort_transaction() to fail");

        TEST_SAY("abort_transaction() failed: %s\n",
                 rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_is_fatal(error), "Expected a fatal error");
        rd_kafka_error_destroy(error);

        fatal_err = rd_kafka_fatal_error(rk, errstr, sizeof(errstr));
        TEST_ASSERT(fatal_err, "Expected a fatal error to have been raised");
        TEST_SAY("Fatal error: %s: %s\n", rd_kafka_err2name(fatal_err), errstr);

        /* All done */

        rd_kafka_destroy(rk);

        allowed_error = RD_KAFKA_RESP_ERR_NO_ERROR;

        SUB_TEST_PASS();
}


/**
 * @brief Test EndTxn errors.
 */
static void do_test_txn_endtxn_errors(void) {
        rd_kafka_t *rk                    = NULL;
        rd_kafka_mock_cluster_t *mcluster = NULL;
        rd_kafka_resp_err_t err;
        struct {
                size_t error_cnt;
                rd_kafka_resp_err_t errors[4];
                rd_kafka_resp_err_t exp_err;
                rd_bool_t exp_retriable;
                rd_bool_t exp_abortable;
                rd_bool_t exp_fatal;
                rd_bool_t exp_successful_abort;
        } scenario[] = {
            /* This list of errors is from the EndTxnResponse handler in
             * AK clients/.../TransactionManager.java */
            {
                /* #0 */
                2,
                {RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
                 RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE},
                /* Should auto-recover */
                RD_KAFKA_RESP_ERR_NO_ERROR,
            },
            {
                /* #1 */
                2,
                {RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
                 RD_KAFKA_RESP_ERR_NOT_COORDINATOR},
                /* Should auto-recover */
                RD_KAFKA_RESP_ERR_NO_ERROR,
            },
            {
                /* #2 */
                1,
                {RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS},
                /* Should auto-recover */
                RD_KAFKA_RESP_ERR_NO_ERROR,
            },
            {
                /* #3 */
                3,
                {RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                 RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                 RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS},
                /* Should auto-recover */
                RD_KAFKA_RESP_ERR_NO_ERROR,
            },
            {
                /* #4: the abort is auto-recovering thru epoch bump */
                1,
                {RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID},
                RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID,
                rd_false /* !retriable */,
                rd_true /* abortable */,
                rd_false /* !fatal */,
                rd_true /* successful abort */
            },
            {
                /* #5: the abort is auto-recovering thru epoch bump */
                1,
                {RD_KAFKA_RESP_ERR_INVALID_PRODUCER_ID_MAPPING},
                RD_KAFKA_RESP_ERR_INVALID_PRODUCER_ID_MAPPING,
                rd_false /* !retriable */,
                rd_true /* abortable */,
                rd_false /* !fatal */,
                rd_true /* successful abort */
            },
            {
                /* #6 */
                1,
                {RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH},
                /* This error is normalized */
                RD_KAFKA_RESP_ERR__FENCED,
                rd_false /* !retriable */,
                rd_false /* !abortable */,
                rd_true /* fatal */
            },
            {
                /* #7 */
                1,
                {RD_KAFKA_RESP_ERR_PRODUCER_FENCED},
                /* This error is normalized */
                RD_KAFKA_RESP_ERR__FENCED,
                rd_false /* !retriable */,
                rd_false /* !abortable */,
                rd_true /* fatal */
            },
            {
                /* #8 */
                1,
                {RD_KAFKA_RESP_ERR_TRANSACTIONAL_ID_AUTHORIZATION_FAILED},
                RD_KAFKA_RESP_ERR_TRANSACTIONAL_ID_AUTHORIZATION_FAILED,
                rd_false /* !retriable */,
                rd_false /* !abortable */,
                rd_true /* fatal */
            },
            {
                /* #9 */
                1,
                {RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED},
                RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED,
                rd_false /* !retriable */,
                rd_true /* abortable */,
                rd_false /* !fatal */
            },
            {
                /* #10 */
                /* Any other error should raise a fatal error */
                1,
                {RD_KAFKA_RESP_ERR_INVALID_MSG_SIZE},
                RD_KAFKA_RESP_ERR_INVALID_MSG_SIZE,
                rd_false /* !retriable */,
                rd_true /* abortable */,
                rd_false /* !fatal */,
            },
            {
                /* #11 */
                1,
                {RD_KAFKA_RESP_ERR_PRODUCER_FENCED},
                /* This error is normalized */
                RD_KAFKA_RESP_ERR__FENCED,
                rd_false /* !retriable */,
                rd_false /* !abortable */,
                rd_true /* fatal */
            },
            {0},
        };
        int i;

        SUB_TEST_QUICK();

        for (i = 0; scenario[i].error_cnt > 0; i++) {
                int j;
                /* For each scenario, test:
                 *   commit_transaction()
                 *   flush() + commit_transaction()
                 *   abort_transaction()
                 *   flush() + abort_transaction()
                 */
                for (j = 0; j < (2 + 2); j++) {
                        rd_bool_t commit     = j < 2;
                        rd_bool_t with_flush = j & 1;
                        rd_bool_t exp_successful_abort =
                            !commit && scenario[i].exp_successful_abort;
                        const char *commit_str =
                            commit ? (with_flush ? "commit&flush" : "commit")
                                   : (with_flush ? "abort&flush" : "abort");
                        rd_kafka_topic_partition_list_t *offsets;
                        rd_kafka_consumer_group_metadata_t *cgmetadata;
                        rd_kafka_error_t *error;
                        test_timing_t t_call;

                        TEST_SAY("Testing scenario #%d %s with %" PRIusz
                                 " injected erorrs, expecting %s\n",
                                 i, commit_str, scenario[i].error_cnt,
                                 exp_successful_abort
                                     ? "successful abort"
                                     : rd_kafka_err2name(scenario[i].exp_err));

                        if (!rk) {
                                const char *txnid = "myTxnId";
                                rk = create_txn_producer(&mcluster, txnid, 3,
                                                         NULL);
                                TEST_CALL_ERROR__(
                                    rd_kafka_init_transactions(rk, 5000));
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
                        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
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
                        rd_kafka_topic_partition_list_add(offsets, "srctopic4",
                                                          3)
                            ->offset = 12;
                        rd_kafka_topic_partition_list_add(offsets, "srctopic64",
                                                          60)
                            ->offset = 99999;

                        cgmetadata =
                            rd_kafka_consumer_group_metadata_new("mygroupid");

                        TEST_CALL_ERROR__(rd_kafka_send_offsets_to_transaction(
                            rk, offsets, cgmetadata, -1));

                        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
                        rd_kafka_topic_partition_list_destroy(offsets);

                        /*
                         * Commit transaction, first with som failures,
                         * then succeed.
                         */
                        rd_kafka_mock_push_request_errors_array(
                            mcluster, RD_KAFKAP_EndTxn, scenario[i].error_cnt,
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
                                TEST_SAY(
                                    "Scenario #%d %s failed: %s: %s "
                                    "(retriable=%s, req_abort=%s, "
                                    "fatal=%s)\n",
                                    i, commit_str, rd_kafka_error_name(error),
                                    rd_kafka_error_string(error),
                                    RD_STR_ToF(
                                        rd_kafka_error_is_retriable(error)),
                                    RD_STR_ToF(
                                        rd_kafka_error_txn_requires_abort(
                                            error)),
                                    RD_STR_ToF(rd_kafka_error_is_fatal(error)));
                        else
                                TEST_SAY("Scenario #%d %s succeeded\n", i,
                                         commit_str);

                        if (!scenario[i].exp_err || exp_successful_abort) {
                                TEST_ASSERT(!error,
                                            "Expected #%d %s to succeed, "
                                            "got %s",
                                            i, commit_str,
                                            rd_kafka_error_string(error));
                                continue;
                        }


                        TEST_ASSERT(error != NULL, "Expected #%d %s to fail", i,
                                    commit_str);
                        TEST_ASSERT(scenario[i].exp_err ==
                                        rd_kafka_error_code(error),
                                    "Scenario #%d: expected %s, not %s", i,
                                    rd_kafka_err2name(scenario[i].exp_err),
                                    rd_kafka_error_name(error));
                        TEST_ASSERT(
                            scenario[i].exp_retriable ==
                                (rd_bool_t)rd_kafka_error_is_retriable(error),
                            "Scenario #%d: retriable mismatch", i);
                        TEST_ASSERT(
                            scenario[i].exp_abortable ==
                                (rd_bool_t)rd_kafka_error_txn_requires_abort(
                                    error),
                            "Scenario #%d: abortable mismatch", i);
                        TEST_ASSERT(
                            scenario[i].exp_fatal ==
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
                                TEST_SAY(
                                    "Abortable error, "
                                    "aborting transaction\n");
                                TEST_CALL_ERROR__(
                                    rd_kafka_abort_transaction(rk, -1));

                        } else if (rd_kafka_error_is_retriable(error)) {
                                rd_kafka_error_destroy(error);
                                TEST_SAY("Retriable error, retrying %s once\n",
                                         commit_str);
                                if (commit)
                                        TEST_CALL_ERROR__(
                                            rd_kafka_commit_transaction(rk,
                                                                        5000));
                                else
                                        TEST_CALL_ERROR__(
                                            rd_kafka_abort_transaction(rk,
                                                                       5000));
                        } else {
                                TEST_FAIL(
                                    "Scenario #%d %s: "
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
static void do_test_txn_endtxn_infinite(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster = NULL;
        const char *txnid                 = "myTxnId";
        int i;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, NULL);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        for (i = 0; i < 2; i++) {
                rd_bool_t commit       = i == 0;
                const char *commit_str = commit ? "commit" : "abort";
                rd_kafka_error_t *error;
                test_timing_t t_call;

                /* Messages will fail on as the transaction fails,
                 * ignore the DR error */
                test_curr->ignore_dr_err = rd_true;

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                TEST_CALL_ERR__(rd_kafka_producev(
                    rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_VALUE("hi", 2),
                    RD_KAFKA_V_END));

                /*
                 * Commit/abort transaction, first with som retriable failures,
                 * then success.
                 */
                rd_kafka_mock_push_request_errors(
                    mcluster, RD_KAFKAP_EndTxn, 10,
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

                TEST_SAY("%s returned %s\n", commit_str,
                         error ? rd_kafka_error_string(error) : "success");

                TEST_ASSERT(!error, "Expected %s to succeed, got %s",
                            commit_str, rd_kafka_error_string(error));
        }

        /* All done */

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}



/**
 * @brief Test that the commit/abort user timeout is honoured.
 */
static void do_test_txn_endtxn_timeout(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster = NULL;
        const char *txnid                 = "myTxnId";
        int i;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, NULL);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        for (i = 0; i < 2; i++) {
                rd_bool_t commit       = i == 0;
                const char *commit_str = commit ? "commit" : "abort";
                rd_kafka_error_t *error;
                test_timing_t t_call;

                /* Messages will fail as the transaction fails,
                 * ignore the DR error */
                test_curr->ignore_dr_err = rd_true;

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                TEST_CALL_ERR__(rd_kafka_producev(
                    rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_VALUE("hi", 2),
                    RD_KAFKA_V_END));

                /*
                 * Commit/abort transaction, first with some retriable failures
                 * whos retries exceed the user timeout.
                 */
                rd_kafka_mock_push_request_errors(
                    mcluster, RD_KAFKAP_EndTxn, 10,
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

                TEST_SAY_ERROR(error, "%s returned: ", commit_str);
                TEST_ASSERT(error != NULL, "Expected %s to fail", commit_str);
                TEST_ASSERT(
                    rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected %s to fail with timeout, not %s: %s", commit_str,
                    rd_kafka_error_name(error), rd_kafka_error_string(error));
                TEST_ASSERT(rd_kafka_error_is_retriable(error),
                            "%s failure should raise a retriable error",
                            commit_str);
                rd_kafka_error_destroy(error);

                /* Now call it again with an infinite timeout, should work. */
                TIMING_START(&t_call, "%s_transaction() nr 2", commit_str);
                if (commit)
                        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));
                else
                        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));
                TIMING_STOP(&t_call);
        }

        /* All done */

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}



/**
 * @brief Test commit/abort inflight timeout behaviour, which should result
 *        in a retriable error.
 */
static void do_test_txn_endtxn_timeout_inflight(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster = NULL;
        const char *txnid                 = "myTxnId";
        int32_t coord_id                  = 1;
        int i;

        SUB_TEST();

        allowed_error          = RD_KAFKA_RESP_ERR__TIMED_OUT;
        test_curr->is_fatal_cb = error_is_fatal_cb;

        rk = create_txn_producer(&mcluster, txnid, 1, "transaction.timeout.ms",
                                 "5000", NULL);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        for (i = 0; i < 2; i++) {
                rd_bool_t commit       = i == 0;
                const char *commit_str = commit ? "commit" : "abort";
                rd_kafka_error_t *error;
                test_timing_t t_call;

                /* Messages will fail as the transaction fails,
                 * ignore the DR error */
                test_curr->ignore_dr_err = rd_true;

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                TEST_CALL_ERR__(rd_kafka_producev(
                    rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_VALUE("hi", 2),
                    RD_KAFKA_V_END));

                /* Let EndTxn & EndTxn retry timeout */
                rd_kafka_mock_broker_push_request_error_rtts(
                    mcluster, coord_id, RD_KAFKAP_EndTxn, 2,
                    RD_KAFKA_RESP_ERR_NO_ERROR, 10000,
                    RD_KAFKA_RESP_ERR_NO_ERROR, 10000);

                rd_sleep(1);

                TIMING_START(&t_call, "%s_transaction()", commit_str);
                if (commit)
                        error = rd_kafka_commit_transaction(rk, 4000);
                else
                        error = rd_kafka_abort_transaction(rk, 4000);
                TIMING_STOP(&t_call);

                TEST_SAY_ERROR(error, "%s returned: ", commit_str);
                TEST_ASSERT(error != NULL, "Expected %s to fail", commit_str);
                TEST_ASSERT(
                    rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected %s to fail with timeout, not %s: %s", commit_str,
                    rd_kafka_error_name(error), rd_kafka_error_string(error));
                TEST_ASSERT(rd_kafka_error_is_retriable(error),
                            "%s failure should raise a retriable error",
                            commit_str);
                rd_kafka_error_destroy(error);

                /* Now call it again with an infinite timeout, should work. */
                TIMING_START(&t_call, "%s_transaction() nr 2", commit_str);
                if (commit)
                        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));
                else
                        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));
                TIMING_STOP(&t_call);
        }

        /* All done */

        rd_kafka_destroy(rk);

        allowed_error          = RD_KAFKA_RESP_ERR_NO_ERROR;
        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}



/**
 * @brief Test that EndTxn is properly sent for aborted transactions
 *        even if AddOffsetsToTxnRequest was retried.
 *        This is a check for a txn_req_cnt bug.
 */
static void do_test_txn_req_cnt(void) {
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
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;
        rd_kafka_topic_partition_list_add(offsets, "srctopic64", 40)->offset =
            999999111;

        rd_kafka_mock_push_request_errors(mcluster, RD_KAFKAP_AddOffsetsToTxn,
                                          2,
                                          RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
                                          RD_KAFKA_RESP_ERR_NOT_COORDINATOR);

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_TxnOffsetCommit, 2,
            RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));

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
static void do_test_txn_requires_abort_errors(void) {
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
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        /* Wait for messages to fail */
        test_flush(rk, 5000);

        /* Any other transactional API should now raise an error */
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        error =
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1);

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);
        TEST_ASSERT(error, "expected error");
        TEST_ASSERT(rd_kafka_error_txn_requires_abort(error),
                    "expected abortable error, not %s",
                    rd_kafka_error_string(error));
        TEST_SAY("Error %s: %s\n", rd_kafka_error_name(error),
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
            mcluster, RD_KAFKAP_AddPartitionsToTxn, 1,
            RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        error = rd_kafka_commit_transaction(rk, 5000);
        TEST_ASSERT(error, "commit_transaction should have failed");
        TEST_SAY("commit_transaction() error %s: %s\n",
                 rd_kafka_error_name(error), rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        /*
         * 3. Restart transaction and fail on AddOffsetsToTxn
         */
        TEST_SAY("3. Fail on AddOffsetsToTxn\n");

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_AddOffsetsToTxn, 1,
            RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED);

        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;
        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        error =
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1);
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
static void do_test_txn_broker_down_in_txn(rd_bool_t down_coord) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int32_t coord_id, leader_id, down_id;
        const char *down_what;
        rd_kafka_resp_err_t err;
        const char *topic            = "test";
        const char *transactional_id = "txnid";
        int msgcnt                   = 1000;
        int remains                  = 0;

        /* Assign coordinator and leader to two different brokers */
        coord_id  = 1;
        leader_id = 2;
        if (down_coord) {
                down_id   = coord_id;
                down_what = "coordinator";
        } else {
                down_id   = leader_id;
                down_what = "leader";
        }

        SUB_TEST_QUICK("Test %s down", down_what);

        rk = create_txn_producer(&mcluster, transactional_id, 3, NULL);

        /* Broker down is not a test-failing error */
        allowed_error          = RD_KAFKA_RESP_ERR__TRANSPORT;
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

        test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA, 0,
                                  msgcnt / 2, NULL, 0, &remains);

        TEST_SAY("Bringing down %s %" PRId32 "\n", down_what, down_id);
        rd_kafka_mock_broker_set_down(mcluster, down_id);

        rd_kafka_flush(rk, 3000);

        /* Produce remaining messages */
        test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA,
                                  msgcnt / 2, msgcnt / 2, NULL, 0, &remains);

        rd_sleep(2);

        TEST_SAY("Bringing up %s %" PRId32 "\n", down_what, down_id);
        rd_kafka_mock_broker_set_up(mcluster, down_id);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

        TEST_ASSERT(remains == 0, "%d message(s) were not produced\n", remains);

        rd_kafka_destroy(rk);

        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}



/**
 * @brief Advance the coord_id to the next broker.
 */
static void set_next_coord(rd_kafka_mock_cluster_t *mcluster,
                           const char *transactional_id,
                           int broker_cnt,
                           int32_t *coord_idp) {
        int32_t new_coord_id;

        new_coord_id = 1 + ((*coord_idp) % (broker_cnt));
        TEST_SAY("Changing transaction coordinator from %" PRId32 " to %" PRId32
                 "\n",
                 *coord_idp, new_coord_id);
        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      new_coord_id);

        *coord_idp = new_coord_id;
}

/**
 * @brief Switch coordinator during a transaction.
 *
 */
static void do_test_txn_switch_coordinator(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int32_t coord_id;
        const char *topic            = "test";
        const char *transactional_id = "txnid";
        const int broker_cnt         = 5;
        const int iterations         = 20;
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

        for (i = 0; i < iterations; i++) {
                const int msgcnt = 100;
                int remains      = 0;

                set_next_coord(mcluster, transactional_id, broker_cnt,
                               &coord_id);

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

                test_produce_msgs2(rk, topic, 0, RD_KAFKA_PARTITION_UA, 0,
                                   msgcnt / 2, NULL, 0);

                if (!(i % 3))
                        set_next_coord(mcluster, transactional_id, broker_cnt,
                                       &coord_id);

                /* Produce remaining messages */
                test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA,
                                          msgcnt / 2, msgcnt / 2, NULL, 0,
                                          &remains);

                if ((i & 1) || !(i % 8))
                        set_next_coord(mcluster, transactional_id, broker_cnt,
                                       &coord_id);


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
 * @brief Switch coordinator during a transaction when AddOffsetsToTxn
 *        are sent. #3571.
 */
static void do_test_txn_switch_coordinator_refresh(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic            = "test";
        const char *transactional_id = "txnid";
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;

        SUB_TEST("Test switching coordinators (refresh)");

        rk = create_txn_producer(&mcluster, transactional_id, 3, NULL);

        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      1);

        /* Start transactioning */
        TEST_SAY("Starting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        /* Switch the coordinator so that AddOffsetsToTxnRequest
         * will respond with NOT_COORDINATOR. */
        TEST_SAY("Switching to coordinator 2\n");
        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      2);

        /*
         * Send some arbitrary offsets.
         */
        offsets = rd_kafka_topic_partition_list_new(4);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;
        rd_kafka_topic_partition_list_add(offsets, "srctopic64", 29)->offset =
            99999;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(rd_kafka_send_offsets_to_transaction(
            rk, offsets, cgmetadata, 20 * 1000));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);


        /* Produce some messages */
        test_produce_msgs2(rk, topic, 0, RD_KAFKA_PARTITION_UA, 0, 10, NULL, 0);

        /* And commit the transaction */
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Test fatal error handling when transactions are not supported
 *        by the broker.
 */
static void do_test_txns_not_supported(void) {
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
        rd_kafka_mock_set_apiversion(mcluster, 22 /*InitProducerId*/, -1, -1);


        rd_kafka_brokers_add(rk, rd_kafka_mock_cluster_bootstraps(mcluster));



        error = rd_kafka_init_transactions(rk, 5 * 1000);
        TEST_SAY("init_transactions() returned %s: %s\n",
                 error ? rd_kafka_error_name(error) : "success",
                 error ? rd_kafka_error_string(error) : "success");

        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE,
                    "Expected init_transactions() to fail with %s, not %s: %s",
                    rd_kafka_err2name(RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE),
                    rd_kafka_error_name(error), rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("test"),
                                RD_KAFKA_V_KEY("test", 4), RD_KAFKA_V_END);
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
static void do_test_txns_send_offsets_concurrent_is_retried(void) {
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

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        /* Wait for messages to be delivered */
        test_flush(rk, 5000);


        /*
         * Have AddOffsetsToTxn fail but eventually succeed due to
         * infinite retries.
         */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_AddOffsetsToTxn,
            1 + 5, /* first request + some retries */
            RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
            RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
            RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
            RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
            RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
            RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, 5000));

        /* All done */

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Verify that send_offsets_to_transaction() with no eligible offsets
 *        is handled properly - the call should succeed immediately and be
 *        repeatable.
 */
static void do_test_txns_send_offsets_non_eligible(void) {
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

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        /* Wait for messages to be delivered */
        test_flush(rk, 5000);

        /* Empty offsets list */
        offsets = rd_kafka_topic_partition_list_new(0);

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));

        /* Now call it again, should also succeed. */
        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));

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
static void do_test_txns_no_timeout_crash(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;

        SUB_TEST_QUICK();

        rk =
            create_txn_producer(&mcluster, "txnid", 3, "socket.timeout.ms",
                                "1000", "transaction.timeout.ms", "5000", NULL);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
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
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;
        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        error =
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1);
        TEST_ASSERT(error, "Expected send_offsets..() to fail");
        TEST_SAY("send_offsets..() failed with %serror: %s\n",
                 rd_kafka_error_is_retriable(error) ? "retriable " : "",
                 rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__TIMED_OUT,
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
        error =
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1);
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
static void do_test_txn_auth_failure(int16_t ApiKey,
                                     rd_kafka_resp_err_t ErrorCode) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;

        SUB_TEST_QUICK("ApiKey=%s ErrorCode=%s", rd_kafka_ApiKey2str(ApiKey),
                       rd_kafka_err2name(ErrorCode));

        rk = create_txn_producer(&mcluster, "txnid", 3, NULL);

        rd_kafka_mock_push_request_errors(mcluster, ApiKey, 1, ErrorCode);

        error = rd_kafka_init_transactions(rk, 5000);
        TEST_ASSERT(error, "Expected init_transactions() to fail");

        TEST_SAY("init_transactions() failed: %s: %s\n",
                 rd_kafka_err2name(rd_kafka_error_code(error)),
                 rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_code(error) == ErrorCode,
                    "Expected error %s, not %s", rd_kafka_err2name(ErrorCode),
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
static void do_test_txn_flush_timeout(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        rd_kafka_error_t *error;
        const char *txnid      = "myTxnId";
        const char *topic      = "myTopic";
        const int32_t coord_id = 2;
        int msgcounter         = 0;
        rd_bool_t is_retry     = rd_false;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, "message.timeout.ms",
                                 "10000", "transaction.timeout.ms", "10000",
                                 /* Speed up coordinator reconnect */
                                 "reconnect.backoff.max.ms", "1000", NULL);


        /* Broker down is not a test-failing error */
        test_curr->is_fatal_cb = error_is_fatal_cb;
        allowed_error          = RD_KAFKA_RESP_ERR__TRANSPORT;

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
                test_curr->exp_dr_err    = RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;

                /* Assign invalid partition leaders for some partitions so
                 * that messages will not be delivered. */
                rd_kafka_mock_partition_set_leader(mcluster, topic, 0, -1);
                rd_kafka_mock_partition_set_leader(mcluster, topic, 1, -1);

        } else {
                /* The retry should succeed */
                test_curr->ignore_dr_err = rd_false;
                test_curr->exp_dr_err    = is_retry
                                            ? RD_KAFKA_RESP_ERR_NO_ERROR
                                            : RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;

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
        test_produce_msgs2_nowait(rk, topic, RD_KAFKA_PARTITION_UA, 0, 0, 100,
                                  NULL, 10, &msgcounter);


        /*
         * Send some arbitrary offsets.
         */
        offsets = rd_kafka_topic_partition_list_new(4);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;
        rd_kafka_topic_partition_list_add(offsets, "srctopic64", 49)->offset =
            999999111;
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 0)->offset =
            999;
        rd_kafka_topic_partition_list_add(offsets, "srctopic64", 34)->offset =
            123456789;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        rd_sleep(2);

        if (!is_retry) {
                /* Now disconnect the coordinator. */
                TEST_SAY("Disconnecting transaction coordinator %" PRId32 "\n",
                         coord_id);
                rd_kafka_mock_broker_set_down(mcluster, coord_id);
        }

        /*
         * Start committing.
         */
        error = rd_kafka_commit_transaction(rk, -1);

        if (!is_retry) {
                TEST_ASSERT(error != NULL, "Expected commit to fail");
                TEST_SAY("commit_transaction() failed (expectedly): %s\n",
                         rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);

        } else {
                TEST_ASSERT(!error, "Expected commit to succeed, not: %s",
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
static void do_test_txn_coord_req_destroy(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int i;
        int errcnt = 0;

        SUB_TEST();

        rk = create_txn_producer(&mcluster, "txnid", 3, NULL);

        test_curr->ignore_dr_err = rd_true;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        for (i = 0; i < 15; i++) {
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
                    mcluster, RD_KAFKAP_AddPartitionsToTxn,
                    2, /* first request + number of internal retries */
                    RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                    RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

                rd_kafka_mock_push_request_errors(
                    mcluster, RD_KAFKAP_AddOffsetsToTxn,
                    1, /* first request + number of internal retries */
                    RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS);

                err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                        RD_KAFKA_V_VALUE("hi", 2),
                                        RD_KAFKA_V_END);
                TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

                rd_kafka_mock_push_request_errors(
                    mcluster, RD_KAFKAP_Produce, 4,
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
                    RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
                    RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED,
                    RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED);
                /* FIXME: When KIP-360 is supported, add this error:
                 *        RD_KAFKA_RESP_ERR_OUT_OF_ORDER_SEQUENCE_NUMBER */

                err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                        RD_KAFKA_V_VALUE("hi", 2),
                                        RD_KAFKA_V_END);
                TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));


                /*
                 * Send offsets to transaction
                 */

                offsets = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)
                    ->offset = 12;

                cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

                error = rd_kafka_send_offsets_to_transaction(rk, offsets,
                                                             cgmetadata, -1);

                TEST_SAY("send_offsets_to_transaction() #%d: %s\n", i,
                         rd_kafka_error_string(error));

                /* As we can't control the exact timing and sequence
                 * of requests this sometimes fails and sometimes succeeds,
                 * but we run the test enough times to trigger at least
                 * one failure. */
                if (error) {
                        TEST_SAY(
                            "send_offsets_to_transaction() #%d "
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
multi_find_on_response_received_cb(rd_kafka_t *rk,
                                   int sockfd,
                                   const char *brokername,
                                   int32_t brokerid,
                                   int16_t ApiKey,
                                   int16_t ApiVersion,
                                   int32_t CorrId,
                                   size_t size,
                                   int64_t rtt,
                                   rd_kafka_resp_err_t err,
                                   void *ic_opaque) {
        rd_kafka_mock_cluster_t *mcluster = rd_kafka_handle_mock_cluster(rk);
        rd_bool_t done = rd_atomic32_get(&multi_find_req_cnt) > 10000;

        if (ApiKey != RD_KAFKAP_AddOffsetsToTxn || done)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        TEST_SAY("on_response_received_cb: %s: %s: brokerid %" PRId32
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
static void do_test_txn_coord_req_multi_find(void) {
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
        rk                      = create_txn_producer(&mcluster, txnid, 3,
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
        allowed_error          = RD_KAFKA_RESP_ERR__TRANSPORT;
        test_curr->is_fatal_cb = error_is_fatal_cb;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        for (i = 0; i < 3; i++) {
                err = rd_kafka_producev(
                    rk, RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_PARTITION(i),
                    RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
                TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));
        }

        test_flush(rk, 5000);

        /*
         * send_offsets_to_transaction() will query for the group coordinator,
         * we need to make those requests slow so that multiple requests are
         * sent.
         */
        for (i = 1; i <= 3; i++)
                rd_kafka_mock_broker_set_rtt(mcluster, (int32_t)i, 4000);

        /*
         * Send offsets to transaction
         */

        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 12;

        cgmetadata = rd_kafka_consumer_group_metadata_new(groupid);

        error =
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1);

        TEST_SAY("send_offsets_to_transaction() %s\n",
                 rd_kafka_error_string(error));
        TEST_ASSERT(!error, "send_offsets_to_transaction() failed: %s",
                    rd_kafka_error_string(error));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        /* Clear delay */
        for (i = 1; i <= 3; i++)
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
multi_addparts_response_received_cb(rd_kafka_t *rk,
                                    int sockfd,
                                    const char *brokername,
                                    int32_t brokerid,
                                    int16_t ApiKey,
                                    int16_t ApiVersion,
                                    int32_t CorrId,
                                    size_t size,
                                    int64_t rtt,
                                    rd_kafka_resp_err_t err,
                                    void *ic_opaque) {

        if (ApiKey == RD_KAFKAP_AddPartitionsToTxn) {
                TEST_SAY("on_response_received_cb: %s: %s: brokerid %" PRId32
                         ", ApiKey %hd, CorrId %d, rtt %.2fms, count %" PRId32
                         ": %s\n",
                         rd_kafka_name(rk), brokername, brokerid, ApiKey,
                         CorrId, rtt != -1 ? (float)rtt / 1000.0 : 0.0,
                         rd_atomic32_get(&multi_addparts_resp_cnt),
                         rd_kafka_err2name(err));

                rd_atomic32_add(&multi_addparts_resp_cnt, 1);
        }

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static void do_test_txn_addparts_req_multi(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        const char *txnid = "txnid", *topic = "mytopic";
        int32_t txn_coord = 2;

        SUB_TEST();

        rd_atomic32_init(&multi_addparts_resp_cnt, 0);

        on_response_received_cb = multi_addparts_response_received_cb;
        rk = create_txn_producer(&mcluster, txnid, 3, "linger.ms", "0",
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
        TEST_CALL_ERR__(rd_kafka_producev(rk, RD_KAFKA_V_TOPIC(topic),
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
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        rd_usleep(500 * 1000, NULL);

        /* Produce to partition 1 */
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_PARTITION(1),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        TEST_SAY("Waiting for two AddPartitionsToTxnResponse\n");
        while (rd_atomic32_get(&multi_addparts_resp_cnt) < 2)
                rd_usleep(10 * 1000, NULL);

        TEST_SAY("%" PRId32 " AddPartitionsToTxnResponses seen\n",
                 rd_atomic32_get(&multi_addparts_resp_cnt));

        /* Produce to partition 2, this message will hang in
         * queue if the bug is not fixed. */
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_PARTITION(2),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        /* Allow some extra time for things to settle before committing
         * transaction. */
        rd_usleep(1000 * 1000, NULL);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, 10 * 1000));

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
static void do_test_unstable_offset_commit(void) {
        rd_kafka_t *rk, *c;
        rd_kafka_conf_t *c_conf;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_topic_partition_list_t *offsets;
        const char *topic              = "srctopic4";
        const int msgcnt               = 100;
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
        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, msgcnt, NULL, 0,
                                  &remains);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));


        /* Commit offset */
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, topic, 0)->offset =
            offset_to_commit;
        TEST_CALL_ERR__(rd_kafka_commit(c, offsets, 0 /*sync*/));
        rd_kafka_topic_partition_list_destroy(offsets);

        /* Retrieve offsets by calling committed().
         *
         * Have OffsetFetch fail and retry, on the first iteration
         * the API timeout is higher than the amount of time the retries will
         * take and thus succeed, and on the second iteration the timeout
         * will be lower and thus fail. */
        for (i = 0; i < 2; i++) {
                rd_kafka_resp_err_t err;
                rd_kafka_resp_err_t exp_err =
                    i == 0 ? RD_KAFKA_RESP_ERR_NO_ERROR
                           : RD_KAFKA_RESP_ERR__TIMED_OUT;
                int timeout_ms = exp_err ? 200 : 5 * 1000;

                rd_kafka_mock_push_request_errors(
                    mcluster, RD_KAFKAP_OffsetFetch,
                    1 + 5, /* first request + some retries */
                    RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                    RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                    RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                    RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                    RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
                    RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT);

                offsets = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(offsets, topic, 0);

                err = rd_kafka_committed(c, offsets, timeout_ms);

                TEST_SAY("#%d: committed() returned %s (expected %s)\n", i,
                         rd_kafka_err2name(err), rd_kafka_err2name(exp_err));

                TEST_ASSERT(err == exp_err,
                            "#%d: Expected committed() to return %s, not %s", i,
                            rd_kafka_err2name(exp_err), rd_kafka_err2name(err));
                TEST_ASSERT(offsets->cnt == 1,
                            "Expected 1 committed offset, not %d",
                            offsets->cnt);
                if (!exp_err)
                        TEST_ASSERT(offsets->elems[0].offset ==
                                        offset_to_commit,
                                    "Expected committed offset %" PRId64
                                    ", "
                                    "not %" PRId64,
                                    offset_to_commit, offsets->elems[0].offset);
                else
                        TEST_ASSERT(offsets->elems[0].offset < 0,
                                    "Expected no committed offset, "
                                    "not %" PRId64,
                                    offsets->elems[0].offset);

                rd_kafka_topic_partition_list_destroy(offsets);
        }

        TEST_SAY("Phase 2: OffsetFetch lookup through assignment\n");
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, topic, 0)->offset =
            RD_KAFKA_OFFSET_STORED;

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_OffsetFetch,
            1 + 5, /* first request + some retries */
            RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
            RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
            RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
            RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
            RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT,
            RD_KAFKA_RESP_ERR_UNSTABLE_OFFSET_COMMIT);

        test_consumer_incremental_assign("assign", c, offsets);
        rd_kafka_topic_partition_list_destroy(offsets);

        test_consumer_poll_exact("consume", c, 0, 1 /*eof*/, 0, msgcnt / 2,
                                 rd_true /*exact counts*/, NULL);

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
static void do_test_commit_after_msg_timeout(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int32_t coord_id, leader_id;
        rd_kafka_resp_err_t err;
        rd_kafka_error_t *error;
        const char *topic            = "test";
        const char *transactional_id = "txnid";
        int remains                  = 0;

        SUB_TEST_QUICK();

        /* Assign coordinator and leader to two different brokers */
        coord_id  = 1;
        leader_id = 2;

        rk = create_txn_producer(&mcluster, transactional_id, 3,
                                 "message.timeout.ms", "5000",
                                 "transaction.timeout.ms", "10000", NULL);

        /* Broker down is not a test-failing error */
        allowed_error          = RD_KAFKA_RESP_ERR__TRANSPORT;
        test_curr->is_fatal_cb = error_is_fatal_cb;
        test_curr->exp_dr_err  = RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;

        err = rd_kafka_mock_topic_create(mcluster, topic, 1, 3);
        TEST_ASSERT(!err, "Failed to create topic: %s", rd_kafka_err2str(err));

        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      coord_id);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, leader_id);

        /* Start transactioning */
        TEST_SAY("Starting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        TEST_SAY("Bringing down %" PRId32 "\n", leader_id);
        rd_kafka_mock_broker_set_down(mcluster, leader_id);
        rd_kafka_mock_broker_set_down(mcluster, coord_id);

        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, 1, NULL, 0, &remains);

        error = rd_kafka_commit_transaction(rk, -1);
        TEST_ASSERT(error != NULL, "expected commit_transaciton() to fail");
        TEST_SAY_ERROR(error, "commit_transaction() failed (as expected): ");
        TEST_ASSERT(rd_kafka_error_txn_requires_abort(error),
                    "Expected txn_requires_abort error");
        rd_kafka_error_destroy(error);

        /* Bring the brokers up so the abort can complete */
        rd_kafka_mock_broker_set_up(mcluster, coord_id);
        rd_kafka_mock_broker_set_up(mcluster, leader_id);

        TEST_SAY("Aborting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        TEST_ASSERT(remains == 0, "%d message(s) were not flushed\n", remains);

        TEST_SAY("Attempting second transaction, which should succeed\n");
        test_curr->is_fatal_cb = error_is_fatal_cb;
        test_curr->exp_dr_err  = RD_KAFKA_RESP_ERR_NO_ERROR;

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));
        test_produce_msgs2_nowait(rk, topic, 0, 0, 0, 1, NULL, 0, &remains);

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

        TEST_ASSERT(remains == 0, "%d message(s) were not produced\n", remains);

        rd_kafka_destroy(rk);

        allowed_error          = RD_KAFKA_RESP_ERR_NO_ERROR;
        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}


/**
 * @brief #3575: Verify that OUT_OF_ORDER_SEQ does not trigger an epoch bump
 *        during an ongoing transaction.
 *        The transaction should instead enter the abortable state.
 */
static void do_test_out_of_order_seq(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        int32_t txn_coord = 1, leader = 2;
        const char *txnid = "myTxnId";
        test_timing_t timing;
        rd_kafka_resp_err_t err;

        SUB_TEST_QUICK();

        rk = create_txn_producer(&mcluster, txnid, 3, "batch.num.messages", "1",
                                 NULL);

        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid,
                                      txn_coord);

        rd_kafka_mock_partition_set_leader(mcluster, "mytopic", 0, leader);

        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb   = NULL;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));



        /* Produce one seeding message first to get the leader up and running */
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));
        test_flush(rk, -1);

        /* Let partition leader have a latency of 2 seconds
         * so that we can have multiple messages in-flight. */
        rd_kafka_mock_broker_set_rtt(mcluster, leader, 2 * 1000);

        /* Produce a message, let it fail with with different errors,
         * ending with OUT_OF_ORDER which previously triggered an
         * Epoch bump. */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 3,
            RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION,
            RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION,
            RD_KAFKA_RESP_ERR_OUT_OF_ORDER_SEQUENCE_NUMBER);

        /* Produce three messages that will be delayed
         * and have errors injected.*/
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        /* Now sleep a short while so that the messages are processed
         * by the broker and errors are returned. */
        TEST_SAY("Sleeping..\n");
        rd_sleep(5);

        rd_kafka_mock_broker_set_rtt(mcluster, leader, 0);

        /* Produce a fifth message, should fail with ERR__STATE since
         * the transaction should have entered the abortable state. */
        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_PARTITION(0),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__STATE,
                    "Expected produce() to fail with ERR__STATE, not %s",
                    rd_kafka_err2name(err));
        TEST_SAY("produce() failed as expected: %s\n", rd_kafka_err2str(err));

        /* Commit the transaction, should fail with abortable error. */
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

        /* Abort the transaction */
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));

        /* Run a new transaction without errors to verify that the
         * producer can recover. */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Verify lossless delivery if topic disappears from Metadata for awhile.
 *
 * If a topic is removed from metadata inbetween transactions, the producer
 * will remove its partition state for the topic's partitions.
 * If later the same topic comes back (same topic instance, not a new creation)
 * then the producer must restore the previously used msgid/BaseSequence
 * in case the same Epoch is still used, or messages will be silently lost
 * as they would seem like legit duplicates to the broker.
 *
 * Reproduction:
 *   1. produce msgs to topic, commit transaction.
 *   2. remove topic from metadata
 *   3. make sure client updates its metadata, which removes the partition
 *      objects.
 *   4. restore the topic in metadata
 *   5. produce new msgs to topic, commit transaction.
 *   6. consume topic. All messages should be accounted for.
 */
static void do_test_topic_disappears_for_awhile(void) {
        rd_kafka_t *rk, *c;
        rd_kafka_conf_t *c_conf;
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic = "mytopic";
        const char *txnid = "myTxnId";
        test_timing_t timing;
        int i;
        int msgcnt              = 0;
        const int partition_cnt = 10;

        SUB_TEST_QUICK();

        rk = create_txn_producer(
            &mcluster, txnid, 1, "batch.num.messages", "3", "linger.ms", "100",
            "topic.metadata.refresh.interval.ms", "2000", NULL);

        rd_kafka_mock_topic_create(mcluster, topic, partition_cnt, 1);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        for (i = 0; i < 2; i++) {
                int cnt                = 3 * 2 * partition_cnt;
                rd_bool_t remove_topic = (i % 2) == 0;
                /*
                 * Start a transaction
                 */
                TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


                while (cnt-- >= 0) {
                        TEST_CALL_ERR__(rd_kafka_producev(
                            rk, RD_KAFKA_V_TOPIC(topic),
                            RD_KAFKA_V_PARTITION(cnt % partition_cnt),
                            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));
                        msgcnt++;
                }

                /* Commit the transaction */
                TIMING_START(&timing, "commit_transaction(-1)");
                TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));
                TIMING_STOP(&timing);



                if (remove_topic) {
                        /* Make it seem the topic is removed, refresh metadata,
                         * and then make the topic available again. */
                        const rd_kafka_metadata_t *md;

                        TEST_SAY("Marking topic as non-existent\n");

                        rd_kafka_mock_topic_set_error(
                            mcluster, topic,
                            RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);

                        TEST_CALL_ERR__(rd_kafka_metadata(rk, 0, NULL, &md,
                                                          tmout_multip(5000)));

                        rd_kafka_metadata_destroy(md);

                        rd_sleep(2);

                        TEST_SAY("Bringing topic back to life\n");
                        rd_kafka_mock_topic_set_error(
                            mcluster, topic, RD_KAFKA_RESP_ERR_NO_ERROR);
                }
        }

        TEST_SAY("Verifying messages by consumtion\n");
        test_conf_init(&c_conf, NULL, 0);
        test_conf_set(c_conf, "security.protocol", "PLAINTEXT");
        test_conf_set(c_conf, "bootstrap.servers",
                      rd_kafka_mock_cluster_bootstraps(mcluster));
        test_conf_set(c_conf, "enable.partition.eof", "true");
        test_conf_set(c_conf, "auto.offset.reset", "earliest");
        c = test_create_consumer("mygroup", NULL, c_conf, NULL);

        test_consumer_subscribe(c, topic);
        test_consumer_poll_exact("consume", c, 0, partition_cnt, 0, msgcnt,
                                 rd_true /*exact*/, NULL);
        rd_kafka_destroy(c);


        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Test that group coordinator requests can handle an
 *        untimely disconnect.
 *
 * The transaction manager makes use of librdkafka coord_req to commit
 * transaction offsets to the group coordinator.
 * If the connection to the given group coordinator is not up the
 * coord_req code will request a connection once, but if this connection fails
 * there will be no new attempts and the coord_req will idle until either
 * destroyed or the connection is retried for other reasons.
 * This in turn stalls the send_offsets_to_transaction() call until the
 * transaction times out.
 *
 * There are two variants to this test based on switch_coord:
 *  - True - Switches the coordinator during the downtime.
 *           The client should detect this and send the request to the
 *           new coordinator.
 *  - False - The coordinator remains on the down broker. Client will reconnect
 *            when down broker comes up again.
 */
struct some_state {
        rd_kafka_mock_cluster_t *mcluster;
        rd_bool_t switch_coord;
        int32_t broker_id;
        const char *grpid;
};

static int delayed_up_cb(void *arg) {
        struct some_state *state = arg;
        rd_sleep(3);
        if (state->switch_coord) {
                TEST_SAY("Switching group coordinator to %" PRId32 "\n",
                         state->broker_id);
                rd_kafka_mock_coordinator_set(state->mcluster, "group",
                                              state->grpid, state->broker_id);
        } else {
                TEST_SAY("Bringing up group coordinator %" PRId32 "..\n",
                         state->broker_id);
                rd_kafka_mock_broker_set_up(state->mcluster, state->broker_id);
        }
        return 0;
}

static void do_test_disconnected_group_coord(rd_bool_t switch_coord) {
        const char *topic       = "mytopic";
        const char *txnid       = "myTxnId";
        const char *grpid       = "myGrpId";
        const int partition_cnt = 1;
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        struct some_state state = RD_ZERO_INIT;
        test_timing_t timing;
        thrd_t thrd;
        int ret;

        SUB_TEST_QUICK("switch_coord=%s", RD_STR_ToF(switch_coord));

        test_curr->is_fatal_cb = error_is_fatal_cb;
        allowed_error          = RD_KAFKA_RESP_ERR__TRANSPORT;

        rk = create_txn_producer(&mcluster, txnid, 3, NULL);

        rd_kafka_mock_topic_create(mcluster, topic, partition_cnt, 1);

        /* Broker 1: txn coordinator
         * Broker 2: group coordinator
         * Broker 3: partition leader & backup coord if switch_coord=true */
        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid, 1);
        rd_kafka_mock_coordinator_set(mcluster, "group", grpid, 2);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 3);

        /* Bring down group coordinator so there are no undesired
         * connections to it. */
        rd_kafka_mock_broker_set_down(mcluster, 2);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));
        test_flush(rk, -1);

        rd_sleep(1);

        /* Run a background thread that after 3s, which should be enough
         * to perform the first failed connection attempt, makes the
         * group coordinator available again. */
        state.switch_coord = switch_coord;
        state.mcluster     = mcluster;
        state.grpid        = grpid;
        state.broker_id    = switch_coord ? 3 : 2;
        if (thrd_create(&thrd, delayed_up_cb, &state) != thrd_success)
                TEST_FAIL("Failed to create thread");

        TEST_SAY("Calling send_offsets_to_transaction()\n");
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 0)->offset = 1;
        cgmetadata = rd_kafka_consumer_group_metadata_new(grpid);

        TIMING_START(&timing, "send_offsets_to_transaction(-1)");
        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));
        TIMING_STOP(&timing);
        TIMING_ASSERT(&timing, 0, 10 * 1000 /*10s*/);

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);
        thrd_join(thrd, &ret);

        /* Commit the transaction */
        TIMING_START(&timing, "commit_transaction(-1)");
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));
        TIMING_STOP(&timing);

        rd_kafka_destroy(rk);

        allowed_error          = RD_KAFKA_RESP_ERR_NO_ERROR;
        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}


/**
 * @brief Test that a NULL coordinator is not fatal when
 * the transactional producer reconnects to the txn coordinator
 * and the first thing it does is a FindCoordinatorRequest that
 * fails with COORDINATOR_NOT_AVAILABLE, setting coordinator to NULL.
 */
static void do_test_txn_coordinator_null_not_fatal(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        int32_t coord_id             = 1;
        const char *topic            = "test";
        const char *transactional_id = "txnid";
        int msgcnt                   = 1;
        int remains                  = 0;

        SUB_TEST_QUICK();

        /* Broker down is not a test-failing error */
        allowed_error          = RD_KAFKA_RESP_ERR__TRANSPORT;
        test_curr->is_fatal_cb = error_is_fatal_cb;
        test_curr->exp_dr_err  = RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;

        /* One second is the minimum transaction timeout */
        rk = create_txn_producer(&mcluster, transactional_id, 1,
                                 "transaction.timeout.ms", "1000", NULL);

        err = rd_kafka_mock_topic_create(mcluster, topic, 1, 1);
        TEST_ASSERT(!err, "Failed to create topic: %s", rd_kafka_err2str(err));

        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      coord_id);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, coord_id);

        /* Start transactioning */
        TEST_SAY("Starting transaction\n");
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        /* Makes the produce request timeout. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, coord_id, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, 3000);

        test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA, 0,
                                  msgcnt, NULL, 0, &remains);

        /* This value is linked to transaction.timeout.ms, needs enough time
         * so the message times out and a DrainBump sequence is started. */
        rd_kafka_flush(rk, 1000);

        /* To trigger the error the COORDINATOR_NOT_AVAILABLE response
         * must come AFTER idempotent state has changed to WaitTransport
         * but BEFORE it changes to WaitPID. To make it more likely
         * rd_kafka_txn_coord_timer_start timeout can be changed to 5 ms
         * in rd_kafka_txn_coord_query, when unable to query for
         * transaction coordinator.
         */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, coord_id, RD_KAFKAP_FindCoordinator, 1,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE, 10);

        /* Coordinator down starts the FindCoordinatorRequest loop. */
        TEST_SAY("Bringing down coordinator %" PRId32 "\n", coord_id);
        rd_kafka_mock_broker_set_down(mcluster, coord_id);

        /* Coordinator down for some time. */
        rd_usleep(100 * 1000, NULL);

        /* When it comes up, the error is triggered, if the preconditions
         * happen. */
        TEST_SAY("Bringing up coordinator %" PRId32 "\n", coord_id);
        rd_kafka_mock_broker_set_up(mcluster, coord_id);

        /* Make sure DRs are received */
        rd_kafka_flush(rk, 1000);

        error = rd_kafka_commit_transaction(rk, -1);

        TEST_ASSERT(remains == 0, "%d message(s) were not produced\n", remains);
        TEST_ASSERT(error != NULL, "Expected commit_transaction() to fail");
        TEST_SAY("commit_transaction() failed (expectedly): %s\n",
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        /* Needs to wait some time before closing to make sure it doesn't go
         * into TERMINATING state before error is triggered. */
        rd_usleep(1000 * 1000, NULL);
        rd_kafka_destroy(rk);

        allowed_error          = RD_KAFKA_RESP_ERR_NO_ERROR;
        test_curr->exp_dr_err  = RD_KAFKA_RESP_ERR_NO_ERROR;
        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}



/**
 * @brief Simple test to make sure the init_transactions() timeout is honoured
 *        and also not infinite.
 */
static void do_test_txn_resumable_init(void) {
        rd_kafka_t *rk;
        const char *transactional_id = "txnid";
        rd_kafka_error_t *error;
        test_timing_t duration;

        SUB_TEST();

        rd_kafka_conf_t *conf;

        test_conf_init(&conf, NULL, 20);
        test_conf_set(conf, "bootstrap.servers", "");
        test_conf_set(conf, "transactional.id", transactional_id);
        test_conf_set(conf, "transaction.timeout.ms", "4000");

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* First make sure a lower timeout is honoured. */
        TIMING_START(&duration, "init_transactions(1000)");
        error = rd_kafka_init_transactions(rk, 1000);
        TIMING_STOP(&duration);

        if (error)
                TEST_SAY("First init_transactions failed (as expected): %s\n",
                         rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected _TIMED_OUT, not %s",
                    error ? rd_kafka_error_string(error) : "success");
        rd_kafka_error_destroy(error);

        TIMING_ASSERT(&duration, 900, 1500);

        TEST_SAY(
            "Performing second init_transactions() call now with an "
            "infinite timeout: "
            "should time out in 2 x transaction.timeout.ms\n");

        TIMING_START(&duration, "init_transactions(infinite)");
        error = rd_kafka_init_transactions(rk, -1);
        TIMING_STOP(&duration);

        if (error)
                TEST_SAY("Second init_transactions failed (as expected): %s\n",
                         rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected _TIMED_OUT, not %s",
                    error ? rd_kafka_error_string(error) : "success");
        rd_kafka_error_destroy(error);

        TIMING_ASSERT(&duration, 2 * 4000 - 500, 2 * 4000 + 500);

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Retries a transaction call until it succeeds or returns a
 *        non-retriable error - which will cause the test to fail.
 *
 * @param intermed_calls Is a block of code that will be called after each
 *                       retriable failure of \p call.
 */
#define RETRY_TXN_CALL__(call, intermed_calls)                                 \
        do {                                                                   \
                rd_kafka_error_t *_error = call;                               \
                if (!_error)                                                   \
                        break;                                                 \
                TEST_SAY_ERROR(_error, "%s: ", "" #call);                      \
                TEST_ASSERT(rd_kafka_error_is_retriable(_error),               \
                            "Expected retriable error");                       \
                TEST_SAY("%s failed, retrying in 1 second\n", "" #call);       \
                rd_kafka_error_destroy(_error);                                \
                intermed_calls;                                                \
                rd_sleep(1);                                                   \
        } while (1)

/**
 * @brief Call \p call and expect it to fail with \p exp_err_code.
 */
#define TXN_CALL_EXPECT_ERROR__(call, exp_err_code)                            \
        do {                                                                   \
                rd_kafka_error_t *_error = call;                               \
                TEST_ASSERT(_error != NULL,                                    \
                            "%s: Expected %s error, got success", "" #call,    \
                            rd_kafka_err2name(exp_err_code));                  \
                TEST_SAY_ERROR(_error, "%s: ", "" #call);                      \
                TEST_ASSERT(rd_kafka_error_code(_error) == exp_err_code,       \
                            "%s: Expected %s error, got %s", "" #call,         \
                            rd_kafka_err2name(exp_err_code),                   \
                            rd_kafka_error_name(_error));                      \
                rd_kafka_error_destroy(_error);                                \
        } while (0)


/**
 * @brief Simple test to make sure short API timeouts can be safely resumed
 *        by calling the same API again.
 *
 * @param do_commit Commit transaction if true, else abort transaction.
 */
static void do_test_txn_resumable_calls_timeout(rd_bool_t do_commit) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        int32_t coord_id             = 1;
        const char *topic            = "test";
        const char *transactional_id = "txnid";
        int msgcnt                   = 1;
        int remains                  = 0;

        SUB_TEST("%s_transaction", do_commit ? "commit" : "abort");

        rk = create_txn_producer(&mcluster, transactional_id, 1, NULL);

        err = rd_kafka_mock_topic_create(mcluster, topic, 1, 1);
        TEST_ASSERT(!err, "Failed to create topic: %s", rd_kafka_err2str(err));

        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      coord_id);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, coord_id);

        TEST_SAY("Starting transaction\n");
        TEST_SAY("Delaying first two InitProducerIdRequests by 500ms\n");
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, coord_id, RD_KAFKAP_InitProducerId, 2,
            RD_KAFKA_RESP_ERR_NO_ERROR, 500, RD_KAFKA_RESP_ERR_NO_ERROR, 500);

        RETRY_TXN_CALL__(
            rd_kafka_init_transactions(rk, 100),
            TXN_CALL_EXPECT_ERROR__(rd_kafka_abort_transaction(rk, -1),
                                    RD_KAFKA_RESP_ERR__CONFLICT));

        RETRY_TXN_CALL__(rd_kafka_begin_transaction(rk), /*none*/);


        TEST_SAY("Delaying ProduceRequests by 3000ms\n");
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, coord_id, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, 3000);

        test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA, 0,
                                  msgcnt, NULL, 0, &remains);


        TEST_SAY("Delaying SendOffsetsToTransaction by 400ms\n");
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, coord_id, RD_KAFKAP_AddOffsetsToTxn, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, 400);
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 0)->offset = 12;
        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        /* This is not a resumable call on timeout */
        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));

        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);


        TEST_SAY("Delaying EndTxnRequests by 1200ms\n");
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, coord_id, RD_KAFKAP_EndTxn, 1, RD_KAFKA_RESP_ERR_NO_ERROR,
            1200);

        /* Committing/aborting the transaction will also be delayed by the
         * previous accumulated remaining delays. */

        if (do_commit) {
                TEST_SAY("Committing transaction\n");

                RETRY_TXN_CALL__(
                    rd_kafka_commit_transaction(rk, 100),
                    TXN_CALL_EXPECT_ERROR__(rd_kafka_abort_transaction(rk, -1),
                                            RD_KAFKA_RESP_ERR__CONFLICT));
        } else {
                TEST_SAY("Aborting transaction\n");

                RETRY_TXN_CALL__(
                    rd_kafka_abort_transaction(rk, 100),
                    TXN_CALL_EXPECT_ERROR__(rd_kafka_commit_transaction(rk, -1),
                                            RD_KAFKA_RESP_ERR__CONFLICT));
        }

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Verify that resuming timed out calls that after the timeout, but
 *        before the resuming call, would error out.
 */
static void do_test_txn_resumable_calls_timeout_error(rd_bool_t do_commit) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_resp_err_t err;
        int32_t coord_id             = 1;
        const char *topic            = "test";
        const char *transactional_id = "txnid";
        int msgcnt                   = 1;
        int remains                  = 0;
        rd_kafka_error_t *error;

        SUB_TEST_QUICK("%s_transaction", do_commit ? "commit" : "abort");

        rk = create_txn_producer(&mcluster, transactional_id, 1, NULL);

        err = rd_kafka_mock_topic_create(mcluster, topic, 1, 1);
        TEST_ASSERT(!err, "Failed to create topic: %s", rd_kafka_err2str(err));

        rd_kafka_mock_coordinator_set(mcluster, "transaction", transactional_id,
                                      coord_id);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, coord_id);

        TEST_SAY("Starting transaction\n");

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA, 0,
                                  msgcnt, NULL, 0, &remains);


        TEST_SAY("Fail EndTxn fatally after 2000ms\n");
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, coord_id, RD_KAFKAP_EndTxn, 1,
            RD_KAFKA_RESP_ERR_INVALID_TXN_STATE, 2000);

        if (do_commit) {
                TEST_SAY("Committing transaction\n");

                TXN_CALL_EXPECT_ERROR__(rd_kafka_commit_transaction(rk, 500),
                                        RD_KAFKA_RESP_ERR__TIMED_OUT);

                /* Sleep so that the background EndTxn fails locally and sets
                 * an error result. */
                rd_sleep(3);

                error = rd_kafka_commit_transaction(rk, -1);

        } else {
                TEST_SAY("Aborting transaction\n");

                TXN_CALL_EXPECT_ERROR__(rd_kafka_commit_transaction(rk, 500),
                                        RD_KAFKA_RESP_ERR__TIMED_OUT);

                /* Sleep so that the background EndTxn fails locally and sets
                 * an error result. */
                rd_sleep(3);

                error = rd_kafka_commit_transaction(rk, -1);
        }

        TEST_ASSERT(error != NULL && rd_kafka_error_is_fatal(error),
                    "Expected fatal error, not %s",
                    rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR_INVALID_TXN_STATE,
                    "Expected error INVALID_TXN_STATE, got %s",
                    rd_kafka_error_name(error));
        rd_kafka_error_destroy(error);

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Concurrent transaction API calls are not permitted.
 *        This test makes sure they're properly enforced.
 *
 * For each transactional API, call it with a 5s timeout, and during that time
 * from another thread call transactional APIs, one by one, and verify that
 * we get an ERR__CONFLICT error back in the second thread.
 *
 * We use a mutex for synchronization, the main thread will hold the lock
 * when not calling an API but release it just prior to calling.
 * The other thread will acquire the lock, sleep, and hold the lock while
 * calling the concurrent API that should fail immediately, releasing the lock
 * when done.
 *
 */

struct _txn_concurrent_state {
        const char *api;
        mtx_t lock;
        rd_kafka_t *rk;
        struct test *test;
};

static int txn_concurrent_thread_main(void *arg) {
        struct _txn_concurrent_state *state = arg;
        static const char *apis[]           = {
            "init_transactions",           "begin_transaction",
            "send_offsets_to_transaction", "commit_transaction",
            "abort_transaction",           NULL};
        rd_kafka_t *rk       = state->rk;
        const char *main_api = NULL;
        int i;

        /* Update TLS variable so TEST_..() macros work */
        test_curr = state->test;

        while (1) {
                const char *api         = NULL;
                const int timeout_ms    = 10000;
                rd_kafka_error_t *error = NULL;
                rd_kafka_resp_err_t exp_err;
                test_timing_t duration;

                /* Wait for other thread's txn call to start, then sleep a bit
                 * to increase the chance of that call has really begun. */
                mtx_lock(&state->lock);

                if (state->api && state->api == main_api) {
                        /* Main thread is still blocking on the last API call */
                        TEST_SAY("Waiting for main thread to finish %s()\n",
                                 main_api);
                        mtx_unlock(&state->lock);
                        rd_sleep(1);
                        continue;
                } else if (!(main_api = state->api)) {
                        mtx_unlock(&state->lock);
                        break;
                }

                rd_sleep(1);

                for (i = 0; (api = apis[i]) != NULL; i++) {
                        TEST_SAY(
                            "Triggering concurrent %s() call while "
                            "main is in %s() call\n",
                            api, main_api);
                        TIMING_START(&duration, "%s", api);

                        if (!strcmp(api, "init_transactions"))
                                error =
                                    rd_kafka_init_transactions(rk, timeout_ms);
                        else if (!strcmp(api, "begin_transaction"))
                                error = rd_kafka_begin_transaction(rk);
                        else if (!strcmp(api, "send_offsets_to_transaction")) {
                                rd_kafka_topic_partition_list_t *offsets =
                                    rd_kafka_topic_partition_list_new(1);
                                rd_kafka_consumer_group_metadata_t *cgmetadata =
                                    rd_kafka_consumer_group_metadata_new(
                                        "mygroupid");
                                rd_kafka_topic_partition_list_add(
                                    offsets, "srctopic4", 0)
                                    ->offset = 12;

                                error = rd_kafka_send_offsets_to_transaction(
                                    rk, offsets, cgmetadata, -1);
                                rd_kafka_consumer_group_metadata_destroy(
                                    cgmetadata);
                                rd_kafka_topic_partition_list_destroy(offsets);
                        } else if (!strcmp(api, "commit_transaction"))
                                error =
                                    rd_kafka_commit_transaction(rk, timeout_ms);
                        else if (!strcmp(api, "abort_transaction"))
                                error =
                                    rd_kafka_abort_transaction(rk, timeout_ms);
                        else
                                TEST_FAIL("Unknown API: %s", api);

                        TIMING_STOP(&duration);

                        TEST_SAY_ERROR(error, "Conflicting %s() call: ", api);
                        TEST_ASSERT(error,
                                    "Expected conflicting %s() call to fail",
                                    api);

                        exp_err = !strcmp(api, main_api)
                                      ? RD_KAFKA_RESP_ERR__PREV_IN_PROGRESS
                                      : RD_KAFKA_RESP_ERR__CONFLICT;

                        TEST_ASSERT(rd_kafka_error_code(error) == exp_err,

                                    "Conflicting %s(): Expected %s, not %s",
                                    api, rd_kafka_err2str(exp_err),
                                    rd_kafka_error_name(error));
                        TEST_ASSERT(
                            rd_kafka_error_is_retriable(error),
                            "Conflicting %s(): Expected retriable error", api);
                        rd_kafka_error_destroy(error);
                        /* These calls should fail immediately */
                        TIMING_ASSERT(&duration, 0, 100);
                }

                mtx_unlock(&state->lock);
        }

        return 0;
}

static void do_test_txn_concurrent_operations(rd_bool_t do_commit) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int32_t coord_id = 1;
        rd_kafka_resp_err_t err;
        const char *topic            = "test";
        const char *transactional_id = "txnid";
        int remains                  = 0;
        thrd_t thrd;
        struct _txn_concurrent_state state = RD_ZERO_INIT;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;

        SUB_TEST("%s", do_commit ? "commit" : "abort");

        test_timeout_set(90);

        /* We need to override the value of socket.connection.setup.timeout.ms
         * to be at least 2*RTT of the mock broker. This is because the first
         * ApiVersion request will fail, since we make the request with v3, and
         * the mock broker's MaxVersion is 2, so the request is retried with v0.
         * We use the value 3*RTT to add some buffer.
         */
        rk = create_txn_producer(&mcluster, transactional_id, 1,
                                 "socket.connection.setup.timeout.ms", "15000",
                                 NULL);

        /* Set broker RTT to 3.5s so that the background thread has ample
         * time to call its conflicting APIs.
         * This value must be less than socket.connection.setup.timeout.ms/2. */
        rd_kafka_mock_broker_set_rtt(mcluster, coord_id, 3500);

        err = rd_kafka_mock_topic_create(mcluster, topic, 1, 1);
        TEST_ASSERT(!err, "Failed to create topic: %s", rd_kafka_err2str(err));

        /* Set up shared state between us and the concurrent thread */
        mtx_init(&state.lock, mtx_plain);
        state.test = test_curr;
        state.rk   = rk;

        /* We release the lock only while calling the TXN API */
        mtx_lock(&state.lock);

        /* Spin up concurrent thread */
        if (thrd_create(&thrd, txn_concurrent_thread_main, (void *)&state) !=
            thrd_success)
                TEST_FAIL("Failed to create thread");

#define _start_call(callname)                                                  \
        do {                                                                   \
                state.api = callname;                                          \
                mtx_unlock(&state.lock);                                       \
        } while (0)
#define _end_call() mtx_lock(&state.lock)

        _start_call("init_transactions");
        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));
        _end_call();

        /* This call doesn't block, so can't really be tested concurrently. */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        test_produce_msgs2_nowait(rk, topic, 0, RD_KAFKA_PARTITION_UA, 0, 10,
                                  NULL, 0, &remains);

        _start_call("send_offsets_to_transaction");
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 0)->offset = 12;
        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        TEST_CALL_ERROR__(
            rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata, -1));
        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);
        _end_call();

        if (do_commit) {
                _start_call("commit_transaction");
                TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, -1));
                _end_call();
        } else {
                _start_call("abort_transaction");
                TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, -1));
                _end_call();
        }

        /* Signal completion to background thread */
        state.api = NULL;

        mtx_unlock(&state.lock);

        thrd_join(thrd, NULL);

        rd_kafka_destroy(rk);

        mtx_destroy(&state.lock);

        SUB_TEST_PASS();
}


/**
 * @brief KIP-360: Test that fatal idempotence errors triggers abortable
 *        transaction errors, but let the broker-side abort of the
 *        transaction fail with a fencing error.
 *        Should raise a fatal error.
 *
 * @param error_code Which error code EndTxn should fail with.
 *                   Either RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH (older)
 *                   or RD_KAFKA_RESP_ERR_PRODUCER_FENCED (newer).
 */
static void do_test_txn_fenced_abort(rd_kafka_resp_err_t error_code) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_error_t *error;
        int32_t txn_coord = 2;
        const char *txnid = "myTxnId";
        char errstr[512];
        rd_kafka_resp_err_t fatal_err;
        size_t errors_cnt;

        SUB_TEST_QUICK("With error %s", rd_kafka_err2name(error_code));

        rk = create_txn_producer(&mcluster, txnid, 3, "batch.num.messages", "1",
                                 NULL);

        rd_kafka_mock_coordinator_set(mcluster, "transaction", txnid,
                                      txn_coord);

        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb   = error_is_fatal_cb;
        allowed_error            = RD_KAFKA_RESP_ERR__FENCED;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));

        /*
         * Start a transaction
         */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


        /* Produce a message without error first */
        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        test_flush(rk, -1);

        /* Fail abort transaction  */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, txn_coord, RD_KAFKAP_EndTxn, 1, error_code, 0);

        /* Fail the PID reinit */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, txn_coord, RD_KAFKAP_InitProducerId, 1, error_code, 0);

        /* Produce a message, let it fail with a fatal idempo error. */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID);

        TEST_CALL_ERR__(rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC("mytopic"), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));

        test_flush(rk, -1);

        /* Abort the transaction, should fail with a fatal error */
        error = rd_kafka_abort_transaction(rk, -1);
        TEST_ASSERT(error != NULL, "Expected abort_transaction() to fail");

        TEST_SAY_ERROR(error, "abort_transaction() failed: ");
        TEST_ASSERT(rd_kafka_error_is_fatal(error), "Expected a fatal error");
        rd_kafka_error_destroy(error);

        fatal_err = rd_kafka_fatal_error(rk, errstr, sizeof(errstr));
        TEST_ASSERT(fatal_err, "Expected a fatal error to have been raised");
        TEST_SAY("Fatal error: %s: %s\n", rd_kafka_err2name(fatal_err), errstr);

        /* Verify that the producer sent the expected number of EndTxn requests
         * by inspecting the mock broker error stack,
         * which should now be empty. */
        if (rd_kafka_mock_broker_error_stack_cnt(
                mcluster, txn_coord, RD_KAFKAP_EndTxn, &errors_cnt)) {
                TEST_FAIL(
                    "Broker error count should succeed for API %s"
                    " on broker %" PRId32,
                    rd_kafka_ApiKey2str(RD_KAFKAP_EndTxn), txn_coord);
        }
        /* Checks all the  RD_KAFKAP_EndTxn responses have been consumed */
        TEST_ASSERT(errors_cnt == 0,
                    "Expected error count 0 for API %s, found %zu",
                    rd_kafka_ApiKey2str(RD_KAFKAP_EndTxn), errors_cnt);

        if (rd_kafka_mock_broker_error_stack_cnt(
                mcluster, txn_coord, RD_KAFKAP_InitProducerId, &errors_cnt)) {
                TEST_FAIL(
                    "Broker error count should succeed for API %s"
                    " on broker %" PRId32,
                    rd_kafka_ApiKey2str(RD_KAFKAP_InitProducerId), txn_coord);
        }
        /* Checks none of the RD_KAFKAP_InitProducerId responses have been
         * consumed
         */
        TEST_ASSERT(errors_cnt == 1,
                    "Expected error count 1 for API %s, found %zu",
                    rd_kafka_ApiKey2str(RD_KAFKAP_InitProducerId), errors_cnt);

        /* All done */
        rd_kafka_destroy(rk);

        allowed_error = RD_KAFKA_RESP_ERR_NO_ERROR;

        SUB_TEST_PASS();
}


/**
 * @brief Test that the TxnOffsetCommit op doesn't retry without waiting
 * if the coordinator is found but not available, causing too frequent retries.
 */
static void
do_test_txn_offset_commit_doesnt_retry_too_quickly(rd_bool_t times_out) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_consumer_group_metadata_t *cgmetadata;
        rd_kafka_error_t *error;
        int timeout;

        SUB_TEST_QUICK("times_out=%s", RD_STR_ToF(times_out));

        rk = create_txn_producer(&mcluster, "txnid", 3, NULL);

        test_curr->ignore_dr_err = rd_true;

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, 5000));

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        /* Wait for messages to be delivered */
        test_flush(rk, 5000);

        /*
         * Fail TxnOffsetCommit with COORDINATOR_NOT_AVAILABLE
         * repeatedly.
         */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_TxnOffsetCommit, 4,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE);

        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, "srctopic4", 3)->offset = 1;

        cgmetadata = rd_kafka_consumer_group_metadata_new("mygroupid");

        /* The retry delay is 500ms, with 4 retries it should take at least
         * 2000ms for this call to succeed. */
        timeout = times_out ? 500 : 4000;
        error   = rd_kafka_send_offsets_to_transaction(rk, offsets, cgmetadata,
                                                     timeout);
        rd_kafka_consumer_group_metadata_destroy(cgmetadata);
        rd_kafka_topic_partition_list_destroy(offsets);

        if (times_out) {
                TEST_ASSERT(rd_kafka_error_code(error) ==
                                RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE,
                            "expected %s, got: %s",
                            rd_kafka_err2name(
                                RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE),
                            rd_kafka_err2str(rd_kafka_error_code(error)));
        } else {
                TEST_ASSERT(rd_kafka_error_code(error) ==
                                RD_KAFKA_RESP_ERR_NO_ERROR,
                            "expected \"Success\", found: %s",
                            rd_kafka_err2str(rd_kafka_error_code(error)));
        }
        rd_kafka_error_destroy(error);

        /* All done */
        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


int main_0105_transactions_mock(int argc, char **argv) {
        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_txn_recoverable_errors();

        do_test_txn_fatal_idempo_errors();

        do_test_txn_fenced_reinit(RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH);
        do_test_txn_fenced_reinit(RD_KAFKA_RESP_ERR_PRODUCER_FENCED);

        do_test_txn_req_cnt();

        do_test_txn_requires_abort_errors();

        do_test_txn_slow_reinit(rd_false);
        do_test_txn_slow_reinit(rd_true);

        /* Just do a subset of tests in quick mode */
        if (test_quick)
                return 0;

        do_test_txn_endtxn_errors();

        do_test_txn_endtxn_infinite();

        do_test_txn_endtxn_timeout();

        do_test_txn_endtxn_timeout_inflight();

        /* Bring down the coordinator */
        do_test_txn_broker_down_in_txn(rd_true);

        /* Bring down partition leader */
        do_test_txn_broker_down_in_txn(rd_false);

        do_test_txns_not_supported();

        do_test_txns_send_offsets_concurrent_is_retried();

        do_test_txns_send_offsets_non_eligible();

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

        do_test_txn_switch_coordinator_refresh();

        do_test_out_of_order_seq();

        do_test_topic_disappears_for_awhile();

        do_test_disconnected_group_coord(rd_false);

        do_test_disconnected_group_coord(rd_true);

        do_test_txn_coordinator_null_not_fatal();

        do_test_txn_resumable_calls_timeout(rd_true);

        do_test_txn_resumable_calls_timeout(rd_false);

        do_test_txn_resumable_calls_timeout_error(rd_true);

        do_test_txn_resumable_calls_timeout_error(rd_false);
        do_test_txn_resumable_init();

        do_test_txn_concurrent_operations(rd_true /*commit*/);

        do_test_txn_concurrent_operations(rd_false /*abort*/);

        do_test_txn_fenced_abort(RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH);

        do_test_txn_fenced_abort(RD_KAFKA_RESP_ERR_PRODUCER_FENCED);

        do_test_txn_offset_commit_doesnt_retry_too_quickly(rd_true);

        do_test_txn_offset_commit_doesnt_retry_too_quickly(rd_false);

        return 0;
}
