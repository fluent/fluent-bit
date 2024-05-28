/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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


/**
 * @name Idempotent producer tests using the mock cluster
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
 * @brief Create an idempotent producer and a mock cluster.
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
create_idempo_producer(rd_kafka_mock_cluster_t **mclusterp,
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

        test_conf_set(conf, "enable.idempotence", "true");
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
 * @brief A possibly persisted error should treat the message as not persisted,
 *        avoid increasing next expected sequence an causing a possible fatal
 *        error.
 *        n = 1 triggered the "sequence desynchronization" fatal
 *        error, n > 1 triggered the "rewound sequence number" fatal error.
 *        See #3584.
 *
 * @param n Number of messages (1 to 5) to send before disconnection. These
 *        will fail with a possibly persisted error,
 *        rest will be sent before reconnecting.
 *
 */
static void
do_test_idempo_possibly_persisted_not_causing_fatal_error(size_t n) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        size_t i;
        int remains = 0;

        SUB_TEST_QUICK();

        rk = create_idempo_producer(&mcluster, 1, "batch.num.messages", "1",
                                    "linger.ms", "0", NULL);
        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb   = error_is_fatal_cb;
        /* Only allow an error from the disconnection below. */
        allowed_error = RD_KAFKA_RESP_ERR__TRANSPORT;

        /* Produce 5 messages without error first, msgids 1->5. */
        test_produce_msgs2(rk, "mytopic", 0, 0, 0, 5, NULL, 64);
        rd_kafka_flush(rk, -1);

        /* First sequence is for the immediately produced reply,
         * response is never delivered because of the disconnection. */
        for (i = 0; i < n; i++) {
                rd_kafka_mock_broker_push_request_error_rtts(
                    mcluster, 1, RD_KAFKAP_Produce, 1,
                    RD_KAFKA_RESP_ERR_NO_ERROR, 750);
        }

        /* After disconnection: first message fails with NOT_ENOUGH_REPLICAS,
         * rest with OUT_OF_ORDER_SEQUENCE_NUMBER. */
        for (i = 0; i < 5; i++) {
                if (i == 0) {
                        rd_kafka_mock_broker_push_request_error_rtts(
                            mcluster, 1, RD_KAFKAP_Produce, 1,
                            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS, 750);
                } else {
                        rd_kafka_mock_broker_push_request_error_rtts(
                            mcluster, 1, RD_KAFKAP_Produce, 1,
                            RD_KAFKA_RESP_ERR_OUT_OF_ORDER_SEQUENCE_NUMBER, 1);
                }
        }

        /* Produce n messages that will be retried, msgids 6->(6+n-1). */
        test_produce_msgs2_nowait(rk, "mytopic", 0, 0, 0, n, NULL, 64,
                                  &remains);

        /* Wait that messages are sent, then set it down and up again.
         * "possibly persisted" errors won't increase next_ack,
         * but it will be increased when receiving a NO_ERROR
         * during the second retry after broker is set up again. */
        rd_usleep(250000, 0);
        rd_kafka_mock_broker_set_down(mcluster, 1);
        rd_usleep(250000, 0);

        /* Produce rest of (5 - n) messages that will enqueued
         * after retried ones, msgids (6+n)->10. */
        if (n < 5)
                test_produce_msgs2_nowait(rk, "mytopic", 0, 0, 0, 5 - n, NULL,
                                          64, &remains);

        rd_kafka_mock_broker_set_up(mcluster, 1);

        /* All done, producer recovers without fatal errors. */
        rd_kafka_flush(rk, -1);
        rd_kafka_destroy(rk);

        allowed_error = RD_KAFKA_RESP_ERR_NO_ERROR;

        SUB_TEST_PASS();
}

/**
 * @brief After a possibly persisted error that caused a retry, messages
 *        can fail with DUPLICATE_SEQUENCE_NUMBER or succeed and in both
 *        cases they'll be considered as persisted.
 */
static void
do_test_idempo_duplicate_sequence_number_after_possibly_persisted(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        int remains = 0;

        SUB_TEST_QUICK();

        rk = create_idempo_producer(&mcluster, 1, "batch.num.messages", "1",
                                    "linger.ms", "0", NULL);
        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb   = error_is_fatal_cb;
        /* Only allow an error from the disconnection below. */
        allowed_error = RD_KAFKA_RESP_ERR__TRANSPORT;

        /* Produce 5 messages without error first, msgids 1-5. */
        test_produce_msgs2(rk, "mytopic", 0, 0, 0, 5, NULL, 64);


        /* Make sure first response comes after disconnection. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_Produce, 5,
            RD_KAFKA_RESP_ERR_DUPLICATE_SEQUENCE_NUMBER, 500,
            RD_KAFKA_RESP_ERR_NO_ERROR, 0, RD_KAFKA_RESP_ERR_NO_ERROR, 0,
            RD_KAFKA_RESP_ERR_NO_ERROR, 0, RD_KAFKA_RESP_ERR_NO_ERROR, 0);

        test_produce_msgs2_nowait(rk, "mytopic", 0, 0, 0, 5, NULL, 64,
                                  &remains);

        /* Let the message fail because of _TRANSPORT (possibly persisted). */
        rd_kafka_mock_broker_set_down(mcluster, 1);

        rd_usleep(250000, 0);

        /* When retrying the first DUPLICATE_SEQUENCE_NUMBER is treated
         * as NO_ERROR. */
        rd_kafka_mock_broker_set_up(mcluster, 1);

        /* All done. */
        rd_kafka_flush(rk, -1);
        rd_kafka_destroy(rk);

        allowed_error = RD_KAFKA_RESP_ERR_NO_ERROR;

        SUB_TEST_PASS();
}

/**
 * @brief When a message fails on the broker with a possibly persisted error
 *        NOT_ENOUGH_REPLICAS_AFTER_APPEND, in case next messages
 *        succeed, it should be implicitly acked.
 */
static void do_test_idempo_success_after_possibly_persisted(void) {
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;

        SUB_TEST_QUICK();

        rk = create_idempo_producer(&mcluster, 1, "batch.num.messages", "1",
                                    "linger.ms", "0", NULL);
        test_curr->ignore_dr_err = rd_true;
        test_curr->is_fatal_cb   = error_is_fatal_cb;

        /* Make sure first response fails with possibly persisted
         * error NOT_ENOUGH_REPLICAS_AFTER_APPEND next messages
         * will succeed. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS_AFTER_APPEND, 0);

        /* Produce 5 messages, msgids 1-5. */
        test_produce_msgs2(rk, "mytopic", 0, 0, 0, 5, NULL, 64);

        /* All done. */
        rd_kafka_flush(rk, -1);
        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}

int main_0144_idempotence_mock(int argc, char **argv) {
        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        int i;
        for (i = 1; i <= 5; i++)
                do_test_idempo_possibly_persisted_not_causing_fatal_error(i);

        do_test_idempo_duplicate_sequence_number_after_possibly_persisted();

        do_test_idempo_success_after_possibly_persisted();

        return 0;
}
