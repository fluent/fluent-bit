/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
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

#include <stdarg.h>
#include <errno.h>

static int is_fatal_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                        const char *reason) {
        /* Ignore connectivity errors since we'll be bringing down
         * .. connectivity.
         * SASL auther will think a connection-down even in the auth
         * state means the broker doesn't support SASL PLAIN. */
        TEST_SAY("is_fatal?: %s: %s\n", rd_kafka_err2str(err), reason);
        if (err == RD_KAFKA_RESP_ERR__TRANSPORT ||
            err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN ||
            err == RD_KAFKA_RESP_ERR__AUTHENTICATION ||
            err == RD_KAFKA_RESP_ERR__TIMED_OUT)
                return 0;
        return 1;
}


#if WITH_SOCKEM
/**
 * Producer message retry testing
 */

/* Hang on to the first broker socket we see in connect_cb,
 * reject all the rest (connection refused) to make sure we're only
 * playing with one single broker for this test. */

#include "sockem_ctrl.h"


/**
 * @brief Test produce retries.
 *
 * @param should_fail If true, do negative testing which should fail.
 */
static void do_test_produce_retries (const char *topic,
                                     int idempotence,
                                     int try_fail,
                                     int should_fail) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        uint64_t testid;
        rd_kafka_resp_err_t err;
        int msgcnt = 1;
        sockem_ctrl_t ctrl;

        TEST_SAY(_C_BLU "Test produce retries "
                 "(idempotence=%d,try_fail=%d,should_fail=%d)\n",
                 idempotence, try_fail, should_fail);

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 60);

        if (should_fail &&
            !strcmp(test_conf_get(conf, "enable.sparse.connections"),
                    "true")) {
                rd_kafka_conf_destroy(conf);
                TEST_SAY(_C_YEL "Sparse connections enabled: "
                         "skipping connection-timing related test\n");
                return;
        }

        sockem_ctrl_init(&ctrl);

        test_conf_set(conf, "socket.timeout.ms", "1000");
        /* Avoid disconnects on request timeouts */
        test_conf_set(conf, "socket.max.fails", "100");
        test_conf_set(conf, "enable.idempotence", idempotence?"true":"false");
        test_curr->exp_dr_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        test_curr->exp_dr_status = RD_KAFKA_MSG_STATUS_PERSISTED;
        if (!try_fail) {
                test_conf_set(conf, "retries", "5");
        } else {
                /* enable.idempotence=true request retries >= 1 which
                 * makes the test pass. Adjust expected error accordingly. */
                if (idempotence)
                        test_conf_set(conf, "retries", "5");
                else
                        test_conf_set(conf, "retries", "0");
                if (should_fail) {
                        test_curr->exp_dr_err = RD_KAFKA_RESP_ERR__MSG_TIMED_OUT;
                        test_curr->exp_dr_status = RD_KAFKA_MSG_STATUS_POSSIBLY_PERSISTED;
                }
        }
        test_conf_set(conf, "retry.backoff.ms", "5000");
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        test_socket_enable(conf);
        test_curr->is_fatal_cb = is_fatal_cb;

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_producer_topic(rk, topic, NULL);

        /* Create the topic to make sure connections are up and ready. */
        err = test_auto_create_topic_rkt(rk, rkt, tmout_multip(5000));
        TEST_ASSERT(!err, "topic creation failed: %s", rd_kafka_err2str(err));

        /* Set initial delay to 3s */
        sockem_ctrl_set_delay(&ctrl, 0, 3000); /* Takes effect immediately */

        /* After two retries, remove the delay, the third retry
         * should kick in and work. */
        sockem_ctrl_set_delay(&ctrl,
                              ((1000 /*socket.timeout.ms*/ +
                                5000 /*retry.backoff.ms*/) * 2) - 2000, 0);

        test_produce_msgs(rk, rkt, testid, RD_KAFKA_PARTITION_UA,
                          0, msgcnt, NULL, 0);


        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        if (!should_fail) {
                TEST_SAY("Verifying messages with consumer\n");
                test_consume_msgs_easy(NULL, topic, testid, -1, msgcnt, NULL);
        }

        sockem_ctrl_term(&ctrl);

        TEST_SAY(_C_GRN "Test produce retries "
                 "(idempotence=%d,try_fail=%d,should_fail=%d): PASS\n",
                 idempotence, try_fail, should_fail);
}
#endif




/**
 * @brief Simple on_request_sent interceptor that simply disconnects
 *        the socket when first ProduceRequest is seen.
 *        Sub-sequent ProduceRequests will not trigger a disconnect, to allow
 *        for retries.
 */
static mtx_t produce_disconnect_lock;
static int produce_disconnects = 0;
static rd_kafka_resp_err_t on_request_sent (rd_kafka_t *rk,
                                            int sockfd,
                                            const char *brokername,
                                            int32_t brokerid,
                                            int16_t ApiKey,
                                            int16_t ApiVersion,
                                            int32_t CorrId,
                                            size_t  size,
                                            void *ic_opaque) {

        /* Ignore if not a ProduceRequest */
        if (ApiKey != 0)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        mtx_lock(&produce_disconnect_lock);
        if (produce_disconnects == 0) {
                char buf[512];
                ssize_t r;
                printf(_C_CYA "%s:%d: shutting down socket %d (%s)\n" _C_CLR,
                       __FILE__, __LINE__, sockfd, brokername);
#ifdef _WIN32
                closesocket(sockfd);
#else
                close(sockfd);
#endif
                /* There is a chance the broker responded in the
                 * time it took us to get here, so purge the
                 * socket recv buffer to make sure librdkafka does not see
                 * the response. */
                while ((r = recv(sockfd, buf, sizeof(buf), 0)) > 0)
                        printf(_C_CYA "%s:%d: "
                               "purged %"PRIdsz" bytes from socket\n",
                               __FILE__, __LINE__, r);
                produce_disconnects = 1;
        }
        mtx_unlock(&produce_disconnect_lock);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static rd_kafka_resp_err_t on_new_producer (rd_kafka_t *rk,
                                            const rd_kafka_conf_t *conf,
                                            void *ic_opaque,
                                            char *errstr, size_t errstr_size) {
        return rd_kafka_interceptor_add_on_request_sent(
                rk, "disconnect_on_send",
                on_request_sent, NULL);
}

/**
 * @brief Test produce retries by disconnecting right after ProduceRequest
 *        has been sent.
 *
 * @param should_fail If true, do negative testing which should fail.
 */
static void do_test_produce_retries_disconnect (const char *topic,
                                                int idempotence,
                                                int try_fail,
                                                int should_fail) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        uint64_t testid;
        rd_kafka_resp_err_t err;
        int msgcnt = 1;
        int partition_cnt;

        TEST_SAY(_C_BLU "Test produce retries by disconnect "
                 "(idempotence=%d,try_fail=%d,should_fail=%d)\n",
                 idempotence, try_fail, should_fail);

        test_curr->is_fatal_cb = is_fatal_cb;

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 60);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        test_conf_set(conf, "socket.timeout.ms", test_quick ? "3000":"10000");
        test_conf_set(conf, "message.timeout.ms", test_quick ? "9000":"30000");
        test_conf_set(conf, "enable.idempotence", idempotence?"true":"false");
        if (!try_fail) {
                test_conf_set(conf, "retries", "1");
        } else {
                /* enable.idempotence=true request retries >= 1 which
                 * makes the test pass. */
                if (!idempotence)
                        test_conf_set(conf, "retries", "0");
        }

        mtx_init(&produce_disconnect_lock, mtx_plain);
        produce_disconnects = 0;

        rd_kafka_conf_interceptor_add_on_new(conf, "on_new_producer",
                                             on_new_producer, NULL);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_producer_topic(rk, topic, NULL);

        err = test_produce_sync(rk, rkt, testid, 0);

        if (should_fail) {
                if (!err)
                        TEST_FAIL("Expected produce to fail\n");
                else
                        TEST_SAY("Produced message failed as expected: %s\n",
                                 rd_kafka_err2str(err));
        } else {
                if (err)
                        TEST_FAIL("Produced message failed: %s\n",
                                  rd_kafka_err2str(err));
                else
                        TEST_SAY("Produced message delivered\n");
        }

        mtx_lock(&produce_disconnect_lock);
        TEST_ASSERT(produce_disconnects == 1,
                    "expected %d disconnects, not %d", 1, produce_disconnects);
        mtx_unlock(&produce_disconnect_lock);


        partition_cnt = test_get_partition_count(rk, topic, tmout_multip(5000));

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        TEST_SAY("Verifying messages with consumer\n");
        test_consume_msgs_easy(NULL, topic, testid, partition_cnt,
                               /* Since we don't know the number of
                                * messages that got thru on the socket
                                * before disconnect we can't let the
                                * expected message count be 0 in case of
                                * should_fail, so instead ignore the message
                                * count (-1). */
                               should_fail ? -1 : msgcnt, NULL);

        TEST_SAY(_C_GRN "Test produce retries by disconnect "
                 "(idempotence=%d,try_fail=%d,should_fail=%d): PASS\n",
                 idempotence, try_fail, should_fail);
}


int main_0076_produce_retry (int argc, char **argv) {
        const char *topic = test_mk_topic_name("0076_produce_retry", 1);
        const rd_bool_t has_idempotence =
                test_broker_version >= TEST_BRKVER(0,11,0,0);

#if WITH_SOCKEM
        if (has_idempotence) {
                /* Idempotence, no try fail, should succeed. */
                do_test_produce_retries(topic, 1, 0, 0);
                /* Idempotence, try fail, should succeed. */
                do_test_produce_retries(topic, 1, 1, 0);
        }
        /* No idempotence, try fail, should fail. */
        do_test_produce_retries(topic, 0, 1, 1);
#endif

        if (has_idempotence) {
                /* Idempotence, no try fail, should succeed. */
                do_test_produce_retries_disconnect(topic, 1, 0, 0);
                /* Idempotence, try fail, should succeed. */
                do_test_produce_retries_disconnect(topic, 1, 1, 0);
        }
        /* No idempotence, try fail, should fail. */
        do_test_produce_retries_disconnect(topic, 0, 1, 1);

        return 0;
}


