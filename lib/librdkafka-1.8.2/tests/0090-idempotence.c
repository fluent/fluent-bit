/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2018, Magnus Edenhill
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

/**
 * @name Idempotent Producer tests
 *
 */

static struct {
        int batch_cnt;
        int initial_fail_batch_cnt;
        rd_atomic32_t produce_cnt;
} state;



/**
 * @brief This is called prior to parsing the ProduceResponse,
 *        we use it to inject errors.
 *
 * @locality an internal rdkafka thread
 */
static rd_kafka_resp_err_t handle_ProduceResponse (rd_kafka_t *rk,
                                                   int32_t brokerid,
                                                   uint64_t msgseq,
                                                   rd_kafka_resp_err_t err) {
        rd_kafka_resp_err_t new_err = err;
        int n;

        if (err == RD_KAFKA_RESP_ERR__RETRY)
                return err; /* Skip internal retries, such as triggered by
                             * rd_kafka_broker_bufq_purge_by_toppar() */

        n = rd_atomic32_add(&state.produce_cnt, 1);

        /* Let the first N ProduceRequests fail with request timeout.
         * Do allow the first request through. */
        if (n > 1 && n <= state.initial_fail_batch_cnt) {
                if (err)
                        TEST_WARN("First %d ProduceRequests should not "
                                  "have failed, this is #%d with error %s for "
                                  "brokerid %"PRId32" and msgseq %"PRIu64"\n",
                                  state.initial_fail_batch_cnt, n,
                                  rd_kafka_err2name(err), brokerid, msgseq);
                assert(!err &&
                       *"First N ProduceRequests should not have failed");
                new_err = RD_KAFKA_RESP_ERR__TIMED_OUT;
        }

        TEST_SAY("handle_ProduceResponse(broker %"PRId32
                 ", MsgSeq %"PRId64", Error %s) -> new Error %s\n",
                 brokerid, msgseq,
                 rd_kafka_err2name(err),
                 rd_kafka_err2name(new_err));

        return new_err;
}


/**
 * @brief Test handling of implicit acks.
 *
 * @param batch_cnt Total number of batches, ProduceRequests, sent.
 * @param initial_fail_batch_cnt How many of the initial batches should
 *                               fail with an emulated network timeout.
 */
static void do_test_implicit_ack (const char *what,
                                  int batch_cnt, int initial_fail_batch_cnt) {
        rd_kafka_t *rk;
        const char *topic = test_mk_topic_name("0090_idempotence_impl_ack", 1);
        const int32_t partition = 0;
        uint64_t testid;
        int msgcnt = 10*batch_cnt;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        test_msgver_t mv;

        TEST_SAY(_C_MAG "[ Test implicit ack: %s ]\n", what);

        rd_atomic32_init(&state.produce_cnt, 0);
        state.batch_cnt = batch_cnt;
        state.initial_fail_batch_cnt = initial_fail_batch_cnt;

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 60);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        test_conf_set(conf, "enable.idempotence", "true");
        test_conf_set(conf, "batch.num.messages", "10");
        test_conf_set(conf, "linger.ms", "500");
        test_conf_set(conf, "retry.backoff.ms", "10");

        /* The ProduceResponse handler will inject timed-out-in-flight
         * errors for the first N ProduceRequests, which will trigger retries
         * that in turn will result in OutOfSequence errors. */
        test_conf_set(conf, "ut_handle_ProduceResponse",
                      (char *)handle_ProduceResponse);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        test_create_topic(rk, topic, 1, 1);

        rkt = test_create_producer_topic(rk, topic, NULL);


        TEST_SAY("Producing %d messages\n", msgcnt);
        test_produce_msgs(rk, rkt, testid, -1, 0, msgcnt, NULL, 0);

        TEST_SAY("Flushing..\n");
        rd_kafka_flush(rk, 10000);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        TEST_SAY("Verifying messages with consumer\n");
        test_msgver_init(&mv, testid);
        test_consume_msgs_easy_mv(NULL, topic, partition,
                                  testid, 1, msgcnt, NULL, &mv);
        test_msgver_verify("verify", &mv, TEST_MSGVER_ALL, 0, msgcnt);
        test_msgver_clear(&mv);

        TEST_SAY(_C_GRN "[ Test implicit ack: %s : PASS ]\n", what);
}


int main_0090_idempotence (int argc, char **argv) {
        /* The broker maintains a window of the N last ProduceRequests
         * per partition and producer to allow ProduceRequest retries
         * for previously successful requests to return a non-error response.
         * This limit is currently (AK 2.0) hard coded at 5. */
        const int broker_req_window = 5;

        do_test_implicit_ack("within broker request window",
                             broker_req_window * 2,
                             broker_req_window);

        do_test_implicit_ack("outside broker request window",
                             broker_req_window + 3,
                             broker_req_window + 3);

        return 0;
}
