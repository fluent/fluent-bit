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

#if WITH_SOCKEM
#include "rdkafka.h"

#include <stdarg.h>

/**
 * @name Verify #1985:
 *
 * Previously known topic transitions to UNKNOWN when metadata times out,
 * new messages are put on UA, when brokers come up again and metadata
 * is retrieved the UA messages must be produced.
 */

static rd_atomic32_t refuse_connect;


/**
 * @brief Sockem connect, called from **internal librdkafka thread** through
 *        librdkafka's connect_cb
 */
static int connect_cb (struct test *test, sockem_t *skm, const char *id) {
        if (rd_atomic32_get(&refuse_connect) > 0)
                return -1;
        else
                return 0;
}

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

static int msg_dr_cnt = 0;
static int msg_dr_fail_cnt = 0;

static void dr_msg_cb (rd_kafka_t *rk, const rd_kafka_message_t *rkmessage,
                       void *opaque) {
        msg_dr_cnt++;
        TEST_SAYL(3, "Delivery for message %.*s: %s\n",
                  (int)rkmessage->len, (const char *)rkmessage->payload,
                  rd_kafka_err2name(rkmessage->err));

        if (rkmessage->err) {
                TEST_FAIL_LATER("Expected message to succeed, got %s",
                                rd_kafka_err2str(rkmessage->err));
                msg_dr_fail_cnt++;
        }
}



int main_0088_produce_metadata_timeout (int argc, char **argv) {
        int64_t testid;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        const char *topic = test_mk_topic_name("0088_produce_metadata_timeout",
                                               1);
        int msgcnt = 0;
        rd_kafka_conf_t *conf;

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 15*60*2);
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);
        test_conf_set(conf, "metadata.max.age.ms", "10000");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "-1");
        test_conf_set(conf, "linger.ms", "5000");
        test_conf_set(conf, "batch.num.messages", "5");

        test_socket_enable(conf);
        test_curr->connect_cb = connect_cb;
        test_curr->is_fatal_cb = is_fatal_cb;

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* Create topic with single partition, for simplicity. */
        test_create_topic(rk, topic, 1, 1);

        rkt = rd_kafka_topic_new(rk, topic, NULL);

        /* Produce first set of messages and wait for delivery */
        test_produce_msgs_nowait(rk, rkt, testid, RD_KAFKA_PARTITION_UA,
                                 msgcnt, 20, NULL, 0, 0, &msgcnt);
        while (msg_dr_cnt < 5)
                rd_kafka_poll(rk, 1000);

        TEST_SAY(_C_YEL "Disconnecting sockets and "
                 "refusing future connections\n");
        rd_atomic32_set(&refuse_connect, 1);
        test_socket_close_all(test_curr, 1/*reinit*/);


        /* Wait for metadata timeout */
        TEST_SAY("Waiting for metadata timeout\n");
        rd_sleep(10+5);

        /* These messages will be put on the UA queue */
        test_produce_msgs_nowait(rk, rkt, testid, RD_KAFKA_PARTITION_UA,
                                 msgcnt, 20, NULL, 0, 0, &msgcnt);

        /* Restore the connection(s) when metadata has timed out. */
        TEST_SAY(_C_YEL "Allowing connections\n");
        rd_atomic32_set(&refuse_connect, 0);

        rd_sleep(3);
        test_produce_msgs_nowait(rk, rkt, testid, RD_KAFKA_PARTITION_UA,
                                 msgcnt, 20, NULL, 0, 0, &msgcnt);

        test_flush(rk, 2*5*1000); /* linger.ms * 2 */

        TEST_ASSERT(msg_dr_cnt == msgcnt,
                    "expected %d, got %d", msgcnt, msg_dr_cnt);
        TEST_ASSERT(msg_dr_fail_cnt == 0,
                    "expected %d dr failures, got %d", 0, msg_dr_fail_cnt);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        return 0;
}
#endif
