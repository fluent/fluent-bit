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
 * Verify that consumtion continues after broker connectivity failure.
 */

static int simulate_network_down = 0;

/**
 * @brief Sockem connect, called from **internal librdkafka thread** through
 *        librdkafka's connect_cb
 */
static int connect_cb (struct test *test, sockem_t *skm, const char *id) {
        int r;

        TEST_LOCK();
        r = simulate_network_down;
        TEST_UNLOCK();

        if (r) {
                sockem_close(skm);
                return ECONNREFUSED;
        } else {
                /* Let it go real slow so we dont consume all
                 * the messages right away. */
                sockem_set(skm, "rx.thruput", 100000, NULL);
        }
        return 0;
}

static int is_fatal_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                        const char *reason) {
        /* Ignore connectivity errors since we'll be bringing down
         * .. connectivity.
         * SASL auther will think a connection-down even in the auth
         * state means the broker doesn't support SASL PLAIN. */
        if (err == RD_KAFKA_RESP_ERR__TRANSPORT ||
            err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN ||
            err == RD_KAFKA_RESP_ERR__AUTHENTICATION)
                return 0;
        return 1;
}


int main_0049_consume_conn_close (int argc, char **argv) {
        rd_kafka_t *rk;
        const char *topic = test_mk_topic_name("0049_consume_conn_close", 1);
        uint64_t testid;
        int msgcnt = test_on_ci ? 1000 : 10000;
        test_msgver_t mv;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *tconf;
        rd_kafka_topic_partition_list_t *assignment;
        rd_kafka_resp_err_t err;

        if (!test_conf_match(NULL, "sasl.mechanisms", "GSSAPI")) {
                TEST_SKIP("KNOWN ISSUE: ApiVersionRequest+SaslHandshake "
                          "will not play well with sudden disconnects\n");
                return 0;
        }

        test_conf_init(&conf, &tconf, 60);
        /* Want an even number so it is divisable by two without surprises */
        msgcnt = (msgcnt / (int)test_timeout_multiplier) & ~1;

        testid = test_id_generate();
        test_produce_msgs_easy(topic, testid, RD_KAFKA_PARTITION_UA, msgcnt);


        test_socket_enable(conf);
        test_curr->connect_cb = connect_cb;
        test_curr->is_fatal_cb = is_fatal_cb;

        test_topic_conf_set(tconf, "auto.offset.reset", "smallest");

        rk = test_create_consumer(topic, NULL, conf, tconf);

        test_consumer_subscribe(rk, topic);

        test_msgver_init(&mv, testid);

        test_consumer_poll("consume.up", rk, testid, -1, 0, msgcnt/2, &mv);

        err = rd_kafka_assignment(rk, &assignment);
        TEST_ASSERT(!err, "assignment() failed: %s", rd_kafka_err2str(err));
        TEST_ASSERT(assignment->cnt > 0, "empty assignment");

        TEST_SAY("Bringing down the network\n");

        TEST_LOCK();
        simulate_network_down = 1;
        TEST_UNLOCK();
        test_socket_close_all(test_curr, 1/*reinit*/);

        TEST_SAY("Waiting for session timeout to expire (6s), and then some\n");

        /* Commit an offset, which should fail, to trigger the offset commit
         * callback fallback (CONSUMER_ERR) */
        assignment->elems[0].offset = 123456789;
        TEST_SAY("Committing offsets while down, should fail eventually\n");
        err = rd_kafka_commit(rk, assignment, 1/*async*/);
        TEST_ASSERT(!err, "async commit failed: %s", rd_kafka_err2str(err));
        rd_kafka_topic_partition_list_destroy(assignment);

        rd_sleep(10);

        TEST_SAY("Bringing network back up\n");
        TEST_LOCK();
        simulate_network_down = 0;
        TEST_UNLOCK();

        TEST_SAY("Continuing to consume..\n");
        test_consumer_poll("consume.up2", rk, testid, -1, msgcnt/2, msgcnt/2,
                           &mv);

        test_msgver_verify("consume", &mv, TEST_MSGVER_ORDER|TEST_MSGVER_DUP,
                           0, msgcnt);

        test_msgver_clear(&mv);

        test_consumer_close(rk);
        rd_kafka_destroy(rk);

        return 0;
}


#endif
