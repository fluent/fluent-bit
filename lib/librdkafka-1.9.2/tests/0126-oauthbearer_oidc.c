/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2021, Magnus Edenhill
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
/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */

static rd_bool_t error_seen;
/**
 * @brief After config OIDC, make sure the producer and consumer
 *        can work successfully.
 *
 */
static void
do_test_produce_consumer_with_OIDC(const rd_kafka_conf_t *base_conf) {
        const char *topic;
        uint64_t testid;
        rd_kafka_t *p1;
        rd_kafka_t *c1;
        rd_kafka_conf_t *conf;

        const char *url = test_getenv("VALID_OIDC_URL", NULL);

        SUB_TEST("Test producer and consumer with oidc configuration");

        if (!url) {
                SUB_TEST_SKIP(
                    "VALID_OIDC_URL environment variable is not set\n");
                return;
        }

        conf = rd_kafka_conf_dup(base_conf);
        test_conf_set(conf, "sasl.oauthbearer.token.endpoint.url", url);

        testid = test_id_generate();

        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        p1 = test_create_handle(RD_KAFKA_PRODUCER, rd_kafka_conf_dup(conf));

        topic = test_mk_topic_name("0126-oauthbearer_oidc", 1);
        test_create_topic(p1, topic, 1, 3);
        TEST_SAY("Topic: %s is created\n", topic);

        test_produce_msgs2(p1, topic, testid, 0, 0, 1, NULL, 0);

        test_conf_set(conf, "auto.offset.reset", "earliest");
        c1 = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        test_consumer_subscribe(c1, topic);

        /* Give it some time to trigger the token refresh. */
        rd_usleep(5 * 1000 * 1000, NULL);
        test_consumer_poll("OIDC.C1", c1, testid, 1, -1, 1, NULL);

        test_consumer_close(c1);

        rd_kafka_destroy(p1);
        rd_kafka_destroy(c1);
        SUB_TEST_PASS();
}


static void
auth_error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque) {
        if (err == RD_KAFKA_RESP_ERR__AUTHENTICATION ||
            err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN) {
                TEST_SAY("Expected error: %s: %s\n", rd_kafka_err2str(err),
                         reason);
                error_seen = rd_true;
        } else
                TEST_FAIL("Unexpected error: %s: %s", rd_kafka_err2str(err),
                          reason);
        rd_kafka_yield(rk);
}


/**
 * @brief After config OIDC, if the token is expired, make sure
 *        the authentication fail as expected.
 *
 */
static void do_test_produce_consumer_with_OIDC_expired_token_should_fail(
    const rd_kafka_conf_t *base_conf) {
        rd_kafka_t *c1;
        uint64_t testid;
        rd_kafka_conf_t *conf;

        const char *expired_url = test_getenv("EXPIRED_TOKEN_OIDC_URL", NULL);

        SUB_TEST("Test OAUTHBEARER/OIDC failing with expired JWT");

        if (!expired_url) {
                SUB_TEST_SKIP(
                    "EXPIRED_TOKEN_OIDC_URL environment variable is not set\n");
                return;
        }

        conf = rd_kafka_conf_dup(base_conf);

        error_seen = rd_false;
        test_conf_set(conf, "sasl.oauthbearer.token.endpoint.url", expired_url);

        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        testid = test_id_generate();

        c1 = test_create_consumer("OIDC.fail.C1", NULL, conf, NULL);

        test_consumer_poll_no_msgs("OIDC.fail.C1", c1, testid, 10 * 1000);
        TEST_ASSERT(error_seen);

        test_consumer_close(c1);
        rd_kafka_destroy(c1);
        SUB_TEST_PASS();
}


/**
 * @brief After config OIDC, if the token is not valid, make sure the
 *        authentication fail as expected.
 *
 */
static void do_test_produce_consumer_with_OIDC_should_fail(
    const rd_kafka_conf_t *base_conf) {
        rd_kafka_t *c1;
        uint64_t testid;
        rd_kafka_conf_t *conf;

        const char *invalid_url = test_getenv("INVALID_OIDC_URL", NULL);

        SUB_TEST("Test OAUTHBEARER/OIDC failing with invalid JWT");

        if (!invalid_url) {
                SUB_TEST_SKIP(
                    "INVALID_OIDC_URL environment variable is not set\n");
                return;
        }

        conf = rd_kafka_conf_dup(base_conf);

        error_seen = rd_false;

        test_conf_set(conf, "sasl.oauthbearer.token.endpoint.url", invalid_url);

        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        testid = test_id_generate();

        c1 = test_create_consumer("OIDC.fail.C1", NULL, conf, NULL);

        test_consumer_poll_no_msgs("OIDC.fail.C1", c1, testid, 10 * 1000);

        TEST_ASSERT(error_seen);

        test_consumer_close(c1);
        rd_kafka_destroy(c1);
        SUB_TEST_PASS();
}


int main_0126_oauthbearer_oidc(int argc, char **argv) {
        rd_kafka_conf_t *conf;
        const char *sec;
        const char *oidc;

        test_conf_init(&conf, NULL, 60);

        sec = test_conf_get(conf, "security.protocol");
        if (!strstr(sec, "sasl")) {
                TEST_SKIP("Apache Kafka cluster not configured for SASL\n");
                return 0;
        }

        oidc = test_conf_get(conf, "sasl.oauthbearer.method");
        if (rd_strcasecmp(oidc, "OIDC")) {
                TEST_SKIP("`sasl.oauthbearer.method=OIDC` is required\n");
                return 0;
        }

        do_test_produce_consumer_with_OIDC(conf);
        do_test_produce_consumer_with_OIDC_should_fail(conf);
        do_test_produce_consumer_with_OIDC_expired_token_should_fail(conf);

        rd_kafka_conf_destroy(conf);

        return 0;
}
