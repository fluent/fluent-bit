/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2021-2022, Magnus Edenhill
 *               2025, Confluent Inc.
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

#define TEST_FIXTURES_FOLDER             "./fixtures"
#define TEST_FIXTURES_OAUTHBEARER_FOLDER TEST_FIXTURES_FOLDER "/oauthbearer/"
#define TEST_FIXTURES_JWT_ASSERTION_TEMPLATE                                   \
        TEST_FIXTURES_OAUTHBEARER_FOLDER "jwt_assertion_template.json"

static rd_bool_t error_seen;
/**
 * @brief After config OIDC, make sure the producer and consumer
 *        can work successfully.
 *
 */
static void
do_test_produce_consumer_with_OIDC(const char *test_name,
                                   const rd_kafka_conf_t *base_conf) {
        const char *topic;
        uint64_t testid;
        rd_kafka_t *p1;
        rd_kafka_t *c1;
        rd_kafka_conf_t *conf;

        const char *url = test_getenv("VALID_OIDC_URL", NULL);

        SUB_TEST("Test producer and consumer with oidc configuration: %s",
                 test_name);

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
        test_create_topic_wait_exists(p1, topic, 1, 3, 5000);
        TEST_SAY("Topic: %s is created\n", topic);

        test_produce_msgs2(p1, topic, testid, 0, 0, 1, NULL, 0);

        test_conf_set(conf, "auto.offset.reset", "earliest");
        c1 = test_create_consumer(topic, NULL, conf, NULL);
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
 * @brief After configiguring OIDC, make sure the
 *        authentication fails as expected.
 */
static void do_test_produce_consumer_with_OIDC_should_fail(
    const char *test_name,
    const rd_kafka_conf_t *base_conf) {
        rd_kafka_t *c1;
        uint64_t testid;
        rd_kafka_conf_t *conf;

        const char *url = test_getenv("VALID_OIDC_URL", NULL);

        SUB_TEST("Test authentication failure with oidc configuration: %s",
                 test_name);
        if (!url) {
                SUB_TEST_SKIP(
                    "VALID_OIDC_URL environment variable is not set\n");
                return;
        }

        conf = rd_kafka_conf_dup(base_conf);

        error_seen = rd_false;

        conf = rd_kafka_conf_dup(base_conf);
        test_conf_set(conf, "sasl.oauthbearer.token.endpoint.url", url);

        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        testid = test_id_generate();

        c1 = test_create_consumer("OIDC.fail.C1", NULL, conf, NULL);

        test_consumer_poll_no_msgs("OIDC.fail.C1", c1, testid, 5 * 1000);

        TEST_ASSERT(error_seen);

        test_consumer_close(c1);
        rd_kafka_destroy(c1);
        SUB_TEST_PASS();
}

/**
 * @brief After config OIDC, if the token endpoint is not valid, make sure the
 *        authentication fail as expected.
 *
 */
static void
do_test_produce_consumer_with_OIDC_should_fail_invalid_token_endpoint(
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

typedef enum oidc_configuration_jwt_bearer_variation_t {
        /** Use a private key file. */
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_FILE,
        /** Use an encrypted private key file. */
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_FILE_ENCRYPTED,
        /** Use a private key file
         *  set as a configuration property. */
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_STRING,
        /** Use an encrypted private key file
         *  set as a configuration property. */
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_STRING_ENCRYPTED,
        /** Use a private key file
         *  and a template for the JWT assertion. */
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION_TEMPLATE_FILE,
        /** Use a private key file and set the JOSE algorithm to ES256.
         *  This variation will fail as the private key is RSA in trivup  */
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION_JOSE_ALGORITHM_ES256,
        /** Invalid scope */
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION_INVALID_SCOPE,
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION__CNT
} oidc_configuration_jwt_bearer_variation_t;

#define OIDC_CONFIGURATION_JWT_BEARER_VARIATION__FIRST_FAILING                 \
        OIDC_CONFIGURATION_JWT_BEARER_VARIATION_JOSE_ALGORITHM_ES256

static const char *oidc_configuration_jwt_bearer_variation_name(
    oidc_configuration_jwt_bearer_variation_t variation) {
        rd_assert(
            variation >=
                OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_FILE &&
            variation < OIDC_CONFIGURATION_JWT_BEARER_VARIATION__CNT);
        static const char *names[] = {
            "private key file",       "private key encrypted file",
            "private key pem string", "private key encrypted pem string",
            "template file",          "JOSE algorithm ES256",
            "invalid scope"};
        return names[variation];
}

static rd_kafka_conf_t *oidc_configuration_jwt_bearer(
    rd_kafka_conf_t *conf,
    oidc_configuration_jwt_bearer_variation_t variation) {
        char file_content[4096];
        const char *private_key_file =
            test_getenv("OAUTHBEARER_CLIENT_PRIVATE_KEY", NULL);
        const char *private_key_encrypted_file =
            test_getenv("OAUTHBEARER_CLIENT_PRIVATE_KEY_ENCRYPTED", NULL);
        const char *private_key_password =
            test_getenv("OAUTHBEARER_CLIENT_PRIVATE_KEY_PASSWORD", NULL);

        conf = rd_kafka_conf_dup(conf);
        test_conf_set(conf, "sasl.oauthbearer.grant.type",
                      "urn:ietf:params:oauth:grant-type:jwt-bearer");
        /* "sub" isn't mandatory if already defined in the template. */
        if (variation != OIDC_CONFIGURATION_JWT_BEARER_VARIATION_TEMPLATE_FILE)
                test_conf_set(conf, "sasl.oauthbearer.assertion.claim.sub",
                              "testuser");
        else
                test_conf_set(conf,
                              "sasl.oauthbearer.assertion.jwt.template.file",
                              TEST_FIXTURES_JWT_ASSERTION_TEMPLATE);

        if (variation ==
            OIDC_CONFIGURATION_JWT_BEARER_VARIATION_JOSE_ALGORITHM_ES256)
                test_conf_set(conf, "sasl.oauthbearer.assertion.algorithm",
                              "ES256");
        if (variation == OIDC_CONFIGURATION_JWT_BEARER_VARIATION_INVALID_SCOPE)
                test_conf_set(conf, "sasl.oauthbearer.scope", "invalid_scope");

        switch (variation) {
        case OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_FILE:
        case OIDC_CONFIGURATION_JWT_BEARER_VARIATION_TEMPLATE_FILE:
        case OIDC_CONFIGURATION_JWT_BEARER_VARIATION_JOSE_ALGORITHM_ES256:
        case OIDC_CONFIGURATION_JWT_BEARER_VARIATION_INVALID_SCOPE:
                if (!private_key_file)
                        goto fail;

                test_conf_set(conf,
                              "sasl.oauthbearer.assertion.private.key.file",
                              private_key_file);
                break;
        case OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_FILE_ENCRYPTED:
                if (!private_key_encrypted_file || !private_key_password)
                        goto fail;
                test_conf_set(conf,
                              "sasl.oauthbearer.assertion.private.key.file",
                              private_key_encrypted_file);
                test_conf_set(
                    conf, "sasl.oauthbearer.assertion.private.key.passphrase",
                    private_key_password);
                break;
        case OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_STRING:
                if (!private_key_file)
                        goto fail;
                TEST_ASSERT(test_read_file(private_key_file, file_content,
                                           sizeof(file_content)) > 0);

                test_conf_set(conf,
                              "sasl.oauthbearer.assertion.private.key.pem",
                              file_content);
                break;
        case OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_STRING_ENCRYPTED:
                if (!private_key_encrypted_file || !private_key_password)
                        goto fail;
                TEST_ASSERT(test_read_file(private_key_file, file_content,
                                           sizeof(file_content)) > 0);

                test_conf_set(conf,
                              "sasl.oauthbearer.assertion.private.key.pem",
                              file_content);
                test_conf_set(
                    conf, "sasl.oauthbearer.assertion.private.key.passphrase",
                    private_key_password);
                break;
        default:
                rd_assert(!*"Unknown OIDC JWT bearer test variation");
        }
        return conf;
fail:
        rd_kafka_conf_destroy(conf);
        TEST_WARN("Skipping OIDC JWT bearer test variation: %s",
                  oidc_configuration_jwt_bearer_variation_name(variation));
        return NULL;
}

void do_test_produce_consumer_with_OIDC_jwt_bearer(rd_kafka_conf_t *conf) {
        rd_kafka_conf_t *jwt_bearer_conf;
        oidc_configuration_jwt_bearer_variation_t variation;
        for (variation =
                 OIDC_CONFIGURATION_JWT_BEARER_VARIATION_PRIVATE_KEY_FILE;
             variation < OIDC_CONFIGURATION_JWT_BEARER_VARIATION__CNT;
             variation++) {
                const char *test_name;
                jwt_bearer_conf =
                    oidc_configuration_jwt_bearer(conf, variation);
                if (!jwt_bearer_conf)
                        continue;

                test_name = tsprintf(
                    "JWT bearer: %s\n",
                    oidc_configuration_jwt_bearer_variation_name(variation));

                if (variation <
                    OIDC_CONFIGURATION_JWT_BEARER_VARIATION__FIRST_FAILING)
                        do_test_produce_consumer_with_OIDC(test_name,
                                                           jwt_bearer_conf);
                else
                        do_test_produce_consumer_with_OIDC_should_fail(
                            test_name, jwt_bearer_conf);
                rd_kafka_conf_destroy(jwt_bearer_conf);
        }
}

int main_0126_oauthbearer_oidc(int argc, char **argv) {
        rd_kafka_conf_t *conf;
        const char *sec;
        const char *oidc;

        test_conf_init(&conf, NULL, 60);

        sec = test_conf_get(conf, "security.protocol");
        if (!strstr(sec, "sasl")) {
                TEST_SKIP("Apache Kafka cluster not configured for SASL\n");
                rd_kafka_conf_destroy(conf);
                return 0;
        }

        oidc = test_conf_get(conf, "sasl.oauthbearer.method");
        if (rd_strcasecmp(oidc, "OIDC")) {
                TEST_SKIP("`sasl.oauthbearer.method=OIDC` is required\n");
                rd_kafka_conf_destroy(conf);
                return 0;
        }

        do_test_produce_consumer_with_OIDC("client_credentials", conf);
        do_test_produce_consumer_with_OIDC_should_fail_invalid_token_endpoint(
            conf);
        do_test_produce_consumer_with_OIDC_expired_token_should_fail(conf);
        do_test_produce_consumer_with_OIDC_jwt_bearer(conf);

        rd_kafka_conf_destroy(conf);

        return 0;
}
