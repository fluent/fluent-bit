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
static rd_bool_t user_token_cb_called;
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


/**
 * @brief After config OIDC, make sure the share consumer
 *        can work successfully.
 */
static void
do_test_produce_share_consumer_with_OIDC(const char *test_name,
                                         const rd_kafka_conf_t *base_conf) {
        const char *topic;
        rd_kafka_t *p1;
        rd_kafka_share_t *sc1;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        const char *grp_conf[] = {"share.auto.offset.reset", "SET", "earliest"};
        int consumed           = 0, attempts;
        const int msg_cnt      = 10;

        const char *url = test_getenv("VALID_OIDC_URL", NULL);

        SUB_TEST("Test share consumer with oidc configuration: %s", test_name);

        if (!url) {
                SUB_TEST_SKIP(
                    "VALID_OIDC_URL environment variable is not set\n");
                return;
        }

        conf = rd_kafka_conf_dup(base_conf);
        test_conf_set(conf, "sasl.oauthbearer.token.endpoint.url", url);

        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        p1 = test_create_handle(RD_KAFKA_PRODUCER, conf);

        topic = test_mk_topic_name("0126-oauthbearer_oidc_share", 1);
        test_create_topic_wait_exists(p1, topic, 1, 3, 5000);
        TEST_SAY("Topic: %s is created\n", topic);

        test_produce_msgs_easy(topic, 0, 0, msg_cnt);

        /* Create share consumer (picks up SASL config from test_conf_init) */
        sc1 = test_create_share_consumer("oidc-share-group", NULL);

        /* Set group config for earliest offset */
        test_IncrementalAlterConfigs_simple(p1, RD_KAFKA_RESOURCE_GROUP,
                                            "oidc-share-group", grp_conf, 1);

        /* Subscribe */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(sc1, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        /* Give it some time to trigger the token refresh. */
        rd_usleep(5 * 1000 * 1000, NULL);

        /* Consume messages */
        attempts = 50;
        while (consumed < msg_cnt && attempts-- > 0) {
                size_t rcvd = 0;
                size_t m;
                rd_kafka_error_t *err;

                rd_kafka_messages_destroy(batch);
                batch = NULL;

                err = rd_kafka_share_poll(sc1, 3000, &batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }

                rcvd = rd_kafka_messages_count(batch);
                for (m = 0; m < rcvd; m++) {
                        if (!rd_kafka_messages_get(batch, m)->err)
                                consumed++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_ASSERT(consumed == msg_cnt, "Expected %d messages, consumed %d",
                    msg_cnt, consumed);
        TEST_SAY("Share consumer consumed %d/%d messages with OIDC\n", consumed,
                 msg_cnt);

        rd_kafka_share_consumer_close(sc1);
        rd_kafka_share_destroy(sc1);
        rd_kafka_destroy(p1);
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
 * @brief Test-only token-refresh callback used to verify that a
 *        user-registered callback pre-empts the built-in OIDC callbacks.
 */
static void user_token_refresh_cb(rd_kafka_t *rk,
                                  const char *oauthbearer_config,
                                  void *opaque) {
        user_token_cb_called = rd_true;
        rd_kafka_oauthbearer_set_token_failure(
            rk, "aws_iam test user token refresh cb");
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
 * @brief After config OIDC with expired token, make sure the share consumer
 *        authentication fails as expected.
 */
static void do_test_produce_share_consumer_with_OIDC_expired_token_should_fail(
    const rd_kafka_conf_t *base_conf) {
        rd_kafka_share_t *sc1;
        rd_kafka_conf_t *conf;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd                = 0;
        rd_kafka_error_t *err;
        rd_kafka_topic_partition_list_t *subs;
        int attempts;
        char errstr[512];

        const char *expired_url = test_getenv("EXPIRED_TOKEN_OIDC_URL", NULL);

        SUB_TEST(
            "Test OAUTHBEARER/OIDC share consumer failing with "
            "expired JWT");

        if (!expired_url) {
                SUB_TEST_SKIP(
                    "EXPIRED_TOKEN_OIDC_URL environment variable is not "
                    "set\n");
                return;
        }

        conf = rd_kafka_conf_dup(base_conf);

        error_seen = rd_false;
        test_conf_set(conf, "sasl.oauthbearer.token.endpoint.url", expired_url);
        test_conf_set(conf, "group.id", "oidc-share-fail");

        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        sc1 = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(sc1, "Failed to create share consumer: %s", errstr);

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, "oidc-share-fail-topic",
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(sc1, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        attempts = 10;
        while (!error_seen && attempts-- > 0) {
                err = rd_kafka_share_poll(sc1, 3000, &batch);
                if (err)
                        rd_kafka_error_destroy(err);
                rcvd = rd_kafka_messages_count(batch);
                TEST_ASSERT(rcvd == 0,
                            "Expected no messages with expired token, got %zu",
                            rcvd);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(error_seen,
                    "Expected authentication error for share consumer "
                    "with expired token");

        rd_kafka_share_consumer_close(sc1);
        rd_kafka_share_destroy(sc1);
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


/**
 * @brief After config OIDC with invalid token endpoint, make sure the
 *        share consumer authentication fails as expected.
 */
static void
do_test_produce_share_consumer_with_OIDC_should_fail_invalid_token_endpoint(
    const rd_kafka_conf_t *base_conf) {
        rd_kafka_share_t *sc1;
        rd_kafka_conf_t *conf;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd                = 0;
        rd_kafka_error_t *err;
        rd_kafka_topic_partition_list_t *subs;
        int attempts;
        char errstr[512];

        const char *invalid_url = test_getenv("INVALID_OIDC_URL", NULL);

        SUB_TEST(
            "Test OAUTHBEARER/OIDC share consumer failing with "
            "invalid JWT");

        if (!invalid_url) {
                SUB_TEST_SKIP(
                    "INVALID_OIDC_URL environment variable is not set\n");
                return;
        }

        conf = rd_kafka_conf_dup(base_conf);

        error_seen = rd_false;
        test_conf_set(conf, "sasl.oauthbearer.token.endpoint.url", invalid_url);
        test_conf_set(conf, "group.id", "oidc-share-fail-invalid");

        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        sc1 = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(sc1, "Failed to create share consumer: %s", errstr);

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, "oidc-share-fail-invalid-topic",
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(sc1, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        attempts = 10;
        while (!error_seen && attempts-- > 0) {
                err = rd_kafka_share_poll(sc1, 3000, &batch);
                if (err)
                        rd_kafka_error_destroy(err);
                rcvd = rd_kafka_messages_count(batch);
                TEST_ASSERT(rcvd == 0,
                            "Expected no messages with invalid token "
                            "endpoint, got %zu",
                            rcvd);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(error_seen,
                    "Expected authentication error for share consumer "
                    "with invalid token endpoint");

        rd_kafka_share_consumer_close(sc1);
        rd_kafka_share_destroy(sc1);
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

/**
 * @brief Share consumer version of
 * do_test_produce_consumer_with_OIDC_should_fail. Verifies authentication
 * failure with share consumer.
 */
static void do_test_produce_share_consumer_with_OIDC_should_fail(
    const char *test_name,
    const rd_kafka_conf_t *base_conf) {
        rd_kafka_share_t *sc1;
        rd_kafka_conf_t *conf;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd                = 0;
        rd_kafka_error_t *err;
        rd_kafka_topic_partition_list_t *subs;
        int attempts;
        char errstr[512];

        const char *url = test_getenv("VALID_OIDC_URL", NULL);

        SUB_TEST("Test share consumer auth failure with oidc configuration: %s",
                 test_name);
        if (!url) {
                SUB_TEST_SKIP(
                    "VALID_OIDC_URL environment variable is not set\n");
                return;
        }

        error_seen = rd_false;

        conf = rd_kafka_conf_dup(base_conf);
        test_conf_set(conf, "sasl.oauthbearer.token.endpoint.url", url);
        test_conf_set(conf, "group.id", "oidc-share-should-fail");

        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        sc1 = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(sc1, "Failed to create share consumer: %s", errstr);

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, "oidc-share-should-fail-topic",
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(sc1, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        attempts = 10;
        while (!error_seen && attempts-- > 0) {
                err = rd_kafka_share_poll(sc1, 3000, &batch);
                if (err)
                        rd_kafka_error_destroy(err);
                rcvd = rd_kafka_messages_count(batch);
                TEST_ASSERT(rcvd == 0,
                            "Expected no messages on auth failure, got %zu",
                            rcvd);
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }

        TEST_ASSERT(error_seen,
                    "Expected authentication error for share consumer");

        rd_kafka_share_consumer_close(sc1);
        rd_kafka_share_destroy(sc1);
        SUB_TEST_PASS();
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

void do_test_produce_share_consumer_with_OIDC_jwt_bearer(
    rd_kafka_conf_t *conf) {
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
                        do_test_produce_share_consumer_with_OIDC(
                            test_name, jwt_bearer_conf);
                else
                        do_test_produce_share_consumer_with_OIDC_should_fail(
                            test_name, jwt_bearer_conf);
                rd_kafka_conf_destroy(jwt_bearer_conf);
        }
}


typedef enum oidc_configuration_metadata_authentication_variation_t {
        /** Azure IMDS. Successful case. */
        OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_SUCCESS,
        /** Azure IMDS. Missing client ID. */
        OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_MISSING_CLIENT_ID,
        /** Azure IMDS. Missing resource parameter. */
        OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_MISSING_RESOURCE,
        /** Azure IMDS. Missing API version. */
        OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_MISSING_API_VERSION,
        OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION__CNT
} oidc_configuration_metadata_authentication_variation_t;

#define OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION__FIRST_FAILING    \
        OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_MISSING_CLIENT_ID

static const char *oidc_configuration_metadata_authentication_variation_name(
    oidc_configuration_metadata_authentication_variation_t variation) {
        rd_assert(
            variation >=
                OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_SUCCESS &&
            variation <
                OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION__CNT);
        static const char *names[] = {
            "Azure IMDS: success", "Azure IMDS: missing client ID",
            "Azure IMDS: missing resource", "Azure IMDS: missing API version"};
        return names[variation];
}

static rd_kafka_conf_t *oidc_configuration_metadata_authentication(
    rd_kafka_conf_t *conf,
    oidc_configuration_metadata_authentication_variation_t variation) {
        conf = rd_kafka_conf_dup(conf);
        switch (variation) {
        case OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_SUCCESS:
                test_conf_set(conf,
                              "sasl.oauthbearer.metadata.authentication.type",
                              "azure_imds");
                test_conf_set(conf, "sasl.oauthbearer.config",
                              "query=__metadata_authentication_type=azure_imds&"
                              "api-version=2025-04-07&resource="
                              "api://external_resource_id&client_id=client_id");
                break;
        case OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_MISSING_CLIENT_ID:
                test_conf_set(conf,
                              "sasl.oauthbearer.metadata.authentication.type",
                              "azure_imds");
                test_conf_set(conf, "sasl.oauthbearer.config",
                              "query=__metadata_authentication_type=azure_imds&"
                              "api-version=2025-04-07&resource="
                              "api://external_resource_id");
                break;
        case OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_MISSING_RESOURCE:
                test_conf_set(conf,
                              "sasl.oauthbearer.metadata.authentication.type",
                              "azure_imds");
                test_conf_set(conf, "sasl.oauthbearer.config",
                              "query=__metadata_authentication_type=azure_imds&"
                              "api-version=2025-04-07&"
                              "client_id=client_id");
                break;
        case OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_MISSING_API_VERSION:
                test_conf_set(conf,
                              "sasl.oauthbearer.metadata.authentication.type",
                              "azure_imds");
                test_conf_set(conf, "sasl.oauthbearer.config",
                              "query=__metadata_authentication_type=azure_imds&"
                              "resource="
                              "api://external_resource_id&client_id=client_id");
                break;
        default:
                TEST_ASSERT(rd_false,
                            "Unknown OIDC metadata authentication type");
        }
        return conf;
}

/* Test metadata-based authentication cases against Trivup. */
void do_test_produce_consumer_with_OIDC_metadata_authentication(
    rd_kafka_conf_t *conf) {
        rd_kafka_conf_t *metadata_authentication_conf;
        oidc_configuration_metadata_authentication_variation_t variation;
        for (
            variation =
                OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_SUCCESS;
            variation <
            OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION__CNT;
            variation++) {
                const char *test_name;
                metadata_authentication_conf =
                    oidc_configuration_metadata_authentication(conf, variation);

                test_name = tsprintf(
                    "Metadata authentication variation: %s\n",
                    oidc_configuration_metadata_authentication_variation_name(
                        variation));

                if (variation <
                    OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION__FIRST_FAILING)
                        do_test_produce_consumer_with_OIDC(
                            test_name, metadata_authentication_conf);
                else
                        do_test_produce_consumer_with_OIDC_should_fail(
                            test_name, metadata_authentication_conf);
                rd_kafka_conf_destroy(metadata_authentication_conf);
        }
}

void do_test_produce_share_consumer_with_OIDC_metadata_authentication(
    rd_kafka_conf_t *conf) {
        rd_kafka_conf_t *metadata_authentication_conf;
        oidc_configuration_metadata_authentication_variation_t variation;
        for (
            variation =
                OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION_AZURE_IMDS_SUCCESS;
            variation <
            OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION__CNT;
            variation++) {
                const char *test_name;
                metadata_authentication_conf =
                    oidc_configuration_metadata_authentication(conf, variation);

                test_name = tsprintf(
                    "Metadata authentication variation: %s\n",
                    oidc_configuration_metadata_authentication_variation_name(
                        variation));

                if (variation <
                    OIDC_CONFIGURATION_METADATA_AUTHENTICATION_VARIATION__FIRST_FAILING)
                        do_test_produce_share_consumer_with_OIDC(
                            test_name, metadata_authentication_conf);
                else
                        do_test_produce_share_consumer_with_OIDC_should_fail(
                            test_name, metadata_authentication_conf);
                rd_kafka_conf_destroy(metadata_authentication_conf);
        }
}

typedef enum oidc_configuration_sub_claim_variation_t {
        /** Use default "sub" claim (backward compatibility). */
        OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_DEFAULT_SUB,
        /** Explicitly set "sub" as the claim name. */
        OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_EXPLICIT_SUB,
        /** Use custom claim name "client_id". */
        OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_CUSTOM_CLIENT_ID,
        /** Set empty string "" — resets to default "sub" per librdkafka string
           semantics. */
        OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_EMPTY_STRING,
        /** Use a claim name that doesn't exist in the token (should fail). */
        OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_MISSING_CLAIM,
        OIDC_CONFIGURATION_SUB_CLAIM_VARIATION__CNT
} oidc_configuration_sub_claim_variation_t;

#define OIDC_CONFIGURATION_SUB_CLAIM_VARIATION__FIRST_FAILING                  \
        OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_MISSING_CLAIM

static const char *oidc_configuration_sub_claim_variation_name(
    oidc_configuration_sub_claim_variation_t variation) {
        rd_assert(variation >=
                      OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_DEFAULT_SUB &&
                  variation < OIDC_CONFIGURATION_SUB_CLAIM_VARIATION__CNT);
        static const char *names[] = {
            "default sub claim", "explicit sub claim", "custom client_id claim",
            "empty string (defaults to sub)", "missing claim (should fail)"};
        return names[variation];
}

/**
 * @brief Configure OIDC with different subject claim name variations.
 *
 * Note: This test assumes the OIDC token provider returns tokens with
 * standard claims including "sub" and "client_id".
 * The test validates that librdkafka can extract the subject from
 * different claims based on configuration.
 */
static rd_kafka_conf_t *oidc_configuration_sub_claim(
    rd_kafka_conf_t *conf,
    oidc_configuration_sub_claim_variation_t variation) {
        conf = rd_kafka_conf_dup(conf);

        switch (variation) {
        case OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_DEFAULT_SUB:
                break;
        case OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_EXPLICIT_SUB:
                test_conf_set(conf, "sasl.oauthbearer.sub.claim.name", "sub");
                break;
        case OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_CUSTOM_CLIENT_ID:
                test_conf_set(conf, "sasl.oauthbearer.sub.claim.name",
                              "client_id");
                break;
        case OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_EMPTY_STRING:
                test_conf_set(conf, "sasl.oauthbearer.sub.claim.name", "");
                break;
        case OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_MISSING_CLAIM:
                test_conf_set(conf, "sasl.oauthbearer.sub.claim.name",
                              "nonexistent_claim");
                break;
        default:
                rd_assert(!*"Unknown OIDC sub claim test variation");
        }
        return conf;
}

/**
 * @brief Test producer and consumer with different subject claim name
 *        configurations.
 *
 * This test validates KIP-768 parity for sasl.oauthbearer.sub.claim.name:
 * - Default behavior uses "sub" claim
 * - Custom claim names can be configured
 * - Missing configured claim causes validation failure
 * - Non-empty claim value is enforced
 */
void do_test_produce_consumer_with_OIDC_sub_claim(rd_kafka_conf_t *conf) {
        rd_kafka_conf_t *sub_claim_conf;
        oidc_configuration_sub_claim_variation_t variation;

        const char *url = test_getenv("VALID_OIDC_URL", NULL);

        /* Check if we should skip sub claim tests based on environment */
        if (!url) {
                SUB_TEST_SKIP(
                    "VALID_OIDC_URL environment variable is not set, "
                    "skipping sub claim tests\n");
                return;
        }

        for (variation = OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_DEFAULT_SUB;
             variation < OIDC_CONFIGURATION_SUB_CLAIM_VARIATION__CNT;
             variation++) {
                const char *test_name;
                sub_claim_conf = oidc_configuration_sub_claim(conf, variation);

                test_name = tsprintf(
                    "Sub claim variation: %s\n",
                    oidc_configuration_sub_claim_variation_name(variation));

                if (variation <
                    OIDC_CONFIGURATION_SUB_CLAIM_VARIATION__FIRST_FAILING) {
                        /* These variations should succeed */
                        do_test_produce_consumer_with_OIDC(test_name,
                                                           sub_claim_conf);
                } else {
                        /* These variations should fail */
                        do_test_produce_consumer_with_OIDC_should_fail(
                            test_name, sub_claim_conf);
                }
                rd_kafka_conf_destroy(sub_claim_conf);
        }
}

void do_test_produce_share_consumer_with_OIDC_sub_claim(rd_kafka_conf_t *conf) {
        rd_kafka_conf_t *sub_claim_conf;
        oidc_configuration_sub_claim_variation_t variation;

        const char *url = test_getenv("VALID_OIDC_URL", NULL);

        if (!url) {
                SUB_TEST_SKIP(
                    "VALID_OIDC_URL environment variable is not set, "
                    "skipping share consumer sub claim tests\n");
                return;
        }

        for (variation = OIDC_CONFIGURATION_SUB_CLAIM_VARIATION_DEFAULT_SUB;
             variation < OIDC_CONFIGURATION_SUB_CLAIM_VARIATION__CNT;
             variation++) {
                const char *test_name;
                sub_claim_conf = oidc_configuration_sub_claim(conf, variation);

                test_name = tsprintf(
                    "Sub claim variation: %s\n",
                    oidc_configuration_sub_claim_variation_name(variation));

                if (variation <
                    OIDC_CONFIGURATION_SUB_CLAIM_VARIATION__FIRST_FAILING) {
                        do_test_produce_share_consumer_with_OIDC(
                            test_name, sub_claim_conf);
                } else {
                        do_test_produce_share_consumer_with_OIDC_should_fail(
                            test_name, sub_claim_conf);
                }
                rd_kafka_conf_destroy(sub_claim_conf);
        }
}

/**
 * @brief aws_iam round-trips through rd_kafka_conf_set/get, confirming
 *        the s2i wiring for the new enum value.
 */
static void do_test_OIDC_aws_iam_conf_roundtrip(void) {
        rd_kafka_conf_t *conf;
        char errstr[512];
        char value[64];
        size_t value_size = sizeof(value);

        SUB_TEST("aws_iam round-trips through rd_kafka_conf_set/get");

        conf = rd_kafka_conf_new();

        TEST_ASSERT(rd_kafka_conf_set(
                        conf, "sasl.oauthbearer.metadata.authentication.type",
                        "aws_iam", errstr, sizeof(errstr)) == RD_KAFKA_CONF_OK,
                    "Failed to set aws_iam: %s", errstr);

        TEST_ASSERT(rd_kafka_conf_get(
                        conf, "sasl.oauthbearer.metadata.authentication.type",
                        value, &value_size) == RD_KAFKA_CONF_OK,
                    "Failed to read aws_iam back from conf");
        TEST_ASSERT(strcmp(value, "aws_iam") == 0,
                    "Expected 'aws_iam', got '%s'", value);

        rd_kafka_conf_destroy(conf);
        SUB_TEST_PASS();
}

/**
 * @brief When method=oidc and metadata.authentication.type=aws_iam
 *        but no token-refresh callback is registered, the built-in
 *        stub installed by librdkafka surfaces a token-refresh
 *        failure rather than silently falling back to a different
 *        OIDC flow.
 */
static void do_test_OIDC_aws_iam_stub_fires_without_callback(
    const rd_kafka_conf_t *base_conf) {
        rd_kafka_t *c1;
        uint64_t testid;
        rd_kafka_conf_t *conf;

        SUB_TEST("aws_iam stub fails token refresh when no callback is set");

        conf = rd_kafka_conf_dup(base_conf);
        test_conf_set(conf, "sasl.oauthbearer.metadata.authentication.type",
                      "aws_iam");

        error_seen = rd_false;
        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        testid = test_id_generate();

        c1 = test_create_consumer("aws_iam.stub.C1", NULL, conf, NULL);

        test_consumer_poll_no_msgs("aws_iam.stub.C1", c1, testid, 5 * 1000);
        TEST_ASSERT(error_seen,
                    "Expected aws_iam stub to surface a token refresh "
                    "failure");

        test_consumer_close(c1);
        rd_kafka_destroy(c1);
        SUB_TEST_PASS();
}

/**
 * @brief User-registered token refresh callback takes precedence over
 *        the aws_iam stub.
 */
static void
do_test_OIDC_aws_iam_user_callback_wins(const rd_kafka_conf_t *base_conf) {
        rd_kafka_t *c1;
        uint64_t testid;
        rd_kafka_conf_t *conf;

        SUB_TEST(
            "aws_iam: user-registered token refresh callback wins over stub");

        conf = rd_kafka_conf_dup(base_conf);
        test_conf_set(conf, "sasl.oauthbearer.metadata.authentication.type",
                      "aws_iam");

        rd_kafka_conf_set_oauthbearer_token_refresh_cb(conf,
                                                       user_token_refresh_cb);

        user_token_cb_called = rd_false;
        error_seen           = rd_false;
        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        testid = test_id_generate();

        c1 = test_create_consumer("aws_iam.user_cb.C1", NULL, conf, NULL);

        test_consumer_poll_no_msgs("aws_iam.user_cb.C1", c1, testid, 5 * 1000);
        TEST_ASSERT(user_token_cb_called,
                    "Expected user-registered token refresh callback to "
                    "fire instead of the aws_iam stub");
        TEST_ASSERT(error_seen,
                    "Expected user-callback's set_token_failure to surface "
                    "as an authentication error");

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
                rd_kafka_conf_destroy(conf);
                return 0;
        }

        oidc = test_conf_get(conf, "sasl.oauthbearer.method");
        if (rd_strcasecmp(oidc, "OIDC")) {
                TEST_SKIP("`sasl.oauthbearer.method=OIDC` is required\n");
                rd_kafka_conf_destroy(conf);
                return 0;
        }

        test_timeout_set(300);
        do_test_produce_consumer_with_OIDC("client_credentials", conf);
        do_test_produce_share_consumer_with_OIDC("client_credentials", conf);
        do_test_produce_consumer_with_OIDC_should_fail_invalid_token_endpoint(
            conf);
        do_test_produce_share_consumer_with_OIDC_should_fail_invalid_token_endpoint(
            conf);
        do_test_produce_consumer_with_OIDC_expired_token_should_fail(conf);
        do_test_produce_share_consumer_with_OIDC_expired_token_should_fail(
            conf);
        do_test_produce_consumer_with_OIDC_jwt_bearer(conf);
        do_test_produce_share_consumer_with_OIDC_jwt_bearer(conf);
        do_test_produce_consumer_with_OIDC_metadata_authentication(conf);
        do_test_produce_share_consumer_with_OIDC_metadata_authentication(conf);
        do_test_produce_consumer_with_OIDC_sub_claim(conf);
        do_test_produce_share_consumer_with_OIDC_sub_claim(conf);

        do_test_OIDC_aws_iam_conf_roundtrip();
        do_test_OIDC_aws_iam_stub_fires_without_callback(conf);
        do_test_OIDC_aws_iam_user_callback_wins(conf);

        rd_kafka_conf_destroy(conf);

        return 0;
}
