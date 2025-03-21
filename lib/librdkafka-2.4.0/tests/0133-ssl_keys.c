/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2022, Magnus Edenhill
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
#include "rdstring.h"

/**
 * @brief Tests reading SSL PKCS#12 keystore or PEM certificate and key from
 * file. Decoding it with the correct password or not.
 *
 * Ensures it's read correctly on Windows too.
 * See https://github.com/confluentinc/librdkafka/issues/3992
 */
static void do_test_ssl_keys(const char *type, rd_bool_t correct_password) {
#define TEST_FIXTURES_FOLDER            "./fixtures"
#define TEST_FIXTURES_SSL_FOLDER        TEST_FIXTURES_FOLDER "/ssl/"
#define TEST_FIXTURES_KEYSTORE_PASSWORD "use_strong_password_keystore_client"
#define TEST_FIXTURES_KEY_PASSWORD      "use_strong_password_keystore_client2"
#define TEST_KEYSTORE_LOCATION          TEST_FIXTURES_SSL_FOLDER "client.keystore.p12"
#define TEST_CERTIFICATE_LOCATION                                              \
        TEST_FIXTURES_SSL_FOLDER "client2.certificate.pem"
#define TEST_KEY_LOCATION TEST_FIXTURES_SSL_FOLDER "client2.key"

        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        char errstr[256];

        SUB_TEST_QUICK("keystore type = %s, correct password = %s", type,
                       RD_STR_ToF(correct_password));

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "security.protocol", "SSL");

        if (!strcmp(type, "PKCS12")) {
                test_conf_set(conf, "ssl.keystore.location",
                              TEST_KEYSTORE_LOCATION);
                if (correct_password)
                        test_conf_set(conf, "ssl.keystore.password",
                                      TEST_FIXTURES_KEYSTORE_PASSWORD);
                else
                        test_conf_set(conf, "ssl.keystore.password",
                                      TEST_FIXTURES_KEYSTORE_PASSWORD
                                      " and more");
        } else if (!strcmp(type, "PEM")) {
                test_conf_set(conf, "ssl.certificate.location",
                              TEST_CERTIFICATE_LOCATION);
                test_conf_set(conf, "ssl.key.location", TEST_KEY_LOCATION);
                if (correct_password)
                        test_conf_set(conf, "ssl.key.password",
                                      TEST_FIXTURES_KEY_PASSWORD);
                else
                        test_conf_set(conf, "ssl.keystore.password",
                                      TEST_FIXTURES_KEYSTORE_PASSWORD
                                      " and more");
        } else {
                TEST_FAIL("Unexpected key type\n");
        }

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        if ((rk != NULL) != correct_password) {
                TEST_FAIL("Expected rd_kafka creation to %s\n",
                          correct_password ? "succeed" : "fail");
        }

        if (rk)
                rd_kafka_destroy(rk);
        else
                rd_kafka_conf_destroy(conf);

        SUB_TEST_PASS();

#undef TEST_FIXTURES_KEYSTORE_PASSWORD
#undef TEST_FIXTURES_KEY_PASSWORD
#undef TEST_KEYSTORE_LOCATION
#undef TEST_CERTIFICATE_LOCATION
#undef TEST_KEY_LOCATION
#undef TEST_FIXTURES_FOLDER
#undef TEST_FIXTURES_SSL_FOLDER
}


int main_0133_ssl_keys(int argc, char **argv) {
        do_test_ssl_keys("PKCS12", rd_true);
        do_test_ssl_keys("PKCS12", rd_false);
        do_test_ssl_keys("PEM", rd_true);
        do_test_ssl_keys("PEM", rd_false);
        return 0;
}
