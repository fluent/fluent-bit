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


static void test_providers(const char *providers,
                           rd_bool_t must_pass,
                           rd_bool_t must_fail) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        char errstr[512];

        SUB_TEST_QUICK("providers=%s, %s pass, %s fail", providers,
                       must_pass ? "must" : "may", must_fail ? "must" : "may");

        test_conf_init(&conf, NULL, 10);

        /* Enable debugging so we get some extra information on
         * OpenSSL version and provider versions in the test log. */
        test_conf_set(conf, "debug", "security");
        test_conf_set(conf, "ssl.providers", providers);
        test_conf_set(conf, "security.protocol", "ssl");

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));

        TEST_SAY("rd_kafka_new(ssl.providers=%s): %s\n", providers,
                 rk ? "success" : errstr);

        if (must_pass && !rk)
                TEST_FAIL("Expected ssl.providers=%s to work, got %s",
                          providers, errstr);
        else if (must_fail && rk)
                TEST_FAIL("Expected ssl.providers=%s to fail", providers);

        if (!rk)
                rd_kafka_conf_destroy(conf);
        else
                rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}

int main_0134_ssl_provider(int argc, char **argv) {
        rd_kafka_conf_t *conf;
        char errstr[512];
        rd_kafka_conf_res_t res;

        test_conf_init(&conf, NULL, 10);

        /* Check that we're linked/built with OpenSSL 3.x */
        res = rd_kafka_conf_set(conf, "ssl.providers", "a,b", errstr,
                                sizeof(errstr));
        rd_kafka_conf_destroy(conf);
        if (res == RD_KAFKA_CONF_INVALID) {
                TEST_SKIP("%s\n", errstr);
                return 0;
        }

        /* Must pass since 'default' is always built in */
        test_providers("default", rd_true, rd_false);
        /* May fail, if legacy provider is not available. */
        test_providers("default,legacy", rd_false, rd_false);
        /* Must fail since non-existent provider */
        test_providers("default,thisProviderDoesNotExist", rd_false, rd_true);
        return 0;
}
