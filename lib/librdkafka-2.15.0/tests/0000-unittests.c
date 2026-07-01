/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2017-2022, Magnus Edenhill
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


/**
 * @brief Initialize a client with debugging to have it print its
 *        build options, OpenSSL version, etc.
 *        Useful for manually verifying build options in CI logs.
 */
static void show_build_opts(void) {
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        rd_kafka_t *rk;
        char errstr[512];

        TEST_SAY("builtin.features = %s\n",
                 test_conf_get(conf, "builtin.features"));

        test_conf_set(conf, "debug", "generic,security");

        /* Try with SSL first, which may or may not be a build option. */
        if (rd_kafka_conf_set(conf, "security.protocol", "SSL", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK)
                TEST_SAY("Failed to security.protocol=SSL: %s\n", errstr);

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(rk, "Failed to create producer: %s", errstr);

        rd_kafka_destroy(rk);
}


/**
 * @brief Call librdkafka built-in unit-tests
 */
int main_0000_unittests(int argc, char **argv) {
        int fails = 0;

        show_build_opts();

        fails += rd_kafka_unittest();
        if (fails)
                TEST_FAIL("%d unit-test(s) failed", fails);
        return 0;
}
