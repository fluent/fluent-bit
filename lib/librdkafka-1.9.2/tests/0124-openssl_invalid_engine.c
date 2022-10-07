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

int main_0124_openssl_invalid_engine(int argc, char **argv) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        char errstr[512];
        rd_kafka_conf_res_t res;

        test_conf_init(&conf, NULL, 30);
        res = rd_kafka_conf_set(conf, "ssl.engine.location", "invalid_path",
                                errstr, sizeof(errstr));

        if (res == RD_KAFKA_CONF_INVALID) {
                rd_kafka_conf_destroy(conf);
                TEST_SKIP("%s\n", errstr);
                return 0;
        }

        if (res != RD_KAFKA_CONF_OK)
                TEST_FAIL("%s", errstr);

        if (rd_kafka_conf_set(conf, "security.protocol", "ssl", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK)
                TEST_FAIL("%s", errstr);

        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        TEST_ASSERT(!rk,
                    "kafka_new() should not succeed with invalid engine"
                    " path, error: %s",
                    errstr);
        TEST_SAY("rd_kafka_new() failed (as expected): %s\n", errstr);

        TEST_ASSERT(strstr(errstr, "engine initialization failed in"),
                    "engine"
                    " initialization failure expected because of invalid engine"
                    " path, error: %s",
                    errstr);

        rd_kafka_conf_destroy(conf);
        return 0;
}
