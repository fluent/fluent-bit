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
#include "rdkafka.h"

/**
 * @brief Simple producev() verification
 */

/**
 * @brief Verify #1478: The internal shared rkt reference was not destroyed
 *        when producev() failed.
 */

static void do_test_srkt_leak (void) {
        rd_kafka_conf_t *conf;
        char buf[2000];
        rd_kafka_t *rk;
        rd_kafka_resp_err_t err;

        conf = rd_kafka_conf_new();
        test_conf_set(conf, "message.max.bytes", "1000");

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        err = rd_kafka_producev(rk,
                                RD_KAFKA_V_TOPIC("test"),
                                RD_KAFKA_V_VALUE(buf, sizeof(buf)),
                                RD_KAFKA_V_END);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE,
                    "expected MSG_SIZE_TOO_LARGE, not %s",
                    rd_kafka_err2str(err));

        rd_kafka_destroy(rk);
}


int main_0074_producev (int argc, char **argv) {
        do_test_srkt_leak();
        return 0;
}
