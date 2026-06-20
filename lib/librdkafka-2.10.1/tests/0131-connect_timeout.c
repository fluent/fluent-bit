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

#include "rdkafka.h"


/**
 * @name Verify socket.connection.setup.timeout.ms by using
 *       a mock cluster with an rtt > timeout.
 */

static void
log_cb(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
        rd_atomic32_t *log_cntp = rd_kafka_opaque(rk);

        if (!strstr(buf, "Connection setup timed out"))
                return;

        TEST_SAY("Log: %s level %d fac %s: %s\n", rd_kafka_name(rk), level, fac,
                 buf);

        rd_atomic32_add(log_cntp, 1);
}

int main_0131_connect_timeout(int argc, char **argv) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_atomic32_t log_cnt;

        test_conf_init(NULL, NULL, 20);
        conf = rd_kafka_conf_new();
        test_conf_set(conf, "test.mock.num.brokers", "2");
        test_conf_set(conf, "test.mock.broker.rtt", "10000");
        test_conf_set(conf, "socket.connection.setup.timeout.ms", "6000");
        test_conf_set(conf, "debug", "broker");
        rd_atomic32_init(&log_cnt, 0);
        rd_kafka_conf_set_log_cb(conf, log_cb);
        rd_kafka_conf_set_opaque(conf, &log_cnt);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        rd_sleep(3);
        TEST_ASSERT(rd_atomic32_get(&log_cnt) == 0,
                    "Should not have seen a disconnect this soon");

        rd_sleep(5);
        TEST_ASSERT(rd_atomic32_get(&log_cnt) > 0,
                    "Should have seen at least one "
                    "disconnect by now");

        rd_kafka_destroy(rk);

        return 0;
}
