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

#include "rdkafka.h"

#include "../src/rdkafka_proto.h"
#include "../src/rdunittest.h"

#include <stdarg.h>


/**
 * @name Verify connections.max.idle.ms
 *
 */

static void
log_cb(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
        rd_atomic32_t *log_cntp = rd_kafka_opaque(rk);

        if (!strstr(buf, "Connection max idle time exceeded"))
                return;

        TEST_SAY("Log: %s level %d fac %s: %s\n", rd_kafka_name(rk), level, fac,
                 buf);

        rd_atomic32_add(log_cntp, 1);
}

static void do_test_idle(rd_bool_t set_idle) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_atomic32_t log_cnt;

        SUB_TEST_QUICK("set_idle = %s", set_idle ? "yes" : "no");

        test_conf_init(&conf, NULL, 10);
        test_conf_set(conf, "debug", "broker");
        test_conf_set(conf, "connections.max.idle.ms", set_idle ? "5000" : "0");
        rd_atomic32_init(&log_cnt, 0);
        rd_kafka_conf_set_log_cb(conf, log_cb);
        rd_kafka_conf_set_opaque(conf, &log_cnt);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        rd_sleep(3);
        TEST_ASSERT(rd_atomic32_get(&log_cnt) == 0,
                    "Should not have seen an idle disconnect this soon");

        rd_sleep(5);
        if (set_idle)
                TEST_ASSERT(rd_atomic32_get(&log_cnt) > 0,
                            "Should have seen at least one idle "
                            "disconnect by now");
        else
                TEST_ASSERT(rd_atomic32_get(&log_cnt) == 0,
                            "Should not have seen an idle disconnect");

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


int main_0123_connections_max_idle(int argc, char **argv) {

        do_test_idle(rd_true);
        do_test_idle(rd_false);

        return 0;
}
