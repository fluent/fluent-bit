/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020, Magnus Edenhill
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
 * @name Connecting to two different clusters should emit warning.
 *
 */

static void
log_cb(const rd_kafka_t *rk, int level, const char *fac, const char *buf) {
        rd_atomic32_t *log_cntp = rd_kafka_opaque(rk);
        rd_bool_t matched       = !strcmp(fac, "CLUSTERID") &&
                            strstr(buf, "reports different ClusterId");

        TEST_SAY("%sLog: %s level %d fac %s: %s\n", matched ? _C_GRN : "",
                 rd_kafka_name(rk), level, fac, buf);

        if (matched)
                rd_atomic32_add(log_cntp, 1);
}


int main_0121_clusterid(int argc, char **argv) {
        rd_kafka_mock_cluster_t *cluster_a, *cluster_b;
        const char *bootstraps_a, *bootstraps_b;
        size_t bs_size;
        char *bootstraps;
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_atomic32_t log_cnt;
        int cnt = 0;

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        /* Create two clusters */
        cluster_a = test_mock_cluster_new(1, &bootstraps_a);
        cluster_b = test_mock_cluster_new(1, &bootstraps_b);
        rd_kafka_mock_broker_set_down(cluster_b, 1);

        test_conf_init(&conf, NULL, 10);

        /* Combine bootstraps from both clusters */
        bs_size    = strlen(bootstraps_a) + strlen(bootstraps_b) + 2;
        bootstraps = malloc(bs_size);
        rd_snprintf(bootstraps, bs_size, "%s,%s", bootstraps_a, bootstraps_b);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        free(bootstraps);

        rd_atomic32_init(&log_cnt, 0);
        rd_kafka_conf_set_log_cb(conf, log_cb);
        rd_kafka_conf_set_opaque(conf, &log_cnt);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);


        while (rd_atomic32_get(&log_cnt) == 0) {
                const rd_kafka_metadata_t *md;

                /* After 3 seconds bring down cluster a and bring up
                 * cluster b, this is to force the client to connect to
                 * the other cluster. */
                if (cnt == 3) {
                        rd_kafka_mock_broker_set_down(cluster_a, 1);
                        rd_kafka_mock_broker_set_up(cluster_b, 1);
                }

                if (!rd_kafka_metadata(rk, 1, NULL, &md, 1000))
                        rd_kafka_metadata_destroy(md);
                rd_sleep(1);

                cnt++;
        }


        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(cluster_a);
        test_mock_cluster_destroy(cluster_b);

        return 0;
}
