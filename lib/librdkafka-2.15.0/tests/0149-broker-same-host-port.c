/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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

static rd_bool_t broker1_changed;
static rd_bool_t broker2_changed;
static rd_bool_t broker3_changed;

/**
 * @brief Keep track of which brokers have changed their nodename.
 */
static void broker_same_host_port_mock_log_cb(const rd_kafka_t *rk,
                                              int level,
                                              const char *fac,
                                              const char *buf) {
        const char *nodename = "to localhost:11192";
        if (strstr(buf, "/1: Nodename changed") && strstr(buf, nodename))
                broker1_changed = rd_true;

        if (strstr(buf, "/2: Nodename changed") && strstr(buf, nodename))
                broker2_changed = rd_true;

        if (strstr(buf, "/3: Nodename changed") && strstr(buf, nodename))
                broker3_changed = rd_true;
}

static void broker_same_host_port_mock_verify_broker_ids(rd_kafka_t *rk) {
        const rd_kafka_metadata_t *md;
        rd_kafka_resp_err_t err;
        int32_t *ids;
        size_t cnt               = 0;
        const size_t num_brokers = 3;
        size_t i;

        /* Trigger Metadata request which will get initial broker hostnames. */
        err = rd_kafka_metadata(rk, 0, NULL, &md, tmout_multip(5000));
        /* Metadata timeout can happen if nodename change did already
         * take place and there was a disconnection followed by a retry */
        if (err && err != RD_KAFKA_RESP_ERR__TIMED_OUT)
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        else if (!err)
                rd_kafka_metadata_destroy(md);

        ids = rd_kafka_brokers_learned_ids(rk, &cnt);

        TEST_ASSERT(cnt == num_brokers,
                    "expected %" PRIusz " brokers in cache, not %" PRIusz,
                    num_brokers, cnt);

        for (i = 0; i < cnt; i++) {
                int32_t expected_id = i + 1;

                TEST_ASSERT(ids[i] == expected_id,
                            "expected broker %d in cache, not %d", expected_id,
                            ids[i]);
        }
        if (ids)
                free(ids);
}

/**
 * @brief It should be possible to set the same hostname to brokers with
 *        broker ids, when doing that, verify that the brokers are kept
 *        separate instances and that the hostname is propagated to all of them.
 */
int main_0149_broker_same_host_port_mock(int argc, char **argv) {
        rd_kafka_mock_cluster_t *cluster;
        const char *bootstraps;
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        const size_t num_brokers = 3;
        size_t i;
        test_conf_log_interceptor_t *log_interceptor;
        const char *debug_contexts[2] = {"broker", NULL};

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        cluster = test_mock_cluster_new(num_brokers, &bootstraps);

        test_conf_init(&conf, NULL, tmout_multip(10));
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        log_interceptor = test_conf_set_log_interceptor(
            conf, broker_same_host_port_mock_log_cb, debug_contexts);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("Initial metadata request\n");
        /* Trigger Metadata request which will get initial broker hostnames. */
        broker_same_host_port_mock_verify_broker_ids(rk);

        TEST_SAY("Changing nodenames\n");
        for (i = 1; i <= num_brokers; i++) {
                rd_kafka_mock_broker_set_host_port(cluster, i, "localhost",
                                                   11192);
        }

        TEST_SAY("Modified nodenames metadata request\n");
        /* Trigger Metadata request which will get initial changed hostnames. */
        broker_same_host_port_mock_verify_broker_ids(rk);

        TEST_SAY("Verifying all brokers changed nodename\n");
        while (!(broker1_changed && broker2_changed && broker3_changed))
                rd_usleep(100000, 0);

        TEST_SAY("Verification complete\n");
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(cluster);
        rd_free(log_interceptor);

        return 0;
}
