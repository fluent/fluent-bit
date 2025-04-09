/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
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

/**
 * Tests multiple rd_kafka_t object creations and destructions.
 * Issue #20
 */

#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */

int main_0001_multiobj(int argc, char **argv) {
        int partition = RD_KAFKA_PARTITION_UA; /* random */
        int i;
        int NUM_ITER      = test_quick ? 2 : 5;
        const char *topic = NULL;

        TEST_SAY("Creating and destroying %i kafka instances\n", NUM_ITER);

        /* Create, use and destroy NUM_ITER kafka instances. */
        for (i = 0; i < NUM_ITER; i++) {
                rd_kafka_t *rk;
                rd_kafka_topic_t *rkt;
                rd_kafka_conf_t *conf;
                rd_kafka_topic_conf_t *topic_conf;
                char msg[128];
                test_timing_t t_full, t_destroy;

                test_conf_init(&conf, &topic_conf, 30);

                if (!topic)
                        topic = test_mk_topic_name("0001", 0);

                TIMING_START(&t_full, "full create-produce-destroy cycle");
                rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

                rkt = rd_kafka_topic_new(rk, topic, topic_conf);
                if (!rkt)
                        TEST_FAIL(
                            "Failed to create topic for "
                            "rdkafka instance #%i: %s\n",
                            i, rd_kafka_err2str(rd_kafka_last_error()));

                rd_snprintf(msg, sizeof(msg),
                            "%s test message for iteration #%i", argv[0], i);

                /* Produce a message */
                rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY, msg,
                                 strlen(msg), NULL, 0, NULL);

                /* Wait for it to be sent (and possibly acked) */
                rd_kafka_flush(rk, -1);

                /* Destroy topic */
                rd_kafka_topic_destroy(rkt);

                /* Destroy rdkafka instance */
                TIMING_START(&t_destroy, "rd_kafka_destroy()");
                rd_kafka_destroy(rk);
                TIMING_STOP(&t_destroy);

                TIMING_STOP(&t_full);

                /* Topic is created on the first iteration. */
                if (i > 0)
                        TIMING_ASSERT(&t_full, 0, 999);
        }

        return 0;
}
