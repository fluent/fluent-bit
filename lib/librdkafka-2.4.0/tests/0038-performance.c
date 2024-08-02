/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2016-2022, Magnus Edenhill
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

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * Basic performance tests.
 * These tests dont fail but provide a throughput rate indication.
 *
 * + Produce N messages to one partition, acks=1, size=100
 */


int main_0038_performance(int argc, char **argv) {
        const char *topic   = test_mk_topic_name(__FUNCTION__, 1);
        const int partition = 0;
        const int msgsize   = 100;
        uint64_t testid;
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        rd_kafka_topic_t *rkt;
        test_timing_t t_create, t_produce, t_consume;
        int totsize = 1024 * 1024 * (test_quick ? 8 : 128);
        int msgcnt;

        if (!strcmp(test_mode, "valgrind") || !strcmp(test_mode, "helgrind") ||
            !strcmp(test_mode, "drd"))
                totsize = 1024 * 1024 * 8; /* 8 meg, valgrind is slow. */

        msgcnt = totsize / msgsize;

        TEST_SAY("Producing %d messages of size %d to %s [%d]\n", msgcnt,
                 (int)msgsize, topic, partition);
        testid = test_id_generate();
        test_conf_init(&conf, NULL, 120);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        test_conf_set(conf, "queue.buffering.max.messages", "10000000");
        test_conf_set(conf, "linger.ms", "100");
        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_producer_topic(rk, topic, "acks", "1", NULL);

        /* First produce one message to create the topic, etc, this might take
         * a while and we dont want this to affect the throughput timing. */
        TIMING_START(&t_create, "CREATE TOPIC");
        test_produce_msgs(rk, rkt, testid, partition, 0, 1, NULL, msgsize);
        TIMING_STOP(&t_create);

        TIMING_START(&t_produce, "PRODUCE");
        test_produce_msgs(rk, rkt, testid, partition, 1, msgcnt - 1, NULL,
                          msgsize);
        TIMING_STOP(&t_produce);

        TEST_SAY("Destroying producer\n");
        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        TEST_SAY("Creating consumer\n");
        test_conf_init(&conf, NULL, 120);
        rk  = test_create_consumer(NULL, NULL, conf, NULL);
        rkt = rd_kafka_topic_new(rk, topic, NULL);

        test_consumer_start("CONSUME", rkt, partition,
                            RD_KAFKA_OFFSET_BEGINNING);
        TIMING_START(&t_consume, "CONSUME");
        test_consume_msgs("CONSUME", rkt, testid, partition, TEST_NO_SEEK, 0,
                          msgcnt, 1);
        TIMING_STOP(&t_consume);
        test_consumer_stop("CONSUME", rkt, partition);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        TEST_REPORT(
            "{ \"producer\": "
            " { \"mb_per_sec\": %.2f, \"records_per_sec\": %.2f },"
            " \"consumer\": "
            "{ \"mb_per_sec\": %.2f, \"records_per_sec\": %.2f } "
            "}",
            (double)(totsize /
                     ((double)TIMING_DURATION(&t_produce) / 1000000.0f)) /
                1000000.0f,
            (float)(msgcnt /
                    ((double)TIMING_DURATION(&t_produce) / 1000000.0f)),
            (double)(totsize /
                     ((double)TIMING_DURATION(&t_consume) / 1000000.0f)) /
                1000000.0f,
            (float)(msgcnt /
                    ((double)TIMING_DURATION(&t_consume) / 1000000.0f)));
        return 0;
}
