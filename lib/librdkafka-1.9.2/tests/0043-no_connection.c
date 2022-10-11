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
 * Make sure library behaves even if there is no broker connection.
 */



static void test_producer_no_connection(void) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        int i;
        const int partition_cnt = 2;
        int msgcnt              = 0;
        test_timing_t t_destroy;

        test_conf_init(&conf, NULL, 20);

        test_conf_set(conf, "bootstrap.servers", NULL);

        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_topic_object(rk, __FUNCTION__, "message.timeout.ms",
                                       "5000", NULL);

        test_produce_msgs_nowait(rk, rkt, 0, RD_KAFKA_PARTITION_UA, 0, 100,
                                 NULL, 100, 0, &msgcnt);
        for (i = 0; i < partition_cnt; i++)
                test_produce_msgs_nowait(rk, rkt, 0, i, 0, 100, NULL, 100, 0,
                                         &msgcnt);

        rd_kafka_poll(rk, 1000);

        TEST_SAY("%d messages in queue\n", rd_kafka_outq_len(rk));

        rd_kafka_topic_destroy(rkt);

        TIMING_START(&t_destroy, "rd_kafka_destroy()");
        rd_kafka_destroy(rk);
        TIMING_STOP(&t_destroy);
}

int main_0043_no_connection(int argc, char **argv) {
        test_producer_no_connection();

        return 0;
}
