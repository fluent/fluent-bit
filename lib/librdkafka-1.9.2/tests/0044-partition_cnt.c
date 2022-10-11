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
 * Make sure library behaves when the partition count for a topic changes.
 * This test requires to be run under trivup to be able to use kafka-topics.sh
 */



/**
 * - Create topic with 2 partitions
 * - Start producing messages to UA partition
 * - Change to 4 partitions
 * - Produce more messages to UA partition
 * - Wait for DRs
 * - Close
 */

static void test_producer_partition_cnt_change(void) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        const char *topic       = test_mk_topic_name(__FUNCTION__, 1);
        const int partition_cnt = 4;
        int msgcnt              = test_quick ? 500 : 100000;
        test_timing_t t_destroy;
        int produced = 0;

        test_conf_init(&conf, NULL, 20);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        test_create_topic(rk, topic, partition_cnt / 2, 1);

        rkt =
            test_create_topic_object(rk, __FUNCTION__, "message.timeout.ms",
                                     tsprintf("%d", tmout_multip(10000)), NULL);

        test_produce_msgs_nowait(rk, rkt, 0, RD_KAFKA_PARTITION_UA, 0,
                                 msgcnt / 2, NULL, 100, 0, &produced);

        test_create_partitions(rk, topic, partition_cnt);

        test_produce_msgs_nowait(rk, rkt, 0, RD_KAFKA_PARTITION_UA, msgcnt / 2,
                                 msgcnt / 2, NULL, 100, 0, &produced);

        test_wait_delivery(rk, &produced);

        rd_kafka_topic_destroy(rkt);

        TIMING_START(&t_destroy, "rd_kafka_destroy()");
        rd_kafka_destroy(rk);
        TIMING_STOP(&t_destroy);
}

int main_0044_partition_cnt(int argc, char **argv) {
        if (!test_can_create_topics(1))
                return 0;

        test_producer_partition_cnt_change();

        return 0;
}
