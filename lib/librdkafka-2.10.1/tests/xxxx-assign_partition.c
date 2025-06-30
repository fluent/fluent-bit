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

#include "test.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * Consumer partition assignment test, without consumer group balancing.
 */


int main_0016_assign_partition(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_t *rk_p, *rk_c;
        rd_kafka_topic_t *rkt_p;
        int msg_cnt       = 1000;
        int msg_base      = 0;
        int partition_cnt = 2;
        int partition;
        uint64_t testid;
        rd_kafka_topic_conf_t *default_topic_conf;
        rd_kafka_topic_partition_list_t *partitions;
        char errstr[512];

        testid = test_id_generate();

        /* Produce messages */
        rk_p  = test_create_producer();
        rkt_p = test_create_producer_topic(rk_p, topic, NULL);

        for (partition = 0; partition < partition_cnt; partition++) {
                test_produce_msgs(rk_p, rkt_p, testid, partition,
                                  msg_base + (partition * msg_cnt), msg_cnt,
                                  NULL, 0);
        }

        rd_kafka_topic_destroy(rkt_p);
        rd_kafka_destroy(rk_p);


        test_conf_init(NULL, &default_topic_conf, 0);
        if (rd_kafka_topic_conf_set(default_topic_conf, "auto.offset.reset",
                                    "smallest", errstr,
                                    sizeof(errstr)) != RD_KAFKA_CONF_OK)
                TEST_FAIL("%s\n", errstr);

        rk_c =
            test_create_consumer(topic /*group_id*/, NULL, default_topic_conf);

        /* Fill in partition set */
        partitions = rd_kafka_topic_partition_list_new(partition_cnt);

        for (partition = 0; partition < partition_cnt; partition++)
                rd_kafka_topic_partition_list_add(partitions, topic, partition);

        test_consumer_assign("assign.partition", rk_c, partitions);

        /* Make sure all messages are available */
        test_consumer_poll("verify.all", rk_c, testid, partition_cnt, msg_base,
                           partition_cnt * msg_cnt);

        /* Stop assignments */
        test_consumer_unassign("unassign.partitions", rk_c);

#if 0  // FIXME when get_offset() is functional
        /* Acquire stored offsets */
        for (partition = 0 ; partition < partition_cnt ; partition++) {
                rd_kafka_resp_err_t err;
                rd_kafka_topic_t *rkt_c = rd_kafka_topic_new(rk_c, topic, NULL);
                int64_t offset;
                test_timing_t t_offs;

                TIMING_START(&t_offs, "GET.OFFSET");
                err = rd_kafka_consumer_get_offset(rkt_c, partition,
                                                   &offset, 5000);
                TIMING_STOP(&t_offs);
                if (err)
                        TEST_FAIL("Failed to get offsets for %s [%"PRId32"]: "
                                  "%s\n",
                                  rd_kafka_topic_name(rkt_c), partition,
                                  rd_kafka_err2str(err));
                TEST_SAY("get_offset for %s [%"PRId32"] returned %"PRId64"\n",
                         rd_kafka_topic_name(rkt_c), partition, offset);

                rd_kafka_topic_destroy(rkt_c);
        }
#endif
        test_consumer_close(rk_c);

        rd_kafka_destroy(rk_c);

        return 0;
}
