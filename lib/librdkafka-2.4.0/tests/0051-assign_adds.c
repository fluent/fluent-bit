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
#include "rdkafka.h"

#include <stdarg.h>

/**
 * Verify that quick assignment additions work.
 *  * Create topics T1,T2,T3
 *  * Create consumer
 *  * Assign T1
 *  * Assign T1,T2
 *  * Assign T1,T2,T3
 *  * Verify that all messages from all three topics are consumed
 *  * Assign T1,T3
 *  * Verify that there were no duplicate messages.
 */

int main_0051_assign_adds(int argc, char **argv) {
        rd_kafka_t *rk;
#define TOPIC_CNT 3
        char *topic[TOPIC_CNT] = {
            rd_strdup(test_mk_topic_name("0051_assign_adds_1", 1)),
            rd_strdup(test_mk_topic_name("0051_assign_adds_2", 1)),
            rd_strdup(test_mk_topic_name("0051_assign_adds_3", 1)),
        };
        uint64_t testid;
        int msgcnt = test_quick ? 100 : 1000;
        test_msgver_t mv;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *tconf;
        int i;
        rd_kafka_topic_partition_list_t *tlist;
        rd_kafka_resp_err_t err;

        msgcnt = (msgcnt / TOPIC_CNT) * TOPIC_CNT;
        testid = test_id_generate();

        rk = test_create_producer();
        for (i = 0; i < TOPIC_CNT; i++) {
                rd_kafka_topic_t *rkt;

                rkt = test_create_producer_topic(rk, topic[i], NULL);

                test_produce_msgs(rk, rkt, testid, 0, (msgcnt / TOPIC_CNT) * i,
                                  (msgcnt / TOPIC_CNT), NULL, 100);

                rd_kafka_topic_destroy(rkt);
        }

        rd_kafka_destroy(rk);

        test_conf_init(&conf, &tconf, 60);
        test_topic_conf_set(tconf, "auto.offset.reset", "smallest");

        rk = test_create_consumer(topic[0], NULL, conf, tconf);

        tlist = rd_kafka_topic_partition_list_new(TOPIC_CNT);
        for (i = 0; i < TOPIC_CNT; i++) {
                rd_kafka_topic_partition_list_add(tlist, topic[i], 0);
                TEST_SAY("Assign %d topic(s):\n", tlist->cnt);
                test_print_partition_list(tlist);

                err = rd_kafka_assign(rk, tlist);
                TEST_ASSERT(!err, "assign() failed: %s", rd_kafka_err2str(err));
        }

        test_msgver_init(&mv, testid);

        TEST_SAY("Expecting to consume all %d messages from %d topics\n",
                 msgcnt, TOPIC_CNT);

        test_consumer_poll("consume", rk, testid, -1, 0, msgcnt, &mv);

        /* Now remove T2 */
        rd_kafka_topic_partition_list_del(tlist, topic[1], 0);
        err = rd_kafka_assign(rk, tlist);
        TEST_ASSERT(!err, "assign() failed: %s", rd_kafka_err2str(err));

        TEST_SAY(
            "Should not see any messages for session.timeout.ms+some more\n");
        test_consumer_poll_no_msgs("consume", rk, testid, (int)(6000 * 1.5));

        test_msgver_verify("consume", &mv, TEST_MSGVER_ORDER | TEST_MSGVER_DUP,
                           0, msgcnt);

        test_msgver_clear(&mv);

        rd_kafka_topic_partition_list_destroy(tlist);

        test_consumer_close(rk);
        rd_kafka_destroy(rk);

        for (i = 0; i < TOPIC_CNT; i++)
                rd_free(topic[i]);

        return 0;
}
