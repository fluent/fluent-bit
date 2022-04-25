/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2018, Magnus Edenhill
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
 * @brief Attempt to verify head-of-line-blocking behaviour.
 *
 * - Create two high-level consumers with socket.timeout.ms=low,
 *   and max.poll.interval.ms=high, metadata refresh interval=low.
 * - Have first consumer join the group (subscribe()), should finish quickly.
 * - Have second consumer join the group, but don't call poll on
 *   the first consumer for some time to have the second consumer
 *   block on JoinGroup.
 * - Verify that errors were raised due to timed out (Metadata) requests.
 */

struct _consumer {
        rd_kafka_t *rk;
        int64_t last;
        int cnt;
        int rebalance_cnt;
        int max_rebalance_cnt;
};

static void do_consume (struct _consumer *cons, int timeout_s) {
        rd_kafka_message_t *rkm;

        rkm = rd_kafka_consumer_poll(cons->rk, 100+(timeout_s*1000));
        if (!rkm)
                return;

        TEST_ASSERT(!rkm->err,
                    "%s consumer error: %s (last poll was %dms ago)",
                    rd_kafka_name(cons->rk),
                    rd_kafka_message_errstr(rkm),
                    (int)((test_clock() - cons->last)/1000));

        rd_kafka_message_destroy(rkm);

        cons->cnt++;
        cons->last = test_clock();

        if (timeout_s > 0) {
                TEST_SAY("%s: simulate processing by sleeping for %ds\n",
                         rd_kafka_name(cons->rk), timeout_s);
                rd_sleep(timeout_s);
        }
}


static void rebalance_cb (rd_kafka_t *rk,
                          rd_kafka_resp_err_t err,
                          rd_kafka_topic_partition_list_t *parts,
                          void *opaque) {
        struct _consumer *cons = opaque;

        cons->rebalance_cnt++;

        TEST_SAY(_C_BLU "%s rebalance #%d/%d: %s: %d partition(s)\n",
                 rd_kafka_name(cons->rk),
                 cons->rebalance_cnt, cons->max_rebalance_cnt,
                 rd_kafka_err2name(err),
                 parts->cnt);

        TEST_ASSERT(cons->rebalance_cnt <= cons->max_rebalance_cnt,
                    "%s rebalanced %d times, max was %d",
                    rd_kafka_name(cons->rk),
                    cons->rebalance_cnt, cons->max_rebalance_cnt);

        if (err == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS)
                rd_kafka_assign(rk, parts);
        else
                rd_kafka_assign(rk, NULL);
}


#define _CONSUMER_CNT 2
int main_0093_holb_consumer (int argc, char **argv) {
        const char *topic = test_mk_topic_name("0093_holb_consumer", 1);
        int64_t testid;
        const int msgcnt = 100;
        struct _consumer c[_CONSUMER_CNT] = RD_ZERO_INIT;
        rd_kafka_conf_t *conf;

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 60);

        test_create_topic(NULL, topic, 1, 1);

        test_produce_msgs_easy(topic, testid, 0, msgcnt);

        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "max.poll.interval.ms", "20000");
        test_conf_set(conf, "socket.timeout.ms", "3000");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        /* Trigger other requests often */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "500");
        rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);

        rd_kafka_conf_set_opaque(conf, &c[0]);
        c[0].rk = test_create_consumer(topic, NULL,
                                       rd_kafka_conf_dup(conf), NULL);

        rd_kafka_conf_set_opaque(conf, &c[1]);
        c[1].rk = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(c[0].rk, topic);

        /* c0: assign */
        c[0].max_rebalance_cnt = 1;

        /* c1: none, hasn't joined yet */
        c[1].max_rebalance_cnt = 0;

        TEST_SAY("Waiting for c[0] assignment\n");
        while (1) {
                rd_kafka_topic_partition_list_t *parts = NULL;

                do_consume(&c[0], 1/*1s*/);

                if (rd_kafka_assignment(c[0].rk, &parts) !=
                    RD_KAFKA_RESP_ERR_NO_ERROR ||
                    !parts || parts->cnt == 0) {
                        if (parts)
                                rd_kafka_topic_partition_list_destroy(parts);
                        continue;
                }

                TEST_SAY("%s got assignment of %d partition(s)\n",
                         rd_kafka_name(c[0].rk), parts->cnt);
                rd_kafka_topic_partition_list_destroy(parts);
                break;
        }

        TEST_SAY("c[0] got assignment, consuming..\n");
        do_consume(&c[0], 5/*5s*/);

        TEST_SAY("Joining second consumer\n");
        test_consumer_subscribe(c[1].rk, topic);

        /* Just poll second consumer for 10s, the rebalance will not
         * finish until the first consumer polls */
        do_consume(&c[1], 10/*10s*/);

        /* c0: the next call to do_consume/poll will trigger
         *     its rebalance callback, first revoke then assign. */
        c[0].max_rebalance_cnt += 2;
        /* c1: first rebalance */
        c[1].max_rebalance_cnt++;

        TEST_SAY("Expected rebalances: c[0]: %d/%d, c[1]: %d/%d\n",
                 c[0].rebalance_cnt, c[0].max_rebalance_cnt,
                 c[1].rebalance_cnt, c[1].max_rebalance_cnt);

        /* Let rebalances kick in, then consume messages. */
        while (c[0].cnt + c[1].cnt < msgcnt) {
                do_consume(&c[0], 0);
                do_consume(&c[1], 0);
        }

        /* Allow the extra revoke rebalance on close() */
        c[0].max_rebalance_cnt++;
        c[1].max_rebalance_cnt++;

        test_consumer_close(c[0].rk);
        test_consumer_close(c[1].rk);

        rd_kafka_destroy(c[0].rk);
        rd_kafka_destroy(c[1].rk);

        return 0;
}
