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
 * Verify that long-processing consumer does not leave the group during
 * processing when processing time < max.poll.interval.ms but
 * max.poll.interval.ms > socket.timeout.ms.
 *
 * MO:
 *  - produce N*.. messages to two partitions
 *  - create two consumers, c0 and c1.
 *  - subscribe c0, wait for rebalance, poll first message.
 *  - subscribe c1
 *  - have both consumers poll messages and spend T seconds processing
 *    each message.
 *  - wait until both consumers have received N messages each.
 *  - check that no errors (disconnects, etc) or extra rebalances were raised.
 */


const int64_t processing_time = 31 * 1000 * 1000; /*31s*/

struct _consumer {
        rd_kafka_t *rk;
        int64_t last;
        int cnt;
        int rebalance_cnt;
        int max_rebalance_cnt;
};

static void do_consume(struct _consumer *cons, int timeout_s) {
        rd_kafka_message_t *rkm;

        rkm = rd_kafka_consumer_poll(cons->rk, timeout_s * 1000);
        if (!rkm)
                return;

        TEST_ASSERT(!rkm->err, "%s consumer error: %s (last poll was %dms ago)",
                    rd_kafka_name(cons->rk), rd_kafka_message_errstr(rkm),
                    (int)((test_clock() - cons->last) / 1000));

        TEST_SAY(
            "%s: processing message #%d from "
            "partition %" PRId32 " at offset %" PRId64 "\n",
            rd_kafka_name(cons->rk), cons->cnt, rkm->partition, rkm->offset);

        rd_kafka_message_destroy(rkm);

        cons->cnt++;
        cons->last = test_clock();

        TEST_SAY("%s: simulate processing by sleeping for %ds\n",
                 rd_kafka_name(cons->rk), timeout_s);
        rd_sleep(timeout_s);
}


static void rebalance_cb(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *parts,
                         void *opaque) {
        struct _consumer *cons = opaque;

        cons->rebalance_cnt++;

        TEST_SAY(_C_BLU "%s rebalance #%d/%d: %s: %d partition(s)\n",
                 rd_kafka_name(cons->rk), cons->rebalance_cnt,
                 cons->max_rebalance_cnt, rd_kafka_err2name(err), parts->cnt);

        TEST_ASSERT(cons->rebalance_cnt <= cons->max_rebalance_cnt,
                    "%s rebalanced %d times, max was %d",
                    rd_kafka_name(cons->rk), cons->rebalance_cnt,
                    cons->max_rebalance_cnt);

        if (err == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS)
                rd_kafka_assign(rk, parts);
        else
                rd_kafka_assign(rk, NULL);
}


#define _CONSUMER_CNT 2
static void do_test_with_subscribe(const char *topic) {
        int64_t testid;
        const int msgcnt                  = 3;
        struct _consumer c[_CONSUMER_CNT] = RD_ZERO_INIT;
        rd_kafka_conf_t *conf;

        TEST_SAY(_C_MAG "[ Test max.poll.interval.ms with subscribe() ]\n");

        testid = test_id_generate();

        test_conf_init(&conf, NULL,
                       10 + (int)(processing_time / 1000000) * msgcnt);

        /* Produce extra messages since we can't fully rely on the
         * random partitioner to provide exact distribution. */
        test_produce_msgs_easy(topic, testid, -1, msgcnt * _CONSUMER_CNT * 2);
        test_produce_msgs_easy(topic, testid, 1, msgcnt / 2);

        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "max.poll.interval.ms", "20000" /*20s*/);
        test_conf_set(conf, "socket.timeout.ms", "15000" /*15s*/);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.partition.eof", "false");
        /* Trigger other requests often */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "1000");
        rd_kafka_conf_set_rebalance_cb(conf, rebalance_cb);

        rd_kafka_conf_set_opaque(conf, &c[0]);
        c[0].rk =
            test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);

        rd_kafka_conf_set_opaque(conf, &c[1]);
        c[1].rk = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(c[0].rk, topic);

        /* c0: assign, (c1 joins) revoke, assign */
        c[0].max_rebalance_cnt = 3;
        /* c1: assign */
        c[1].max_rebalance_cnt = 1;

        /* Wait for assignment */
        while (1) {
                rd_kafka_topic_partition_list_t *parts = NULL;

                do_consume(&c[0], 1 /*1s*/);

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

        test_consumer_subscribe(c[1].rk, topic);

        /* Poll until both consumers have finished reading N messages */
        while (c[0].cnt < msgcnt && c[1].cnt < msgcnt) {
                do_consume(&c[0], 0);
                do_consume(&c[1], 10 /*10s*/);
        }

        /* Allow the extra revoke rebalance on close() */
        c[0].max_rebalance_cnt++;
        c[1].max_rebalance_cnt++;

        test_consumer_close(c[0].rk);
        test_consumer_close(c[1].rk);

        rd_kafka_destroy(c[0].rk);
        rd_kafka_destroy(c[1].rk);

        TEST_SAY(_C_GRN
                 "[ Test max.poll.interval.ms with subscribe(): PASS ]\n");
}


/**
 * @brief Verify that max.poll.interval.ms does NOT kick in
 *        when just using assign() and not subscribe().
 */
static void do_test_with_assign(const char *topic) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_message_t *rkm;

        TEST_SAY(_C_MAG "[ Test max.poll.interval.ms with assign() ]\n");

        test_conf_init(&conf, NULL, 60);

        test_create_topic(NULL, topic, 2, 1);

        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "max.poll.interval.ms", "7000" /*7s*/);

        rk = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_assign_partition("ASSIGN", rk, topic, 0,
                                       RD_KAFKA_OFFSET_END);


        /* Sleep for longer than max.poll.interval.ms */
        rd_sleep(10);

        /* Make sure no error was raised */
        while ((rkm = rd_kafka_consumer_poll(rk, 0))) {
                TEST_ASSERT(!rkm->err, "Unexpected consumer error: %s: %s",
                            rd_kafka_err2name(rkm->err),
                            rd_kafka_message_errstr(rkm));

                rd_kafka_message_destroy(rkm);
        }


        test_consumer_close(rk);
        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN "[ Test max.poll.interval.ms with assign(): PASS ]\n");
}


/**
 * @brief Verify that max.poll.interval.ms kicks in even if
 *        the application hasn't called poll once.
 */
static void do_test_no_poll(const char *topic) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_message_t *rkm;
        rd_bool_t raised = rd_false;

        TEST_SAY(_C_MAG "[ Test max.poll.interval.ms without calling poll ]\n");

        test_conf_init(&conf, NULL, 60);

        test_create_topic(NULL, topic, 2, 1);

        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "max.poll.interval.ms", "7000" /*7s*/);

        rk = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(rk, topic);

        /* Sleep for longer than max.poll.interval.ms */
        rd_sleep(10);

        /* Make sure the error is raised */
        while ((rkm = rd_kafka_consumer_poll(rk, 0))) {
                if (rkm->err == RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED)
                        raised = rd_true;

                rd_kafka_message_destroy(rkm);
        }

        TEST_ASSERT(raised, "Expected to have seen ERR__MAX_POLL_EXCEEDED");

        test_consumer_close(rk);
        rd_kafka_destroy(rk);

        TEST_SAY(_C_GRN
                 "[ Test max.poll.interval.ms without calling poll: PASS ]\n");
}


int main_0091_max_poll_interval_timeout(int argc, char **argv) {
        const char *topic =
            test_mk_topic_name("0091_max_poll_interval_tmout", 1);

        test_create_topic(NULL, topic, 2, 1);

        do_test_with_subscribe(topic);

        do_test_with_assign(topic);

        do_test_no_poll(topic);

        return 0;
}
