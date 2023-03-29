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
#include "rdstring.h"

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */


/**
 * KafkaConsumer balanced group testing: termination
 *
 * Runs two consumers subscribing to the same topics, waits for both to
 * get an assignment and then closes one of them.
 */


static int assign_cnt       = 0;
static int consumed_msg_cnt = 0;


static void rebalance_cb(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *partitions,
                         void *opaque) {
        char *memberid = rd_kafka_memberid(rk);

        TEST_SAY("%s: MemberId \"%s\": Consumer group rebalanced: %s\n",
                 rd_kafka_name(rk), memberid, rd_kafka_err2str(err));

        if (memberid)
                free(memberid);

        test_print_partition_list(partitions);

        switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                assign_cnt++;
                rd_kafka_assign(rk, partitions);
                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                if (assign_cnt == 0)
                        TEST_FAIL("asymetric rebalance_cb\n");
                assign_cnt--;
                rd_kafka_assign(rk, NULL);
                break;

        default:
                TEST_FAIL("rebalance failed: %s\n", rd_kafka_err2str(err));
                break;
        }
}


static void consume_all(rd_kafka_t **rk_c,
                        int rk_cnt,
                        int exp_msg_cnt,
                        int max_time /*ms*/) {
        int64_t ts_start = test_clock();
        int i;

        max_time *= 1000;
        while (ts_start + max_time > test_clock()) {
                for (i = 0; i < rk_cnt; i++) {
                        rd_kafka_message_t *rkmsg;

                        if (!rk_c[i])
                                continue;

                        rkmsg = rd_kafka_consumer_poll(rk_c[i], 500);

                        if (!rkmsg)
                                continue;
                        else if (rkmsg->err)
                                TEST_SAY(
                                    "Message error "
                                    "(at offset %" PRId64
                                    " after "
                                    "%d/%d messages and %dms): %s\n",
                                    rkmsg->offset, consumed_msg_cnt,
                                    exp_msg_cnt,
                                    (int)(test_clock() - ts_start) / 1000,
                                    rd_kafka_message_errstr(rkmsg));
                        else
                                consumed_msg_cnt++;

                        rd_kafka_message_destroy(rkmsg);

                        if (consumed_msg_cnt >= exp_msg_cnt) {
                                static int once = 0;
                                if (!once++)
                                        TEST_SAY("All messages consumed\n");
                                return;
                        }
                }
        }
}

struct args {
        rd_kafka_t *c;
        rd_kafka_queue_t *queue;
};

static int poller_thread_main(void *p) {
        struct args *args = (struct args *)p;

        while (!rd_kafka_consumer_closed(args->c)) {
                rd_kafka_message_t *rkm;

                /* Using a long timeout (1 minute) to verify that the
                 * queue is woken when close is done. */
                rkm = rd_kafka_consume_queue(args->queue, 60 * 1000);
                if (rkm)
                        rd_kafka_message_destroy(rkm);
        }

        return 0;
}

/**
 * @brief Close consumer using async queue.
 */
static void consumer_close_queue(rd_kafka_t *c) {
        /* Use the standard consumer queue rather than a temporary queue,
         * the latter is covered by test 0116. */
        rd_kafka_queue_t *queue = rd_kafka_queue_get_consumer(c);
        struct args args        = {c, queue};
        thrd_t thrd;
        int ret;

        /* Spin up poller thread */
        if (thrd_create(&thrd, poller_thread_main, (void *)&args) !=
            thrd_success)
                TEST_FAIL("Failed to create thread");

        TEST_SAY("Closing consumer %s using queue\n", rd_kafka_name(c));
        TEST_CALL_ERROR__(rd_kafka_consumer_close_queue(c, queue));

        if (thrd_join(thrd, &ret) != thrd_success)
                TEST_FAIL("thrd_join failed");

        rd_kafka_queue_destroy(queue);
}


static void do_test(rd_bool_t with_queue) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
#define _CONS_CNT 2
        rd_kafka_t *rk_p, *rk_c[_CONS_CNT];
        rd_kafka_topic_t *rkt_p;
        int msg_cnt       = test_quick ? 100 : 1000;
        int msg_base      = 0;
        int partition_cnt = 2;
        int partition;
        uint64_t testid;
        rd_kafka_topic_conf_t *default_topic_conf;
        rd_kafka_topic_partition_list_t *topics;
        rd_kafka_resp_err_t err;
        test_timing_t t_assign, t_consume;
        char errstr[512];
        int i;

        SUB_TEST("with_queue=%s", RD_STR_ToF(with_queue));

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


        test_conf_init(NULL, &default_topic_conf,
                       5 + ((test_session_timeout_ms * 3) / 1000));
        if (rd_kafka_topic_conf_set(default_topic_conf, "auto.offset.reset",
                                    "smallest", errstr,
                                    sizeof(errstr)) != RD_KAFKA_CONF_OK)
                TEST_FAIL("%s\n", errstr);

        /* Fill in topic subscription set */
        topics = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(topics, topic, -1);

        /* Create consumers and start subscription */
        for (i = 0; i < _CONS_CNT; i++) {
                rk_c[i] = test_create_consumer(
                    topic /*group_id*/, rebalance_cb, NULL,
                    rd_kafka_topic_conf_dup(default_topic_conf));

                err = rd_kafka_poll_set_consumer(rk_c[i]);
                if (err)
                        TEST_FAIL("poll_set_consumer: %s\n",
                                  rd_kafka_err2str(err));

                err = rd_kafka_subscribe(rk_c[i], topics);
                if (err)
                        TEST_FAIL("subscribe: %s\n", rd_kafka_err2str(err));
        }

        rd_kafka_topic_conf_destroy(default_topic_conf);

        rd_kafka_topic_partition_list_destroy(topics);


        /* Wait for both consumers to get an assignment */
        TEST_SAY("Awaiting assignments for %d consumer(s)\n", _CONS_CNT);
        TIMING_START(&t_assign, "WAIT.ASSIGN");
        while (assign_cnt < _CONS_CNT)
                consume_all(rk_c, _CONS_CNT, msg_cnt,
                            test_session_timeout_ms + 3000);
        TIMING_STOP(&t_assign);

        /* Now close one of the consumers, this will cause a rebalance. */
        TEST_SAY("Closing down 1/%d consumer(s): %s\n", _CONS_CNT,
                 rd_kafka_name(rk_c[0]));
        if (with_queue)
                consumer_close_queue(rk_c[0]);
        else
                TEST_CALL_ERR__(rd_kafka_consumer_close(rk_c[0]));

        rd_kafka_destroy(rk_c[0]);
        rk_c[0] = NULL;

        /* Let remaining consumers run for a while to take over the now
         * lost partitions. */

        if (assign_cnt != _CONS_CNT - 1)
                TEST_FAIL("assign_cnt %d, should be %d\n", assign_cnt,
                          _CONS_CNT - 1);

        TIMING_START(&t_consume, "CONSUME.WAIT");
        consume_all(rk_c, _CONS_CNT, msg_cnt, test_session_timeout_ms + 3000);
        TIMING_STOP(&t_consume);

        TEST_SAY("Closing remaining consumers\n");
        for (i = 0; i < _CONS_CNT; i++) {
                test_timing_t t_close;
                rd_kafka_topic_partition_list_t *sub;
                int j;

                if (!rk_c[i])
                        continue;

                /* Query subscription */
                err = rd_kafka_subscription(rk_c[i], &sub);
                if (err)
                        TEST_FAIL("%s: subscription() failed: %s\n",
                                  rd_kafka_name(rk_c[i]),
                                  rd_kafka_err2str(err));
                TEST_SAY("%s: subscription (%d):\n", rd_kafka_name(rk_c[i]),
                         sub->cnt);
                for (j = 0; j < sub->cnt; j++)
                        TEST_SAY(" %s\n", sub->elems[j].topic);
                rd_kafka_topic_partition_list_destroy(sub);

                /* Run an explicit unsubscribe() (async) prior to close()
                 * to trigger race condition issues on termination. */
                TEST_SAY("Unsubscribing instance %s\n", rd_kafka_name(rk_c[i]));
                err = rd_kafka_unsubscribe(rk_c[i]);
                if (err)
                        TEST_FAIL("%s: unsubscribe failed: %s\n",
                                  rd_kafka_name(rk_c[i]),
                                  rd_kafka_err2str(err));

                TEST_SAY("Closing %s\n", rd_kafka_name(rk_c[i]));
                TIMING_START(&t_close, "CONSUMER.CLOSE");
                if (with_queue)
                        consumer_close_queue(rk_c[i]);
                else
                        TEST_CALL_ERR__(rd_kafka_consumer_close(rk_c[i]));
                TIMING_STOP(&t_close);

                rd_kafka_destroy(rk_c[i]);
                rk_c[i] = NULL;
        }

        TEST_SAY("%d/%d messages consumed\n", consumed_msg_cnt, msg_cnt);
        if (consumed_msg_cnt < msg_cnt)
                TEST_FAIL("Only %d/%d messages were consumed\n",
                          consumed_msg_cnt, msg_cnt);
        else if (consumed_msg_cnt > msg_cnt)
                TEST_SAY(
                    "At least %d/%d messages were consumed "
                    "multiple times\n",
                    consumed_msg_cnt - msg_cnt, msg_cnt);

        SUB_TEST_PASS();
}


int main_0018_cgrp_term(int argc, char **argv) {
        do_test(rd_false /* rd_kafka_consumer_close() */);
        do_test(rd_true /*  rd_kafka_consumer_close_queue() */);

        return 0;
}
