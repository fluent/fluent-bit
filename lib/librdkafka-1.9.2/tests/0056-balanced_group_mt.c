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

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafka.h" /* for Kafka driver */

/**
 * KafkaConsumer balanced group with multithreading tests
 *
 * Runs a consumer subscribing to a topic with multiple partitions and farms
 * consuming of each partition to a separate thread.
 */

#define MAX_THRD_CNT 4

static int assign_cnt        = 0;
static int consumed_msg_cnt  = 0;
static int consumers_running = 0;
static int exp_msg_cnt;

static mtx_t lock;
static thrd_t tids[MAX_THRD_CNT];

typedef struct part_consume_info_s {
        rd_kafka_queue_t *rkqu;
        int partition;
} part_consume_info_t;

static int is_consuming() {
        int result;
        mtx_lock(&lock);
        result = consumers_running;
        mtx_unlock(&lock);
        return result;
}

static int partition_consume(void *args) {
        part_consume_info_t *info = (part_consume_info_t *)args;
        rd_kafka_queue_t *rkqu    = info->rkqu;
        int partition             = info->partition;
        int64_t ts_start          = test_clock();
        int max_time              = (test_session_timeout_ms + 3000) * 1000;
        int running               = 1;

        free(args); /* Free the parameter struct dynamically allocated for us */

        while (ts_start + max_time > test_clock() && running &&
               is_consuming()) {
                rd_kafka_message_t *rkmsg;

                rkmsg = rd_kafka_consume_queue(rkqu, 500);

                if (!rkmsg)
                        continue;
                else if (rkmsg->err == RD_KAFKA_RESP_ERR__PARTITION_EOF)
                        running = 0;
                else if (rkmsg->err) {
                        mtx_lock(&lock);
                        TEST_FAIL(
                            "Message error "
                            "(at offset %" PRId64
                            " after "
                            "%d/%d messages and %dms): %s",
                            rkmsg->offset, consumed_msg_cnt, exp_msg_cnt,
                            (int)(test_clock() - ts_start) / 1000,
                            rd_kafka_message_errstr(rkmsg));
                        mtx_unlock(&lock);
                } else {
                        if (rkmsg->partition != partition) {
                                mtx_lock(&lock);
                                TEST_FAIL(
                                    "Message consumed has partition %d "
                                    "but we expected partition %d.",
                                    rkmsg->partition, partition);
                                mtx_unlock(&lock);
                        }
                }
                rd_kafka_message_destroy(rkmsg);

                mtx_lock(&lock);
                if (running && ++consumed_msg_cnt >= exp_msg_cnt) {
                        TEST_SAY("All messages consumed\n");
                        running = 0;
                }
                mtx_unlock(&lock);
        }

        rd_kafka_queue_destroy(rkqu);

        return thrd_success;
}

static thrd_t spawn_thread(rd_kafka_queue_t *rkqu, int partition) {
        thrd_t thr;
        part_consume_info_t *info = malloc(sizeof(part_consume_info_t));

        info->rkqu      = rkqu;
        info->partition = partition;

        if (thrd_create(&thr, &partition_consume, info) != thrd_success) {
                TEST_FAIL("Failed to create consumer thread.");
        }
        return thr;
}

static int rebalanced = 0;

static void rebalance_cb(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *partitions,
                         void *opaque) {
        int i;
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
                mtx_lock(&lock);
                consumers_running = 1;
                mtx_unlock(&lock);

                for (i = 0; i < partitions->cnt && i < MAX_THRD_CNT; ++i) {
                        rd_kafka_topic_partition_t part = partitions->elems[i];
                        rd_kafka_queue_t *rkqu;
                        /* This queue is loosed in partition-consume. */
                        rkqu = rd_kafka_queue_get_partition(rk, part.topic,
                                                            part.partition);

                        rd_kafka_queue_forward(rkqu, NULL);
                        tids[part.partition] =
                            spawn_thread(rkqu, part.partition);
                }

                rebalanced = 1;

                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                if (assign_cnt == 0)
                        TEST_FAIL("asymetric rebalance_cb");
                assign_cnt--;
                rd_kafka_assign(rk, NULL);
                mtx_lock(&lock);
                consumers_running = 0;
                mtx_unlock(&lock);

                break;

        default:
                TEST_FAIL("rebalance failed: %s", rd_kafka_err2str(err));
                break;
        }
}

static void get_assignment(rd_kafka_t *rk_c) {
        while (!rebalanced) {
                rd_kafka_message_t *rkmsg;
                rkmsg = rd_kafka_consumer_poll(rk_c, 500);
                if (rkmsg)
                        rd_kafka_message_destroy(rkmsg);
        }
}

int main_0056_balanced_group_mt(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_t *rk_p, *rk_c;
        rd_kafka_topic_t *rkt_p;
        int msg_cnt       = test_quick ? 100 : 1000;
        int msg_base      = 0;
        int partition_cnt = 2;
        int partition;
        uint64_t testid;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_conf_t *default_topic_conf;
        rd_kafka_topic_partition_list_t *sub, *topics;
        rd_kafka_resp_err_t err;
        test_timing_t t_assign, t_close, t_consume;
        int i;

        exp_msg_cnt = msg_cnt * partition_cnt;

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

        if (mtx_init(&lock, mtx_plain) != thrd_success)
                TEST_FAIL("Cannot create mutex.");

        test_conf_init(&conf, &default_topic_conf,
                       (test_session_timeout_ms * 3) / 1000);

        test_conf_set(conf, "enable.partition.eof", "true");

        test_topic_conf_set(default_topic_conf, "auto.offset.reset",
                            "smallest");

        /* Fill in topic subscription set */
        topics = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(topics, topic, RD_KAFKA_PARTITION_UA);

        /* Create consumers and start subscription */
        rk_c = test_create_consumer(topic /*group_id*/, rebalance_cb, conf,
                                    default_topic_conf);

        test_consumer_subscribe(rk_c, topic);

        rd_kafka_topic_partition_list_destroy(topics);

        /* Wait for both consumers to get an assignment */
        TIMING_START(&t_assign, "WAIT.ASSIGN");
        get_assignment(rk_c);
        TIMING_STOP(&t_assign);

        TIMING_START(&t_consume, "CONSUME.WAIT");
        for (i = 0; i < MAX_THRD_CNT; ++i) {
                int res;
                if (tids[i] != 0)
                        thrd_join(tids[i], &res);
        }
        TIMING_STOP(&t_consume);

        TEST_SAY("Closing remaining consumers\n");
        /* Query subscription */
        err = rd_kafka_subscription(rk_c, &sub);
        TEST_ASSERT(!err, "%s: subscription () failed: %s", rd_kafka_name(rk_c),
                    rd_kafka_err2str(err));
        TEST_SAY("%s: subscription (%d):\n", rd_kafka_name(rk_c), sub->cnt);
        for (i = 0; i < sub->cnt; ++i)
                TEST_SAY(" %s\n", sub->elems[i].topic);
        rd_kafka_topic_partition_list_destroy(sub);

        /* Run an explicit unsubscribe () (async) prior to close ()
         * to trigger race condition issues on termination. */
        TEST_SAY("Unsubscribing instance %s\n", rd_kafka_name(rk_c));
        err = rd_kafka_unsubscribe(rk_c);
        TEST_ASSERT(!err, "%s: unsubscribe failed: %s", rd_kafka_name(rk_c),
                    rd_kafka_err2str(err));

        TEST_SAY("Closing %s\n", rd_kafka_name(rk_c));
        TIMING_START(&t_close, "CONSUMER.CLOSE");
        err = rd_kafka_consumer_close(rk_c);
        TIMING_STOP(&t_close);
        TEST_ASSERT(!err, "consumer_close failed: %s", rd_kafka_err2str(err));

        rd_kafka_destroy(rk_c);
        rk_c = NULL;

        TEST_SAY("%d/%d messages consumed\n", consumed_msg_cnt, exp_msg_cnt);
        TEST_ASSERT(consumed_msg_cnt >= exp_msg_cnt,
                    "Only %d/%d messages were consumed", consumed_msg_cnt,
                    exp_msg_cnt);

        if (consumed_msg_cnt > exp_msg_cnt)
                TEST_SAY(
                    "At least %d/%d messages were consumed "
                    "multiple times\n",
                    consumed_msg_cnt - exp_msg_cnt, exp_msg_cnt);

        mtx_destroy(&lock);

        return 0;
}
