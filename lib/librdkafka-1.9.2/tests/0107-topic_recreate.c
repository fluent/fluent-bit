/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020, Magnus Edenhill
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

#include "../src/rdkafka_proto.h"


/**
 * @name Verify that producer and consumer resumes operation after
 *       a topic has been deleted and recreated.
 */

/**
 * The message value to produce, one of:
 *   "before"  - before topic deletion
 *   "during"  - during topic deletion
 *   "after"   - after topic has been re-created
 *   "end"     - stop producing
 */
static mtx_t value_mtx;
static char *value;

static const int msg_rate = 10; /**< Messages produced per second */

static struct test *this_test; /**< Exposes current test struct (in TLS) to
                                *   producer thread. */


/**
 * @brief Treat all error_cb as non-test-fatal.
 */
static int
is_error_fatal(rd_kafka_t *rk, rd_kafka_resp_err_t err, const char *reason) {
        return rd_false;
}

/**
 * @brief Producing thread
 */
static int run_producer(void *arg) {
        const char *topic    = arg;
        rd_kafka_t *producer = test_create_producer();
        int ret              = 0;

        test_curr = this_test;

        /* Don't check message status */
        test_curr->exp_dr_status = (rd_kafka_msg_status_t)-1;

        while (1) {
                rd_kafka_resp_err_t err;

                mtx_lock(&value_mtx);
                if (!strcmp(value, "end")) {
                        mtx_unlock(&value_mtx);
                        break;
                } else if (strcmp(value, "before")) {
                        /* Ignore Delivery report errors after topic
                         * has been deleted and eventually re-created,
                         * we rely on the consumer to verify that
                         * messages are produced. */
                        test_curr->ignore_dr_err = rd_true;
                }

                err = rd_kafka_producev(
                    producer, RD_KAFKA_V_TOPIC(topic),
                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                    RD_KAFKA_V_VALUE(value, strlen(value)), RD_KAFKA_V_END);

                if (err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART ||
                    err == RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
                        TEST_SAY("Produce failed (expectedly): %s\n",
                                 rd_kafka_err2name(err));
                else
                        TEST_ASSERT(!err, "producev() failed: %s",
                                    rd_kafka_err2name(err));

                mtx_unlock(&value_mtx);

                rd_usleep(1000000 / msg_rate, NULL);

                rd_kafka_poll(producer, 0);
        }

        if (rd_kafka_flush(producer, 5000)) {
                TEST_WARN("Failed to flush all message(s), %d remain\n",
                          rd_kafka_outq_len(producer));
                /* Purge the messages to see which partition they were for */
                rd_kafka_purge(producer, RD_KAFKA_PURGE_F_QUEUE |
                                             RD_KAFKA_PURGE_F_INFLIGHT);
                rd_kafka_flush(producer, 5000);
                TEST_SAY("%d message(s) in queue after purge\n",
                         rd_kafka_outq_len(producer));

                ret = 1; /* Fail test from main thread */
        }

        rd_kafka_destroy(producer);

        return ret;
}


/**
 * @brief Expect at least \p cnt messages with value matching \p exp_value,
 *        else fail the current test.
 */
static void
expect_messages(rd_kafka_t *consumer, int cnt, const char *exp_value) {
        int match_cnt = 0, other_cnt = 0, err_cnt = 0;
        size_t exp_len = strlen(exp_value);

        TEST_SAY("Expecting >= %d messages with value \"%s\"...\n", cnt,
                 exp_value);

        while (match_cnt < cnt) {
                rd_kafka_message_t *rkmessage;

                rkmessage = rd_kafka_consumer_poll(consumer, 1000);
                if (!rkmessage)
                        continue;

                if (rkmessage->err) {
                        TEST_SAY("Consume error: %s\n",
                                 rd_kafka_message_errstr(rkmessage));
                        err_cnt++;
                } else if (rkmessage->len == exp_len &&
                           !memcmp(rkmessage->payload, exp_value, exp_len)) {
                        match_cnt++;
                } else {
                        TEST_SAYL(3,
                                  "Received \"%.*s\", expected \"%s\": "
                                  "ignored\n",
                                  (int)rkmessage->len,
                                  (const char *)rkmessage->payload, exp_value);
                        other_cnt++;
                }

                rd_kafka_message_destroy(rkmessage);
        }

        TEST_SAY(
            "Consumed %d messages matching \"%s\", "
            "ignored %d others, saw %d error(s)\n",
            match_cnt, exp_value, other_cnt, err_cnt);
}


/**
 * @brief Test topic create + delete + create with first topic having
 *        \p part_cnt_1 partitions and second topic having \p part_cnt_2 .
 */
static void do_test_create_delete_create(int part_cnt_1, int part_cnt_2) {
        rd_kafka_t *consumer;
        thrd_t producer_thread;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        int ret           = 0;

        TEST_SAY(_C_MAG
                 "[ Test topic create(%d parts)+delete+create(%d parts) ]\n",
                 part_cnt_1, part_cnt_2);

        consumer = test_create_consumer(topic, NULL, NULL, NULL);

        /* Create topic */
        test_create_topic(consumer, topic, part_cnt_1, 3);

        /* Start consumer */
        test_consumer_subscribe(consumer, topic);
        test_consumer_wait_assignment(consumer, rd_true);

        mtx_lock(&value_mtx);
        value = "before";
        mtx_unlock(&value_mtx);

        /* Create producer thread */
        if (thrd_create(&producer_thread, run_producer, (void *)topic) !=
            thrd_success)
                TEST_FAIL("thrd_create failed");

        /* Consume messages for 5s */
        expect_messages(consumer, msg_rate * 5, value);

        /* Delete topic */
        mtx_lock(&value_mtx);
        value = "during";
        mtx_unlock(&value_mtx);

        test_delete_topic(consumer, topic);
        rd_sleep(5);

        /* Re-create topic */
        test_create_topic(consumer, topic, part_cnt_2, 3);

        mtx_lock(&value_mtx);
        value = "after";
        mtx_unlock(&value_mtx);

        /* Consume for 5 more seconds, should see new messages */
        expect_messages(consumer, msg_rate * 5, value);

        rd_kafka_destroy(consumer);

        /* Wait for producer to exit */
        mtx_lock(&value_mtx);
        value = "end";
        mtx_unlock(&value_mtx);

        if (thrd_join(producer_thread, &ret) != thrd_success || ret != 0)
                TEST_FAIL("Producer failed: see previous errors");

        TEST_SAY(_C_GRN
                 "[ Test topic create(%d parts)+delete+create(%d parts): "
                 "PASS ]\n",
                 part_cnt_1, part_cnt_2);
}


int main_0107_topic_recreate(int argc, char **argv) {
        this_test = test_curr; /* Need to expose current test struct (in TLS)
                                * to producer thread. */

        this_test->is_fatal_cb = is_error_fatal;

        mtx_init(&value_mtx, mtx_plain);

        test_conf_init(NULL, NULL, 60);

        do_test_create_delete_create(10, 3);
        do_test_create_delete_create(3, 6);

        return 0;
}
