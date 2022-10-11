/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2021, Magnus Edenhill
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

typedef struct consumer_s {
        const char *what;
        rd_kafka_queue_t *rkq;
        int timeout_ms;
        int consume_msg_cnt;
        int expected_msg_cnt;
        rd_kafka_t *rk;
        uint64_t testid;
        test_msgver_t *mv;
        struct test *test;
} consumer_t;

static int consumer_batch_queue(void *arg) {
        consumer_t *arguments = arg;
        int msg_cnt           = 0;
        int i;
        test_timing_t t_cons;

        rd_kafka_queue_t *rkq     = arguments->rkq;
        int timeout_ms            = arguments->timeout_ms;
        const int consume_msg_cnt = arguments->consume_msg_cnt;
        rd_kafka_t *rk            = arguments->rk;
        uint64_t testid           = arguments->testid;
        rd_kafka_message_t **rkmessage =
            malloc(consume_msg_cnt * sizeof(*rkmessage));

        if (arguments->test)
                test_curr = arguments->test;

        TEST_SAY(
            "%s calling consume_batch_queue(timeout=%d, msgs=%d) "
            "and expecting %d messages back\n",
            rd_kafka_name(rk), timeout_ms, consume_msg_cnt,
            arguments->expected_msg_cnt);

        TIMING_START(&t_cons, "CONSUME");
        msg_cnt = (int)rd_kafka_consume_batch_queue(rkq, timeout_ms, rkmessage,
                                                    consume_msg_cnt);
        TIMING_STOP(&t_cons);

        TEST_SAY("%s consumed %d/%d/%d message(s)\n", rd_kafka_name(rk),
                 msg_cnt, arguments->consume_msg_cnt,
                 arguments->expected_msg_cnt);
        TEST_ASSERT(msg_cnt == arguments->expected_msg_cnt,
                    "consumed %d messages, expected %d", msg_cnt,
                    arguments->expected_msg_cnt);

        for (i = 0; i < msg_cnt; i++) {
                if (test_msgver_add_msg(rk, arguments->mv, rkmessage[i]) == 0)
                        TEST_FAIL(
                            "The message is not from testid "
                            "%" PRId64 " \n",
                            testid);
                rd_kafka_message_destroy(rkmessage[i]);
        }

        return 0;
}


/**
 * @brief Produce 400 messages and consume 500 messages totally by 2 consumers
 *        using batch queue method, verify if there isn't any missed or
 *        duplicate messages received by the two consumers.
 *        The reasons for setting the consume messages number is higher than
 *        or equal to the produce messages number are:
 *        1) Make sure each consumer can at most receive half of the produced
 *           messages even though the consumers expect more.
 *        2) If the consume messages number is smaller than the produce
 *           messages number, it's hard to verify that the messages returned
 *           are added to the batch queue before or after the rebalancing.
 *           But if the consume messages number is larger than the produce
 *           messages number, and we still received half of the produced
 *           messages by each consumer, we can make sure that the buffer
 *           cleaning is happened during the batch queue process to guarantee
 *           only received messages added to the batch queue after the
 *           rebalance.
 *
 *        1. Produce 100 messages to each of the 4 partitions
 *        2. First consumer subscribes to the topic, wait for it's assignment
 *        3. The first consumer consumes 500 messages using the batch queue
 *           method
 *        4. Second consumer subscribes to the topic, wait for it's assignment
 *        5. Rebalance happenes
 *        6. The second consumer consumes 500 messages using the batch queue
 *           method
 *        7. Each consumer receives 200 messages finally
 *        8. Combine all the messages received by the 2 consumers and
 *           verify if there isn't any missed or duplicate messages
 *
 */
static void do_test_consume_batch(const char *strategy) {
        const int partition_cnt = 4;
        rd_kafka_queue_t *rkq1, *rkq2;
        const char *topic;
        rd_kafka_t *c1;
        rd_kafka_t *c2;
        int p;
        const int timeout_ms = 12000; /* Must be > rebalance time */
        uint64_t testid;
        const int consume_msg_cnt = 500;
        const int produce_msg_cnt = 400;
        rd_kafka_conf_t *conf;
        consumer_t c1_args = RD_ZERO_INIT;
        consumer_t c2_args = RD_ZERO_INIT;
        test_msgver_t mv;
        thrd_t thread_id;

        SUB_TEST("partition.assignment.strategy = %s", strategy);

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "partition.assignment.strategy", strategy);

        testid = test_id_generate();
        test_msgver_init(&mv, testid);

        /* Produce messages */
        topic = test_mk_topic_name("0122-buffer_cleaning", 1);

        for (p = 0; p < partition_cnt; p++)
                test_produce_msgs_easy(topic, testid, p,
                                       produce_msg_cnt / partition_cnt);

        /* Create consumers */
        c1 = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        c2 = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(c1, topic);
        test_consumer_wait_assignment(c1, rd_false);

        /* Create generic consume queue */
        rkq1 = rd_kafka_queue_get_consumer(c1);

        c1_args.what             = "C1.PRE";
        c1_args.rkq              = rkq1;
        c1_args.timeout_ms       = timeout_ms;
        c1_args.consume_msg_cnt  = consume_msg_cnt;
        c1_args.expected_msg_cnt = produce_msg_cnt / 2;
        c1_args.rk               = c1;
        c1_args.testid           = testid;
        c1_args.mv               = &mv;
        c1_args.test             = test_curr;
        if (thrd_create(&thread_id, consumer_batch_queue, &c1_args) !=
            thrd_success)
                TEST_FAIL("Failed to create thread for %s", "C1.PRE");

        test_consumer_subscribe(c2, topic);
        test_consumer_wait_assignment(c2, rd_false);

        thrd_join(thread_id, NULL);

        /* Create generic consume queue */
        rkq2 = rd_kafka_queue_get_consumer(c2);

        c2_args.what = "C2.PRE";
        c2_args.rkq  = rkq2;
        /* Second consumer should be able to consume all messages right away */
        c2_args.timeout_ms       = 5000;
        c2_args.consume_msg_cnt  = consume_msg_cnt;
        c2_args.expected_msg_cnt = produce_msg_cnt / 2;
        c2_args.rk               = c2;
        c2_args.testid           = testid;
        c2_args.mv               = &mv;

        consumer_batch_queue(&c2_args);

        test_msgver_verify("C1.PRE + C2.PRE", &mv,
                           TEST_MSGVER_ORDER | TEST_MSGVER_DUP, 0,
                           produce_msg_cnt);
        test_msgver_clear(&mv);

        rd_kafka_queue_destroy(rkq1);
        rd_kafka_queue_destroy(rkq2);

        test_consumer_close(c1);
        test_consumer_close(c2);

        rd_kafka_destroy(c1);
        rd_kafka_destroy(c2);

        SUB_TEST_PASS();
}


int main_0122_buffer_cleaning_after_rebalance(int argc, char **argv) {
        do_test_consume_batch("range");
        do_test_consume_batch("cooperative-sticky");
        return 0;
}
