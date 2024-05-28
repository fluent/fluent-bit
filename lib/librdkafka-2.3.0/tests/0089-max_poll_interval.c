/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
 *               2023, Confluent Inc.
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
 * Verify that long-processing consumer leaves the group during
 * processing, with or without a log queue.
 *
 * MO:
 *  - produce messages to a single partition topic.
 *  - create two consumers, c1 and c2.
 *  - process first message slowly (2 * max.poll.interval.ms)
 *  - verify in other consumer that group rebalances after max.poll.interval.ms
 *    and the partition is assigned to the other consumer.
 */

/**
 *  @brief Test max.poll.interval.ms without any additional polling.
 */
static void do_test(void) {
        const char *topic = test_mk_topic_name("0089_max_poll_interval", 1);
        uint64_t testid;
        const int msgcnt = 10;
        rd_kafka_t *c[2];
        rd_kafka_conf_t *conf;
        int64_t ts_next[2]    = {0, 0};
        int64_t ts_exp_msg[2] = {0, 0};
        int cmsgcnt           = 0;
        int i;
        int bad = -1;

        SUB_TEST();

        testid = test_id_generate();

        test_create_topic(NULL, topic, 1, 1);

        test_produce_msgs_easy(topic, testid, -1, msgcnt);

        test_conf_init(&conf, NULL, 60);

        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "max.poll.interval.ms", "10000" /*10s*/);
        test_conf_set(conf, "auto.offset.reset", "earliest");

        c[0] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        c[1] = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(c[0], topic);
        test_consumer_subscribe(c[1], topic);

        while (1) {
                for (i = 0; i < 2; i++) {
                        int64_t now;
                        rd_kafka_message_t *rkm;

                        /* Consumer is "processing" */
                        if (ts_next[i] > test_clock())
                                continue;

                        rkm = rd_kafka_consumer_poll(c[i], 100);
                        if (!rkm)
                                continue;

                        if (rkm->err) {
                                TEST_WARN(
                                    "Consumer %d error: %s: "
                                    "ignoring\n",
                                    i, rd_kafka_message_errstr(rkm));
                                continue;
                        }

                        now = test_clock();

                        cmsgcnt++;

                        TEST_SAY(
                            "Consumer %d received message (#%d) "
                            "at offset %" PRId64 "\n",
                            i, cmsgcnt, rkm->offset);

                        if (ts_exp_msg[i]) {
                                /* This consumer is expecting a message
                                 * after a certain time, namely after the
                                 * rebalance following max.poll.. being
                                 * exceeded in the other consumer */
                                TEST_ASSERT(
                                    now > ts_exp_msg[i],
                                    "Consumer %d: did not expect "
                                    "message for at least %dms",
                                    i, (int)((ts_exp_msg[i] - now) / 1000));
                                TEST_ASSERT(
                                    now < ts_exp_msg[i] + 10000 * 1000,
                                    "Consumer %d: expected message "
                                    "within 10s, not after %dms",
                                    i, (int)((now - ts_exp_msg[i]) / 1000));
                                TEST_SAY(
                                    "Consumer %d: received message "
                                    "at offset %" PRId64 " after rebalance\n",
                                    i, rkm->offset);

                                rd_kafka_message_destroy(rkm);
                                goto done;

                        } else if (cmsgcnt == 1) {
                                /* Process this message for 20s */
                                ts_next[i] = now + (20000 * 1000);

                                /* Exp message on other consumer after
                                 * max.poll.interval.ms */
                                ts_exp_msg[i ^ 1] = now + (10000 * 1000);

                                /* This is the bad consumer */
                                bad = i;

                                TEST_SAY(
                                    "Consumer %d processing message at "
                                    "offset %" PRId64 "\n",
                                    i, rkm->offset);
                                rd_kafka_message_destroy(rkm);
                        } else {
                                rd_kafka_message_destroy(rkm);

                                TEST_FAIL(
                                    "Consumer %d did not expect "
                                    "a message",
                                    i);
                        }
                }
        }

done:

        TEST_ASSERT(bad != -1, "Bad consumer not set");

        /* Wait for error ERR__MAX_POLL_EXCEEDED on the bad consumer. */
        while (1) {
                rd_kafka_message_t *rkm;

                rkm = rd_kafka_consumer_poll(c[bad], 1000);
                TEST_ASSERT(rkm, "Expected consumer result within 1s");

                TEST_ASSERT(rkm->err, "Did not expect message on bad consumer");

                TEST_SAY("Consumer error: %s: %s\n",
                         rd_kafka_err2name(rkm->err),
                         rd_kafka_message_errstr(rkm));

                if (rkm->err == RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED) {
                        rd_kafka_message_destroy(rkm);
                        break;
                }

                rd_kafka_message_destroy(rkm);
        }


        for (i = 0; i < 2; i++)
                rd_kafka_destroy_flags(c[i],
                                       RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);

        SUB_TEST_PASS();
}


/**
 *  @brief Test max.poll.interval.ms while polling log queue.
 */
static void do_test_with_log_queue(void) {
        const char *topic = test_mk_topic_name("0089_max_poll_interval", 1);
        uint64_t testid;
        const int msgcnt = 10;
        rd_kafka_t *c[2];
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *logq[2];
        int64_t ts_next[2]    = {0, 0};
        int64_t ts_exp_msg[2] = {0, 0};
        int cmsgcnt           = 0;
        int i;
        int bad = -1;
        char errstr[512];

        SUB_TEST();

        testid = test_id_generate();

        test_create_topic(NULL, topic, 1, 1);

        test_produce_msgs_easy(topic, testid, -1, msgcnt);

        test_conf_init(&conf, NULL, 60);

        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "max.poll.interval.ms", "10000" /*10s*/);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "log.queue", "true");

        c[0] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        c[1] = test_create_consumer(topic, NULL, conf, NULL);


        for (i = 0; i < 2; i++) {
                logq[i] = rd_kafka_queue_new(c[i]);
                TEST_CALL__(rd_kafka_set_log_queue(c[i], logq[i]));
                test_consumer_subscribe(c[i], topic);
        }

        while (1) {
                for (i = 0; i < 2; i++) {
                        int64_t now;
                        rd_kafka_message_t *rkm;

                        /* Consumer is "processing".
                         * When we are "processing", we poll the log queue. */
                        if (ts_next[i] > test_clock()) {
                                rd_kafka_event_destroy(
                                    rd_kafka_queue_poll(logq[i], 100));
                                continue;
                        }

                        rkm = rd_kafka_consumer_poll(c[i], 100);
                        if (!rkm)
                                continue;

                        if (rkm->err) {
                                TEST_WARN(
                                    "Consumer %d error: %s: "
                                    "ignoring\n",
                                    i, rd_kafka_message_errstr(rkm));
                                continue;
                        }

                        now = test_clock();

                        cmsgcnt++;

                        TEST_SAY(
                            "Consumer %d received message (#%d) "
                            "at offset %" PRId64 "\n",
                            i, cmsgcnt, rkm->offset);

                        if (ts_exp_msg[i]) {
                                /* This consumer is expecting a message
                                 * after a certain time, namely after the
                                 * rebalance following max.poll.. being
                                 * exceeded in the other consumer */
                                TEST_ASSERT(
                                    now > ts_exp_msg[i],
                                    "Consumer %d: did not expect "
                                    "message for at least %dms",
                                    i, (int)((ts_exp_msg[i] - now) / 1000));
                                TEST_ASSERT(
                                    now < ts_exp_msg[i] + 10000 * 1000,
                                    "Consumer %d: expected message "
                                    "within 10s, not after %dms",
                                    i, (int)((now - ts_exp_msg[i]) / 1000));
                                TEST_SAY(
                                    "Consumer %d: received message "
                                    "at offset %" PRId64 " after rebalance\n",
                                    i, rkm->offset);

                                rd_kafka_message_destroy(rkm);
                                goto done;

                        } else if (cmsgcnt == 1) {
                                /* Process this message for 20s */
                                ts_next[i] = now + (20000 * 1000);

                                /* Exp message on other consumer after
                                 * max.poll.interval.ms */
                                ts_exp_msg[i ^ 1] = now + (10000 * 1000);

                                /* This is the bad consumer */
                                bad = i;

                                TEST_SAY(
                                    "Consumer %d processing message at "
                                    "offset %" PRId64 "\n",
                                    i, rkm->offset);
                                rd_kafka_message_destroy(rkm);
                        } else {
                                rd_kafka_message_destroy(rkm);

                                TEST_FAIL(
                                    "Consumer %d did not expect "
                                    "a message",
                                    i);
                        }
                }
        }

done:

        TEST_ASSERT(bad != -1, "Bad consumer not set");

        /* Wait for error ERR__MAX_POLL_EXCEEDED on the bad consumer. */
        while (1) {
                rd_kafka_message_t *rkm;

                rkm = rd_kafka_consumer_poll(c[bad], 1000);
                TEST_ASSERT(rkm, "Expected consumer result within 1s");

                TEST_ASSERT(rkm->err, "Did not expect message on bad consumer");

                TEST_SAY("Consumer error: %s: %s\n",
                         rd_kafka_err2name(rkm->err),
                         rd_kafka_message_errstr(rkm));

                if (rkm->err == RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED) {
                        rd_kafka_message_destroy(rkm);
                        break;
                }

                rd_kafka_message_destroy(rkm);
        }


        for (i = 0; i < 2; i++) {
                rd_kafka_destroy_flags(c[i],
                                       RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE);
                rd_kafka_queue_destroy(logq[i]);
        }

        SUB_TEST_PASS();
}


/**
 * @brief Consumer should be able to rejoin the group just by polling after
 * leaving due to a max.poll.interval.ms timeout. The poll does not need to
 * go through any special function, any queue containing consumer messages
 * should suffice.
 * We test with the result of rd_kafka_queue_get_consumer, and an arbitrary
 * queue that is forwarded to by the result of rd_kafka_queue_get_consumer.
 * We also test with an arbitrary queue that is forwarded to the the result of
 * rd_kafka_queue_get_consumer.
 */
static void
do_test_rejoin_after_interval_expire(rd_bool_t forward_to_another_q,
                                     rd_bool_t forward_to_consumer_q) {
        const char *topic = test_mk_topic_name("0089_max_poll_interval", 1);
        rd_kafka_conf_t *conf;
        char groupid[64];
        rd_kafka_t *rk                    = NULL;
        rd_kafka_queue_t *consumer_queue  = NULL;
        rd_kafka_queue_t *forwarder_queue = NULL;
        rd_kafka_event_t *event           = NULL;
        rd_kafka_queue_t *polling_queue   = NULL;

        SUB_TEST(
            "Testing with forward_to_another_q = %d, forward_to_consumer_q = "
            "%d",
            forward_to_another_q, forward_to_consumer_q);

        test_create_topic(NULL, topic, 1, 1);

        test_str_id_generate(groupid, sizeof(groupid));
        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "max.poll.interval.ms", "10000" /*10s*/);
        test_conf_set(conf, "partition.assignment.strategy", "range");

        /* We need to specify a non-NULL rebalance CB to get events of type
         * RD_KAFKA_EVENT_REBALANCE. */
        rk = test_create_consumer(groupid, test_rebalance_cb, conf, NULL);

        consumer_queue = rd_kafka_queue_get_consumer(rk);

        test_consumer_subscribe(rk, topic);

        if (forward_to_another_q) {
                polling_queue = rd_kafka_queue_new(rk);
                rd_kafka_queue_forward(consumer_queue, polling_queue);
        } else if (forward_to_consumer_q) {
                forwarder_queue = rd_kafka_queue_new(rk);
                rd_kafka_queue_forward(forwarder_queue, consumer_queue);
                polling_queue = forwarder_queue;
        } else
                polling_queue = consumer_queue;

        event = test_wait_event(polling_queue, RD_KAFKA_EVENT_REBALANCE,
                                (int)(test_timeout_multiplier * 10000));
        TEST_ASSERT(event,
                    "Did not get a rebalance event for initial group join");
        TEST_ASSERT(rd_kafka_event_error(event) ==
                        RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                    "Group join should assign partitions");
        rd_kafka_assign(rk, rd_kafka_event_topic_partition_list(event));
        rd_kafka_event_destroy(event);

        rd_sleep(10 + 1); /* Exceed max.poll.interval.ms. */

        /* Note that by polling for the group leave, we're also polling the
         * consumer queue, and hence it should trigger a rejoin. */
        event = test_wait_event(polling_queue, RD_KAFKA_EVENT_REBALANCE,
                                (int)(test_timeout_multiplier * 10000));
        TEST_ASSERT(event, "Did not get a rebalance event for the group leave");
        TEST_ASSERT(rd_kafka_event_error(event) ==
                        RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS,
                    "Group leave should revoke partitions");
        rd_kafka_assign(rk, NULL);
        rd_kafka_event_destroy(event);

        event = test_wait_event(polling_queue, RD_KAFKA_EVENT_REBALANCE,
                                (int)(test_timeout_multiplier * 10000));
        TEST_ASSERT(event, "Should get a rebalance event for the group rejoin");
        TEST_ASSERT(rd_kafka_event_error(event) ==
                        RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                    "Group rejoin should assign partitions");
        rd_kafka_assign(rk, rd_kafka_event_topic_partition_list(event));
        rd_kafka_event_destroy(event);

        if (forward_to_another_q)
                rd_kafka_queue_destroy(polling_queue);
        if (forward_to_consumer_q)
                rd_kafka_queue_destroy(forwarder_queue);
        rd_kafka_queue_destroy(consumer_queue);
        test_consumer_close(rk);
        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}

static void consume_cb(rd_kafka_message_t *rkmessage, void *opaque) {
        TEST_SAY("Consume callback\n");
}

/**
 * @brief Test that max.poll.interval.ms is reset when
 * rd_kafka_poll is called with consume_cb.
 * See issue #4421.
 */
static void do_test_max_poll_reset_with_consumer_cb(void) {
        const char *topic = test_mk_topic_name("0089_max_poll_interval", 1);
        rd_kafka_conf_t *conf;
        char groupid[64];
        rd_kafka_t *rk = NULL;

        SUB_TEST();

        test_create_topic(NULL, topic, 1, 1);
        uint64_t testid = test_id_generate();

        test_produce_msgs_easy(topic, testid, -1, 100);

        test_str_id_generate(groupid, sizeof(groupid));
        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "session.timeout.ms", "10000");
        test_conf_set(conf, "max.poll.interval.ms", "10000" /*10s*/);
        test_conf_set(conf, "partition.assignment.strategy", "range");
        rd_kafka_conf_set_consume_cb(conf, consume_cb);

        rk = test_create_consumer(groupid, NULL, conf, NULL);
        rd_kafka_poll_set_consumer(rk);

        test_consumer_subscribe(rk, topic);
        TEST_SAY("Subscribed to %s and sleeping for 5 s\n", topic);
        rd_sleep(5);
        rd_kafka_poll(rk, 10);
        TEST_SAY(
            "Polled and sleeping again for 6s. Max poll should be reset\n");
        rd_sleep(6);

        /* Poll should work */
        rd_kafka_poll(rk, 10);
        test_consumer_close(rk);
        rd_kafka_destroy(rk);
}

int main_0089_max_poll_interval(int argc, char **argv) {
        do_test();
        do_test_with_log_queue();
        do_test_rejoin_after_interval_expire(rd_false, rd_false);
        do_test_rejoin_after_interval_expire(rd_true, rd_false);
        do_test_rejoin_after_interval_expire(rd_false, rd_true);
        do_test_max_poll_reset_with_consumer_cb();
        return 0;
}
