/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2022, Magnus Edenhill
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
        int i, err_cnt = 0;
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

        for (i = 0; i < msg_cnt; i++) {
                rd_kafka_message_t *rkm = rkmessage[i];
                if (rkm->err) {
                        TEST_WARN("Consumer error: %s: %s\n",
                                  rd_kafka_err2name(rkm->err),
                                  rd_kafka_message_errstr(rkm));
                        err_cnt++;
                } else if (test_msgver_add_msg(rk, arguments->mv,
                                               rkmessage[i]) == 0) {
                        TEST_FAIL(
                            "The message is not from testid "
                            "%" PRId64,
                            testid);
                }
        }
        TEST_SAY("%s consumed %d/%d/%d message(s)\n", rd_kafka_name(rk),
                 msg_cnt, arguments->consume_msg_cnt,
                 arguments->expected_msg_cnt);
        TEST_ASSERT((msg_cnt - err_cnt) == arguments->expected_msg_cnt,
                    "consumed %d messages, %d errors, expected %d", msg_cnt,
                    err_cnt, arguments->expected_msg_cnt);

        for (i = 0; i < msg_cnt; i++) {
                rd_kafka_message_destroy(rkmessage[i]);
        }

        rd_free(rkmessage);

        return 0;
}


static void do_test_consume_batch_with_seek(void) {
        rd_kafka_queue_t *rkq;
        const char *topic;
        rd_kafka_t *consumer;
        int p;
        uint64_t testid;
        rd_kafka_conf_t *conf;
        consumer_t consumer_args = RD_ZERO_INIT;
        test_msgver_t mv;
        thrd_t thread_id;
        rd_kafka_error_t *err;
        rd_kafka_topic_partition_list_t *seek_toppars;
        const int partition_cnt      = 2;
        const int timeout_ms         = 10000;
        const int consume_msg_cnt    = 10;
        const int produce_msg_cnt    = 8;
        const int32_t seek_partition = 0;
        const int64_t seek_offset    = 1;
        const int expected_msg_cnt   = produce_msg_cnt - seek_offset;

        SUB_TEST();

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "auto.offset.reset", "earliest");

        testid = test_id_generate();
        test_msgver_init(&mv, testid);

        /* Produce messages */
        topic = test_mk_topic_name("0137-barrier_batch_consume", 1);

        test_create_topic_wait_exists(NULL, topic, partition_cnt, 1, 5000);

        for (p = 0; p < partition_cnt; p++)
                test_produce_msgs_easy(topic, testid, p,
                                       produce_msg_cnt / partition_cnt);

        /* Create consumers */
        consumer = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(consumer, topic);
        test_consumer_wait_assignment(consumer, rd_false);

        /* Create generic consume queue */
        rkq = rd_kafka_queue_get_consumer(consumer);

        consumer_args.what             = "CONSUMER";
        consumer_args.rkq              = rkq;
        consumer_args.timeout_ms       = timeout_ms;
        consumer_args.consume_msg_cnt  = consume_msg_cnt;
        consumer_args.expected_msg_cnt = expected_msg_cnt;
        consumer_args.rk               = consumer;
        consumer_args.testid           = testid;
        consumer_args.mv               = &mv;
        consumer_args.test             = test_curr;
        if (thrd_create(&thread_id, consumer_batch_queue, &consumer_args) !=
            thrd_success)
                TEST_FAIL("Failed to create thread for %s", "CONSUMER");

        seek_toppars = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(seek_toppars, topic, seek_partition);
        rd_kafka_topic_partition_list_set_offset(seek_toppars, topic,
                                                 seek_partition, seek_offset);
        err = rd_kafka_seek_partitions(consumer, seek_toppars, 2000);

        TEST_ASSERT(
            !err, "Failed to seek partition %d for topic %s to offset %" PRId64,
            seek_partition, topic, seek_offset);

        thrd_join(thread_id, NULL);

        test_msgver_verify("CONSUME", &mv,
                           TEST_MSGVER_ORDER | TEST_MSGVER_DUP |
                               TEST_MSGVER_BY_OFFSET,
                           0, expected_msg_cnt);
        test_msgver_clear(&mv);

        rd_kafka_topic_partition_list_destroy(seek_toppars);

        rd_kafka_queue_destroy(rkq);

        test_consumer_close(consumer);

        rd_kafka_destroy(consumer);

        SUB_TEST_PASS();
}


static void do_test_consume_batch_with_pause_and_resume_different_batch(void) {
        rd_kafka_queue_t *rkq;
        const char *topic;
        rd_kafka_t *consumer;
        int p;
        uint64_t testid;
        rd_kafka_conf_t *conf;
        consumer_t consumer_args = RD_ZERO_INIT;
        test_msgver_t mv;
        thrd_t thread_id;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *pause_partition_list;
        const int timeout_ms       = 2000;
        const int consume_msg_cnt  = 10;
        const int produce_msg_cnt  = 8;
        const int partition_cnt    = 2;
        const int expected_msg_cnt = 4;
        int32_t pause_partition    = 0;
        int32_t running_partition  = 1;

        SUB_TEST();

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "auto.offset.reset", "earliest");

        testid = test_id_generate();
        test_msgver_init(&mv, testid);

        /* Produce messages */
        topic = test_mk_topic_name("0137-barrier_batch_consume", 1);

        test_create_topic_wait_exists(NULL, topic, partition_cnt, 1, 5000);

        for (p = 0; p < partition_cnt; p++)
                test_produce_msgs_easy(topic, testid, p,
                                       produce_msg_cnt / partition_cnt);

        /* Create consumers */
        consumer = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(consumer, topic);
        test_consumer_wait_assignment(consumer, rd_false);

        /* Create generic consume queue */
        rkq = rd_kafka_queue_get_consumer(consumer);

        consumer_args.what             = "CONSUMER";
        consumer_args.rkq              = rkq;
        consumer_args.timeout_ms       = timeout_ms;
        consumer_args.consume_msg_cnt  = consume_msg_cnt;
        consumer_args.expected_msg_cnt = expected_msg_cnt;
        consumer_args.rk               = consumer;
        consumer_args.testid           = testid;
        consumer_args.mv               = &mv;
        consumer_args.test             = test_curr;
        if (thrd_create(&thread_id, consumer_batch_queue, &consumer_args) !=
            thrd_success)
                TEST_FAIL("Failed to create thread for %s", "CONSUMER");

        pause_partition_list = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(pause_partition_list, topic,
                                          pause_partition);

        rd_sleep(1);
        err = rd_kafka_pause_partitions(consumer, pause_partition_list);

        TEST_ASSERT(!err, "Failed to pause partition %d for topic %s",
                    pause_partition, topic);

        thrd_join(thread_id, NULL);

        test_msgver_verify_part("CONSUME", &mv,
                                TEST_MSGVER_ORDER | TEST_MSGVER_DUP |
                                    TEST_MSGVER_BY_OFFSET,
                                topic, running_partition, 0, expected_msg_cnt);

        test_msgver_clear(&mv);
        test_msgver_init(&mv, testid);
        consumer_args.mv = &mv;

        err = rd_kafka_resume_partitions(consumer, pause_partition_list);

        TEST_ASSERT(!err, "Failed to resume partition %d for topic %s",
                    pause_partition, topic);

        consumer_batch_queue(&consumer_args);

        test_msgver_verify_part("CONSUME", &mv,
                                TEST_MSGVER_ORDER | TEST_MSGVER_DUP |
                                    TEST_MSGVER_BY_OFFSET,
                                topic, pause_partition, 0, expected_msg_cnt);

        rd_kafka_topic_partition_list_destroy(pause_partition_list);

        test_msgver_clear(&mv);

        rd_kafka_queue_destroy(rkq);

        test_consumer_close(consumer);

        rd_kafka_destroy(consumer);

        SUB_TEST_PASS();
}


static void do_test_consume_batch_with_pause_and_resume_same_batch(void) {
        rd_kafka_queue_t *rkq;
        const char *topic;
        rd_kafka_t *consumer;
        int p;
        uint64_t testid;
        rd_kafka_conf_t *conf;
        consumer_t consumer_args = RD_ZERO_INIT;
        test_msgver_t mv;
        thrd_t thread_id;
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *pause_partition_list;
        const int timeout_ms      = 10000;
        const int consume_msg_cnt = 10;
        const int produce_msg_cnt = 8;
        const int partition_cnt   = 2;
        int32_t pause_partition   = 0;

        SUB_TEST();

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "auto.offset.reset", "earliest");

        testid = test_id_generate();
        test_msgver_init(&mv, testid);

        /* Produce messages */
        topic = test_mk_topic_name("0137-barrier_batch_consume", 1);

        test_create_topic_wait_exists(NULL, topic, partition_cnt, 1, 5000);

        for (p = 0; p < partition_cnt; p++)
                test_produce_msgs_easy(topic, testid, p,
                                       produce_msg_cnt / partition_cnt);

        /* Create consumers */
        consumer = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(consumer, topic);
        test_consumer_wait_assignment(consumer, rd_false);

        /* Create generic consume queue */
        rkq = rd_kafka_queue_get_consumer(consumer);

        consumer_args.what             = "CONSUMER";
        consumer_args.rkq              = rkq;
        consumer_args.timeout_ms       = timeout_ms;
        consumer_args.consume_msg_cnt  = consume_msg_cnt;
        consumer_args.expected_msg_cnt = produce_msg_cnt;
        consumer_args.rk               = consumer;
        consumer_args.testid           = testid;
        consumer_args.mv               = &mv;
        consumer_args.test             = test_curr;
        if (thrd_create(&thread_id, consumer_batch_queue, &consumer_args) !=
            thrd_success)
                TEST_FAIL("Failed to create thread for %s", "CONSUMER");

        pause_partition_list = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(pause_partition_list, topic,
                                          pause_partition);

        rd_sleep(1);
        err = rd_kafka_pause_partitions(consumer, pause_partition_list);

        TEST_ASSERT(!err, "Failed to pause partition %d for topic %s",
                    pause_partition, topic);

        rd_sleep(1);

        err = rd_kafka_resume_partitions(consumer, pause_partition_list);

        TEST_ASSERT(!err, "Failed to resume partition %d for topic %s",
                    pause_partition, topic);

        thrd_join(thread_id, NULL);

        test_msgver_verify("CONSUME", &mv,
                           TEST_MSGVER_ORDER | TEST_MSGVER_DUP |
                               TEST_MSGVER_BY_OFFSET,
                           0, produce_msg_cnt);

        rd_kafka_topic_partition_list_destroy(pause_partition_list);

        test_msgver_clear(&mv);

        rd_kafka_queue_destroy(rkq);

        test_consumer_close(consumer);

        rd_kafka_destroy(consumer);

        SUB_TEST_PASS();
}


static void do_test_consume_batch_store_offset(void) {
        rd_kafka_queue_t *rkq;
        const char *topic;
        rd_kafka_t *consumer;
        int p;
        int i;
        uint64_t testid;
        rd_kafka_conf_t *conf;
        consumer_t consumer_args = RD_ZERO_INIT;
        test_msgver_t mv;
        const int partition_cnt    = 1;
        const int timeout_ms       = 10000;
        const int consume_msg_cnt  = 4;
        const int no_of_consume    = 2;
        const int produce_msg_cnt  = 8;
        const int expected_msg_cnt = produce_msg_cnt;

        SUB_TEST();

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "enable.auto.offset.store", "true");
        test_conf_set(conf, "auto.offset.reset", "earliest");

        testid = test_id_generate();
        test_msgver_init(&mv, testid);

        /* Produce messages */
        topic = test_mk_topic_name("0137-barrier_batch_consume", 1);

        test_create_topic_wait_exists(NULL, topic, partition_cnt, 1, 5000);

        for (p = 0; p < partition_cnt; p++)
                test_produce_msgs_easy(topic, testid, p,
                                       produce_msg_cnt / partition_cnt);

        for (i = 0; i < no_of_consume; i++) {

                /* Create consumers */
                consumer = test_create_consumer(topic, NULL,
                                                rd_kafka_conf_dup(conf), NULL);
                test_consumer_subscribe(consumer, topic);
                test_consumer_wait_assignment(consumer, rd_false);

                /* Create generic consume queue */
                rkq = rd_kafka_queue_get_consumer(consumer);

                consumer_args.what            = "CONSUMER";
                consumer_args.rkq             = rkq;
                consumer_args.timeout_ms      = timeout_ms;
                consumer_args.consume_msg_cnt = consume_msg_cnt;
                consumer_args.expected_msg_cnt =
                    produce_msg_cnt / no_of_consume;
                consumer_args.rk     = consumer;
                consumer_args.testid = testid;
                consumer_args.mv     = &mv;
                consumer_args.test   = test_curr;

                consumer_batch_queue(&consumer_args);
                rd_kafka_commit(consumer, NULL, rd_false);

                rd_kafka_queue_destroy(rkq);
                test_consumer_close(consumer);
                rd_kafka_destroy(consumer);
        }

        test_msgver_verify("CONSUME", &mv,
                           TEST_MSGVER_ORDER | TEST_MSGVER_DUP |
                               TEST_MSGVER_BY_OFFSET,
                           0, expected_msg_cnt);

        test_msgver_clear(&mv);

        rd_kafka_conf_destroy(conf);

        SUB_TEST_PASS();
}


static void do_test_consume_batch_control_msgs(void) {
        const char *topic = test_mk_topic_name("0137-barrier_batch_consume", 1);
        const int32_t partition = 0;
        rd_kafka_conf_t *conf, *c_conf;
        rd_kafka_t *producer, *consumer;
        uint64_t testid;
        const int msgcnt[2] = {2, 3};
        test_msgver_t mv;
        rd_kafka_queue_t *rkq;
        consumer_t consumer_args   = RD_ZERO_INIT;
        const int partition_cnt    = 1;
        const int timeout_ms       = 5000;
        const int consume_msg_cnt  = 10;
        const int expected_msg_cnt = 2;
        int32_t pause_partition    = 0;
        int64_t expected_offset    = msgcnt[0] + msgcnt[1] + 2;
        rd_kafka_topic_partition_list_t *pause_partition_list;
        rd_kafka_resp_err_t err;
        thrd_t thread_id;

        SUB_TEST("Testing control msgs flow");

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 30);

        test_conf_set(conf, "transactional.id", topic);
        test_conf_set(conf, "batch.num.messages", "1");
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        producer = test_create_handle(RD_KAFKA_PRODUCER, conf);

        test_create_topic_wait_exists(producer, topic, partition_cnt, 1, 5000);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(producer, 30 * 1000));

        /*
         * Transaction 1
         */
        TEST_SAY("Transaction 1: %d msgs\n", msgcnt[0]);
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_produce_msgs2(producer, topic, testid, partition, 0, msgcnt[0],
                           NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(producer, -1));

        /*
         * Transaction 2
         */
        TEST_SAY("Transaction 2: %d msgs\n", msgcnt[1]);
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(producer));
        test_produce_msgs2(producer, topic, testid, partition, 0, msgcnt[1],
                           NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_abort_transaction(producer, -1));

        rd_kafka_destroy(producer);

        rd_sleep(2);

        /*
         * Consumer
         */
        test_conf_init(&c_conf, NULL, 0);
        test_conf_set(c_conf, "enable.auto.commit", "false");
        test_conf_set(c_conf, "enable.auto.offset.store", "true");
        test_conf_set(c_conf, "auto.offset.reset", "earliest");
        consumer = test_create_consumer(topic, NULL, c_conf, NULL);

        test_consumer_subscribe(consumer, topic);
        test_consumer_wait_assignment(consumer, rd_false);

        /* Create generic consume queue */
        rkq = rd_kafka_queue_get_consumer(consumer);

        test_msgver_init(&mv, testid);
        test_msgver_ignore_eof(&mv);

        consumer_args.what             = "CONSUMER";
        consumer_args.rkq              = rkq;
        consumer_args.timeout_ms       = timeout_ms;
        consumer_args.consume_msg_cnt  = consume_msg_cnt;
        consumer_args.expected_msg_cnt = expected_msg_cnt;
        consumer_args.rk               = consumer;
        consumer_args.testid           = testid;
        consumer_args.mv               = &mv;
        consumer_args.test             = test_curr;


        if (thrd_create(&thread_id, consumer_batch_queue, &consumer_args) !=
            thrd_success)
                TEST_FAIL("Failed to create thread for %s", "CONSUMER");

        pause_partition_list = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(pause_partition_list, topic,
                                          pause_partition);

        rd_sleep(1);
        err = rd_kafka_pause_partitions(consumer, pause_partition_list);

        TEST_ASSERT(!err, "Failed to pause partition %d for topic %s",
                    pause_partition, topic);

        rd_sleep(1);

        err = rd_kafka_resume_partitions(consumer, pause_partition_list);

        TEST_ASSERT(!err, "Failed to resume partition %d for topic %s",
                    pause_partition, topic);

        thrd_join(thread_id, NULL);

        rd_kafka_commit(consumer, NULL, rd_false);

        rd_kafka_committed(consumer, pause_partition_list, timeout_ms);

        TEST_ASSERT(pause_partition_list->elems[0].offset == expected_offset,
                    "Expected offset should be %" PRId64 ", but it is %" PRId64,
                    expected_offset, pause_partition_list->elems[0].offset);

        rd_kafka_topic_partition_list_destroy(pause_partition_list);

        rd_kafka_queue_destroy(rkq);

        test_msgver_clear(&mv);

        test_consumer_close(consumer);

        rd_kafka_destroy(consumer);

        SUB_TEST_PASS();
}


/**
 * @brief Test that rd_kafka_consume_batch_queue correctly updates consumer
 *        position when EOF messages are received with
 * enable.partition.eof=true.
 *
 * This is a regression test for the bug where EOF messages incorrectly
 * advanced the consumer position by 2 instead of 1 (last_offset + 2 instead
 * of last_offset + 1).
 */
static void do_test_consume_batch_eof_position(void) {
        const char *topic;
        rd_kafka_t *consumer;
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *rkq;
        uint64_t testid;
        const int partition_cnt             = 1;
        const int partition                 = 0;
        const int produce_msg_cnt           = 5;
        const int consume_msg_cnt           = 10;
        const int timeout_ms                = 1000;
        const int session_timeout_s         = 60;
        const int replication_factor        = -1;
        const int topic_creation_timeout_ms = 5000;
        rd_kafka_message_t **rkmessages;
        int msg_cnt, i;
        int64_t last_real_offset = -1;
        int64_t eof_offset       = -1;
        int64_t position_after_eof;
        rd_kafka_topic_partition_list_t *positions;
        rd_kafka_resp_err_t err;
        int eof_received = 0;

        SUB_TEST_QUICK("Testing EOF position with consume_batch_queue");

        /* Create consumer configuration with enable.partition.eof=true */
        test_conf_init(&conf, NULL, session_timeout_s);
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.partition.eof", "true");

        testid = test_id_generate();

        topic = test_mk_topic_name("0137-barrier_batch_consume", 1);

        /* Create topic */
        test_create_topic_wait_exists(NULL, topic, partition_cnt,
                                      replication_factor,
                                      topic_creation_timeout_ms);
        test_produce_msgs_easy(topic, testid, partition, produce_msg_cnt);

        consumer = test_create_consumer(topic, NULL, conf, NULL);
        test_consumer_subscribe(consumer, topic);
        test_consumer_wait_assignment(consumer, rd_false);

        /* Create generic consume queue */
        rkq = rd_kafka_queue_get_consumer(consumer);

        /* Consume messages in batches until we get EOF */
        rkmessages = malloc(consume_msg_cnt * sizeof(*rkmessages));

        while (!eof_received) {
                msg_cnt = (int)rd_kafka_consume_batch_queue(
                    rkq, timeout_ms, rkmessages, consume_msg_cnt);

                TEST_ASSERT(msg_cnt >= 0, "consume_batch_queue failed");

                if (msg_cnt == 0) {
                        TEST_WARN("No messages received, retrying...");
                        continue;
                }

                /* Check if EOF messages are received */
                for (i = 0; i < msg_cnt; i++) {
                        rd_kafka_message_t *rkm = rkmessages[i];

                        if (rkm->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                                eof_received = 1;
                                eof_offset   = rkm->offset;
                                TEST_SAY("Received EOF at offset %" PRId64 "\n",
                                         eof_offset);
                        } else if (!rkm->err) {
                                last_real_offset = rkm->offset;
                        }
                }

                /* Destroy messages */
                for (i = 0; i < msg_cnt; i++)
                        rd_kafka_message_destroy(rkmessages[i]);
        }

        rd_free(rkmessages);

        /* Test that the last real message offset is the expected value */
        TEST_ASSERT(last_real_offset == produce_msg_cnt - 1,
                    "Expected last message offset %" PRId64 ", got %" PRId64,
                    (int64_t)(produce_msg_cnt - 1), last_real_offset);

        /* Get consumer position after EOF */
        positions = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(positions, topic, partition);

        err = rd_kafka_position(consumer, positions);
        TEST_ASSERT(!err, "rd_kafka_position failed: %s",
                    rd_kafka_err2str(err));

        /* Extract the position value from the partition list */
        position_after_eof = positions->elems[0].offset;

        TEST_SAY("Last real message offset: %" PRId64
                 "\n"
                 "EOF offset: %" PRId64
                 "\n"
                 "Position after EOF: %" PRId64 "\n",
                 last_real_offset, eof_offset, position_after_eof);

        TEST_ASSERT(position_after_eof == last_real_offset + 1,
                    "Position after EOF should be %" PRId64
                    " (last_offset + 1), "
                    "but got %" PRId64
                    ". This indicates the EOF offset bug where "
                    "position incorrectly advances by +2 instead of +1",
                    last_real_offset + 1, position_after_eof);

        rd_kafka_topic_partition_list_destroy(positions);
        rd_kafka_queue_destroy(rkq);
        test_consumer_close(consumer);
        rd_kafka_destroy(consumer);

        SUB_TEST_PASS();
}


int main_0137_barrier_batch_consume(int argc, char **argv) {
        do_test_consume_batch_with_seek();
        do_test_consume_batch_store_offset();
        do_test_consume_batch_with_pause_and_resume_different_batch();
        do_test_consume_batch_with_pause_and_resume_same_batch();
        do_test_consume_batch_control_msgs();
        do_test_consume_batch_eof_position();

        return 0;
}
