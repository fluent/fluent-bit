/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
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
 * @name Producer transaction tests
 *
 */


/**
 * @brief Produce messages using batch interface.
 */
void do_produce_batch (rd_kafka_t *rk, const char *topic, uint64_t testid,
                       int32_t partition, int msg_base, int cnt) {
        rd_kafka_message_t *messages;
        rd_kafka_topic_t *rkt = rd_kafka_topic_new(rk, topic, NULL);
        int i;
        int ret;
        int remains = cnt;

        TEST_SAY("Batch-producing %d messages to partition %"PRId32"\n",
                 cnt, partition);

        messages = rd_calloc(sizeof(*messages), cnt);
        for (i = 0 ; i < cnt ; i++) {
                char key[128];
                char value[128];

                test_prepare_msg(testid, partition, msg_base + i,
                                 value, sizeof(value),
                                 key, sizeof(key));
                messages[i].key = rd_strdup(key);
                messages[i].key_len = strlen(key);
                messages[i].payload = rd_strdup(value);
                messages[i].len = strlen(value);
                messages[i]._private = &remains;
        }

        ret = rd_kafka_produce_batch(rkt, partition, RD_KAFKA_MSG_F_COPY,
                                     messages, cnt);

        rd_kafka_topic_destroy(rkt);

        TEST_ASSERT(ret == cnt,
                    "Failed to batch-produce: %d/%d messages produced",
                    ret, cnt);

        for (i = 0 ; i < cnt ; i++) {
                TEST_ASSERT(!messages[i].err,
                            "Failed to produce message: %s",
                            rd_kafka_err2str(messages[i].err));
                rd_free(messages[i].key);
                rd_free(messages[i].payload);
        }
        rd_free(messages);

        /* Wait for deliveries */
        test_wait_delivery(rk, &remains);
}



/**
 * @brief Basic producer transaction testing without consumed input
 *        (only consumed output for verification).
 *        e.g., no consumer offsets to commit with transaction.
 */
static void do_test_basic_producer_txn (void) {
        const char *topic = test_mk_topic_name("0103_transactions", 1);
        const int partition_cnt = 4;
#define _TXNCNT 6
        struct {
                const char *desc;
                uint64_t testid;
                int msgcnt;
                rd_bool_t abort;
                rd_bool_t sync;
                rd_bool_t batch;
                rd_bool_t batch_any;
        } txn[_TXNCNT] = {
                { "Commit transaction, sync producing",
                  0, 100, rd_false, rd_true },
                { "Commit transaction, async producing",
                  0, 1000, rd_false, rd_false },
                { "Commit transaction, sync batch producing to any partition",
                  0, 100, rd_false, rd_true, rd_true, rd_true },
                { "Abort transaction, sync producing",
                  0, 500, rd_true, rd_true },
                { "Abort transaction, async producing",
                  0, 5000, rd_true, rd_false },
                { "Abort transaction, sync batch producing to one partition",
                  0, 500, rd_true, rd_true, rd_true, rd_false },

        };
        rd_kafka_t *p, *c;
        rd_kafka_conf_t *conf, *p_conf, *c_conf;
        int i;

        test_conf_init(&conf, NULL, 30);

        /* Create producer */
        p_conf = rd_kafka_conf_dup(conf);
        rd_kafka_conf_set_dr_msg_cb(p_conf, test_dr_msg_cb);
        test_conf_set(p_conf, "transactional.id", topic);
        p = test_create_handle(RD_KAFKA_PRODUCER, p_conf);

        // FIXME: add testing were the txn id is reused (and thus fails)

        /* Create topic */
        test_create_topic(p, topic, partition_cnt, 3);

        /* Create consumer */
        c_conf = conf;
        test_conf_set(c_conf, "isolation.level", "read_committed");
        c = test_create_consumer(topic, NULL, c_conf, NULL);

        /* Subscribe to topic */
        test_consumer_subscribe(c, topic);

        /* Wait for assignment to make sure consumer is fetching messages
         * below, so we can use the poll_no_msgs() timeout to
         * determine that messages were indeed aborted. */
        test_consumer_wait_assignment(c);

        /* Init transactions */
        TEST_CALL_ERROR__(rd_kafka_init_transactions(p, 30*1000));

        for (i = 0 ; i < _TXNCNT ; i++) {
                int wait_msgcnt = 0;

                TEST_SAY(_C_BLU "txn[%d]: Begin transaction: %s\n" _C_CLR,
                         i, txn[i].desc);

                /* Begin a transaction */
                TEST_CALL_ERROR__(rd_kafka_begin_transaction(p));

                /* If the transaction is aborted it is okay if
                 * messages fail producing, since they'll be
                 * purged from queues. */
                test_curr->ignore_dr_err = txn[i].abort;

                /* Produce messages */
                txn[i].testid = test_id_generate();
                TEST_SAY("txn[%d]: Produce %d messages %ssynchronously "
                         "with testid %"PRIu64"\n",
                         i, txn[i].msgcnt,
                         txn[i].sync ? "" : "a",
                         txn[i].testid);

                if (!txn[i].batch) {
                        if (txn[i].sync)
                                test_produce_msgs2(p, topic, txn[i].testid,
                                                   RD_KAFKA_PARTITION_UA, 0,
                                                   txn[i].msgcnt, NULL, 0);
                        else
                                test_produce_msgs2_nowait(p, topic,
                                                          txn[i].testid,
                                                          RD_KAFKA_PARTITION_UA,
                                                          0,
                                                          txn[i].msgcnt,
                                                          NULL, 0,
                                                          &wait_msgcnt);
                } else if (txn[i].batch_any) {
                        /* Batch: use any partition */
                        do_produce_batch(p, topic, txn[i].testid,
                                         RD_KAFKA_PARTITION_UA,
                                         0, txn[i].msgcnt);
                } else {
                        /* Batch: specific partition */
                        do_produce_batch(p, topic, txn[i].testid,
                                         1 /* partition */,
                                         0, txn[i].msgcnt);
                }


                /* Abort or commit transaction */
                TEST_SAY("txn[%d]: %s" _C_CLR " transaction\n",
                         i, txn[i].abort ? _C_RED "Abort" : _C_GRN "Commit");
                if (txn[i].abort) {
                        test_curr->ignore_dr_err = rd_true;
                        TEST_CALL_ERROR__(rd_kafka_abort_transaction(p,
                                                                     30*1000));
                } else {
                        test_curr->ignore_dr_err = rd_false;
                        TEST_CALL_ERROR__(rd_kafka_commit_transaction(p,
                                                                      30*1000));
                }

                if (!txn[i].sync)
                        /* Wait for delivery reports */
                        test_wait_delivery(p, &wait_msgcnt);

                /* Consume messages */
                if (txn[i].abort)
                        test_consumer_poll_no_msgs(txn[i].desc, c,
                                                   txn[i].testid, 3000);
                else
                        test_consumer_poll(txn[i].desc, c,
                                           txn[i].testid, partition_cnt, 0,
                                           txn[i].msgcnt, NULL);

                TEST_SAY(_C_GRN "txn[%d]: Finished successfully: %s\n" _C_CLR,
                         i, txn[i].desc);
        }

        rd_kafka_destroy(p);

        test_consumer_close(c);
        rd_kafka_destroy(c);
}


/**
 * @brief Consumes \p cnt messages and returns them in the provided array
 *        which must be pre-allocated.
 */
static void consume_messages (rd_kafka_t *c,
                              rd_kafka_message_t **msgs, int msgcnt) {
        int i = 0;
        while (i < msgcnt) {
                msgs[i] = rd_kafka_consumer_poll(c, 1000);
                if (!msgs[i])
                        continue;

                if (msgs[i]->err) {
                        TEST_SAY("%s consumer error: %s\n",
                                 rd_kafka_name(c),
                                 rd_kafka_message_errstr(msgs[i]));
                        rd_kafka_message_destroy(msgs[i]);
                        continue;
                }

                TEST_SAYL(3, "%s: consumed message %s [%d] @ %"PRId64"\n",
                          rd_kafka_name(c),
                          rd_kafka_topic_name(msgs[i]->rkt),
                          msgs[i]->partition, msgs[i]->offset);


                i++;
        }
}

static void destroy_messages (rd_kafka_message_t **msgs, int msgcnt) {
        while (msgcnt-- > 0)
                rd_kafka_message_destroy(msgs[msgcnt]);
}


/**
 * @brief Test a transactional consumer + transactional producer combo,
 *        mimicing a streams job.
 *
 * One input topic produced to by transactional producer 1,
 * consumed by transactional consumer 1, which forwards messages
 * to transactional producer 2 that writes messages to output topic,
 * which is consumed and verified by transactional consumer 2.
 *
 * Every 3rd transaction is aborted.
 */
void do_test_consumer_producer_txn (void) {
        char *input_topic =
                rd_strdup(test_mk_topic_name("0103-transactions-input", 1));
        char *output_topic =
                rd_strdup(test_mk_topic_name("0103-transactions-output", 1));
        const char *c1_groupid = input_topic;
        const char *c2_groupid = output_topic;
        rd_kafka_t *p1, *p2, *c1, *c2;
        rd_kafka_conf_t *conf, *tmpconf, *c1_conf;
        uint64_t testid;
#define _MSGCNT (10 * 30)
        const int txncnt = 10;
        const int msgcnt = _MSGCNT;
        int txn;
        int committed_msgcnt = 0;
        test_msgver_t expect_mv, actual_mv;

        TEST_SAY(_C_BLU "[ Transactional test with %d transactions ]\n",
                 txncnt);

        test_conf_init(&conf, NULL, 30);

        testid = test_id_generate();

        /*
         *
         * Producer 1
         *     |
         *     v
         * input topic
         *     |
         *     v
         * Consumer 1    }
         *     |         } transactional streams job
         *     v         }
         * Producer 2    }
         *     |
         *     v
         * output tpic
         *     |
         *     v
         * Consumer 2
         */


        /* Create Producer 1 and seed input topic */
        tmpconf = rd_kafka_conf_dup(conf);
        test_conf_set(tmpconf, "transactional.id", input_topic);
        rd_kafka_conf_set_dr_msg_cb(tmpconf, test_dr_msg_cb);
        p1 = test_create_handle(RD_KAFKA_PRODUCER, tmpconf);

        /* Create input and output topics */
        test_create_topic(p1, input_topic, 4, 3);
        test_create_topic(p1, output_topic, 4, 3);

        /* Seed input topic with messages */
        TEST_CALL_ERROR__(rd_kafka_init_transactions(p1, 30*1000));
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(p1));
        test_produce_msgs2(p1, input_topic, testid, RD_KAFKA_PARTITION_UA,
                           0, msgcnt, NULL, 0);
        TEST_CALL_ERROR__(rd_kafka_commit_transaction(p1, 30*1000));

        rd_kafka_destroy(p1);

        /* Create Consumer 1: reading msgs from input_topic (Producer 1) */
        tmpconf = rd_kafka_conf_dup(conf);
        test_conf_set(tmpconf, "isolation.level", "read_committed");
        test_conf_set(tmpconf, "auto.offset.reset", "earliest");
        test_conf_set(tmpconf, "enable.auto.commit", "false");
        c1_conf = rd_kafka_conf_dup(tmpconf);
        c1 = test_create_consumer(c1_groupid, NULL, tmpconf, NULL);
        test_consumer_subscribe(c1, input_topic);

        /* Create Producer 2 */
        tmpconf = rd_kafka_conf_dup(conf);
        test_conf_set(tmpconf, "transactional.id", output_topic);
        rd_kafka_conf_set_dr_msg_cb(tmpconf, test_dr_msg_cb);
        p2 = test_create_handle(RD_KAFKA_PRODUCER, tmpconf);
        TEST_CALL_ERROR__(rd_kafka_init_transactions(p2, 30*1000));

        /* Create Consumer 2: reading msgs from output_topic (Producer 2) */
        tmpconf = rd_kafka_conf_dup(conf);
        test_conf_set(tmpconf, "isolation.level", "read_committed");
        test_conf_set(tmpconf, "auto.offset.reset", "earliest");
        c2 = test_create_consumer(c2_groupid, NULL, tmpconf, NULL);
        test_consumer_subscribe(c2, output_topic);

        rd_kafka_conf_destroy(conf);

        /* Keep track of what messages to expect on the output topic */
        test_msgver_init(&expect_mv, testid);

        for (txn = 0 ; txn < txncnt ; txn++) {
                int msgcnt2 = 10 * (1 + (txn % 3));
                rd_kafka_message_t *msgs[_MSGCNT];
                int i;
                rd_bool_t do_abort = !(txn % 3);
                rd_bool_t recreate_consumer = do_abort && txn == 3;
                rd_kafka_topic_partition_list_t *offsets;
                rd_kafka_resp_err_t err;
                rd_kafka_consumer_group_metadata_t *c1_cgmetadata;
                int remains = msgcnt2;

                TEST_SAY(_C_BLU "Begin transaction #%d/%d "
                         "(msgcnt=%d, do_abort=%s, recreate_consumer=%s)\n",
                         txn, txncnt, msgcnt2,
                         do_abort ? "true":"false",
                         recreate_consumer ? "true":"false");

                consume_messages(c1, msgs, msgcnt2);

                TEST_CALL_ERROR__(rd_kafka_begin_transaction(p2));

                for (i = 0 ; i < msgcnt2 ; i++) {
                        rd_kafka_message_t *msg = msgs[i];

                        if (!do_abort) {
                                /* The expected msgver based on the input topic
                                 * will be compared to the actual msgver based
                                 * on the output topic, so we need to
                                 * override the topic name to match
                                 * the actual msgver's output topic. */
                                test_msgver_add_msg0(__FUNCTION__, __LINE__,
                                                     rd_kafka_name(p2),
                                                     &expect_mv, msg,
                                                     output_topic);
                                committed_msgcnt++;
                        }

                        err = rd_kafka_producev(p2,
                                                RD_KAFKA_V_TOPIC(output_topic),
                                                RD_KAFKA_V_KEY(msg->key,
                                                               msg->key_len),
                                                RD_KAFKA_V_VALUE(msg->payload,
                                                                 msg->len),
                                                RD_KAFKA_V_MSGFLAGS(
                                                        RD_KAFKA_MSG_F_COPY),
                                                RD_KAFKA_V_OPAQUE(&remains),
                                                RD_KAFKA_V_END);
                        TEST_ASSERT(!err, "produce failed: %s",
                                    rd_kafka_err2str(err));

                        rd_kafka_poll(p2, 0);
                }

                destroy_messages(msgs, msgcnt2);

                err = rd_kafka_assignment(c1, &offsets);
                TEST_ASSERT(!err, "failed to get consumer assignment: %s",
                            rd_kafka_err2str(err));

                err = rd_kafka_position(c1, offsets);
                TEST_ASSERT(!err, "failed to get consumer position: %s",
                            rd_kafka_err2str(err));

                c1_cgmetadata = rd_kafka_consumer_group_metadata(c1);
                TEST_ASSERT(c1_cgmetadata != NULL,
                            "failed to get consumer group metadata");

                TEST_CALL_ERROR__(
                        rd_kafka_send_offsets_to_transaction(
                                p2, offsets, c1_cgmetadata, -1));


                rd_kafka_consumer_group_metadata_destroy(c1_cgmetadata);

                rd_kafka_topic_partition_list_destroy(offsets);


                if (do_abort) {
                        test_curr->ignore_dr_err = rd_true;
                        TEST_CALL_ERROR__(rd_kafka_abort_transaction(
                                                  p2, 30*1000));
                } else {
                        test_curr->ignore_dr_err = rd_false;
                        TEST_CALL_ERROR__(rd_kafka_commit_transaction(
                                                  p2, 30*1000));
                }

                TEST_ASSERT(remains == 0,
                            "expected no remaining messages "
                            "in-flight/in-queue, got %d", remains);


                if (recreate_consumer) {
                        /* Recreate the consumer to pick up
                         * on the committed offset. */
                        TEST_SAY("Recreating consumer 1\n");
                        rd_kafka_consumer_close(c1);
                        rd_kafka_destroy(c1);

                        c1 = test_create_consumer(c1_groupid, NULL, c1_conf,
                                                  NULL);
                        test_consumer_subscribe(c1, input_topic);
                }
        }

        test_msgver_init(&actual_mv, testid);

        test_consumer_poll("Verify output topic", c2, testid,
                           -1, 0, committed_msgcnt, &actual_mv);

        test_msgver_verify_compare("Verify output topic",
                                   &actual_mv, &expect_mv,
                                   TEST_MSGVER_ALL);

        test_msgver_clear(&actual_mv);
        test_msgver_clear(&expect_mv);

        rd_kafka_consumer_close(c1);
        rd_kafka_consumer_close(c2);
        rd_kafka_destroy(c1);
        rd_kafka_destroy(c2);
        rd_kafka_destroy(p2);

        rd_free(input_topic);
        rd_free(output_topic);
}


/**
 * @brief Testing misuse of the transaction API.
 */
static void do_test_misuse_txn (void) {
        const char *topic = test_mk_topic_name("0103-test_misuse_txn", 1);
        rd_kafka_t *p;
        rd_kafka_conf_t *conf;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t fatal_err;
        char errstr[512];
        int i;

        /*
         * transaction.timeout.ms out of range (from broker's point of view)
         */
        TEST_SAY("[ Test out-of-range transaction.timeout.ms ]\n");
        test_conf_init(&conf, NULL, 10);

        test_conf_set(conf, "transactional.id", topic);
        test_conf_set(conf, "transaction.timeout.ms", "2147483647");

        p = test_create_handle(RD_KAFKA_PRODUCER, conf);

        error = rd_kafka_init_transactions(p, 10*1000);
        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                    RD_KAFKA_RESP_ERR_INVALID_TRANSACTION_TIMEOUT,
                    "Expected error ERR_INVALID_TRANSACTION_TIMEOUT, "
                    "not %s: %s",
                    rd_kafka_error_name(error),
                    error ? rd_kafka_error_string(error) : "");
        TEST_ASSERT(rd_kafka_error_is_fatal(error),
                    "Expected error to have is_fatal() set");
        rd_kafka_error_destroy(error);
        /* Check that a fatal error is raised */
        fatal_err = rd_kafka_fatal_error(p, errstr, sizeof(errstr));
        TEST_ASSERT(fatal_err == RD_KAFKA_RESP_ERR_INVALID_TRANSACTION_TIMEOUT,
                    "Expected fatal error ERR_INVALID_TRANSACTION_TIMEOUT, "
                    "not %s: %s",
                    rd_kafka_err2name(fatal_err),
                    fatal_err ? errstr : "");

        rd_kafka_destroy(p);


        /*
         * Multiple calls to init_transactions(): finish on first.
         */
        TEST_SAY("[ Test multiple init_transactions(): finish on first ]\n");
        test_conf_init(&conf, NULL, 10);

        test_conf_set(conf, "transactional.id", topic);

        p = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(p, 30*1000));

        error = rd_kafka_init_transactions(p, 1);
        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__STATE,
                    "Expected ERR__STATE error, not %s",
                    rd_kafka_error_name(error));
        rd_kafka_error_destroy(error);

        TEST_CALL_ERROR__(rd_kafka_begin_transaction(p));

        error = rd_kafka_init_transactions(p, 3*1000);
        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__STATE,
                    "Expected ERR__STATE error, not %s",
                    rd_kafka_error_name(error));
        rd_kafka_error_destroy(error);

        rd_kafka_destroy(p);


        /*
         * Multiple calls to init_transactions(): timeout on first.
         */
        TEST_SAY("[ Test multiple init_transactions(): timeout on first ]\n");
        test_conf_init(&conf, NULL, 10);

        test_conf_set(conf, "transactional.id", topic);

        p = test_create_handle(RD_KAFKA_PRODUCER, conf);

        error = rd_kafka_init_transactions(p, 1);
        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_SAY("error: %s, %d\n", rd_kafka_error_string(error), rd_kafka_error_is_retriable(error));
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected ERR__TIMED_OUT, not %s: %s",
                    rd_kafka_error_name(error),
                    rd_kafka_error_string(error));
        TEST_ASSERT(rd_kafka_error_is_retriable(error),
                    "Expected error to be retriable");
        rd_kafka_error_destroy(error);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(p, 30*1000));

        rd_kafka_destroy(p);


        /*
         * Multiple calls to init_transactions(): hysterical amounts
         */
        TEST_SAY("[ Test multiple init_transactions(): hysterical amounts ]\n");
        test_conf_init(&conf, NULL, 10);

        test_conf_set(conf, "transactional.id", topic);

        p = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* Call until init succeeds */
        for (i = 0 ; i < 5000 ; i++) {
                if (!(error = rd_kafka_init_transactions(p, 1)))
                        break;

                TEST_ASSERT(rd_kafka_error_is_retriable(error),
                            "Expected error to be retriable");
                rd_kafka_error_destroy(error);

                error = rd_kafka_begin_transaction(p);
                TEST_ASSERT(error, "Expected begin_transactions() to fail");
                TEST_ASSERT(rd_kafka_error_code(error) ==
                            RD_KAFKA_RESP_ERR__STATE,
                            "Expected begin_transactions() to fail "
                            "with STATE, not %s",
                            rd_kafka_error_name(error));

                rd_kafka_error_destroy(error);
        }

        TEST_SAY("init_transactions() succeeded after %d call(s)\n", i+1);

        /* Make sure a sub-sequent init call fails. */
        error = rd_kafka_init_transactions(p, 5*1000);
        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__STATE,
                    "Expected init_transactions() to fail with STATE, not %s",
                    rd_kafka_error_name(error));
        rd_kafka_error_destroy(error);

        /* But begin.. should work now */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(p));

        rd_kafka_destroy(p);
}


/**
 * @brief is_fatal_cb for fenced_txn test.
 */
static int fenced_txn_is_fatal_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                                   const char *reason) {
        TEST_SAY("is_fatal?: %s: %s\n", rd_kafka_err2str(err), reason);
        if (err == RD_KAFKA_RESP_ERR__FENCED) {
                TEST_SAY("Saw the expected fatal error\n");
                return 0;
        }
        return 1;
}


/**
 * @brief Check that transaction fencing is handled correctly.
 */
static void do_test_fenced_txn (rd_bool_t produce_after_fence) {
        const char *topic = test_mk_topic_name("0103_fenced_txn", 1);
        rd_kafka_conf_t *conf;
        rd_kafka_t *p1, *p2;
        rd_kafka_error_t *error;
        uint64_t testid;

        TEST_SAY(_C_BLU "[ Fenced producer transactions "
                 "(%sproduce after fence)]\n",
                 produce_after_fence ? "" : "do not ");

        if (produce_after_fence)
                test_curr->is_fatal_cb = fenced_txn_is_fatal_cb;

        test_curr->ignore_dr_err = rd_false;

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 30);

        test_conf_set(conf, "transactional.id", topic);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        p1 = test_create_handle(RD_KAFKA_PRODUCER, rd_kafka_conf_dup(conf));
        p2 = test_create_handle(RD_KAFKA_PRODUCER, rd_kafka_conf_dup(conf));
        rd_kafka_conf_destroy(conf);

        TEST_CALL_ERROR__(rd_kafka_init_transactions(p1, 30*1000));

        /* Begin a transaction */
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(p1));

        /* Produce some messages */
        test_produce_msgs2(p1, topic, testid, RD_KAFKA_PARTITION_UA,
                           0, 10, NULL, 0);

        /* Initialize transactions on producer 2, this should
         * fence off producer 1. */
        TEST_CALL_ERROR__(rd_kafka_init_transactions(p2, 30*1000));

        if (produce_after_fence) {
                /* This will fail hard since the epoch was bumped. */
                TEST_SAY("Producing after producing fencing\n");
                test_curr->ignore_dr_err = rd_true;
                test_produce_msgs2(p1, topic, testid, RD_KAFKA_PARTITION_UA,
                                   0, 10, NULL, 0);
        }


        error = rd_kafka_commit_transaction(p1, 30*1000);

        if (produce_after_fence) {
                TEST_ASSERT(rd_kafka_fatal_error(p1, NULL, 0),
                            "Expected a fatal error to have been raised");

                TEST_ASSERT(error, "Expected commit_transaction() to fail");
                TEST_ASSERT(rd_kafka_error_is_fatal(error),
                            "Expected commit_transaction() to return a "
                            "fatal error");
                TEST_ASSERT(!rd_kafka_error_txn_requires_abort(error),
                            "Expected commit_transaction() not to return an "
                            "abortable error");
                TEST_ASSERT(!rd_kafka_error_is_retriable(error),
                            "Expected commit_transaction() not to return a "
                            "retriable error");
                TEST_ASSERT(rd_kafka_error_code(error) ==
                            RD_KAFKA_RESP_ERR__STATE /* FIXME ? */,
                            "Expected commit_transaction() to return %s, "
                            "not %s: %s",
                            rd_kafka_err2name(RD_KAFKA_RESP_ERR__STATE),
                            rd_kafka_error_name(error),
                            rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
        } else {
                TEST_ASSERT(!error,
                            "commit_transaction() should not have failed: "
                            "%s: %s",
                            rd_kafka_error_name(error),
                            rd_kafka_error_string(error));
        }


        rd_kafka_destroy(p1);
        rd_kafka_destroy(p2);

        /* Make sure no messages were committed. */
        test_consume_txn_msgs_easy(topic, topic, testid,
                                   test_get_partition_count(NULL, topic,
                                                            10*1000),
                                   0, NULL);

        TEST_SAY(_C_GRN "[ Fenced producer transactions "
                 "(produce_after_fence=%s) succeeded ]\n",
                 produce_after_fence ? "yes" : "no");
}

int main_0103_transactions (int argc, char **argv) {

        do_test_misuse_txn();
        do_test_basic_producer_txn();
        do_test_consumer_producer_txn();
        do_test_fenced_txn(rd_false /* no produce after fencing */);
        do_test_fenced_txn(rd_true /* produce after fencing */);

        return 0;
}



/**
 * @brief Transaction tests that don't require a broker.
 */
static void do_test_txn_local (void) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *p;
        rd_kafka_error_t *error;
        test_timing_t t_init;
        int timeout_ms = 7 * 1000;

        /*
         * No transactional.id, init_transactions() should fail.
         */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", NULL);

        p = test_create_handle(RD_KAFKA_PRODUCER, conf);

        error = rd_kafka_init_transactions(p, 10);
        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                    RD_KAFKA_RESP_ERR__NOT_CONFIGURED,
                    "Expected ERR__NOT_CONFIGURED, not %s",
                    rd_kafka_error_name(error));
        rd_kafka_error_destroy(error);

        rd_kafka_destroy(p);


        /*
         * No brokers, init_transactions() should time out according
         * to the timeout.
         */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", NULL);
        test_conf_set(conf, "transactional.id", "test");
        p = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("Waiting for init_transactions() timeout %d ms\n",
                 timeout_ms);

        test_timeout_set((timeout_ms + 2000) / 1000);

        TIMING_START(&t_init, "init_transactions()");
        error = rd_kafka_init_transactions(p, timeout_ms);
        TIMING_STOP(&t_init);
        TEST_ASSERT(error, "Expected init_transactions() to fail");
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__TIMED_OUT,
                    "Expected RD_KAFKA_RESP_ERR__TIMED_OUT, "
                    "not %s: %s",
                    rd_kafka_error_name(error),
                    rd_kafka_error_string(error));

        TEST_SAY("init_transactions() failed as expected: %s\n",
                 rd_kafka_error_string(error));

        rd_kafka_error_destroy(error);

        TIMING_ASSERT(&t_init, timeout_ms - 2000, timeout_ms + 5000);

        rd_kafka_destroy(p);
}


int main_0103_transactions_local (int argc, char **argv) {

        do_test_txn_local();

        return 0;
}
