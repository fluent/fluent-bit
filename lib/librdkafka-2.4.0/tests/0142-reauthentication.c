/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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

static int delivered_msg = 0;
static int expect_err    = 0;
static int error_seen    = 0;

static void
dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
        if (rkmessage->err)
                TEST_FAIL("Message delivery failed: %s\n",
                          rd_kafka_err2str(rkmessage->err));
        else {
                delivered_msg++;
        }
}

static void
auth_error_cb(rd_kafka_t *rk, int err, const char *reason, void *opaque) {
        if (expect_err && (err == RD_KAFKA_RESP_ERR__AUTHENTICATION ||
                           err == RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN)) {
                TEST_SAY("Expected error: %s: %s\n", rd_kafka_err2str(err),
                         reason);
                error_seen = rd_true;
        } else
                TEST_FAIL("Unexpected error: %s: %s", rd_kafka_err2str(err),
                          reason);
        rd_kafka_yield(rk);
}


/* Test producer message loss while reauth happens between produce. */
void do_test_producer(int64_t reauth_time, const char *topic) {
        rd_kafka_topic_t *rkt = NULL;
        rd_kafka_conf_t *conf = NULL;
        rd_kafka_t *rk        = NULL;
        uint64_t testid       = test_id_generate();
        rd_kafka_resp_err_t err;
        int msgrate, msgcnt, sent_msg;
        test_timing_t t_produce;

        msgrate = 200; /* msg/sec */
        /* Messages should be produced such that at least one reauth happens.
         * The 1.2 is added as a buffer to avoid flakiness. */
        msgcnt        = msgrate * reauth_time / 1000 * 1.2;
        delivered_msg = 0;
        sent_msg      = 0;

        SUB_TEST("test producer message loss while reauthenticating");

        test_conf_init(&conf, NULL, 30);
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_producer_topic(rk, topic, NULL);

        /* Create the topic to make sure connections are up and ready. */
        err = test_auto_create_topic_rkt(rk, rkt, tmout_multip(5000));
        TEST_ASSERT(!err, "topic creation failed: %s", rd_kafka_err2str(err));

        TIMING_START(&t_produce, "PRODUCE");
        /* Produce enough messages such that we have time enough for at least
         * one reauth. */
        test_produce_msgs_nowait(rk, rkt, testid, 0, 0, msgcnt, NULL, 0,
                                 msgrate, &sent_msg);
        TIMING_STOP(&t_produce);

        rd_kafka_flush(rk, 10 * 1000);

        TEST_ASSERT(TIMING_DURATION(&t_produce) >= reauth_time * 1000,
                    "time enough for one reauth should pass (%ld vs %ld)",
                    TIMING_DURATION(&t_produce), reauth_time * 1000);
        TEST_ASSERT(delivered_msg == sent_msg,
                    "did not deliver as many messages as sent (%d vs %d)",
                    delivered_msg, sent_msg);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}

/* Test consumer message loss while reauth happens between consume. */
void do_test_consumer(int64_t reauth_time, const char *topic) {
        uint64_t testid;
        rd_kafka_t *p1;
        rd_kafka_t *c1;
        rd_kafka_conf_t *conf;
        int64_t start_time = 0;
        int64_t wait_time  = reauth_time * 1.2 * 1000;
        int recv_cnt = 0, sent_cnt = 0;

        SUB_TEST("test consumer message loss while reauthenticating");

        testid = test_id_generate();

        test_conf_init(&conf, NULL, 30);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        p1 = test_create_handle(RD_KAFKA_PRODUCER, rd_kafka_conf_dup(conf));

        test_create_topic(p1, topic, 1, 3);
        TEST_SAY("Topic: %s is created\n", topic);

        test_conf_set(conf, "auto.offset.reset", "earliest");
        c1 = test_create_consumer(topic, NULL, conf, NULL);
        test_consumer_subscribe(c1, topic);

        start_time = test_clock();
        while ((test_clock() - start_time) <= wait_time) {
                /* Produce one message. */
                test_produce_msgs2(p1, topic, testid, 0, 0, 1, NULL, 0);
                sent_cnt++;

                rd_kafka_message_t *rkm = rd_kafka_consumer_poll(c1, 100);
                if (!rkm || rkm->err) {
                        /* Ignore errors. Add a flush for good measure so maybe
                         * we'll have messages in the next iteration. */
                        rd_kafka_flush(p1, 50);
                        continue;
                }
                recv_cnt++;
                rd_kafka_message_destroy(rkm);

                /* An approximate way of maintaining the message rate as 200
                 * msg/s */
                rd_usleep(1000 * 50, NULL);
        }

        /* Final flush and receive any remaining messages. */
        rd_kafka_flush(p1, 10 * 1000);
        recv_cnt +=
            test_consumer_poll_timeout("timeout", c1, testid, -1, -1,
                                       sent_cnt - recv_cnt, NULL, 10 * 1000);

        test_consumer_close(c1);

        TEST_ASSERT(sent_cnt == recv_cnt,
                    "did not receive as many messages as sent (%d vs %d)",
                    sent_cnt, recv_cnt);

        rd_kafka_destroy(p1);
        rd_kafka_destroy(c1);
        SUB_TEST_PASS();
}



/* Test produce from a transactional producer while there is a reauth, and check
 * consumed messages for a committed or an aborted transaction. */
void do_test_txn_producer(int64_t reauth_time,
                          const char *topic,
                          rd_bool_t abort_txn) {
        rd_kafka_topic_t *rkt = NULL;
        rd_kafka_conf_t *conf = NULL;
        rd_kafka_t *rk        = NULL;
        uint64_t testid       = test_id_generate();
        rd_kafka_resp_err_t err;
        int msgrate, msgcnt, sent_msg;
        test_timing_t t_produce;

        delivered_msg = 0;
        sent_msg      = 0;
        msgrate       = 200; /* msg/sec */
        /* Messages should be produced such that at least one reauth happens.
         * The 1.2 is added as a buffer to avoid flakiness. */
        msgcnt = msgrate * reauth_time / 1000 * 1.2;

        SUB_TEST("test reauth in the middle of a txn, txn is %s",
                 abort_txn ? "aborted" : "committed");

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "transactional.id", topic);
        test_conf_set(conf, "transaction.timeout.ms",
                      tsprintf("%ld", (int64_t)(reauth_time * 1.2 + 60000)));
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_producer_topic(rk, topic, NULL);

        err = test_auto_create_topic_rkt(rk, rkt, tmout_multip(5000));
        TEST_ASSERT(!err, "topic creation failed: %s", rd_kafka_err2str(err));

        TEST_CALL_ERROR__(rd_kafka_init_transactions(rk, -1));
        TEST_CALL_ERROR__(rd_kafka_begin_transaction(rk));


        TIMING_START(&t_produce, "PRODUCE");
        /* Produce enough messages such that we have time enough for at least
         * one reauth. */
        test_produce_msgs_nowait(rk, rkt, testid, 0, 0, msgcnt, NULL, 0,
                                 msgrate, &sent_msg);
        TIMING_STOP(&t_produce);

        rd_kafka_flush(rk, 10 * 1000);

        TEST_ASSERT(TIMING_DURATION(&t_produce) >= reauth_time * 1000,
                    "time enough for one reauth should pass (%ld vs %ld)",
                    TIMING_DURATION(&t_produce), reauth_time * 1000);
        TEST_ASSERT(delivered_msg == sent_msg,
                    "did not deliver as many messages as sent (%d vs %d)",
                    delivered_msg, sent_msg);

        if (abort_txn) {
                rd_kafka_t *c = NULL;

                TEST_CALL_ERROR__(rd_kafka_abort_transaction(rk, 30 * 1000));

                /* We can reuse conf because the old one's been moved to rk
                 * already. */
                test_conf_init(&conf, NULL, 30);
                test_conf_set(conf, "isolation.level", "read_committed");
                c = test_create_consumer("mygroup", NULL, conf, NULL);
                test_consumer_poll_no_msgs("mygroup", c, testid, 10 * 1000);

                rd_kafka_destroy(c);
        } else {
                TEST_CALL_ERROR__(rd_kafka_commit_transaction(rk, 30 * 1000));
                test_consume_txn_msgs_easy("mygroup", topic, testid, -1,
                                           sent_msg, NULL);
        }

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/* Check reauthentication in case of OAUTHBEARER mechanism, with different
 * reauth times and token lifetimes. */
void do_test_oauthbearer(int64_t reauth_time,
                         const char *topic,
                         int64_t token_lifetime_ms,
                         rd_bool_t use_sasl_queue) {
        rd_kafka_topic_t *rkt = NULL;
        rd_kafka_conf_t *conf = NULL;
        rd_kafka_t *rk        = NULL;
        uint64_t testid       = test_id_generate();
        rd_kafka_resp_err_t err;
        char *mechanism;
        int msgrate, msgcnt, sent_msg;
        test_timing_t t_produce;
        int token_lifetime_s = token_lifetime_ms / 1000;

        SUB_TEST(
            "test reauthentication with oauthbearer, reauth_time = %ld, "
            "token_lifetime = %ld",
            reauth_time, token_lifetime_ms);

        test_conf_init(&conf, NULL, 30);
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);
        rd_kafka_conf_enable_sasl_queue(conf, use_sasl_queue);

        mechanism = test_conf_get(conf, "sasl.mechanism");
        if (rd_strcasecmp(mechanism, "oauthbearer")) {
                rd_kafka_conf_destroy(conf);
                SUB_TEST_SKIP(
                    "`sasl.mechanism=OAUTHBEARER` is required, have %s\n",
                    mechanism);
        }

        test_conf_set(
            conf, "sasl.oauthbearer.config",
            tsprintf("principal=admin scope=requiredScope lifeSeconds=%d",
                     token_lifetime_s));
        test_conf_set(conf, "enable.sasl.oauthbearer.unsecure.jwt", "true");
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* Enable to background queue since we don't want to poll the SASL
         * queue. */
        if (use_sasl_queue)
                rd_kafka_sasl_background_callbacks_enable(rk);

        rkt = test_create_producer_topic(rk, topic, NULL);

        /* Create the topic to make sure connections are up and ready. */
        err = test_auto_create_topic_rkt(rk, rkt, tmout_multip(5000));
        TEST_ASSERT(!err, "topic creation failed: %s", rd_kafka_err2str(err));

        msgrate = 200; /* msg/sec */
        /* Messages should be produced such that at least one reauth happens.
         * The 1.2 is added as a buffer to avoid flakiness. */
        msgcnt        = msgrate * reauth_time / 1000 * 1.2;
        delivered_msg = 0;
        sent_msg      = 0;

        TIMING_START(&t_produce, "PRODUCE");
        test_produce_msgs_nowait(rk, rkt, testid, 0, 0, msgcnt, NULL, 0,
                                 msgrate, &sent_msg);
        TIMING_STOP(&t_produce);

        rd_kafka_flush(rk, 10 * 1000);

        TEST_ASSERT(TIMING_DURATION(&t_produce) >= reauth_time * 1000,
                    "time enough for one reauth should pass (%ld vs %ld)",
                    TIMING_DURATION(&t_produce), reauth_time * 1000);
        TEST_ASSERT(delivered_msg == sent_msg,
                    "did not deliver as many messages as sent (%d vs %d)",
                    delivered_msg, sent_msg);

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/* Check that credentials changed into wrong ones cause authentication errors.
 */
void do_test_reauth_failure(int64_t reauth_time, const char *topic) {
        rd_kafka_topic_t *rkt = NULL;
        rd_kafka_conf_t *conf = NULL;
        rd_kafka_t *rk        = NULL;
        uint64_t testid       = test_id_generate();
        char *mechanism;
        rd_kafka_resp_err_t err;
        int msgrate, msgcnt, sent_msg;
        test_timing_t t_produce;

        msgrate = 200; /* msg/sec */
        /* Messages should be produced such that at least one reauth happens.
         * The 1.2 is added as a buffer to avoid flakiness. */
        msgcnt     = msgrate * reauth_time / 1000 * 1.2;
        error_seen = 0;
        expect_err = 0;

        SUB_TEST("test reauth failure with wrong credentials for reauth");

        test_conf_init(&conf, NULL, 30);
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);
        rd_kafka_conf_set_error_cb(conf, auth_error_cb);

        mechanism = test_conf_get(conf, "sasl.mechanism");

        if (!rd_strcasecmp(mechanism, "oauthbearer")) {
                rd_kafka_conf_destroy(conf);
                SUB_TEST_SKIP(
                    "PLAIN or SCRAM mechanism is required is required, have "
                    "OAUTHBEARER");
        }

        rk  = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt = test_create_producer_topic(rk, topic, NULL);

        /* Create the topic to make sure connections are up and ready. */
        err = test_auto_create_topic_rkt(rk, rkt, tmout_multip(5000));
        TEST_ASSERT(!err, "topic creation failed: %s", rd_kafka_err2str(err));

        rd_kafka_sasl_set_credentials(rk, "somethingwhich", "isnotright");
        expect_err = 1;

        TIMING_START(&t_produce, "PRODUCE");
        /* Produce enough messages such that we have time enough for at least
         * one reauth. */
        test_produce_msgs_nowait(rk, rkt, testid, 0, 0, msgcnt, NULL, 0,
                                 msgrate, &sent_msg);
        TIMING_STOP(&t_produce);

        TEST_ASSERT(TIMING_DURATION(&t_produce) >= reauth_time * 1000,
                    "time enough for one reauth should pass (%ld vs %ld)",
                    TIMING_DURATION(&t_produce), reauth_time * 1000);
        TEST_ASSERT(error_seen, "should have had an authentication error");

        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


int main_0142_reauthentication(int argc, char **argv) {
        size_t broker_id_cnt;
        int32_t *broker_ids   = NULL;
        rd_kafka_conf_t *conf = NULL;
        const char *security_protocol, *sasl_mechanism;

        size_t i;
        int64_t reauth_time = INT64_MAX;
        const char *topic   = test_mk_topic_name(__FUNCTION__ + 5, 1);

        test_conf_init(&conf, NULL, 30);
        security_protocol = test_conf_get(NULL, "security.protocol");

        if (strncmp(security_protocol, "sasl", 4)) {
                rd_kafka_conf_destroy(conf);
                TEST_SKIP("Test requires SASL_PLAINTEXT or SASL_SSL, got %s\n",
                          security_protocol);
                return 0;
        }

        sasl_mechanism = test_conf_get(NULL, "sasl.mechanism");
        if (!rd_strcasecmp(sasl_mechanism, "oauthbearer"))
                test_conf_set(conf, "enable.sasl.oauthbearer.unsecure.jwt",
                              "true");

        rd_kafka_t *rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("Fetching broker IDs\n");
        broker_ids = test_get_broker_ids(rk, &broker_id_cnt);

        TEST_ASSERT(broker_id_cnt != 0);

        for (i = 0; i < broker_id_cnt; i++) {
                char *property_value = test_get_broker_config_entry(
                    rk, broker_ids[i], "connections.max.reauth.ms");

                int64_t parsed_value;

                if (!property_value)
                        continue;

                parsed_value = strtoll(property_value, NULL, 0);
                if (parsed_value < reauth_time)
                        reauth_time = parsed_value;

                free(property_value);
        }

        if (broker_ids)
                free(broker_ids);
        if (rk)
                rd_kafka_destroy(rk);

        if (reauth_time ==
                INT64_MAX /* denotes property is unset on all brokers */
            ||
            reauth_time == 0 /* denotes at least one broker without timeout */
        ) {
                TEST_SKIP(
                    "Test requires all brokers to have non-zero "
                    "connections.max.reauth.ms\n");
                return 0;
        }

        /* Each test (7 of them) will take slightly more than 1 reauth_time
         * interval. Additional 30s provide a reasonable buffer. */
        test_timeout_set(9 * reauth_time / 1000 + 30);


        do_test_consumer(reauth_time, topic);
        do_test_producer(reauth_time, topic);
        do_test_txn_producer(reauth_time, topic, rd_false /* abort txn */);
        do_test_txn_producer(reauth_time, topic, rd_true /* abort txn */);

        /* Case when token_lifetime is shorter than the maximum reauth time
         * configured on the broker.
         * In this case, the broker returns the time to the next
         * reauthentication based on the expiry provided in the token.
         * We should recreate the token and reauthenticate before this
         * reauth time. */
        do_test_oauthbearer(reauth_time, topic, reauth_time / 2, rd_true);
        do_test_oauthbearer(reauth_time, topic, reauth_time / 2, rd_false);
        /* Case when the token_lifetime is greater than the maximum reauth time
         * configured.
         * In this case, the broker returns the maximum reauth time configured.
         * We don't need to recreate the token, but we need to reauthenticate
         * using the same token. */
        do_test_oauthbearer(reauth_time, topic, reauth_time * 2, rd_true);
        do_test_oauthbearer(reauth_time, topic, reauth_time * 2, rd_false);

        do_test_reauth_failure(reauth_time, topic);

        return 0;
}
