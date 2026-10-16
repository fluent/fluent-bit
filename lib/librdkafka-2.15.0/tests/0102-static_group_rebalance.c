/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019-2022, Magnus Edenhill
 *               2025, Confluent Inc.
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
 * @name KafkaConsumer static membership tests
 *
 * Runs two consumers subscribing to multiple topics simulating various
 * rebalance scenarios with static group membership enabled.
 */

#define _CONSUMER_CNT 2

typedef struct _consumer_s {
        rd_kafka_t *rk;
        test_msgver_t *mv;
        int64_t assigned_at;
        int64_t revoked_at;
        int partition_cnt;
        rd_kafka_resp_err_t expected_rb_event;
        int curr_line;
} _consumer_t;


/**
 * @brief Call poll until a rebalance has been triggered
 */
static int static_member_wait_rebalance0(int line,
                                         _consumer_t *c,
                                         int64_t start,
                                         int64_t *target,
                                         int timeout_ms) {
        int64_t tmout = test_clock() + (timeout_ms * 1000);
        test_timing_t t_time;

        c->curr_line = line;

        TEST_SAY("line %d: %s awaiting %s event\n", line, rd_kafka_name(c->rk),
                 rd_kafka_err2name(c->expected_rb_event));

        TIMING_START(&t_time, "wait_rebalance");
        while (timeout_ms < 0 ? 1 : test_clock() <= tmout) {
                if (*target > start) {
                        c->curr_line = 0;
                        return 1;
                }
                test_consumer_poll_once(c->rk, c->mv, 1000);
        }
        TIMING_STOP(&t_time);

        c->curr_line = 0;

        TEST_SAY("line %d: %s timed out awaiting %s event\n", line,
                 rd_kafka_name(c->rk), rd_kafka_err2name(c->expected_rb_event));

        return 0;
}

#define static_member_expect_rebalance(C, START, TARGET, TIMEOUT_MS)           \
        do {                                                                   \
                if (!static_member_wait_rebalance0(__LINE__, C, START, TARGET, \
                                                   TIMEOUT_MS))                \
                        TEST_FAIL("%s: timed out waiting for %s event",        \
                                  rd_kafka_name((C)->rk),                      \
                                  rd_kafka_err2name((C)->expected_rb_event));  \
        } while (0)

#define static_member_wait_rebalance(C, START, TARGET, TIMEOUT_MS)             \
        static_member_wait_rebalance0(__LINE__, C, START, TARGET, TIMEOUT_MS)


static void rebalance_cb(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *parts,
                         void *opaque) {
        _consumer_t *c = opaque;

        TEST_ASSERT(c->expected_rb_event == err,
                    "line %d: %s: Expected rebalance event %s got %s\n",
                    c->curr_line, rd_kafka_name(rk),
                    rd_kafka_err2name(c->expected_rb_event),
                    rd_kafka_err2name(err));

        switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                TEST_SAY("line %d: %s Assignment (%d partition(s)):\n",
                         c->curr_line, rd_kafka_name(rk), parts->cnt);
                test_print_partition_list(parts);

                c->partition_cnt = parts->cnt;
                c->assigned_at   = test_clock();
                rd_kafka_assign(rk, parts);

                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                c->revoked_at = test_clock();
                rd_kafka_assign(rk, NULL);
                TEST_SAY("line %d: %s revoked %d partitions\n", c->curr_line,
                         rd_kafka_name(c->rk), parts->cnt);

                break;

        default:
                TEST_FAIL("rebalance failed: %s", rd_kafka_err2str(err));
                break;
        }

        /* Reset error */
        c->expected_rb_event = RD_KAFKA_RESP_ERR_NO_ERROR;

        /* prevent poll from triggering more than one rebalance event */
        rd_kafka_yield(rk);
}


static void do_test_static_group_rebalance(void) {
        rd_kafka_conf_t *conf;
        test_msgver_t mv;
        int64_t rebalance_start;
        _consumer_t c[_CONSUMER_CNT] = RD_ZERO_INIT;
        const int msgcnt             = 100;
        uint64_t testid              = test_id_generate();
        const char *topic =
            test_mk_topic_name("0102_static_group_rebalance", 1);
        char *topics = rd_strdup(tsprintf("^%s.*", topic));
        test_timing_t t_close;

        SUB_TEST();

        test_conf_init(&conf, NULL, 70);
        test_msgver_init(&mv, testid);
        c[0].mv = &mv;
        c[1].mv = &mv;

        test_create_topic_wait_exists(NULL, topic, 3, 1, 5000);
        test_produce_msgs_easy(topic, testid, RD_KAFKA_PARTITION_UA, msgcnt);

        test_conf_set(conf, "max.poll.interval.ms", "9000");
        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        /* Keep this interval higher than cluster metadata propagation
         * time to make sure no additional rebalances are triggered
         * when refreshing the full metadata with a regex subscription. */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "2000");
        test_conf_set(conf, "metadata.max.age.ms", "5000");
        test_conf_set(conf, "enable.partition.eof", "true");
        test_conf_set(conf, "group.instance.id", "consumer1");

        rd_kafka_conf_set_opaque(conf, &c[0]);
        c[0].rk = test_create_consumer(topic, rebalance_cb,
                                       rd_kafka_conf_dup(conf), NULL);

        rd_kafka_conf_set_opaque(conf, &c[1]);
        test_conf_set(conf, "group.instance.id", "consumer2");
        c[1].rk = test_create_consumer(topic, rebalance_cb,
                                       rd_kafka_conf_dup(conf), NULL);

        test_wait_topic_exists(c[1].rk, topic, 5000);

        test_consumer_subscribe(c[0].rk, topics);
        test_consumer_subscribe(c[1].rk, topics);

        /*
         * Static members enforce `max.poll.interval.ms` which may prompt
         * an unwanted rebalance while the other consumer awaits its assignment.
         * These members remain in the member list however so we must
         * interleave calls to poll while awaiting our assignment to avoid
         * unexpected rebalances being triggered.
         */
        rebalance_start        = test_clock();
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        while (!static_member_wait_rebalance(&c[0], rebalance_start,
                                             &c[0].assigned_at, 1000)) {
                /* keep consumer 2 alive while consumer 1 awaits
                 * its assignment
                 */
                c[1].curr_line = __LINE__;
                test_consumer_poll_once(c[1].rk, &mv, 0);
        }

        static_member_expect_rebalance(&c[1], rebalance_start,
                                       &c[1].assigned_at, -1);

        /*
         * Consume all the messages so we can watch for duplicates
         * after rejoin/rebalance operations.
         */
        c[0].curr_line = __LINE__;
        test_consumer_poll("serve.queue", c[0].rk, testid, c[0].partition_cnt,
                           0, -1, &mv);
        c[1].curr_line = __LINE__;
        test_consumer_poll("serve.queue", c[1].rk, testid, c[1].partition_cnt,
                           0, -1, &mv);

        test_msgver_verify("first.verify", &mv, TEST_MSGVER_ALL, 0, msgcnt);

        TEST_SAY("== Testing consumer restart ==\n");

        /* Only c[1] should exhibit rebalance behavior */
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        TIMING_START(&t_close, "consumer restart");
        test_consumer_close(c[1].rk);
        rd_kafka_destroy(c[1].rk);
        c[1].rk = test_create_consumer(topic, rebalance_cb,
                                       rd_kafka_conf_dup(conf), NULL);
        rd_kafka_conf_destroy(conf);
        rd_kafka_poll_set_consumer(c[1].rk);

        test_consumer_subscribe(c[1].rk, topics);

        /* Await assignment */
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        rebalance_start        = test_clock();
        while (!static_member_wait_rebalance(&c[1], rebalance_start,
                                             &c[1].assigned_at, 1000)) {
                c[0].curr_line = __LINE__;
                test_consumer_poll_once(c[0].rk, &mv, 0);
        }
        TIMING_STOP(&t_close);

        /* Should complete before `session.timeout.ms` */
        TIMING_ASSERT(&t_close, 0, 6000);


        TEST_SAY("== Testing subscription expansion ==\n");

        /*
         * New topics matching the subscription pattern should cause
         * group rebalance
         */
        test_create_topic_wait_exists(c->rk, tsprintf("%snew", topic), 1, 1,
                                      5000);

        /* Await revocation */
        rebalance_start        = test_clock();
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        while (!static_member_wait_rebalance(&c[0], rebalance_start,
                                             &c[0].revoked_at, 1000)) {
                c[1].curr_line = __LINE__;
                test_consumer_poll_once(c[1].rk, &mv, 0);
        }

        static_member_expect_rebalance(&c[1], rebalance_start, &c[1].revoked_at,
                                       -1);

        /* Await assignment */
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        while (!static_member_wait_rebalance(&c[0], rebalance_start,
                                             &c[0].assigned_at, 1000)) {
                c[1].curr_line = __LINE__;
                test_consumer_poll_once(c[1].rk, &mv, 0);
        }

        static_member_expect_rebalance(&c[1], rebalance_start,
                                       &c[1].assigned_at, -1);

        TEST_SAY("== Testing consumer unsubscribe ==\n");

        /* Unsubscribe should send a LeaveGroupRequest invoking a rebalance */

        /* Send LeaveGroup incrementing generation by 1 */
        rebalance_start = test_clock();
        rd_kafka_unsubscribe(c[1].rk);

        /* Await revocation */
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        static_member_expect_rebalance(&c[1], rebalance_start, &c[1].revoked_at,
                                       -1);
        static_member_expect_rebalance(&c[0], rebalance_start, &c[0].revoked_at,
                                       -1);

        /* New cgrp generation with 1 member, c[0] */
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        static_member_expect_rebalance(&c[0], rebalance_start,
                                       &c[0].assigned_at, -1);

        /* Send JoinGroup bumping generation by 1 */
        rebalance_start = test_clock();
        test_consumer_subscribe(c[1].rk, topics);

        /* End previous single member generation */
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        static_member_expect_rebalance(&c[0], rebalance_start, &c[0].revoked_at,
                                       -1);

        /* Await assignment */
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        while (!static_member_wait_rebalance(&c[1], rebalance_start,
                                             &c[1].assigned_at, 1000)) {
                c[0].curr_line = __LINE__;
                test_consumer_poll_once(c[0].rk, &mv, 0);
        }

        static_member_expect_rebalance(&c[0], rebalance_start,
                                       &c[0].assigned_at, -1);

        TEST_SAY("== Testing max poll violation ==\n");
        /* max.poll.interval.ms should still be enforced by the consumer */

        /*
         * Stop polling consumer 2 until we reach
         * `max.poll.interval.ms` and is evicted from the group.
         */
        rebalance_start        = test_clock();
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        c[0].curr_line         = __LINE__;
        /* consumer 2 will time out and all partitions will be assigned to
         * consumer 1. */
        static_member_expect_rebalance(&c[0], rebalance_start, &c[0].revoked_at,
                                       -1);
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        static_member_expect_rebalance(&c[0], rebalance_start,
                                       &c[0].assigned_at, -1);

        /* consumer 2 restarts polling and re-joins the group */
        rebalance_start        = test_clock();
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        c[1].curr_line         = __LINE__;
        test_consumer_poll_expect_err(c[1].rk, testid, 1000,
                                      RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED);

        /* Await revocation */
        while (!static_member_wait_rebalance(&c[0], rebalance_start,
                                             &c[0].revoked_at, 1000)) {
                c[1].curr_line = __LINE__;
                test_consumer_poll_once(c[1].rk, &mv, 0);
        }

        static_member_expect_rebalance(&c[1], rebalance_start, &c[1].revoked_at,
                                       -1);

        /* Await assignment */
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        while (!static_member_wait_rebalance(&c[1], rebalance_start,
                                             &c[1].assigned_at, 1000)) {
                c[0].curr_line = __LINE__;
                test_consumer_poll_once(c[0].rk, &mv, 0);
        }

        static_member_expect_rebalance(&c[0], rebalance_start,
                                       &c[0].assigned_at, -1);

        TEST_SAY("== Testing `session.timeout.ms` member eviction ==\n");

        rebalance_start        = test_clock();
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        TIMING_START(&t_close, "consumer close");
        test_consumer_close(c[0].rk);
        rd_kafka_destroy(c[0].rk);

        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        static_member_expect_rebalance(&c[1], rebalance_start, &c[1].revoked_at,
                                       2 * 7000);

        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        static_member_expect_rebalance(&c[1], rebalance_start,
                                       &c[1].assigned_at, 2000);

        /* Should take at least as long as `session.timeout.ms` but less than
         * `max.poll.interval.ms`, but since we can't really know when
         * the last Heartbeat or SyncGroup request was sent we need to
         * allow some leeway on the minimum side (4s), and also some on
         * the maximum side (1s) for slow runtimes. */
        TIMING_ASSERT(&t_close, 6000 - 4000, 9000 + 1000);

        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        test_consumer_close(c[1].rk);
        rd_kafka_destroy(c[1].rk);

        test_msgver_verify("final.validation", &mv, TEST_MSGVER_ALL, 0, msgcnt);
        test_msgver_clear(&mv);
        free(topics);

        SUB_TEST_PASS();
}


/**
 * @brief Await a non-empty assignment for all consumers in \p c
 */
static void await_assignment_multi(const char *what, rd_kafka_t **c, int cnt) {
        rd_kafka_topic_partition_list_t *parts;
        int assignment_cnt;

        TEST_SAY("%s\n", what);

        do {
                int i;
                int timeout_ms = 1000;

                assignment_cnt = 0;

                for (i = 0; i < cnt; i++) {
                        test_consumer_poll_no_msgs("poll", c[i], 0, timeout_ms);
                        timeout_ms = 100;

                        if (!rd_kafka_assignment(c[i], &parts) && parts) {
                                TEST_SAY("%s has %d partition(s) assigned\n",
                                         rd_kafka_name(c[i]), parts->cnt);
                                if (parts->cnt > 0)
                                        assignment_cnt++;
                                rd_kafka_topic_partition_list_destroy(parts);
                        }
                }

        } while (assignment_cnt < cnt);
}


static const rd_kafka_t *valid_fatal_rk;
/**
 * @brief Tells test harness that fatal error should not fail the current test
 */
static int
is_fatal_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err, const char *reason) {
        return rk != valid_fatal_rk;
}

/**
 * @brief Test that consumer fencing raises a fatal error, classic protocol
 */
static void do_test_fenced_member_classic(void) {
        rd_kafka_t *c[3]; /* 0: consumer2b, 1: consumer1, 2: consumer2a */
        rd_kafka_conf_t *conf;
        const char *topic =
            test_mk_topic_name("0102_static_group_rebalance", 1);
        rd_kafka_message_t *rkm;
        char errstr[512];
        rd_kafka_resp_err_t err;

        SUB_TEST();

        test_conf_init(&conf, NULL, 30);

        test_create_topic(NULL, topic, 3, 1);

        test_conf_set(conf, "group.instance.id", "consumer1");
        test_conf_set(conf, "client.id", "consumer1");
        c[1] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);

        test_conf_set(conf, "group.instance.id", "consumer2");
        test_conf_set(conf, "client.id", "consumer2a");
        c[2] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);

        test_wait_topic_exists(c[2], topic, 5000);

        test_consumer_subscribe(c[1], topic);
        test_consumer_subscribe(c[2], topic);

        await_assignment_multi("Awaiting initial assignments", &c[1], 2);

        /* Create conflicting consumer */
        TEST_SAY("Creating conflicting consumer2 instance\n");
        test_conf_set(conf, "group.instance.id", "consumer2");
        test_conf_set(conf, "client.id", "consumer2b");
        c[0] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        rd_kafka_conf_destroy(conf);

        test_curr->is_fatal_cb = is_fatal_cb;
        valid_fatal_rk = c[2]; /* consumer2a is the consumer that should fail */

        test_consumer_subscribe(c[0], topic);

        /* consumer1 should not be affected (other than a rebalance which
         * we ignore here)... */
        test_consumer_poll_no_msgs("consumer1", c[1], 0, 5000);

        /* .. but consumer2a should now have been fenced off by consumer2b */
        rkm = rd_kafka_consumer_poll(c[2], 5000);
        TEST_ASSERT(rkm != NULL, "Expected error, not timeout");
        TEST_ASSERT(rkm->err == RD_KAFKA_RESP_ERR__FATAL,
                    "Expected ERR__FATAL, not %s: %s",
                    rd_kafka_err2str(rkm->err), rd_kafka_message_errstr(rkm));
        TEST_SAY("Fenced consumer returned expected: %s: %s\n",
                 rd_kafka_err2name(rkm->err), rd_kafka_message_errstr(rkm));
        rd_kafka_message_destroy(rkm);


        /* Read the actual error */
        err = rd_kafka_fatal_error(c[2], errstr, sizeof(errstr));
        TEST_SAY("%s fatal error: %s: %s\n", rd_kafka_name(c[2]),
                 rd_kafka_err2name(err), errstr);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_FENCED_INSTANCE_ID,
                    "Expected ERR_FENCED_INSTANCE_ID as fatal error, not %s",
                    rd_kafka_err2name(err));

        TEST_SAY("close\n");
        /* Close consumer2a, should also return a fatal error */
        err = rd_kafka_consumer_close(c[2]);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__FATAL,
                    "Expected close on %s to return ERR__FATAL, not %s",
                    rd_kafka_name(c[2]), rd_kafka_err2name(err));

        rd_kafka_destroy(c[2]);

        /* consumer2b and consumer1 should be fine and get their
         * assignments */
        await_assignment_multi("Awaiting post-fencing assignment", c, 2);

        rd_kafka_destroy(c[0]);
        rd_kafka_destroy(c[1]);

        SUB_TEST_PASS();
}

/**
 * @brief Test that consumer fencing raises a fatal error,
 *        consumer protocol (KIP-848).
 *        The difference with the behavior of the classic one is that
 *        the member that is fenced is the one that is joining the group
 *        and not the one that was already in the group.
 *        Also the error is ERR_UNRELEASED_INSTANCE_ID instead of
 *        ERR_FENCED_INSTANCE_ID.
 */
static void do_test_fenced_member_consumer(void) {
        rd_kafka_t *c[3]; /* 0: consumer2b, 1: consumer1, 2: consumer2a */
        rd_kafka_conf_t *conf;
        const char *topic =
            test_mk_topic_name("0102_static_group_rebalance", 1);
        rd_kafka_message_t *rkm;
        char errstr[512];
        rd_kafka_resp_err_t err;

        SUB_TEST();

        test_conf_init(&conf, NULL, 30);

        test_create_topic(NULL, topic, 3, 1);

        test_conf_set(conf, "group.instance.id", "consumer1");
        test_conf_set(conf, "client.id", "consumer1");
        c[1] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);

        test_conf_set(conf, "group.instance.id", "consumer2");
        test_conf_set(conf, "client.id", "consumer2a");
        c[2] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);

        test_wait_topic_exists(c[2], topic, 5000);

        test_consumer_subscribe(c[1], topic);
        test_consumer_subscribe(c[2], topic);

        await_assignment_multi("Awaiting initial assignments", &c[1], 2);

        /* Create conflicting consumer */
        TEST_SAY("Creating conflicting consumer 2 instance\n");
        test_conf_set(conf, "group.instance.id", "consumer2");
        test_conf_set(conf, "client.id", "consumer2b");
        c[0] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);
        rd_kafka_conf_destroy(conf);

        test_curr->is_fatal_cb = is_fatal_cb;
        valid_fatal_rk = c[0]; /* consumer2b is the consumer that should fail */

        test_consumer_subscribe(c[0], topic);

        /* consumer1 should not be affected (other than a rebalance which
         * we ignore here)... */
        test_consumer_poll_no_msgs("consumer1", c[1], 0, 5000);

        /* consumer2b should be fenced off on joining */
        rkm = rd_kafka_consumer_poll(c[0], 5000);
        TEST_ASSERT(rkm != NULL, "Expected error, not timeout");
        TEST_ASSERT(rkm->err == RD_KAFKA_RESP_ERR__FATAL,
                    "Expected ERR__FATAL, not %s: %s",
                    rd_kafka_err2str(rkm->err), rd_kafka_message_errstr(rkm));
        TEST_SAY("Fenced consumer returned expected: %s: %s\n",
                 rd_kafka_err2name(rkm->err), rd_kafka_message_errstr(rkm));
        rd_kafka_message_destroy(rkm);


        /* Read the actual error */
        err = rd_kafka_fatal_error(c[0], errstr, sizeof(errstr));
        TEST_SAY("%s fatal error: %s: %s\n", rd_kafka_name(c[0]),
                 rd_kafka_err2name(err), errstr);
        TEST_ASSERT(
            err == RD_KAFKA_RESP_ERR_UNRELEASED_INSTANCE_ID,
            "Expected ERR_UNRELEASED_INSTANCE_ID as fatal error, not %s",
            rd_kafka_err2name(err));

        TEST_SAY("close\n");
        /* Close consumer2b, should also return a fatal error */
        err = rd_kafka_consumer_close(c[0]);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__FATAL,
                    "Expected close on %s to return ERR__FATAL, not %s",
                    rd_kafka_name(c[0]), rd_kafka_err2name(err));

        rd_kafka_destroy(c[0]);

        /* consumer1 and consumer2a should be fine and get their
         * assignments */
        await_assignment_multi("Awaiting post-fencing assignment", &c[1], 2);

        rd_kafka_destroy(c[1]);
        rd_kafka_destroy(c[2]);

        SUB_TEST_PASS();
}
/**
 * @brief Create a new consumer with given \p boostraps
 *        \p group_id and \p group_instance_id .
 */
static rd_kafka_t *create_consumer(const char *bootstraps,
                                   const char *group_id,
                                   const char *group_instance_id) {
        rd_kafka_conf_t *conf;
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.instance.id", group_instance_id);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.partition.eof", "true");
        return test_create_consumer(group_id, NULL, conf, NULL);
}

/**
 * @brief Get generation id of consumer \p consumer .
 */
static int32_t consumer_generation_id(rd_kafka_t *consumer) {
        rd_kafka_consumer_group_metadata_t *group_metadata;
        int32_t generation_id;

        group_metadata = rd_kafka_consumer_group_metadata(consumer);
        generation_id =
            rd_kafka_consumer_group_metadata_generation_id(group_metadata);
        rd_kafka_consumer_group_metadata_destroy(group_metadata);
        return generation_id;
}

/**
 * @brief Check if the API key in \p request is the same as that
 *        pointed by \p opaque .
 */
static rd_bool_t is_api_key(rd_kafka_mock_request_t *request, void *opaque) {
        int32_t api_key = *(int32_t *)opaque;
        return rd_kafka_mock_request_api_key(request) == api_key;
}

/**
 * @enum do_test_static_membership_mock_variation_t
 * @brief Variations of the static membership mock test.
 */
typedef enum do_test_static_membership_mock_variation_t {
        /** Consumer 1 leaves with unsubscribe and rejoins the group */
        DO_TEST_STATIC_MEMBERSHIP_MOCK_VARIATION_SAME_INSTANCE = 0,
        /** Consumer 1 leaves with unsubscribe and a new consumer with same
         *  group.instance.id joins the group */
        DO_TEST_STATIC_MEMBERSHIP_MOCK_VARIATION_NEW_INSTANCE = 1,
        DO_TEST_STATIC_MEMBERSHIP_MOCK_VARIATION__CNT
} do_test_static_membership_mock_variation_t;

/**
 * @brief Static group membership tests with the mock cluster.
 *        Checks that consumer returns the same assignment
 *        and generation id after re-joining.
 *
 * @param variation Test variation to run.
 *
 * @sa `do_test_static_membership_mock_variation_t`
 */
static void do_test_static_membership_mock(
    do_test_static_membership_mock_variation_t variation) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        int32_t api_key   = RD_KAFKAP_ConsumerGroupHeartbeat;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        rd_kafka_t *consumer1, *consumer2, *consumer_1_to_destroy = NULL;
        int32_t prev_generation_id1, next_generation_id1, prev_generation_id2,
            next_generation_id2;
        rd_kafka_topic_partition_list_t *prev_assignment1, *prev_assignment2,
            *next_assignment1, *next_assignment2;

        SUB_TEST_QUICK(
            "%s",
            variation == DO_TEST_STATIC_MEMBERSHIP_MOCK_VARIATION_SAME_INSTANCE
                ? "with same instance"
                : "with new instance");

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 2, 3);

        TEST_SAY("Creating consumers\n");
        consumer1 = create_consumer(bootstraps, topic, "c1");
        consumer2 = create_consumer(bootstraps, topic, "c2");

        TEST_SAY("Subscribing consumers to topic \"%s\"\n", topic);
        test_consumer_subscribe(consumer1, topic);
        test_consumer_subscribe(consumer2, topic);

        TEST_SAY("Waiting one EOF of consumer 1\n");
        test_consumer_poll_exact("first consumer", consumer1, 0, 1, 0, 0,
                                 rd_true, NULL);
        TEST_SAY("Waiting one EOF of consumer 2\n");
        test_consumer_poll_exact("second consumer", consumer2, 0, 1, 0, 0,
                                 rd_true, NULL);

        prev_generation_id1 = consumer_generation_id(consumer1);
        prev_generation_id2 = consumer_generation_id(consumer2);
        TEST_CALL_ERR__(rd_kafka_assignment(consumer1, &prev_assignment1));
        TEST_CALL_ERR__(rd_kafka_assignment(consumer2, &prev_assignment2));
        TEST_ASSERT(prev_assignment1 != NULL,
                    "Expected assignment for consumer 1 before the change");
        TEST_ASSERT(prev_assignment2 != NULL,
                    "Expected assignment for consumer 2 before the change");

        TEST_SAY("Unsubscribing consumer 1\n");
        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_unsubscribe(consumer1));
        test_mock_wait_matching_requests(mcluster, 1, 1000, is_api_key,
                                         &api_key);
        rd_kafka_mock_stop_request_tracking(mcluster);

        if (variation ==
            DO_TEST_STATIC_MEMBERSHIP_MOCK_VARIATION_NEW_INSTANCE) {
                /* Don't destroy it immediately because the
                 * topic partition lists still hold a reference. */
                consumer_1_to_destroy = consumer1;

                TEST_SAY("Re-creating consumer 1\n");
                /* Re-create the consumer with same group and instance id. */
                consumer1 = create_consumer(bootstraps, topic, "c1");
        }

        TEST_SAY("Subscribing consumer 1 again\n");
        test_consumer_subscribe(consumer1, topic);
        test_consumer_wait_assignment(consumer1, rd_false);

        next_generation_id1 = consumer_generation_id(consumer1);
        next_generation_id2 = consumer_generation_id(consumer2);

        TEST_ASSERT(next_generation_id1 == prev_generation_id1,
                    "Expected same generation id for consumer 1, "
                    "got %d != %d",
                    prev_generation_id1, next_generation_id1);
        TEST_ASSERT(next_generation_id2 == prev_generation_id2,
                    "Expected same generation id for consumer 2, "
                    "got %d != %d",
                    prev_generation_id2, next_generation_id2);

        TEST_CALL_ERR__(rd_kafka_assignment(consumer1, &next_assignment1));
        TEST_CALL_ERR__(rd_kafka_assignment(consumer2, &next_assignment2));
        TEST_ASSERT(next_assignment1 != NULL,
                    "Expected assignment for consumer 1 after the change");
        TEST_ASSERT(next_assignment2 != NULL,
                    "Expected assignment for consumer 2 after the change");
        TEST_ASSERT(!test_partition_list_and_offsets_cmp(prev_assignment1,
                                                         next_assignment1),
                    "Expected same assignment for consumer 1 after the change");
        TEST_ASSERT(!test_partition_list_and_offsets_cmp(prev_assignment2,
                                                         next_assignment2),
                    "Expected same assignment for consumer 2 after the change");

        rd_kafka_topic_partition_list_destroy(prev_assignment1);
        rd_kafka_topic_partition_list_destroy(prev_assignment2);
        rd_kafka_topic_partition_list_destroy(next_assignment1);
        rd_kafka_topic_partition_list_destroy(next_assignment2);

        RD_IF_FREE(consumer_1_to_destroy, rd_kafka_destroy);
        rd_kafka_destroy(consumer1);
        rd_kafka_destroy(consumer2);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

int main_0102_static_group_rebalance(int argc, char **argv) {
        /* TODO: check again when regexes
         * will be supported by KIP-848 */
        if (test_consumer_group_protocol_classic()) {
                do_test_static_group_rebalance();
        }

        if (test_consumer_group_protocol_classic()) {
                do_test_fenced_member_classic();
        } else {
                do_test_fenced_member_consumer();
        }

        return 0;
}

int main_0102_static_group_rebalance_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);
        int variation;

        if (test_consumer_group_protocol_classic()) {
                TEST_SKIP(
                    "Static membership isn't implemented "
                    "in mock cluster for classic protocol\n");
                return 0;
        }

        for (variation = DO_TEST_STATIC_MEMBERSHIP_MOCK_VARIATION_SAME_INSTANCE;
             variation < DO_TEST_STATIC_MEMBERSHIP_MOCK_VARIATION__CNT;
             variation++) {
                do_test_static_membership_mock(variation);
        }

        return 0;
}
