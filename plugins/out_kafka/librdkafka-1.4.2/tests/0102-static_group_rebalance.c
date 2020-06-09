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
static int static_member_wait_rebalance0 (int line,
                                          _consumer_t *c, int64_t start,
                                          int64_t *target, int timeout_ms) {
        int64_t tmout = test_clock() + (timeout_ms * 1000);

        c->curr_line = line;

        TEST_SAY("line %d: %s awaiting %s event\n",
                 line, rd_kafka_name(c->rk),
                 rd_kafka_err2name(c->expected_rb_event));

        while (timeout_ms < 0 ? 1 : test_clock() <= tmout) {
                if (*target > start) {
                        c->curr_line = 0;
                        return 1;
                }
                test_consumer_poll_once(c->rk, c->mv, 1000);
        }

        c->curr_line = 0;

        TEST_SAY("line %d: %s timed out awaiting %s event\n",
                 line, rd_kafka_name(c->rk),
                 rd_kafka_err2name(c->expected_rb_event));

        return 0;
}

#define static_member_expect_rebalance(C,START,TARGET,TIMEOUT_MS) do {  \
                if (!static_member_wait_rebalance0(__LINE__,C,          \
                                                   START,TARGET,TIMEOUT_MS)) \
                        TEST_FAIL("%s: timed out waiting for %s event", \
                                  rd_kafka_name((C)->rk),               \
                                  rd_kafka_err2name((C)->expected_rb_event)); \
        } while (0)

#define static_member_wait_rebalance(C,START,TARGET,TIMEOUT_MS)         \
        static_member_wait_rebalance0(__LINE__,C, START,TARGET,TIMEOUT_MS)


static void rebalance_cb (rd_kafka_t *rk,
                          rd_kafka_resp_err_t err,
                          rd_kafka_topic_partition_list_t *parts,
                          void *opaque) {
        _consumer_t *c = opaque;

        TEST_ASSERT(c->expected_rb_event == err,
                    "line %d: %s: Expected rebalance event %s got %s\n",
                    c->curr_line, rd_kafka_name(rk),
                    rd_kafka_err2name(c->expected_rb_event),
                    rd_kafka_err2name(err));

        switch (err)
        {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                TEST_SAY("line %d: %s Assignment (%d partition(s)):\n",
                         c->curr_line, rd_kafka_name(rk), parts->cnt);
                test_print_partition_list(parts);

                c->partition_cnt = parts->cnt;
                c->assigned_at = test_clock();
                rd_kafka_assign(rk, parts);

                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                c->revoked_at = test_clock();
                rd_kafka_assign(rk, NULL);
                TEST_SAY("line %d: %s revoked %d partitions\n",
                         c->curr_line, rd_kafka_name(c->rk), parts->cnt);

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


static void do_test_static_group_rebalance (void) {
        rd_kafka_conf_t *conf;
        test_msgver_t mv;
        int64_t rebalance_start;
        _consumer_t c[_CONSUMER_CNT] = RD_ZERO_INIT;
        const int msgcnt = 100;
        uint64_t testid  = test_id_generate();
        const char *topic = test_mk_topic_name("0102_static_group_rebalance",
                                               1);
        char *topics = rd_strdup(tsprintf("^%s.*", topic));
        test_timing_t t_close;

        test_conf_init(&conf, NULL, 70);
        test_msgver_init(&mv, testid);
        c[0].mv = &mv;
        c[1].mv = &mv;

        test_create_topic(NULL, topic, 3, 1);
        test_produce_msgs_easy(topic, testid, RD_KAFKA_PARTITION_UA, msgcnt);

        test_conf_set(conf, "max.poll.interval.ms", "9000");
        test_conf_set(conf, "session.timeout.ms", "6000");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "500");
        test_conf_set(conf, "enable.partition.eof", "true");
        test_conf_set(conf, "group.instance.id", "consumer1");

        rd_kafka_conf_set_opaque(conf, &c[0]);
        c[0].rk = test_create_consumer(topic, rebalance_cb,
                                       rd_kafka_conf_dup(conf), NULL);

        rd_kafka_conf_set_opaque(conf, &c[1]);
        test_conf_set(conf, "group.instance.id", "consumer2");
        c[1].rk = test_create_consumer(topic, rebalance_cb,
                                       rd_kafka_conf_dup(conf), NULL);
        rd_kafka_conf_destroy(conf);

        test_consumer_subscribe(c[0].rk, topics);
        test_consumer_subscribe(c[1].rk, topics);

        /*
         * Static members enforce `max.poll.interval.ms` which may prompt
         * an unwanted rebalance while the other consumer awaits its assignment.
         * These members remain in the member list however so we must
         * interleave calls to poll while awaiting our assignment to avoid
         * unexpected rebalances being triggered.
         */
        rebalance_start = test_clock();
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
        test_consumer_poll("serve.queue",
                           c[0].rk, testid, c[0].partition_cnt, 0, -1, &mv);
        c[1].curr_line = __LINE__;
        test_consumer_poll("serve.queue",
                           c[1].rk, testid, c[1].partition_cnt, 0, -1, &mv);

        test_msgver_verify("first.verify", &mv, TEST_MSGVER_ALL, 0, msgcnt);

        TEST_SAY("== Testing consumer restart ==\n");
        conf = rd_kafka_conf_dup(rd_kafka_conf(c[1].rk));

        /* Only c[1] should exhibit rebalance behavior */
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        TIMING_START(&t_close, "consumer restart");
        test_consumer_close(c[1].rk);
        rd_kafka_destroy(c[1].rk);

        c[1].rk = test_create_handle(RD_KAFKA_CONSUMER, conf);
        rd_kafka_poll_set_consumer(c[1].rk);

        test_consumer_subscribe(c[1].rk, topics);

        /* Await assignment */
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        rebalance_start = test_clock();
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
        test_create_topic(c->rk, tsprintf("%snew", topic), 1, 1);

        /* Await revocation */
        rebalance_start = test_clock();
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        while (!static_member_wait_rebalance(&c[0], rebalance_start,
                                             &c[0].revoked_at, 1000)) {
                c[1].curr_line = __LINE__;
                test_consumer_poll_once(c[1].rk, &mv, 0);
        }

        static_member_expect_rebalance(&c[1], rebalance_start,
                                       &c[1].revoked_at, -1);

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
        static_member_expect_rebalance(&c[1], rebalance_start,
                                       &c[1].revoked_at, -1);
        static_member_expect_rebalance(&c[0], rebalance_start,
                                       &c[0].revoked_at, -1);

        /* New cgrp generation with 1 member, c[0] */
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        static_member_expect_rebalance(&c[0], rebalance_start,
                                       &c[0].assigned_at, -1);

        /* Send JoinGroup bumping generation by 1 */
        rebalance_start = test_clock();
        test_consumer_subscribe(c[1].rk, topics);

        /* End previous single member generation */
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        static_member_expect_rebalance(&c[0], rebalance_start,
                                       &c[0].revoked_at, -1);

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
         * Block long enough for consumer 2 to be evicted from the group
         * `max.poll.interval.ms` + `session.timeout.ms`
         */
        rebalance_start = test_clock();
        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        c[0].curr_line = __LINE__;
        test_consumer_poll_no_msgs("wait.max.poll", c[0].rk, testid,
                                   6000 + 9000);
        c[1].curr_line = __LINE__;
        test_consumer_poll_expect_err(c[1].rk, testid, 1000,
                                      RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED);

        /* Await revocation */
        while (!static_member_wait_rebalance(&c[0], rebalance_start,
                                             &c[0].revoked_at, 1000)) {
                c[1].curr_line = __LINE__;
                test_consumer_poll_once(c[1].rk, &mv, 0);
        }

        static_member_expect_rebalance(&c[1], rebalance_start,
                                       &c[1].revoked_at, -1);

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

        rebalance_start = test_clock();
        c[0].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        TIMING_START(&t_close, "consumer close");
        test_consumer_close(c[0].rk);
        rd_kafka_destroy(c[0].rk);

        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        static_member_expect_rebalance(&c[1], rebalance_start,
                                       &c[1].revoked_at, 2*7000);

        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS;
        static_member_expect_rebalance(&c[1], rebalance_start,
                                       &c[1].assigned_at, 2000);

        /* Should take at least as long as `session.timeout.ms` but less than
         * `max.poll.interval.ms`, but since we can't really know when
         * the last Heartbeat or SyncGroup request was sent we need to
         * allow some leeway on the minimum side (4s), and also some on
         * the maximum side (1s) for slow runtimes. */
        TIMING_ASSERT(&t_close, 6000-4000, 9000+1000);

        c[1].expected_rb_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        test_consumer_close(c[1].rk);
        rd_kafka_destroy(c[1].rk);

        test_msgver_verify("final.validation", &mv, TEST_MSGVER_ALL, 0,
                           msgcnt);
        test_msgver_clear(&mv);
        free(topics);
}


/**
 * @brief Await a non-empty assignment for all consumers in \p c
 */
static void await_assignment_multi (const char *what, rd_kafka_t **c, int cnt) {
        rd_kafka_topic_partition_list_t *parts;
        int assignment_cnt;

        TEST_SAY("%s\n", what);

        do {
                int i;
                int timeout_ms = 1000;

                assignment_cnt = 0;

                for (i = 0 ; i < cnt ; i++) {
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
static int is_fatal_cb (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                        const char *reason) {
        return rk != valid_fatal_rk;
}

/**
 * @brief Test that consumer fencing raises a fatal error
 */
static void do_test_fenced_member (void) {
        rd_kafka_t *c[3]; /* 0: consumer2b, 1: consumer1, 2: consumer2a */
        rd_kafka_conf_t *conf;
        const char *topic = test_mk_topic_name("0102_static_group_rebalance",
                                               1);
        rd_kafka_message_t *rkm;
        char errstr[512];
        rd_kafka_resp_err_t err;

        TEST_SAY(_C_MAG "[ Test fenced member ]\n");

        test_conf_init(&conf, NULL, 30);

        test_create_topic(NULL, topic, 3, 1);

        test_conf_set(conf, "group.instance.id", "consumer1");
        c[1] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);

        test_conf_set(conf, "group.instance.id", "consumer2");
        c[2] = test_create_consumer(topic, NULL, rd_kafka_conf_dup(conf), NULL);

        test_consumer_subscribe(c[1], topic);
        test_consumer_subscribe(c[2], topic);

        await_assignment_multi("Awaiting initial assignments", &c[1], 2);

        /* Create conflicting consumer */
        TEST_SAY("Creating conflicting consumer2 instance\n");
        test_conf_set(conf, "group.instance.id", "consumer2");
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
                    rd_kafka_err2str(rkm->err),
                    rd_kafka_message_errstr(rkm));
        TEST_SAY("Fenced consumer returned expected: %s: %s\n",
                 rd_kafka_err2name(rkm->err),
                 rd_kafka_message_errstr(rkm));


        /* Read the actual error */
        err = rd_kafka_fatal_error(c[2], errstr, sizeof(errstr));
        TEST_SAY("%s fatal error: %s: %s\n",
                 rd_kafka_name(c[2]), rd_kafka_err2name(err), errstr);
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
}



int main_0102_static_group_rebalance (int argc, char **argv) {

        do_test_static_group_rebalance();

        do_test_fenced_member();

        return 0;
}
