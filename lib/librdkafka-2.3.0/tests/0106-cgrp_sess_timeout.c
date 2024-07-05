/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020-2022, Magnus Edenhill
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
 * @name Verify that the high-level consumer times out itself if
 *       heartbeats are not successful (issue #2631).
 */

static const char *commit_type;
static int rebalance_cnt;
static rd_kafka_resp_err_t rebalance_exp_event;
static rd_kafka_resp_err_t commit_exp_err;

static void rebalance_cb(rd_kafka_t *rk,
                         rd_kafka_resp_err_t err,
                         rd_kafka_topic_partition_list_t *parts,
                         void *opaque) {

        rebalance_cnt++;
        TEST_SAY("Rebalance #%d: %s: %d partition(s)\n", rebalance_cnt,
                 rd_kafka_err2name(err), parts->cnt);

        TEST_ASSERT(
            err == rebalance_exp_event, "Expected rebalance event %s, not %s",
            rd_kafka_err2name(rebalance_exp_event), rd_kafka_err2name(err));

        if (err == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS) {
                test_consumer_assign("assign", rk, parts);
        } else {
                rd_kafka_resp_err_t commit_err;

                if (strcmp(commit_type, "auto")) {
                        rd_kafka_resp_err_t perr;

                        TEST_SAY("Performing %s commit\n", commit_type);

                        perr = rd_kafka_position(rk, parts);
                        TEST_ASSERT(!perr, "Failed to acquire position: %s",
                                    rd_kafka_err2str(perr));

                        /* Sleep a short while so the broker times out the
                         * member too. */
                        rd_sleep(1);

                        commit_err = rd_kafka_commit(
                            rk, parts, !strcmp(commit_type, "async"));

                        if (!strcmp(commit_type, "async"))
                                TEST_ASSERT(!commit_err,
                                            "Async commit should not fail, "
                                            "but it returned %s",
                                            rd_kafka_err2name(commit_err));
                        else
                                TEST_ASSERT(
                                    commit_err == commit_exp_err ||
                                        (!commit_exp_err &&
                                         commit_err ==
                                             RD_KAFKA_RESP_ERR__NO_OFFSET),
                                    "Expected %s commit to return %s, "
                                    "not %s",
                                    commit_type,
                                    rd_kafka_err2name(commit_exp_err),
                                    rd_kafka_err2name(commit_err));
                }

                test_consumer_unassign("unassign", rk);
        }

        /* Make sure only one rebalance callback is served per poll()
         * so that expect_rebalance() returns to the test logic on each
         * rebalance. */
        rd_kafka_yield(rk);
}


/**
 * @brief Wait for an expected rebalance event, or fail.
 */
static void expect_rebalance(const char *what,
                             rd_kafka_t *c,
                             rd_kafka_resp_err_t exp_event,
                             int timeout_s) {
        int64_t tmout = test_clock() + (timeout_s * 1000000);
        int start_cnt = rebalance_cnt;

        TEST_SAY("Waiting for %s (%s) for %ds\n", what,
                 rd_kafka_err2name(exp_event), timeout_s);

        rebalance_exp_event = exp_event;

        while (tmout > test_clock() && rebalance_cnt == start_cnt) {
                if (test_consumer_poll_once(c, NULL, 1000))
                        rd_sleep(1);
        }

        if (rebalance_cnt == start_cnt + 1) {
                rebalance_exp_event = RD_KAFKA_RESP_ERR_NO_ERROR;
                return;
        }

        TEST_FAIL("Timed out waiting for %s (%s)\n", what,
                  rd_kafka_err2name(exp_event));
}


/**
 * @brief Verify that session timeouts are handled by the consumer itself.
 *
 * @param use_commit_type "auto", "sync" (manual), "async" (manual)
 */
static void do_test_session_timeout(const char *use_commit_type) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        rd_kafka_t *c;
        const char *groupid = "mygroup";
        const char *topic   = "test";

        rebalance_cnt = 0;
        commit_type   = use_commit_type;

        SUB_TEST0(!strcmp(use_commit_type, "sync") /*quick*/,
                  "Test session timeout with %s commit", use_commit_type);

        mcluster = test_mock_cluster_new(3, &bootstraps);

        rd_kafka_mock_coordinator_set(mcluster, "group", groupid, 1);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, 0, 0, 0, 100, 10, "bootstrap.servers",
                                 bootstraps, "batch.num.messages", "10", NULL);

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "security.protocol", "PLAINTEXT");
        test_conf_set(conf, "group.id", groupid);
        test_conf_set(conf, "session.timeout.ms", "5000");
        test_conf_set(conf, "heartbeat.interval.ms", "1000");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit",
                      !strcmp(commit_type, "auto") ? "true" : "false");

        c = test_create_consumer(groupid, rebalance_cb, conf, NULL);

        test_consumer_subscribe(c, topic);

        /* Let Heartbeats fail after a couple of successful ones */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Heartbeat, 9, RD_KAFKA_RESP_ERR_NO_ERROR,
            RD_KAFKA_RESP_ERR_NO_ERROR, RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR);

        expect_rebalance("initial assignment", c,
                         RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS, 5 + 2);

        /* Consume a couple of messages so that we have something to commit */
        test_consumer_poll("consume", c, 0, -1, 0, 10, NULL);

        /* The commit in the rebalance callback should fail when the
         * member has timed out from the group. */
        commit_exp_err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;

        expect_rebalance("session timeout revoke", c,
                         RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS, 2 + 5 + 2);

        expect_rebalance("second assignment", c,
                         RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS, 5 + 2);

        /* Final rebalance in close().
         * Its commit will work. */
        rebalance_exp_event = RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS;
        commit_exp_err      = RD_KAFKA_RESP_ERR_NO_ERROR;

        test_consumer_close(c);

        rd_kafka_destroy(c);

        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


/**
 * @brief Attempt manual commit when assignment has been lost (#3217)
 */
static void do_test_commit_on_lost(void) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        rd_kafka_t *c;
        const char *groupid = "mygroup";
        const char *topic   = "test";
        rd_kafka_resp_err_t err;

        SUB_TEST();

        test_curr->is_fatal_cb = test_error_is_not_fatal_cb;

        mcluster = test_mock_cluster_new(3, &bootstraps);

        rd_kafka_mock_coordinator_set(mcluster, "group", groupid, 1);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, 0, 0, 0, 100, 10, "bootstrap.servers",
                                 bootstraps, "batch.num.messages", "10", NULL);

        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "security.protocol", "PLAINTEXT");
        test_conf_set(conf, "group.id", groupid);
        test_conf_set(conf, "session.timeout.ms", "5000");
        test_conf_set(conf, "heartbeat.interval.ms", "1000");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");

        c = test_create_consumer(groupid, test_rebalance_cb, conf, NULL);

        test_consumer_subscribe(c, topic);

        /* Consume a couple of messages so that we have something to commit */
        test_consumer_poll("consume", c, 0, -1, 0, 10, NULL);

        /* Make the coordinator unreachable, this will cause a local session
         * timeout followed by a revoke and assignment lost. */
        rd_kafka_mock_broker_set_down(mcluster, 1);

        /* Wait until the assignment is lost */
        TEST_SAY("Waiting for assignment to be lost...\n");
        while (!rd_kafka_assignment_lost(c))
                rd_sleep(1);

        TEST_SAY("Assignment is lost, committing\n");
        /* Perform manual commit */
        err = rd_kafka_commit(c, NULL, 0 /*sync*/);
        TEST_SAY("commit() returned: %s\n", rd_kafka_err2name(err));
        TEST_ASSERT(err, "expected commit to fail");

        test_consumer_close(c);

        rd_kafka_destroy(c);

        test_mock_cluster_destroy(mcluster);

        test_curr->is_fatal_cb = NULL;

        SUB_TEST_PASS();
}


int main_0106_cgrp_sess_timeout(int argc, char **argv) {

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_session_timeout("sync");
        do_test_session_timeout("async");
        do_test_session_timeout("auto");

        do_test_commit_on_lost();

        return 0;
}
