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

#include <stdarg.h>

/**
 * Verify that subscription is updated on metadata changes:
 *  - topic additions
 *  - topic deletions
 *  - partition count changes
 *  - replica rack changes (using mock broker)
 */



/**
 * Wait for REBALANCE ASSIGN event and perform assignment
 *
 * Va-args are \p topic_cnt tuples of the expected assignment:
 *   { const char *topic, int partition_cnt }
 */
static void await_assignment(const char *pfx,
                             rd_kafka_t *rk,
                             rd_kafka_queue_t *queue,
                             int topic_cnt,
                             ...) {
        rd_kafka_event_t *rkev;
        rd_kafka_topic_partition_list_t *tps;
        int i;
        va_list ap;
        int fails        = 0;
        int exp_part_cnt = 0;

        TEST_SAY("%s: waiting for assignment\n", pfx);
        rkev = test_wait_event(queue, RD_KAFKA_EVENT_REBALANCE, 30000);
        if (!rkev)
                TEST_FAIL("timed out waiting for assignment");
        TEST_ASSERT(rd_kafka_event_error(rkev) ==
                        RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                    "expected ASSIGN, got %s",
                    rd_kafka_err2str(rd_kafka_event_error(rkev)));
        tps = rd_kafka_event_topic_partition_list(rkev);

        TEST_SAY("%s: assignment:\n", pfx);
        test_print_partition_list(tps);

        va_start(ap, topic_cnt);
        for (i = 0; i < topic_cnt; i++) {
                const char *topic = va_arg(ap, const char *);
                int partition_cnt = va_arg(ap, int);
                int p;
                TEST_SAY("%s: expecting %s with %d partitions\n", pfx, topic,
                         partition_cnt);
                for (p = 0; p < partition_cnt; p++) {
                        if (!rd_kafka_topic_partition_list_find(tps, topic,
                                                                p)) {
                                TEST_FAIL_LATER(
                                    "%s: expected partition %s [%d] "
                                    "not found in assginment",
                                    pfx, topic, p);
                                fails++;
                        }
                }
                exp_part_cnt += partition_cnt;
        }
        va_end(ap);

        TEST_ASSERT(exp_part_cnt == tps->cnt,
                    "expected assignment of %d partitions, got %d",
                    exp_part_cnt, tps->cnt);

        if (fails > 0)
                TEST_FAIL("%s: assignment mismatch: see above", pfx);

        rd_kafka_assign(rk, tps);
        rd_kafka_event_destroy(rkev);
}


/**
 * Wait for REBALANCE REVOKE event and perform unassignment.
 */
static void
await_revoke(const char *pfx, rd_kafka_t *rk, rd_kafka_queue_t *queue) {
        rd_kafka_event_t *rkev;

        TEST_SAY("%s: waiting for revoke\n", pfx);
        rkev = test_wait_event(queue, RD_KAFKA_EVENT_REBALANCE, 30000);
        if (!rkev)
                TEST_FAIL("timed out waiting for revoke");
        TEST_ASSERT(rd_kafka_event_error(rkev) ==
                        RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS,
                    "expected REVOKE, got %s",
                    rd_kafka_err2str(rd_kafka_event_error(rkev)));
        rd_kafka_assign(rk, NULL);
        rd_kafka_event_destroy(rkev);
}

/**
 * Wait \p timeout_ms to make sure no rebalance was triggered.
 */
static void await_no_rebalance(const char *pfx,
                               rd_kafka_t *rk,
                               rd_kafka_queue_t *queue,
                               int timeout_ms) {
        rd_kafka_event_t *rkev;

        TEST_SAY("%s: waiting for %d ms to not see rebalance\n", pfx,
                 timeout_ms);
        rkev = test_wait_event(queue, RD_KAFKA_EVENT_REBALANCE, timeout_ms);
        if (!rkev)
                return;
        TEST_ASSERT(rkev, "did not expect %s: %s", rd_kafka_event_name(rkev),
                    rd_kafka_err2str(rd_kafka_event_error(rkev)));
        rd_kafka_event_destroy(rkev);
}


/**
 * Wait for REBALANCE event and perform assignment/unassignment.
 * For the first time and after each event, wait till for \p timeout before
 * stopping. Terminates earlier if \p min_events were seen.
 * Asserts that \p min_events were processed.
 * \p min_events set to 0 means it tries to drain all rebalance events and
 * asserts only the fact that at least 1 event was processed.
 */
static void await_rebalance(const char *pfx,
                            rd_kafka_t *rk,
                            rd_kafka_queue_t *queue,
                            int timeout_ms,
                            int min_events) {
        rd_kafka_event_t *rkev;
        int processed = 0;

        while (1) {
                TEST_SAY("%s: waiting for %d ms for rebalance event\n", pfx,
                         timeout_ms);

                rkev = test_wait_event(queue, RD_KAFKA_EVENT_REBALANCE,
                                       timeout_ms);
                if (!rkev)
                        break;
                TEST_ASSERT(rd_kafka_event_type(rkev) ==
                                RD_KAFKA_EVENT_REBALANCE,
                            "either expected a timeout or a "
                            "RD_KAFKA_EVENT_REBALANCE, got %s : %s",
                            rd_kafka_event_name(rkev),
                            rd_kafka_err2str(rd_kafka_event_error(rkev)));

                TEST_SAY("Calling test_rebalance_cb, assignment type is %s\n",
                         rd_kafka_rebalance_protocol(rk));
                test_rebalance_cb(rk, rd_kafka_event_error(rkev),
                                  rd_kafka_event_topic_partition_list(rkev),
                                  NULL);

                processed++;

                rd_kafka_event_destroy(rkev);

                if (min_events && processed >= min_events)
                        break;
        }

        if (min_events)
                min_events = 1;

        TEST_ASSERT(
            processed >= min_events,
            "Expected to process at least %d rebalance event, processed %d",
            min_events, processed);
}

static void do_test_non_exist_and_partchange(void) {
        char *topic_a = rd_strdup(test_mk_topic_name("topic_a", 1));
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *queue;

        /**
         * Test #1:
         * - Subscribe to non-existing topic.
         * - Verify empty assignment
         * - Create topic
         * - Verify new assignment containing topic
         */

        SUB_TEST();

        test_conf_init(&conf, NULL, 60);

        /* Decrease metadata interval to speed up topic change discovery. */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");

        rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
        rk = test_create_consumer(test_str_id_generate_tmp(), NULL, conf, NULL);
        queue = rd_kafka_queue_get_consumer(rk);

        TEST_SAY("#1: Subscribing to %s\n", topic_a);
        test_consumer_subscribe(rk, topic_a);

        /* Should not see a rebalance since no topics are matched. */
        await_no_rebalance("#1: empty", rk, queue, 10000);

        TEST_SAY("#1: creating topic %s\n", topic_a);
        test_create_topic(NULL, topic_a, 2, 1);

        await_assignment("#1: proper", rk, queue, 1, topic_a, 2);


        /**
         * Test #2 (continue with #1 consumer)
         * - Increase the partition count
         * - Verify updated assignment
         */
        test_kafka_topics("--alter --topic %s --partitions 4", topic_a);
        await_revoke("#2", rk, queue);

        await_assignment("#2: more partitions", rk, queue, 1, topic_a, 4);

        test_consumer_close(rk);
        rd_kafka_queue_destroy(queue);
        rd_kafka_destroy(rk);

        rd_free(topic_a);

        SUB_TEST_PASS();
}



static void do_test_regex(void) {
        char *base_topic = rd_strdup(test_mk_topic_name("topic", 1));
        char *topic_b    = rd_strdup(tsprintf("%s_b", base_topic));
        char *topic_c    = rd_strdup(tsprintf("%s_c", base_topic));
        char *topic_d    = rd_strdup(tsprintf("%s_d", base_topic));
        char *topic_e    = rd_strdup(tsprintf("%s_e", base_topic));
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *queue;

        /**
         * Regex test:
         * - Create topic b
         * - Subscribe to b & d & e
         * - Verify b assignment
         * - Create topic c
         * - Verify no rebalance
         * - Create topic d
         * - Verify b & d assignment
         */

        SUB_TEST();

        test_conf_init(&conf, NULL, 60);

        /* Decrease metadata interval to speed up topic change discovery. */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");

        rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
        rk = test_create_consumer(test_str_id_generate_tmp(), NULL, conf, NULL);
        queue = rd_kafka_queue_get_consumer(rk);

        TEST_SAY("Regex: creating topic %s (subscribed)\n", topic_b);
        test_create_topic(NULL, topic_b, 2, 1);
        rd_sleep(1);  // FIXME: do check&wait loop instead

        TEST_SAY("Regex: Subscribing to %s & %s & %s\n", topic_b, topic_d,
                 topic_e);
        test_consumer_subscribe(rk, tsprintf("^%s_[bde]$", base_topic));

        await_assignment("Regex: just one topic exists", rk, queue, 1, topic_b,
                         2);

        TEST_SAY("Regex: creating topic %s (not subscribed)\n", topic_c);
        test_create_topic(NULL, topic_c, 4, 1);

        /* Should not see a rebalance since no topics are matched. */
        await_no_rebalance("Regex: empty", rk, queue, 10000);

        TEST_SAY("Regex: creating topic %s (subscribed)\n", topic_d);
        test_create_topic(NULL, topic_d, 1, 1);

        await_revoke("Regex: rebalance after topic creation", rk, queue);

        await_assignment("Regex: two topics exist", rk, queue, 2, topic_b, 2,
                         topic_d, 1);

        test_consumer_close(rk);
        rd_kafka_queue_destroy(queue);
        rd_kafka_destroy(rk);

        rd_free(base_topic);
        rd_free(topic_b);
        rd_free(topic_c);
        rd_free(topic_d);
        rd_free(topic_e);

        SUB_TEST_PASS();
}

/**
 * @remark Requires scenario=noautocreate.
 */
static void do_test_topic_remove(void) {
        char *topic_f = rd_strdup(test_mk_topic_name("topic_f", 1));
        char *topic_g = rd_strdup(test_mk_topic_name("topic_g", 1));
        int parts_f   = 5;
        int parts_g   = 9;
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *queue;
        rd_kafka_topic_partition_list_t *topics;
        rd_kafka_resp_err_t err;

        /**
         * Topic removal test:
         * - Create topic f & g
         * - Subscribe to f & g
         * - Verify f & g assignment
         * - Remove topic f
         * - Verify g assignment
         * - Remove topic g
         * - Verify empty assignment
         */

        SUB_TEST("Topic removal testing");

        test_conf_init(&conf, NULL, 60);

        /* Decrease metadata interval to speed up topic change discovery. */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");

        rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
        rk = test_create_consumer(test_str_id_generate_tmp(), NULL, conf, NULL);
        queue = rd_kafka_queue_get_consumer(rk);

        TEST_SAY("Topic removal: creating topic %s (subscribed)\n", topic_f);
        test_create_topic(NULL, topic_f, parts_f, 1);

        TEST_SAY("Topic removal: creating topic %s (subscribed)\n", topic_g);
        test_create_topic(NULL, topic_g, parts_g, 1);

        rd_sleep(1);  // FIXME: do check&wait loop instead

        TEST_SAY("Topic removal: Subscribing to %s & %s\n", topic_f, topic_g);
        topics = rd_kafka_topic_partition_list_new(2);
        rd_kafka_topic_partition_list_add(topics, topic_f,
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_topic_partition_list_add(topics, topic_g,
                                          RD_KAFKA_PARTITION_UA);
        err = rd_kafka_subscribe(rk, topics);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR, "%s",
                    rd_kafka_err2str(err));
        rd_kafka_topic_partition_list_destroy(topics);

        await_assignment("Topic removal: both topics exist", rk, queue, 2,
                         topic_f, parts_f, topic_g, parts_g);

        TEST_SAY("Topic removal: removing %s\n", topic_f);
        test_kafka_topics("--delete --topic %s", topic_f);

        await_revoke("Topic removal: rebalance after topic removal", rk, queue);

        await_assignment("Topic removal: one topic exists", rk, queue, 1,
                         topic_g, parts_g);

        TEST_SAY("Topic removal: removing %s\n", topic_g);
        test_kafka_topics("--delete --topic %s", topic_g);

        await_revoke("Topic removal: rebalance after 2nd topic removal", rk,
                     queue);

        /* Should not see another rebalance since all topics now removed */
        await_no_rebalance("Topic removal: empty", rk, queue, 10000);

        test_consumer_close(rk);
        rd_kafka_queue_destroy(queue);
        rd_kafka_destroy(rk);

        rd_free(topic_f);
        rd_free(topic_g);

        SUB_TEST_PASS();
}



/**
 * @brief Subscribe to a regex and continually create a lot of matching topics,
 *        triggering many rebalances.
 *
 * This is using the mock cluster.
 *
 */
static void do_test_regex_many_mock(const char *assignment_strategy,
                                    rd_bool_t lots_of_topics) {
        const char *base_topic = "topic";
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        int topic_cnt              = lots_of_topics ? 300 : 50;
        int await_assignment_every = lots_of_topics ? 150 : 15;
        int i;

        SUB_TEST("%s with %d topics", assignment_strategy, topic_cnt);

        mcluster = test_mock_cluster_new(3, &bootstraps);
        test_conf_init(&conf, NULL, 60 * 5);

        test_conf_set(conf, "security.protocol", "plaintext");
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "partition.assignment.strategy",
                      assignment_strategy);
        /* Decrease metadata interval to speed up topic change discovery. */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "3000");

        rk = test_create_consumer("mygroup", test_rebalance_cb, conf, NULL);

        test_consumer_subscribe(rk, tsprintf("^%s_.*", base_topic));

        for (i = 0; i < topic_cnt; i++) {
                char topic[256];

                rd_snprintf(topic, sizeof(topic), "%s_%d", base_topic, i);


                TEST_SAY("Creating topic %s\n", topic);
                TEST_CALL_ERR__(rd_kafka_mock_topic_create(mcluster, topic,
                                                           1 + (i % 8), 1));

                test_consumer_poll_no_msgs("POLL", rk, 0,
                                           lots_of_topics ? 100 : 300);

                /* Wait for an assignment to let the consumer catch up on
                 * all rebalancing. */
                if (i % await_assignment_every == await_assignment_every - 1)
                        test_consumer_wait_assignment(rk, rd_true /*poll*/);
                else if (!lots_of_topics)
                        rd_usleep(100 * 1000, NULL);
        }

        test_consumer_close(rk);
        rd_kafka_destroy(rk);

        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


/**
 * @brief Changing the broker racks should trigger a rejoin, if the client rack
 * is set, and the set of partition racks changes due to the broker rack change.
 *
 * This is using the mock cluster.
 *
 */
static void do_test_replica_rack_change_mock(const char *assignment_strategy,
                                             rd_bool_t use_regex,
                                             rd_bool_t use_client_rack,
                                             rd_bool_t use_replica_rack) {
        const char *subscription = use_regex ? "^top" : "topic";
        const char *topic        = "topic";
        const char *test_name    = tsprintf(
            "Replica rack changes (%s, subscription = \"%s\", %s client.rack, "
            "%s replica.rack)",
            assignment_strategy, subscription,
            use_client_rack ? "with" : "without",
            use_replica_rack ? "with" : "without");
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_queue_t *queue;

        SUB_TEST("Testing %s", test_name);

        mcluster = test_mock_cluster_new(3, &bootstraps);
        test_conf_init(&conf, NULL, 60 * 4);

        if (use_replica_rack) {
                rd_kafka_mock_broker_set_rack(mcluster, 1, "rack0");
                rd_kafka_mock_broker_set_rack(mcluster, 2, "rack1");
                rd_kafka_mock_broker_set_rack(mcluster, 3, "rack2");
        }

        TEST_SAY("Creating topic %s\n", topic);
        TEST_CALL_ERR__(rd_kafka_mock_topic_create(mcluster, topic,
                                                   2 /* partition_cnt */,
                                                   1 /* replication_factor */));

        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "partition.assignment.strategy",
                      assignment_strategy);
        /* Decrease metadata interval to speed up topic change discovery. */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "3000");

        if (use_client_rack)
                test_conf_set(conf, "client.rack", "client_rack");

        rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_REBALANCE);
        rk = test_create_consumer(test_str_id_generate_tmp(), NULL, conf, NULL);
        queue = rd_kafka_queue_get_consumer(rk);

        TEST_SAY("%s: Subscribing via %s\n", test_name, subscription);
        test_consumer_subscribe(rk, subscription);

        await_rebalance(tsprintf("%s: initial assignment", test_name), rk,
                        queue, 10000, 1);

        /* Avoid issues if the replica assignment algorithm for mock broker
         * changes, and change all the racks. */
        if (use_replica_rack) {
                TEST_SAY("%s: changing rack for all brokers\n", test_name);
                rd_kafka_mock_broker_set_rack(mcluster, 1, "rack2");
                rd_kafka_mock_broker_set_rack(mcluster, 2, "rack0");
                rd_kafka_mock_broker_set_rack(mcluster, 3, "rack1");
        }

        if (use_client_rack && use_replica_rack)
                await_rebalance(tsprintf("%s: rebalance", test_name), rk, queue,
                                10000, 1);
        else
                await_no_rebalance(
                    tsprintf("%s: no rebalance without racks", test_name), rk,
                    queue, 10000);

        test_consumer_close(rk);
        rd_kafka_queue_destroy(queue);
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


/* Even if the leader has no rack, it should do rack-aware assignment in case
 * one of the group members has a rack configured. */
static void do_test_replica_rack_change_leader_no_rack_mock(
    const char *assignment_strategy) {
        const char *topic     = "topic";
        const char *test_name = "Replica rack changes with leader rack absent.";
        rd_kafka_t *c1, *c2;
        rd_kafka_conf_t *conf1, *conf2;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_queue_t *queue;
        rd_kafka_topic_partition_list_t *asg1, *asg2;

        SUB_TEST("Testing %s", test_name);

        mcluster = test_mock_cluster_new(2, &bootstraps);
        test_conf_init(&conf1, NULL, 60 * 4);

        rd_kafka_mock_broker_set_rack(mcluster, 1, "rack0");
        rd_kafka_mock_broker_set_rack(mcluster, 2, "rack1");

        TEST_SAY("Creating topic %s\n", topic);
        TEST_CALL_ERR__(rd_kafka_mock_topic_create(mcluster, topic,
                                                   2 /* partition_cnt */,
                                                   1 /* replication_factor */));

        test_conf_set(conf1, "bootstrap.servers", bootstraps);
        test_conf_set(conf1, "partition.assignment.strategy",
                      assignment_strategy);
        /* Decrease metadata interval to speed up topic change discovery. */
        test_conf_set(conf1, "topic.metadata.refresh.interval.ms", "3000");

        conf2 = rd_kafka_conf_dup(conf1);

        /* Setting the group.instance.id ensures that the leader is always c1.
         */
        test_conf_set(conf1, "client.id", "client1Leader");
        test_conf_set(conf1, "group.instance.id", "client1Leader");

        test_conf_set(conf2, "client.id", "client2Follower");
        test_conf_set(conf2, "group.instance.id", "client2Follower");
        test_conf_set(conf2, "client.rack", "rack0");

        rd_kafka_conf_set_events(conf1, RD_KAFKA_EVENT_REBALANCE);
        c1    = test_create_consumer("mygroup", NULL, conf1, NULL);
        queue = rd_kafka_queue_get_consumer(c1);

        c2 = test_create_consumer("mygroup", NULL, conf2, NULL);

        TEST_SAY("%s: Subscribing via %s\n", test_name, topic);
        test_consumer_subscribe(c1, topic);
        test_consumer_subscribe(c2, topic);

        /* Poll to cause joining. */
        rd_kafka_poll(c1, 1);
        rd_kafka_poll(c2, 1);

        /* Drain all events, as we want to process the assignment. */
        await_rebalance(tsprintf("%s: initial assignment", test_name), c1,
                        queue, 10000, 0);

        rd_kafka_assignment(c1, &asg1);
        rd_kafka_assignment(c2, &asg2);

        /* Because of the deterministic nature of replica assignment in the mock
         * broker, we can always be certain that topic:0 has its only replica on
         * broker 1, and topic:1 has its only replica on broker 2. */
        TEST_ASSERT(asg1->cnt == 1 && asg1->elems[0].partition == 1,
                    "Expected c1 to be assigned topic1:1");
        TEST_ASSERT(asg2->cnt == 1 && asg2->elems[0].partition == 0,
                    "Expected c2 to be assigned topic1:0");

        rd_kafka_topic_partition_list_destroy(asg1);
        rd_kafka_topic_partition_list_destroy(asg2);

        /* Avoid issues if the replica assignment algorithm for mock broker
         * changes, and change all the racks. */
        TEST_SAY("%s: changing rack for all brokers\n", test_name);
        rd_kafka_mock_broker_set_rack(mcluster, 2, "rack0");
        rd_kafka_mock_broker_set_rack(mcluster, 1, "rack1");

        /* Poll to cause rejoining. */
        rd_kafka_poll(c1, 1);
        rd_kafka_poll(c2, 1);

        /* Drain all events, as we want to process the assignment. */
        await_rebalance(tsprintf("%s: rebalance", test_name), c1, queue, 10000,
                        0);

        rd_kafka_assignment(c1, &asg1);
        rd_kafka_assignment(c2, &asg2);

        /* Because of the deterministic nature of replica assignment in the mock
         * broker, we can always be certain that topic:0 has its only replica on
         * broker 1, and topic:1 has its only replica on broker 2. */
        TEST_ASSERT(asg1->cnt == 1 && asg1->elems[0].partition == 0,
                    "Expected c1 to be assigned topic1:0");
        TEST_ASSERT(asg2->cnt == 1 && asg2->elems[0].partition == 1,
                    "Expected c2 to be assigned topic1:1");

        rd_kafka_topic_partition_list_destroy(asg1);
        rd_kafka_topic_partition_list_destroy(asg2);

        test_consumer_close(c1);
        test_consumer_close(c2);
        rd_kafka_queue_destroy(queue);
        rd_kafka_destroy(c1);
        rd_kafka_destroy(c2);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

int main_0045_subscribe_update(int argc, char **argv) {

        if (!test_can_create_topics(1))
                return 0;

        do_test_regex();

        return 0;
}

int main_0045_subscribe_update_non_exist_and_partchange(int argc, char **argv) {

        do_test_non_exist_and_partchange();

        return 0;
}

int main_0045_subscribe_update_topic_remove(int argc, char **argv) {

        if (!test_can_create_topics(1))
                return 0;

        do_test_topic_remove();

        return 0;
}


int main_0045_subscribe_update_mock(int argc, char **argv) {
        do_test_regex_many_mock("range", rd_false);
        do_test_regex_many_mock("cooperative-sticky", rd_false);
        do_test_regex_many_mock("cooperative-sticky", rd_true);

        return 0;
}


int main_0045_subscribe_update_racks_mock(int argc, char **argv) {
        int use_replica_rack = 0;
        int use_client_rack  = 0;

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        for (use_replica_rack = 0; use_replica_rack < 2; use_replica_rack++) {
                for (use_client_rack = 0; use_client_rack < 2;
                     use_client_rack++) {
                        do_test_replica_rack_change_mock(
                            "range", rd_true /* use_regex */, use_client_rack,
                            use_replica_rack);
                        do_test_replica_rack_change_mock(
                            "range", rd_true /* use_regex */, use_client_rack,
                            use_replica_rack);
                        do_test_replica_rack_change_mock(
                            "cooperative-sticky", rd_true /* use_regex */,
                            use_client_rack, use_replica_rack);
                        do_test_replica_rack_change_mock(
                            "cooperative-sticky", rd_true /* use_regex */,
                            use_client_rack, use_replica_rack);
                }
        }

        /* Do not test with range assignor (yet) since it does not do rack aware
         * assignment properly with the NULL rack, even for the Java client. */
        do_test_replica_rack_change_leader_no_rack_mock("cooperative-sticky");

        return 0;
}
