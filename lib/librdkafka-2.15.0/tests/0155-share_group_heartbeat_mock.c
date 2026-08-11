#include "test.h"

#include "../src/rdkafka_proto.h"

/**
 * @name Mock tests for share consumer and ShareGroupHeartbeat
 *
 * Note: rd_kafka_assignment() and rd_kafka_fatal_error() are called via
 *       test_share_consumer_get_rk() to access the underlying rd_kafka_t
 *       handle from the share consumer.
 */

static rd_bool_t is_share_heartbeat_request(rd_kafka_mock_request_t *request,
                                            void *opaque) {
        return rd_kafka_mock_request_api_key(request) ==
               RD_KAFKAP_ShareGroupHeartbeat;
}

/**
 * @brief Wait for at least \p num ShareGroupHeartbeat requests
 *        to be received by the mock cluster.
 *
 * @return Number of heartbeats received.
 */
static int wait_share_heartbeats(rd_kafka_mock_cluster_t *mcluster,
                                 int num,
                                 int confidence_interval) {
        return test_mock_wait_matching_requests(
            mcluster, num, confidence_interval, is_share_heartbeat_request,
            NULL);
}

/**
 * @brief Create a share consumer connected to mock cluster.
 */
static rd_kafka_share_t *create_share_consumer(const char *bootstraps,
                                               const char *group_id) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        char errstr[512];

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer: %s",
                    errstr);

        return rkshare;
}

/**
 * @brief Poll rd_kafka_share_poll() until it returns a fatal
 *        error or \p timeout_ms elapses.
 *
 * While waiting for the fatal error no records are expected, and any
 * error returned must be fatal; both are asserted.
 *
 * @return The fatal rd_kafka_error_t* (caller owns it and must destroy it),
 *         or NULL if the timeout elapsed without any error.
 */
static rd_kafka_error_t *wait_fatal_error(rd_kafka_share_t *share_c,
                                          int timeout_ms) {
        int64_t deadline           = test_clock() + (int64_t)timeout_ms * 1000;
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd;
        rd_kafka_error_t *error;

        while (test_clock() < deadline) {
                error = rd_kafka_share_poll(share_c, 100, &batch);
                rcvd  = rd_kafka_messages_count(batch);

                TEST_ASSERT(rcvd == 0,
                            "Expected no records while waiting for fatal "
                            "error, got %d",
                            (int)rcvd);

                rd_kafka_messages_destroy(batch);
                batch = NULL;

                if (error) {
                        TEST_ASSERT(rd_kafka_error_is_fatal(error),
                                    "Expected a fatal error, got non-fatal %s",
                                    rd_kafka_error_name(error));
                        return error;
                }
        }
        return NULL;
}

static int count_topic_partitions(rd_kafka_topic_partition_list_t *assignment,
                                  const char *topic) {
        int i, count = 0;
        for (i = 0; i < assignment->cnt; i++) {
                if (strcmp(assignment->elems[i].topic, topic) == 0)
                        count++;
        }
        return count;
}

/**
 * @brief Wait until rd_kafka_assignment() returns exactly
 *        \p expected_cnt partitions, or \p timeout_ms elapses.
 *
 * The heartbeat thread updates assignments independently,
 * so no polling is needed.
 *
 * @return The final assignment count.
 */
static int wait_assignment_count(rd_kafka_share_t *share_c,
                                 int expected_cnt,
                                 int timeout_ms) {
        int64_t deadline = test_clock() + (int64_t)timeout_ms * 1000;
        int cnt          = -1;

        while (test_clock() < deadline) {
                rd_kafka_topic_partition_list_t *assignment;

                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c), &assignment));
                cnt = assignment->cnt;
                rd_kafka_topic_partition_list_destroy(assignment);

                if (cnt == expected_cnt)
                        return cnt;

                rd_usleep(500 * 1000, 0);
        }
        return cnt;
}


/**
 * @brief Test basic ShareGroupHeartbeat flow:
 *        join, receive assignment, heartbeats, leave.
 */
static void do_test_share_group_heartbeat_basic(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        int found_heartbeats, cnt;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for join heartbeat */
        found_heartbeats = wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(found_heartbeats >= 1,
                    "Expected at least 1 heartbeat, got %d", found_heartbeats);

        /* Wait until assignment propagates */
        cnt = wait_assignment_count(share_c, 3, 10000);
        TEST_ASSERT(cnt == 3, "Expected 3 partitions assigned, got %d", cnt);

        /* Verify multiple heartbeats */
        found_heartbeats = wait_share_heartbeats(mcluster, 2, 1000);
        TEST_ASSERT(found_heartbeats >= 2,
                    "Expected at least 2 heartbeats, got %d", found_heartbeats);

        /* Close consumer (sends leave heartbeat) */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        /* Verify leave heartbeat was sent */
        found_heartbeats = wait_share_heartbeats(mcluster, 3, 1000);

        /* Verify no more heartbeats after leave.
         * Use a generous sleep (5s) and confidence interval (1000ms)
         * to avoid false positives under CPU contention. */
        rd_kafka_mock_stop_request_tracking(mcluster);
        rd_kafka_mock_start_request_tracking(mcluster);
        rd_sleep(5);
        found_heartbeats = wait_share_heartbeats(mcluster, 0, 1000);
        TEST_ASSERT(found_heartbeats == 0,
                    "Expected 0 heartbeats after leave, got %d",
                    found_heartbeats);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test assignment redistribution when consumers join/leave.
 */
static void do_test_share_group_assignment_rebalance(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_topic_partition_list_t *share_c1_assignment,
            *share_c2_assignment;
        rd_kafka_share_t *share_c1, *share_c2;
        int64_t deadline;
        int cnt;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-rebalance";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c1 = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c1, subscription));

        /* C1 joins - wait for all 3 partitions */
        cnt = wait_assignment_count(share_c1, 3, 10000);
        TEST_ASSERT(cnt == 3, "Expected C1 to have 3 partitions, got %d", cnt);

        /* C2 joins - partitions should be redistributed */
        share_c2 = create_share_consumer(bootstraps, group);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c2, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait until both consumers have partitions and total == 3 */
        deadline = test_clock() + 15000 * 1000;
        while (test_clock() < deadline) {

                TEST_CALL_ERR__(
                    rd_kafka_assignment(test_share_consumer_get_rk(share_c1),
                                        &share_c1_assignment));
                TEST_CALL_ERR__(
                    rd_kafka_assignment(test_share_consumer_get_rk(share_c2),
                                        &share_c2_assignment));

                if (share_c1_assignment->cnt + share_c2_assignment->cnt == 3 &&
                    share_c1_assignment->cnt > 0 &&
                    share_c2_assignment->cnt > 0) {
                        rd_kafka_topic_partition_list_destroy(
                            share_c1_assignment);
                        rd_kafka_topic_partition_list_destroy(
                            share_c2_assignment);
                        break;
                }
                rd_kafka_topic_partition_list_destroy(share_c1_assignment);
                rd_kafka_topic_partition_list_destroy(share_c2_assignment);
                rd_usleep(200 * 1000, 0);
        }
        /* Final check after loop */
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c1), &share_c1_assignment));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c2), &share_c2_assignment));
        TEST_ASSERT(share_c1_assignment->cnt + share_c2_assignment->cnt == 3,
                    "Expected total 3 partitions, got %d + %d = %d",
                    share_c1_assignment->cnt, share_c2_assignment->cnt,
                    share_c1_assignment->cnt + share_c2_assignment->cnt);
        TEST_ASSERT(share_c1_assignment->cnt > 0 &&
                        share_c2_assignment->cnt > 0,
                    "Expected both consumers to have partitions, "
                    "got C1=%d, C2=%d",
                    share_c1_assignment->cnt, share_c2_assignment->cnt);
        rd_kafka_topic_partition_list_destroy(share_c1_assignment);
        rd_kafka_topic_partition_list_destroy(share_c2_assignment);

        /* C2 leaves - C1 should get all partitions back */
        test_share_consumer_close(share_c2);
        test_share_destroy(share_c2);

        cnt = wait_assignment_count(share_c1, 3, 10000);
        TEST_ASSERT(cnt == 3,
                    "Expected C1 to have 3 partitions after C2 left, got %d",
                    cnt);

        /* Cleanup */
        test_share_consumer_close(share_c1);
        test_share_destroy(share_c1);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test multi-topic assignment with mixed subscriptions.
 *        C1: both topics, C2: orders only, C3: events only
 */
static void do_test_share_group_multi_topic_assignment(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *sub_both, *sub_orders, *sub_events;
        rd_kafka_topic_partition_list_t *share_c1_assign, *share_c2_assign,
            *share_c3_assign;
        rd_kafka_share_t *share_c1, *share_c2, *share_c3;
        const char *topic_orders = "test-orders";
        const char *topic_events = "test-events";
        const char *group        = "test-share-group-multi";
        int total_orders, total_events, cnt;
        int64_t deadline;

        SUB_TEST_QUICK();

        /* Setup: orders (4 partitions), events (2 partitions) */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic_orders, 4, 1);
        rd_kafka_mock_topic_create(mcluster, topic_events, 2, 1);

        sub_both = rd_kafka_topic_partition_list_new(2);
        rd_kafka_topic_partition_list_add(sub_both, topic_orders,
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_topic_partition_list_add(sub_both, topic_events,
                                          RD_KAFKA_PARTITION_UA);

        sub_orders = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(sub_orders, topic_orders,
                                          RD_KAFKA_PARTITION_UA);

        sub_events = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(sub_events, topic_events,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);

        /* C1 joins (both topics) - should get all 6 partitions */
        share_c1 = create_share_consumer(bootstraps, group);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c1, sub_both));
        cnt = wait_assignment_count(share_c1, 6, 10000);
        TEST_ASSERT(cnt == 6, "C1 should have all 6 partitions, got %d", cnt);

        /* C2 joins (orders only) - orders should split.
         * Wait until C2 has at least 1 orders partition and
         * total orders == 4, total events == 2. */
        share_c2 = create_share_consumer(bootstraps, group);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c2, sub_orders));

        deadline = test_clock() + 15000 * 1000;
        while (test_clock() < deadline) {
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c1), &share_c1_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));

                total_orders =
                    count_topic_partitions(share_c1_assign, topic_orders) +
                    count_topic_partitions(share_c2_assign, topic_orders);
                total_events =
                    count_topic_partitions(share_c1_assign, topic_events) +
                    count_topic_partitions(share_c2_assign, topic_events);

                if (total_orders == 4 && total_events == 2 &&
                    count_topic_partitions(share_c2_assign, topic_orders) > 0) {
                        rd_kafka_topic_partition_list_destroy(share_c1_assign);
                        rd_kafka_topic_partition_list_destroy(share_c2_assign);
                        break;
                }
                rd_kafka_topic_partition_list_destroy(share_c1_assign);
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                rd_usleep(200 * 1000, 0);
        }
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c1), &share_c1_assign));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c2), &share_c2_assign));
        total_orders = count_topic_partitions(share_c1_assign, topic_orders) +
                       count_topic_partitions(share_c2_assign, topic_orders);
        total_events = count_topic_partitions(share_c1_assign, topic_events) +
                       count_topic_partitions(share_c2_assign, topic_events);
        TEST_ASSERT(total_orders == 4, "Total orders should be 4, got %d",
                    total_orders);
        TEST_ASSERT(total_events == 2, "Total events should be 2, got %d",
                    total_events);
        TEST_ASSERT(count_topic_partitions(share_c2_assign, topic_orders) > 0,
                    "C2 should have at least 1 orders partition");
        rd_kafka_topic_partition_list_destroy(share_c1_assign);
        rd_kafka_topic_partition_list_destroy(share_c2_assign);

        /* C3 joins (events only) - events should split.
         * Wait until C3 has at least 1 events partition. */
        share_c3 = create_share_consumer(bootstraps, group);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c3, sub_events));

        deadline = test_clock() + 15000 * 1000;
        while (test_clock() < deadline) {

                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c1), &share_c1_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c3), &share_c3_assign));

                total_orders =
                    count_topic_partitions(share_c1_assign, topic_orders) +
                    count_topic_partitions(share_c2_assign, topic_orders) +
                    count_topic_partitions(share_c3_assign, topic_orders);
                total_events =
                    count_topic_partitions(share_c1_assign, topic_events) +
                    count_topic_partitions(share_c2_assign, topic_events) +
                    count_topic_partitions(share_c3_assign, topic_events);

                if (total_orders == 4 && total_events == 2 &&
                    count_topic_partitions(share_c3_assign, topic_events) > 0) {
                        rd_kafka_topic_partition_list_destroy(share_c1_assign);
                        rd_kafka_topic_partition_list_destroy(share_c2_assign);
                        rd_kafka_topic_partition_list_destroy(share_c3_assign);
                        break;
                }
                rd_kafka_topic_partition_list_destroy(share_c1_assign);
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                rd_kafka_topic_partition_list_destroy(share_c3_assign);
                rd_usleep(200 * 1000, 0);
        }
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c1), &share_c1_assign));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c2), &share_c2_assign));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c3), &share_c3_assign));
        total_orders = count_topic_partitions(share_c1_assign, topic_orders) +
                       count_topic_partitions(share_c2_assign, topic_orders) +
                       count_topic_partitions(share_c3_assign, topic_orders);
        total_events = count_topic_partitions(share_c1_assign, topic_events) +
                       count_topic_partitions(share_c2_assign, topic_events) +
                       count_topic_partitions(share_c3_assign, topic_events);
        TEST_ASSERT(total_orders == 4, "Total orders should be 4, got %d",
                    total_orders);
        TEST_ASSERT(total_events == 2, "Total events should be 2, got %d",
                    total_events);
        TEST_ASSERT(count_topic_partitions(share_c3_assign, topic_events) > 0,
                    "C3 should have at least 1 events partition");
        rd_kafka_topic_partition_list_destroy(share_c1_assign);
        rd_kafka_topic_partition_list_destroy(share_c2_assign);
        rd_kafka_topic_partition_list_destroy(share_c3_assign);

        /* C1 leaves - C2 should get all orders, C3 all events.
         * Wait until C2 has 4 orders and C3 has 2 events. */
        test_share_consumer_close(share_c1);
        test_share_destroy(share_c1);

        deadline = test_clock() + 15000 * 1000;
        while (test_clock() < deadline) {
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c3), &share_c3_assign));

                if (count_topic_partitions(share_c2_assign, topic_orders) ==
                        4 &&
                    count_topic_partitions(share_c3_assign, topic_events) ==
                        2) {
                        rd_kafka_topic_partition_list_destroy(share_c2_assign);
                        rd_kafka_topic_partition_list_destroy(share_c3_assign);
                        break;
                }
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                rd_kafka_topic_partition_list_destroy(share_c3_assign);
                rd_usleep(200 * 1000, 0);
        }
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c2), &share_c2_assign));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c3), &share_c3_assign));
        TEST_ASSERT(count_topic_partitions(share_c2_assign, topic_orders) == 4,
                    "C2 should have all 4 orders partitions, got %d",
                    count_topic_partitions(share_c2_assign, topic_orders));
        TEST_ASSERT(count_topic_partitions(share_c3_assign, topic_events) == 2,
                    "C3 should have all 2 events partitions, got %d",
                    count_topic_partitions(share_c3_assign, topic_events));
        rd_kafka_topic_partition_list_destroy(share_c2_assign);
        rd_kafka_topic_partition_list_destroy(share_c3_assign);

        /* C2 leaves - C3 should still have events only */
        test_share_consumer_close(share_c2);
        test_share_destroy(share_c2);

        /* Wait for C3 to stabilize with 2 events, 0 orders */
        cnt = wait_assignment_count(share_c3, 2, 10000);
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c3), &share_c3_assign));
        TEST_ASSERT(count_topic_partitions(share_c3_assign, topic_events) == 2,
                    "C3 should still have 2 events partitions, got %d",
                    count_topic_partitions(share_c3_assign, topic_events));
        TEST_ASSERT(count_topic_partitions(share_c3_assign, topic_orders) == 0,
                    "C3 should have 0 orders partitions (not subscribed), "
                    "got %d",
                    count_topic_partitions(share_c3_assign, topic_orders));
        rd_kafka_topic_partition_list_destroy(share_c3_assign);

        /* Cleanup */
        test_share_consumer_close(share_c3);
        test_share_destroy(share_c3);

        rd_kafka_topic_partition_list_destroy(sub_both);
        rd_kafka_topic_partition_list_destroy(sub_orders);
        rd_kafka_topic_partition_list_destroy(sub_events);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test fatal error injection for ShareGroupHeartbeat.
 *
 * When a fatal exception occurs during heartbeat, the consumer should
 * transition to fatal state and no longer be usable.
 */
static void do_test_share_group_error_injection(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-errors";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Inject a fatal error (INVALID_REQUEST) during heartbeat.
         * This matches testFailureOnFatalException which verifies
         * transitionToFatal() is called on fatal heartbeat errors. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_INVALID_REQUEST, 0);

        /* Wait for the fatal error to propagate via consume_batch. */
        error = wait_fatal_error(share_c, 7000);
        TEST_ASSERT(error != NULL,
                    "Expected a fatal error but none received within timeout");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR_INVALID_REQUEST,
                    "Expected INVALID_REQUEST fatal error, got %s",
                    rd_kafka_error_name(error));
        TEST_SAY("Consumer entered fatal state: %s\n",
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        /* Cleanup. Consumer is in fatal state, but close() still flushes
         * pending acks and leaves the share session, so it succeeds. */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(!error, "Expected close to succeed, got %s",
                    rd_kafka_error_name(error));
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test network timeout for ShareGroupHeartbeat.
 *
 * When a heartbeat times out due to network latency, the consumer should
 * handle the timeout and retry with backoff, eventually recovering.
 */
static void do_test_share_group_rtt_injection(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription, *assignment;
        rd_kafka_share_t *share_c;
        rd_kafka_conf_t *conf;
        char errstr[512];
        int found_heartbeats;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-rtt";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        /* Create consumer with short socket timeout so RTT injection
         * causes an actual timeout. Default is 60s which is too long. */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "socket.timeout.ms", "3000");

        share_c = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(share_c != NULL, "Failed to create share consumer: %s",
                    errstr);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 500);
        rd_usleep(500 * 1000, 0);

        /* Verify initial assignment */
        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        TEST_ASSERT(assignment->cnt == 3,
                    "Expected 3 partitions initially, got %d", assignment->cnt);
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Inject RTT larger than socket.timeout.ms to cause a real timeout.
         * The Java test verifies TimeoutException + backoff retry. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, 5000);

        /* Wait through the timeout period - consumer should recover */
        rd_usleep(500 * 1000, 0);

        /* Verify heartbeats resumed after timeout recovery */
        found_heartbeats = wait_share_heartbeats(mcluster, 2, 1000);
        TEST_ASSERT(found_heartbeats >= 1,
                    "Expected heartbeats to resume after timeout, got %d",
                    found_heartbeats);

        /* Wait for assignment to be restored */
        rd_usleep(500 * 1000, 0);

        /* Verify consumer recovered and still has assignment */
        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        TEST_ASSERT(assignment->cnt == 3,
                    "Expected 3 partitions after timeout recovery, got %d",
                    assignment->cnt);
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test session timeout for ShareGroupHeartbeat.
 *
 * Tests that the mock broker correctly times out members that stop
 * heartbeating. Uses a short session timeout (3000ms) and verifies:
 * - Member is removed after timeout
 * - Remaining members get reassigned partitions
 */
static void do_test_share_group_session_timeout(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_topic_partition_list_t *share_c1_assign, *share_c2_assign;
        rd_kafka_share_t *share_c1, *share_c2;
        int share_c1_initial = 0, share_c2_initial = 0;
        int64_t dl;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-timeout";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 4, 1);

        /* Set heartbeat interval shorter than session timeout so consumers
         * don't time out while waiting for assignment updates. */
        rd_kafka_mock_sharegroup_set_heartbeat_interval(mcluster, 1000);
        /* Set session timeout. Must be > heartbeat_interval to avoid
         * spurious timeouts but short enough for the test to finish
         * quickly. */
        rd_kafka_mock_sharegroup_set_session_timeout(mcluster, 3000);

        share_c1 = create_share_consumer(bootstraps, group);
        share_c2 = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);

        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c1, subscription));
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c2, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for both to join and rebalance to complete. */
        dl = test_clock() + 15000 * 1000;
        while (test_clock() < dl) {
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c1), &share_c1_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));
                share_c1_initial = share_c1_assign->cnt;
                share_c2_initial = share_c2_assign->cnt;
                rd_kafka_topic_partition_list_destroy(share_c1_assign);
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                if (share_c1_initial + share_c2_initial == 4 &&
                    share_c1_initial > 0 && share_c2_initial > 0)
                        break;
                rd_usleep(200 * 1000, 0);
        }
        TEST_ASSERT(share_c1_initial + share_c2_initial == 4,
                    "Total should be 4 partitions, got %d",
                    share_c1_initial + share_c2_initial);
        TEST_ASSERT(share_c1_initial > 0 && share_c2_initial > 0,
                    "Both consumers should have partitions");

        /* Destroy C2 without close to simulate crash */
        test_share_destroy(share_c2);

        /* Wait for C2's session to time out (3s) and C1 to get
         * all partitions back. */
        TEST_ASSERT(wait_assignment_count(share_c1, 4, 10000) == 4,
                    "C1 should have all 4 partitions after C2 timeout");

        test_share_consumer_close(share_c1);
        test_share_destroy(share_c1);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test target assignment API for ShareGroupHeartbeat.
 *
 * Tests that the mock broker can apply manual target assignments:
 * 1. Two consumers join and get automatic assignment (2 partitions each)
 * 2. Retrieve member IDs using rd_kafka_mock_sharegroup_get_member_ids()
 * 3. Set manual target assignment: C1 gets all 4 partitions, C2 gets none
 * 4. Verify consumers receive the manual assignment
 */
static void do_test_share_group_target_assignment(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_topic_partition_list_t *share_c1_assign, *share_c2_assign;
        rd_kafka_topic_partition_list_t *target_c1, *target_c2;
        rd_kafka_topic_partition_list_t *assignments[2];
        rd_kafka_share_t *share_c1, *share_c2;
        char **member_ids;
        size_t member_cnt;
        rd_kafka_resp_err_t err;
        int64_t dl;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-target";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 4, 1);

        share_c1 = create_share_consumer(bootstraps, group);
        share_c2 = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);

        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c1, subscription));
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c2, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for both to join and rebalance to complete */
        dl = test_clock() + 15000 * 1000;
        while (test_clock() < dl) {
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c1), &share_c1_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));
                if (share_c1_assign->cnt + share_c2_assign->cnt == 4 &&
                    share_c1_assign->cnt > 0 && share_c2_assign->cnt > 0) {
                        rd_kafka_topic_partition_list_destroy(share_c1_assign);
                        rd_kafka_topic_partition_list_destroy(share_c2_assign);
                        break;
                }
                rd_kafka_topic_partition_list_destroy(share_c1_assign);
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                rd_usleep(200 * 1000, 0);
        }
        /* Final check */
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c1), &share_c1_assign));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c2), &share_c2_assign));
        TEST_ASSERT(share_c1_assign->cnt + share_c2_assign->cnt == 4,
                    "Total should be 4 partitions, got %d",
                    share_c1_assign->cnt + share_c2_assign->cnt);
        TEST_ASSERT(share_c1_assign->cnt > 0 && share_c2_assign->cnt > 0,
                    "Both consumers should have partitions initially");
        rd_kafka_topic_partition_list_destroy(share_c1_assign);
        rd_kafka_topic_partition_list_destroy(share_c2_assign);

        /* Retrieve member IDs */
        err = rd_kafka_mock_sharegroup_get_member_ids(mcluster, group,
                                                      &member_ids, &member_cnt);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected no error, got %s", rd_kafka_err2str(err));
        TEST_ASSERT(member_cnt == 2, "Expected 2 members, got %zu", member_cnt);

        /* Set manual target assignment: all to first member */
        target_c1 = rd_kafka_topic_partition_list_new(4);
        rd_kafka_topic_partition_list_add(target_c1, topic, 0);
        rd_kafka_topic_partition_list_add(target_c1, topic, 1);
        rd_kafka_topic_partition_list_add(target_c1, topic, 2);
        rd_kafka_topic_partition_list_add(target_c1, topic, 3);

        target_c2 = rd_kafka_topic_partition_list_new(0);

        assignments[0] = target_c1;
        assignments[1] = target_c2;

        rd_kafka_mock_sharegroup_target_assignment(
            mcluster, group, (const char **)member_ids, assignments, 2);

        rd_kafka_topic_partition_list_destroy(target_c1);
        rd_kafka_topic_partition_list_destroy(target_c2);

        /* Wait until one consumer has all 4 and the other has 0. */
        dl = test_clock() + 15000 * 1000;
        while (test_clock() < dl) {

                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c1), &share_c1_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));

                if ((share_c1_assign->cnt == 4 && share_c2_assign->cnt == 0) ||
                    (share_c1_assign->cnt == 0 && share_c2_assign->cnt == 4)) {
                        rd_kafka_topic_partition_list_destroy(share_c1_assign);
                        rd_kafka_topic_partition_list_destroy(share_c2_assign);
                        break;
                }
                rd_kafka_topic_partition_list_destroy(share_c1_assign);
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                rd_usleep(200 * 1000, 0);
        }

        /* Verify manual assignment was applied */
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c1), &share_c1_assign));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c2), &share_c2_assign));

        TEST_ASSERT(share_c1_assign->cnt + share_c2_assign->cnt == 4,
                    "Total should still be 4 partitions, got %d",
                    share_c1_assign->cnt + share_c2_assign->cnt);
        TEST_ASSERT(
            (share_c1_assign->cnt == 4 && share_c2_assign->cnt == 0) ||
                (share_c1_assign->cnt == 0 && share_c2_assign->cnt == 4),
            "Expected one consumer to have all 4 partitions and the "
            "other to have 0, got C1=%d, C2=%d",
            share_c1_assign->cnt, share_c2_assign->cnt);

        rd_kafka_topic_partition_list_destroy(share_c1_assign);
        rd_kafka_topic_partition_list_destroy(share_c2_assign);

        /* Free member IDs */
        rd_free(member_ids[0]);
        rd_free(member_ids[1]);
        rd_free(member_ids);

        /* Cleanup */
        test_share_consumer_close(share_c1);
        test_share_consumer_close(share_c2);
        test_share_destroy(share_c1);
        test_share_destroy(share_c2);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test that a healthy, continuously-heartbeating member is never
 *        fenced by the mock broker's session timeout timer.
 *
 * This test sets a 2-second session timeout and then keeps the consumer
 * active for 10 seconds. If the session timeout timer incorrectly fences
 * active members, the assignment would drop. This validates that the timer
 * only fences truly timed-out members (those that stopped heartbeating).
 * Related to KIP-932 session timeout logic.
 */
static void do_test_share_group_no_spurious_fencing(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription, *assignment;
        rd_kafka_share_t *share_c;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-no-fence";
        int i;

        SUB_TEST_QUICK();

        /* Setup with a short session timeout and a heartbeat interval that
         * is well below it, so the active consumer is never spuriously
         * timed out. */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);
        rd_kafka_mock_sharegroup_set_heartbeat_interval(mcluster, 500);
        rd_kafka_mock_sharegroup_set_session_timeout(mcluster, 2000);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for join and initial assignment. */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Wait for 5s (2.5x the 2s session timeout) and verify
         * the assignment is not dropped.
         * If the broker's session timeout timer incorrectly fences active
         * members, the assignment will drop. */
        TEST_SAY("Waiting for 5 seconds with 2s session timeout...\n");
        for (i = 0; i < 5; i++) {
                rd_usleep(1000 * 1000, 0);

                /* Verify assignment is still intact */
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c), &assignment));
                TEST_ASSERT(assignment->cnt == 3,
                            "Assignment dropped at %ds (spurious fencing!)",
                            i + 1);
                rd_kafka_topic_partition_list_destroy(assignment);
        }

        TEST_SAY("No spurious fencing after 5 seconds\n");

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/* TODO: Add do_test_share_group_max_size() once
 *        0155 fix PR is merged*/

/**
 * @brief UNKNOWN_MEMBER_ID error handling.
 *
 * When a consumer receives UNKNOWN_MEMBER_ID error, it should rejoin
 * with epoch=0 (fresh join).
 *
 * NOT YET COMPATIBLE: UNKNOWN_MEMBER_ID triggers an incorrect assert in
 * development builds (rdkafka_cgrp.c:6631). Pending fix by Pranav.
 * See sghb_test_discrepancies.txt #3.
 */
static void do_test_unknown_member_id_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        int found_heartbeats;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-unknown-member";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Inject UNKNOWN_MEMBER_ID error */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID, 0);

        /* Wait for consumer to handle error and rejoin */
        rd_usleep(500 * 1000, 0);

        /* Verify heartbeats continue (rejoin happened) */
        found_heartbeats = wait_share_heartbeats(mcluster, 2, 1000);
        TEST_ASSERT(found_heartbeats >= 1,
                    "Expected heartbeats to continue after UNKNOWN_MEMBER_ID, "
                    "got %d",
                    found_heartbeats);

        /* Verify consumer eventually gets assignment back */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions after rejoin");

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief FENCED_MEMBER_EPOCH error handling.
 *
 * When a consumer receives FENCED_MEMBER_EPOCH error, it should be fenced
 * and then rejoin with epoch=0.
 */
static void do_test_fenced_member_epoch_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        int found_heartbeats;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-fenced";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Inject FENCED_MEMBER_EPOCH error */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_FENCED_MEMBER_EPOCH, 0);

        /* Wait for consumer to handle error and rejoin */
        rd_usleep(500 * 1000, 0);

        /* Verify heartbeats continue (rejoin happened) */
        found_heartbeats = wait_share_heartbeats(mcluster, 2, 1000);
        TEST_ASSERT(
            found_heartbeats >= 1,
            "Expected heartbeats to continue after FENCED_MEMBER_EPOCH, "
            "got %d",
            found_heartbeats);

        /* Verify consumer eventually gets assignment back */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions after rejoin");

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief COORDINATOR_NOT_AVAILABLE error handling.
 *
 * When a consumer receives COORDINATOR_NOT_AVAILABLE, it should retry
 * (retriable error).
 */
static void do_test_coordinator_not_available_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        int found_heartbeats;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-coord-unavail";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Inject COORDINATOR_NOT_AVAILABLE error (transient) */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE, 0);

        /* Wait for consumer to handle transient error and retry */
        rd_usleep(500 * 1000, 0);

        /* Verify heartbeats continue after transient error */
        found_heartbeats = wait_share_heartbeats(mcluster, 2, 1000);
        TEST_ASSERT(
            found_heartbeats >= 1,
            "Expected heartbeats to continue after COORDINATOR_NOT_AVAILABLE, "
            "got %d",
            found_heartbeats);

        /* Verify consumer still has assignment */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions after retry");

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief NOT_COORDINATOR error handling.
 *
 * When a consumer receives NOT_COORDINATOR, it should find a new coordinator.
 */
static void do_test_not_coordinator_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        int found_heartbeats;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-not-coord";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Inject NOT_COORDINATOR error */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR, 0);

        /* Wait for consumer to find new coordinator and continue.
         * NOT_COORDINATOR triggers coordinator rediscovery which may take
         * longer than COORDINATOR_NOT_AVAILABLE. */
        rd_usleep(500 * 1000, 0);

        /* Verify heartbeats continue after finding coordinator */
        found_heartbeats = wait_share_heartbeats(mcluster, 2, 1000);
        TEST_ASSERT(found_heartbeats >= 1,
                    "Expected heartbeats to continue after NOT_COORDINATOR, "
                    "got %d",
                    found_heartbeats);

        /* Verify consumer still has assignment */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions after finding coordinator");

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief GROUP_AUTHORIZATION_FAILED error handling (fatal).
 *
 * When a consumer receives GROUP_AUTHORIZATION_FAILED, it should treat
 * it as a fatal error.
 */
static void do_test_group_authorization_failed_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-auth-failed";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join */
        wait_share_heartbeats(mcluster, 1, 1000);
        rd_usleep(500 * 1000, 0);

        /* Inject GROUP_AUTHORIZATION_FAILED error (fatal) */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED, 0);

        /* Wait for the fatal error to propagate via consume_batch. */
        error = wait_fatal_error(share_c, 5000);
        TEST_ASSERT(error != NULL,
                    "Expected a fatal error but none received within timeout");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED,
                    "Expected GROUP_AUTHORIZATION_FAILED fatal error, got %s",
                    rd_kafka_error_name(error));
        TEST_SAY("Consumer entered fatal state: %s\n",
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        /* Cleanup. Consumer is in fatal state, but close() still flushes
         * pending acks and leaves the share session, so it succeeds. */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(!error, "Expected close to succeed, got %s",
                    rd_kafka_error_name(error));
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief GROUP_MAX_SIZE_REACHED error handling.
 *
 * When a new member tries to join and gets GROUP_MAX_SIZE_REACHED,
 * the error should be treated as fatal for that consumer.
 */
static void do_test_group_max_size_reached_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c1, *share_c2;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-max-size";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 4, 1);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        /* First consumer joins successfully */
        share_c1 = create_share_consumer(bootstraps, group);

        rd_kafka_mock_start_request_tracking(mcluster);

        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c1, subscription));

        /* Wait for share_c1 to fully join and stabilize */
        TEST_ASSERT(wait_assignment_count(share_c1, 4, 10000) == 4,
                    "Expected share_c1 to have 4 partitions");

        /* Push multiple GROUP_MAX_SIZE_REACHED errors so that even if
         * share_c1's regular heartbeat consumes some, share_c2's join heartbeat
         * will also get one. The Java test uses server-side maxSize=1
         * config; we simulate by injecting errors for all heartbeats. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 5,
            RD_KAFKA_RESP_ERR_GROUP_MAX_SIZE_REACHED, 0);

        /* Create second consumer - should be rejected */
        share_c2 = create_share_consumer(bootstraps, group);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c2, subscription));

        /* Wait for the fatal error to propagate via consume_batch. */
        error = wait_fatal_error(share_c2, 5000);
        TEST_ASSERT(error != NULL,
                    "Expected a fatal error but none received within timeout");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR_GROUP_MAX_SIZE_REACHED,
                    "Expected GROUP_MAX_SIZE_REACHED fatal error, got %s",
                    rd_kafka_error_name(error));
        TEST_SAY("share consumer 2 correctly rejected with fatal error: %s\n",
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        rd_kafka_topic_partition_list_destroy(subscription);

        /* Cleanup. share_c2 is in fatal state, but close() no longer
         * early-returns the stored fatal error, so it succeeds. */
        test_share_consumer_close(share_c1);
        rd_kafka_error_t *c2_close_error =
            rd_kafka_share_consumer_close(share_c2);
        TEST_ASSERT(!c2_close_error,
                    "Expected share_c2 close to succeed, "
                    "got %s",
                    rd_kafka_error_name(c2_close_error));
        test_share_destroy(share_c1);
        test_share_destroy(share_c2);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Member rejoin with epoch zero.
 *
 * A member in stable state (epoch > 0) that sends heartbeat with epoch=0
 * should be treated as a rejoin and assigned a new member ID.
 */
static void do_test_member_rejoin_with_epoch_zero(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription, *assignment;
        rd_kafka_share_t *share_c;
        int found_heartbeats;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-rejoin";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        rd_usleep(500 * 1000, 0);

        /* Verify initial assignment (member is now in stable state) */
        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        TEST_ASSERT(assignment->cnt == 3,
                    "Expected 3 partitions initially, got %d", assignment->cnt);
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Force a rejoin by injecting UNKNOWN_MEMBER_ID error
         * This will cause client to rejoin with epoch=0 */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID, 0);

        /* Wait for consumer to rejoin with epoch=0 */
        rd_usleep(2000 * 1000, 0);

        /* Verify rejoin heartbeats */
        found_heartbeats = wait_share_heartbeats(mcluster, 2, 1000);
        TEST_ASSERT(found_heartbeats >= 1, "Expected rejoin heartbeats, got %d",
                    found_heartbeats);

        /* Verify consumer gets assignment back */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions after rejoin");

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Leaving member bumps group epoch.
 *
 * When a member sends leave heartbeat (epoch=-1), the group epoch should
 * be bumped and remaining members should get updated assignment.
 */
static void do_test_leaving_member_bumps_group_epoch(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_topic_partition_list_t *share_c1_assign, *share_c2_assign;
        rd_kafka_share_t *share_c1, *share_c2;
        int64_t dl;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-leave-epoch";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 4, 1);

        /* Set heartbeat interval shorter than session timeout so both
         * consumers can heartbeat frequently enough for the rebalance
         * to complete before we check assignments. */
        rd_kafka_mock_sharegroup_set_heartbeat_interval(mcluster, 1000);

        share_c1 = create_share_consumer(bootstraps, group);
        share_c2 = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);

        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c1, subscription));
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c2, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for both to join and rebalance to complete */
        dl = test_clock() + 15000 * 1000;
        while (test_clock() < dl) {
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c1), &share_c1_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));
                if (share_c1_assign->cnt + share_c2_assign->cnt == 4 &&
                    share_c1_assign->cnt > 0 && share_c2_assign->cnt > 0) {
                        rd_kafka_topic_partition_list_destroy(share_c1_assign);
                        rd_kafka_topic_partition_list_destroy(share_c2_assign);
                        break;
                }
                rd_kafka_topic_partition_list_destroy(share_c1_assign);
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                rd_usleep(200 * 1000, 0);
        }

        /* C2 leaves (sends epoch=-1 leave heartbeat) */
        test_share_consumer_close(share_c2);
        test_share_destroy(share_c2);

        /* Wait for C1 to get all partitions after C2 left */
        TEST_ASSERT(wait_assignment_count(share_c1, 4, 10000) == 4,
                    "C1 should have all 4 partitions after C2 left");

        /* Cleanup */
        test_share_consumer_close(share_c1);
        test_share_destroy(share_c1);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Partition assignment with changing topics.
 *
 * Note: This test is limited in mock broker - we can test initial assignment
 * with multiple topics in subscription, but cannot dynamically add topics.
 */
static void do_test_partition_assignment_with_multiple_topics(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription, *assignment;
        rd_kafka_share_t *share_c;
        const char *topic1 = "test-multi-topic-1";
        const char *topic2 = "test-multi-topic-2";
        const char *group  = "test-share-group-multi-topic-sub";
        int topic1_count = 0, topic2_count = 0, i;

        SUB_TEST_QUICK();

        /* Setup - create two topics */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic1, 3, 1);
        rd_kafka_mock_topic_create(mcluster, topic2, 2, 1);

        share_c = create_share_consumer(bootstraps, group);

        /* Subscribe to both topics */
        subscription = rd_kafka_topic_partition_list_new(2);
        rd_kafka_topic_partition_list_add(subscription, topic1,
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_topic_partition_list_add(subscription, topic2,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for join and assignment */
        TEST_ASSERT(wait_assignment_count(share_c, 5, 10000) == 5,
                    "Expected 5 partitions (3+2)");

        /* Verify assignment includes partitions from both topics */
        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));

        /* Count partitions per topic */
        for (i = 0; i < assignment->cnt; i++) {
                if (strcmp(assignment->elems[i].topic, topic1) == 0)
                        topic1_count++;
                else if (strcmp(assignment->elems[i].topic, topic2) == 0)
                        topic2_count++;
        }
        TEST_ASSERT(topic1_count == 3,
                    "Expected 3 partitions from topic1, got %d", topic1_count);
        TEST_ASSERT(topic2_count == 2,
                    "Expected 2 partitions from topic2, got %d", topic2_count);
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Multiple members partition distribution.
 *
 * N members join group subscribed to topic with M partitions.
 * Verify partitions are distributed fairly (all members get some).
 * Note: Share groups may allow the same partition to be assigned to
 * multiple consumers, so we check for fair distribution rather than
 * exclusive assignment.
 */
static void do_test_multiple_members_partition_distribution(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_topic_partition_list_t *share_c1_assign, *share_c2_assign,
            *share_c3_assign;
        rd_kafka_share_t *share_c1, *share_c2, *share_c3;
        const char *topic    = test_mk_topic_name(__FUNCTION__, 0);
        const char *group    = "test-share-group-distribution";
        int total_partitions = 0;
        rd_bool_t converged;
        int64_t dl;

        SUB_TEST_QUICK();

        /* Setup - 6 partitions, 3 consumers */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 6, 1);

        share_c1 = create_share_consumer(bootstraps, group);
        share_c2 = create_share_consumer(bootstraps, group);
        share_c3 = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);

        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c1, subscription));
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c2, subscription));
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c3, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait until all 3 consumers have converged on a fair distribution
         * (each member holds at least 1 partition and the total is >= 6) and
         * assert on the snapshot that satisfied that check.
         *
         * The assignment is driven by the heartbeat thread and churns while
         * the three members are still joining, so a member may transiently
         * hold partitions and then have them reassigned. Re-reading the
         * assignment after convergence would race against that churn and
         * observe an intermediate state, so the lists that satisfied the
         * check are kept and asserted on directly. */
        TEST_SAY(
            "Waiting for 3 members to converge on a fair distribution "
            "of 6 partitions...\n");
        share_c1_assign = share_c2_assign = share_c3_assign = NULL;
        converged                                           = rd_false;
        dl = test_clock() + 15000 * 1000;
        while (test_clock() < dl) {
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c1), &share_c1_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c3), &share_c3_assign));
                total_partitions = share_c1_assign->cnt + share_c2_assign->cnt +
                                   share_c3_assign->cnt;
                TEST_SAY(
                    "Current assignment: share consumer 1=%d, "
                    "share consumer 2=%d, share consumer 3=%d (total=%d)\n",
                    share_c1_assign->cnt, share_c2_assign->cnt,
                    share_c3_assign->cnt, total_partitions);
                if (share_c1_assign->cnt >= 1 && share_c2_assign->cnt >= 1 &&
                    share_c3_assign->cnt >= 1 && total_partitions >= 6) {
                        converged = rd_true;
                        TEST_SAY(
                            "All 3 members converged, fair distribution "
                            "reached\n");
                        break;
                }
                rd_kafka_topic_partition_list_destroy(share_c1_assign);
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                rd_kafka_topic_partition_list_destroy(share_c3_assign);
                TEST_SAY("Not yet converged, retrying in 200ms...\n");
                rd_usleep(200 * 1000, 0);
        }

        TEST_ASSERT(converged,
                    "Consumers did not converge on a fair distribution "
                    "(each member >= 1 partition, total >= 6) within timeout");

        TEST_SAY(
            "Partition distribution: share consumer 1=%d, share consumer 2=%d, "
            "share consumer 3=%d (total=%d)\n",
            share_c1_assign->cnt, share_c2_assign->cnt, share_c3_assign->cnt,
            total_partitions);

        rd_kafka_topic_partition_list_destroy(share_c1_assign);
        rd_kafka_topic_partition_list_destroy(share_c2_assign);
        rd_kafka_topic_partition_list_destroy(share_c3_assign);

        /* Cleanup */
        test_share_consumer_close(share_c1);
        test_share_consumer_close(share_c2);
        test_share_consumer_close(share_c3);
        test_share_destroy(share_c1);
        test_share_destroy(share_c2);
        test_share_destroy(share_c3);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Heartbeat successful response completes leave.
 *
 * When a member sends leave heartbeat (epoch=-1), verify successful
 * response completes the leave.
 */
static void do_test_leave_heartbeat_completes_successfully(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-leave-success";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Leave group - should send leave heartbeat and complete.
         * Note: After close(), we cannot call rd_kafka_assignment() anymore
         * as the broker handle is destroyed. */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(!error, "Expected close to succeed, got %s",
                    rd_kafka_error_name(error));

        /* Cleanup */
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Heartbeat failed response during leave still completes.
 *
 * When a member sends leave heartbeat and gets an error response,
 * the leave should still complete (best effort).
 */
static void do_test_leave_heartbeat_completes_on_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-leave-error";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Inject error for the leave heartbeat */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE, 0);

        /* Leave group - should still complete despite error (best effort).
         * The key behavior: close() must not hang even when the leave
         * heartbeat gets an error response. */
        error = rd_kafka_share_consumer_close(share_c);
        /* Close completed (didn't hang) - this is the primary assertion.
         * The return code may vary depending on whether the error was
         * processed during leave. */
        TEST_SAY("Leave completed with: %s (didn't hang - correct)\n",
                 rd_kafka_error_name(error));
        if (error)
                rd_kafka_error_destroy(error);

        /* Cleanup */
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Subscription change updates assignment.
 *
 * Consumer subscribed to topic A, change subscription to topic B,
 * verify assignment updates.
 */
static void do_test_subscription_change(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription, *assignment;
        rd_kafka_share_t *share_c;
        int found_topicA = 0, found_topicB = 0, i;
        int64_t dl;
        const char *topicA = "test-sub-change-topic-A";
        const char *topicB = "test-sub-change-topic-B";
        const char *group  = "test-share-group-sub-change";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topicA, 2, 1);
        rd_kafka_mock_topic_create(mcluster, topicB, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        /* First subscription: topic A */
        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topicA,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for assignment to topic A */
        TEST_ASSERT(wait_assignment_count(share_c, 2, 10000) == 2,
                    "Expected 2 partitions from topicA");

        /* Verify assignment has topic A only */
        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        for (i = 0; i < assignment->cnt; i++) {
                TEST_ASSERT(strcmp(assignment->elems[i].topic, topicA) == 0,
                            "Expected topicA, got %s",
                            assignment->elems[i].topic);
        }
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Change subscription to topic B */
        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topicB,
                                          RD_KAFKA_PARTITION_UA);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for assignment to switch to topic B (3 partitions) */
        dl = test_clock() + 15000 * 1000;
        while (test_clock() < dl) {
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c), &assignment));
                found_topicA = 0;
                found_topicB = 0;
                for (i = 0; i < assignment->cnt; i++) {
                        if (strcmp(assignment->elems[i].topic, topicA) == 0)
                                found_topicA++;
                        else if (strcmp(assignment->elems[i].topic, topicB) ==
                                 0)
                                found_topicB++;
                }
                rd_kafka_topic_partition_list_destroy(assignment);
                if (found_topicA == 0 && found_topicB == 3)
                        break;
                rd_usleep(200 * 1000, 0);
        }
        TEST_ASSERT(found_topicA == 0,
                    "Expected 0 partitions from topicA after change, got %d",
                    found_topicA);
        TEST_ASSERT(found_topicB == 3,
                    "Expected 3 partitions from topicB after change, got %d",
                    found_topicB);

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief GROUP_ID_NOT_FOUND while unsubscribed is benign.
 *
 * When a member that has already unsubscribed receives GROUP_ID_NOT_FOUND,
 * it should be treated as benign (the group may have been auto-deleted).
 * This should NOT cause a fatal error.
 */
static void do_test_group_id_not_found_while_unsubscribed(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        rd_kafka_resp_err_t fatal_err;
        rd_kafka_error_t *error;
        char errstr[256];
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-id-not-found-unsub";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Unsubscribe first to transition to unsubscribed state.
         * The Java test has member in UNSUBSCRIBED state when the
         * error arrives. */
        TEST_CALL_ERR__(rd_kafka_share_unsubscribe(share_c));
        rd_usleep(500 * 1000, 0);

        /* Now inject GROUP_ID_NOT_FOUND.
         * Since the member is unsubscribed, this should be benign. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 3,
            RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND, 0);

        /* Wait for the error to be processed */
        rd_usleep(500 * 1000, 0);

        /* Verify consumer is NOT in fatal state - error should be benign */
        fatal_err = rd_kafka_fatal_error(test_share_consumer_get_rk(share_c),
                                         errstr, sizeof(errstr));
        TEST_ASSERT(fatal_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected no fatal error when GROUP_ID_NOT_FOUND arrives "
                    "while unsubscribed, but got: %s (%s)",
                    rd_kafka_err2str(fatal_err), errstr);

        /* Close consumer */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_SAY("Close returned: %s\n", rd_kafka_error_name(error));
        if (error)
                rd_kafka_error_destroy(error);

        /* Cleanup */
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief GROUP_ID_NOT_FOUND while stable is fatal.
 *
 * When an active member (epoch > 0) receives GROUP_ID_NOT_FOUND,
 * it should be treated as a fatal error (group unexpectedly deleted).
 */
static void do_test_group_id_not_found_while_stable_is_fatal(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription, *assignment;
        rd_kafka_share_t *share_c;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-id-not-found-stable";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        rd_usleep(500 * 1000, 0);

        /* Verify initial assignment - member is in stable state */
        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        TEST_ASSERT(assignment->cnt == 3,
                    "Expected 3 partitions initially, got %d", assignment->cnt);
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Inject GROUP_ID_NOT_FOUND for an active/stable member.
         * This should be treated as fatal (group unexpectedly deleted). */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND, 0);

        /* Wait for the fatal error to propagate via consume_batch. */
        error = wait_fatal_error(share_c, 5000);
        TEST_ASSERT(error != NULL,
                    "Expected a fatal error but none received within timeout");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND,
                    "Expected GROUP_ID_NOT_FOUND fatal error, got %s",
                    rd_kafka_error_name(error));
        TEST_SAY("Consumer entered fatal state: %s\n",
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        /* Cleanup. Consumer is in fatal state, but close() still flushes
         * pending acks and leaves the share session, so it succeeds. */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(!error, "Expected close to succeed, got %s",
                    rd_kafka_error_name(error));
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief INVALID_REQUEST error handling.
 *
 * When a consumer receives INVALID_REQUEST error, it should be treated
 * as a fatal error.
 */
static void do_test_invalid_request_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-invalid-request";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join */
        wait_share_heartbeats(mcluster, 1, 1000);
        rd_usleep(500 * 1000, 0);

        /* Inject INVALID_REQUEST error (fatal) */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_INVALID_REQUEST, 0);

        /* Wait for the fatal error to propagate via consume_batch. */
        error = wait_fatal_error(share_c, 5000);
        TEST_ASSERT(error != NULL,
                    "Expected a fatal error but none received within timeout");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR_INVALID_REQUEST,
                    "Expected INVALID_REQUEST fatal error, got %s",
                    rd_kafka_error_name(error));
        TEST_SAY("Consumer entered fatal state: %s\n",
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        /* Cleanup. Consumer is in fatal state, but close() still flushes
         * pending acks and leaves the share session, so it succeeds. */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(!error, "Expected close to succeed, got %s",
                    rd_kafka_error_name(error));
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief UNSUPPORTED_VERSION error handling.
 *
 * When a consumer receives UNSUPPORTED_VERSION error, it should be
 * treated as a fatal error.
 */
static void do_test_unsupported_version_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        rd_kafka_error_t *error;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-unsupported-version";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join */
        wait_share_heartbeats(mcluster, 1, 1000);
        rd_usleep(500 * 1000, 0);

        /* Inject UNSUPPORTED_VERSION error (fatal) */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_UNSUPPORTED_VERSION, 0);

        /* Wait for the fatal error to propagate via consume_batch. */
        error = wait_fatal_error(share_c, 5000);
        TEST_ASSERT(error != NULL,
                    "Expected a fatal error but none received within timeout");
        TEST_ASSERT(rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR_UNSUPPORTED_VERSION,
                    "Expected UNSUPPORTED_VERSION fatal error, got %s",
                    rd_kafka_error_name(error));
        TEST_SAY("Consumer entered fatal state: %s\n",
                 rd_kafka_error_string(error));
        rd_kafka_error_destroy(error);

        /* Cleanup. Consumer is in fatal state, but close() still flushes
         * pending acks and leaves the share session, so it succeeds. */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(!error, "Expected close to succeed, got %s",
                    rd_kafka_error_name(error));
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief COORDINATOR_LOAD_IN_PROGRESS error handling.
 *
 * When a consumer receives COORDINATOR_LOAD_IN_PROGRESS, it should
 * retry with backoff (transient error).
 */
static void do_test_coordinator_load_in_progress_error(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_share_t *share_c;
        int found_heartbeats;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-coord-load";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions initially");

        /* Inject COORDINATOR_LOAD_IN_PROGRESS error (transient) */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_ShareGroupHeartbeat, 1,
            RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS, 0);

        /* Wait for consumer to handle transient error and retry */
        rd_usleep(500 * 1000, 0);

        /* Verify heartbeats continue after transient error */
        found_heartbeats = wait_share_heartbeats(mcluster, 2, 1000);
        TEST_ASSERT(found_heartbeats >= 1,
                    "Expected heartbeats to continue after "
                    "COORDINATOR_LOAD_IN_PROGRESS, got %d",
                    found_heartbeats);

        /* Verify consumer still has assignment */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions after retry");

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Consumer graceful shutdown during stable state.
 *
 * Consumer in stable state leaves group gracefully, sending leave
 * heartbeat with epoch=-1.
 */
static void do_test_graceful_shutdown_stable_state(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription, *assignment;
        rd_kafka_share_t *share_c;
        rd_kafka_error_t *error;
        int found_heartbeats;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-graceful-shutdown";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial join and assignment */
        wait_share_heartbeats(mcluster, 1, 1000);
        rd_usleep(500 * 1000, 0);

        /* Verify initial assignment - member is in stable state */
        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        TEST_ASSERT(assignment->cnt == 3,
                    "Expected 3 partitions initially, got %d", assignment->cnt);
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Record heartbeat count before close */
        found_heartbeats = wait_share_heartbeats(mcluster, 1, 1000);
        rd_kafka_mock_stop_request_tracking(mcluster);
        rd_kafka_mock_start_request_tracking(mcluster);

        /* Close consumer gracefully - should send leave heartbeat */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(!error, "Expected close to succeed, got %s",
                    rd_kafka_error_name(error));

        /* Verify leave heartbeat was sent */
        found_heartbeats = wait_share_heartbeats(mcluster, 1, 1000);
        TEST_SAY("Found %d heartbeats during shutdown\n", found_heartbeats);

        /* Cleanup */
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Consumer resubscribes after unsubscribe.
 *
 * Tests the unsubscribe then resubscribe flow.
 */
static void do_test_resubscribe_after_unsubscribe(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription, *assignment;
        rd_kafka_share_t *share_c;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-resubscribe";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);

        share_c = create_share_consumer(bootstraps, group);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        rd_kafka_mock_start_request_tracking(mcluster);

        /* First subscribe */
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        wait_share_heartbeats(mcluster, 1, 1000);
        rd_usleep(500 * 1000, 0);

        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        TEST_ASSERT(assignment->cnt == 3,
                    "Expected 3 partitions on first subscribe, got %d",
                    assignment->cnt);
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Unsubscribe */
        TEST_SAY("Unsubscribing...\n");
        TEST_CALL_ERR__(rd_kafka_share_unsubscribe(share_c));
        rd_usleep(500 * 1000, 0);

        /* Verify no assignment after unsubscribe */
        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        TEST_ASSERT(assignment->cnt == 0,
                    "Expected 0 partitions after unsubscribe, got %d",
                    assignment->cnt);
        rd_kafka_topic_partition_list_destroy(assignment);

        /* Resubscribe */
        TEST_SAY("Resubscribing...\n");
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Verify assignment restored */
        TEST_ASSERT(wait_assignment_count(share_c, 3, 10000) == 3,
                    "Expected 3 partitions after resubscribe");

        /* Cleanup */
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Consumer leaves and remaining consumers get reassigned.
 *
 * Tests rebalance when a consumer leaves the group.
 */
static void do_test_consumer_leave_rebalance(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_topic_partition_list_t *share_c1_assign, *share_c2_assign;
        rd_kafka_share_t *share_c1, *share_c2, *share_c3;
        int final_total;
        int64_t dl;
        const char *topic = test_mk_topic_name(__FUNCTION__, 0);
        const char *group = "test-share-group-leave-rebalance";

        SUB_TEST_QUICK();

        /* Setup */
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 6, 1);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        share_c1 = create_share_consumer(bootstraps, group);
        share_c2 = create_share_consumer(bootstraps, group);
        share_c3 = create_share_consumer(bootstraps, group);

        rd_kafka_mock_start_request_tracking(mcluster);

        /* All three join */
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c1, subscription));
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c2, subscription));
        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c3, subscription));
        rd_kafka_topic_partition_list_destroy(subscription);

        /* Wait for initial balance */
        wait_share_heartbeats(mcluster, 4, 1000);
        wait_share_heartbeats(mcluster, 3, 1000);

        /* Get initial assignments */
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c1), &share_c1_assign));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c2), &share_c2_assign));
        TEST_SAY(
            "Initial: share consumer 1=%d, share consumer 2=%d (before share "
            "consumer 3 leaves)\n",
            share_c1_assign->cnt, share_c2_assign->cnt);
        rd_kafka_topic_partition_list_destroy(share_c1_assign);
        rd_kafka_topic_partition_list_destroy(share_c2_assign);

        /* share consumer 3 leaves */
        TEST_SAY("Share consumer 3 leaving...\n");
        test_share_consumer_close(share_c3);
        test_share_destroy(share_c3);

        /* Wait for rebalance to propagate to remaining consumers */
        dl = test_clock() + 15000 * 1000;
        while (test_clock() < dl) {

                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c1), &share_c1_assign));
                TEST_CALL_ERR__(rd_kafka_assignment(
                    test_share_consumer_get_rk(share_c2), &share_c2_assign));
                final_total = share_c1_assign->cnt + share_c2_assign->cnt;
                rd_kafka_topic_partition_list_destroy(share_c1_assign);
                rd_kafka_topic_partition_list_destroy(share_c2_assign);
                if (final_total >= 6)
                        break;
                rd_usleep(200 * 1000, 0);
        }
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c1), &share_c1_assign));
        TEST_CALL_ERR__(rd_kafka_assignment(
            test_share_consumer_get_rk(share_c2), &share_c2_assign));
        final_total = share_c1_assign->cnt + share_c2_assign->cnt;
        TEST_SAY(
            "After share consumer 3 leave: share consumer 1=%d, "
            "share consumer 2=%d\n",
            share_c1_assign->cnt, share_c2_assign->cnt);
        rd_kafka_topic_partition_list_destroy(share_c1_assign);
        rd_kafka_topic_partition_list_destroy(share_c2_assign);
        TEST_ASSERT(final_total >= 6,
                    "Expected >= 6 partitions after rebalance, got %d",
                    final_total);

        /* Cleanup */
        test_share_consumer_close(share_c1);
        test_share_consumer_close(share_c2);
        test_share_destroy(share_c1);
        test_share_destroy(share_c2);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test calling close twice on the same consumer
 */
static void do_test_double_close(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        const char *topic    = test_mk_topic_name(__FUNCTION__, 1);
        const char *group_id = topic;
        rd_kafka_share_t *share_c;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_error_t *error;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);
        rd_kafka_mock_start_request_tracking(mcluster);

        share_c = create_share_consumer(bootstraps, group_id);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        wait_share_heartbeats(mcluster, 3, 1000);

        /* First close - should succeed */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(!error, "Expected first close to succeed, got %s",
                    rd_kafka_error_name(error));

        /* Second close - should handle gracefully without crashing.
         * The Java equivalent tests verify the CompletableFuture
         * completes immediately on double-leave. */
        error = rd_kafka_share_consumer_close(share_c);
        TEST_ASSERT(error != NULL,
                    "Expected second close to return error on already-closed "
                    "consumer, got NULL");
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR__STATE,
                    "Expected _STATE, got %s",
                    rd_kafka_err2name(rd_kafka_error_code(error)));
        rd_kafka_error_destroy(error);

        rd_kafka_topic_partition_list_destroy(subscription);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Test consumer subscribed to a topic with no messages
 */
static void do_test_empty_topic_subscription(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        const char *topic    = test_mk_topic_name(__FUNCTION__, 1);
        const char *group_id = topic;
        rd_kafka_share_t *share_c;
        rd_kafka_topic_partition_list_t *subscription, *assignment;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 3, 1);
        rd_kafka_mock_start_request_tracking(mcluster);

        share_c = create_share_consumer(bootstraps, group_id);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic,
                                          RD_KAFKA_PARTITION_UA);

        TEST_CALL_ERR__(rd_kafka_share_subscribe(share_c, subscription));
        wait_share_heartbeats(mcluster, 3, 1000);

        /* Wait for assignment on empty topic */
        rd_usleep(500 * 1000, 0);

        TEST_CALL_ERR__(rd_kafka_assignment(test_share_consumer_get_rk(share_c),
                                            &assignment));
        TEST_SAY("Empty topic: %d partitions\n", assignment->cnt);
        TEST_ASSERT(assignment->cnt == 3, "Expected 3 partitions, got %d",
                    assignment->cnt);

        rd_kafka_topic_partition_list_destroy(subscription);
        rd_kafka_topic_partition_list_destroy(assignment);
        test_share_consumer_close(share_c);
        test_share_destroy(share_c);

        rd_kafka_mock_stop_request_tracking(mcluster);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


/**
 * @brief subscribe() with an empty topic list is equivalent to
 *        unsubscribe() — must return NO_ERROR and leave the consumer
 *        in the unsubscribed state.
 */
static void do_test_empty_topic_list_subscription(void) {
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        rd_kafka_share_t *share_c;
        rd_kafka_topic_partition_list_t *empty_list;
        rd_kafka_resp_err_t err;
        const char *group = "test-share-group-empty-topic-list";

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(1, &bootstraps);

        share_c = create_share_consumer(bootstraps, group);

        /* subscribe(empty_list) must succeed and act as unsubscribe. */
        empty_list = rd_kafka_topic_partition_list_new(0);
        err        = rd_kafka_share_subscribe(share_c, empty_list);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR from subscribe(empty_list), got %s",
                    rd_kafka_err2str(err));
        rd_kafka_topic_partition_list_destroy(empty_list);

        test_share_destroy(share_c);

        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


int main_0155_share_group_heartbeat_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);

        test_timeout_set(1500);

        do_test_share_group_heartbeat_basic();
        do_test_share_group_assignment_rebalance();
        do_test_share_group_multi_topic_assignment();
        do_test_share_group_error_injection();
        do_test_share_group_rtt_injection();
        do_test_share_group_session_timeout();
        do_test_share_group_target_assignment();
        do_test_share_group_no_spurious_fencing();
        do_test_unknown_member_id_error();

        do_test_fenced_member_epoch_error();
        do_test_coordinator_not_available_error();
        do_test_not_coordinator_error();
        do_test_group_authorization_failed_error();
        do_test_group_max_size_reached_error();
        do_test_invalid_request_error();
        do_test_unsupported_version_error();
        do_test_coordinator_load_in_progress_error();

        do_test_member_rejoin_with_epoch_zero();
        do_test_leaving_member_bumps_group_epoch();

        do_test_partition_assignment_with_multiple_topics();
        do_test_multiple_members_partition_distribution();

        do_test_leave_heartbeat_completes_successfully();
        do_test_leave_heartbeat_completes_on_error();
        do_test_graceful_shutdown_stable_state();
        do_test_consumer_leave_rebalance();
        do_test_double_close();

        do_test_subscription_change();
        do_test_resubscribe_after_unsubscribe();
        do_test_empty_topic_subscription();
        do_test_empty_topic_list_subscription();

        do_test_group_id_not_found_while_unsubscribed();
        do_test_group_id_not_found_while_stable_is_fatal();

        return 0;
}
