/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2025, Confluent Inc.
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
#include "testshared.h"
#include "rdkafka.h"

/**
 * @brief Share consumer subscription tests using operation-based framework.
 *
 * This test file uses a declarative, operation-based framework where tests
 * are defined as sequences of operations. The framework handles:
 * - Automatic topic name generation
 * - Topic creation and deletion
 * - Consumer creation and destruction
 * - Message production and consumption
 * - Subscription verification
 */


#define MAX_TOPICS    20
#define MAX_CONSUMERS 4
#define MAX_OPS       50

/** Common producer reused across all tests. */
static rd_kafka_t *common_producer;

/** Common admin client reused across all tests. */
static rd_kafka_t *common_admin;

/**
 * @brief Operation types for subscription tests
 */
typedef enum {
        TEST_OP_END = 0,         /**< End of operations marker */
        TEST_OP_SUBSCRIBE,       /**< Subscribe to N new topics */
        TEST_OP_SUBSCRIBE_ADD,   /**< Add N topics to existing subscription */
        TEST_OP_UNSUBSCRIBE,     /**< Unsubscribe from all topics */
        TEST_OP_RESUBSCRIBE,     /**< Replace subscription with N new topics */
        TEST_OP_PRODUCE,         /**< Produce to specified topic set */
        TEST_OP_CONSUME,         /**< Consume messages */
        TEST_OP_VERIFY_SUB_CNT,  /**< Verify subscription count */
        TEST_OP_DELETE_TOPIC,    /**< Delete topic by index */
        TEST_OP_WAIT,            /**< Wait for specified milliseconds */
        TEST_OP_CREATE_CONSUMER, /**< Create additional consumer */
        TEST_OP_POLL_NO_SUB,     /**< Poll without subscription (edge case) */
        TEST_OP_CREATE_TOPIC, /**< Create subscribed topics that weren't created
                               */
        TEST_OP_SUBSCRIBE_EXISTING, /**< Subscribe to already created topics */
        TEST_OP_PRODUCE_TO_TOPIC,   /**< Produce to specific topic index */
        TEST_OP_SUBSCRIBE_EMPTY,    /**< Subscribe with empty list (==
                                     unsubscribe) */
} test_op_type_t;

/**
 * @brief Flags for operations
 */
typedef enum {
        TEST_OP_F_NONE              = 0,
        TEST_OP_F_SKIP_TOPIC_CREATE = 1 << 0, /**< Don't create topics */
        TEST_OP_F_PRODUCE_TO_OLD = 1 << 1, /**< Produce to old subscription */
        TEST_OP_F_VERIFY_NO_OLD_MSGS = 1 << 2, /**< Verify no old messages */
} test_op_flags_t;

/**
 * @brief Single operation in a test scenario
 */
typedef struct {
        test_op_type_t op;     /**< Operation type */
        int topic_cnt;         /**< Number of topics (SUBSCRIBE/RESUBSCRIBE) */
        int msgs_per_topic;    /**< Messages per topic (PRODUCE) */
        int expected_msgs;     /**< Expected message count (CONSUME, -1=any) */
        int expected_sub_cnt;  /**< Expected subscription count (VERIFY_SUB_CNT)
                                */
        int topic_idx;         /**< Topic index (DELETE_TOPIC) */
        int wait_ms;           /**< Wait time (WAIT) */
        int consumer_idx;      /**< Consumer index (multi-consumer) */
        int repeat_cnt;        /**< Repeat count (SUBSCRIBE/UNSUBSCRIBE) */
        test_op_flags_t flags; /**< Operation flags */
} test_op_t;

/**
 * @brief Test scenario configuration
 */
typedef struct {
        const char *name;       /**< Test name for logging */
        int consumer_cnt;       /**< Number of consumers (default: 1) */
        test_op_t ops[MAX_OPS]; /**< Operations, terminated by TEST_OP_END */
} test_scenario_t;

/**
 * @brief Runtime state for test execution
 */
typedef struct {
        /* Consumers */
        rd_kafka_share_t *consumers[MAX_CONSUMERS];
        int consumer_cnt;

        /* Topics: all created topics */
        char *all_topics[MAX_TOPICS];
        int all_topic_cnt;
        int msgs_produced[MAX_TOPICS]; /**< Messages produced per topic */

        /* Current subscription tracking per consumer */
        int sub_start_idx[MAX_CONSUMERS]; /**< Start index in all_topics */
        int sub_count[MAX_CONSUMERS];     /**< Count of subscribed topics */

        /* Previous subscription (for RESUBSCRIBE verification) */
        int old_sub_start_idx;
        int old_sub_count;

        /* Group name */
        char group_name[128];
} sub_test_state_t;


#define SUBSCRIBE(n)                                                           \
        { .op = TEST_OP_SUBSCRIBE, .topic_cnt = (n), .repeat_cnt = 1 }
#define SUBSCRIBE_REPEAT(n, r)                                                 \
        { .op = TEST_OP_SUBSCRIBE, .topic_cnt = (n), .repeat_cnt = (r) }
#define SUBSCRIBE_ADD(n)                                                       \
        { .op = TEST_OP_SUBSCRIBE_ADD, .topic_cnt = (n) }
#define SUBSCRIBE_NO_CREATE(n)                                                 \
        {                                                                      \
                .op = TEST_OP_SUBSCRIBE, .topic_cnt = (n), .repeat_cnt = 1,    \
                .flags = TEST_OP_F_SKIP_TOPIC_CREATE                           \
        }
#define UNSUBSCRIBE()                                                          \
        { .op = TEST_OP_UNSUBSCRIBE, .repeat_cnt = 1 }
#define UNSUBSCRIBE_REPEAT(r)                                                  \
        { .op = TEST_OP_UNSUBSCRIBE, .repeat_cnt = (r) }
#define RESUBSCRIBE(n)                                                         \
        { .op = TEST_OP_RESUBSCRIBE, .topic_cnt = (n) }
#define PRODUCE(msgs)                                                          \
        { .op = TEST_OP_PRODUCE, .msgs_per_topic = (msgs) }
#define PRODUCE_TO_OLD(msgs)                                                   \
        {                                                                      \
                .op = TEST_OP_PRODUCE, .msgs_per_topic = (msgs),               \
                .flags = TEST_OP_F_PRODUCE_TO_OLD                              \
        }
#define PRODUCE_TO_TOPIC(idx, msgs)                                            \
        {                                                                      \
                .op = TEST_OP_PRODUCE_TO_TOPIC, .topic_idx = (idx),            \
                .msgs_per_topic = (msgs)                                       \
        }
#define CONSUME(expected)                                                      \
        { .op = TEST_OP_CONSUME, .expected_msgs = (expected) }
#define CONSUME_VERIFY_NO_OLD(expected)                                        \
        {                                                                      \
                .op = TEST_OP_CONSUME, .expected_msgs = (expected),            \
                .flags = TEST_OP_F_VERIFY_NO_OLD_MSGS                          \
        }
#define CONSUME_ANY()                                                          \
        { .op = TEST_OP_CONSUME, .expected_msgs = -1 }
#define VERIFY_SUB(cnt)                                                        \
        { .op = TEST_OP_VERIFY_SUB_CNT, .expected_sub_cnt = (cnt) }
#define DELETE_TOPIC(idx)                                                      \
        { .op = TEST_OP_DELETE_TOPIC, .topic_idx = (idx) }
#define WAIT_MS(ms)                                                            \
        { .op = TEST_OP_WAIT, .wait_ms = (ms) }
#define CREATE_CONSUMER(idx)                                                   \
        { .op = TEST_OP_CREATE_CONSUMER, .consumer_idx = (idx) }
#define CREATE_TOPIC(n)                                                        \
        { .op = TEST_OP_CREATE_TOPIC, .topic_cnt = (n) }
#define SUBSCRIBE_EXISTING()                                                   \
        { .op = TEST_OP_SUBSCRIBE_EXISTING, .repeat_cnt = 1 }
#define POLL_NO_SUB()                                                          \
        { .op = TEST_OP_POLL_NO_SUB }
#define SUBSCRIBE_EMPTY()                                                      \
        { .op = TEST_OP_SUBSCRIBE_EMPTY }
#define TEST_OPS_END()                                                         \
        { .op = TEST_OP_END }


/**
 * @brief Create a new topic with auto-generated name
 */
static const char *state_create_topic(sub_test_state_t *state,
                                      rd_bool_t wait_exists) {
        char name[128];

        TEST_ASSERT(state->all_topic_cnt < MAX_TOPICS,
                    "Too many topics created");

        rd_snprintf(name, sizeof(name), "0170-t%d", state->all_topic_cnt);
        state->all_topics[state->all_topic_cnt] =
            rd_strdup(test_mk_topic_name(name, 1));

        if (wait_exists) {
                test_create_topic_wait_exists(
                    NULL, state->all_topics[state->all_topic_cnt], 1, -1,
                    30000);
        }

        state->msgs_produced[state->all_topic_cnt] = 0;
        return state->all_topics[state->all_topic_cnt++];
}

/**
 * @brief Execute TEST_OP_SUBSCRIBE
 */
static void exec_subscribe(sub_test_state_t *state, const test_op_t *op) {
        rd_kafka_topic_partition_list_t *tlist;
        int cidx = op->consumer_idx;
        int i, r;

        TEST_SAY("  SUBSCRIBE: %d topic(s), repeat=%d, consumer=%d\n",
                 op->topic_cnt, op->repeat_cnt, cidx);

        /* Save old subscription for RESUBSCRIBE verification */
        state->old_sub_start_idx = state->sub_start_idx[cidx];
        state->old_sub_count     = state->sub_count[cidx];

        /* Track new subscription */
        state->sub_start_idx[cidx] = state->all_topic_cnt;
        state->sub_count[cidx]     = op->topic_cnt;

        /* Create topics and build subscription list */
        tlist = rd_kafka_topic_partition_list_new(op->topic_cnt);
        for (i = 0; i < op->topic_cnt; i++) {
                const char *topic = state_create_topic(
                    state, !(op->flags & TEST_OP_F_SKIP_TOPIC_CREATE));
                rd_kafka_topic_partition_list_add(tlist, topic,
                                                  RD_KAFKA_PARTITION_UA);
        }

        /* Subscribe (possibly multiple times) */
        for (r = 0; r < op->repeat_cnt; r++) {
                TEST_CALL_ERR__(
                    rd_kafka_share_subscribe(state->consumers[cidx], tlist));
        }

        rd_kafka_topic_partition_list_destroy(tlist);
}

/**
 * @brief Execute TEST_OP_SUBSCRIBE_ADD (incremental - add to existing
 * subscription)
 */
static void exec_subscribe_add(sub_test_state_t *state, const test_op_t *op) {
        rd_kafka_topic_partition_list_t *tlist;
        int cidx = op->consumer_idx;
        int i;
        int new_start = state->all_topic_cnt;

        TEST_SAY(
            "  SUBSCRIBE_ADD: adding %d topic(s) to existing %d, consumer=%d\n",
            op->topic_cnt, state->sub_count[cidx], cidx);

        /* Build subscription list including existing + new topics */
        tlist = rd_kafka_topic_partition_list_new(state->sub_count[cidx] +
                                                  op->topic_cnt);

        /* Add existing subscribed topics */
        for (i = 0; i < state->sub_count[cidx]; i++) {
                int idx = state->sub_start_idx[cidx] + i;
                rd_kafka_topic_partition_list_add(tlist, state->all_topics[idx],
                                                  RD_KAFKA_PARTITION_UA);
        }

        /* Create and add new topics */
        for (i = 0; i < op->topic_cnt; i++) {
                const char *topic = state_create_topic(state, rd_true);
                rd_kafka_topic_partition_list_add(tlist, topic,
                                                  RD_KAFKA_PARTITION_UA);
        }

        TEST_CALL_ERR__(
            rd_kafka_share_subscribe(state->consumers[cidx], tlist));

        /* Update subscription tracking - topics are now spread across ranges */
        state->sub_start_idx[cidx] = new_start - state->sub_count[cidx];
        state->sub_count[cidx] += op->topic_cnt;

        rd_kafka_topic_partition_list_destroy(tlist);
}

/**
 * @brief Execute TEST_OP_CREATE_TOPIC (create topics that weren't created)
 */
static void exec_create_topic(sub_test_state_t *state, const test_op_t *op) {
        int cidx = op->consumer_idx;
        int i;

        TEST_SAY("  CREATE_TOPIC: creating subscribed topics for consumer=%d\n",
                 cidx);

        /* Create the topics that were subscribed to but not yet created */
        for (i = 0; i < state->sub_count[cidx]; i++) {
                int idx = state->sub_start_idx[cidx] + i;
                if (state->all_topics[idx]) {
                        test_create_topic_wait_exists(
                            NULL, state->all_topics[idx], 1, -1, 30000);
                }
        }
}

/**
 * @brief Execute TEST_OP_SUBSCRIBE_EXISTING (subscribe to all created topics)
 */
static void exec_subscribe_existing(sub_test_state_t *state,
                                    const test_op_t *op) {
        rd_kafka_topic_partition_list_t *tlist;
        int cidx = op->consumer_idx;
        int i;

        TEST_SAY("  SUBSCRIBE_EXISTING: %d topic(s), consumer=%d\n",
                 state->all_topic_cnt, cidx);

        tlist = rd_kafka_topic_partition_list_new(state->all_topic_cnt);

        for (i = 0; i < state->all_topic_cnt; i++) {
                rd_kafka_topic_partition_list_add(tlist, state->all_topics[i],
                                                  RD_KAFKA_PARTITION_UA);
        }

        TEST_CALL_ERR__(
            rd_kafka_share_subscribe(state->consumers[cidx], tlist));

        state->sub_start_idx[cidx] = 0;
        state->sub_count[cidx]     = state->all_topic_cnt;

        rd_kafka_topic_partition_list_destroy(tlist);
}

/**
 * @brief Execute TEST_OP_PRODUCE_TO_TOPIC (produce to specific topic by index)
 */
static void exec_produce_to_topic(sub_test_state_t *state,
                                  const test_op_t *op) {
        int cidx = op->consumer_idx;
        int idx  = state->sub_start_idx[cidx] + op->topic_idx;

        TEST_ASSERT(op->topic_idx < state->sub_count[cidx],
                    "Topic index %d out of range (sub_count=%d)", op->topic_idx,
                    state->sub_count[cidx]);

        TEST_SAY("  PRODUCE_TO_TOPIC: %d msgs to topic[%d] (%s)\n",
                 op->msgs_per_topic, op->topic_idx, state->all_topics[idx]);

        test_produce_msgs_simple(common_producer, state->all_topics[idx], 0,
                                 op->msgs_per_topic);
        state->msgs_produced[idx] += op->msgs_per_topic;
}

/**
 * @brief Execute TEST_OP_RESUBSCRIBE (replace subscription with new topics)
 */
static void exec_resubscribe(sub_test_state_t *state, const test_op_t *op) {
        rd_kafka_topic_partition_list_t *tlist;
        int cidx = op->consumer_idx;
        int i;

        TEST_SAY("  RESUBSCRIBE: %d new topic(s), consumer=%d\n", op->topic_cnt,
                 cidx);

        /* Save old subscription */
        state->old_sub_start_idx = state->sub_start_idx[cidx];
        state->old_sub_count     = state->sub_count[cidx];

        /* Track new subscription */
        state->sub_start_idx[cidx] = state->all_topic_cnt;
        state->sub_count[cidx]     = op->topic_cnt;

        /* Create new topics */
        tlist = rd_kafka_topic_partition_list_new(op->topic_cnt);
        for (i = 0; i < op->topic_cnt; i++) {
                const char *topic = state_create_topic(state, rd_true);
                rd_kafka_topic_partition_list_add(tlist, topic,
                                                  RD_KAFKA_PARTITION_UA);
        }

        TEST_CALL_ERR__(
            rd_kafka_share_subscribe(state->consumers[cidx], tlist));
        rd_kafka_topic_partition_list_destroy(tlist);
}

/**
 * @brief Execute TEST_OP_UNSUBSCRIBE
 */
static void exec_unsubscribe(sub_test_state_t *state, const test_op_t *op) {
        int cidx = op->consumer_idx;
        int r;

        TEST_SAY("  UNSUBSCRIBE: repeat=%d, consumer=%d\n", op->repeat_cnt,
                 cidx);

        for (r = 0; r < op->repeat_cnt; r++) {
                TEST_CALL_ERR__(
                    rd_kafka_share_unsubscribe(state->consumers[cidx]));
        }

        state->sub_count[cidx] = 0;
}

/**
 * @brief Execute TEST_OP_SUBSCRIBE_EMPTY
 *
 * Subscribe with an empty topic list is equivalent to unsubscribe:
 * must return NO_ERROR and clear the subscription flag.
 */
static void exec_subscribe_empty(sub_test_state_t *state, const test_op_t *op) {
        rd_kafka_topic_partition_list_t *tlist;
        int cidx = op->consumer_idx;

        TEST_SAY("  SUBSCRIBE_EMPTY: consumer=%d\n", cidx);

        tlist = rd_kafka_topic_partition_list_new(0);
        TEST_CALL_ERR__(
            rd_kafka_share_subscribe(state->consumers[cidx], tlist));
        rd_kafka_topic_partition_list_destroy(tlist);

        state->sub_count[cidx] = 0;
}

/**
 * @brief Execute TEST_OP_PRODUCE
 */
static void exec_produce(sub_test_state_t *state, const test_op_t *op) {
        int cidx = op->consumer_idx;
        int start_idx, count, i;

        if (op->flags & TEST_OP_F_PRODUCE_TO_OLD) {
                start_idx = state->old_sub_start_idx;
                count     = state->old_sub_count;
                TEST_SAY("  PRODUCE: %d msgs/topic to OLD %d topic(s)\n",
                         op->msgs_per_topic, count);
        } else {
                start_idx = state->sub_start_idx[cidx];
                count     = state->sub_count[cidx];
                TEST_SAY("  PRODUCE: %d msgs/topic to %d topic(s)\n",
                         op->msgs_per_topic, count);
        }

        for (i = 0; i < count; i++) {
                int idx = start_idx + i;
                test_produce_msgs_simple(common_producer,
                                         state->all_topics[idx], 0,
                                         op->msgs_per_topic);
                state->msgs_produced[idx] += op->msgs_per_topic;
        }
}

/**
 * @brief Execute TEST_OP_CONSUME
 */
static void exec_consume(sub_test_state_t *state, const test_op_t *op) {
        int cidx      = op->consumer_idx;
        int start_idx = state->sub_start_idx[cidx];
        int count     = state->sub_count[cidx];
        const char *topics[MAX_TOPICS];
        int i, consumed;

        /* Build expected topics array */
        for (i = 0; i < count; i++) {
                topics[i] = state->all_topics[start_idx + i];
        }

        if (op->expected_msgs >= 0) {
                TEST_SAY("  CONSUME: expecting %d msgs from %d topic(s)\n",
                         op->expected_msgs, count);
                consumed = test_share_consume_msgs(
                    state->consumers[cidx], op->expected_msgs, 25, 3000,
                    count > 0 ? topics : NULL, count);

                if (op->flags & TEST_OP_F_VERIFY_NO_OLD_MSGS) {
                        TEST_ASSERT(consumed >= 0,
                                    "Received message from old subscription!");
                }
                TEST_ASSERT(consumed == op->expected_msgs,
                            "Expected %d messages, got %d", op->expected_msgs,
                            consumed);
        } else {
                /* Consume any available */
                TEST_SAY("  CONSUME: any available from %d topic(s)\n", count);
                test_share_consume_msgs(state->consumers[cidx], 100, 10, 2000,
                                        count > 0 ? topics : NULL, count);
        }
}

/**
 * @brief Execute TEST_OP_VERIFY_SUB_CNT
 */
static void exec_verify_sub_cnt(sub_test_state_t *state, const test_op_t *op) {
        int cidx = op->consumer_idx;
        rd_kafka_topic_partition_list_t *sub;

        TEST_SAY("  VERIFY_SUB_CNT: expecting %d, consumer=%d\n",
                 op->expected_sub_cnt, cidx);

        sub = test_get_subscription(state->consumers[cidx]);
        TEST_ASSERT(sub->cnt == op->expected_sub_cnt,
                    "Expected %d subscriptions, got %d", op->expected_sub_cnt,
                    sub->cnt);
        rd_kafka_topic_partition_list_destroy(sub);
}

/**
 * @brief Execute TEST_OP_DELETE_TOPIC
 */
static void exec_delete_topic(sub_test_state_t *state, const test_op_t *op) {
        int cidx = op->consumer_idx;
        int idx  = state->sub_start_idx[cidx] + op->topic_idx;

        TEST_ASSERT(op->topic_idx < state->sub_count[cidx],
                    "Topic index %d out of range (sub_count=%d)", op->topic_idx,
                    state->sub_count[cidx]);

        TEST_SAY("  DELETE_TOPIC: index %d (%s)\n", op->topic_idx,
                 state->all_topics[idx]);

        /* Actually delete the topic */
        test_DeleteTopics_simple(common_admin, NULL, &state->all_topics[idx], 1,
                                 NULL);
}

/**
 * @brief Execute TEST_OP_WAIT
 */
static void exec_wait(sub_test_state_t *state, const test_op_t *op) {
        TEST_SAY("  WAIT: %d ms\n", op->wait_ms);
        rd_sleep(op->wait_ms / 1000);
        if (op->wait_ms % 1000)
                rd_usleep((op->wait_ms % 1000) * 1000, NULL);
}

/**
 * @brief Execute TEST_OP_CREATE_CONSUMER
 */
static void exec_create_consumer(sub_test_state_t *state, const test_op_t *op) {
        int cidx = op->consumer_idx;

        TEST_SAY("  CREATE_CONSUMER: index %d\n", cidx);

        TEST_ASSERT(cidx < MAX_CONSUMERS, "Consumer index out of range");
        TEST_ASSERT(state->consumers[cidx] == NULL,
                    "Consumer %d already exists", cidx);

        state->consumers[cidx] =
            test_create_share_consumer(state->group_name, NULL);
        if (cidx >= state->consumer_cnt)
                state->consumer_cnt = cidx + 1;
}

/**
 * @brief Execute TEST_OP_POLL_NO_SUB
 *
 * consume_batch must surface RD_KAFKA_RESP_ERR__STATE with a "not
 * subscribed" message when no subscription is active.
 */
static void exec_poll_no_sub(sub_test_state_t *state, const test_op_t *op) {
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *err;
        size_t rcvd = 0;
        int cidx    = op->consumer_idx;

        TEST_SAY("  POLL_NO_SUB: consumer=%d\n", cidx);

        err  = rd_kafka_share_poll(state->consumers[cidx], 2000, &batch);
        rcvd = rd_kafka_messages_count(batch);
        TEST_ASSERT(err != NULL,
                    "POLL_NO_SUB consumer=%d: expected error, got NULL", cidx);
        TEST_ASSERT(rd_kafka_error_code(err) == RD_KAFKA_RESP_ERR__STATE,
                    "POLL_NO_SUB consumer=%d: expected __STATE, got: %s", cidx,
                    rd_kafka_err2name(rd_kafka_error_code(err)));
        TEST_ASSERT(strstr(rd_kafka_error_string(err), "not subscribed"),
                    "POLL_NO_SUB consumer=%d: expected 'not subscribed' "
                    "substring, got: %s",
                    cidx, rd_kafka_error_string(err));
        TEST_ASSERT(rcvd == 0,
                    "POLL_NO_SUB consumer=%d: expected 0 messages, got %zu",
                    cidx, rcvd);
        rd_kafka_error_destroy(err);
        rd_kafka_messages_destroy(batch);
}

/**
 * @brief Initialize test state
 */
static void state_init(sub_test_state_t *state,
                       const test_scenario_t *scenario) {
        int i;

        memset(state, 0, sizeof(*state));

        /* Append a per-invocation unique suffix so each run gets a
         * fresh share-group on the broker (avoids collisions across
         * re-runs or parallel runs against the same cluster). */
        rd_snprintf(state->group_name, sizeof(state->group_name),
                    "share-%s-rnd%" PRIx64, scenario->name, test_id_generate());
        TEST_SAY("Scenario '%s' using group '%s'\n", scenario->name,
                 state->group_name);

        state->consumer_cnt =
            scenario->consumer_cnt > 0 ? scenario->consumer_cnt : 1;

        /* Create initial consumers */
        for (i = 0; i < state->consumer_cnt; i++) {
                state->consumers[i] =
                    test_create_share_consumer(state->group_name, NULL);
        }

        /* Set group offset to earliest */
        test_share_set_auto_offset_reset(state->group_name, "earliest");
}

/**
 * @brief Cleanup test state
 */
static void state_cleanup(sub_test_state_t *state) {
        int i;

        for (i = 0; i < state->all_topic_cnt; i++) {
                if (state->all_topics[i]) {
                        rd_free(state->all_topics[i]);
                }
        }

        /* Destroy all consumers */
        for (i = 0; i < MAX_CONSUMERS; i++) {
                if (state->consumers[i]) {
                        test_share_consumer_close(state->consumers[i]);
                        test_share_destroy(state->consumers[i]);
                }
        }
}

/**
 * @brief Run a test scenario
 */
static void do_test_scenario(const test_scenario_t *scenario) {
        sub_test_state_t state;
        int op_idx;

        SUB_TEST();

        state_init(&state, scenario);

        /* Execute operations */
        for (op_idx = 0; scenario->ops[op_idx].op != TEST_OP_END; op_idx++) {
                const test_op_t *op = &scenario->ops[op_idx];

                switch (op->op) {
                case TEST_OP_SUBSCRIBE:
                        exec_subscribe(&state, op);
                        break;
                case TEST_OP_SUBSCRIBE_ADD:
                        exec_subscribe_add(&state, op);
                        break;
                case TEST_OP_RESUBSCRIBE:
                        exec_resubscribe(&state, op);
                        break;
                case TEST_OP_UNSUBSCRIBE:
                        exec_unsubscribe(&state, op);
                        break;
                case TEST_OP_PRODUCE:
                        exec_produce(&state, op);
                        break;
                case TEST_OP_PRODUCE_TO_TOPIC:
                        exec_produce_to_topic(&state, op);
                        break;
                case TEST_OP_CONSUME:
                        exec_consume(&state, op);
                        break;
                case TEST_OP_VERIFY_SUB_CNT:
                        exec_verify_sub_cnt(&state, op);
                        break;
                case TEST_OP_DELETE_TOPIC:
                        exec_delete_topic(&state, op);
                        break;
                case TEST_OP_WAIT:
                        exec_wait(&state, op);
                        break;
                case TEST_OP_CREATE_CONSUMER:
                        exec_create_consumer(&state, op);
                        break;
                case TEST_OP_CREATE_TOPIC:
                        exec_create_topic(&state, op);
                        break;
                case TEST_OP_SUBSCRIBE_EXISTING:
                        exec_subscribe_existing(&state, op);
                        break;
                case TEST_OP_POLL_NO_SUB:
                        exec_poll_no_sub(&state, op);
                        break;
                case TEST_OP_SUBSCRIBE_EMPTY:
                        exec_subscribe_empty(&state, op);
                        break;
                default:
                        TEST_FAIL("Unknown operation: %d", op->op);
                }
        }

        state_cleanup(&state);

        SUB_TEST_PASS();
}


/**
 * Basic subscription tests
 */
static const test_scenario_t test_single_subscribe = {
    .name = "single-subscribe",
    .ops  = {SUBSCRIBE(2), PRODUCE(5), VERIFY_SUB(2), CONSUME(10),
             TEST_OPS_END()}};

static const test_scenario_t test_single_unsubscribe = {
    .name = "single-unsubscribe",
    .ops = {SUBSCRIBE(2), PRODUCE(5), CONSUME(10), UNSUBSCRIBE(), VERIFY_SUB(0),
            TEST_OPS_END()}};

static const test_scenario_t test_repeated_subscribe = {
    .name = "repeated-subscribe-no-duplicates",
    .ops  = {SUBSCRIBE_REPEAT(2, 3),    /* Subscribe 3 times to same topics */
             PRODUCE(5), VERIFY_SUB(2), /* Should still be 2, not 6 */
             CONSUME(10), TEST_OPS_END()}};

static const test_scenario_t test_repeated_unsubscribe = {
    .name = "repeated-unsubscribe-no-error",
    .ops  = {SUBSCRIBE(2), PRODUCE(5), CONSUME(10),
             UNSUBSCRIBE_REPEAT(3), /* Unsubscribe 3 times */
             VERIFY_SUB(0), TEST_OPS_END()}};

/**
 * Subscription replacement tests
 */
/* TODO KIP-932: test_topic_switch might be incorrect. Verify and remove. */
// static const test_scenario_t test_topic_switch = {
//     .name = "topic-switch",
//     .ops  = {SUBSCRIBE(2), PRODUCE(10), CONSUME_ANY(),
//              RESUBSCRIBE(2),            /* Switch to 2 new topics */
//              PRODUCE(10),               /* Produce to new topics */
//              PRODUCE_TO_OLD(5),         /* Produce to old topics */
//              CONSUME_VERIFY_NO_OLD(20), /* Should only get new topic msgs */
//              TEST_OPS_END()}};

static const test_scenario_t test_incremental_subscription = {
    .name = "incremental-subscription",
    .ops  = {/* Start with 1 topic */
            SUBSCRIBE(1), PRODUCE(10), VERIFY_SUB(1), CONSUME(10),
            /* Add 1 more topic (now 2 total) */
            SUBSCRIBE_ADD(1), PRODUCE(10), VERIFY_SUB(2),
            CONSUME(20), /* 10 from each of 2 topics */
            /* Add 1 more topic (now 3 total) */
            SUBSCRIBE_ADD(1), PRODUCE(10), VERIFY_SUB(3),
            CONSUME(30), /* 10 from each of 3 topics */
            TEST_OPS_END()}};

/**
 * Edge case tests
 */
static const test_scenario_t test_subscribe_before_topic_exists = {
    .name = "subscribe-before-topic-exists",
    .ops  = {SUBSCRIBE_NO_CREATE(1), /* Subscribe without creating topic */
             CREATE_TOPIC(0),        /* Now create the subscribed topic */
             PRODUCE(5),             /* Produce to the topic */
             CONSUME(5),             /* Should receive all messages */
             TEST_OPS_END()}};

static const test_scenario_t test_poll_empty_topic = {
    .name = "poll-empty-topic",
    .ops  = {SUBSCRIBE(1),
             /* Don't produce - topic is empty */
             CONSUME(0), /* Should return 0, not error */
             TEST_OPS_END()}};

static const test_scenario_t test_poll_no_subscription = {
    .name = "poll-no-subscription",
    .ops  = {POLL_NO_SUB(), /* Poll without subscribing */
             TEST_OPS_END()}};

static const test_scenario_t test_poll_after_unsubscribe = {
    .name = "poll-after-unsubscribe",
    .ops  = {SUBSCRIBE(1), PRODUCE(5), CONSUME_ANY(), /* Consume some */
             UNSUBSCRIBE(), POLL_NO_SUB(), /* Poll after unsubscribe */
             TEST_OPS_END()}};

/**
 * Topic deletion tests
 */
static const test_scenario_t test_topic_deletion = {
    .name = "topic-deletion-while-subscribed",
    .ops  = {SUBSCRIBE(2), PRODUCE(10), CONSUME_ANY(),
             DELETE_TOPIC(1), /* Delete second topic */
             WAIT_MS(3000),
             PRODUCE_TO_TOPIC(0, 5), /* Produce to remaining topic */
             CONSUME_ANY(),          /* Continue consuming from remaining */
             TEST_OPS_END()}};

/**
 * Stress tests
 */
static const test_scenario_t test_rapid_updates = {
    .name = "rapid-subscription-updates",
    .ops  = {SUBSCRIBE(2), RESUBSCRIBE(1), RESUBSCRIBE(3), UNSUBSCRIBE(),
             SUBSCRIBE(2), RESUBSCRIBE(2), UNSUBSCRIBE(), SUBSCRIBE(3),
             VERIFY_SUB(3), TEST_OPS_END()}};

/**
 * @brief Multi-consumer overlap test (standalone)
 *
 * Two consumers in same group with overlapping subscriptions:
 * - Consumer 0: [shared, c0_only]
 * - Consumer 1: [shared, c1_only]
 *
 * This test verifies share group consumers can have overlapping
 * subscriptions and both receive messages from shared topics.
 */
static void do_test_multi_consumer_overlap(void) {
        const char *group = test_mk_topic_name("share-overlap", 1);
        char *shared      = rd_strdup(test_mk_topic_name("0170-shared", 1));
        char *c0_only     = rd_strdup(test_mk_topic_name("0170-c0only", 1));
        char *c1_only     = rd_strdup(test_mk_topic_name("0170-c1only", 1));
        const char *c0_topics[] = {shared, c0_only};
        const char *c1_topics[] = {shared, c1_only};
        rd_kafka_share_t *rkshare0, *rkshare1;
        int c0_cnt = 0, c1_cnt = 0;
        int attempts;

        SUB_TEST("multi-consumer-overlapping-subscriptions");

        /* Create topics */
        test_create_topic_wait_exists(NULL, shared, 1, -1, 30000);
        test_create_topic_wait_exists(NULL, c0_only, 1, -1, 30000);
        test_create_topic_wait_exists(NULL, c1_only, 1, -1, 30000);

        /* Produce messages */
        test_produce_msgs_simple(common_producer, shared, 0, 20);
        test_produce_msgs_simple(common_producer, c0_only, 0, 10);
        test_produce_msgs_simple(common_producer, c1_only, 0, 10);

        /* Create consumers */
        rkshare0 = test_create_share_consumer(group, NULL);
        rkshare1 = test_create_share_consumer(group, NULL);

        /* Set group offset */
        test_share_set_auto_offset_reset(group, "earliest");

        /* Subscribe with overlapping topics */
        test_share_consumer_subscribe_multi(rkshare0, 2, shared, c0_only);
        test_share_consumer_subscribe_multi(rkshare1, 2, shared, c1_only);

        /* Consume - alternate between consumers */
        attempts = 20;
        while ((c0_cnt + c1_cnt) < 10 && attempts-- > 0) {
                int batch_cnt = 0;
                int ret;

                ret = test_share_poll(rkshare0, 2000, c0_topics, 2, &batch_cnt);
                TEST_ASSERT(ret >= 0, "C0 wrong topic");
                c0_cnt += batch_cnt;

                batch_cnt = 0;
                ret = test_share_poll(rkshare1, 2000, c1_topics, 2, &batch_cnt);
                TEST_ASSERT(ret >= 0, "C1 wrong topic");
                c1_cnt += batch_cnt;
        }

        TEST_SAY("C0: %d, C1: %d (total: %d)\n", c0_cnt, c1_cnt,
                 c0_cnt + c1_cnt);
        TEST_ASSERT(c0_cnt > 0 || c1_cnt > 0, "no messages received");

        /* Cleanup */
        test_share_consumer_close(rkshare0);
        test_share_consumer_close(rkshare1);
        test_share_destroy(rkshare0);
        test_share_destroy(rkshare1);

        rd_free(shared);
        rd_free(c0_only);
        rd_free(c1_only);

        SUB_TEST_PASS();
}


/**
 * @brief Topic-level metadata-error policy: when a subscribed topic is
 *        deleted mid-stream, the resulting metadata error
 *        (UNKNOWN_TOPIC_OR_PART / UNKNOWN_TOPIC) is treated as a
 *        transient code by the share consumer — logged internally and
 *        not surfaced to the application via consume_batch.
 *
 * Subscribe to a valid topic, prime the share assignment so the rktp
 * is on rkt_desp, delete the topic, allow metadata propagation, and
 * verify that no topic-level err shows up in subsequent consume_batch
 * calls.
 */
static void test_topic_deletion_does_not_surface_error(void) {
        const char *topic;
        const char *group = "share-topic-delete-no-surface";
        rd_kafka_share_t *consumer;
        rd_kafka_conf_t *conf;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *error;
        char errstr[512];
        char *topic_dup;
        char *topics_for_delete[1];
        rd_kafka_resp_err_t del_err;
        size_t rcvd;
        size_t j;
        int consumed = 0;
        int attempts = 0;
        int post_attempts;
        rd_bool_t surfaced_topic_err = rd_false;

        SUB_TEST();

        if (!strcmp(test_getenv("TEST_BROKER_OS", ""), "windows"))
                SUB_TEST_SKIP(
                    "topic-deletion-does-not-surface-error "
                    "(broker on Windows)\n");

        topic     = test_mk_topic_name("0170-delete-no-surface", 1);
        topic_dup = rd_strdup(topic);
        test_create_topic_wait_exists(common_admin, topic, 1, -1, 60 * 1000);
        test_share_set_auto_offset_reset(group, "earliest");
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Custom consumer that disables the set_notexists defer window
         * (default 30s) so the log-and-drop path runs on the first
         * post-delete metadata refresh instead of being deferred.
         * Also reduce the metadata refresh interval so a refresh actually
         * happens during the post-delete settle window — the default is
         * 5 minutes, which would never fire during the test. */
        test_conf_init(&conf, NULL, 60);
        rd_kafka_conf_set(conf, "group.id", group, errstr, sizeof(errstr));
        rd_kafka_conf_set(conf, "share.acknowledgement.mode", "explicit",
                          errstr, sizeof(errstr));
        rd_kafka_conf_set(conf, "topic.metadata.propagation.max.ms", "0",
                          errstr, sizeof(errstr));
        rd_kafka_conf_set(conf, "topic.metadata.refresh.interval.ms", "500",
                          errstr, sizeof(errstr));
        consumer = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(consumer, "Failed to create share consumer: %s", errstr);
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(consumer, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        /* Prime the share assignment: consume + ACCEPT at least one
         * record so the rktp materialises on rkt_desp (precondition
         * for the metadata-error propagation path to fire). */
        while (consumed < 1 && attempts++ < 30) {
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                error = rd_kafka_share_poll(consumer, 1000, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                if (error) {
                        rd_kafka_error_destroy(error);
                        continue;
                }
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err) {
                                rd_kafka_share_acknowledge(consumer, msg);
                                consumed++;
                        }
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;
        TEST_ASSERT(consumed >= 1,
                    "Pre-condition: expected to consume + ack at least one "
                    "record before deleting the topic");

        TEST_SAY("Deleting topic %s\n", topic);
        topics_for_delete[0] = topic_dup;
        del_err              = test_DeleteTopics_simple(common_admin, NULL,
                                                        topics_for_delete, 1, NULL);
        TEST_ASSERT(!del_err, "DeleteTopics failed: %s",
                    rd_kafka_err2str(del_err));

        /* Wait for the topic delete to propagate in the cluster. */
        rd_sleep(3);

        /* Drain consume_batch and verify no topic-level error reaches
         * the application. _STATE / generic timeouts are expected
         * (no more records); only the metadata-derived topic codes
         * must not surface. */
        for (post_attempts = 0; post_attempts < 30; post_attempts++) {
                rd_kafka_messages_destroy(batch);
                batch = NULL;
                error = rd_kafka_share_poll(consumer, 500, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                if (error) {
                        rd_kafka_resp_err_t code = rd_kafka_error_code(error);
                        TEST_SAY("Post-delete consume_batch: %s\n",
                                 rd_kafka_err2name(code));
                        if (code == RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION ||
                            code == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART ||
                            code == RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC ||
                            code == RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION ||
                            code == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID ||
                            code ==
                                RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED)
                                surfaced_topic_err = rd_true;
                        rd_kafka_error_destroy(error);
                        continue;
                }
                for (j = 0; j < rcvd; j++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, j);
                        if (!msg->err)
                                rd_kafka_share_acknowledge(consumer, msg);
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_ASSERT(!surfaced_topic_err,
                    "Topic-level metadata errors must not surface to "
                    "the application after the subscribed topic is "
                    "deleted (transient codes are log-only)");

        rd_free(topic_dup);
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        SUB_TEST_PASS();
}


/**
 * @brief Test subscribing to 15 topics - triggers multiple fetch responses
 *
 * Creates 15 topics, subscribes to all of them, produces messages to each,
 * and verifies all messages are consumed. This tests the scenario where
 * topics are spread across multiple brokers and require multiple
 * ShareFetch responses.
 */
static void do_test_subscribe_15_topics(void) {
        const char *group        = test_mk_topic_name("share-15topics", 1);
        const int topic_cnt      = 15;
        const int msgs_per_topic = 100;
        const int total_expected = topic_cnt * msgs_per_topic;
        char *topics[15];
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        int consumed               = 0;
        int attempts;
        int t;

        SUB_TEST("subscribe-15-topics");

        /* Create 15 topics */
        for (t = 0; t < topic_cnt; t++) {
                topics[t] = rd_strdup(test_mk_topic_name("0170-15topics", 1));
                test_create_topic_wait_exists(NULL, topics[t], 1, -1, 30000);
        }

        /* Produce messages to each topic */
        for (t = 0; t < topic_cnt; t++) {
                test_produce_msgs_simple(common_producer, topics[t], 0,
                                         msgs_per_topic);
        }
        TEST_SAY("Produced %d messages to %d topics\n", total_expected,
                 topic_cnt);

        /* Create consumer */
        rkshare = test_create_share_consumer(group, NULL);

        /* Set group offset */
        test_share_set_auto_offset_reset(group, "earliest");

        /* Subscribe to all topics */
        subs = rd_kafka_topic_partition_list_new(topic_cnt);
        for (t = 0; t < topic_cnt; t++) {
                rd_kafka_topic_partition_list_add(subs, topics[t],
                                                  RD_KAFKA_PARTITION_UA);
        }
        rd_kafka_share_subscribe(rkshare, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        TEST_SAY("Subscribed to %d topics\n", topic_cnt);

        /* Consume all messages */
        attempts = 100;
        while (consumed < total_expected && attempts-- > 0) {
                size_t rcvd = 0;
                size_t m;
                rd_kafka_error_t *err;

                rd_kafka_messages_destroy(batch);
                batch = NULL;
                err   = rd_kafka_share_poll(rkshare, 2000, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }

                for (m = 0; m < rcvd; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        if (!msg->err)
                                consumed++;
                }

                if (rcvd > 0)
                        TEST_SAY("Progress: %d/%d\n", consumed, total_expected);
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_ASSERT(consumed == total_expected,
                    "Expected %d messages, consumed %d", total_expected,
                    consumed);

        /* Cleanup */
        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        for (t = 0; t < topic_cnt; t++) {
                rd_free(topics[t]);
        }

        SUB_TEST_PASS();
}


/**
 * @brief Test share.auto.offset.reset = earliest
 *
 * Verifies that with share.auto.offset.reset = earliest, consumer receives
 * all messages including those produced before subscription.
 */
static void do_test_auto_offset_reset_earliest(void) {
        rd_kafka_share_t *consumer;
        rd_kafka_messages_t *batch = NULL;
        const char *topic;
        const char *group = "share-offset-earliest-test";
        rd_kafka_topic_partition_list_t *subs;
        int consumed = 0;
        int attempts;
        const int msg_cnt = 100;

        SUB_TEST("share.auto.offset.reset=earliest");

        /* Create topic */
        topic = test_mk_topic_name("0170-offset-earliest", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        /* Produce messages BEFORE consumer subscribes */
        TEST_SAY("Producing %d messages BEFORE subscription...\n", msg_cnt);
        test_produce_msgs_easy(topic, 0, 0, msg_cnt);

        /* Create consumer */
        consumer = test_create_share_consumer(group, NULL);

        /* Configure group with earliest offset */
        test_share_set_auto_offset_reset(group, "earliest");

        /* Subscribe */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(consumer, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        /* Consume - should get all 100 messages */
        TEST_SAY("Consuming with earliest offset...\n");
        attempts = 50;
        while (consumed < msg_cnt && attempts-- > 0) {
                size_t rcvd = 0;
                size_t m;
                rd_kafka_error_t *err;

                rd_kafka_messages_destroy(batch);
                batch = NULL;
                err   = rd_kafka_share_poll(consumer, 2000, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }

                for (m = 0; m < rcvd; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        if (!msg->err)
                                consumed++;
                }

                if (rcvd > 0)
                        TEST_SAY("Progress: %d/%d\n", consumed, msg_cnt);
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_ASSERT(consumed == msg_cnt, "Expected %d messages, got %d",
                    msg_cnt, consumed);

        TEST_SAY("SUCCESS: earliest offset - consumed all %d messages\n",
                 consumed);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        SUB_TEST_PASS();
}

/**
 * @brief Test share.auto.offset.reset default value (latest)
 *
 * Verifies that with default (latest) offset, consumer only receives
 * messages produced after subscription, not pre-existing messages.
 */
static void do_test_auto_offset_reset_default_latest(void) {
        rd_kafka_share_t *consumer;
        rd_kafka_messages_t *batch = NULL;
        const char *topic;
        const char *group = "share-offset-default-test";
        rd_kafka_topic_partition_list_t *subs;
        int consumed_before = 0, consumed_after = 0;
        int attempts;
        const int initial_msgs = 100;
        const int later_msgs   = 50;

        SUB_TEST("share.auto.offset.reset=latest (default)");

        /* Create topic */
        topic = test_mk_topic_name("0170-offset-default", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        /* Produce messages BEFORE consumer subscribes */
        TEST_SAY("Producing %d messages BEFORE subscription...\n",
                 initial_msgs);
        test_produce_msgs_easy(topic, 0, 0, initial_msgs);

        /* Create consumer - NO offset reset config (uses default "latest") */
        consumer = test_create_share_consumer(group, NULL);

        /* Subscribe */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(consumer, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        /* Allow consumer to establish position */
        rd_sleep(3);

        /* Try to consume - should get 0 messages (default is latest) */
        TEST_SAY("Trying to consume with default (latest) offset...\n");
        attempts = 10;
        while (attempts-- > 0) {
                size_t rcvd = 0;
                size_t m;
                rd_kafka_error_t *err;

                rd_kafka_messages_destroy(batch);
                batch = NULL;
                err   = rd_kafka_share_poll(consumer, 1000, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }

                for (m = 0; m < rcvd; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        if (!msg->err)
                                consumed_before++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY(
            "Consumed %d messages from before subscription (expected: 0)\n",
            consumed_before);
        TEST_ASSERT(consumed_before == 0,
                    "With default (latest) offset, should not receive "
                    "pre-existing messages, got %d",
                    consumed_before);

        /* Now produce more messages */
        TEST_SAY("Producing %d more messages AFTER subscription...\n",
                 later_msgs);
        test_produce_msgs_easy(topic, 0, 0, later_msgs);

        /* Consume - should get the new 50 messages */
        TEST_SAY("Consuming messages produced after subscription...\n");
        attempts = 30;
        while (consumed_after < later_msgs && attempts-- > 0) {
                size_t rcvd = 0;
                size_t m;
                rd_kafka_error_t *err;

                rd_kafka_messages_destroy(batch);
                batch = NULL;
                err   = rd_kafka_share_poll(consumer, 1000, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                if (err) {
                        rd_kafka_error_destroy(err);
                        continue;
                }

                for (m = 0; m < rcvd; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        if (!msg->err)
                                consumed_after++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_SAY("Consumed %d messages after subscription (expected: %d)\n",
                 consumed_after, later_msgs);
        TEST_ASSERT(consumed_after == later_msgs,
                    "Expected %d messages after subscription, got %d",
                    later_msgs, consumed_after);

        TEST_SAY(
            "SUCCESS: default (latest) offset verified - before=%d, "
            "after=%d\n",
            consumed_before, consumed_after);

        /* Cleanup */
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        SUB_TEST_PASS();
}

/**
 * @brief rd_kafka_share_subscribe input validation against a real
 *        broker.
 *
 * Covers the share-subscribe API surface contract:
 *   1. A topic name starting with '^' is treated as a literal — no
 *      regex compilation, no rejection. The name is forwarded
 *      verbatim to the broker via
 *      ShareGroupHeartbeat.SubscribedTopicNames; the broker silently
 *      drops names it cannot resolve.
 *   2. Subscription list containing an empty topic name returns
 *      INVALID_ARG.
 *   3. Duplicate topic names return INVALID_ARG.
 */
static void do_test_subscribe_input_validation(void) {
        rd_kafka_share_t *consumer;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_resp_err_t err;
        const char *group = "share-subscribe-validation";

        SUB_TEST();

        /* Case 1: '^foo.*' is forwarded as a literal, not interpreted
         * as a regex. */
        consumer = test_create_share_consumer(group, NULL);

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, "^foo.*",
                                          RD_KAFKA_PARTITION_UA);
        err = rd_kafka_share_subscribe(consumer, subs);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "expected NO_ERROR for '^foo.*' literal topic, got: %s",
                    rd_kafka_err2str(err));
        rd_kafka_topic_partition_list_destroy(subs);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Case 2: entry with empty topic name. */
        consumer = test_create_share_consumer(group, NULL);

        subs = rd_kafka_topic_partition_list_new(2);
        rd_kafka_topic_partition_list_add(subs, "valid-topic",
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_topic_partition_list_add(subs, "", RD_KAFKA_PARTITION_UA);
        err = rd_kafka_share_subscribe(consumer, subs);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                    "expected INVALID_ARG for empty topic name, got: %s",
                    rd_kafka_err2str(err));
        rd_kafka_topic_partition_list_destroy(subs);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Case 3: duplicate topic names. */
        consumer = test_create_share_consumer(group, NULL);

        subs = rd_kafka_topic_partition_list_new(2);
        rd_kafka_topic_partition_list_add(subs, "duplicate-topic",
                                          RD_KAFKA_PARTITION_UA);
        rd_kafka_topic_partition_list_add(subs, "duplicate-topic",
                                          RD_KAFKA_PARTITION_UA);
        err = rd_kafka_share_subscribe(consumer, subs);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                    "expected INVALID_ARG for duplicate topic, got: %s",
                    rd_kafka_err2str(err));
        rd_kafka_topic_partition_list_destroy(subs);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        SUB_TEST_PASS();
}

/**
 * @brief End-to-end verification that '^'-prefixed entries are
 *        forwarded as literals (no regex resolution).
 *
 * Creates a real topic, produces records to it, then:
 *   Phase 1. Subscribes with a regex-shaped string '^<topic>$' that
 *            would match the topic if treated as a regex. The broker
 *            cannot resolve the literal name and silently drops it
 *            from the assignment. The share consumer must receive
 *            zero records.
 *   Phase 2. Unsubscribes, resubscribes with the plain topic name.
 *            The consumer must now receive all produced records.
 */
static void do_test_subscribe_caret_treated_as_literal_e2e(void) {
        rd_kafka_share_t *consumer;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        const char *topic;
        const char *group = "share-caret-literal-e2e";
        const int msg_cnt = 50;
        char caret_pattern[512];
        size_t records_phase1 = 0;
        size_t records_phase2 = 0;
        int attempts;

        SUB_TEST();

        topic = test_mk_topic_name("0170-caret-literal", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);
        test_share_set_auto_offset_reset(group, "earliest");
        test_produce_msgs_easy(topic, 0, 0, msg_cnt);

        consumer = test_create_share_consumer(group, NULL);

        /* Phase 1: '^<topic>$' as a literal — broker drops, no records. */
        rd_snprintf(caret_pattern, sizeof(caret_pattern), "^%s$", topic);
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, caret_pattern,
                                          RD_KAFKA_PARTITION_UA);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(consumer, subs));
        rd_kafka_topic_partition_list_destroy(subs);

        /* rd_kafka_share_subscription must return the subscribed names
         * verbatim (the '^' prefix is not stripped). */
        subs = NULL;
        TEST_CALL_ERR__(rd_kafka_share_subscription(consumer, &subs));
        TEST_ASSERT(subs && subs->cnt == 1,
                    "Phase 1: expected subscription cnt 1, got %d",
                    subs ? subs->cnt : -1);
        TEST_ASSERT(!strcmp(subs->elems[0].topic, caret_pattern),
                    "Phase 1: expected subscription[0]='%s', got '%s'",
                    caret_pattern, subs->elems[0].topic);
        rd_kafka_topic_partition_list_destroy(subs);

        TEST_SAY("Phase 1: subscribed with '%s' (literal); polling...\n",
                 caret_pattern);
        attempts = 10;
        while (attempts-- > 0) {
                size_t rcvd = 0;
                size_t m;
                rd_kafka_error_t *err;

                rd_kafka_messages_destroy(batch);
                batch = NULL;
                err   = rd_kafka_share_poll(consumer, 2000, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                if (err)
                        rd_kafka_error_destroy(err);

                for (m = 0; m < rcvd; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        if (!msg->err)
                                records_phase1++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;
        TEST_ASSERT(records_phase1 == 0,
                    "Phase 1: expected 0 records for '%s' literal "
                    "subscription, got %zu",
                    caret_pattern, records_phase1);
        TEST_SAY("Phase 1: received 0 records as expected\n");

        /* Phase 2: resubscribe with the plain topic name — broker
         * resolves it, consumer receives records. */
        TEST_CALL_ERR__(rd_kafka_share_unsubscribe(consumer));

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(consumer, subs));
        rd_kafka_topic_partition_list_destroy(subs);

        /* rd_kafka_share_subscription must now return the plain name. */
        subs = NULL;
        TEST_CALL_ERR__(rd_kafka_share_subscription(consumer, &subs));
        TEST_ASSERT(subs && subs->cnt == 1,
                    "Phase 2: expected subscription cnt 1, got %d",
                    subs ? subs->cnt : -1);
        TEST_ASSERT(!strcmp(subs->elems[0].topic, topic),
                    "Phase 2: expected subscription[0]='%s', got '%s'", topic,
                    subs->elems[0].topic);
        rd_kafka_topic_partition_list_destroy(subs);

        TEST_SAY("Phase 2: resubscribed with plain name '%s'; consuming...\n",
                 topic);
        attempts = 10;
        while (records_phase2 < (size_t)msg_cnt && attempts-- > 0) {
                size_t rcvd = 0;
                size_t m;
                rd_kafka_error_t *err;

                rd_kafka_messages_destroy(batch);
                batch = NULL;
                err   = rd_kafka_share_poll(consumer, 2000, &batch);
                rcvd  = rd_kafka_messages_count(batch);
                if (err)
                        rd_kafka_error_destroy(err);

                for (m = 0; m < rcvd; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        if (!msg->err)
                                records_phase2++;
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;
        TEST_ASSERT(records_phase2 == (size_t)msg_cnt,
                    "Phase 2: expected %d records, got %zu", msg_cnt,
                    records_phase2);
        TEST_SAY("Phase 2: received %zu/%d records\n", records_phase2, msg_cnt);

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        SUB_TEST_PASS();
}

/**
 * @brief Verify consume_batch surfaces RD_KAFKA_RESP_ERR__STATE with
 *        "not subscribed" when there is no active subscription.
 *
 * Walks the subscription state machine:
 *   Case 1: never subscribed                     -> __STATE
 *   Case 2: after subscribe                      -> not __STATE (recovery)
 *   Case 3: after unsubscribe                    -> __STATE
 *   Case 4: after re-subscribe following unsub   -> not __STATE (recovery)
 *   Case 5: subscribe([]) (== unsubscribe)       -> __STATE
 */
static void do_test_consume_batch_without_subscription(void) {
        rd_kafka_share_t *consumer;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *err;
        size_t rcvd       = 0;
        const char *group = "share-no-subscription";
        const char *topic;

        SUB_TEST();

        topic = test_mk_topic_name("0170-no-subscription", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        consumer = test_create_share_consumer(group, NULL);

        /* Case 1: never subscribed. */
        rd_kafka_messages_destroy(batch);
        batch = NULL;
        err   = rd_kafka_share_poll(consumer, 500, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_ASSERT(err != NULL,
                    "Case 1 (never subscribed): expected error, got NULL");
        TEST_ASSERT(rd_kafka_error_code(err) == RD_KAFKA_RESP_ERR__STATE,
                    "Case 1: expected __STATE, got: %s",
                    rd_kafka_err2name(rd_kafka_error_code(err)));
        TEST_ASSERT(strstr(rd_kafka_error_string(err), "not subscribed"),
                    "Case 1: expected 'not subscribed' substring, got: %s",
                    rd_kafka_error_string(err));
        TEST_ASSERT(rcvd == 0, "Case 1: expected 0 msgs, got %zu", rcvd);
        rd_kafka_error_destroy(err);

        /* Case 2: subscribed -> must not surface __STATE. */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(consumer, subs));
        rd_kafka_topic_partition_list_destroy(subs);

        rd_kafka_messages_destroy(batch);
        batch = NULL;
        err   = rd_kafka_share_poll(consumer, 500, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        if (err) {
                TEST_ASSERT(rd_kafka_error_code(err) !=
                                RD_KAFKA_RESP_ERR__STATE,
                            "Case 2 (subscribed): unexpected __STATE: %s",
                            rd_kafka_error_string(err));
                rd_kafka_error_destroy(err);
        }

        /* Case 3: unsubscribed -> __STATE again. */
        TEST_CALL_ERR__(rd_kafka_share_unsubscribe(consumer));

        rd_kafka_messages_destroy(batch);
        batch = NULL;
        err   = rd_kafka_share_poll(consumer, 500, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_ASSERT(err != NULL,
                    "Case 3 (after unsubscribe): expected error, got NULL");
        TEST_ASSERT(rd_kafka_error_code(err) == RD_KAFKA_RESP_ERR__STATE,
                    "Case 3: expected __STATE, got: %s",
                    rd_kafka_err2name(rd_kafka_error_code(err)));
        TEST_ASSERT(strstr(rd_kafka_error_string(err), "not subscribed"),
                    "Case 3: expected 'not subscribed' substring, got: %s",
                    rd_kafka_error_string(err));
        TEST_ASSERT(rcvd == 0, "Case 3: expected 0 msgs, got %zu", rcvd);
        rd_kafka_error_destroy(err);

        /* Case 4: re-subscribed after unsubscribe -> must not surface __STATE.
         */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        TEST_CALL_ERR__(rd_kafka_share_subscribe(consumer, subs));
        rd_kafka_topic_partition_list_destroy(subs);

        rd_kafka_messages_destroy(batch);
        batch = NULL;
        err   = rd_kafka_share_poll(consumer, 500, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        if (err) {
                TEST_ASSERT(rd_kafka_error_code(err) !=
                                RD_KAFKA_RESP_ERR__STATE,
                            "Case 4 (re-subscribed): unexpected __STATE: %s",
                            rd_kafka_error_string(err));
                rd_kafka_error_destroy(err);
        }

        /* Case 5: subscribe([]) is equivalent to unsubscribe — must
         * return NO_ERROR and clear the F_SUBSCRIPTION flag, so the
         * next consume_batch returns __STATE. */
        rd_kafka_resp_err_t empty_err;

        subs      = rd_kafka_topic_partition_list_new(0);
        empty_err = rd_kafka_share_subscribe(consumer, subs);
        TEST_ASSERT(empty_err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Case 5 (subscribe([])): expected NO_ERROR "
                    "(treated as unsubscribe), got: %s",
                    rd_kafka_err2name(empty_err));
        rd_kafka_topic_partition_list_destroy(subs);

        rd_kafka_messages_destroy(batch);
        batch = NULL;
        err   = rd_kafka_share_poll(consumer, 500, &batch);
        rcvd  = rd_kafka_messages_count(batch);
        TEST_ASSERT(err != NULL,
                    "Case 5 (after subscribe([])): expected error, got NULL");
        TEST_ASSERT(rd_kafka_error_code(err) == RD_KAFKA_RESP_ERR__STATE,
                    "Case 5: expected __STATE, got: %s",
                    rd_kafka_err2name(rd_kafka_error_code(err)));
        TEST_ASSERT(strstr(rd_kafka_error_string(err), "not subscribed"),
                    "Case 5: expected 'not subscribed' substring, got: %s",
                    rd_kafka_error_string(err));
        TEST_ASSERT(rcvd == 0, "Case 5: expected 0 msgs, got %zu", rcvd);
        rd_kafka_error_destroy(err);
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        SUB_TEST_PASS();
}

/* Extends test_ack_cb_state_t to also record the topic of the first
 * callback invocation, so do_test_subscription_change_acks_pending can
 * verify that the implicit ack driven by the subscription change was for
 * t1 (not later t2 acks fired by subsequent polls in the loop). */
typedef struct subchg_ack_state_s {
        test_ack_cb_state_t base; /* must be first - cast-compat with base */
        char first_callback_topic[256];
} subchg_ack_state_t;

static void subchg_ack_cb(rd_kafka_share_t *rkshare,
                          rd_kafka_share_partition_offsets_list_t *partitions,
                          rd_kafka_resp_err_t err,
                          void *opaque) {
        subchg_ack_state_t *st = (subchg_ack_state_t *)opaque;
        const rd_kafka_share_partition_offsets_t *entry;
        const rd_kafka_topic_partition_t *part;

        (void)rkshare;

        /* Mirror test_share_ack_cb's base accounting */
        test_ack_cb_state_push_err(&st->base, err);

        entry = rd_kafka_share_partition_offsets_list_get(partitions, 0);
        if (!entry)
                return;

        st->base.total_offsets +=
            rd_kafka_share_partition_offsets_offsets_cnt(entry);

        /* Record the topic of the first callback invocation only. */
        if (st->base.callback_cnt == 1) {
                part = rd_kafka_share_partition_offsets_partition(entry);
                if (part && part->topic)
                        rd_snprintf(st->first_callback_topic,
                                    sizeof(st->first_callback_topic), "%s",
                                    part->topic);
        }
}


/**
 * @brief Test that a subscription change drives an implicit ack of the
 *        previously-fetched batch, firing the share ack callback.
 *
 * Produce one record to t1 and one to t2. In implicit mode, subscribe to t1,
 * fetch the t1 record (without explicitly acknowledging), then re-subscribe
 * to t2. The subscription change should cause t1's outstanding record to be
 * implicitly acknowledged, firing the ack commit callback for t1's
 * partition.
 *
 * A custom callback records the topic of the first callback invocation so
 * we can verify the callback fired for t1 (not for t2's implicit ack,
 * which can also fire if the polling loop iterates past the t2 record's
 * arrival).
 */
static void do_test_subscription_change_acks_pending(void) {
        char *group;
        char *t1;
        char *t2;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *err;
        subchg_ack_state_t state = {0};
        size_t rcvd              = 0;
        int attempts;

        SUB_TEST();

        /* rd_strdup each test_mk_topic_name() result because the helper
         * returns a pointer to a single TLS static buffer that gets
         * clobbered by the next call. */
        group = rd_strdup(test_mk_topic_name("share-sub-change-ack", 1));
        t1    = rd_strdup(test_mk_topic_name("0170-subchg-t1", 1));
        t2    = rd_strdup(test_mk_topic_name("0170-subchg-t2", 1));

        TEST_SAY("\n");
        TEST_SAY(
            "============================================================\n");
        TEST_SAY("=== subscription-change-drives-ack-callback ===\n");
        TEST_SAY(
            "============================================================\n");

        test_create_topic_wait_exists(NULL, t1, 1, -1, 30000);
        test_create_topic_wait_exists(NULL, t2, 1, -1, 30000);

        test_produce_msgs_simple(common_producer, t1, 0, 1);
        test_produce_msgs_simple(common_producer, t2, 0, 1);

        rkshare = test_create_share_consumer_with_cb(
            group, "implicit", &state.base, subchg_ack_cb);
        test_share_set_auto_offset_reset(group, "earliest");

        /* Subscribe to t1 only */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, t1, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(rkshare, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        /* Poll until the t1 record arrives */
        attempts = 30;
        while (rcvd < 1 && attempts-- > 0) {
                size_t batch_rcvd = 0;
                rd_kafka_messages_destroy(batch);
                batch      = NULL;
                err        = rd_kafka_share_poll(rkshare, 2000, &batch);
                batch_rcvd = rd_kafka_messages_count(batch);
                if (err)
                        rd_kafka_error_destroy(err);
                rcvd += batch_rcvd;
        }
        TEST_ASSERT(rcvd == 1, "Expected 1 record from t1, got %zu", rcvd);
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        TEST_ASSERT(state.base.callback_cnt == 0,
                    "Did not expect callback before subscription change, "
                    "got %d",
                    state.base.callback_cnt);

        /* Re-subscribe to t2 only - this should drive an implicit ack of
         * t1's outstanding batch. */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, t2, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(rkshare, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        /* Poll a few times to drive the callback and pick up the t2 record.
         * Subsequent polls in this loop may also piggyback t2's implicit
         * ack and produce a second callback, but the FIRST callback must
         * be the one driven by the t1 -> t2 subscription change. The
         * custom callback records the topic of the first invocation so
         * we can assert that below. */
        rcvd     = 0;
        attempts = 30;
        while ((rcvd < 1 || state.base.callback_cnt < 1) && attempts-- > 0) {
                size_t batch_rcvd = 0;
                rd_kafka_messages_destroy(batch);
                batch      = NULL;
                err        = rd_kafka_share_poll(rkshare, 1000, &batch);
                batch_rcvd = rd_kafka_messages_count(batch);
                if (err)
                        rd_kafka_error_destroy(err);
                rcvd += batch_rcvd;
        }

        TEST_ASSERT(rcvd == 1, "Expected 1 record from t2, got %zu", rcvd);
        TEST_ASSERT(state.base.callback_cnt >= 1,
                    "Expected ack callback to fire after subscription change, "
                    "got %d callbacks",
                    state.base.callback_cnt);
        TEST_ASSERT(
            test_ack_cb_state_first_err(&state.base) ==
                RD_KAFKA_RESP_ERR_NO_ERROR,
            "Expected no error in callback, got %s",
            rd_kafka_err2name(test_ack_cb_state_first_err(&state.base)));
        TEST_ASSERT(strcmp(state.first_callback_topic, t1) == 0,
                    "Expected first ack callback to be for t1 (%s), got %s", t1,
                    state.first_callback_topic);

        rd_kafka_messages_destroy(batch);
        batch = NULL;

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);
        test_ack_cb_state_destroy(&state.base);

        rd_free(t1);
        rd_free(t2);
        rd_free(group);

        TEST_SAY("=== subscription-change-drives-ack-callback: PASSED ===\n");

        SUB_TEST_PASS();
}


/**
 * @brief Test two share groups on the same topic with different
 *        auto.offset.reset policies (earliest vs latest).
 *
 * Group A is configured for earliest, group B for latest. Records produced
 * before either group joins are visible only to group A; records produced
 * after both have joined are visible to both.
 */
static void do_test_two_groups_earliest_vs_latest(void) {
        char *grpA;
        char *grpB;
        char *topic;
        rd_kafka_share_t *consA, *consB;
        rd_kafka_topic_partition_list_t *subs;
        int countA = 0, countB = 0;
        int attempts;

        SUB_TEST();

        /* rd_strdup each test_mk_topic_name() result because the helper
         * returns a pointer to a single TLS static buffer that gets
         * clobbered by the next call. Without this, grpA, grpB and topic
         * would all alias to the same buffer. */
        grpA  = rd_strdup(test_mk_topic_name("share-grpA-earliest", 1));
        grpB  = rd_strdup(test_mk_topic_name("share-grpB-latest", 1));
        topic = rd_strdup(test_mk_topic_name("0170-evl", 1));

        TEST_SAY("\n");
        TEST_SAY(
            "============================================================\n");
        TEST_SAY("=== two-groups-earliest-vs-latest ===\n");
        TEST_SAY(
            "============================================================\n");

        test_create_topic_wait_exists(NULL, topic, 1, -1, 30000);

        /* Produce 5 records BEFORE the consumers join. These are the
         * "original records present in the broker" that earliest fetches
         * and latest skips. */
        test_produce_msgs_simple(common_producer, topic, 0, 5);

        /* Match the working librdkafka ordering used by
         * do_test_multi_consumer_overlap (0170) and 0171's
         * test_poll_callback_piggybacked_acks:
         *   produce -> create consumer -> set reset -> subscribe -> poll.
         * Setting share.auto.offset.reset before any consumer exists at
         * the broker doesn't take effect; setting it after consumer
         * creation but before subscribe does. */
        consA = test_create_share_consumer(grpA, NULL);
        consB = test_create_share_consumer(grpB, NULL);

        test_share_set_auto_offset_reset(grpA, "earliest");
        test_share_set_auto_offset_reset(grpB, "latest");

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(consA, subs);
        rd_kafka_share_subscribe(consB, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        /* groupA (earliest) fetches the 5 pre-existing records;
         * groupB (latest) skips them (HW=5 anchors the start). */
        attempts = 30;
        while (attempts-- > 0 && countA < 5) {
                int batch_cnt = 0;
                test_share_poll(consA, 1000, NULL, 0, &batch_cnt);
                countA += batch_cnt;

                batch_cnt = 0;
                test_share_poll(consB, 500, NULL, 0, &batch_cnt);
                countB += batch_cnt;
        }
        TEST_ASSERT(countA == 5, "groupA (earliest) expected 5 records, got %d",
                    countA);
        TEST_ASSERT(countB == 0,
                    "groupB (latest) expected 0 records for pre-subscribe "
                    "produce, got %d",
                    countB);

        /* Produce 3 more records AFTER both groups have joined - both
         * groups should see these (earliest continues from HW=5, latest
         * advances from HW=5 too). */
        test_produce_msgs_simple(common_producer, topic, 0, 3);

        attempts = 30;
        while (attempts-- > 0 && countB < 3) {
                int batch_cnt = 0;
                test_share_poll(consA, 500, NULL, 0, &batch_cnt);
                countA += batch_cnt;

                batch_cnt = 0;
                test_share_poll(consB, 1000, NULL, 0, &batch_cnt);
                countB += batch_cnt;
        }
        TEST_ASSERT(countA == 8, "groupA expected 8 records total, got %d",
                    countA);
        TEST_ASSERT(countB == 3,
                    "groupB expected 3 records (post-subscribe only), got %d",
                    countB);

        test_share_consumer_close(consA);
        test_share_consumer_close(consB);
        test_share_destroy(consA);
        test_share_destroy(consB);

        rd_free(grpA);
        rd_free(grpB);
        rd_free(topic);

        TEST_SAY("=== two-groups-earliest-vs-latest: PASSED ===\n");

        SUB_TEST_PASS();
}


/**
 * @brief Test that DeleteRecords advances the LSO and a new share group
 *        with auto.offset.reset=earliest starts at the new LSO.
 *
 * Produce 10 records, DeleteRecords up to offset 5 (LSO -> 5), then create
 * a new share group with earliest and verify exactly 5 records
 * (offsets 5..9) are consumed.
 */
static void do_test_delete_records_advances_lso(void) {
        char *group;
        char *topic;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_share_t *rkshare;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *err_obj;
        rd_kafka_resp_err_t err;
        int64_t first_offset = -1;
        int consumed         = 0;
        size_t batch_cnt     = 0;
        int attempts;
        size_t k;

        SUB_TEST();

        if (!strcmp(test_getenv("TEST_BROKER_OS", ""), "windows"))
                SUB_TEST_SKIP(
                    "delete-records scenario not supported (broker on "
                    "Windows)\n");

        group = rd_strdup(test_mk_topic_name("share-lso-delete", 1));
        topic = rd_strdup(test_mk_topic_name("0170-lso", 1));

        TEST_SAY("\n");
        TEST_SAY(
            "============================================================\n");
        TEST_SAY("=== delete-records-advances-lso ===\n");
        TEST_SAY(
            "============================================================\n");

        test_create_topic_wait_exists(NULL, topic, 1, -1, 30000);
        test_produce_msgs_simple(common_producer, topic, 0, 10);

        /* DeleteRecords up to offset 5: deletes offsets 0..4, LSO moves to 5 */
        offsets = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offsets, topic, 0)->offset = 5;
        err = test_DeleteRecords_simple(common_admin, NULL, offsets, NULL);
        rd_kafka_topic_partition_list_destroy(offsets);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "DeleteRecords failed: %s", rd_kafka_err2name(err));

        /* New share group with earliest should start at the new LSO */
        test_share_set_auto_offset_reset(group, "earliest");
        rkshare = test_create_share_consumer(group, NULL);

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(rkshare, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        attempts = 30;
        while (consumed < 5 && attempts-- > 0) {
                rd_kafka_messages_destroy(batch);
                batch     = NULL;
                err_obj   = rd_kafka_share_poll(rkshare, 2000, &batch);
                batch_cnt = rd_kafka_messages_count(batch);
                if (err_obj) {
                        rd_kafka_error_destroy(err_obj);
                        continue;
                }
                for (k = 0; k < batch_cnt; k++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, k);
                        if (!msg->err) {
                                if (first_offset == -1)
                                        first_offset = msg->offset;
                                consumed++;
                        }
                }
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;
        TEST_ASSERT(consumed == 5,
                    "Expected 5 records (offsets 5..9) after DeleteRecords, "
                    "consumed %d",
                    consumed);
        TEST_ASSERT(first_offset == 5,
                    "Expected first delivered offset to be 5 (new LSO after "
                    "DeleteRecords), got %" PRId64,
                    first_offset);

        /* Verify no additional records show up */
        rd_kafka_messages_destroy(batch);
        batch     = NULL;
        err_obj   = rd_kafka_share_poll(rkshare, 1000, &batch);
        batch_cnt = rd_kafka_messages_count(batch);
        if (err_obj)
                rd_kafka_error_destroy(err_obj);
        TEST_ASSERT(batch_cnt == 0,
                    "Did not expect more records after consuming 5, got %zu",
                    batch_cnt);
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        rd_free(group);
        rd_free(topic);

        TEST_SAY("=== delete-records-advances-lso: PASSED ===\n");

        SUB_TEST_PASS();
}

/* subscribe([]) is equivalent to unsubscribe — must clear the
 * subscription flag so the subsequent poll surfaces __STATE. */
static const test_scenario_t test_poll_after_empty_subscribe = {
    .name = "poll-after-empty-subscribe",
    .ops  = {SUBSCRIBE(1), PRODUCE(5), CONSUME_ANY(),
             SUBSCRIBE_EMPTY(), /* Empty list == unsubscribe */
             POLL_NO_SUB(), TEST_OPS_END()}};

int main_0170_share_consumer_subscription(int argc, char **argv) {
        /* Create common handles for all tests */
        common_producer = test_create_producer();
        common_admin    = test_create_producer();

        test_timeout_set(200);

        /* Auto offset reset tests */
        do_test_auto_offset_reset_earliest();
        do_test_auto_offset_reset_default_latest();

        /* Basic subscription tests */
        do_test_scenario(&test_single_subscribe);
        do_test_scenario(&test_single_unsubscribe);
        do_test_scenario(&test_repeated_subscribe);
        do_test_scenario(&test_repeated_unsubscribe);

        /* Subscription replacement tests */
        /* TODO KIP-932: test_topic_switch might be incorrect. Verify and
         * remove. */
        // do_test_scenario(&test_topic_switch);
        do_test_scenario(&test_incremental_subscription);

        /* Edge case tests */
        do_test_scenario(&test_subscribe_before_topic_exists);
        do_test_scenario(&test_poll_empty_topic);
        do_test_scenario(&test_poll_no_subscription);
        do_test_scenario(&test_poll_after_unsubscribe);

        /* Topic deletion tests (Skipped for Windows)*/
        if (!strcmp(test_getenv("TEST_BROKER_OS", ""), "windows"))
                TEST_SAY(
                    "Skipping topic deletion scenario"
                    "(broker on Windows)\n");
        else
                do_test_scenario(&test_topic_deletion);

        /* Verify that topic deletion does not surface a topic-level
         * error code to consume_batch (transient codes are log-only). */
        test_topic_deletion_does_not_surface_error();

        /* Stress tests */
        do_test_scenario(&test_rapid_updates);

        /* Multi-consumer tests (standalone - requires shared topics) */
        do_test_multi_consumer_overlap();

        /* Scale tests (many topics) */
        do_test_subscribe_15_topics();

        /* Subscription change drives ack callback */
        do_test_subscription_change_acks_pending();

        /* Two groups with earliest vs latest offset reset */
        do_test_two_groups_earliest_vs_latest();

        /* DeleteRecords advances LSO; new group with earliest sees fewer
         * records (skipped on Windows brokers). */
        do_test_delete_records_advances_lso();

        /* Input validation tests */
        do_test_subscribe_input_validation();
        do_test_subscribe_caret_treated_as_literal_e2e();

        /* Subscription state guard tests */
        do_test_consume_batch_without_subscription();
        do_test_scenario(&test_poll_after_empty_subscribe);

        /* Cleanup common handles */
        rd_kafka_destroy(common_admin);
        rd_kafka_destroy(common_producer);

        return 0;
}
