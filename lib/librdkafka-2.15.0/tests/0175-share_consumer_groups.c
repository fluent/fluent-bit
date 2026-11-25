/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2026, Confluent Inc.
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
 * @name Share Consumer Multiple Groups Tests
 *
 * Tests for multiple share groups consuming from the same topic independently.
 * Each share group should receive all messages independently of other groups.
 */

#define MAX_GROUPS            8
#define MAX_CONSUMERS_PER_GRP 4
#define MAX_PARTITIONS        8
#define BATCH_SIZE            1000

/**
 * @brief Configuration for a multi-group share consumer test
 */
typedef struct {
        int group_cnt;                       /**< Number of share groups */
        int consumers_per_group[MAX_GROUPS]; /**< Consumers per group */
        const char *group_names[MAX_GROUPS]; /**< Group names */
        rd_bool_t use_earliest[MAX_GROUPS];  /**< Use earliest offset */
        int partitions;                      /**< Number of partitions */
        int msgs_per_partition;              /**< Messages per partition */
        const char *test_name;               /**< Test description */
        int max_attempts;                    /**< Max poll attempts */
        rd_bool_t produce_before_subscribe;  /**< Produce before subscribe */
        int msgs_produce_after_subscribe;    /**< Messages after subscribe */
} groups_test_config_t;

/**
 * @brief Test state for multi-group tests
 */
typedef struct {
        rd_kafka_share_t *consumers[MAX_GROUPS][MAX_CONSUMERS_PER_GRP];
        int consumed[MAX_GROUPS];
        int expected_per_group;
        char *topic;
} groups_test_state_t;

/**
 * @brief Create consumers for all groups
 */
static void create_group_consumers(groups_test_config_t *config,
                                   groups_test_state_t *state) {
        int g, c;

        for (g = 0; g < config->group_cnt; g++) {
                for (c = 0; c < config->consumers_per_group[g]; c++) {
                        state->consumers[g][c] = test_create_share_consumer(
                            config->group_names[g], NULL);
                }

                /* Configure group offset if earliest */
                if (config->use_earliest[g]) {
                        test_share_set_auto_offset_reset(config->group_names[g],
                                                         "earliest");
                }

                TEST_SAY("Created %d consumer(s) for group '%s' (offset=%s)\n",
                         config->consumers_per_group[g], config->group_names[g],
                         config->use_earliest[g] ? "earliest" : "latest");
        }
}

/**
 * @brief Setup topic and produce initial messages
 */
static void setup_topic_and_produce(groups_test_config_t *config,
                                    groups_test_state_t *state,
                                    int msg_cnt) {
        int p;

        state->topic = rd_strdup(test_mk_topic_name("0175-groups", 1));
        test_create_topic_wait_exists(NULL, state->topic, config->partitions,
                                      -1, 60 * 1000);

        if (msg_cnt > 0) {
                for (p = 0; p < config->partitions; p++) {
                        test_produce_msgs_easy(state->topic, 0, p,
                                               msg_cnt / config->partitions);
                }
                TEST_SAY("Produced %d messages to topic '%s' (%d partitions)\n",
                         msg_cnt, state->topic, config->partitions);
        }
}

/**
 * @brief Subscribe all consumers to the topic
 */
static void subscribe_all_consumers(groups_test_config_t *config,
                                    groups_test_state_t *state) {
        rd_kafka_topic_partition_list_t *subs;
        int g, c;

        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, state->topic,
                                          RD_KAFKA_PARTITION_UA);

        for (g = 0; g < config->group_cnt; g++) {
                for (c = 0; c < config->consumers_per_group[g]; c++) {
                        rd_kafka_share_subscribe(state->consumers[g][c], subs);
                }
        }

        rd_kafka_topic_partition_list_destroy(subs);
        TEST_SAY("Subscribed all consumers to topic '%s'\n", state->topic);

        /* Allow consumers to join groups */
        rd_sleep(2);
}

/**
 * @brief Consume messages from all groups
 */
static void consume_from_all_groups(groups_test_config_t *config,
                                    groups_test_state_t *state) {
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *err;
        int attempts;
        int g, c;
        int idle_rounds = 0;
        int round_consumed;
        int all_done;
        size_t rcvd;
        size_t m;
        char progress[256];
        int pos;

        for (g = 0; g < config->group_cnt; g++) {
                state->consumed[g] = 0;
        }

        attempts = config->max_attempts > 0 ? config->max_attempts : 100;

        while (attempts-- > 0 && idle_rounds < 20) {
                round_consumed = 0;
                all_done       = 1;

                for (g = 0; g < config->group_cnt; g++) {
                        if (state->consumed[g] >= state->expected_per_group)
                                continue;

                        all_done = 0;

                        for (c = 0; c < config->consumers_per_group[g]; c++) {
                                err = rd_kafka_share_poll(
                                    state->consumers[g][c], 500, &batch);
                                if (err) {
                                        TEST_SAY(
                                            "Group %d consumer %d: "
                                            "share_poll failed: %s\n",
                                            g, c, rd_kafka_error_string(err));
                                        rd_kafka_error_destroy(err);
                                        continue;
                                }

                                rcvd = rd_kafka_messages_count(batch);
                                for (m = 0; m < rcvd; m++) {
                                        rd_kafka_message_t *msg =
                                            rd_kafka_messages_get(batch, m);
                                        if (msg && !msg->err)
                                                state->consumed[g]++;
                                }
                                rd_kafka_messages_destroy(batch);
                                batch = NULL;
                                round_consumed += (int)rcvd;
                        }
                }

                if (all_done)
                        break;

                if (round_consumed > 0) {
                        idle_rounds = 0;
                        if (attempts % 10 == 0) {
                                memset(progress, 0, sizeof(progress));
                                pos = 0;
                                for (g = 0; g < config->group_cnt && pos < 200;
                                     g++) {
                                        pos += rd_snprintf(
                                            progress + pos,
                                            sizeof(progress) - pos,
                                            "G%d=%d/%d ", g, state->consumed[g],
                                            state->expected_per_group);
                                }
                                TEST_SAY("Progress: %s\n", progress);
                        }
                } else {
                        idle_rounds++;
                }
        }
}

/**
 * @brief Cleanup test resources
 */
static void cleanup_groups_test(groups_test_config_t *config,
                                groups_test_state_t *state) {
        int g, c;

        if (state->topic) {
                test_delete_topic(
                    test_share_consumer_get_rk(state->consumers[0][0]),
                    state->topic);
                rd_free(state->topic);
        }

        for (g = 0; g < config->group_cnt; g++) {
                for (c = 0; c < config->consumers_per_group[g]; c++) {
                        if (state->consumers[g][c]) {
                                test_share_consumer_close(
                                    state->consumers[g][c]);
                                test_share_destroy(state->consumers[g][c]);
                        }
                }
        }
}

/**
 * @brief Run a multi-group test
 */
static void run_groups_test(groups_test_config_t *config) {
        groups_test_state_t state = {0};
        int g;
        int p;
        int per_partition;
        int total_msgs;
        char result[256] = {0};
        int pos          = 0;
        char unique_suffix[64];
        char unique_test_name[256];
        char unique_group_names[MAX_GROUPS][128];

        /* Per-invocation unique suffix; appended to the test name and
         * to every group name so re-runs / parallel runs get fresh
         * share-groups on the broker. */
        rd_snprintf(unique_suffix, sizeof(unique_suffix), "rnd%" PRIx64,
                    test_id_generate());
        rd_snprintf(unique_test_name, sizeof(unique_test_name), "%s [%s]",
                    config->test_name, unique_suffix);
        config->test_name = unique_test_name;
        for (g = 0; g < config->group_cnt; g++) {
                rd_snprintf(unique_group_names[g],
                            sizeof(unique_group_names[g]), "%s-%s",
                            config->group_names[g], unique_suffix);
                config->group_names[g] = unique_group_names[g];
        }

        TEST_SAY("\n");
        TEST_SAY(
            "============================================================\n");
        TEST_SAY("=== %s ===\n", config->test_name);
        TEST_SAY(
            "============================================================\n");

        /* Calculate expected messages */
        total_msgs = config->partitions * config->msgs_per_partition;
        if (config->produce_before_subscribe) {
                state.expected_per_group = total_msgs;
        } else {
                state.expected_per_group = 0;
        }
        state.expected_per_group += config->msgs_produce_after_subscribe;

        /* Create consumers */
        create_group_consumers(config, &state);

        /* Setup topic and produce initial messages if configured */
        if (config->produce_before_subscribe) {
                setup_topic_and_produce(config, &state, total_msgs);
        } else {
                setup_topic_and_produce(config, &state, 0);
        }

        /* Subscribe all consumers */
        subscribe_all_consumers(config, &state);

        /* Produce after subscribe if configured */
        if (config->msgs_produce_after_subscribe > 0) {
                per_partition =
                    config->msgs_produce_after_subscribe / config->partitions;
                for (p = 0; p < config->partitions; p++) {
                        test_produce_msgs_easy(state.topic, 0, p,
                                               per_partition);
                }
                TEST_SAY("Produced %d messages after subscribe\n",
                         config->msgs_produce_after_subscribe);
        }

        /* Consume from all groups */
        consume_from_all_groups(config, &state);

        /* Verify results */
        for (g = 0; g < config->group_cnt; g++) {
                pos += rd_snprintf(result + pos, sizeof(result) - pos,
                                   "G%d=%d ", g, state.consumed[g]);
        }
        TEST_SAY("Results: %s(expected %d each)\n", result,
                 state.expected_per_group);

        for (g = 0; g < config->group_cnt; g++) {
                /* Allow some tolerance for latest offset tests */
                if (!config->use_earliest[g]) {
                        TEST_ASSERT(
                            state.consumed[g] >= state.expected_per_group - 5 &&
                                state.consumed[g] <=
                                    state.expected_per_group + 5,
                            "Group %d expected ~%d messages, got %d", g,
                            state.expected_per_group, state.consumed[g]);
                } else {
                        TEST_ASSERT(
                            state.consumed[g] == state.expected_per_group,
                            "Group %d expected %d messages, got %d", g,
                            state.expected_per_group, state.consumed[g]);
                }
        }

        TEST_SAY("SUCCESS: %s\n", config->test_name);

        cleanup_groups_test(config, &state);
}

/***************************************************************************
 * Test Cases
 ***************************************************************************/

/**
 * @brief Two groups consuming same topic independently
 */
static void do_test_two_groups_same_topic(void) {
        groups_test_config_t config = {
            .group_cnt                = 2,
            .consumers_per_group      = {1, 1},
            .group_names              = {"share-2grp-A", "share-2grp-B"},
            .use_earliest             = {rd_true, rd_true},
            .partitions               = 1,
            .msgs_per_partition       = 100,
            .test_name                = "Two groups consuming same topic",
            .produce_before_subscribe = rd_true,
        };

        SUB_TEST();
        run_groups_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Three groups with 2 consumers each
 */
static void do_test_three_groups_concurrent(void) {
        groups_test_config_t config = {
            .group_cnt           = 3,
            .consumers_per_group = {2, 2, 2},
            .group_names  = {"share-3grp-A", "share-3grp-B", "share-3grp-C"},
            .use_earliest = {rd_true, rd_true, rd_true},
            .partitions   = 3,
            .msgs_per_partition       = 334,
            .test_name                = "Three groups with 2 consumers each",
            .produce_before_subscribe = rd_true,
            .max_attempts             = 150,
        };

        SUB_TEST();
        run_groups_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Five groups consuming same topic
 */
static void do_test_five_groups_same_topic(void) {
        groups_test_config_t config = {
            .group_cnt           = 5,
            .consumers_per_group = {1, 1, 1, 1, 1},
            .group_names  = {"share-5grp-A", "share-5grp-B", "share-5grp-C",
                             "share-5grp-D", "share-5grp-E"},
            .use_earliest = {rd_true, rd_true, rd_true, rd_true, rd_true},
            .partitions   = 2,
            .msgs_per_partition       = 250,
            .test_name                = "Five groups consuming same topic",
            .produce_before_subscribe = rd_true,
            .max_attempts             = 150,
        };

        SUB_TEST();
        run_groups_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Groups joining at staggered times
 */
static void do_test_groups_staggered_join(void) {
        rd_kafka_share_t *consumer_a, *consumer_b;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *err;
        const char *topic;
        const char *group_a = "share-stagger-A";
        const char *group_b = "share-stagger-B";
        const int msg_cnt   = 100;
        int consumed_a = 0, consumed_b = 0;
        int attempts;
        size_t rcvd;
        size_t m;

        SUB_TEST();

        TEST_SAY("\n");
        TEST_SAY(
            "============================================================\n");
        TEST_SAY("=== Groups joining at staggered times ===\n");
        TEST_SAY(
            "============================================================\n");

        /* Create topic */
        topic = test_mk_topic_name("0175-staggered", 1);
        test_create_topic_wait_exists(NULL, topic, 1, -1, 60 * 1000);

        /* Create first consumer */
        consumer_a = test_create_share_consumer(group_a, NULL);
        test_share_set_auto_offset_reset(group_a, "earliest");

        /* Produce messages */
        test_produce_msgs_easy(topic, 0, 0, msg_cnt);

        /* Subscribe first consumer */
        subs = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
        rd_kafka_share_subscribe(consumer_a, subs);
        rd_sleep(2);

        /* Group A consumes half */
        attempts = 30;
        while (consumed_a < msg_cnt / 2 && attempts-- > 0) {
                err = rd_kafka_share_poll(consumer_a, 1000, &batch);
                if (err) {
                        TEST_SAY("Group A: share_poll failed: %s\n",
                                 rd_kafka_error_string(err));
                        rd_kafka_error_destroy(err);
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);
                for (m = 0; m < rcvd; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        if (msg && !msg->err)
                                consumed_a++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_SAY("Group A consumed %d so far\n", consumed_a);

        /* Now create second consumer */
        consumer_b = test_create_share_consumer(group_b, NULL);
        test_share_set_auto_offset_reset(group_b, "earliest");
        rd_kafka_share_subscribe(consumer_b, subs);
        rd_kafka_topic_partition_list_destroy(subs);
        rd_sleep(2);

        /* Both finish consuming */
        attempts = 50;
        while ((consumed_a < msg_cnt || consumed_b < msg_cnt) &&
               attempts-- > 0) {
                if (consumed_a < msg_cnt) {
                        err = rd_kafka_share_poll(consumer_a, 500, &batch);
                        if (!err) {
                                rcvd = rd_kafka_messages_count(batch);
                                for (m = 0; m < rcvd; m++) {
                                        rd_kafka_message_t *msg =
                                            rd_kafka_messages_get(batch, m);
                                        if (msg && !msg->err)
                                                consumed_a++;
                                }
                                rd_kafka_messages_destroy(batch);
                                batch = NULL;
                        } else {
                                TEST_SAY(
                                    "Group A: share_poll failed: "
                                    "%s\n",
                                    rd_kafka_error_string(err));
                                rd_kafka_error_destroy(err);
                        }
                }

                if (consumed_b < msg_cnt) {
                        err = rd_kafka_share_poll(consumer_b, 500, &batch);
                        if (!err) {
                                rcvd = rd_kafka_messages_count(batch);
                                for (m = 0; m < rcvd; m++) {
                                        rd_kafka_message_t *msg =
                                            rd_kafka_messages_get(batch, m);
                                        if (msg && !msg->err)
                                                consumed_b++;
                                }
                                rd_kafka_messages_destroy(batch);
                                batch = NULL;
                        } else {
                                TEST_SAY(
                                    "Group B: share_poll failed: "
                                    "%s\n",
                                    rd_kafka_error_string(err));
                                rd_kafka_error_destroy(err);
                        }
                }
        }

        TEST_SAY("Results: A=%d, B=%d (expected %d each)\n", consumed_a,
                 consumed_b, msg_cnt);

        TEST_ASSERT(consumed_a == msg_cnt, "Group A expected %d, got %d",
                    msg_cnt, consumed_a);
        TEST_ASSERT(consumed_b == msg_cnt, "Group B expected %d, got %d",
                    msg_cnt, consumed_b);

        TEST_SAY("SUCCESS: Groups joining at staggered times\n");

        test_share_consumer_close(consumer_a);
        test_share_consumer_close(consumer_b);
        test_delete_topic(test_share_consumer_get_rk(consumer_a), topic);
        test_share_destroy(consumer_a);
        test_share_destroy(consumer_b);

        SUB_TEST_PASS();
}

int main_0175_share_consumer_groups(int argc, char **argv) {

        /* Basic multiple groups tests */
        do_test_two_groups_same_topic();
        do_test_three_groups_concurrent();

        /* Scale tests */
        do_test_five_groups_same_topic();

        /* Timing tests */
        do_test_groups_staggered_join();

        return 0;
}
