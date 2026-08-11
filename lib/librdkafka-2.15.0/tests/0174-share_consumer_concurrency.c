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
 * @name Share Consumer Concurrency and Stress Tests
 *
 * Tests share consumer behavior under concurrent producer/consumer scenarios.
 * Each test uses a config-based structure. Producers and consumers each run
 * in their own dedicated threads — there is no main-thread round-robin
 * polling. The main test thread orchestrates start/stop and verifies
 * end-state counters. The per-record invariant validated is first-delivery
 * count (each produced record is first-delivered exactly once; redeliveries
 * are counted separately).
 */

#define MAX_TOPICS        16
#define MAX_PARTITIONS    16
#define MAX_CONSUMERS     16
#define MAX_PRODUCERS     10
#define MAX_CONSUMER_POOL 32
#define BATCH_SIZE        10000

/* Save test_curr for threads (test_curr is TLS) */
static struct test *this_test;

/***************************************************************************
 * Test Configuration and State
 ***************************************************************************/

/**
 * @brief Configuration for a concurrent share consumer test
 */
typedef struct {
        int consumer_cnt;           /**< Number of consumers to create */
        int producer_cnt;           /**< Number of producer threads */
        int topic_cnt;              /**< Number of topics */
        int partitions[MAX_TOPICS]; /**< Partitions per topic */
        int msgs_per_partition;     /**< Messages to produce per partition */
        const char *group_name;     /**< Share group name */
        const char *test_name;      /**< Test description */
        int max_attempts;           /**< Max poll attempts (0 = default) */
        int consumer_delay_ms;      /**< Delay between consumer polls */
        int producer_delay_ms;      /**< Delay between produces */
        rd_bool_t explicit_ack;     /**< Use explicit acknowledgement */
        rd_bool_t staggered_start;  /**< Start producers/consumers at
                                         different times */
} concurrent_test_config_t;

/**
 * @brief Shared state for concurrent test threads
 */
typedef struct {
        mtx_t lock;                   /**< Mutex for state access */
        int total_produced;           /**< Total messages produced */
        int total_consumed;           /**< Total messages consumed
                                       *   (includes redeliveries) */
        int total_first_delivery;     /**< Messages with delivery_count == 1 */
        int total_duplicates;         /**< Messages with delivery_count > 1 */
        int expected_total;           /**< Expected total messages */
        rd_bool_t producers_done;     /**< All producers finished */
        int producers_remaining;      /**< Producer threads still running */
        rd_bool_t test_failed;        /**< Test failure flag */
        char topics[MAX_TOPICS][128]; /**< Topic names */
        int topic_cnt;                /**< Number of topics */
        const char *group_name;       /**< Share group name */
        rd_bool_t explicit_ack;       /**< Use explicit acknowledgement */
} concurrent_test_state_t;

/**
 * @brief Arguments for producer thread
 */
typedef struct {
        concurrent_test_state_t *state;
        int producer_id;
        int msgs_to_produce;
        int delay_ms;
        int partitions[MAX_TOPICS];
} producer_thread_args_t;

/**
 * @brief Per-consumer-thread context.
 *
 * One share consumer per thread; main thread sets @c run to rd_false
 * (under state->lock) to ask the consumer to wind down. The consumer
 * thread sets @c done = rd_true under the same lock right before it
 * returns from consumer_thread_func, so the main thread can poll for a
 * clean exit instead of blocking forever in thrd_join when a consumer
 * is wedged inside librdkafka.
 */
typedef struct {
        concurrent_test_state_t *state;
        int consumer_id;
        rd_bool_t run;
        rd_bool_t done;    /**< Set true just before consumer thread exits */
        int poll_delay_ms; /**< Sleep between polls (from config) */
} consumer_thread_args_t;

/***************************************************************************
 * Thread Functions
 ***************************************************************************/

/**
 * @brief Producer thread function
 *
 * Produces messages to all topics/partitions in round-robin fashion.
 */
static int producer_thread_func(void *arg) {
        producer_thread_args_t *args   = (producer_thread_args_t *)arg;
        concurrent_test_state_t *state = args->state;
        rd_kafka_t *producer;
        rd_kafka_conf_t *conf;
        int produced = 0;
        int t, p;
        rd_kafka_resp_err_t err;
        char value[64];

        /* Restore the TLS test_curr pointer for this thread. The
         * exp_dr_status / ignore_dr_err fields on the struct itself are
         * set once by the main thread before any worker spawns
         * (see run_concurrent_test / do_test_chaos_consumer_lifecycle)
         * — touching them here would race against every other producer
         * thread that aliases the same global tests[] entry. */
        test_curr = this_test;

        /* Enable idempotent producer so retries do not result in duplicate
         * broker-side writes — without this, transient broker/network jitter
         * under the heavy concurrent load these tests generate (e.g.
         * test_max_concurrent with 10 producers × 5000 msgs) causes the
         * broker to store extra records that the share consumer then
         * receives as new offsets with delivery_count=1, inflating the
         * consumed count above expected_total. */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "enable.idempotence", "true");
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
        producer = test_create_handle(RD_KAFKA_PRODUCER, conf);

        TEST_SAY("Producer %d: starting, will produce %d messages\n",
                 args->producer_id, args->msgs_to_produce);

        while (produced < args->msgs_to_produce) {
                for (t = 0;
                     t < state->topic_cnt && produced < args->msgs_to_produce;
                     t++) {
                        for (p = 0; p < args->partitions[t] &&
                                    produced < args->msgs_to_produce;
                             p++) {
                                snprintf(value, sizeof(value), "prod%d-msg%d",
                                         args->producer_id, produced);

                                err = rd_kafka_producev(
                                    producer,
                                    RD_KAFKA_V_TOPIC(state->topics[t]),
                                    RD_KAFKA_V_PARTITION(p),
                                    RD_KAFKA_V_VALUE(value, strlen(value)),
                                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                    RD_KAFKA_V_END);

                                if (err) {
                                        TEST_SAY(
                                            "Producer %d: produce failed: %s\n",
                                            args->producer_id,
                                            rd_kafka_err2str(err));
                                        mtx_lock(&state->lock);
                                        state->test_failed = rd_true;
                                        mtx_unlock(&state->lock);
                                        goto done;
                                }

                                produced++;

                                if (args->delay_ms > 0 && produced % 100 == 0)
                                        rd_usleep(args->delay_ms * 1000, NULL);
                        }
                }

                rd_kafka_flush(producer, 1000);
        }

        rd_kafka_flush(producer, 10000);

        TEST_SAY("Producer %d: finished, produced %d messages\n",
                 args->producer_id, produced);

done:
        mtx_lock(&state->lock);
        state->total_produced += produced;
        if (--state->producers_remaining == 0)
                state->producers_done = rd_true;
        mtx_unlock(&state->lock);

        rd_kafka_destroy(producer);
        free(args);

        return thrd_success;
}

/**
 * @brief Per-thread share consumer poll loop.
 *
 * One share consumer per thread. Creates the consumer, subscribes to all
 * configured topics, then polls until @c args->run is cleared by the main
 * thread. Records first-time deliveries vs redeliveries via
 * rd_kafka_message_delivery_count() into shared counters.
 */
static int consumer_thread_func(void *arg) {
        consumer_thread_args_t *args   = (consumer_thread_args_t *)arg;
        concurrent_test_state_t *state = args->state;
        rd_kafka_share_t *consumer;
        rd_kafka_topic_partition_list_t *subs;
        rd_kafka_messages_t *batch = NULL;
        rd_kafka_error_t *err;
        int t;
        size_t m;
        size_t rcvd;
        rd_bool_t keep_running;

        test_curr = this_test;

        consumer = test_create_share_consumer(
            state->group_name, state->explicit_ack ? "explicit" : NULL);

        subs = rd_kafka_topic_partition_list_new(state->topic_cnt);
        for (t = 0; t < state->topic_cnt; t++) {
                rd_kafka_topic_partition_list_add(subs, state->topics[t],
                                                  RD_KAFKA_PARTITION_UA);
        }
        rd_kafka_share_subscribe(consumer, subs);
        rd_kafka_topic_partition_list_destroy(subs);

        TEST_SAY("Consumer thread %d: subscribed\n", args->consumer_id);

        while (1) {
                int acked_in_batch = 0;

                mtx_lock(&state->lock);
                keep_running = args->run;
                mtx_unlock(&state->lock);
                if (!keep_running)
                        break;

                err = rd_kafka_share_poll(consumer, 500, &batch);
                if (err) {
                        TEST_SAY("Consumer thread %d: share_poll error: %s\n",
                                 args->consumer_id, rd_kafka_error_string(err));
                        rd_kafka_error_destroy(err);
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        continue;
                }
                rcvd = rd_kafka_messages_count(batch);

                /* Per-record atomic step:
                 *   ACK → process (count into shared state under lock) →
                 *   destroy. ack + process happen in the same iteration
                 *   so there is no window where the broker can see an
                 *   ACK for a record that this application has not also
                 *   recorded as consumed in total_first_delivery /
                 *   total_duplicates. The per-batch commit_sync below
                 *   flushes the acks to the broker. */
                for (m = 0; m < rcvd; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);

                        if (!msg)
                                continue;

                        if (msg->err) {
                                const char *msg_topic =
                                    msg->rkt ? rd_kafka_topic_name(msg->rkt)
                                             : "(no-topic)";
                                TEST_SAY(
                                    "Consumer thread %d: SKIPPING record "
                                    "%s[%" PRId32 "] off=%" PRId64
                                    " because msg->err=%s\n",
                                    args->consumer_id, msg_topic,
                                    msg->partition, msg->offset,
                                    rd_kafka_err2name(msg->err));
                                continue;
                        }

                        if (state->explicit_ack) {
                                rd_kafka_resp_err_t ack_err =
                                    rd_kafka_share_acknowledge_type(
                                        consumer, msg,
                                        RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
                                if (ack_err != RD_KAFKA_RESP_ERR_NO_ERROR) {
                                        TEST_SAY(
                                            "Consumer thread %d: "
                                            "acknowledge offset %" PRId64
                                            " failed: %s — skipping count "
                                            "for this record\n",
                                            args->consumer_id, msg->offset,
                                            rd_kafka_err2name(ack_err));
                                        continue;
                                }
                                acked_in_batch++;
                        }

                        /* Process the record at the same instant we
                         * acknowledged it. */
                        {
                                int16_t dc =
                                    rd_kafka_message_delivery_count(msg);
                                mtx_lock(&state->lock);
                                if (dc > 1)
                                        state->total_duplicates++;
                                else
                                        state->total_first_delivery++;
                                state->total_consumed++;
                                mtx_unlock(&state->lock);
                        }
                }

                rd_kafka_messages_destroy(batch);
                batch = NULL;

                /* Flush the per-record acks to the broker before the
                 * next consume_batch or stop check. Per-partition
                 * results are inspected for errors. */
                if (state->explicit_ack && acked_in_batch > 0) {
                        rd_kafka_topic_partition_list_t *cs_result = NULL;
                        rd_kafka_error_t *commit_err =
                            rd_kafka_share_commit_sync(consumer, 5000,
                                                       &cs_result);
                        if (commit_err) {
                                TEST_SAY(
                                    "Consumer thread %d: commit_sync failed "
                                    "(acked_in_batch=%d): %s\n",
                                    args->consumer_id, acked_in_batch,
                                    rd_kafka_error_string(commit_err));
                                rd_kafka_error_destroy(commit_err);
                        } else if (cs_result) {
                                int i;
                                for (i = 0; i < cs_result->cnt; i++) {
                                        if (cs_result->elems[i].err !=
                                            RD_KAFKA_RESP_ERR_NO_ERROR) {
                                                TEST_SAY(
                                                    "Consumer thread %d: "
                                                    "commit_sync per-part "
                                                    "err %s [%" PRId32
                                                    "]: %s\n",
                                                    args->consumer_id,
                                                    cs_result->elems[i].topic,
                                                    cs_result->elems[i]
                                                        .partition,
                                                    rd_kafka_err2name(
                                                        cs_result->elems[i]
                                                            .err));
                                        }
                                }
                        }
                        if (cs_result)
                                rd_kafka_topic_partition_list_destroy(
                                    cs_result);
                }

                if (args->poll_delay_ms > 0)
                        rd_usleep(args->poll_delay_ms * 1000, NULL);
        }

        TEST_SAY("Consumer thread %d: closing\n", args->consumer_id);
        test_share_consumer_close(consumer);
        test_share_destroy(consumer);

        /* Mark this thread as cleanly exited so the main thread's bounded
         * wait can detect it without blocking in thrd_join. */
        mtx_lock(&state->lock);
        args->done = rd_true;
        mtx_unlock(&state->lock);

        return thrd_success;
}

/***************************************************************************
 * Test Runner — fully threaded
 *
 * Every share consumer and every producer runs in its own dedicated
 * thread. The main thread only orchestrates start/stop and verifies
 * final counters. No round-robin main-thread polling.
 ***************************************************************************/

/**
 * @brief Run a concurrent share consumer test with every consumer in its
 *        own thread.
 *
 * @c config->max_attempts is interpreted as an upper bound on the total
 * wait-for-completion time, measured in 500ms ticks (so max_attempts=100
 * gives a 50 s bound). When unset (0), the default is 240 ticks = 120 s.
 */
static void run_concurrent_test(const concurrent_test_config_t *config) {
        concurrent_test_state_t state = {0};
        thrd_t producer_threads[MAX_PRODUCERS];
        thrd_t consumer_threads[MAX_CONSUMERS];
        consumer_thread_args_t consumer_args[MAX_CONSUMERS];
        rd_kafka_share_t *dummy_consumer;
        int t, c, p;
        int total_partitions = 0;
        int msgs_per_producer;
        int max_wait_ticks;
        int wait_ticks;
        int final_produced;
        int final_consumed;
        int final_first_delivery;
        int final_duplicates;
        rd_bool_t final_failed;
        char unique_suffix[64];
        char unique_group[128];
        char unique_test_name[256];

        TEST_ASSERT(config->consumer_cnt <= MAX_CONSUMERS,
                    "consumer_cnt %d exceeds MAX_CONSUMERS %d",
                    config->consumer_cnt, MAX_CONSUMERS);

        /* Generate a per-invocation unique suffix and append it to both
         * the group name and the displayed test name. Avoids collisions
         * across re-runs / parallel runs that share the same broker. */
        rd_snprintf(unique_suffix, sizeof(unique_suffix), "rnd%" PRIx64,
                    test_id_generate());
        rd_snprintf(unique_group, sizeof(unique_group), "%s-%s",
                    config->group_name, unique_suffix);
        rd_snprintf(unique_test_name, sizeof(unique_test_name), "%s [%s]",
                    config->test_name, unique_suffix);

        TEST_SAY("\n");
        TEST_SAY(
            "============================================================\n");
        TEST_SAY("=== %s ===\n", unique_test_name);
        TEST_SAY(
            "============================================================\n");
        TEST_SAY(
            "Threaded: %d consumer threads, %d producer threads, %d topics\n",
            config->consumer_cnt, config->producer_cnt, config->topic_cnt);

        /* Save test context for threads (test_curr is TLS) */
        this_test = test_curr;

        /* Set the DR-callback expectations on the shared test struct
         * ONCE on the main thread, before spawning any worker threads.
         * test_curr is a TLS pointer but the struct it points at lives
         * in the global tests[] array, so writing these fields from
         * each producer thread (as it used to) is a benign-but-noisy
         * data race that TSAN flags. */
        test_curr->exp_dr_status = (rd_kafka_msg_status_t)-1;
        test_curr->ignore_dr_err = rd_true;

        /* Initialize state */
        mtx_init(&state.lock, mtx_plain);
        state.topic_cnt           = config->topic_cnt;
        state.group_name          = unique_group;
        state.explicit_ack        = config->explicit_ack;
        state.producers_remaining = config->producer_cnt;

        for (t = 0; t < config->topic_cnt; t++)
                total_partitions += config->partitions[t];
        state.expected_total = total_partitions * config->msgs_per_partition;
        TEST_SAY(
            "Total partitions: %d, msgs/partition: %d, expected total: %d\n",
            total_partitions, config->msgs_per_partition, state.expected_total);

        /* Create topics */
        for (t = 0; t < config->topic_cnt; t++) {
                rd_snprintf(state.topics[t], sizeof(state.topics[t]), "%s",
                            test_mk_topic_name("0174-concurrent", 1));
                test_create_topic_wait_exists(NULL, state.topics[t],
                                              config->partitions[t], -1,
                                              60 * 1000);
                TEST_SAY("Created topic %s with %d partitions\n",
                         state.topics[t], config->partitions[t]);
        }

        /* Apply broker-side share group config (auto.offset.reset=earliest)
         * via a throwaway consumer registration so the alter sticks before
         * any worker subscribes. */
        dummy_consumer = test_create_share_consumer(unique_group, NULL);
        test_share_set_auto_offset_reset(unique_group, "earliest");
        test_share_consumer_close(dummy_consumer);
        test_share_destroy(dummy_consumer);

        /* Start producer threads */
        msgs_per_producer = state.expected_total / config->producer_cnt;
        for (p = 0; p < config->producer_cnt; p++) {
                producer_thread_args_t *args = rd_calloc(1, sizeof(*args));
                args->state                  = &state;
                args->producer_id            = p;
                args->msgs_to_produce        = msgs_per_producer;
                if (p == config->producer_cnt - 1)
                        args->msgs_to_produce +=
                            state.expected_total % config->producer_cnt;
                args->delay_ms = config->producer_delay_ms;
                for (t = 0; t < config->topic_cnt; t++)
                        args->partitions[t] = config->partitions[t];

                if (thrd_create(&producer_threads[p], producer_thread_func,
                                args) != thrd_success) {
                        TEST_FAIL("Failed to create producer thread %d", p);
                }
        }

        /* Optional staggered start: give producers a head start before
         * spinning up consumer threads. */
        if (config->staggered_start) {
                TEST_SAY("Staggered start: producers run alone for 2 s\n");
                rd_sleep(2);
        }

        /* Start consumer threads — one per consumer */
        for (c = 0; c < config->consumer_cnt; c++) {
                consumer_args[c].state         = &state;
                consumer_args[c].consumer_id   = c;
                consumer_args[c].run           = rd_true;
                consumer_args[c].done          = rd_false;
                consumer_args[c].poll_delay_ms = config->consumer_delay_ms;

                if (thrd_create(&consumer_threads[c], consumer_thread_func,
                                &consumer_args[c]) != thrd_success) {
                        TEST_FAIL("Failed to create consumer thread %d", c);
                }
        }

        /* Wait for all expected first deliveries, bounded by max_attempts
         * ticks of 500ms each (default 240 ticks = 120 s). */
        max_wait_ticks = config->max_attempts > 0 ? config->max_attempts : 240;
        wait_ticks     = max_wait_ticks;

        while (wait_ticks-- > 0) {
                int first_seen;
                int consumed_so_far;
                int dups;
                rd_bool_t producers_done;

                mtx_lock(&state.lock);
                first_seen      = state.total_first_delivery;
                consumed_so_far = state.total_consumed;
                dups            = state.total_duplicates;
                producers_done  = state.producers_done;
                mtx_unlock(&state.lock);

                if (first_seen >= state.expected_total)
                        break;

                if (wait_ticks % 20 == 0)
                        TEST_SAY(
                            "Progress: consumed %d/%d (first=%d, dup=%d, "
                            "producers_done=%d)\n",
                            consumed_so_far, state.expected_total, first_seen,
                            dups, (int)producers_done);

                rd_usleep(500 * 1000, NULL);
        }

        /* Join producers even if drain timed out. */
        for (p = 0; p < config->producer_cnt; p++)
                thrd_join(producer_threads[p], NULL);

        /* Tell consumer threads to stop and join. */
        mtx_lock(&state.lock);
        for (c = 0; c < config->consumer_cnt; c++)
                consumer_args[c].run = rd_false;
        mtx_unlock(&state.lock);

        for (c = 0; c < config->consumer_cnt; c++)
                thrd_join(consumer_threads[c], NULL);

        /* Snapshot results under lock */
        mtx_lock(&state.lock);
        final_produced       = state.total_produced;
        final_consumed       = state.total_consumed;
        final_first_delivery = state.total_first_delivery;
        final_duplicates     = state.total_duplicates;
        final_failed         = state.test_failed;
        mtx_unlock(&state.lock);

        TEST_SAY(
            "Final: produced=%d, consumed=%d (first=%d, dup=%d), "
            "expected=%d\n",
            final_produced, final_consumed, final_first_delivery,
            final_duplicates, state.expected_total);

        TEST_ASSERT(final_produced == state.expected_total,
                    "Expected to produce %d, actually produced %d",
                    state.expected_total, final_produced);

        /* A record can be redelivered if the broker-side acquisition lock
         * expires before an ACCEPT arrives. We distinguish first
         * deliveries (delivery_count == 1) from redeliveries via
         * rd_kafka_message_delivery_count() and assert strict equality on
         * first deliveries — every produced record must have been
         * delivered at least once. Duplicates are tracked separately so a
         * regression in delivery semantics still shows up in the
         * diagnostic output. */
        TEST_ASSERT(final_first_delivery == state.expected_total,
                    "Expected %d first-time deliveries, got %d "
                    "(consumed=%d, duplicates=%d)",
                    state.expected_total, final_first_delivery, final_consumed,
                    final_duplicates);
        TEST_ASSERT(!final_failed, "Producer thread reported failure");

        TEST_SAY("SUCCESS: %s\n", unique_test_name);

        mtx_destroy(&state.lock);
}

/***************************************************************************
 * Test Cases - Basic Concurrency
 ***************************************************************************/

/**
 * @brief Single producer, single consumer, single topic
 */
static void do_test_1p_1c_1t_1part(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 1,
            .producer_cnt       = 1,
            .topic_cnt          = 1,
            .partitions         = {1},
            .msgs_per_partition = 5000,
            .group_name         = "share-conc-1p1c1t1p",
            .test_name = "1 producer, 1 consumer, 1 topic, 1 partition"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Single producer, multiple consumers, single topic
 */
static void do_test_1p_4c_1t_4part(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 4,
            .producer_cnt       = 1,
            .topic_cnt          = 1,
            .partitions         = {4},
            .msgs_per_partition = 5000,
            .group_name         = "share-conc-1p4c1t4p",
            .test_name = "1 producer, 4 consumers, 1 topic, 4 partitions"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Multiple producers, single consumer
 */
static void do_test_4p_1c_1t_4part(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 1,
            .producer_cnt       = 4,
            .topic_cnt          = 1,
            .partitions         = {4},
            .msgs_per_partition = 1250,
            .group_name         = "share-conc-4p1c1t4p",
            .test_name = "4 producers, 1 consumer, 1 topic, 4 partitions"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Multiple producers, multiple consumers, single topic
 */
static void do_test_4p_4c_1t_4part(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 4,
            .producer_cnt       = 4,
            .topic_cnt          = 1,
            .partitions         = {4},
            .msgs_per_partition = 5000,
            .group_name         = "share-conc-4p4c1t4p",
            .test_name = "4 producers, 4 consumers, 1 topic, 4 partitions"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/***************************************************************************
 * Test Cases - Multi-Topic Concurrency
 ***************************************************************************/

/**
 * @brief Multiple topics with concurrent access
 */
static void do_test_2p_2c_3t_2part(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 2,
            .producer_cnt       = 2,
            .topic_cnt          = 3,
            .partitions         = {2, 2, 2},
            .msgs_per_partition = 1666,
            .group_name         = "share-conc-2p2c3t2p",
            .test_name =
                "2 producers, 2 consumers, 3 topics, 2 partitions each"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Many topics with single partition each
 */
static void do_test_2p_2c_8t_1part(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 2,
            .producer_cnt       = 2,
            .topic_cnt          = 8,
            .partitions         = {1, 1, 1, 1, 1, 1, 1, 1},
            .msgs_per_partition = 1250,
            .group_name         = "share-conc-2p2c8t1p",
            .test_name = "2 producers, 2 consumers, 8 topics, 1 partition each",
            .max_attempts = 150};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/***************************************************************************
 * Test Cases - High Contention
 ***************************************************************************/

/**
 * @brief Many consumers competing for single partition
 */
static void do_test_1p_8c_1t_1part(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 8,
            .producer_cnt       = 1,
            .topic_cnt          = 1,
            .partitions         = {1},
            .msgs_per_partition = 10000,
            .group_name         = "share-conc-1p8c1t1p",
            .test_name =
                "1 producer, 8 consumers, 1 partition (high contention)"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief More consumers than partitions
 */
static void do_test_2p_6c_1t_2part(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 6,
            .producer_cnt       = 2,
            .topic_cnt          = 1,
            .partitions         = {2},
            .msgs_per_partition = 15000,
            .group_name         = "share-conc-2p6c1t2p",
            .test_name =
                "2 producers, 6 consumers, 2 partitions (3:1 consumer ratio)"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/***************************************************************************
 * Test Cases - Explicit Acknowledgement
 ***************************************************************************/

/**
 * @brief Concurrent with explicit acknowledgement
 */
static void do_test_explicit_ack_4p_4c(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 4,
            .producer_cnt       = 4,
            .topic_cnt          = 2,
            .partitions         = {2, 2},
            .msgs_per_partition = 5000,
            .group_name         = "share-conc-explicit-4p4c",
            .test_name          = "4 producers, 4 consumers, explicit ack",
            .explicit_ack       = rd_true};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/***************************************************************************
 * Test Cases - Staggered Start
 ***************************************************************************/

/**
 * @brief Consumers start before producers
 */
static void do_test_staggered_start(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 2,
            .producer_cnt       = 2,
            .topic_cnt          = 1,
            .partitions         = {2},
            .msgs_per_partition = 5000,
            .group_name         = "share-conc-staggered",
            .test_name          = "Staggered start: consumers before producers",
            .staggered_start    = rd_true};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/***************************************************************************
 * Test Cases - High Volume Stress
 ***************************************************************************/

/**
 * @brief High volume concurrent test
 */
static void do_test_high_volume_20k(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 4,
            .producer_cnt       = 4,
            .topic_cnt          = 1,
            .partitions         = {4},
            .msgs_per_partition = 5000,
            .group_name         = "share-conc-highvol-20k",
            .test_name          = "High volume: 4p x 4c x 20k messages",
            .max_attempts       = 150};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief High volume with many partitions
 */
static void do_test_high_volume_many_partitions(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 4,
            .producer_cnt       = 4,
            .topic_cnt          = 1,
            .partitions         = {8},
            .msgs_per_partition = 2500,
            .group_name         = "share-conc-highvol-8p",
            .test_name    = "High volume: 8 partitions x 2.5k messages each",
            .max_attempts = 150};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/***************************************************************************
 * Test Cases - Asymmetric Configurations
 ***************************************************************************/

/**
 * @brief Many producers, few consumers
 */
static void do_test_8p_2c(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 2,
            .producer_cnt       = 8,
            .topic_cnt          = 1,
            .partitions         = {4},
            .msgs_per_partition = 2500,
            .group_name         = "share-conc-8p2c",
            .test_name          = "8 producers, 2 consumers (producer heavy)"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Few producers, many consumers
 */
static void do_test_2p_8c(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 8,
            .producer_cnt       = 2,
            .topic_cnt          = 1,
            .partitions         = {4},
            .msgs_per_partition = 10000,
            .group_name         = "share-conc-2p8c",
            .test_name          = "2 producers, 8 consumers (consumer heavy)"};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/***************************************************************************
 * Test Cases - Complex Multi-Topic Multi-Partition
 ***************************************************************************/

/**
 * @brief Complex scenario with varied partition counts
 */
static void do_test_complex_varied_partitions(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 4,
            .producer_cnt       = 4,
            .topic_cnt          = 4,
            .partitions         = {1, 2, 3, 4},
            .msgs_per_partition = 2000,
            .group_name         = "share-conc-complex-varied",
            .test_name    = "4 topics with 1,2,3,4 partitions respectively",
            .max_attempts = 150};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Maximum concurrent scenario
 */
static void do_test_max_concurrent(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = MAX_CONSUMERS,
            .producer_cnt       = MAX_PRODUCERS,
            .topic_cnt          = 4,
            .partitions         = {4, 4, 4, 4},
            .msgs_per_partition = 3125,
            .group_name         = "share-conc-max",
            .test_name    = "Maximum: 10 producers, 10 consumers, 4 topics",
            .max_attempts = 200};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/***************************************************************************
 * Test Cases - Slow Consumer/Producer Scenarios
 ***************************************************************************/

/**
 * @brief Slow consumers with fast producers
 */
static void do_test_slow_consumers(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 2,
            .producer_cnt       = 4,
            .topic_cnt          = 1,
            .partitions         = {2},
            .msgs_per_partition = 5000,
            .group_name         = "share-conc-slow-consumer",
            .test_name          = "Fast producers, slow consumers",
            .consumer_delay_ms  = 50,
            .max_attempts       = 200};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Fast consumers with slow producers
 */
static void do_test_slow_producers(void) {
        concurrent_test_config_t config = {
            .consumer_cnt       = 4,
            .producer_cnt       = 2,
            .topic_cnt          = 1,
            .partitions         = {2},
            .msgs_per_partition = 500,
            .group_name         = "share-conc-slow-producer",
            .test_name          = "Slow producers, fast consumers",
            .producer_delay_ms  = 10000,
            .max_attempts       = 200};

        SUB_TEST();
        run_concurrent_test(&config);

        SUB_TEST_PASS();
}

/**
 * @brief Chaos test: consumer churn during sustained production.
 *
 * Setup:
 *  - 4 producers in dedicated threads producing fixed total messages.
 *  - Pool of CONSUMER_POOL slots; only ACTIVE_CONSUMERS run concurrently.
 *  - Initially start ACTIVE_CONSUMERS threads.
 *  - For ITERATIONS rounds: sleep ITERATION_MS, then stop a random number
 *    of the currently running consumers (>= 1) and start the same number
 *    of fresh ones from the pool. Old threads are joined at the very end.
 *  - After iterations, drain remaining messages and shut everyone down.
 *
 * Invariant for share consumers: every produced record is first-delivered
 * exactly once. Records that a closing consumer hadn't acked are released
 * back to the group and re-delivered with delivery_count > 1 (counted as
 * duplicates, not first deliveries).
 */
static void do_test_chaos_consumer_lifecycle(rd_bool_t explicit_ack) {
        concurrent_test_state_t state         = {0};
        const concurrent_test_config_t config = {
            .consumer_cnt       = 4, /* informational; pool size below */
            .producer_cnt       = 4,
            .topic_cnt          = 1,
            .partitions         = {4},
            .msgs_per_partition = 1000,
            .group_name   = explicit_ack ? "share-chaos-lifecycle-explicit"
                                         : "share-chaos-lifecycle-implicit",
            .test_name    = explicit_ack ? "Chaos (explicit ack): consumer "
                                           "churn during production"
                                         : "Chaos (implicit ack): consumer "
                                           "churn during production",
            .explicit_ack = explicit_ack};
        const int ACTIVE_CONSUMERS = 4;
        const int CONSUMER_POOL    = 12;
        const int ITERATIONS       = 3;
        const int ITERATION_MS     = 6000;
        const int join_poll_ticks  = 10; /* 10 * 500ms = 5 s */
        thrd_t producer_threads[MAX_PRODUCERS];
        thrd_t consumer_threads[MAX_CONSUMER_POOL];
        consumer_thread_args_t consumer_args[MAX_CONSUMER_POOL];
        int started_threads = 0;
        int first_running   = 0;
        int last_running;
        int t, c, p, iter;
        int total_partitions = 0;
        int msgs_per_producer;
        int wait_attempts;
        int dangling = 0;
        int final_produced;
        int final_first_delivery;
        int final_duplicates;
        int final_consumed;
        rd_bool_t final_failed;
        rd_kafka_share_t *dummy_consumer;

        SUB_TEST();

        TEST_ASSERT(CONSUMER_POOL <= MAX_CONSUMER_POOL,
                    "CONSUMER_POOL %d > MAX_CONSUMER_POOL", CONSUMER_POOL);
        TEST_ASSERT(ACTIVE_CONSUMERS <= CONSUMER_POOL, "ACTIVE > POOL");

        TEST_SAY("\n");
        TEST_SAY(
            "============================================================\n");
        TEST_SAY("=== %s ===\n", config.test_name);
        TEST_SAY(
            "============================================================\n");
        TEST_SAY("Active %d, pool %d, iterations %d × %d ms\n",
                 ACTIVE_CONSUMERS, CONSUMER_POOL, ITERATIONS, ITERATION_MS);

        this_test = test_curr;

        /* See note in run_concurrent_test: set these on the main thread
         * before spawning worker threads to avoid TSAN-flagged races on
         * the shared test struct that test_curr aliases. */
        test_curr->exp_dr_status = (rd_kafka_msg_status_t)-1;
        test_curr->ignore_dr_err = rd_true;

        mtx_init(&state.lock, mtx_plain);
        state.topic_cnt           = config.topic_cnt;
        state.group_name          = config.group_name;
        state.explicit_ack        = config.explicit_ack;
        state.producers_remaining = config.producer_cnt;

        for (t = 0; t < config.topic_cnt; t++)
                total_partitions += config.partitions[t];
        state.expected_total = total_partitions * config.msgs_per_partition;
        TEST_SAY("Expected messages: %d\n", state.expected_total);

        for (t = 0; t < config.topic_cnt; t++) {
                rd_snprintf(state.topics[t], sizeof(state.topics[t]), "%s",
                            test_mk_topic_name("0174-chaos", 1));
                test_create_topic_wait_exists(
                    NULL, state.topics[t], config.partitions[t], -1, 60 * 1000);
        }

        /* Apply broker-side group config (auto.offset.reset=earliest) via
         * a throwaway consumer registration, so the alter sticks before
         * any chaos worker subscribes. */
        dummy_consumer = test_create_share_consumer(config.group_name, NULL);
        test_share_set_auto_offset_reset(config.group_name, "earliest");
        test_share_consumer_close(dummy_consumer);
        test_share_destroy(dummy_consumer);

        /* Producer threads */
        msgs_per_producer = state.expected_total / config.producer_cnt;
        for (p = 0; p < config.producer_cnt; p++) {
                producer_thread_args_t *args = rd_calloc(1, sizeof(*args));
                args->state                  = &state;
                args->producer_id            = p;
                args->msgs_to_produce        = msgs_per_producer;
                if (p == config.producer_cnt - 1)
                        args->msgs_to_produce +=
                            state.expected_total % config.producer_cnt;
                /* Light pacing so production stretches across the chaos
                 * iterations rather than finishing before the first churn. */
                args->delay_ms = 5;
                for (t = 0; t < config.topic_cnt; t++)
                        args->partitions[t] = config.partitions[t];

                if (thrd_create(&producer_threads[p], producer_thread_func,
                                args) != thrd_success) {
                        TEST_FAIL("Failed to create producer thread %d", p);
                }
        }

        /* Pre-init the entire pool */
        for (c = 0; c < CONSUMER_POOL; c++) {
                consumer_args[c].state         = &state;
                consumer_args[c].consumer_id   = c;
                consumer_args[c].run           = rd_false;
                consumer_args[c].done          = rd_false;
                consumer_args[c].poll_delay_ms = 0;
        }

        /* Start the initial active set */
        for (c = 0; c < ACTIVE_CONSUMERS; c++) {
                mtx_lock(&state.lock);
                consumer_args[c].run = rd_true;
                mtx_unlock(&state.lock);
                if (thrd_create(&consumer_threads[c], consumer_thread_func,
                                &consumer_args[c]) != thrd_success) {
                        TEST_FAIL(
                            "Failed to create initial consumer "
                            "thread %d",
                            c);
                }
                started_threads++;
        }
        last_running = ACTIVE_CONSUMERS - 1;

        srand((unsigned int)time(NULL));

        for (iter = 0; iter < ITERATIONS; iter++) {
                int running;
                int churn;
                int can_start;
                int s;

                TEST_SAY("--- Iteration %d/%d: sleeping %d ms ---\n", iter + 1,
                         ITERATIONS, ITERATION_MS);
                rd_usleep(ITERATION_MS * 1000, NULL);

                running = last_running - first_running + 1;
                /* Stop at least 1, at most floor(running/2) for stability */
                churn = (running > 1) ? (rand() % ((running / 2) + 1) + 1) : 1;
                TEST_SAY("Iteration %d: stopping %d/%d running consumers\n",
                         iter + 1, churn, running);

                mtx_lock(&state.lock);
                for (s = 0; s < churn && first_running <= last_running;
                     s++, first_running++) {
                        consumer_args[first_running].run = rd_false;
                }
                mtx_unlock(&state.lock);

                /* Replenish with new pool slots (don't reuse stopped slots) */
                can_start = CONSUMER_POOL - started_threads;
                if (can_start <= 0) {
                        TEST_SAY(
                            "Pool exhausted (%d threads spawned); no more "
                            "starts this iteration\n",
                            started_threads);
                        continue;
                }
                if (churn > can_start)
                        churn = can_start;

                TEST_SAY("Iteration %d: starting %d fresh consumers\n",
                         iter + 1, churn);

                for (s = 0; s < churn; s++) {
                        int idx = started_threads;
                        if (idx >= CONSUMER_POOL)
                                break;
                        mtx_lock(&state.lock);
                        consumer_args[idx].run = rd_true;
                        mtx_unlock(&state.lock);
                        if (thrd_create(&consumer_threads[idx],
                                        consumer_thread_func,
                                        &consumer_args[idx]) != thrd_success) {
                                TEST_FAIL(
                                    "Failed to create chaos consumer "
                                    "thread %d",
                                    idx);
                        }
                        started_threads++;
                        last_running = idx;
                }
        }

        TEST_SAY(
            "Iterations done; waiting for production to drain, then "
            "shutting down consumers\n");

        /* Drain loop, bounded so we don't sit for minutes on a stuck
         * test:
         *   - 60 ticks of 500 ms = 30 s absolute cap
         *   - early exit when producers_done AND first_delivery has not
         *     advanced for 10 consecutive ticks (~5 s of no progress).
         *     If the chaos test has stalled, we report and move on
         *     rather than waiting for the full window. */
        wait_attempts         = 60; /* ~30 seconds absolute cap */
        int prev_first_seen   = -1;
        int stale_ticks       = 0;
        const int stale_limit = 10; /* ~5 s with no progress */

        while (wait_attempts-- > 0) {
                int first_seen;
                rd_bool_t producers_done;

                mtx_lock(&state.lock);
                first_seen     = state.total_first_delivery;
                producers_done = state.producers_done;
                mtx_unlock(&state.lock);

                if (producers_done && first_seen >= state.expected_total)
                        break;

                if (first_seen == prev_first_seen) {
                        stale_ticks++;
                        if (producers_done && stale_ticks >= stale_limit) {
                                TEST_SAY(
                                    "Drain: no progress for "
                                    "~%d s after producers done; "
                                    "exiting at %d/%d "
                                    "(test will fail in assertion)\n",
                                    stale_ticks / 2, first_seen,
                                    state.expected_total);
                                break;
                        }
                } else {
                        stale_ticks     = 0;
                        prev_first_seen = first_seen;
                }

                if (wait_attempts % 10 == 0)
                        TEST_SAY(
                            "Drain: %d/%d first deliveries "
                            "(producers_done=%d)\n",
                            first_seen, state.expected_total,
                            (int)producers_done);

                rd_usleep(500 * 1000, NULL);
        }

        /* Join producers - these always exit cleanly so a hard join is
         * safe. */
        for (p = 0; p < config.producer_cnt; p++)
                thrd_join(producer_threads[p], NULL);

        /* Stop all consumer threads. */
        mtx_lock(&state.lock);
        for (c = 0; c < started_threads; c++)
                consumer_args[c].run = rd_false;
        mtx_unlock(&state.lock);

        /* Bounded wait for consumers to exit cleanly. A wedged consumer
         * (eg blocked inside consume_batch waiting on a stale share
         * session) won't return from rd_kafka_share_consumer_close, so
         * thrd_join would block indefinitely. We poll each consumer's
         * done flag for up to ~5 s; any thread that hasn't set it by
         * then is left dangling for the OS to reclaim at process exit
         * and we move straight to the assertions. This matters only
         * when the test is failing — once the underlying librdkafka
         * issue is fixed, every consumer thread reaches its `done = true`
         * within tens of milliseconds. */
        for (c = 0; c < started_threads; c++) {
                rd_bool_t done = rd_false;
                for (t = 0; t < join_poll_ticks; t++) {
                        mtx_lock(&state.lock);
                        done = consumer_args[c].done;
                        mtx_unlock(&state.lock);
                        if (done)
                                break;
                        rd_usleep(500 * 1000, NULL);
                }
                if (done) {
                        thrd_join(consumer_threads[c], NULL);
                } else {
                        /* Detach so the C runtime won't leak the
                         * thrd_t handle when the process exits;
                         * the OS will tear down the still-running
                         * thread when the process terminates. */
                        thrd_detach(consumer_threads[c]);
                        dangling++;
                        TEST_SAY(
                            "Consumer thread %d: did not exit within "
                            "5 s of stop signal — detaching and "
                            "proceeding (likely wedged inside "
                            "librdkafka close path)\n",
                            consumer_args[c].consumer_id);
                }
        }

        if (dangling > 0)
                TEST_SAY(
                    "WARNING: %d/%d consumer thread(s) left "
                    "dangling at test exit\n",
                    dangling, started_threads);

        mtx_lock(&state.lock);
        final_produced       = state.total_produced;
        final_first_delivery = state.total_first_delivery;
        final_duplicates     = state.total_duplicates;
        final_consumed       = state.total_consumed;
        final_failed         = state.test_failed;
        mtx_unlock(&state.lock);

        TEST_SAY(
            "Chaos final: produced=%d, consumed=%d (first=%d, dup=%d), "
            "expected=%d, threads spawned=%d\n",
            final_produced, final_consumed, final_first_delivery,
            final_duplicates, state.expected_total, started_threads);

        TEST_ASSERT(final_produced == state.expected_total,
                    "Expected to produce %d, actually produced %d",
                    state.expected_total, final_produced);
        TEST_ASSERT(final_first_delivery == state.expected_total,
                    "Expected %d first-time deliveries, got %d "
                    "(consumed=%d, duplicates=%d)",
                    state.expected_total, final_first_delivery, final_consumed,
                    final_duplicates);
        TEST_ASSERT(!final_failed, "Producer thread reported failure");
        TEST_SAY(
            "SUCCESS: chaos test - %d threads churned, "
            "every record first-delivered exactly once\n",
            started_threads);

        mtx_destroy(&state.lock);

        SUB_TEST_PASS();
}


/***************************************************************************
 * Main Entry Point
 ***************************************************************************/

int main_0174_share_consumer_concurrency(int argc, char **argv) {

        test_timeout_set(1500);

        /* Every test below runs producers AND consumers in dedicated
         * threads via run_concurrent_test(). There is no main-thread
         * polling — consumer_thread_func handles the poll loop per
         * consumer. */

        /* Basic concurrency tests */
        do_test_1p_1c_1t_1part(); /* Baseline: 1 producer, 1 consumer */
        do_test_1p_4c_1t_4part(); /* Fan out: 1 producer, 4 consumers */
        do_test_4p_1c_1t_4part(); /* Fan in: 4 producers, 1 consumer */
        do_test_4p_4c_1t_4part(); /* Symmetric: 4 producers, 4 consumers */

        /* Multi-topic tests */
        do_test_2p_2c_3t_2part(); /* Multiple topics */
        do_test_2p_2c_8t_1part(); /* Many topics */

        /* High contention tests */
        do_test_1p_8c_1t_1part(); /* Many consumers, 1 partition */
        do_test_2p_6c_1t_2part(); /* More consumers than partitions */

        /* Explicit acknowledgement */
        do_test_explicit_ack_4p_4c();

        /* Staggered start */
        do_test_staggered_start();

        /* High volume stress tests */
        do_test_high_volume_20k();
        do_test_high_volume_many_partitions();

        /* Asymmetric configurations */
        do_test_8p_2c(); /* Producer heavy */
        do_test_2p_8c(); /* Consumer heavy */

        /* Complex scenarios */
        do_test_complex_varied_partitions();
        do_test_max_concurrent();

        /* Slow consumer/producer scenarios */
        do_test_slow_consumers();
        do_test_slow_producers();

        /* Chaos test: consumer lifecycle churn during sustained production.
         * Run once with explicit acknowledgement and once with implicit
         * acknowledgement to cover both ack flows under churn. */
        do_test_chaos_consumer_lifecycle(rd_true);
        do_test_chaos_consumer_lifecycle(rd_false);

        return 0;
}
