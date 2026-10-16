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
 * @name Share consumer max.poll.interval.ms enforcement (KIP-932).
 *
 * Recreates, for the share consumer, the applicable cases from
 * 0089-max_poll_interval.c and 0091-max_poll_interval_timeout.c:
 *
 *  - A share consumer that stops calling rd_kafka_share_poll() for
 *    longer than max.poll.interval.ms is considered failed, leaves the share
 *    group, and surfaces RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED — even if it
 *    never polled once.
 *  - The interval is reset only by rd_kafka_share_poll(); other calls
 *    (rd_kafka_poll(), polling the log queue) do not reset it.
 *  - A blocking rd_kafka_share_poll() that waits longer than
 *    max.poll.interval.ms is not counted against the interval.
 *  - Steady consumption within the interval never triggers the timeout.
 *  - After a timeout the consumer rejoins on the next batch poll.
 *  - A second consumer keeps consuming while the first is evicted.
 *
 */

/* Longer interval for the real-broker tests (matches 0089/0091), giving the
 * group join/assignment enough headroom not to falsely trip. */
#define REAL_MAX_POLL_INTERVAL_MS 10000


/**
 * @brief Create a share consumer with the given max.poll.interval.ms.
 *
 * @param bootstraps  Mock bootstrap servers, or NULL to use the test.conf
 *                    (real broker) default.
 */
static rd_kafka_share_t *create_share_consumer(const char *bootstraps,
                                               const char *group_id,
                                               int max_poll_interval_ms) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        char errstr[512];
        char tmp[32];

        test_conf_init(&conf, NULL, 0);
        if (bootstraps)
                test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", group_id);
        rd_snprintf(tmp, sizeof(tmp), "%d", max_poll_interval_ms);
        test_conf_set(conf, "max.poll.interval.ms", tmp);

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare != NULL, "Failed to create share consumer: %s",
                    errstr);

        return rkshare;
}


/**
 * @brief Consume one batch.
 *
 * @param max_poll_exceeded  If non-NULL, set to rd_true if the batch returned
 *                           RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED.
 * @returns the number of valid (non-error) messages received.
 */
static int share_consume_once(rd_kafka_share_t *rkshare,
                              int timeout_ms,
                              rd_bool_t *max_poll_exceeded) {
        rd_kafka_messages_t *batch = NULL;
        size_t rcvd                = 0;
        size_t i;
        int valid = 0;
        rd_kafka_error_t *error;

        if (max_poll_exceeded)
                *max_poll_exceeded = rd_false;

        error = rd_kafka_share_poll(rkshare, timeout_ms, &batch);
        if (error) {
                if (max_poll_exceeded &&
                    rd_kafka_error_code(error) ==
                        RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED)
                        *max_poll_exceeded = rd_true;
                rd_kafka_error_destroy(error);
                return 0;
        }

        rcvd = rd_kafka_messages_count(batch);
        for (i = 0; i < rcvd; i++) {
                rd_kafka_message_t *msg = rd_kafka_messages_get(batch, i);
                if (!msg->err)
                        valid++;
        }
        rd_kafka_messages_destroy(batch);
        batch = NULL;

        return valid;
}


/**
 * @brief Consume batches until at least one message is received, establishing
 *        share-group membership and a steady assignment. Fails if no message
 *        arrives in time.
 */
static void establish_membership(rd_kafka_share_t *rkshare) {
        int attempts;

        for (attempts = 0; attempts < 30; attempts++) {
                if (share_consume_once(rkshare, 1000, NULL) > 0) {
                        TEST_SAY(
                            "Membership established (consumed a message)\n");
                        return;
                }
        }

        TEST_FAIL("Failed to consume any message to establish membership");
}


/**
 * @brief Poll batches until RD_KAFKA_RESP_ERR__MAX_POLL_EXCEEDED is observed
 *        or @p timeout_ms elapses.
 *
 * @returns rd_true if the error was observed.
 */
static rd_bool_t wait_max_poll_exceeded(rd_kafka_share_t *rkshare,
                                        int timeout_ms) {
        int64_t deadline = test_clock() + (int64_t)timeout_ms * 1000;

        while (test_clock() < deadline) {
                rd_bool_t exceeded = rd_false;
                share_consume_once(rkshare, 500, &exceeded);
                if (exceeded)
                        return rd_true;
        }

        return rd_false;
}


/**
 * @brief Real-broker setup: create a single-partition topic, produce @p msgcnt
 *        messages, set the share group's offset reset to earliest, then create
 *        a subscribed share consumer with the given max.poll.interval.ms.
 *
 * @param topic  Output buffer for the generated topic name.
 */
static rd_kafka_share_t *
real_setup(char *topic, size_t topic_sz, int msgcnt, int max_poll_interval_ms) {
        char group[64];
        uint64_t testid = test_id_generate();
        rd_kafka_share_t *c;

        rd_snprintf(topic, topic_sz, "%s",
                    test_mk_topic_name("0185_share_max_poll", 1));
        test_str_id_generate(group, sizeof(group));

        test_create_topic_wait_exists(NULL, topic, 1, -1, 5000);
        if (msgcnt > 0)
                test_produce_msgs_easy(topic, testid, 0, msgcnt);
        test_share_set_auto_offset_reset(group, "earliest");

        c = create_share_consumer(NULL, group, max_poll_interval_ms);
        test_share_consumer_subscribe_multi(c, 1, topic);

        return c;
}


/*
 * ===========================================================================
 *  Real broker tests
 * ===========================================================================
 */

/**
 * @brief Long "processing" (no polling) past max.poll.interval.ms must evict
 *        the consumer with MAX_POLL_EXCEEDED, after which it can rejoin.
 *
 * Mirrors 0089 do_test() + do_test_rejoin_after_interval_expire().
 */
static void do_test_long_processing(void) {
        char topic[128];
        rd_kafka_share_t *c;
        int consumed = 0;
        int attempts;

        SUB_TEST();

        c = real_setup(topic, sizeof(topic), 20, REAL_MAX_POLL_INTERVAL_MS);
        establish_membership(c);

        TEST_SAY(
            "Simulating long processing: sleeping %ds "
            "(> max.poll.interval.ms=%dms)\n",
            (REAL_MAX_POLL_INTERVAL_MS + 3000) / 1000,
            REAL_MAX_POLL_INTERVAL_MS);
        rd_sleep((REAL_MAX_POLL_INTERVAL_MS + 3000) / 1000);

        TEST_ASSERT(wait_max_poll_exceeded(c, 10000),
                    "Expected MAX_POLL_EXCEEDED after long processing");

        /* The records consumed before the stall are implicitly acknowledged
         * while detecting the timeout (implicit ack is sent at the start of
         * the consume_batch() that returns the error), so the share-partition
         * start offset has advanced past them. Produce fresh records and
         * verify the consumer rejoins and resumes consuming. */
        test_produce_msgs_easy(topic, test_id_generate(), 0, 20);

        for (attempts = 0; attempts < 30 && consumed == 0; attempts++)
                consumed += share_consume_once(c, 1000, NULL);

        TEST_ASSERT(consumed > 0,
                    "Consumer did not rejoin after max.poll.interval.ms");

        test_share_consumer_close(c);
        test_share_destroy(c);

        SUB_TEST_PASS();
}


/**
 * @brief A share consumer that subscribes but NEVER calls consume_batch must
 *        still be evicted with MAX_POLL_EXCEEDED once the interval elapses.
 *
 * Mirrors 0091 do_test_no_poll().
 */
static void do_test_no_poll(void) {
        char topic[128];
        rd_kafka_share_t *c;

        SUB_TEST();

        c = real_setup(topic, sizeof(topic), 20, REAL_MAX_POLL_INTERVAL_MS);

        /* Do NOT consume at all: the background heartbeat joins the group and
         * receives an assignment, which starts the timer; rk_ts_last_poll
         * stays at its initial value, so the interval elapses with no poll. */
        TEST_SAY("Subscribed but never polling; sleeping %ds (> %dms)\n",
                 (REAL_MAX_POLL_INTERVAL_MS + 3000) / 1000,
                 REAL_MAX_POLL_INTERVAL_MS);
        rd_sleep((REAL_MAX_POLL_INTERVAL_MS + 3000) / 1000);

        TEST_ASSERT(
            wait_max_poll_exceeded(c, 10000),
            "Expected MAX_POLL_EXCEEDED even though consume_batch() was "
            "never called before the stall");

        test_share_consumer_close(c);
        test_share_destroy(c);

        SUB_TEST_PASS();
}


/**
 * @brief Steady consumption with per-batch processing below
 *        max.poll.interval.ms must not evict the consumer.
 *
 * Mirrors 0091 do_test_with_subscribe().
 */
static void do_test_steady_consume(void) {
        char topic[128];
        rd_kafka_share_t *c;
        const int msgcnt = 30;
        int consumed     = 0;
        int64_t deadline;

        SUB_TEST();

        c = real_setup(topic, sizeof(topic), msgcnt, REAL_MAX_POLL_INTERVAL_MS);

        /* Consume over a span longer than max.poll.interval.ms, with a short
         * "processing" sleep between polls (all under the interval). */
        deadline =
            test_clock() + (int64_t)(REAL_MAX_POLL_INTERVAL_MS + 5000) * 1000;
        while (consumed < msgcnt && test_clock() < deadline) {
                rd_bool_t exceeded = rd_false;
                consumed += share_consume_once(c, 2000, &exceeded);
                TEST_ASSERT(!exceeded,
                            "Steady consumption must not trip "
                            "max.poll.interval.ms (consumed %d/%d)",
                            consumed, msgcnt);
                rd_sleep(1);
        }

        TEST_ASSERT(consumed >= msgcnt, "Expected %d messages, consumed %d",
                    msgcnt, consumed);

        test_share_consumer_close(c);
        test_share_destroy(c);

        SUB_TEST_PASS();
}


/**
 * @brief Two share consumers in the same group: the one that stops polling for
 *        longer than max.poll.interval.ms is evicted with MAX_POLL_EXCEEDED,
 *        while the other keeps consuming.
 *
 * Mirrors 0089 do_test() (two consumers, one stalls). Note: unlike a classic
 * consumer group a share group has no exclusive partition ownership, so the
 * second consumer consumes concurrently and is not gated on the first's
 * eviction — that timing assertion from 0089 does not apply here.
 */
static void do_test_two_consumers(void) {
        const char *topic = test_mk_topic_name("0185_share_max_poll", 1);
        char group[64];
        uint64_t testid;
        rd_kafka_share_t *c[2];
        int other_consumed = 0;
        int i;
        int64_t deadline;

        SUB_TEST();

        testid = test_id_generate();
        test_str_id_generate(group, sizeof(group));

        test_create_topic_wait_exists(NULL, topic, 1, -1, 5000);
        test_produce_msgs_easy(topic, testid, 0, 100);

        for (i = 0; i < 2; i++)
                c[i] = create_share_consumer(NULL, group,
                                             REAL_MAX_POLL_INTERVAL_MS);

        test_share_set_auto_offset_reset(group, "earliest");

        for (i = 0; i < 2; i++)
                test_share_consumer_subscribe_multi(c[i], 1, topic);

        /* c[0] never polls: it joins the group and is assigned via heartbeat
         * (which starts its max.poll.interval.ms timer) but immediately stalls.
         * Since it never fetches, it never acquires records, so c[1] can
         * consume freely. c[1] keeps polling for longer than the interval,
         * staying in the group and consuming. */
        TEST_SAY("c[0] stalls (never polls); c[1] keeps consuming for %ds\n",
                 (REAL_MAX_POLL_INTERVAL_MS + 3000) / 1000);
        deadline =
            test_clock() + (int64_t)(REAL_MAX_POLL_INTERVAL_MS + 3000) * 1000;
        while (test_clock() < deadline)
                other_consumed += share_consume_once(c[1], 1000, NULL);

        TEST_ASSERT(other_consumed > 0,
                    "c[1] should have kept consuming while c[0] stalled");

        /* c[0] must surface MAX_POLL_EXCEEDED on its next poll (the error was
         * enqueued by the timer while it was stalled). */
        TEST_ASSERT(wait_max_poll_exceeded(c[0], 10000),
                    "c[0] (stalled) expected MAX_POLL_EXCEEDED");

        for (i = 0; i < 2; i++) {
                test_share_consumer_close(c[i]);
                test_share_destroy(c[i]);
        }

        SUB_TEST_PASS();
}


/**
 * @brief While "processing", polling only the log queue must NOT reset the
 *        share consumer's max.poll.interval.ms timer.
 *
 * Mirrors 0089 do_test_with_log_queue().
 */
static void do_test_log_queue_no_reset(void) {
        const char *topic = test_mk_topic_name("0185_share_max_poll", 1);
        char group[64];
        uint64_t testid;
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *c;
        rd_kafka_t *rk;
        rd_kafka_queue_t *logq;
        char errstr[512];
        char tmp[32];
        int64_t deadline;

        SUB_TEST();

        testid = test_id_generate();
        test_str_id_generate(group, sizeof(group));

        test_create_topic_wait_exists(NULL, topic, 1, -1, 5000);
        test_produce_msgs_easy(topic, testid, 0, 20);
        test_share_set_auto_offset_reset(group, "earliest");

        /* Build a consumer with log.queue=true so logs are routed to a
         * dedicated queue that we can poll during "processing". */
        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "group.id", group);
        rd_snprintf(tmp, sizeof(tmp), "%d", REAL_MAX_POLL_INTERVAL_MS);
        test_conf_set(conf, "max.poll.interval.ms", tmp);
        test_conf_set(conf, "log.queue", "true");
        c = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(c, "Failed to create share consumer: %s", errstr);

        rk   = test_share_consumer_get_rk(c);
        logq = rd_kafka_queue_new(rk);
        TEST_CALL__(rd_kafka_set_log_queue(rk, logq));

        test_share_consumer_subscribe_multi(c, 1, topic);
        establish_membership(c);

        TEST_SAY("Polling only the log queue for %ds (> %dms)\n",
                 (REAL_MAX_POLL_INTERVAL_MS + 3000) / 1000,
                 REAL_MAX_POLL_INTERVAL_MS);
        deadline =
            test_clock() + (int64_t)(REAL_MAX_POLL_INTERVAL_MS + 3000) * 1000;
        while (test_clock() < deadline)
                rd_kafka_event_destroy(rd_kafka_queue_poll(logq, 200));

        TEST_ASSERT(
            wait_max_poll_exceeded(c, 10000),
            "Expected MAX_POLL_EXCEEDED: polling the log queue must not "
            "reset the share consumer max.poll.interval.ms timer");

        test_share_consumer_close(c);
        test_share_destroy(c);
        rd_kafka_queue_destroy(logq);

        SUB_TEST_PASS();
}


/**
 * @brief rd_kafka_poll() on the underlying handle must NOT reset the share
 *        consumer's max.poll.interval.ms timer; only
 *        rd_kafka_share_poll() does.
 *
 * Inverse of 0089 do_test_max_poll_reset_with_consumer_cb(): the regular
 * consumer's poll resets the timer, the share consumer's does not.
 */
static void do_test_rd_kafka_poll_does_not_reset(void) {
        char topic[128];
        rd_kafka_share_t *c;
        rd_kafka_t *rk;
        int64_t deadline;

        SUB_TEST();

        c = real_setup(topic, sizeof(topic), 20, REAL_MAX_POLL_INTERVAL_MS);
        establish_membership(c);

        rk = test_share_consumer_get_rk(c);

        TEST_SAY("Calling only rd_kafka_poll() for %ds (> %dms)\n",
                 (REAL_MAX_POLL_INTERVAL_MS + 3000) / 1000,
                 REAL_MAX_POLL_INTERVAL_MS);
        deadline =
            test_clock() + (int64_t)(REAL_MAX_POLL_INTERVAL_MS + 3000) * 1000;
        while (test_clock() < deadline)
                rd_kafka_poll(rk, 200);

        TEST_ASSERT(
            wait_max_poll_exceeded(c, 10000),
            "Expected MAX_POLL_EXCEEDED: rd_kafka_poll() must not reset "
            "the share consumer max.poll.interval.ms timer");

        test_share_consumer_close(c);
        test_share_destroy(c);

        SUB_TEST_PASS();
}


/**
 * @brief A single blocking rd_kafka_share_poll() that waits longer
 *        than max.poll.interval.ms must NOT trip the timeout (the wait is time
 *        spent inside librdkafka, not application processing time).
 */
static void do_test_blocking_poll_no_false_trip(void) {
        char topic[128];
        rd_kafka_share_t *c;
        rd_bool_t exceeded = rd_false;
        int consumed       = 0;
        int attempts;

        SUB_TEST();

        c = real_setup(topic, sizeof(topic), 5, REAL_MAX_POLL_INTERVAL_MS);
        establish_membership(c);

        /* Drain remaining produced messages so the next poll blocks. */
        while (share_consume_once(c, 500, NULL) > 0)
                ;

        TEST_SAY("Blocking in a single consume_batch() for %ds (> %dms)\n",
                 (REAL_MAX_POLL_INTERVAL_MS + 2000) / 1000,
                 REAL_MAX_POLL_INTERVAL_MS);
        share_consume_once(c, REAL_MAX_POLL_INTERVAL_MS + 2000, &exceeded);

        TEST_ASSERT(!exceeded,
                    "A blocking consume_batch() must not trip "
                    "max.poll.interval.ms");

        test_produce_msgs_easy(topic, test_id_generate(), 0, 5);
        for (attempts = 0; attempts < 30 && consumed == 0; attempts++)
                consumed += share_consume_once(c, 1000, &exceeded);

        TEST_ASSERT(!exceeded,
                    "Consumer should remain in the group after a long "
                    "blocking poll");
        TEST_ASSERT(consumed > 0,
                    "Consumer should still consume messages after a long "
                    "blocking poll");

        test_share_consumer_close(c);
        test_share_destroy(c);

        SUB_TEST_PASS();
}


int main_0185_share_consumer_max_poll_interval(int argc, char **argv) {
        test_timeout_set(300);

        do_test_long_processing();
        do_test_no_poll();
        do_test_steady_consume();
        do_test_two_consumers();
        do_test_log_queue_no_reset();
        do_test_rd_kafka_poll_does_not_reset();
        do_test_blocking_poll_no_false_trip();

        return 0;
}
