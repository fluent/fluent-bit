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
#include "testshared.h"

/**
 * @brief Share consumer topic-deletion acknowledgement tests.
 *
 * Consume a full batch from a 3-partition topic, then acknowledge and
 * commit it either before or after deleting that topic, in implicit and
 * explicit modes. The after-delete case is run with two metadata configs
 * (refresh disabled vs fast refresh + no propagation delay) to exercise
 * both "heartbeat reassignment first" and "metadata refresh first"
 * orderings. The ordering is best-effort — the heartbeat may still win in
 * the fast-refresh config — but the app-facing result is identical: topic
 * deletion does not clear the cached leader, so the acknowledgement
 * reaches the broker and the per-partition commit result is
 * UNKNOWN_TOPIC_OR_PART / UNKNOWN_TOPIC_ID. Each case then produces to and
 * drains a second, non-deleted topic to confirm the consumer keeps working
 * and only the surviving topic is returned.
 */

/** Common producer reused across all tests. */
static rd_kafka_t *common_producer;

/** Common admin client reused across all tests. */
static rd_kafka_t *common_admin;

#define TD_NPART     3
#define TD_PER_PART  10
#define TD_TOTAL     (TD_NPART * TD_PER_PART)
#define TD_KEEP_MSGS 5

typedef enum {
        ACK_BEFORE_DELETE,
        ACK_AFTER_HB_FIRST,
        ACK_AFTER_MD_FIRST,
} ack_timing_t;

static const char *ack_timing_name(ack_timing_t t) {
        switch (t) {
        case ACK_BEFORE_DELETE:
                return "before-delete";
        case ACK_AFTER_HB_FIRST:
                return "after-delete-heartbeat-first";
        case ACK_AFTER_MD_FIRST:
                return "after-delete-metadata-first";
        }
        return "?";
}

static rd_bool_t err_is_unknown_topic(rd_kafka_resp_err_t err) {
        /* TODO KIP-932: When the whole topic is deleted the broker cannot find
         * the share partition and fails the entire ShareAcknowledge with a
         * top-level UNKNOWN_SERVER_ERROR (RD_KAFKA_RESP_ERR_UNKNOWN) instead of
         * a per-partition UNKNOWN_TOPIC_OR_PART / UNKNOWN_TOPIC_ID. Remove the
         * UNKNOWN case once the broker reports the deletion per partition. */
        return err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART ||
               err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID ||
               err == RD_KAFKA_RESP_ERR_UNKNOWN;
}

static rd_kafka_share_t *create_topic_delete_consumer(const char *group,
                                                      const char *mode,
                                                      ack_timing_t timing) {
        rd_kafka_conf_t *conf;
        rd_kafka_share_t *rkshare;
        char errstr[512];

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "group.id", group);
        test_conf_set(conf, "share.acknowledgement.mode", mode);
        /* Bound the batch size; the test's batch array is sized for this. */
        test_conf_set(conf, "max.poll.records", "100");
        if (timing == ACK_AFTER_MD_FIRST) {
                /* Refresh metadata quickly and mark the deleted topic
                 * NOTEXISTS without the propagation delay, so a metadata
                 * refresh is likely to land before the heartbeat
                 * reassignment. */
                test_conf_set(conf, "topic.metadata.refresh.interval.ms",
                              "200");
                test_conf_set(conf, "topic.metadata.propagation.max.ms", "0");
        }
        /* Otherwise use the default metadata config: the periodic refresh
         * (minutes) does not fire during this short test, so the heartbeat
         * reassignment lands before any metadata refresh ("heartbeat
         * first"). A large explicit interval is avoided because it would
         * inflate metadata.max.age.ms past the 32-bit overflow point. */

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        TEST_ASSERT(rkshare, "Failed to create share consumer: %s", errstr);
        return rkshare;
}

static void do_test_topic_delete_ack(const char *mode, ack_timing_t timing) {
        rd_kafka_share_t *rkshare;
        rd_kafka_messages_t *batch               = NULL;
        rd_kafka_topic_partition_list_t *results = NULL;
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t del_err;
        char topic_del[512], topic_keep[512], group[160];
        char del_base[128], keep_base[128];
        char *del_topics[1];
        int part_cnt[TD_NPART] = {0};
        size_t m;
        int p, i;
        int total              = 0;
        int attempts           = 20;
        int keep_rcvd          = 0;
        int idle_polls         = 0;
        rd_bool_t explicit_ack = !strcmp(mode, "explicit");
        rd_bool_t after_delete = timing != ACK_BEFORE_DELETE;

        SUB_TEST("mode=%s, %s", mode, ack_timing_name(timing));

        /* Embed mode+timing in the base name so the subtests never share a
         * topic even if test_mk_topic_name repeats its random suffix;
         * otherwise a sibling's leftover records bleed into this drain. */
        rd_snprintf(del_base, sizeof(del_base), "0181-td-del-%s-%s", mode,
                    ack_timing_name(timing));
        rd_snprintf(keep_base, sizeof(keep_base), "0181-td-keep-%s-%s", mode,
                    ack_timing_name(timing));
        rd_snprintf(topic_del, sizeof(topic_del), "%s",
                    test_mk_topic_name(del_base, 1));
        rd_snprintf(topic_keep, sizeof(topic_keep), "%s",
                    test_mk_topic_name(keep_base, 1));
        rd_snprintf(group, sizeof(group), "0181-td-%s-%s", mode,
                    ack_timing_name(timing));
        del_topics[0] = topic_del;

        test_create_topic_wait_exists(NULL, topic_del, TD_NPART, -1, 60 * 1000);
        test_create_topic_wait_exists(NULL, topic_keep, 1, -1, 60 * 1000);
        for (p = 0; p < TD_NPART; p++)
                test_produce_msgs_simple(common_producer, topic_del, p,
                                         TD_PER_PART);

        rkshare = create_topic_delete_consumer(group, mode, timing);
        /* Configure earliest after the consumer exists but before it
         * subscribes/joins, so the pre-produced records are read. */
        test_share_set_auto_offset_reset(group, "earliest");
        test_share_consumer_subscribe_multi(rkshare, 2, topic_del, topic_keep);
        TEST_SAY("Subscribed to %s and %s; starting phase 1 drain\n", topic_del,
                 topic_keep);

        /* Phase 1: drain all produced records. The partitions live on
         * different brokers and the share consumer fetches one broker per
         * round, so the records arrive across several batches; each round
         * also flushes the previous broker's acknowledgements. Verify all
         * records and that every partition is represented. */
        while (total < TD_TOTAL && attempts-- > 0) {
                size_t n;
                error = rd_kafka_share_poll(rkshare, 2000, &batch);
                TEST_ASSERT(!error, "share_poll failed: %s",
                            rd_kafka_error_string(error));
                n = rd_kafka_messages_count(batch);
                TEST_SAY("Phase 1: got %" PRIusz " record(s), total %d/%d\n", n,
                         total + (int)n, TD_TOTAL);
                for (m = 0; m < n; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        TEST_ASSERT(
                            !strcmp(rd_kafka_topic_name(msg->rkt), topic_del),
                            "Phase 1 record from unexpected topic %s",
                            rd_kafka_topic_name(msg->rkt));
                        TEST_ASSERT(
                            msg->partition >= 0 && msg->partition < TD_NPART,
                            "Unexpected partition %" PRId32, msg->partition);
                        part_cnt[msg->partition]++;
                        if (explicit_ack) {
                                rd_kafka_resp_err_t ack_err =
                                    rd_kafka_share_acknowledge(rkshare, msg);
                                TEST_ASSERT(!ack_err, "acknowledge failed: %s",
                                            rd_kafka_err2str(ack_err));
                        }
                        total++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(total == TD_TOTAL, "Expected %d records, got %d", TD_TOTAL,
                    total);
        for (p = 0; p < TD_NPART; p++)
                TEST_ASSERT(part_cnt[p] == TD_PER_PART,
                            "Expected %d records from partition %d, got %d",
                            TD_PER_PART, p, part_cnt[p]);
        TEST_SAY("Phase 1 complete: drained all %d records\n", TD_TOTAL);

        if (after_delete) {
                TEST_SAY("Deleting topic %s before commit\n", topic_del);
                del_err = test_DeleteTopics_simple(common_admin, NULL,
                                                   del_topics, 1, NULL);
                TEST_ASSERT(!del_err, "DeleteTopics failed: %s",
                            rd_kafka_err2str(del_err));
                /* Let the chosen ordering take effect before committing. */
                rd_sleep(1);
        }

        /* Commit the acknowledgements; the per-partition results carry
         * the outcome for each partition. */
        TEST_SAY("Calling commit_sync\n");
        error = rd_kafka_share_commit_sync(rkshare, 30 * 1000, &results);
        TEST_SAY("commit_sync returned (error: %s)\n",
                 error ? rd_kafka_error_string(error) : "none");
        if (error)
                rd_kafka_error_destroy(error);
        TEST_ASSERT(results && results->cnt > 0,
                    "Expected per-partition commit results");
        for (i = 0; i < results->cnt; i++) {
                rd_kafka_resp_err_t perr = results->elems[i].err;
                if (after_delete)
                        TEST_ASSERT(err_is_unknown_topic(perr),
                                    "Expected a deleted-topic error for %s "
                                    "[%" PRId32 "], got %s",
                                    results->elems[i].topic,
                                    results->elems[i].partition,
                                    rd_kafka_err2name(perr));
                else
                        TEST_ASSERT(perr == RD_KAFKA_RESP_ERR_NO_ERROR,
                                    "Expected success for %s [%" PRId32
                                    "], got %s",
                                    results->elems[i].topic,
                                    results->elems[i].partition,
                                    rd_kafka_err2name(perr));
        }
        TEST_SAY("commit_sync results verified (%d partition(s))\n",
                 results->cnt);
        rd_kafka_topic_partition_list_destroy(results);

        if (!after_delete) {
                TEST_SAY("Deleting topic %s after commit\n", topic_del);
                del_err = test_DeleteTopics_simple(common_admin, NULL,
                                                   del_topics, 1, NULL);
                TEST_ASSERT(!del_err, "DeleteTopics failed: %s",
                            rd_kafka_err2str(del_err));
        }

        /* Let the topic delete propagate through the cluster and the
         * share session reconcile (the consumer subscribed to both
         * topics; the broker has to drop the deleted topic from the
         * session before it will start serving the surviving one
         * again). Without this, the produce + consume_batch loop below
         * races the session-recovery window and Phase 2 drains 0
         * records. */
        rd_sleep(3);

        /* Phase 2: drain the surviving topic to empty and verify only its
         * records are returned (the deleted topic must contribute none). */
        test_produce_msgs_simple(common_producer, topic_keep, 0, TD_KEEP_MSGS);
        TEST_SAY("Phase 2: draining surviving topic %s\n", topic_keep);

        /* TODO KIP-932: the deleted topic makes the broker fail the whole
         * session with a top-level UNKNOWN for a while, so we give the drain
         * a larger budget and ignore empty polls until all records arrive.
         * Revert to a plain drain loop once the broker is fixed. */
        attempts = 60;
        while (attempts-- > 0) {
                size_t got;
                error = rd_kafka_share_poll(rkshare, 1000, &batch);
                TEST_ASSERT(!error, "share_poll failed: %s",
                            rd_kafka_error_string(error));
                got = rd_kafka_messages_count(batch);
                TEST_SAY("Phase 2: got %" PRIusz
                         " record(s), kept %d/%d (idle %d)\n",
                         got, keep_rcvd, TD_KEEP_MSGS, idle_polls);
                if (got == 0) {
                        /* An empty poll counts as drained only after every
                         * record has arrived; earlier ones are the session
                         * still recovering. */
                        rd_kafka_messages_destroy(batch);
                        batch = NULL;
                        if (keep_rcvd >= TD_KEEP_MSGS && ++idle_polls >= 3)
                                break;
                        continue;
                }
                idle_polls = 0;
                for (m = 0; m < got; m++) {
                        rd_kafka_message_t *msg =
                            rd_kafka_messages_get(batch, m);
                        TEST_ASSERT(
                            !strcmp(rd_kafka_topic_name(msg->rkt), topic_keep),
                            "Phase 2 returned a record from %s; only %s "
                            "should remain",
                            rd_kafka_topic_name(msg->rkt), topic_keep);
                        if (explicit_ack)
                                rd_kafka_share_acknowledge(rkshare, msg);
                        keep_rcvd++;
                }
                rd_kafka_messages_destroy(batch);
                batch = NULL;
        }
        TEST_ASSERT(keep_rcvd == TD_KEEP_MSGS,
                    "Expected to drain exactly %d records from surviving "
                    "topic %s, got %d",
                    TD_KEEP_MSGS, topic_keep, keep_rcvd);

        test_share_consumer_close(rkshare);
        test_share_destroy(rkshare);

        /* TODO KIP-932: add a delete-then-recreate variant once topic
         * recreation handling is fixed. */
        SUB_TEST_PASS();
}

int main_0181_share_consumer_topic_delete(int argc, char **argv) {
        /* Topic deletion is not supported against Windows brokers. */
        if (!strcmp(test_getenv("TEST_BROKER_OS", ""), "windows")) {
                TEST_SKIP("Topic deletion not supported on Windows brokers\n");
                return 0;
        }

        /* Budget for all subtests (a timeout multiplier is applied on top). */
        test_timeout_set(120);

        common_producer = test_create_producer();
        common_admin    = test_create_producer();

        do_test_topic_delete_ack("implicit", ACK_BEFORE_DELETE);
        do_test_topic_delete_ack("implicit", ACK_AFTER_HB_FIRST);
        do_test_topic_delete_ack("implicit", ACK_AFTER_MD_FIRST);
        do_test_topic_delete_ack("explicit", ACK_BEFORE_DELETE);
        do_test_topic_delete_ack("explicit", ACK_AFTER_HB_FIRST);
        do_test_topic_delete_ack("explicit", ACK_AFTER_MD_FIRST);

        rd_kafka_destroy(common_admin);
        rd_kafka_destroy(common_producer);

        return 0;
}
