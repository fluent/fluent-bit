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

/**
 * Share consumer example using rd_kafka_share_commit_async() to
 * explicitly acknowledge and commit records between polls.
 *
 * Usage:
 *   share_consumer_commit_async <broker> <group.id> <topic1> [topic2 ...]
 *
 * This example demonstrates:
 *  - Consuming records with rd_kafka_share_poll()
 *  - Explicitly acknowledging each record with
 *    rd_kafka_share_acknowledge_type() (ACCEPT)
 *  - Committing the batch's acknowledgements asynchronously with
 *    rd_kafka_share_commit_async() once per poll; the broker's reply is
 *    delivered later to the acknowledgement-commit callback
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"


static volatile sig_atomic_t run = 1;

/**
 * @brief Signal termination of program
 */
static void stop(int sig) {
        run = 0;
}


/**
 * @returns 1 if all bytes are printable, else 0.
 */
static int is_printable(const char *buf, size_t size) {
        size_t i;

        for (i = 0; i < size; i++)
                if (!isprint((int)buf[i]))
                        return 0;

        return 1;
}


/**
 * @brief Acknowledgement-commit callback.
 *
 * rd_kafka_share_commit_async() does not block; its result is reported here.
 * @p partitions lists each partition with the offsets that were committed;
 * @p err is set if the commit failed.
 */
static void
acknowledgement_commit_cb(rd_kafka_share_t *rkshare,
                          rd_kafka_share_partition_offsets_list_t *partitions,
                          rd_kafka_resp_err_t err,
                          void *opaque) {
        size_t i, cnt;

        if (err) {
                fprintf(stderr, "%% Acknowledgement commit failed: %s\n",
                        rd_kafka_err2str(err));
                return;
        }

        cnt = rd_kafka_share_partition_offsets_list_count(partitions);
        for (i = 0; i < cnt; i++) {
                const rd_kafka_share_partition_offsets_t *po =
                    rd_kafka_share_partition_offsets_list_get(partitions, i);
                const rd_kafka_topic_partition_t *tp =
                    rd_kafka_share_partition_offsets_partition(po);
                size_t offset_cnt =
                    rd_kafka_share_partition_offsets_offsets_cnt(po);

                fprintf(stderr,
                        "%% Committed %s [%" PRId32 "]: %zu offset(s)\n",
                        tp->topic, tp->partition, offset_cnt);
        }
}


/**
 * @brief Process a received record.
 *
 * Replace this with your own handling. The return value tells the caller how
 * to acknowledge the record:
 *   0   success           -> ACCEPT  (done, never redeliver it)
 *   > 0 transient failure  -> RELEASE (retry later, maybe another consumer)
 *   < 0 permanent failure  -> REJECT  (give up; the broker archives it)
 */
static int process_message(const rd_kafka_message_t *rkm) {
        printf("Message on %s [%" PRId32 "] at offset %" PRId64,
               rd_kafka_topic_name(rkm->rkt), rkm->partition, rkm->offset);

        if (rkm->key && is_printable(rkm->key, rkm->key_len))
                printf(" Key: %.*s", (int)rkm->key_len, (const char *)rkm->key);

        if (rkm->payload && is_printable(rkm->payload, rkm->len))
                printf(" Value: %.*s", (int)rkm->len,
                       (const char *)rkm->payload);

        printf("\n");

        return 0;
}


int main(int argc, char **argv) {
        rd_kafka_share_t *rkshare;
        rd_kafka_conf_t *conf;
        rd_kafka_resp_err_t err;
        char errstr[512];
        const char *brokers;
        const char *groupid;
        char **topics;
        int topic_cnt;
        rd_kafka_topic_partition_list_t *subscription;
        rd_kafka_error_t *cb_error;
        int i;
        int ret = 0; /* Process exit code */

        if (argc < 4) {
                fprintf(stderr,
                        "%% Usage: "
                        "%s <broker> <group.id> <topic1> [topic2 ..]\n",
                        argv[0]);
                return 1;
        }

        brokers   = argv[1];
        groupid   = argv[2];
        topics    = &argv[3];
        topic_cnt = argc - 3;

        conf = rd_kafka_conf_new();

        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%s\n", errstr);
                rd_kafka_conf_destroy(conf);
                return 1;
        }

        if (rd_kafka_conf_set(conf, "group.id", groupid, errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%s\n", errstr);
                rd_kafka_conf_destroy(conf);
                return 1;
        }

        if (rd_kafka_conf_set(conf, "share.acknowledgement.mode", "explicit",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%s\n", errstr);
                rd_kafka_conf_destroy(conf);
                return 1;
        }

        rkshare = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
        if (!rkshare) {
                fprintf(stderr, "%% Failed to create new share consumer: %s\n",
                        errstr);
                return 1;
        }

        conf = NULL;

        /* Register the acknowledgement-commit callback that
         * rd_kafka_share_commit_async() reports its result to. */
        cb_error = rd_kafka_share_set_acknowledgement_commit_cb(
            rkshare, acknowledgement_commit_cb, NULL);
        if (cb_error) {
                fprintf(stderr,
                        "%% Failed to set acknowledgement commit callback: "
                        "%s\n",
                        rd_kafka_error_string(cb_error));
                rd_kafka_error_destroy(cb_error);
                rd_kafka_share_destroy(rkshare);
                return 1;
        }

        subscription = rd_kafka_topic_partition_list_new(topic_cnt);
        for (i = 0; i < topic_cnt; i++)
                rd_kafka_topic_partition_list_add(subscription, topics[i],
                                                  RD_KAFKA_PARTITION_UA);

        err = rd_kafka_share_subscribe(rkshare, subscription);
        if (err) {
                fprintf(stderr, "%% Failed to subscribe to %d topics: %s\n",
                        subscription->cnt, rd_kafka_err2str(err));
                rd_kafka_topic_partition_list_destroy(subscription);
                rd_kafka_share_destroy(rkshare);
                return 1;
        }

        fprintf(stderr,
                "%% Subscribed to %d topic(s), "
                "waiting for rebalance and messages...\n",
                subscription->cnt);

        rd_kafka_topic_partition_list_destroy(subscription);

        signal(SIGINT, stop);

        while (run) {
                rd_kafka_messages_t *rkmessages = NULL;
                rd_kafka_error_t *error;
                size_t rcvd_msgs;
                size_t k;

                error = rd_kafka_share_poll(rkshare, 3000, &rkmessages);

                if (error) {
                        int fatal = rd_kafka_error_is_fatal(error);
                        fprintf(stderr, "%% Consume error%s: %s\n",
                                fatal ? " (fatal)" : "",
                                rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        rd_kafka_messages_destroy(rkmessages);
                        /* A fatal error is unrecoverable: stop consuming. */
                        if (fatal) {
                                ret = 1;
                                goto done;
                        }
                        continue;
                }

                rcvd_msgs = rd_kafka_messages_count(rkmessages);
                if (rcvd_msgs == 0) {
                        rd_kafka_messages_destroy(rkmessages);
                        continue;
                }

                printf("Received %zu messages\n", rcvd_msgs);

                for (k = 0; k < rcvd_msgs; k++) {
                        rd_kafka_message_t *rkm =
                            rd_kafka_messages_get(rkmessages, k);
                        rd_kafka_share_AcknowledgeType_t ack_type;
                        int rc;

                        if (rkm->err) {
                                /* A record delivered with an error has already
                                 * been acknowledged for you by the library:
                                 * RELEASE (put back for retry) for
                                 * decompression errors, and REJECT (give up)
                                 * for CRC or unsupported-format errors. You can
                                 * still override that by acknowledging the
                                 * offset yourself if your application needs
                                 * different handling. */
                                fprintf(stderr, "%% Consumer error: %d: %s\n",
                                        rkm->err, rd_kafka_message_errstr(rkm));
                                continue;
                        }

                        /* Decide how to acknowledge based on the processing
                         * outcome: ACCEPT on success, RELEASE on a transient
                         * failure so the record can be retried, REJECT on a
                         * permanent failure so the broker archives it. */
                        rc = process_message(rkm);
                        if (rc == 0)
                                ack_type =
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT;
                        else if (rc > 0)
                                ack_type =
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_RELEASE;
                        else
                                ack_type =
                                    RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT;

                        err = rd_kafka_share_acknowledge_type(rkshare, rkm,
                                                              ack_type);
                        if (err)
                                fprintf(stderr,
                                        "%% Acknowledge error for "
                                        "%s [%" PRId32 "] @ %" PRId64 ": %s\n",
                                        rd_kafka_topic_name(rkm->rkt),
                                        rkm->partition, rkm->offset,
                                        rd_kafka_err2str(err));
                }

                /* Flush this batch's acknowledgements before the next poll().
                 * commit_async() does not block; the result is delivered to
                 * the acknowledgement-commit callback. */
                error = rd_kafka_share_commit_async(rkshare);
                if (error) {
                        fprintf(stderr, "%% Commit async error: %s\n",
                                rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                }

                rd_kafka_messages_destroy(rkmessages);
        }

done:
        fprintf(stderr, "%% Closing share consumer\n");
        rd_kafka_share_consumer_close(rkshare);

        rd_kafka_share_destroy(rkshare);

        return ret;
}
