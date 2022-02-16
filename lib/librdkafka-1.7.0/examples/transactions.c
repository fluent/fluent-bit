/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020, Magnus Edenhill
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
 * @name Transactions example for Apache Kafka 2.5.0 (KIP-447) and later.
 *
 * This example show-cases a simple transactional consume-process-produce
 * application that reads messages from an input topic, extracts all
 * numbers from the message's value string, adds them up, and sends
 * the sum to the output topic as part of a transaction.
 * The transaction is committed every 5 seconds or 100 messages, whichever
 * comes first. As the transaction is committed a new transaction is started.
 *
 * This example makes use of incremental rebalancing (KIP-429) and the
 * cooperative-sticky partition.assignment.strategy on the consumer, providing
 * hitless rebalances.
 */

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>


/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"


static volatile sig_atomic_t run = 1;

/**
 * @brief A fatal error has occurred, immediately exit the application.
 */
#define fatal(...) do {                                 \
                fprintf(stderr, "FATAL ERROR: ");       \
                fprintf(stderr, __VA_ARGS__);           \
                fprintf(stderr, "\n");                  \
                exit(1);                                \
        } while (0)

/**
 * @brief Same as fatal() but takes an rd_kafka_error_t object, prints its
 *        error message, destroys the object and then exits fatally.
 */
#define fatal_error(what,error) do {                                    \
                fprintf(stderr, "FATAL ERROR: %s: %s: %s\n",             \
                        what, rd_kafka_error_name(error),               \
                        rd_kafka_error_string(error));                  \
                rd_kafka_error_destroy(error);                          \
                exit(1);                                                \
        } while (0)

/**
 * @brief Signal termination of program
 */
static void stop (int sig) {
        run = 0;
}


/**
 * @brief Message delivery report callback.
 *
 * This callback is called exactly once per message, indicating if
 * the message was succesfully delivered
 * (rkmessage->err == RD_KAFKA_RESP_ERR_NO_ERROR) or permanently
 * failed delivery (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR).
 *
 * The callback is triggered from rd_kafka_poll(), rd_kafka_flush(),
 * rd_kafka_abort_transaction() and rd_kafka_commit_transaction() and
 * executes on the application's thread.
 *
 * The current transactional will enter the abortable state if any
 * message permanently fails delivery and the application must then
 * call rd_kafka_abort_transaction(). But it does not need to be done from
 * here, this state is checked by all the transactional APIs and it is better
 * to perform this error checking when calling
 * rd_kafka_send_offsets_to_transaction() and rd_kafka_commit_transaction().
 * In the case of transactional producing the delivery report callback is
 * mostly useful for logging the produce failures.
 */
static void dr_msg_cb (rd_kafka_t *rk,
                       const rd_kafka_message_t *rkmessage, void *opaque) {
        if (rkmessage->err)
                fprintf(stderr,
                        "%% Message delivery failed: %s\n",
                        rd_kafka_err2str(rkmessage->err));

        /* The rkmessage is destroyed automatically by librdkafka */
}



/**
 * @brief Create a transactional producer.
 */
static rd_kafka_t *
create_transactional_producer (const char *brokers, const char *output_topic) {
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        rd_kafka_t *rk;
        char errstr[256];
        rd_kafka_error_t *error;

        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers,
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            rd_kafka_conf_set(conf, "transactional.id",
                              "librdkafka_transactions_example",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK)
                fatal("Failed to configure producer: %s", errstr);

        /* This callback will be called once per message to indicate
         * final delivery status. */
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

        /* Create producer */
        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        if (!rk) {
                rd_kafka_conf_destroy(conf);
                fatal("Failed to create producer: %s", errstr);
        }

        /* Initialize transactions, this is only performed once
         * per transactional producer to acquire its producer id, et.al. */
        error = rd_kafka_init_transactions(rk, -1);
        if (error)
                fatal_error("init_transactions()", error);

        return rk;
}


/**
 * @brief Rewind consumer's consume position to the last committed offsets
 *        for the current assignment.
 */
static void rewind_consumer (rd_kafka_t *consumer) {
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_resp_err_t err;
        rd_kafka_error_t *error;
        int i;

        /* Get committed offsets for the current assignment, if there
         * is a current assignment. */
        err = rd_kafka_assignment(consumer, &offsets);
        if (err) {
                fprintf(stderr, "No current assignment to rewind: %s\n",
                        rd_kafka_err2str(err));
                return;
        }

        if (offsets->cnt == 0) {
                fprintf(stderr, "No current assignment to rewind\n");
                rd_kafka_topic_partition_list_destroy(offsets);
                return;
        }

        /* Note: Timeout must be lower than max.poll.interval.ms */
        err = rd_kafka_committed(consumer, offsets, 10*1000);
        if (err)
                fatal("Failed to acquire committed offsets: %s",
                      rd_kafka_err2str(err));

        /* Seek to committed offset, or start of partition if no
         * committed offset is available. */
        for (i = 0 ; i < offsets->cnt ; i++) {
                /* No committed offset, start from beginning */
                if (offsets->elems[i].offset < 0)
                        offsets->elems[i].offset =
                                RD_KAFKA_OFFSET_BEGINNING;
        }

        /* Perform seek */
        error = rd_kafka_seek_partitions(consumer, offsets, -1);
        if (error)
                fatal_error("Failed to seek", error);

        rd_kafka_topic_partition_list_destroy(offsets);
}

/**
 * @brief Abort the current transaction and rewind consumer offsets to
 *        position where the transaction last started, i.e., the committed
 *        consumer offset, then begin a new transaction.
 */
static void abort_transaction_and_rewind (rd_kafka_t *consumer,
                                          rd_kafka_t *producer) {
        rd_kafka_error_t *error;

        fprintf(stdout, "Aborting transaction and rewinding offsets\n");

        /* Abort the current transaction */
        error = rd_kafka_abort_transaction(producer, -1);
        if (error)
                fatal_error("Failed to abort transaction", error);

        /* Rewind consumer */
        rewind_consumer(consumer);

        /* Begin a new transaction */
        error = rd_kafka_begin_transaction(producer);
        if (error)
                fatal_error("Failed to begin transaction", error);
}


/**
 * @brief Commit the current transaction.
 *
 * @returns 1 if transaction was successfully committed, or 0
 *          if the current transaction was aborted.
 */
static int commit_transaction (rd_kafka_t *consumer,
                               rd_kafka_t *producer) {
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        rd_kafka_consumer_group_metadata_t *cgmd;
        rd_kafka_topic_partition_list_t *offsets;

        fprintf(stdout, "Committing transaction\n");

        /* Send the input consumer's offset to transaction
         * to commit those offsets along with the transaction itself,
         * this is what guarantees exactly-once-semantics (EOS), that
         * input (offsets) and output (messages) are committed atomically. */

        /* Get the consumer's current group metadata state */
        cgmd = rd_kafka_consumer_group_metadata(consumer);

        /* Get consumer's current assignment */
        err = rd_kafka_assignment(consumer, &offsets);
        if (err || offsets->cnt == 0) {
                /* No partition offsets to commit because consumer
                 * (most likely) lost the assignment, abort transaction. */
                if (err)
                        fprintf(stderr,
                                "Failed to get consumer assignment to commit: "
                                "%s\n", rd_kafka_err2str(err));
                else
                        rd_kafka_topic_partition_list_destroy(offsets);

                error = rd_kafka_abort_transaction(producer, -1);
                if (error)
                        fatal_error("Failed to abort transaction", error);

                return 0;
        }

        /* Get consumer's current position for this partition */
        err = rd_kafka_position(consumer, offsets);
        if (err)
                fatal("Failed to get consumer position: %s",
                      rd_kafka_err2str(err));

        /* Send offsets to transaction coordinator */
        error = rd_kafka_send_offsets_to_transaction(producer,
                                                     offsets, cgmd, -1);
        rd_kafka_consumer_group_metadata_destroy(cgmd);
        rd_kafka_topic_partition_list_destroy(offsets);
        if (error) {
                if (rd_kafka_error_txn_requires_abort(error)) {
                        fprintf(stderr,
                                "WARNING: Failed to send offsets to "
                                "transaction: %s: %s: aborting transaction\n",
                                rd_kafka_error_name(error),
                                rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);

                        /* Abort transaction */
                        error = rd_kafka_abort_transaction(producer, -1);
                        if (error)
                                fatal_error("Failed to abort transaction",
                                            error);
                        return 0;
                } else {
                        fatal_error("Failed to send offsets to transaction",
                                    error);
                }
        }

        /* Commit the transaction */
        error = rd_kafka_commit_transaction(producer, -1);
        if (error) {
                if (rd_kafka_error_txn_requires_abort(error)) {
                        fprintf(stderr,
                                "WARNING: Failed to commit transaction: "
                                "%s: %s: aborting transaction\n",
                                rd_kafka_error_name(error),
                                rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);

                        /* Abort transaction */
                        error = rd_kafka_abort_transaction(producer, -1);
                        if (error)
                                fatal_error("Failed to abort transaction",
                                            error);
                        return 0;
                } else {
                        fatal_error("Failed to commit transaction", error);
                }
        }

        return 1;
}

/**
 * @brief Commit the current transaction and start a new transaction.
 */
static void commit_transaction_and_start_new (rd_kafka_t *consumer,
                                              rd_kafka_t *producer) {
        rd_kafka_error_t *error;

        /* Commit transaction.
         * If commit failed the transaction is aborted and we need
         * to rewind the consumer to the last committed offsets. */
        if (!commit_transaction(consumer, producer))
                rewind_consumer(consumer);

        /* Begin new transaction */
        error = rd_kafka_begin_transaction(producer);
        if (error)
                fatal_error("Failed to begin new transaction", error);
}

/**
 * @brief The rebalance will be triggered (from rd_kafka_consumer_poll())
 *        when the consumer's partition assignment is assigned or revoked.
 */
static void
consumer_group_rebalance_cb (rd_kafka_t *consumer,
                             rd_kafka_resp_err_t err,
                             rd_kafka_topic_partition_list_t *partitions,
                             void *opaque) {
        rd_kafka_t *producer = (rd_kafka_t *)opaque;
        rd_kafka_error_t *error;

        switch (err)
        {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                fprintf(stdout,
                        "Consumer group rebalanced: "
                        "%d new partition(s) assigned\n",
                        partitions->cnt);

                /* Start fetching messages for the assigned partitions
                 * and add them to the consumer's local assignment. */
                error = rd_kafka_incremental_assign(consumer, partitions);
                if (error)
                        fatal_error("Incremental assign failed", error);
                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                if (rd_kafka_assignment_lost(consumer)) {
                        fprintf(stdout,
                                "Consumer group rebalanced: assignment lost: "
                                "aborting current transaction\n");

                        error = rd_kafka_abort_transaction(producer, -1);
                        if (error)
                                fatal_error("Failed to abort transaction",
                                            error);
                } else {
                        fprintf(stdout,
                                "Consumer group rebalanced: %d partition(s) "
                                "revoked: committing current transaction\n",
                                partitions->cnt);

                        commit_transaction(consumer, producer);
                }

                /* Begin new transaction */
                error = rd_kafka_begin_transaction(producer);
                if (error)
                        fatal_error("Failed to begin transaction", error);

                /* Stop fetching messages for the revoekd partitions
                 * and remove them from the consumer's local assignment. */
                error = rd_kafka_incremental_unassign(consumer, partitions);
                if (error)
                        fatal_error("Incremental unassign failed", error);
                break;

        default:
                /* NOTREACHED */
                fatal("Unexpected rebalance event: %s", rd_kafka_err2name(err));
        }
}


/**
 * @brief Create the input consumer.
 */
static rd_kafka_t *create_input_consumer (const char *brokers,
                                          const char *input_topic,
                                          rd_kafka_t *producer) {
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        rd_kafka_t *rk;
        char errstr[256];
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *topics;

        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers,
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            rd_kafka_conf_set(conf, "group.id",
                              "librdkafka_transactions_example_group",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            rd_kafka_conf_set(conf, "partition.assignment.strategy",
                              "cooperative-sticky",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            rd_kafka_conf_set(conf, "auto.offset.reset", "earliest",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            /* The input consumer's offsets are explicitly committed with the
             * output producer's transaction using
             * rd_kafka_send_offsets_to_transaction(), so auto commits
             * must be disabled. */
            rd_kafka_conf_set(conf, "enable.auto.commit", "false",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fatal("Failed to configure consumer: %s", errstr);
        }

        /* This callback will be called when the consumer group is rebalanced
         * and the consumer's partition assignment is assigned or revoked. */
        rd_kafka_conf_set_rebalance_cb(conf, consumer_group_rebalance_cb);

        /* The producer handle is needed in the consumer's rebalance callback
         * to be able to abort and commit transactions, so we pass the
         * producer as the consumer's opaque. */
        rd_kafka_conf_set_opaque(conf, producer);

        /* Create consumer */
        rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
        if (!rk) {
                rd_kafka_conf_destroy(conf);
                fatal("Failed to create consumer: %s", errstr);
        }

        /* Forward all partition messages to the main queue and
         * rd_kafka_consumer_poll(). */
        rd_kafka_poll_set_consumer(rk);

        /* Subscribe to the input topic */
        topics = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(topics, input_topic,
                                          /* The partition is ignored in
                                           * rd_kafka_subscribe() */
                                          RD_KAFKA_PARTITION_UA);
        err = rd_kafka_subscribe(rk, topics);
        rd_kafka_topic_partition_list_destroy(topics);
        if (err) {
                rd_kafka_destroy(rk);
                fatal("Failed to subscribe to %s: %s\n",
                      input_topic, rd_kafka_err2str(err));
        }

        return rk;
}


/**
 * @brief Find and parse next integer string in \p start.
 * @returns Pointer after found integer string, or NULL if not found.
 */
static const void *find_next_int (const void *start, const void *end,
                                  int *intp) {
        const char *p;
        int collecting = 0;
        int num = 0;

        for (p = (const char *)start ; p < (const char *)end ; p++) {
                if (isdigit((int)(*p))) {
                        collecting = 1;
                        num = (num * 10) + ((int)*p - ((int)'0'));
                } else if (collecting)
                        break;
        }

        if (!collecting)
                return NULL; /* No integer string found */

        *intp = num;

        return p;
}


/**
 * @brief Process a message from the input consumer by parsing all
 *        integer strings, adding them, and then producing the sum
 *        the output topic using the transactional producer for the given
 *        inut partition.
 */
static void process_message (rd_kafka_t *consumer,
                             rd_kafka_t *producer,
                             const char *output_topic,
                             const rd_kafka_message_t *rkmessage) {
        int num;
        long unsigned sum = 0;
        const void *p, *end;
        rd_kafka_resp_err_t err;
        char value[64];

        if (rkmessage->len == 0)
                return; /* Ignore empty messages */

        p = rkmessage->payload;
        end = ((const char *)rkmessage->payload) + rkmessage->len;

        /* Find and sum all numbers in the message */
        while ((p = find_next_int(p, end, &num)))
                sum += num;

        if (sum == 0)
                return; /* No integers in message, ignore it. */

        snprintf(value, sizeof(value), "%lu", sum);

        /* Emit output message on transactional producer */
        while (1) {
                err = rd_kafka_producev(
                        producer,
                        RD_KAFKA_V_TOPIC(output_topic),
                        /* Use same key as input message */
                        RD_KAFKA_V_KEY(rkmessage->key,
                                       rkmessage->key_len),
                        /* Value is the current sum of this
                         * transaction. */
                        RD_KAFKA_V_VALUE(value, strlen(value)),
                        /* Copy value since it is allocated on the stack */
                        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                        RD_KAFKA_V_END);

                if (!err)
                        break;
                else if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
                        /* If output queue fills up we need to wait for
                         * some delivery reports and then retry. */
                        rd_kafka_poll(producer, 100);
                        continue;
                } else {
                        fprintf(stderr,
                                "WARNING: Failed to produce message to %s: "
                                "%s: aborting transaction\n",
                                output_topic, rd_kafka_err2str(err));
                        abort_transaction_and_rewind(consumer, producer);
                        return;
                }
        }
}


int main (int argc, char **argv) {
        rd_kafka_t *producer, *consumer;
        int msgcnt = 0;
        time_t last_commit = 0;
        const char *brokers, *input_topic, *output_topic;
        rd_kafka_error_t *error;

        /*
         * Argument validation
         */
        if (argc != 4) {
                fprintf(stderr,
                        "%% Usage: %s <broker> <input-topic> <output-topic>\n",
                        argv[0]);
                return 1;
        }

        brokers = argv[1];
        input_topic = argv[2];
        output_topic = argv[3];

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        producer = create_transactional_producer(brokers, output_topic);

        consumer = create_input_consumer(brokers, input_topic, producer);

        fprintf(stdout,
                "Expecting integers to sum on input topic %s ...\n"
                "To generate input messages you can use:\n"
                "  $ seq 1 100 | examples/producer %s %s\n"
                "Observe summed integers on output topic %s:\n"
                "  $ examples/consumer %s just-watching %s\n"
                "\n",
                input_topic, brokers, input_topic,
                output_topic, brokers, output_topic);

        /* Begin transaction and start waiting for messages */
        error = rd_kafka_begin_transaction(producer);
        if (error)
                fatal_error("Failed to begin transaction", error);

        while (run) {
                rd_kafka_message_t *msg;

                /* Commit transaction every 100 messages or 5 seconds */
                if (msgcnt > 0 &&
                    (msgcnt > 100 || last_commit + 5 <= time(NULL))) {
                        printf("msgcnt %d, elapsed %d\n", msgcnt,
                               (int)(time(NULL) - last_commit));
                        commit_transaction_and_start_new(consumer, producer);
                        msgcnt = 0;
                        last_commit = time(NULL);
                }

                /* Wait for new mesages or error events */
                msg = rd_kafka_consumer_poll(consumer, 1000/*1 second*/);
                if (!msg)
                        continue; /* Poll timeout */

                if (msg->err) {
                        /* Client errors are typically just informational
                         * since the client will automatically try to recover
                         * from all types of errors.
                         * It is thus sufficient for the application to log and
                         * continue operating when a consumer error is
                         * encountered. */
                        fprintf(stderr, "WARNING: Consumer error: %s\n",
                                rd_kafka_message_errstr(msg));
                        rd_kafka_message_destroy(msg);
                        continue;
                }

                /* Process message */
                process_message(consumer, producer, output_topic, msg);

                rd_kafka_message_destroy(msg);

                msgcnt++;
        }

        fprintf(stdout, "Closing consumer\n");
        rd_kafka_consumer_close(consumer);
        rd_kafka_destroy(consumer);

        fprintf(stdout, "Closing producer\n");
        rd_kafka_destroy(producer);

        return 0;
}
