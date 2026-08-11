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

/**
 * @name Transactions example for Apache Kafka <= 2.4.0 (no KIP-447 support).
 *
 * This example show-cases a simple transactional consume-process-produce
 * application that reads messages from an input topic, extracts all
 * numbers from the message's value string, adds them up, and sends
 * the sum to the output topic as part of a transaction.
 * The transaction is committed every 5 seconds or 100 messages, whichever
 * comes first. As the transaction is committed a new transaction is started.
 *
 * @remark This example does not yet support incremental rebalancing and thus
 *         not the cooperative-sticky partition.assignment.strategy.
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

static rd_kafka_t *consumer;

/* From command-line arguments */
static const char *brokers, *input_topic, *output_topic;


/**
 * @struct This is the per input partition state, constisting of
 * a transactional producer and the in-memory state for the current transaction.
 * This demo simply finds all numbers (ascii string numbers) in the message
 * payload and adds them.
 */
struct state {
        rd_kafka_t *producer; /**< Per-input partition output producer */
        rd_kafka_topic_partition_t *rktpar; /**< Back-pointer to the
                                             *   input partition. */
        time_t last_commit;                 /**< Last transaction commit */
        int msgcnt; /**< Number of messages processed in current txn */
};
/* Current assignment for the input consumer.
 * The .opaque field of each partition points to an allocated 'struct state'.
 */
static rd_kafka_topic_partition_list_t *assigned_partitions;



/**
 * @brief A fatal error has occurred, immediately exit the application.
 */
#define fatal(...)                                                             \
        do {                                                                   \
                fprintf(stderr, "FATAL ERROR: ");                              \
                fprintf(stderr, __VA_ARGS__);                                  \
                fprintf(stderr, "\n");                                         \
                exit(1);                                                       \
        } while (0)

/**
 * @brief Same as fatal() but takes an rd_kafka_error_t object, prints its
 *        error message, destroys the object and then exits fatally.
 */
#define fatal_error(what, error)                                               \
        do {                                                                   \
                fprintf(stderr, "FATAL ERROR: %s: %s: %s\n", what,             \
                        rd_kafka_error_name(error),                            \
                        rd_kafka_error_string(error));                         \
                rd_kafka_error_destroy(error);                                 \
                exit(1);                                                       \
        } while (0)

/**
 * @brief Signal termination of program
 */
static void stop(int sig) {
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
static void
dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
        if (rkmessage->err)
                fprintf(stderr, "%% Message delivery failed: %s\n",
                        rd_kafka_err2str(rkmessage->err));

        /* The rkmessage is destroyed automatically by librdkafka */
}



/**
 * @brief Create a transactional producer for the given input pratition
 *        and begin a new transaction.
 */
static rd_kafka_t *
create_transactional_producer(const rd_kafka_topic_partition_t *rktpar) {
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        rd_kafka_t *rk;
        char errstr[256];
        rd_kafka_error_t *error;
        char transactional_id[256];

        snprintf(transactional_id, sizeof(transactional_id),
                 "librdkafka_transactions_older_example_%s-%d", rktpar->topic,
                 rktpar->partition);

        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            rd_kafka_conf_set(conf, "transactional.id", transactional_id,
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            rd_kafka_conf_set(conf, "transaction.timeout.ms", "60000", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK)
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


        /* Begin a new transaction */
        error = rd_kafka_begin_transaction(rk);
        if (error)
                fatal_error("begin_transaction()", error);

        return rk;
}


/**
 * @brief Abort the current transaction and destroy the producer.
 */
static void destroy_transactional_producer(rd_kafka_t *rk) {
        rd_kafka_error_t *error;

        fprintf(stdout, "%s: aborting transaction and terminating producer\n",
                rd_kafka_name(rk));

        /* Abort the current transaction, ignore any errors
         * since we're terminating the producer anyway. */
        error = rd_kafka_abort_transaction(rk, -1);
        if (error) {
                fprintf(stderr,
                        "WARNING: Ignoring abort_transaction() error since "
                        "producer is being destroyed: %s\n",
                        rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
        }

        rd_kafka_destroy(rk);
}



/**
 * @brief Abort the current transaction and rewind consumer offsets to
 *        position where the transaction last started, i.e., the committed
 *        consumer offset.
 */
static void abort_transaction_and_rewind(struct state *state) {
        rd_kafka_topic_t *rkt =
            rd_kafka_topic_new(consumer, state->rktpar->topic, NULL);
        rd_kafka_topic_partition_list_t *offset;
        rd_kafka_resp_err_t err;
        rd_kafka_error_t *error;

        fprintf(stdout,
                "Aborting transaction and rewinding offset for %s [%d]\n",
                state->rktpar->topic, state->rktpar->partition);

        /* Abort the current transaction */
        error = rd_kafka_abort_transaction(state->producer, -1);
        if (error)
                fatal_error("Failed to abort transaction", error);

        /* Begin a new transaction */
        error = rd_kafka_begin_transaction(state->producer);
        if (error)
                fatal_error("Failed to begin transaction", error);

        /* Get committed offset for this partition */
        offset = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offset, state->rktpar->topic,
                                          state->rktpar->partition);

        /* Note: Timeout must be lower than max.poll.interval.ms */
        err = rd_kafka_committed(consumer, offset, 10 * 1000);
        if (err)
                fatal("Failed to acquire committed offset for %s [%d]: %s",
                      state->rktpar->topic, (int)state->rktpar->partition,
                      rd_kafka_err2str(err));

        /* Seek to committed offset, or start of partition if no
         * no committed offset is available. */
        err = rd_kafka_seek(rkt, state->rktpar->partition,
                            offset->elems[0].offset < 0
                                ?
                                /* No committed offset, start from beginning */
                                RD_KAFKA_OFFSET_BEGINNING
                                :
                                /* Use committed offset */
                                offset->elems[0].offset,
                            0);

        if (err)
                fatal("Failed to seek %s [%d]: %s", state->rktpar->topic,
                      (int)state->rktpar->partition, rd_kafka_err2str(err));

        rd_kafka_topic_destroy(rkt);
}


/**
 * @brief Commit the current transaction and start a new transaction.
 */
static void commit_transaction_and_start_new(struct state *state) {
        rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        rd_kafka_consumer_group_metadata_t *cgmd;
        rd_kafka_topic_partition_list_t *offset;

        fprintf(stdout, "Committing transaction for %s [%d]\n",
                state->rktpar->topic, state->rktpar->partition);

        /* Send the input consumer's offset to transaction
         * to commit those offsets along with the transaction itself,
         * this is what guarantees exactly-once-semantics (EOS), that
         * input (offsets) and output (messages) are committed atomically. */

        /* Get the consumer's current group state */
        cgmd = rd_kafka_consumer_group_metadata(consumer);

        /* Get consumer's current position for this partition */
        offset = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(offset, state->rktpar->topic,
                                          state->rktpar->partition);
        err = rd_kafka_position(consumer, offset);
        if (err)
                fatal("Failed to get consumer position for %s [%d]: %s",
                      state->rktpar->topic, state->rktpar->partition,
                      rd_kafka_err2str(err));

        /* Send offsets to transaction coordinator */
        error = rd_kafka_send_offsets_to_transaction(state->producer, offset,
                                                     cgmd, -1);
        rd_kafka_consumer_group_metadata_destroy(cgmd);
        rd_kafka_topic_partition_list_destroy(offset);
        if (error) {
                if (rd_kafka_error_txn_requires_abort(error)) {
                        fprintf(stderr,
                                "WARNING: Failed to send offsets to "
                                "transaction: %s: %s: aborting transaction\n",
                                rd_kafka_error_name(error),
                                rd_kafka_error_string(error));
                        rd_kafka_error_destroy(error);
                        abort_transaction_and_rewind(state);
                        return;
                } else {
                        fatal_error("Failed to send offsets to transaction",
                                    error);
                }
        }

        /* Commit the transaction */
        error = rd_kafka_commit_transaction(state->producer, -1);
        if (error) {
                if (rd_kafka_error_txn_requires_abort(error)) {
                        fprintf(stderr,
                                "WARNING: Failed to commit transaction: "
                                "%s: %s: aborting transaction\n",
                                rd_kafka_error_name(error),
                                rd_kafka_error_string(error));
                        abort_transaction_and_rewind(state);
                        rd_kafka_error_destroy(error);
                        return;
                } else {
                        fatal_error("Failed to commit transaction", error);
                }
        }

        /* Begin new transaction */
        error = rd_kafka_begin_transaction(state->producer);
        if (error)
                fatal_error("Failed to begin new transaction", error);
}

/**
 * @brief The rebalance will be triggered (from rd_kafka_consumer_poll())
 *        when the consumer's partition assignment is assigned or revoked.
 *
 * Prior to KIP-447 being supported there must be one transactional output
 * producer for each consumed input partition, so we create and destroy
 * these producer's from this callback.
 */
static void
consumer_group_rebalance_cb(rd_kafka_t *rk,
                            rd_kafka_resp_err_t err,
                            rd_kafka_topic_partition_list_t *partitions,
                            void *opaque) {
        int i;

        if (!strcmp(rd_kafka_rebalance_protocol(rk), "COOPERATIVE"))
                fatal(
                    "This example has not yet been modified to work with "
                    "cooperative incremental rebalancing "
                    "(partition.assignment.strategy=cooperative-sticky)");

        switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS:
                assigned_partitions =
                    rd_kafka_topic_partition_list_copy(partitions);

                fprintf(stdout, "Consumer group rebalanced, new assignment:\n");

                /* Create a transactional producer for each input partition */
                for (i = 0; i < assigned_partitions->cnt; i++) {
                        /* Store the partition-to-producer mapping
                         * in the partition's opaque field. */
                        rd_kafka_topic_partition_t *rktpar =
                            &assigned_partitions->elems[i];
                        struct state *state = calloc(1, sizeof(*state));

                        state->producer = create_transactional_producer(rktpar);
                        state->rktpar   = rktpar;
                        rktpar->opaque  = state;
                        state->last_commit = time(NULL);

                        fprintf(stdout,
                                " %s [%d] with transactional producer %s\n",
                                rktpar->topic, rktpar->partition,
                                rd_kafka_name(state->producer));
                }

                /* Let the consumer know the rebalance has been handled
                 * by calling assign.
                 * This will also tell the consumer to start fetching messages
                 * for the assigned partitions. */
                rd_kafka_assign(rk, partitions);
                break;

        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                fprintf(stdout,
                        "Consumer group rebalanced, assignment revoked\n");

                /* Abort the current transactions and destroy all producers */
                for (i = 0; i < assigned_partitions->cnt; i++) {
                        /* Store the partition-to-producer mapping
                         * in the partition's opaque field. */
                        struct state *state =
                            (struct state *)assigned_partitions->elems[i]
                                .opaque;

                        destroy_transactional_producer(state->producer);
                        free(state);
                }

                rd_kafka_topic_partition_list_destroy(assigned_partitions);
                assigned_partitions = NULL;

                /* Let the consumer know the rebalance has been handled
                 * and revoke the current assignment. */
                rd_kafka_assign(rk, NULL);
                break;

        default:
                /* NOTREACHED */
                fatal("Unexpected rebalance event: %s", rd_kafka_err2name(err));
        }
}


/**
 * @brief Create the input consumer.
 */
static rd_kafka_t *create_input_consumer(const char *brokers,
                                         const char *input_topic) {
        rd_kafka_conf_t *conf = rd_kafka_conf_new();
        rd_kafka_t *rk;
        char errstr[256];
        rd_kafka_resp_err_t err;
        rd_kafka_topic_partition_list_t *topics;

        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            rd_kafka_conf_set(conf, "group.id",
                              "librdkafka_transactions_older_example_group",
                              errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
            /* The input consumer's offsets are explicitly committed with the
             * output producer's transaction using
             * rd_kafka_send_offsets_to_transaction(), so auto commits
             * must be disabled. */
            rd_kafka_conf_set(conf, "enable.auto.commit", "false", errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fatal("Failed to configure consumer: %s", errstr);
        }

        /* This callback will be called when the consumer group is rebalanced
         * and the consumer's partition assignment is assigned or revoked. */
        rd_kafka_conf_set_rebalance_cb(conf, consumer_group_rebalance_cb);

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
                fatal("Failed to subscribe to %s: %s\n", input_topic,
                      rd_kafka_err2str(err));
        }

        return rk;
}


/**
 * @brief Find and parse next integer string in \p start.
 * @returns Pointer after found integer string, or NULL if not found.
 */
static const void *
find_next_int(const void *start, const void *end, int *intp) {
        const char *p;
        int collecting = 0;
        int num        = 0;

        for (p = (const char *)start; p < (const char *)end; p++) {
                if (isdigit((int)(*p))) {
                        collecting = 1;
                        num        = (num * 10) + ((int)*p - ((int)'0'));
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
static void process_message(struct state *state,
                            const rd_kafka_message_t *rkmessage) {
        int num;
        long unsigned sum = 0;
        const void *p, *end;
        rd_kafka_resp_err_t err;
        char value[64];

        if (rkmessage->len == 0)
                return; /* Ignore empty messages */

        p   = rkmessage->payload;
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
                    state->producer, RD_KAFKA_V_TOPIC(output_topic),
                    /* Use same key as input message */
                    RD_KAFKA_V_KEY(rkmessage->key, rkmessage->key_len),
                    /* Value is the current sum of this
                     * transaction. */
                    RD_KAFKA_V_VALUE(value, strlen(value)),
                    /* Copy value since it is allocated on the stack */
                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY), RD_KAFKA_V_END);

                if (!err)
                        break;
                else if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
                        /* If output queue fills up we need to wait for
                         * some delivery reports and then retry. */
                        rd_kafka_poll(state->producer, 100);
                        continue;
                } else {
                        fprintf(stderr,
                                "WARNING: Failed to produce message to %s: "
                                "%s: aborting transaction\n",
                                output_topic, rd_kafka_err2str(err));
                        abort_transaction_and_rewind(state);
                        return;
                }
        }
}


int main(int argc, char **argv) {
        /*
         * Argument validation
         */
        if (argc != 4) {
                fprintf(stderr,
                        "%% Usage: %s <broker> <input-topic> <output-topic>\n",
                        argv[0]);
                return 1;
        }

        brokers      = argv[1];
        input_topic  = argv[2];
        output_topic = argv[3];

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        consumer = create_input_consumer(brokers, input_topic);

        fprintf(stdout,
                "Expecting integers to sum on input topic %s ...\n"
                "To generate input messages you can use:\n"
                "  $ seq 1 100 | examples/producer %s %s\n",
                input_topic, brokers, input_topic);

        while (run) {
                rd_kafka_message_t *msg;
                struct state *state;
                rd_kafka_topic_partition_t *rktpar;

                /* Wait for new mesages or error events */
                msg = rd_kafka_consumer_poll(consumer, 1000 /*1 second*/);
                if (!msg)
                        continue;

                if (msg->err) {
                        /* Client errors are typically just informational
                         * since the client will automatically try to recover
                         * from all types of errors.
                         * It is thus sufficient for the application to log and
                         * continue operating when an error is received. */
                        fprintf(stderr, "WARNING: Consumer error: %s\n",
                                rd_kafka_message_errstr(msg));
                        rd_kafka_message_destroy(msg);
                        continue;
                }

                /* Find output producer for this input partition */
                rktpar = rd_kafka_topic_partition_list_find(
                    assigned_partitions, rd_kafka_topic_name(msg->rkt),
                    msg->partition);
                if (!rktpar)
                        fatal(
                            "BUG: No output producer for assigned "
                            "partition %s [%d]",
                            rd_kafka_topic_name(msg->rkt), (int)msg->partition);

                /* Get state struct for this partition */
                state = (struct state *)rktpar->opaque;

                /* Process message */
                process_message(state, msg);

                rd_kafka_message_destroy(msg);

                /* Commit transaction every 100 messages or 5 seconds */
                if (++state->msgcnt > 100 ||
                    state->last_commit + 5 <= time(NULL)) {
                        commit_transaction_and_start_new(state);
                        state->msgcnt      = 0;
                        state->last_commit = time(NULL);
                }
        }

        fprintf(stdout, "Closing consumer\n");
        rd_kafka_consumer_close(consumer);

        rd_kafka_destroy(consumer);

        return 0;
}
