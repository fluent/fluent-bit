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
 * Example utility that shows how to use DeleteRecords (AdminAPI)
 * do delete all messages/records up to (but not including) a specific offset
 * from one or more topic partitions.
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>


/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"


static rd_kafka_queue_t *queue; /** Admin result queue.
                                 *  This is a global so we can
                                 *  yield in stop() */
static volatile sig_atomic_t run = 1;

/**
 * @brief Signal termination of program
 */
static void stop(int sig) {
        if (!run) {
                fprintf(stderr, "%% Forced termination\n");
                exit(2);
        }
        run = 0;
        rd_kafka_queue_yield(queue);
}


/**
 * @brief Parse an integer or fail.
 */
int64_t parse_int(const char *what, const char *str) {
        char *end;
        unsigned long n = strtoull(str, &end, 0);

        if (end != str + strlen(str)) {
                fprintf(stderr, "%% Invalid input for %s: %s: not an integer\n",
                        what, str);
                exit(1);
        }

        return (int64_t)n;
}


int main(int argc, char **argv) {
        rd_kafka_conf_t *conf; /* Temporary configuration object */
        char errstr[512];      /* librdkafka API error reporting buffer */
        const char *brokers;   /* Argument: broker list */
        rd_kafka_t *rk;        /* Admin client instance */
        rd_kafka_topic_partition_list_t *offsets_before; /* Delete messages up
                                                          * to but not
                                                          * including these
                                                          * offsets */
        rd_kafka_DeleteRecords_t *del_records; /* Container for offsets_before*/
        rd_kafka_AdminOptions_t *options;      /* (Optional) Options for
                                                * DeleteRecords() */
        rd_kafka_event_t *event;               /* DeleteRecords result event */
        int exitcode = 0;
        int i;

        /*
         * Argument validation
         */
        if (argc < 5 || (argc - 2) % 3 != 0) {
                fprintf(stderr,
                        "%% Usage: %s <broker> "
                        "<topic> <partition> <offset_before> "
                        "<topic2> <partition2> <offset_before2> ...\n"
                        "\n"
                        "Delete all messages up to but not including the "
                        "specified offset(s).\n"
                        "\n",
                        argv[0]);
                return 1;
        }

        brokers = argv[1];

        /* Parse topic partition offset tuples and add to offsets list */
        offsets_before = rd_kafka_topic_partition_list_new((argc - 2) / 3);
        for (i = 2; i < argc; i += 3) {
                const char *topic = argv[i];
                int partition     = parse_int("partition", argv[i + 1]);
                int64_t offset    = parse_int("offset_before", argv[i + 2]);

                rd_kafka_topic_partition_list_add(offsets_before, topic,
                                                  partition)
                    ->offset = offset;
        }

        /*
         * Create Kafka client configuration place-holder
         */
        conf = rd_kafka_conf_new();

        /* Set bootstrap broker(s) as a comma-separated list of
         * host or host:port (default port 9092).
         * librdkafka will use the bootstrap brokers to acquire the full
         * set of brokers from the cluster. */
        if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr,
                              sizeof(errstr)) != RD_KAFKA_CONF_OK) {
                fprintf(stderr, "%s\n", errstr);
                return 1;
        }
        rd_kafka_conf_set(conf, "debug", "admin,topic,metadata", NULL, 0);

        /*
         * Create an admin client, it can be created using any client type,
         * so we choose producer since it requires no extra configuration
         * and is more light-weight than the consumer.
         *
         * NOTE: rd_kafka_new() takes ownership of the conf object
         *       and the application must not reference it again after
         *       this call.
         */
        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        if (!rk) {
                fprintf(stderr, "%% Failed to create new producer: %s\n",
                        errstr);
                return 1;
        }

        /* The Admin API is completely asynchronous, results are emitted
         * on the result queue that is passed to DeleteRecords() */
        queue = rd_kafka_queue_new(rk);

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        /* Set timeout (optional) */
        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DELETERECORDS);
        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 30 * 1000 /* 30s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                return 1;
        }

        /* Create argument */
        del_records = rd_kafka_DeleteRecords_new(offsets_before);
        /* We're now done with offsets_before */
        rd_kafka_topic_partition_list_destroy(offsets_before);

        /* Call DeleteRecords */
        rd_kafka_DeleteRecords(rk, &del_records, 1, options, queue);

        /* Clean up input arguments */
        rd_kafka_DeleteRecords_destroy(del_records);
        rd_kafka_AdminOptions_destroy(options);


        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /*indefinitely*/);

        if (!event) {
                /* User hit Ctrl-C */
                fprintf(stderr, "%% Cancelled by user\n");

        } else if (rd_kafka_event_error(event)) {
                /* DeleteRecords request failed */
                fprintf(stderr, "%% DeleteRecords failed: %s\n",
                        rd_kafka_event_error_string(event));
                exitcode = 2;

        } else {
                /* DeleteRecords request succeeded, but individual
                 * partitions may have errors. */
                const rd_kafka_DeleteRecords_result_t *result;
                const rd_kafka_topic_partition_list_t *offsets;
                int i;

                result  = rd_kafka_event_DeleteRecords_result(event);
                offsets = rd_kafka_DeleteRecords_result_offsets(result);

                printf("DeleteRecords results:\n");
                for (i = 0; i < offsets->cnt; i++)
                        printf(" %s [%" PRId32 "] offset %" PRId64 ": %s\n",
                               offsets->elems[i].topic,
                               offsets->elems[i].partition,
                               offsets->elems[i].offset,
                               rd_kafka_err2str(offsets->elems[i].err));
        }

        /* Destroy event object when we're done with it.
         * Note: rd_kafka_event_destroy() allows a NULL event. */
        rd_kafka_event_destroy(event);

        signal(SIGINT, SIG_DFL);

        /* Destroy queue */
        rd_kafka_queue_destroy(queue);

        /* Destroy the producer instance */
        rd_kafka_destroy(rk);

        return exitcode;
}
