/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2022, Magnus Edenhill
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
 * AlterConsumerGroupOffsets usage example.
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef _WIN32
#include "../win32/wingetopt.h"
#else
#include <getopt.h>
#endif


/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is builtin from within the librdkafka source tree and thus differs. */
#include "rdkafka.h"


const char *argv0;

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


static void usage(const char *reason, ...) {

        fprintf(stderr,
                "Alter consumer group offsets usage examples\n"
                "\n"
                "Usage: %s <options> <group_id> <topic>\n"
                "                   <partition1> <offset1>\n"
                "                   <partition2> <offset2>\n"
                "                   ...\n"
                "\n"
                "Options:\n"
                "   -b <brokers>    Bootstrap server list to connect to.\n"
                "   -X <prop=val>   Set librdkafka configuration property.\n"
                "                   See CONFIGURATION.md for full list.\n"
                "   -d <dbg,..>     Enable librdkafka debugging (%s).\n"
                "\n",
                argv0, rd_kafka_get_debug_contexts());

        if (reason) {
                va_list ap;
                char reasonbuf[512];

                va_start(ap, reason);
                vsnprintf(reasonbuf, sizeof(reasonbuf), reason, ap);
                va_end(ap);

                fprintf(stderr, "ERROR: %s\n", reasonbuf);
        }

        exit(reason ? 1 : 0);
}


#define fatal(...)                                                             \
        do {                                                                   \
                fprintf(stderr, "ERROR: ");                                    \
                fprintf(stderr, __VA_ARGS__);                                  \
                fprintf(stderr, "\n");                                         \
                exit(2);                                                       \
        } while (0)


/**
 * @brief Set config property. Exit on failure.
 */
static void conf_set(rd_kafka_conf_t *conf, const char *name, const char *val) {
        char errstr[512];

        if (rd_kafka_conf_set(conf, name, val, errstr, sizeof(errstr)) !=
            RD_KAFKA_CONF_OK)
                fatal("Failed to set %s=%s: %s", name, val, errstr);
}


static void
print_partition_list(FILE *fp,
                     const rd_kafka_topic_partition_list_t *partitions,
                     int print_offset,
                     const char *prefix) {
        int i;

        if (partitions->cnt == 0) {
                fprintf(fp, "%sNo partition found", prefix);
        }
        for (i = 0; i < partitions->cnt; i++) {
                char offset_string[512] = {};
                *offset_string          = '\0';
                if (print_offset) {
                        snprintf(offset_string, sizeof(offset_string),
                                 " offset %" PRId64,
                                 partitions->elems[i].offset);
                }
                fprintf(fp, "%s%s %s [%" PRId32 "]%s error %s",
                        i > 0 ? "\n" : "", prefix, partitions->elems[i].topic,
                        partitions->elems[i].partition, offset_string,
                        rd_kafka_err2str(partitions->elems[i].err));
        }
        fprintf(fp, "\n");
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

static void
cmd_alter_consumer_group_offsets(rd_kafka_conf_t *conf, int argc, char **argv) {
        char errstr[512]; /* librdkafka API error reporting buffer */
        rd_kafka_t *rk;   /* Admin client instance */
        rd_kafka_AdminOptions_t *options; /* (Optional) Options for
                                           * AlterConsumerGroupOffsets() */
        rd_kafka_event_t *event; /* AlterConsumerGroupOffsets result event */
        const int min_argc = 2;
        int i, num_partitions = 0;
        const char *group_id, *topic;
        rd_kafka_AlterConsumerGroupOffsets_t *alter_consumer_group_offsets;

        /*
         * Argument validation
         */
        if (argc < min_argc || (argc - min_argc) % 2 != 0) {
                usage("Wrong number of arguments");
        }

        num_partitions = (argc - min_argc) / 2;
        group_id       = argv[0];
        topic          = argv[1];

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
                exit(1);
        }

        /* The Admin API is completely asynchronous, results are emitted
         * on the result queue that is passed to AlterConsumerGroupOffsets() */
        queue = rd_kafka_queue_new(rk);

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        /* Set timeout (optional) */
        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_ALTERCONSUMERGROUPOFFSETS);
        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 30 * 1000 /* 30s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                exit(1);
        }

        /* Read passed partition-offsets */
        rd_kafka_topic_partition_list_t *partitions =
            rd_kafka_topic_partition_list_new(num_partitions);
        for (i = 0; i < num_partitions; i++) {
                rd_kafka_topic_partition_list_add(
                    partitions, topic,
                    parse_int("partition", argv[min_argc + i * 2]))
                    ->offset = parse_int("offset", argv[min_argc + 1 + i * 2]);
        }

        /* Create argument */
        alter_consumer_group_offsets =
            rd_kafka_AlterConsumerGroupOffsets_new(group_id, partitions);
        /* Call AlterConsumerGroupOffsets */
        rd_kafka_AlterConsumerGroupOffsets(rk, &alter_consumer_group_offsets, 1,
                                           options, queue);

        /* Clean up input arguments */
        rd_kafka_AlterConsumerGroupOffsets_destroy(
            alter_consumer_group_offsets);
        rd_kafka_AdminOptions_destroy(options);
        rd_kafka_topic_partition_list_destroy(partitions);


        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /* indefinitely but limited by
                                               * the request timeout set
                                               * above (30s) */);

        if (!event) {
                /* User hit Ctrl-C,
                 * see yield call in stop() signal handler */
                fprintf(stderr, "%% Cancelled by user\n");

        } else if (rd_kafka_event_error(event)) {
                /* AlterConsumerGroupOffsets request failed */
                fprintf(stderr, "%% AlterConsumerGroupOffsets failed: %s\n",
                        rd_kafka_event_error_string(event));
                exit(1);

        } else {
                /* AlterConsumerGroupOffsets request succeeded, but individual
                 * partitions may have errors. */
                const rd_kafka_AlterConsumerGroupOffsets_result_t *result;
                const rd_kafka_group_result_t **groups;
                size_t n_groups, i;

                result = rd_kafka_event_AlterConsumerGroupOffsets_result(event);
                groups = rd_kafka_AlterConsumerGroupOffsets_result_groups(
                    result, &n_groups);

                printf("AlterConsumerGroupOffsets results:\n");
                for (i = 0; i < n_groups; i++) {
                        const rd_kafka_group_result_t *group = groups[i];
                        const rd_kafka_topic_partition_list_t *partitions =
                            rd_kafka_group_result_partitions(group);
                        print_partition_list(stderr, partitions, 1, "      ");
                }
        }

        /* Destroy event object when we're done with it.
         * Note: rd_kafka_event_destroy() allows a NULL event. */
        rd_kafka_event_destroy(event);

        /* Destroy queue */
        rd_kafka_queue_destroy(queue);

        /* Destroy the producer instance */
        rd_kafka_destroy(rk);
}

int main(int argc, char **argv) {
        rd_kafka_conf_t *conf; /**< Client configuration object */
        int opt;
        argv0 = argv[0];

        /*
         * Create Kafka client configuration place-holder
         */
        conf = rd_kafka_conf_new();


        /*
         * Parse common options
         */
        while ((opt = getopt(argc, argv, "b:X:d:")) != -1) {
                switch (opt) {
                case 'b':
                        conf_set(conf, "bootstrap.servers", optarg);
                        break;

                case 'X': {
                        char *name = optarg, *val;

                        if (!(val = strchr(name, '=')))
                                fatal("-X expects a name=value argument");

                        *val = '\0';
                        val++;

                        conf_set(conf, name, val);
                        break;
                }

                case 'd':
                        conf_set(conf, "debug", optarg);
                        break;

                default:
                        usage("Unknown option %c", (char)opt);
                }
        }

        cmd_alter_consumer_group_offsets(conf, argc - optind, &argv[optind]);

        return 0;
}
