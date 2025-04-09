/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2024, Confluent Inc.
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
 * ARE DISCLAIMED. IN NO EVENT SH THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Example utility that shows how to use Elect Leaders (AdminAPI)
 * to trigger preffered or unclean elections for
 * one or more topic partitions.
 */

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

static rd_kafka_queue_t *queue = NULL; /** Admin result queue.
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
        if (queue)
                rd_kafka_queue_yield(queue);
}

static void usage(const char *reason, ...) {

        fprintf(stderr,
                "Elect Leaders usage examples\n"
                "\n"
                "Usage: %s <options> <election_type> "
                "<topic1> <partition1> ...\n"
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
print_elect_leaders_result(const rd_kafka_ElectLeaders_result_t *result) {
        const rd_kafka_topic_partition_result_t **results;
        size_t results_cnt;
        size_t i;

        results = rd_kafka_ElectLeaders_result_partitions(result, &results_cnt);
        printf("ElectLeaders response has %zu partition(s):\n", results_cnt);
        for (i = 0; i < results_cnt; i++) {
                const rd_kafka_topic_partition_t *partition =
                    rd_kafka_topic_partition_result_partition(results[i]);
                const rd_kafka_error_t *err =
                    rd_kafka_topic_partition_result_error(results[i]);
                if (rd_kafka_error_code(err)) {
                        printf("%% ElectLeaders failed for %s [%" PRId32
                               "] : %s\n",
                               partition->topic, partition->partition,
                               rd_kafka_error_string(err));
                } else {
                        printf("%% ElectLeaders succeeded for %s [%" PRId32
                               "]\n",
                               partition->topic, partition->partition);
                }
        }
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

static void cmd_elect_leaders(rd_kafka_conf_t *conf, int argc, char **argv) {
        rd_kafka_t *rk;
        char errstr[512];
        rd_kafka_AdminOptions_t *options;
        rd_kafka_event_t *event                     = NULL;
        rd_kafka_topic_partition_list_t *partitions = NULL;
        rd_kafka_ElectionType_t election_type;
        rd_kafka_ElectLeaders_t *elect_leaders;
        int i;
        int retval = 0;

        if ((argc - 1) % 2 != 0) {
                usage("Invalid number of arguments");
        }

        election_type = parse_int("election_type", argv[0]);

        argc--;
        argv++;
        if (argc > 0) {
                partitions = rd_kafka_topic_partition_list_new(argc / 2);
                for (i = 0; i < argc; i += 2) {
                        rd_kafka_topic_partition_list_add(
                            partitions, argv[i],
                            parse_int("partition", argv[i + 1]));
                }
        }

        elect_leaders = rd_kafka_ElectLeaders_new(election_type, partitions);

        if (partitions) {
                rd_kafka_topic_partition_list_destroy(partitions);
        }

        /*
         * Create consumer instance
         * NOTE: rd_kafka_new() takes ownership of the conf object
         *       and the application must not reference it again after
         *       this call.
         */
        rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
        if (!rk)
                fatal("Failed to create new consumer: %s", errstr);

        /*
         * Elect Leaders
         */
        queue = rd_kafka_queue_new(rk);

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);


        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ELECTLEADERS);

        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 30 * 1000 /* 30s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                goto exit;
        }

        if (rd_kafka_AdminOptions_set_operation_timeout(
                options, 30 * 1000 /* 30s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set operation timeout: %s\n",
                        errstr);
                goto exit;
        }

        rd_kafka_ElectLeaders(rk, elect_leaders, options, queue);

        rd_kafka_ElectLeaders_destroy(elect_leaders);
        rd_kafka_AdminOptions_destroy(options);

        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /* indefinitely but limited by
                                               * the request timeout set
                                               * above  */);

        if (!event) {
                /* User hit Ctrl-C,
                 * see yield call in stop() signal handler */
                fprintf(stderr, "%% Cancelled by user\n");

        } else if (rd_kafka_event_error(event)) {
                rd_kafka_resp_err_t err = rd_kafka_event_error(event);
                /* ElectLeaders request failed */
                fprintf(stderr, "%% ElectLeaders failed[%" PRId32 "]: %s\n",
                        err, rd_kafka_event_error_string(event));
                retval = 1;
                goto exit;
        } else {
                /* ElectLeaders request succeeded */
                const rd_kafka_ElectLeaders_result_t *result;
                result = rd_kafka_event_ElectLeaders_result(event);
                print_elect_leaders_result(result);
        }


exit:
        if (event)
                rd_kafka_event_destroy(event);

        rd_kafka_queue_destroy(queue);
        /* Destroy the client instance */
        rd_kafka_destroy(rk);

        exit(retval);
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

        cmd_elect_leaders(conf, argc - optind, &argv[optind]);

        return 0;
}
