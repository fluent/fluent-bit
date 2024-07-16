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
 * ListConsumerGroups usage example.
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
                "List groups usage examples\n"
                "\n"
                "Usage: %s <options> <state1> <state2> ...\n"
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

/**
 * @brief Print group information.
 */
static int print_groups_info(const rd_kafka_ListConsumerGroups_result_t *list) {
        size_t i;
        const rd_kafka_ConsumerGroupListing_t **result_groups;
        const rd_kafka_error_t **errors;
        size_t result_groups_cnt;
        size_t result_error_cnt;
        result_groups =
            rd_kafka_ListConsumerGroups_result_valid(list, &result_groups_cnt);
        errors =
            rd_kafka_ListConsumerGroups_result_errors(list, &result_error_cnt);

        if (result_groups_cnt == 0) {
                fprintf(stderr, "No matching groups found\n");
        }

        for (i = 0; i < result_groups_cnt; i++) {
                const rd_kafka_ConsumerGroupListing_t *group = result_groups[i];
                const char *group_id =
                    rd_kafka_ConsumerGroupListing_group_id(group);
                rd_kafka_consumer_group_state_t state =
                    rd_kafka_ConsumerGroupListing_state(group);
                int is_simple_consumer_group =
                    rd_kafka_ConsumerGroupListing_is_simple_consumer_group(
                        group);

                printf("Group \"%s\", is simple %" PRId32
                       ", "
                       "state %s",
                       group_id, is_simple_consumer_group,
                       rd_kafka_consumer_group_state_name(state));
                printf("\n");
        }
        for (i = 0; i < result_error_cnt; i++) {
                const rd_kafka_error_t *error = errors[i];
                printf("Error[%" PRId32 "]: %s\n", rd_kafka_error_code(error),
                       rd_kafka_error_string(error));
        }
        return 0;
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

/**
 * @brief Call rd_kafka_ListConsumerGroups() with a list of
 * groups.
 */
static void
cmd_list_consumer_groups(rd_kafka_conf_t *conf, int argc, char **argv) {
        rd_kafka_t *rk;
        const char **states_str = NULL;
        char errstr[512];
        rd_kafka_AdminOptions_t *options;
        rd_kafka_event_t *event = NULL;
        rd_kafka_error_t *error = NULL;
        int i;
        int retval     = 0;
        int states_cnt = 0;
        rd_kafka_consumer_group_state_t *states;


        if (argc >= 1) {
                states_str = (const char **)&argv[0];
                states_cnt = argc;
        }
        states = calloc(states_cnt, sizeof(rd_kafka_consumer_group_state_t));
        for (i = 0; i < states_cnt; i++) {
                states[i] = parse_int("state code", states_str[i]);
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
         * List consumer groups
         */
        queue = rd_kafka_queue_new(rk);

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_LISTCONSUMERGROUPS);

        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 10 * 1000 /* 10s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                goto exit;
        }

        if ((error = rd_kafka_AdminOptions_set_match_consumer_group_states(
                 options, states, states_cnt))) {
                fprintf(stderr, "%% Failed to set states: %s\n",
                        rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
                goto exit;
        }
        free(states);

        rd_kafka_ListConsumerGroups(rk, options, queue);
        rd_kafka_AdminOptions_destroy(options);

        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /* indefinitely but limited by
                                               * the request timeout set
                                               * above (10s) */);

        if (!event) {
                /* User hit Ctrl-C,
                 * see yield call in stop() signal handler */
                fprintf(stderr, "%% Cancelled by user\n");

        } else if (rd_kafka_event_error(event)) {
                rd_kafka_resp_err_t err = rd_kafka_event_error(event);
                /* ListConsumerGroups request failed */
                fprintf(stderr,
                        "%% ListConsumerGroups failed[%" PRId32 "]: %s\n", err,
                        rd_kafka_event_error_string(event));
                goto exit;

        } else {
                /* ListConsumerGroups request succeeded, but individual
                 * groups may have errors. */
                const rd_kafka_ListConsumerGroups_result_t *result;

                result = rd_kafka_event_ListConsumerGroups_result(event);
                printf("ListConsumerGroups results:\n");
                retval = print_groups_info(result);
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

        cmd_list_consumer_groups(conf, argc - optind, &argv[optind]);

        return 0;
}
