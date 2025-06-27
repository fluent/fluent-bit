/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2022, Magnus Edenhill
 *               2023, Confluent Inc.
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
 * DescribeConsumerGroups usage example.
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
                "Describe groups usage examples\n"
                "\n"
                "Usage: %s <options> <include_authorized_operations> <group1> "
                "<group2> ...\n"
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
 * @brief Print group member information.
 */
static void
print_group_member_info(const rd_kafka_MemberDescription_t *member) {
        printf(
            "  Member \"%s\" with client-id %s,"
            " group instance id: %s, host %s\n",
            rd_kafka_MemberDescription_consumer_id(member),
            rd_kafka_MemberDescription_client_id(member),
            rd_kafka_MemberDescription_group_instance_id(member),
            rd_kafka_MemberDescription_host(member));
        const rd_kafka_MemberAssignment_t *assignment =
            rd_kafka_MemberDescription_assignment(member);
        const rd_kafka_topic_partition_list_t *topic_partitions =
            rd_kafka_MemberAssignment_partitions(assignment);
        if (!topic_partitions) {
                printf("    No assignment\n");
        } else if (topic_partitions->cnt == 0) {
                printf("    Empty assignment\n");
        } else {
                printf("    Assignment:\n");
                print_partition_list(stdout, topic_partitions, 0, "      ");
        }
}


/**
 * @brief Print group information.
 */
static void print_group_info(const rd_kafka_ConsumerGroupDescription_t *group) {
        int member_cnt;
        size_t j;
        size_t authorized_operations_cnt;
        const rd_kafka_AclOperation_t *authorized_operations;
        const rd_kafka_error_t *error;
        char coordinator_desc[512];
        const rd_kafka_Node_t *coordinator = NULL;
        const char *group_id =
            rd_kafka_ConsumerGroupDescription_group_id(group);
        const char *partition_assignor =
            rd_kafka_ConsumerGroupDescription_partition_assignor(group);
        rd_kafka_consumer_group_state_t state =
            rd_kafka_ConsumerGroupDescription_state(group);
        authorized_operations =
            rd_kafka_ConsumerGroupDescription_authorized_operations(
                group, &authorized_operations_cnt);
        member_cnt  = rd_kafka_ConsumerGroupDescription_member_count(group);
        error       = rd_kafka_ConsumerGroupDescription_error(group);
        coordinator = rd_kafka_ConsumerGroupDescription_coordinator(group);
        *coordinator_desc = '\0';

        if (coordinator != NULL) {
                snprintf(coordinator_desc, sizeof(coordinator_desc),
                         ", coordinator [id: %" PRId32
                         ", host: %s"
                         ", port: %" PRIu16 "]",
                         rd_kafka_Node_id(coordinator),
                         rd_kafka_Node_host(coordinator),
                         rd_kafka_Node_port(coordinator));
        }
        printf(
            "Group \"%s\", partition assignor \"%s\", "
            " state %s%s, with %" PRId32 " member(s)\n",
            group_id, partition_assignor,
            rd_kafka_consumer_group_state_name(state), coordinator_desc,
            member_cnt);
        for (j = 0; j < authorized_operations_cnt; j++) {
                printf("%s operation is allowed\n",
                       rd_kafka_AclOperation_name(authorized_operations[j]));
        }
        if (error)
                printf(" error[%" PRId32 "]: %s", rd_kafka_error_code(error),
                       rd_kafka_error_string(error));
        printf("\n");
        for (j = 0; j < (size_t)member_cnt; j++) {
                const rd_kafka_MemberDescription_t *member =
                    rd_kafka_ConsumerGroupDescription_member(group, j);
                print_group_member_info(member);
        }
}


/**
 * @brief Print groups information.
 */
static int
print_groups_info(const rd_kafka_DescribeConsumerGroups_result_t *grpdesc,
                  int groups_cnt) {
        size_t i;
        const rd_kafka_ConsumerGroupDescription_t **result_groups;
        size_t result_groups_cnt;
        result_groups = rd_kafka_DescribeConsumerGroups_result_groups(
            grpdesc, &result_groups_cnt);

        if (result_groups_cnt == 0) {
                if (groups_cnt > 0) {
                        fprintf(stderr, "No matching groups found\n");
                        return 1;
                } else {
                        fprintf(stderr, "No groups in cluster\n");
                }
        }

        for (i = 0; i < result_groups_cnt; i++) {
                print_group_info(result_groups[i]);
                printf("\n");
        }
        return 0;
}

/**
 * @brief Parse an integer or fail.
 */
int64_t parse_int(const char *what, const char *str) {
        char *end;
        long n = strtol(str, &end, 0);

        if (end != str + strlen(str)) {
                fprintf(stderr, "%% Invalid input for %s: %s: not an integer\n",
                        what, str);
                exit(1);
        }

        return (int64_t)n;
}

/**
 * @brief Call rd_kafka_DescribeConsumerGroups() with a list of
 * groups.
 */
static void
cmd_describe_consumer_groups(rd_kafka_conf_t *conf, int argc, char **argv) {
        rd_kafka_t *rk      = NULL;
        const char **groups = NULL;
        char errstr[512];
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_event_t *event          = NULL;
        rd_kafka_error_t *error;
        int retval         = 0;
        int groups_cnt     = 0;
        const int min_argc = 2;
        int include_authorized_operations;

        if (argc < min_argc)
                usage("Wrong number of arguments");

        include_authorized_operations =
            parse_int("include_authorized_operations", argv[0]);
        if (include_authorized_operations < 0 ||
            include_authorized_operations > 1)
                usage("include_authorized_operations not a 0-1 int");

        groups     = (const char **)&argv[1];
        groups_cnt = argc - 1;

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
         * Describe consumer groups
         */
        queue = rd_kafka_queue_new(rk);

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_DESCRIBECONSUMERGROUPS);

        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 10 * 1000 /* 10s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                retval = 1;
                goto exit;
        }
        if ((error = rd_kafka_AdminOptions_set_include_authorized_operations(
                 options, include_authorized_operations))) {
                fprintf(stderr,
                        "%% Failed to set require authorized operations: %s\n",
                        rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
                retval = 1;
                goto exit;
        }

        rd_kafka_DescribeConsumerGroups(rk, groups, groups_cnt, options, queue);

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
                /* DescribeConsumerGroups request failed */
                fprintf(stderr,
                        "%% DescribeConsumerGroups failed[%" PRId32 "]: %s\n",
                        err, rd_kafka_event_error_string(event));
                retval = 1;

        } else {
                /* DescribeConsumerGroups request succeeded, but individual
                 * groups may have errors. */
                const rd_kafka_DescribeConsumerGroups_result_t *result;

                result = rd_kafka_event_DescribeConsumerGroups_result(event);
                printf("DescribeConsumerGroups results:\n");
                retval = print_groups_info(result, groups_cnt);
        }


exit:
        /* Cleanup. */
        if (event)
                rd_kafka_event_destroy(event);
        if (options)
                rd_kafka_AdminOptions_destroy(options);
        if (queue)
                rd_kafka_queue_destroy(queue);
        if (rk)
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

        cmd_describe_consumer_groups(conf, argc - optind, &argv[optind]);

        return 0;
}
