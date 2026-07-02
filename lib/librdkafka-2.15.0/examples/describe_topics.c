/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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
 * DescribeTopics usage example.
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
                "Describe topics usage examples\n"
                "\n"
                "Usage: %s <options> <include_topic_authorized_operations> "
                "<topic1> <topic2> ...\n"
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
 * @brief Print node information.
 */
static void print_node_info(const rd_kafka_Node_t *node) {
        if (!node) {
                printf("\t\t(null)\n");
                return;
        }

        printf("\t\tNode [id: %" PRId32
               ", host: %s"
               ", port: %" PRIu16 ", rack %s]\n",
               rd_kafka_Node_id(node), rd_kafka_Node_host(node),
               rd_kafka_Node_port(node), rd_kafka_Node_rack(node));
}

/**
 * @brief Print partition information.
 */
static void
print_partition_info(const rd_kafka_TopicPartitionInfo_t *partition) {
        size_t k;
        int id;
        const rd_kafka_Node_t **isr;
        size_t isr_cnt;
        const rd_kafka_Node_t **replicas;
        size_t replica_cnt;

        id = rd_kafka_TopicPartitionInfo_partition(partition);
        printf("\tPartition id: %d\n", id);

        printf("\tPartition leader: \n");
        print_node_info(rd_kafka_TopicPartitionInfo_leader(partition));

        isr = rd_kafka_TopicPartitionInfo_isr(partition, &isr_cnt);
        if (isr_cnt) {
                printf(
                    "\tThe in-sync replica count is: %d, they "
                    "are: \n",
                    (int)isr_cnt);
                for (k = 0; k < isr_cnt; k++)
                        print_node_info(isr[k]);
        } else
                printf("\tThe in-sync replica count is 0\n");

        replicas = rd_kafka_TopicPartitionInfo_isr(partition, &replica_cnt);
        if (replica_cnt) {
                printf(
                    "\tThe replica count is: %d, they "
                    "are: \n",
                    (int)replica_cnt);
                for (k = 0; k < replica_cnt; k++)
                        print_node_info(replicas[k]);
        } else
                printf("\tThe replica count is 0\n");
}

/**
 * @brief Print topic information.
 */
static void print_topic_info(const rd_kafka_TopicDescription_t *topic) {
        size_t j;
        const char *topic_name        = rd_kafka_TopicDescription_name(topic);
        const rd_kafka_error_t *error = rd_kafka_TopicDescription_error(topic);
        const rd_kafka_AclOperation_t *authorized_operations;
        size_t authorized_operations_cnt;
        const rd_kafka_TopicPartitionInfo_t **partitions;
        size_t partition_cnt;
        const rd_kafka_Uuid_t *topic_id =
            rd_kafka_TopicDescription_topic_id(topic);
        const char *topic_id_str = rd_kafka_Uuid_base64str(topic_id);

        if (rd_kafka_error_code(error)) {
                printf("Topic: %s (Topic Id: %s) has error[%" PRId32 "]: %s\n",
                       topic_name, topic_id_str, rd_kafka_error_code(error),
                       rd_kafka_error_string(error));
                return;
        }

        authorized_operations = rd_kafka_TopicDescription_authorized_operations(
            topic, &authorized_operations_cnt);

        printf(
            "Topic: %s (Topic Id: %s) succeeded, has %ld authorized operations "
            "allowed, they are:\n",
            topic_name, topic_id_str, authorized_operations_cnt);

        for (j = 0; j < authorized_operations_cnt; j++)
                printf("\t%s operation is allowed\n",
                       rd_kafka_AclOperation_name(authorized_operations[j]));


        partitions =
            rd_kafka_TopicDescription_partitions(topic, &partition_cnt);

        printf("partition count is: %d\n", (int)partition_cnt);
        for (j = 0; j < partition_cnt; j++) {
                print_partition_info(partitions[j]);
                printf("\n");
        }
}


/**
 * @brief Print topics information.
 */
static int print_topics_info(const rd_kafka_DescribeTopics_result_t *topicdesc,
                             int topic_cnt) {
        size_t i;
        const rd_kafka_TopicDescription_t **result_topics;
        size_t result_topics_cnt;
        result_topics = rd_kafka_DescribeTopics_result_topics(
            topicdesc, &result_topics_cnt);

        if (result_topics_cnt == 0) {
                if (topic_cnt > 0) {
                        fprintf(stderr, "No matching topics found\n");
                        return 1;
                } else {
                        fprintf(stderr, "No topics requested\n");
                }
        }

        for (i = 0; i < result_topics_cnt; i++) {
                print_topic_info(result_topics[i]);
                printf("\n");
        }
        return 0;
}


/**
 * @brief Call rd_kafka_DescribeTopics() with a list of
 * topics.
 */
static void cmd_describe_topics(rd_kafka_conf_t *conf, int argc, char **argv) {
        rd_kafka_t *rk                     = NULL;
        const char **topic_names           = NULL;
        rd_kafka_TopicCollection_t *topics = NULL;
        char errstr[512];
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_event_t *event          = NULL;
        rd_kafka_error_t *error;
        int retval         = 0;
        int topics_cnt     = 0;
        const int min_argc = 1;
        int include_topic_authorized_operations;

        if (argc < min_argc)
                usage("Wrong number of arguments");

        include_topic_authorized_operations =
            parse_int("include_topic_authorized_operations", argv[0]);
        if (include_topic_authorized_operations < 0 ||
            include_topic_authorized_operations > 1)
                usage("include_topic_authorized_operations not a 0-1 int");

        topic_names = (const char **)&argv[1];
        topics_cnt  = argc - 1;
        topics =
            rd_kafka_TopicCollection_of_topic_names(topic_names, topics_cnt);

        /*
         * Create producer instance
         * NOTE: rd_kafka_new() takes ownership of the conf object
         *       and the application must not reference it again after
         *       this call.
         */
        rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
        if (!rk)
                fatal("Failed to create new producer: %s", errstr);

        queue = rd_kafka_queue_new(rk);

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DESCRIBETOPICS);

        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 10 * 1000 /* 10s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                goto exit;
        }
        if ((error = rd_kafka_AdminOptions_set_include_authorized_operations(
                 options, include_topic_authorized_operations))) {
                fprintf(stderr,
                        "%% Failed to set require topic authorized operations: "
                        "%s\n",
                        rd_kafka_error_string(error));
                rd_kafka_error_destroy(error);
                retval = 1;
                goto exit;
        }

        /* Call DescribeTopics */
        rd_kafka_DescribeTopics(rk, topics, options, queue);

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
                /* DescribeTopics request failed */
                fprintf(stderr, "%% DescribeTopics failed[%" PRId32 "]: %s\n",
                        err, rd_kafka_event_error_string(event));
                retval = 1;
                goto exit;

        } else {
                /* DescribeTopics request succeeded, but individual
                 * groups may have errors. */
                const rd_kafka_DescribeTopics_result_t *result;

                result = rd_kafka_event_DescribeTopics_result(event);
                printf("DescribeTopics results:\n");
                retval = print_topics_info(result, topics_cnt);
        }


exit:
        /* Cleanup. */
        if (topics)
                rd_kafka_TopicCollection_destroy(topics);
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

        cmd_describe_topics(conf, argc - optind, &argv[optind]);
        return 0;
}
