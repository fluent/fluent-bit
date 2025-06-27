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
 * IncrementalAlterConfigs usage example.
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
                "Incremental alter config usage examples\n"
                "\n"
                "Usage: %s <options> <res_type1> <res_name1> <alter_op_type1> "
                "<config_name1> <config_value1> ...\n"
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



static void print_alter_configs_result(
    FILE *fp,
    const rd_kafka_IncrementalAlterConfigs_result_t *result,
    const char *prefix) {
        size_t i;
        size_t config_cnt;
        const rd_kafka_ConfigResource_t **configs =
            rd_kafka_IncrementalAlterConfigs_result_resources(result,
                                                              &config_cnt);

        for (i = 0; i < config_cnt; i++) {
                const rd_kafka_ConfigResource_t *config = configs[i];

                const char *resname = rd_kafka_ConfigResource_name(config);
                rd_kafka_ResourceType_t restype =
                    rd_kafka_ConfigResource_type(config);
                rd_kafka_resp_err_t err = rd_kafka_ConfigResource_error(config);

                fprintf(fp, "%sResource type: %s name: %s error: %s: %s\n",
                        prefix, rd_kafka_ResourceType_name(restype), resname,
                        rd_kafka_err2str(err),
                        rd_kafka_ConfigResource_error_string(config));
        }
}


/**
 * @brief Call rd_kafka_IncrementalAlterConfigs() with a list of
 *        configs to alter.
 */
static void
cmd_incremental_alter_configs(rd_kafka_conf_t *conf, int argc, char **argv) {
        rd_kafka_t *rk;
        char errstr[512];
        rd_kafka_AdminOptions_t *options;
        rd_kafka_event_t *event = NULL;
        rd_kafka_error_t *error;
        int retval         = 0;
        const char *prefix = "    ";
        int i              = 0;
        int resources      = 0;
        int config_cnt;
        rd_kafka_ResourceType_t prev_restype = RD_KAFKA_RESOURCE_UNKNOWN;
        char *prev_resname                   = NULL;
        rd_kafka_ConfigResource_t **configs;

        if (argc % 5 != 0) {
                usage("Invalid number of arguments: %d", argc);
        }

        config_cnt = argc / 5;
        configs    = calloc(config_cnt, sizeof(*configs));

        for (i = 0; i < config_cnt; i++) {
                char *restype_s       = argv[i * 5];
                char *resname         = argv[i * 5 + 1];
                char *alter_op_type_s = argv[i * 5 + 2];
                char *config_name     = argv[i * 5 + 3];
                char *config_value    = argv[i * 5 + 4];
                rd_kafka_ConfigResource_t *config;
                rd_kafka_AlterConfigOpType_t op_type;
                rd_kafka_ResourceType_t restype =
                    !strcmp(restype_s, "TOPIC")
                        ? RD_KAFKA_RESOURCE_TOPIC
                        : !strcmp(restype_s, "BROKER")
                              ? RD_KAFKA_RESOURCE_BROKER
                              : RD_KAFKA_RESOURCE_UNKNOWN;

                if (restype == RD_KAFKA_RESOURCE_UNKNOWN) {
                        usage("Invalid resource type: %s", restype_s);
                }

                /* It's not necessary, but cleaner and more efficient to group
                 * incremental alterations for the same ConfigResource.*/
                if (restype != prev_restype || strcmp(resname, prev_resname)) {
                        configs[resources++] =
                            rd_kafka_ConfigResource_new(restype, resname);
                }

                config       = configs[resources - 1];
                prev_restype = restype;
                prev_resname = resname;

                if (!strcmp(alter_op_type_s, "SET")) {
                        op_type = RD_KAFKA_ALTER_CONFIG_OP_TYPE_SET;
                } else if (!strcmp(alter_op_type_s, "APPEND")) {
                        op_type = RD_KAFKA_ALTER_CONFIG_OP_TYPE_APPEND;
                } else if (!strcmp(alter_op_type_s, "SUBTRACT")) {
                        op_type = RD_KAFKA_ALTER_CONFIG_OP_TYPE_SUBTRACT;
                } else if (!strcmp(alter_op_type_s, "DELETE")) {
                        op_type = RD_KAFKA_ALTER_CONFIG_OP_TYPE_DELETE;
                } else {
                        usage("Invalid alter config operation: %s",
                              alter_op_type_s);
                }

                error = rd_kafka_ConfigResource_add_incremental_config(
                    config, config_name, op_type, config_value);

                if (error) {
                        usage(
                            "Error setting incremental config alteration %s"
                            " at index %d: %s",
                            alter_op_type_s, i, rd_kafka_error_string(error));
                }
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
         * Incremental alter configs
         */
        queue = rd_kafka_queue_new(rk);

        /* Signal handler for clean shutdown */
        signal(SIGINT, stop);

        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_INCREMENTALALTERCONFIGS);

        if (rd_kafka_AdminOptions_set_request_timeout(
                options, 10 * 1000 /* 10s */, errstr, sizeof(errstr))) {
                fprintf(stderr, "%% Failed to set timeout: %s\n", errstr);
                goto exit;
        }

        rd_kafka_IncrementalAlterConfigs(rk, configs, resources, options,
                                         queue);

        rd_kafka_ConfigResource_destroy_array(configs, resources);
        free(configs);

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
                /* IncrementalAlterConfigs request failed */
                fprintf(stderr, "%% IncrementalAlterConfigs failed: %s: %s\n",
                        rd_kafka_err2str(err),
                        rd_kafka_event_error_string(event));
                goto exit;

        } else {
                /* IncrementalAlterConfigs request succeeded, but individual
                 * configs may have errors. */
                const rd_kafka_IncrementalAlterConfigs_result_t *result =
                    rd_kafka_event_IncrementalAlterConfigs_result(event);
                printf("IncrementalAlterConfigs results:\n");
                print_alter_configs_result(stdout, result, prefix);
        }


exit:
        if (event)
                rd_kafka_event_destroy(event);
        rd_kafka_AdminOptions_destroy(options);
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

        cmd_incremental_alter_configs(conf, argc - optind, &argv[optind]);

        return 0;
}
