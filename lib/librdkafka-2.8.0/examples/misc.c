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
 * A collection of smaller usage examples
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


static void usage(const char *reason, ...) {

        fprintf(stderr,
                "Miscellaneous librdkafka usage examples\n"
                "\n"
                "Usage: %s <options> <command> [<command arguments>]\n"
                "\n"
                "Commands:\n"
                " List groups:\n"
                "   %s -b <brokers> list_groups <group>\n"
                "\n"
                " Show librdkafka version:\n"
                "   %s version\n"
                "\n"
                "Common options for all commands:\n"
                "   -b <brokers>    Bootstrap server list to connect to.\n"
                "   -X <prop=val>   Set librdkafka configuration property.\n"
                "                   See CONFIGURATION.md for full list.\n"
                "   -d <dbg,..>     Enable librdkafka debugging (%s).\n"
                "\n",
                argv0, argv0, argv0, rd_kafka_get_debug_contexts());

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
 * Commands
 *
 */

/**
 * @brief Just print the librdkafka version
 */
static void cmd_version(rd_kafka_conf_t *conf, int argc, char **argv) {
        if (argc)
                usage("version command takes no arguments");

        printf("librdkafka v%s\n", rd_kafka_version_str());
        rd_kafka_conf_destroy(conf);
}


/**
 * @brief Call rd_kafka_list_groups() with an optional groupid argument.
 */
static void cmd_list_groups(rd_kafka_conf_t *conf, int argc, char **argv) {
        rd_kafka_t *rk;
        const char *groupid = NULL;
        char errstr[512];
        rd_kafka_resp_err_t err;
        const struct rd_kafka_group_list *grplist;
        int i;
        int retval = 0;

        if (argc > 1)
                usage("too many arguments to list_groups");

        if (argc == 1)
                groupid = argv[0];

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
         * List groups
         */
        err = rd_kafka_list_groups(rk, groupid, &grplist, 10 * 1000 /*10s*/);
        if (err)
                fatal("rd_kafka_list_groups(%s) failed: %s", groupid,
                      rd_kafka_err2str(err));

        if (grplist->group_cnt == 0) {
                if (groupid) {
                        fprintf(stderr, "Group %s not found\n", groupid);
                        retval = 1;
                } else {
                        fprintf(stderr, "No groups in cluster\n");
                }
        }

        /*
         * Print group information
         */
        for (i = 0; i < grplist->group_cnt; i++) {
                int j;
                const struct rd_kafka_group_info *grp = &grplist->groups[i];

                printf(
                    "Group \"%s\" protocol-type %s, protocol %s, "
                    "state %s, with %d member(s))",
                    grp->group, grp->protocol_type, grp->protocol, grp->state,
                    grp->member_cnt);
                if (grp->err)
                        printf(" error: %s", rd_kafka_err2str(grp->err));
                printf("\n");
                for (j = 0; j < grp->member_cnt; j++) {
                        const struct rd_kafka_group_member_info *mb =
                            &grp->members[j];
                        printf(
                            "  Member \"%s\" with client-id %s, host %s, "
                            "%d bytes of metadat, %d bytes of assignment\n",
                            mb->member_id, mb->client_id, mb->client_host,
                            mb->member_metadata_size,
                            mb->member_assignment_size);
                }
        }

        rd_kafka_group_list_destroy(grplist);

        /* Destroy the client instance */
        rd_kafka_destroy(rk);

        exit(retval);
}



int main(int argc, char **argv) {
        rd_kafka_conf_t *conf; /**< Client configuration object */
        int opt, i;
        const char *cmd;
        static const struct {
                const char *cmd;
                void (*func)(rd_kafka_conf_t *conf, int argc, char **argv);
        } cmds[] = {
            {"version", cmd_version},
            {"list_groups", cmd_list_groups},
            {NULL},
        };

        argv0 = argv[0];

        if (argc == 1)
                usage(NULL);

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


        if (optind == argc)
                usage("No command specified");


        cmd = argv[optind++];

        /*
         * Find matching command and run it
         */
        for (i = 0; cmds[i].cmd; i++) {
                if (!strcmp(cmds[i].cmd, cmd)) {
                        cmds[i].func(conf, argc - optind, &argv[optind]);
                        exit(0);
                }
        }

        usage("Unknown command: %s", cmd);

        /* NOTREACHED */
        return 0;
}
