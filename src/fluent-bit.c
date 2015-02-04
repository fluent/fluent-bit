/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <mk_config/mk_config.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/in_kmsg.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_version.h>

static void flb_help(int rc)
{
    printf("Usage: fluent-bit [OPTION]\n\n");
    printf("%sAvailable Options%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -t, --tag=TAG\t\tset a Tag (default: %s)\n", FLB_CONFIG_DEFAULT_TAG);
    printf("  -v, --version\t\tshow version number\n");
    printf("  -h, --help\t\tprint this help\n\n");
    exit(rc);
}

static void flb_version()
{
    printf("Fluent Bit v%s\n", FLB_VERSION_STR);
    exit(EXIT_SUCCESS);
}

static void flb_banner()
{
    printf("%sFluent-Bit v%s%s\n", ANSI_BOLD, FLB_VERSION_STR, ANSI_RESET);
    printf("%sCopyright (C) Treasure Data%s\n\n", ANSI_BOLD ANSI_YELLOW, ANSI_RESET);
}

int main(int argc, char **argv)
{
    int opt;
    struct flb_config *config;

    /* local variables to handle config options */
    char *cfg_tag = NULL;

    static const struct option long_opts[] = {
        { "tag",     required_argument, NULL, 't' },
        { "version", no_argument      , NULL, 'v' },
        { "help",    no_argument      , NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "tvh",
                              long_opts, NULL)) != -1) {

        switch (opt) {
        case 't':
            cfg_tag = optarg;
            break;
        case 'h':
            flb_help(EXIT_SUCCESS);
        case 'v':
            flb_version();
            exit(EXIT_SUCCESS);
        default:
            flb_help(EXIT_FAILURE);
        }
    }

    config = malloc(sizeof(struct flb_config));
    if (!config) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    if (cfg_tag) {
        config->tag = cfg_tag;
    }
    else {
        config->tag = strdup(FLB_CONFIG_DEFAULT_TAG);
    }

    flb_banner();
    in_kmsg_start();

    return 0;
}
