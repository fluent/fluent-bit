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
#include <getopt.h>

#include <mk_config/mk_config.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/in_kmsg.h>

static void flb_help(int rc)
{
    printf("Usage: fluent-bit [OPTION]\n\n");
    printf("%sAvailable Options%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -v, --version\t\t\t\tshow version number\n");
    printf("  -h, --help\t\t\t\tprint this help\n\n");
    exit(rc);
}

static void flb_version()
{
    printf("Fluent Bit v0.1\n");
    printf("Copyright (C) Treasure Data");
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int opt;

    static const struct option long_opts[] = {
        { "version",   no_argument, NULL, 'v' },
        { "help",      no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "hv",
                              long_opts, NULL)) != -1) {

        switch (opt) {
        case 'h':
            flb_help(EXIT_SUCCESS);
        case 'v':
            flb_version();
            exit(EXIT_SUCCESS);
        default:
            flb_help(EXIT_FAILURE);
        }
    }

    in_kmsg_start();

    return 0;
}
