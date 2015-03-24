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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_engine.h>

static void flb_help(int rc)
{
    printf("Usage: fluent-bit [OPTION]\n\n");
    printf("%sAvailable Options%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -f, --flush=SECONDS\tflush timeout in seconds (default: %i)\n",
           FLB_CONFIG_FLUSH_SECS);
    printf("  -i, --input=INPUT\tset an input\n");
    printf("  -o, --output=OUTPUT\tset an output\n");
    printf("  -t, --tag=TAG\t\tset a Tag (default: %s)\n", FLB_CONFIG_DEFAULT_TAG);
    printf("  -V, --verbose\t\tenable verbose mode\n");
    printf("  -v, --version\t\tshow version number\n");
    printf("  -h, --help\t\tprint this help\n\n");

    printf("%sInputs%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  CPU Usage\t\tcpu\n");
    printf("  Kernel Ring Buffer\tkmsg\n\n");

    printf("%sOutputs%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  Fluentd\t\tfluentd://host:port  (in_forward)\n\n");
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
    int ret;
    struct flb_config *config;

    /* local variables to handle config options */
    char *cfg_output = NULL;
    char *cfg_tag = NULL;

    /* Setup long-options */
    static const struct option long_opts[] = {
        { "flush",   required_argument, NULL, 'f' },
        { "input",   required_argument, NULL, 'i' },
        { "output",  required_argument, NULL, 'o' },
        { "tag",     required_argument, NULL, 't' },
        { "version", no_argument      , NULL, 'v' },
        { "verbose", no_argument      , NULL, 'V' },
        { "help",    no_argument      , NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    /* Create configuration context */
    config = flb_config_init();
    if (!config) {
        exit(EXIT_FAILURE);
    }

    /* Register all supported inputs */
    flb_input_register_all(config);

    /* Parse the command line options */
    while ((opt = getopt_long(argc, argv, "f:i:o:t:vVh",
                              long_opts, NULL)) != -1) {

        switch (opt) {
        case 'f':
            config->flush = atoi(optarg);
            break;
        case 'i':
            ret = flb_input_enable(optarg, config);
            if (ret != 0) {
                flb_utils_error(FLB_ERR_INPUT_INVALID);
            }
        case 'o':
            cfg_output = optarg;
            break;
        case 't':
            cfg_tag = optarg;
            break;
        case 'h':
            flb_help(EXIT_SUCCESS);
        case 'v':
            flb_version();
            exit(EXIT_SUCCESS);
        case 'V':
            config->verbose = __flb_config_verbose = FLB_TRUE;
            break;
        default:
            flb_help(EXIT_FAILURE);
        }
    }

    /* We need an output */
    if (!cfg_output) {
        flb_utils_error(FLB_ERR_OUTPUT_UNDEF);
    }

    /* Validate flush time (seconds) */
    if (config->flush < 1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH);
    }

    /* Tag */
    if (cfg_tag) {
        config->tag = cfg_tag;
    }
    else {
        config->tag = strdup(FLB_CONFIG_DEFAULT_TAG);
    }

    /* Inputs */
    ret = flb_input_check(config);
    if (ret == -1) {
        flb_utils_error(FLB_ERR_INPUT_UNDEF);
    }

    /* Output */
    ret = flb_output_check(config, cfg_output);
    if (ret == -1) {
        flb_utils_error(FLB_ERR_OUTPUT_INVALID);
    }

    flb_banner();
    if (config->verbose == FLB_TRUE) {
        flb_utils_print_setup(config);
    }

    flb_engine_start(config);
    return 0;
}
