/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_str.h>

#ifdef FLB_HAVE_MTRACE
#include <mcheck.h>
#endif

struct flb_config *config;

#define PLUGIN_INPUT    0
#define PLUGIN_OUTPUT   1

#define get_key(a, b, c)   mk_rconf_section_get_key(a, b, c)
#define n_get_key(a, b, c) (intptr_t) get_key(a, b, c)
#define s_get_key(a, b, c) (char *) get_key(a, b, c)

static void flb_help(int rc, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *in;
    struct flb_output_plugin *out;

    printf("Usage: fluent-bit [OPTION]\n\n");
    printf("%sAvailable Options%s\n", ANSI_BOLD, ANSI_RESET);
#ifdef FLB_HAVE_BUFFERING
    printf("  -b  --buf_path=PATH\tspecify a buffering path\n");
    printf("  -B  --buf_workers=N\tnumber of workers for buffering\n");
#endif
    printf("  -c  --config=FILE\tspecify an optional configuration file\n");
    printf("  -d, --daemon\t\trun Fluent Bit in background mode\n");
    printf("  -f, --flush=SECONDS\tflush timeout in seconds (default: %i)\n",
           FLB_CONFIG_FLUSH_SECS);
    printf("  -i, --input=INPUT\tset an input\n");
    printf("  -m, --match=MATCH\tset plugin match, same as '-p match=abc'\n");
    printf("  -o, --output=OUTPUT\tset an output\n");
    printf("  -p, --prop=\"A=B\"\tset plugin configuration property\n");
    printf("  -l, --logfile=FILE\twrite log info to a file\n");
    printf("  -t, --tag=TAG\t\tset plugin tag, same as '-p tag=abc'\n");
    printf("  -v, --verbose\t\tenable verbose mode\n");
#ifdef FLB_HAVE_HTTP
    printf("  -H, --http\t\tenable monitoring HTTP server\n");
    printf("  -P, --port\t\tset HTTP server TCP port (default: %s)\n",
           FLB_CONFIG_HTTP_PORT);
#endif
    printf("  -u, --user_header=\"KEY=VALUE\"\tset user header\n");
    printf("  -q, --quiet\t\tquiet mode\n");
    printf("  -V, --version\t\tshow version number\n");
    printf("  -h, --help\t\tprint this help\n\n");

    printf("%sInputs%s\n", ANSI_BOLD, ANSI_RESET);

    /* Iterate each supported input */
    mk_list_foreach(head, &config->in_plugins) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        if (strcmp(in->name, "lib") == 0) {
            /* useless..., just skip it. */
            continue;
        }
        printf("  %-22s%s\n", in->name, in->description);
    }
    printf("\n%sOutputs%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &config->out_plugins) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        if (strcmp(out->name, "lib") == 0) {
            /* useless..., just skip it. */
            continue;
        }
        printf("  %-22s%s\n", out->name, out->description);
    }

    printf("\n%sInternal Flags%s\n", ANSI_BOLD, ANSI_RESET);
    printf(" %s\n", FLB_INFO_FLAGS);
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


static void flb_signal_handler(int signal)
{
    write(STDERR_FILENO, "[engine] caught signal\n", 23);

    switch (signal) {
    case SIGINT:
    case SIGQUIT:
    case SIGHUP:
    case SIGTERM:
        flb_engine_shutdown(config);
#ifdef FLB_HAVE_MTRACE
        /* Stop tracing malloc and free */
        muntrace();
#endif
        _exit(EXIT_SUCCESS);
    default:
        break;
    }
}

static void flb_signal_init()
{
    signal(SIGINT,  &flb_signal_handler);
    signal(SIGQUIT, &flb_signal_handler);
    signal(SIGHUP,  &flb_signal_handler);
    signal(SIGTERM, &flb_signal_handler);
}

static int input_set_property(struct flb_input_instance *in, char *kv)
{
    int ret;
    char *key;
    char *value;
    if( !flb_utils_parse_key_value(kv, &key, &value) ) {
        ret = flb_input_set_property(in, key, value);
        flb_free(key);
        flb_free(value);
    }
    return ret;
}

static int output_set_property(struct flb_output_instance *out, char *kv)
{
    char *key;
    char *value;
    int  ret = -1;

    if( !flb_utils_parse_key_value(kv, &key, &value) ) {
        ret = flb_output_set_property(out, key, value);
        flb_free(key);
        flb_free(value);
    }

    return ret;
}

static void flb_service_conf_err(struct mk_rconf_section *section, char *key)
{
    fprintf(stderr, "Invalid configuration value at %s.%s\n",
            section->name, key);
}

static int flb_service_conf(struct flb_config *config, char *file)
{
    char *name;
    int  ret = -1;
    struct mk_list *head;
    struct mk_list *h_prop;
    struct mk_rconf *fconf = NULL;
    struct mk_rconf_entry *entry;
    struct mk_rconf_section *section;
    struct flb_input_instance *in;
    struct flb_output_instance *out;

    fconf = mk_rconf_open(file);
    if (!fconf) {
        return -1;
    }

    /* Read main [SERVICE] section */
    section = mk_rconf_section_get(fconf, "SERVICE");
    if (section) {
        /* Iterate properties */
        mk_list_foreach(h_prop, &section->entries) {
            entry = mk_list_entry(h_prop, struct mk_rconf_entry, _head);
            /* Set the property */
            flb_config_set_property(config, entry->key, entry->val);
        }
    }

    /* Read all [INPUT] sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "INPUT") != 0) {
            continue;
        }

        /* Get the input plugin name */
        name = s_get_key(section, "Name", MK_RCONF_STR);
        if (!name) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }

        flb_debug("[service] loading input: %s", name);

        /* Create an instace of the plugin */
        in = flb_input_new(config, name, NULL);
        flb_free(name);
        if (!in) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }

        /* Iterate other properties */
        mk_list_foreach(h_prop, &section->entries) {
            entry = mk_list_entry(h_prop, struct mk_rconf_entry, _head);
            if (strcasecmp(entry->key, "Name") == 0) {
                continue;
            }

            /* Set the property */
            flb_input_set_property(in, entry->key, entry->val);
        }
    }

    /* Read all [OUTPUT] sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "OUTPUT") != 0) {
            continue;
        }

        /* Get the output plugin name */
        name = s_get_key(section, "Name", MK_RCONF_STR);
        if (!name) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }

        /* Create an instace of the plugin */
        out = flb_output_new(config, name, NULL);
        flb_free(name);
        if (!out) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }

        /* Iterate other properties */
        mk_list_foreach(h_prop, &section->entries) {
            entry = mk_list_entry(h_prop, struct mk_rconf_entry, _head);
            if (strcasecmp(entry->key, "Name") == 0) {
                continue;
            }

            /* Set the property */
            flb_output_set_property(out, entry->key, entry->val);
        }
    }
    ret = 0;
flb_service_conf_end:
    if (fconf != NULL) {
        mk_rconf_free(fconf);
    }
    return ret;
}

int main(int argc, char **argv)
{
    int opt;
    int ret;

    /* handle plugin properties:  -1 = none, 0 = input, 1 = output */
    int last_plugin = -1;

    /* local variables to handle config options */
    char *cfg_file = NULL;
    struct flb_input_instance *in = NULL;
    struct flb_output_instance *out = NULL;

    /* Setup long-options */
    static const struct option long_opts[] = {
        { "buf_path",    required_argument, NULL, 'b' },
        { "buf_workers", required_argument, NULL, 'B' },
        { "config",      required_argument, NULL, 'c' },
        { "daemon",      no_argument      , NULL, 'd' },
        { "flush",       required_argument, NULL, 'f' },
        { "http",        no_argument      , NULL, 'H' },
        { "logfile",     required_argument, NULL, 'l' },
        { "port",        required_argument, NULL, 'P' },
        { "input",       required_argument, NULL, 'i' },
        { "match",       required_argument, NULL, 'm' },
        { "output",      required_argument, NULL, 'o' },
        { "prop",        required_argument, NULL, 'p' },
        { "tag",         required_argument, NULL, 't' },
        { "user_header", required_argument, NULL, 'u' },
        { "version",     no_argument      , NULL, 'V' },
        { "verbose",     no_argument      , NULL, 'v' },
        { "quiet",       no_argument      , NULL, 'q' },
        { "help",        no_argument      , NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

#ifdef FLB_HAVE_MTRACE
    /* Start tracing malloc and free */
    mtrace();
#endif

    /* Signal handler */
    flb_signal_init();

    /* Create configuration context */
    config = flb_config_init();
    if (!config) {
        exit(EXIT_FAILURE);
    }

    /* Parse the command line options */
    while ((opt = getopt_long(argc, argv, "b:B:c:df:i:m:o:p:t:l:u:vqVhHP:",
                              long_opts, NULL)) != -1) {

        switch (opt) {
#ifdef FLB_HAVE_BUFFERING
        case 'b':
            config->buffer_path = flb_strdup(optarg);
            if (config->buffer_workers <= 0) {
                config->buffer_workers = 1;
            }
            break;
        case 'B':
            config->buffer_workers = atoi(optarg);
            break;
#endif
        case 'c':
            cfg_file = flb_strdup(optarg);
            break;
        case 'd':
            config->daemon = FLB_TRUE;
            break;
        case 'f':
            config->flush = atoi(optarg);
            break;
        case 'i':
            in = flb_input_new(config, optarg, NULL);
            if (!in) {
                flb_utils_error(FLB_ERR_INPUT_INVALID);
            }
            last_plugin = PLUGIN_INPUT;
            break;
        case 'm':
            if (out) {
                flb_output_set_property(out, "match", optarg);
            }
            break;
        case 'o':
            out = flb_output_new(config, optarg, NULL);
            if (!out) {
                flb_utils_error(FLB_ERR_OUTPUT_INVALID);
            }
            last_plugin = PLUGIN_OUTPUT;
            break;
        case 'l':
            config->logfile = flb_strdup(optarg);
            break;
        case 'p':
            if (last_plugin == PLUGIN_INPUT) {
                input_set_property(in, optarg);
            }
            else if (last_plugin == PLUGIN_OUTPUT) {
                output_set_property(out, optarg);
            }
            break;
        case 'u':
            flb_config_set_property(config, FLB_CONF_STR_USER_HEADER ,optarg);
            break;
        case 't':
            if (in) {
                flb_input_set_property(in, "tag", optarg);
            }
            break;
        case 'h':
            flb_help(EXIT_SUCCESS, config);
            break;
#ifdef FLB_HAVE_HTTP
        case 'H':
            config->http_server = FLB_TRUE;
            break;
        case 'P':
            config->http_port = flb_strdup(optarg);
            break;
#endif
        case 'V':
            flb_version();
            exit(EXIT_SUCCESS);
        case 'v':
            config->verbose++;
            break;
        case 'q':
            config->verbose = FLB_LOG_OFF;
            break;
        default:
            flb_help(EXIT_FAILURE, config);
        }
    }

    if (!config->logfile) {
        config->log = flb_log_init(config, FLB_LOG_STDERR, config->verbose, NULL);
    }
    else {
        config->log = flb_log_init(config, FLB_LOG_FILE, config->verbose,
                                   config->logfile);
    }

    /* Validate config file */
    if (cfg_file) {
        if (access(cfg_file, R_OK) != 0) {
            flb_utils_error(FLB_ERR_CFG_FILE);
        }

        /* Load the service configuration file */
        ret = flb_service_conf(config, cfg_file);
        if (ret != 0) {
            flb_utils_error(FLB_ERR_CFG_FILE_FORMAT);
        }
    }

    /* Validate flush time (seconds) */
    if (config->flush < 1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH);
    }

    /* Inputs */
    ret = flb_input_check(config);
    if (ret == -1) {
        flb_utils_error(FLB_ERR_INPUT_UNDEF);
    }

    /* Outputs */
    ret = flb_output_check(config);
    if (ret == -1) {
        flb_utils_error(FLB_ERR_OUTPUT_UNDEF);
    }

    flb_banner();
    if (config->verbose == FLB_TRUE) {
        flb_utils_print_setup(config);
    }

    /* Run in background/daemon mode */
    if (config->daemon == FLB_TRUE) {
        flb_utils_set_daemon(config);
    }

    flb_engine_start(config);
    return 0;
}
