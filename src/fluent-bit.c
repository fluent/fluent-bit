/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <signal.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_meta.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_parser.h>

/* Libbacktrace support */
#ifdef FLB_HAVE_LIBBACKTRACE
#include <backtrace.h>
#include <backtrace-supported.h>

struct flb_stacktrace {
    struct backtrace_state *state;
	int error;
    int line;
};

struct flb_stacktrace flb_st;

static void flb_stacktrace_error_callback(void *data,
                                          const char *msg, int errnum)
{
    struct flb_stacktrace *ctx = data;
    fprintf(stderr, "ERROR: %s (%d)", msg, errnum);
	ctx->error = 1;
}

static int flb_stacktrace_print_callback(void *data, uintptr_t pc,
                                         const char *filename, int lineno,
                                         const char *function)
{
    struct flb_stacktrace *p = data;

    fprintf(stdout, "#%-2i 0x%-17lx in  %s() at %s:%d\n",
            p->line,
            (unsigned long) pc,
            function == NULL ? "???" : function,
            filename == NULL ? "???" : filename + sizeof(FLB_SOURCE_DIR),
            lineno);
    p->line++;
    return 0;
}

static inline void flb_stacktrace_init(char *prog)
{
    memset(&flb_st, '\0', sizeof(struct flb_stacktrace));
    flb_st.state = backtrace_create_state(prog,
                                          BACKTRACE_SUPPORTS_THREADS,
                                          flb_stacktrace_error_callback, NULL);
}

void flb_stacktrace_print()
{
    struct flb_stacktrace *ctx;

    ctx = &flb_st;
    backtrace_full(ctx->state, 3, flb_stacktrace_print_callback,
                   flb_stacktrace_error_callback, ctx);
}

#endif

#ifdef FLB_HAVE_MTRACE
#include <mcheck.h>
#endif

struct flb_config *config;

#define PLUGIN_INPUT    0
#define PLUGIN_OUTPUT   1
#define PLUGIN_FILTER   2

#define get_key(a, b, c)   mk_rconf_section_get_key(a, b, c)
#define n_get_key(a, b, c) (intptr_t) get_key(a, b, c)
#define s_get_key(a, b, c) (char *) get_key(a, b, c)

static void flb_help(int rc, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *in;
    struct flb_output_plugin *out;
    struct flb_filter_plugin *filter;

    printf("Usage: fluent-bit [OPTION]\n\n");
    printf("%sAvailable Options%s\n", ANSI_BOLD, ANSI_RESET);
    printf("  -b  --storage_path=PATH\tspecify a storage buffering path\n");
    printf("  -c  --config=FILE\tspecify an optional configuration file\n");
#ifdef FLB_HAVE_FORK
    printf("  -d, --daemon\t\trun Fluent Bit in background mode\n");
#endif
    printf("  -f, --flush=SECONDS\tflush timeout in seconds (default: %i)\n",
           FLB_CONFIG_FLUSH_SECS);
    printf("  -F  --filter=FILTER\t set a filter\n");
    printf("  -i, --input=INPUT\tset an input\n");
    printf("  -m, --match=MATCH\tset plugin match, same as '-p match=abc'\n");
    printf("  -o, --output=OUTPUT\tset an output\n");
    printf("  -p, --prop=\"A=B\"\tset plugin configuration property\n");
    printf("  -R, --parser=FILE\tspecify a parser configuration file\n");
    printf("  -e, --plugin=FILE\tload an external plugin (shared lib)\n");
    printf("  -l, --log_file=FILE\twrite log info to a file\n");
    printf("  -t, --tag=TAG\t\tset plugin tag, same as '-p tag=abc'\n");
    printf("  -v, --verbose\t\tenable verbose mode\n");
#ifdef FLB_HAVE_HTTP_SERVER
    printf("  -H, --http\t\tenable monitoring HTTP server\n");
    printf("  -P, --port\t\tset HTTP server TCP port (default: %s)\n",
           FLB_CONFIG_HTTP_PORT);
#endif
    printf("  -s, --coro_stack_size\tSet coroutines stack size in bytes "
           "(default: %i)\n", config->coro_stack_size);
    printf("  -q, --quiet\t\tquiet mode\n");
    printf("  -S, --sosreport\tsupport report for Enterprise customers\n");
    printf("  -V, --version\t\tshow version number\n");
    printf("  -h, --help\t\tprint this help\n\n");

    printf("%sInputs%s\n", ANSI_BOLD, ANSI_RESET);

    /* Iterate each supported input */
    mk_list_foreach(head, &config->in_plugins) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        if (strcmp(in->name, "lib") == 0 || (in->flags & FLB_INPUT_PRIVATE)) {
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

    printf("\n%sFilters%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &config->filter_plugins) {
        filter = mk_list_entry(head, struct flb_filter_plugin, _head);
        printf("  %-22s%s\n", filter->name, filter->description);
    }

    printf("\n%sInternal%s\n", ANSI_BOLD, ANSI_RESET);
    printf(" Event Loop  = %s\n", mk_event_backend());
    printf(" Build Flags = %s\n", FLB_INFO_FLAGS);
    exit(rc);
}

static void flb_version()
{
    printf("Fluent Bit v%s\n", FLB_VERSION_STR);
    exit(EXIT_SUCCESS);
}

static void flb_banner()
{
    fprintf(stderr, "%sFluent Bit v%s%s\n",
            ANSI_BOLD, FLB_VERSION_STR, ANSI_RESET);
    fprintf(stderr, "%sCopyright (C) Treasure Data%s\n\n",
            ANSI_BOLD ANSI_YELLOW, ANSI_RESET);
}

#define flb_print_signal(X) case X:                       \
    write (STDERR_FILENO, #X ")\n" , sizeof(#X ")\n")-1); \
    break;

static void flb_signal_handler(int signal)
{
    char s[] = "[engine] caught signal (";

    /* write signal number */
    write(STDERR_FILENO, s, sizeof(s) - 1);
    switch (signal) {
        flb_print_signal(SIGINT);
#ifndef _WIN32
        flb_print_signal(SIGQUIT);
        flb_print_signal(SIGHUP);
#endif
        flb_print_signal(SIGTERM);
        flb_print_signal(SIGSEGV);
    };

    /* Signal handlers */
    switch (signal) {
    case SIGINT:
#ifndef _WIN32
    case SIGQUIT:
    case SIGHUP:
#endif
        flb_engine_shutdown(config);
#ifdef FLB_HAVE_MTRACE
        /* Stop tracing malloc and free */
        muntrace();
#endif
        _exit(EXIT_SUCCESS);
    case SIGTERM:
        flb_engine_exit(config);
        break;
    case SIGSEGV:
#ifdef FLB_HAVE_LIBBACKTRACE
        flb_stacktrace_print();
#endif
        abort();
    default:
        break;
    }
}

static void flb_signal_init()
{
    signal(SIGINT,  &flb_signal_handler);
#ifndef _WIN32
    signal(SIGQUIT, &flb_signal_handler);
    signal(SIGHUP,  &flb_signal_handler);
#endif
    signal(SIGTERM, &flb_signal_handler);
    signal(SIGSEGV, &flb_signal_handler);
}

static int input_set_property(struct flb_input_instance *in, char *kv)
{
    int ret;
    int len;
    int sep;
    char *key;
    char *value;

    len = strlen(kv);
    sep = mk_string_char_search(kv, '=', len);
    if (sep == -1) {
        return -1;
    }

    key = mk_string_copy_substr(kv, 0, sep);
    value = kv + sep + 1;

    if (!key) {
        return -1;
    }

    ret = flb_input_set_property(in, key, value);
    if (ret == -1) {
        fprintf(stderr, "[error] setting up '%s' plugin property '%s'\n",
                in->p->name, key);
    }

    flb_free(key);
    return ret;
}

static int output_set_property(struct flb_output_instance *out, char *kv)
{
    int ret;
    int len;
    int sep;
    char *key;
    char *value;
    len = strlen(kv);
    sep = mk_string_char_search(kv, '=', len);
    if (sep == -1) {
        return -1;
    }

    key = mk_string_copy_substr(kv, 0, sep);
    value = kv + sep + 1;

    if (!key) {
        return -1;
    }

    ret = flb_output_set_property(out, key, value);
    flb_free(key);
    return ret;
}

static int filter_set_property(struct flb_filter_instance *filter, char *kv)
{
    int ret;
    int len;
    int sep;
    char *key;
    char *value;

    len = strlen(kv);
    sep = mk_string_char_search(kv, '=', len);
    if (sep == -1) {
        return -1;
    }

    key = mk_string_copy_substr(kv, 0, sep);
    value = kv + sep + 1;

    if (!key) {
        return -1;
    }

    ret = flb_filter_set_property(filter, key, value);
    flb_free(key);
    return ret;
}

static void flb_service_conf_err(struct mk_rconf_section *section, char *key)
{
    fprintf(stderr, "Invalid configuration value at %s.%s\n",
            section->name, key);
}

static int flb_service_conf_path_set(struct flb_config *config, char *file)
{
    char *p;
    char *end;
    char path[PATH_MAX + 1];

    p = realpath(file, path);
    if (!p) {
        return -1;
    }

    /* lookup path ending and truncate */
    end = strrchr(path, '/');
    if (!end) {
        return -1;
    }

    end++;
    *end = '\0';
    config->conf_path = flb_strdup(path);

    return 0;
}

static int flb_service_conf(struct flb_config *config, char *file)
{
    int ret = -1;
    char *tmp;
    char *name;
    struct mk_list *head;
    struct mk_list *h_prop;
    struct mk_rconf *fconf = NULL;
    struct mk_rconf_entry *entry;
    struct mk_rconf_section *section;
    struct flb_input_instance *in;
    struct flb_output_instance *out;
    struct flb_filter_instance *filter;

#ifdef FLB_HAVE_STATIC_CONF
    fconf = flb_config_static_open(file);
#else
    fconf = mk_rconf_open(file);
#endif

    if (!fconf) {
        return -1;
    }

    /* Process all meta commands */
    mk_list_foreach(head, &fconf->metas) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);
        flb_meta_run(config, entry->key, entry->val);
    }

    /* Set configuration root path */
    flb_service_conf_path_set(config, file);

    /* Validate sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);

        if (strcasecmp(section->name, "SERVICE") == 0 ||
            strcasecmp(section->name, "INPUT") == 0 ||
            strcasecmp(section->name, "FILTER") == 0 ||
            strcasecmp(section->name, "OUTPUT") == 0) {

            /* continue on valid sections */
            continue;
        }

        /* Extra sanity checks */
        if (strcasecmp(section->name, "PARSER") == 0) {
            fprintf(stderr,
                    "Section [PARSER] is not valid in the main "
                    "configuration file. It belongs to \n"
                    "the Parsers_File configuration files.\n");
        }
        else {
            fprintf(stderr,
                    "Error: unexpected section [%s] in the main "
                    "configuration file.\n", section->name);
        }
        exit(EXIT_FAILURE);
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
        tmp = flb_env_var_translate(config->env, name);
        in = flb_input_new(config, tmp, NULL, FLB_TRUE);
        mk_mem_free(name);
        if (!in) {
            fprintf(stderr, "Input plugin '%s' cannot be loaded\n", tmp);
            mk_mem_free(tmp);
            goto flb_service_conf_end;
        }
        mk_mem_free(tmp);

        /* Iterate other properties */
        mk_list_foreach(h_prop, &section->entries) {
            entry = mk_list_entry(h_prop, struct mk_rconf_entry, _head);
            if (strcasecmp(entry->key, "Name") == 0) {
                continue;
            }

            /* Set the property */
            ret = flb_input_set_property(in, entry->key, entry->val);
            if (ret == -1) {
                fprintf(stderr, "Error setting up %s plugin property '%s'\n",
                        in->name, entry->key);
                goto flb_service_conf_end;
            }
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
        tmp = flb_env_var_translate(config->env, name);
        out = flb_output_new(config, tmp, NULL);
        mk_mem_free(name);
        if (!out) {
            fprintf(stderr, "Output plugin '%s' cannot be loaded\n", tmp);
            mk_mem_free(tmp);
            goto flb_service_conf_end;
        }
        mk_mem_free(tmp);

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

    /* Read all [FILTER] sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "FILTER") != 0) {
            continue;
        }
        /* Get the filter plugin name */
        name = s_get_key(section, "Name", MK_RCONF_STR);
        if (!name) {
            flb_service_conf_err(section, "Name");
            goto flb_service_conf_end;
        }
        /* Create an instace of the plugin */
        tmp = flb_env_var_translate(config->env, name);
        filter = flb_filter_new(config, tmp, NULL);
        mk_mem_free(tmp);
        mk_mem_free(name);
        if (!filter) {
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
            flb_filter_set_property(filter, entry->key, entry->val);
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
    struct flb_filter_instance *filter = NULL;

#ifdef FLB_HAVE_LIBBACKTRACE
    flb_stacktrace_init(argv[0]);
#endif

#ifndef _WIN32
    /* Setup long-options */
    static const struct option long_opts[] = {
        { "storage_path",    required_argument, NULL, 'b' },
        { "config",          required_argument, NULL, 'c' },
#ifdef FLB_HAVE_FORK
        { "daemon",          no_argument      , NULL, 'd' },
#endif
        { "flush",           required_argument, NULL, 'f' },
        { "http",            no_argument      , NULL, 'H' },
        { "log_file",        required_argument, NULL, 'l' },
        { "port",            required_argument, NULL, 'P' },
        { "input",           required_argument, NULL, 'i' },
        { "match",           required_argument, NULL, 'm' },
        { "output",          required_argument, NULL, 'o' },
        { "filter",          required_argument, NULL, 'F' },
        { "parser",          required_argument, NULL, 'R' },
        { "prop",            required_argument, NULL, 'p' },
        { "plugin",          required_argument, NULL, 'e' },
        { "tag",             required_argument, NULL, 't' },
        { "version",         no_argument      , NULL, 'V' },
        { "verbose",         no_argument      , NULL, 'v' },
        { "quiet",           no_argument      , NULL, 'q' },
        { "help",            no_argument      , NULL, 'h' },
        { "coro_stack_size", required_argument, NULL, 's'},
        { "sosreport",       no_argument      , NULL, 'S' },
#ifdef FLB_HAVE_HTTP_SERVER
        { "http_server",     no_argument      , NULL, 'H' },
        { "http_listen",     required_argument, NULL, 'L' },
        { "http_port",       required_argument, NULL, 'P' },
#endif
        { NULL, 0, NULL, 0 }
    };
#endif

#ifdef FLB_HAVE_MTRACE
    /* Start tracing malloc and free */
    mtrace();
#endif


#ifdef _WIN32
    /* Initialize sockets */
    WSADATA wsaData;
    int err;

    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", err);
        exit(EXIT_FAILURE);
    }
#endif

    /* Signal handler */
    flb_signal_init();

    /* Initialize Monkey Core library */
    mk_core_init();

    /* Create configuration context */
    config = flb_config_init();
    if (!config) {
        exit(EXIT_FAILURE);
    }

#ifndef FLB_HAVE_STATIC_CONF

    /* Parse the command line options */
    while ((opt = getopt_long(argc, argv,
                              "b:c:df:i:m:o:R:F:p:e:"
                              "t:l:vqVhL:HP:s:S",
                              long_opts, NULL)) != -1) {

        switch (opt) {
        case 'b':
            config->storage_path = flb_strdup(optarg);
            break;
        case 'c':
            cfg_file = flb_strdup(optarg);
            break;
#ifdef FLB_HAVE_FORK
        case 'd':
            config->daemon = FLB_TRUE;
            break;
#endif

#ifdef FLB_HAVE_PROXY_GO
        case 'e':
            if (!flb_plugin_proxy_create(optarg, 0, config)) {
                exit(EXIT_FAILURE);
            }
            break;
#else
        case 'e':
            fprintf(stderr, "Error: proxy Golang plugin not available\n");
            exit(EXIT_FAILURE);
#endif
        case 'f':
            config->flush = atoi(optarg);
            break;
        case 'i':
            in = flb_input_new(config, optarg, NULL, FLB_TRUE);
            if (!in) {
                flb_utils_error(FLB_ERR_INPUT_INVALID);
            }
            last_plugin = PLUGIN_INPUT;
            break;
        case 'm':
            if (last_plugin == PLUGIN_FILTER) {
                flb_filter_set_property(filter, "match", optarg);
            }
            else if (last_plugin == PLUGIN_OUTPUT) {
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
#ifdef FLB_HAVE_REGEX
        case 'R':
            ret = flb_parser_conf_file(optarg, config);
            if (ret != 0) {
                exit(EXIT_FAILURE);
            }
            break;
#endif
        case 'F':
            filter = flb_filter_new(config, optarg, NULL);
            if (!filter) {
                flb_utils_error(FLB_ERR_FILTER_INVALID);
            }
            last_plugin = PLUGIN_FILTER;
            break;
        case 'l':
            config->log_file = flb_strdup(optarg);
            break;
        case 'p':
            if (last_plugin == PLUGIN_INPUT) {
                ret = input_set_property(in, optarg);
                if (ret != 0) {
                    exit(EXIT_FAILURE);
                }
            }
            else if (last_plugin == PLUGIN_OUTPUT) {
                output_set_property(out, optarg);
            }
            else if (last_plugin == PLUGIN_FILTER) {
                filter_set_property(filter, optarg);
            }
            break;
        case 't':
            if (in) {
                flb_input_set_property(in, "tag", optarg);
            }
            break;
        case 'h':
            flb_help(EXIT_SUCCESS, config);
            break;
#ifdef FLB_HAVE_HTTP_SERVER
        case 'H':
            config->http_server = FLB_TRUE;
            break;
        case 'L':
            if (config->http_listen) {
                flb_free(config->http_listen);
            }
            config->http_listen = flb_strdup(optarg);
            break;
        case 'P':
            if (config->http_port) {
                flb_free(config->http_port);
            }
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
        case 's':
            config->coro_stack_size = (unsigned int) atoi(optarg);
            break;
        case 'S':
            config->support_mode = FLB_TRUE;
            break;
        default:
            flb_help(EXIT_FAILURE, config);
        }
    }
#endif /* !FLB_HAVE_STATIC_CONF */

    if (config->verbose != FLB_LOG_OFF) {
        flb_banner();
    }

    /* Validate config file */
#ifndef FLB_HAVE_STATIC_CONF
    if (cfg_file) {
        if (access(cfg_file, R_OK) != 0) {
            flb_utils_error(FLB_ERR_CFG_FILE);
        }

        /* Load the service configuration file */
        ret = flb_service_conf(config, cfg_file);
        if (ret != 0) {
            flb_utils_error(FLB_ERR_CFG_FILE_STOP);
        }
        flb_free(cfg_file);
    }
#else
    ret = flb_service_conf(config, "fluent-bit.conf");
    if (ret != 0) {
        flb_utils_error(FLB_ERR_CFG_FILE_STOP);
    }
#endif

    /* Check co-routine stack size */
    if (config->coro_stack_size < getpagesize()) {
        flb_utils_error(FLB_ERR_CORO_STACK_SIZE);
    }

    /* Validate flush time (seconds) */
    if (config->flush < 1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH);
    }

    /* Inputs */
    ret = flb_input_check(config);
    if (ret == -1 && config->support_mode == FLB_FALSE) {
        flb_utils_error(FLB_ERR_INPUT_UNDEF);
    }

    /* Outputs */
    ret = flb_output_check(config);
    if (ret == -1 && config->support_mode == FLB_FALSE) {
        flb_utils_error(FLB_ERR_OUTPUT_UNDEF);
    }

    if (config->verbose == FLB_TRUE) {
        flb_utils_print_setup(config);
    }

#ifdef FLB_HAVE_FORK
    /* Run in background/daemon mode */
    if (config->daemon == FLB_TRUE) {
        flb_utils_set_daemon(config);
    }
#endif

    ret = flb_engine_start(config);
    if (ret == -1) {
        flb_engine_shutdown(config);
    }

    return 0;
}
