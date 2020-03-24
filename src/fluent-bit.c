/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_dump.h>
#include <fluent-bit/flb_stacktrace.h>
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
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_parser.h>



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

static void flb_version()
{
    printf("Fluent Bit v%s\n", FLB_VERSION_STR);
    exit(EXIT_SUCCESS);
}

static void flb_banner()
{
    fprintf(stderr, "%sFluent Bit v%s%s\n", ANSI_BOLD, FLB_VERSION_STR,
            ANSI_RESET);
    fprintf(stderr, "* %sCopyright (C) 2019-2020 The Fluent Bit Authors%s\n",
            ANSI_BOLD ANSI_YELLOW, ANSI_RESET);
    fprintf(stderr, "* %sCopyright (C) 2015-2018 Treasure Data%s\n",
            ANSI_BOLD ANSI_YELLOW, ANSI_RESET);
    fprintf(stderr, "* Fluent Bit is a CNCF sub-project under the "
            "umbrella of Fluentd\n");
    fprintf(stderr, "* https://fluentbit.io\n\n");
}

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
#ifdef FLB_HAVE_PARSER
    printf("  -R, --parser=FILE\tspecify a parser configuration file\n");
#endif
    printf("  -e, --plugin=FILE\tload an external plugin (shared lib)\n");
    printf("  -l, --log_file=FILE\twrite log info to a file\n");
    printf("  -t, --tag=TAG\t\tset plugin tag, same as '-p tag=abc'\n");
#ifdef FLB_HAVE_STREAM_PROCESSOR
    printf("  -T, --sp-task=SQL\tdefine a stream processor task\n");
#endif
    printf("  -v, --verbose\t\tincrease logging verbosity (default: info)\n");
#ifdef FLB_HAVE_TRACE
    printf("  -vv\t\t\ttrace mode (available)\n");
#endif
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

/*
 * If the description is larger than the allowed 80 chars including left
 * padding, split the content in multiple lines and align it properly.
 */
static void help_plugin_description(int left_padding, char *str)
{
    int len;
    int max;
    int line = 0;
    char *c;
    char *p;
    char *end;
    char fmt[32];

    if (!str) {
        printf("no description available\n");
        return;
    }

    max = 80 - left_padding;
    len = strlen(str);

    if (len <= max) {
        printf("%s\n", str);
        return;
    }

    p = str;
    len = strlen(str);
    end = str + len;

    while (p < end) {
        if ((p + max) > end) {
            c = end;
        }
        else {
            c = p + max;
            while (*c != ' ' && c > p) {
                c--;
            }
        }

        if (c == p) {
            len = end - p;
        }
        else {
            len = c - p;
        }

        snprintf(fmt, sizeof(fmt) - 1, "%%*s%%.%is\n", len);
        if (line == 0) {
            printf(fmt, 0, "", p);
        }
        else {
            printf(fmt, left_padding, " ", p);
        }
        line++;
        p += len + 1;
    }
}

static void flb_help_plugin(int rc, struct flb_config *config, int type,
                            struct flb_input_instance *in,
                            struct flb_filter_instance *filter,
                            struct flb_output_instance *out)


{
    int max = 0;
    int len;
    char fmt[32];
    char fmt_prf[32];
    char def[32];
    char *desc = NULL;
    flb_sds_t tmp;
    struct flb_config_map *opt = NULL;
    struct flb_config_map *m = NULL;

    flb_banner();

    if (type == PLUGIN_INPUT) {
        printf("%sHELP%s\n%s input plugin\n", ANSI_BOLD, ANSI_RESET,
               in->p->name);
        desc = in->p->description;
        opt = m = in->p->config_map;
    }
    else if (type == PLUGIN_FILTER) {
        printf("%sHELP%s\n%s filter plugin\n", ANSI_BOLD, ANSI_RESET,
               filter->p->name);
        desc = filter->p->description;
        opt = m = filter->p->config_map;
    }
    else if (type == PLUGIN_OUTPUT) {
        printf("%sHELP%s\n%s output plugin\n", ANSI_BOLD, ANSI_RESET,
               out->p->name);
        desc = out->p->description;
        opt = m = out->p->config_map;
    }

    if (desc) {
        printf(ANSI_BOLD "\nDESCRIPTION\n" ANSI_RESET "%s\n", desc);
    }

    if (!opt) {
        exit(rc);
    }

    printf(ANSI_BOLD "\nOPTIONS\n" ANSI_RESET);

    /* Find the larger name, just for formatting purposes */
    while (m && m->name) {
        len = strlen(m->name);
        if (len > max) {
            max = len;
        }
        m++;
    }
    max += 2;

    snprintf(fmt, sizeof(fmt) - 1, "%%-%is", max);
    snprintf(fmt_prf, sizeof(fmt_prf) - 1, "%%-%is", max);
    snprintf(def, sizeof(def) - 1, "%%*s> default: %%s, type: ");
    m = opt;
    while (m && m->name) {
        if (m->type == FLB_CONFIG_MAP_STR_PREFIX) {
            len = strlen(m->name);
            tmp = flb_sds_create_size(len + 2);
            flb_sds_printf(&tmp, "%sN", m->name);
            printf(fmt_prf, tmp);
            flb_sds_destroy(tmp);
        }
        else {
            printf(fmt, m->name);
        }

        help_plugin_description(max, m->desc);
        if (m->def_value) {
            printf(def, max, " ", m->def_value);
        }
        else {
            printf("%*s> type: ", max, " ");
        }

        if (m->type == FLB_CONFIG_MAP_STR) {
            printf("string");
        }
        else if (m->type == FLB_CONFIG_MAP_INT) {
            printf("integer");
        }
        else if (m->type == FLB_CONFIG_MAP_BOOL) {
            printf("boolean");
        }
        else if(m->type == FLB_CONFIG_MAP_DOUBLE) {
            printf("double");
        }
        else if (m->type == FLB_CONFIG_MAP_SIZE) {
            printf("size");
        }
        else if (m->type == FLB_CONFIG_MAP_TIME) {
            printf("time");
        }
        else if (flb_config_map_mult_type(m->type) == FLB_CONFIG_MAP_CLIST) {
            len = flb_config_map_expected_values(m->type);
            if (len == -1) {
                printf("multiple comma delimited strings");
            }
            else {
                printf("comma delimited strings (minimum %i)", len);
            }
        }
        else if (flb_config_map_mult_type(m->type) == FLB_CONFIG_MAP_SLIST) {
            len = flb_config_map_expected_values(m->type);
            if (len == -1) {
                printf("multiple space delimited strings");
            }
            else {
                printf("space delimited strings (minimum %i)", len);
            }
        }
        else if (m->type == FLB_CONFIG_MAP_STR_PREFIX) {
            printf("prefixed string");
        }

        printf("\n\n");
        m++;
    }

    exit(rc);
}

#define flb_print_signal(X) case X:                       \
    write (STDERR_FILENO, #X ")\n", sizeof(#X ")\n")-1); \
    break;

static void flb_signal_handler(int signal)
{
    char s[] = "[engine] caught signal (";

    /* write signal number */
    write(STDERR_FILENO, s, sizeof(s) - 1);
    switch (signal) {
        flb_print_signal(SIGINT);
#ifndef FLB_SYSTEM_WINDOWS
        flb_print_signal(SIGQUIT);
        flb_print_signal(SIGHUP);
        flb_print_signal(SIGCONT);
#endif
        flb_print_signal(SIGTERM);
        flb_print_signal(SIGSEGV);
    };

    /* Signal handlers */
    switch (signal) {
    case SIGINT:
#ifndef FLB_SYSTEM_WINDOWS
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
#ifndef FLB_SYSTEM_WINDOWS
    case SIGCONT:
        flb_dump(config);
        break;
#endif
    default:
        break;
    }
}

static void flb_signal_init()
{
    signal(SIGINT,  &flb_signal_handler);
#ifndef FLB_SYSTEM_WINDOWS
    signal(SIGQUIT, &flb_signal_handler);
    signal(SIGHUP,  &flb_signal_handler);
    signal(SIGCONT, &flb_signal_handler);
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
    char *end;
    char *path;

    path = realpath(file, NULL);
    if (!path) {
        return -1;
    }

    /* lookup path ending and truncate */
    end = strrchr(path, FLB_DIRCHAR);
    if (!end) {
        free(path);
        return -1;
    }

    end++;
    *end = '\0';
    config->conf_path = flb_strdup(path);
    free(path);

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
            flb_sds_destroy(tmp);
            goto flb_service_conf_end;
        }
        flb_sds_destroy(tmp);

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
            flb_sds_destroy(tmp);
            goto flb_service_conf_end;
        }
        flb_sds_destroy(tmp);

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
        flb_sds_destroy(tmp);
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
#ifdef FLB_HAVE_PARSER
        { "parser",          required_argument, NULL, 'R' },
#endif
        { "prop",            required_argument, NULL, 'p' },
        { "plugin",          required_argument, NULL, 'e' },
        { "tag",             required_argument, NULL, 't' },
#ifdef FLB_HAVE_STREAM_PROCESSOR
        { "sp-task",         required_argument, NULL, 'T' },
#endif
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
                              "t:T:l:vqVhL:HP:s:S",
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
        case 'e':
            ret = flb_plugin_load_router(optarg, config);
            if (ret == -1) {
                exit(EXIT_FAILURE);
            }
            break;
        case 'f':
            config->flush = atof(optarg);
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
#ifdef FLB_HAVE_PARSER
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
#ifdef FLB_HAVE_STREAM_PROCESSOR
        case 'T':
            flb_slist_add(&config->stream_processor_tasks, optarg);
            break;
#endif
        case 'h':
            if (last_plugin == -1) {
                flb_help(EXIT_SUCCESS, config);
            }
            else {
                flb_help_plugin(EXIT_SUCCESS, config,
                                last_plugin, in, filter, out);
            }
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

    set_log_level_from_env(config);

    if (config->verbose != FLB_LOG_OFF) {
        flb_banner();
    }

    /* Program name */
    flb_config_set_program_name(config, argv[0]);

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
    if (config->flush <= (double) 0.0) {
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

    /* debug or trace */
    if (config->verbose >= FLB_LOG_DEBUG) {
        flb_utils_print_setup(config);
    }

#ifdef FLB_HAVE_FORK
    /* Run in background/daemon mode */
    if (config->daemon == FLB_TRUE) {
        flb_utils_set_daemon(config);
    }
#endif

    /* Prepare pthread keys */
    flb_thread_prepare();
    flb_output_prepare();

    ret = flb_engine_start(config);
    if (ret == -1 && config) {
        flb_engine_shutdown(config);
    }

    return ret;
}
