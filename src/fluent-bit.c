/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <ctype.h>

#include <cfl/cfl.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_kvlist.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_dump.h>
#include <fluent-bit/flb_stacktrace.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_meta.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_custom.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_help.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_reload.h>
#include <fluent-bit/flb_config_format.h>

#ifdef FLB_HAVE_MTRACE
#include <mcheck.h>
#endif

#ifdef FLB_SYSTEM_WINDOWS
extern int win32_main(int, char**);
extern void win32_started(void);
#endif

flb_ctx_t *ctx;
struct flb_config *config;
volatile sig_atomic_t exit_signal = 0;
volatile sig_atomic_t flb_bin_restarting = FLB_RELOAD_IDLE;

#ifdef FLB_HAVE_LIBBACKTRACE
struct flb_stacktrace flb_st;
#endif

#define FLB_HELP_TEXT    0
#define FLB_HELP_JSON    1


#define PLUGIN_CUSTOM   0
#define PLUGIN_INPUT    1
#define PLUGIN_OUTPUT   2
#define PLUGIN_FILTER   3

#define print_opt(a, b)      printf("  %-24s%s\n", a, b)
#define print_opt_i(a, b, c) printf("  %-24s%s (default: %i)\n", a, b, c)
#define print_opt_s(a, b, c) printf("  %-24s%s (default: %s)\n", a, b, c)

#define get_key(a, b, c)     mk_rconf_section_get_key(a, b, c)
#define n_get_key(a, b, c)   (intptr_t) get_key(a, b, c)
#define s_get_key(a, b, c)   (char *) get_key(a, b, c)

static char *prog_name;

static void flb_signal_init();

static void flb_help(int rc, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *in;
    struct flb_output_plugin *out;
    struct flb_filter_plugin *filter;
    struct flb_processor_plugin *processor;

    printf("Usage: %s [OPTION]\n\n", prog_name);
    printf("%sAvailable Options%s\n", ANSI_BOLD, ANSI_RESET);
    print_opt("-b  --storage_path=PATH", "specify a storage buffering path");
    print_opt("-c  --config=FILE", "specify an optional configuration file");
#ifdef FLB_HAVE_FORK
    print_opt("-d, --daemon", "run Fluent Bit in background mode");
#endif
    print_opt("-D, --dry-run", "dry run");
    print_opt_i("-f, --flush=SECONDS", "flush timeout in seconds",
                FLB_CONFIG_FLUSH_SECS);
    print_opt("-C, --custom=CUSTOM", "enable a custom plugin");
    print_opt("-i, --input=INPUT", "set an input");
    print_opt("-F  --filter=FILTER", "set a filter");
    print_opt("-m, --match=MATCH", "set plugin match, same as '-p match=abc'");
    print_opt("-o, --output=OUTPUT", "set an output");
    print_opt("-p, --prop=\"A=B\"", "set plugin configuration property");
#ifdef FLB_HAVE_PARSER
    print_opt("-R, --parser=FILE", "specify a parser configuration file");
#endif
    print_opt("-e, --plugin=FILE", "load an external plugin (shared lib)");
    print_opt("-l, --log_file=FILE", "write log info to a file");
    print_opt("-t, --tag=TAG", "set plugin tag, same as '-p tag=abc'");
#ifdef FLB_HAVE_STREAM_PROCESSOR
    print_opt("-T, --sp-task=SQL", "define a stream processor task");
#endif
    print_opt("-v, --verbose", "increase logging verbosity (default: info)");
#ifdef FLB_TRACE
    print_opt("-vv", "trace mode (available)");
#endif
#ifdef FLB_HAVE_CHUNK_TRACE
    print_opt("-Z, --enable-chunk-trace", "enable chunk tracing. activating it requires using the HTTP Server API.");
#endif
    print_opt("-w, --workdir", "set the working directory");
#ifdef FLB_HAVE_HTTP_SERVER
    print_opt("-H, --http", "enable monitoring HTTP server");
    print_opt_s("-P, --port", "set HTTP server TCP port",
                FLB_CONFIG_HTTP_PORT);
#endif
    print_opt_i("-s, --coro_stack_size", "set coroutines stack size in bytes",
                config->coro_stack_size);
    print_opt("-q, --quiet", "quiet mode");
    print_opt("-S, --sosreport", "support report for Enterprise customers");
    print_opt("-Y, --enable-hot-reload", "enable for hot reloading");
    print_opt("-W, --disable-thread-safety-on-hot-reloading", "disable thread safety on hot reloading");
    print_opt("-V, --version", "show version number");
    print_opt("-h, --help", "print this help");

    printf("\n%sInputs%s\n", ANSI_BOLD, ANSI_RESET);

    /* Iterate each supported input */
    mk_list_foreach(head, &config->in_plugins) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        if (strcmp(in->name, "lib") == 0 || (in->flags & FLB_INPUT_PRIVATE)) {
            /* useless..., just skip it. */
            continue;
        }
        print_opt(in->name, in->description);
    }

    printf("\n%sProcessors%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &config->processor_plugins) {
        processor = mk_list_entry(head, struct flb_processor_plugin, _head);
        print_opt(processor->name, processor->description);
    }

    printf("\n%sFilters%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &config->filter_plugins) {
        filter = mk_list_entry(head, struct flb_filter_plugin, _head);
        print_opt(filter->name, filter->description);
    }

    printf("\n%sOutputs%s\n", ANSI_BOLD, ANSI_RESET);
    mk_list_foreach(head, &config->out_plugins) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        if (strcmp(out->name, "lib") == 0 || (out->flags & FLB_OUTPUT_PRIVATE)) {
            /* useless..., just skip it. */
            continue;
        }
        print_opt(out->name, out->description);
    }

    printf("\n%sInternal%s\n", ANSI_BOLD, ANSI_RESET);
    printf(" Event Loop  = %s\n", mk_event_backend());
    printf(" Build Flags =%s\n", FLB_INFO_FLAGS);
    exit(rc);
}

/*
 * If the description is larger than the allowed 80 chars including left
 * padding, split the content in multiple lines and align it properly.
 */
static void help_plugin_description(int left_padding, flb_sds_t str)
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

    max = 90 - left_padding;
    len = strlen(str);

    if (len <= max) {
        printf("%s\n", str);
        return;
    }

    p = str;
    len = flb_sds_len(str);
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

static flb_sds_t help_get_value(msgpack_object map, char *key)
{
    flb_sds_t k;
    flb_sds_t val;
    msgpack_object *o;
    struct flb_ra_value *rval = NULL;
    struct flb_record_accessor *ra = NULL;

    k = flb_sds_create(key);
    ra = flb_ra_create(k, FLB_FALSE);
    flb_sds_destroy(k);
    if (!ra) {
        return NULL;
    }

    rval = flb_ra_get_value_object(ra, map);
    if (!rval) {
        flb_ra_destroy(ra);
        return NULL;
    }

    o = &rval->o;
    val = flb_sds_create_len(o->via.str.ptr, o->via.str.size);

    flb_ra_key_value_destroy(rval);
    flb_ra_destroy(ra);

    return val;
}

static void help_print_property(int max, msgpack_object k, msgpack_object v)
{
    int i;
    int len = 0;
    char buf[32];
    char fmt[32];
    char fmt_prf[32];
    char def[32];
    msgpack_object map;
    flb_sds_t tmp;
    flb_sds_t name;
    flb_sds_t type;
    flb_sds_t desc;
    flb_sds_t defv;

    /* Convert property type to uppercase and print it */
    for (i = 0; i < k.via.str.size; i++) {
        buf[i] = toupper(k.via.str.ptr[i]);
    }
    buf[k.via.str.size] = '\0';
    printf(ANSI_BOLD "\n%s\n" ANSI_RESET, buf);

    snprintf(fmt, sizeof(fmt) - 1, "%%-%is", max);
    snprintf(fmt_prf, sizeof(fmt_prf) - 1, "%%-%is", max);
    snprintf(def, sizeof(def) - 1, "%%*s> default: %%s, type: ");

    for (i = 0; i < v.via.array.size; i++) {
        map = v.via.array.ptr[i];

        name = help_get_value(map, "$name");
        type = help_get_value(map, "$type");
        desc = help_get_value(map, "$description");
        defv = help_get_value(map, "$default");

        if (strcmp(type, "prefix") == 0) {
            len = flb_sds_len(name);
            tmp = flb_sds_create_size(len + 2);
            flb_sds_printf(&tmp, "%sN", name);
            printf(fmt_prf, tmp);
            flb_sds_destroy(tmp);
        }
        else {
            printf(fmt, name);
        }

        help_plugin_description(max, desc);

        if (defv) {
            printf(def, max, " ", defv);
        }
        else {
            printf("%*s> type: ", max, " ");
        }
        printf("%s", type);
        printf("\n\n");
    }
}

static void help_format_json(void *help_buf, size_t help_size)
{
    flb_sds_t json;

    json = flb_msgpack_raw_to_json_sds(help_buf, help_size);
    printf("%s\n", json);
    flb_sds_destroy(json);
}

static void help_format_text(void *help_buf, size_t help_size)
{
    int i;
    int x;
    int max = 0;
    int len = 0;
    int ret;
    size_t off = 0;
    flb_sds_t name;
    flb_sds_t type;
    flb_sds_t desc;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object p;
    msgpack_object k;
    msgpack_object v;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, help_buf, help_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return;
    }
    map = result.data;

    type = help_get_value(map, "$type");
    name = help_get_value(map, "$name");
    desc = help_get_value(map, "$description");

    printf("%sHELP%s\n%s %s plugin\n", ANSI_BOLD, ANSI_RESET,
           name, type);
    flb_sds_destroy(type);
    flb_sds_destroy(name);

    if (desc) {
        printf(ANSI_BOLD "\nDESCRIPTION\n" ANSI_RESET "%s\n", desc);
        flb_sds_destroy(desc);
    }

    /* Properties */
    p = map.via.map.ptr[3].val;

    /* Calculate padding */
    for (i = 0; i < p.via.map.size; i++) {
        v = p.via.map.ptr[i].val;
        for (x = 0; x < v.via.map.size; x++) {
            msgpack_object ptr = v.via.array.ptr[x];
            name = help_get_value(ptr, "$name");
            len = flb_sds_len(name);
            flb_sds_destroy(name);
            if (len > max) {
                max = len;
            }
        }
    }
    max += 2;

    /* Iterate each section of properties */
    for (i = 0; i < p.via.map.size; i++) {
        k = p.via.map.ptr[i].key;
        v = p.via.map.ptr[i].val;
        help_print_property(max, k, v);
    }
}

static void flb_help_plugin(int rc, int format,
                            struct flb_config *config, int type,
                            struct flb_cf *cf,
                            struct flb_cf_section *s)
{
    struct flb_config_map *opt = NULL;
    void *help_buf;
    size_t help_size;
    char *name;
    struct flb_custom_instance *c = NULL;
    struct flb_input_instance *i = NULL;
    struct flb_filter_instance *f = NULL;
    struct flb_output_instance *o = NULL;

    flb_version_banner();

    name = flb_cf_section_property_get_string(cf, s, "name");
    if (!name) {
        exit(EXIT_FAILURE);
    }

    if (type == PLUGIN_CUSTOM) {
        c = flb_custom_new(config, name, NULL);
        if (!c) {
            fprintf(stderr, "invalid custom plugin '%s'", name);
            return;
        }
        opt = c->p->config_map;
        flb_help_custom(c, &help_buf, &help_size);
        flb_custom_instance_destroy(c);
    }
    else if (type == PLUGIN_INPUT) {
        i = flb_input_new(config, name, 0, FLB_TRUE);
        if (!i) {
            fprintf(stderr, "invalid input plugin '%s'", name);
            return;
        }
        opt = i->p->config_map;
        flb_help_input(i, &help_buf, &help_size);
        flb_input_instance_destroy(i);
    }
    else if (type == PLUGIN_FILTER) {
        f = flb_filter_new(config, name, 0);
        if (!f) {
            fprintf(stderr, "invalid filter plugin '%s'", name);
            return;
        }
        opt = f->p->config_map;
        flb_help_filter(f, &help_buf, &help_size);
        flb_filter_instance_destroy(f);
    }
    else if (type == PLUGIN_OUTPUT) {
        o = flb_output_new(config, name, 0, FLB_TRUE);
        if (!o) {
            fprintf(stderr, "invalid output plugin '%s'", name);
            return;
        }
        opt = o->p->config_map;
        flb_help_output(o, &help_buf, &help_size);
        flb_output_instance_destroy(o);
    }

    if (!opt) {
        exit(rc);
    }

    if (format == FLB_HELP_TEXT) {
        help_format_text(help_buf, help_size);
    }
    else if (format == FLB_HELP_JSON) {
        help_format_json(help_buf, help_size);
    }

    flb_free(help_buf);
    exit(rc);
}

#define flb_print_signal(X) case X:                       \
    write (STDERR_FILENO, #X ")\n", sizeof(#X ")\n")-1); \
    break;

static void flb_signal_handler_break_loop(int signal)
{
    exit_signal = signal;
}

static void flb_signal_exit(int signal)
{
    int len;
    char ts[32];
    char s[] = "[engine] caught signal (";
    time_t now;
    struct tm *cur;
    flb_ctx_t *ctx = flb_context_get();
    struct flb_cf *cf_opts = flb_cf_context_get();

    now = time(NULL);
    cur = localtime(&now);
    len = snprintf(ts, sizeof(ts) - 1, "[%i/%02i/%02i %02i:%02i:%02i] ",
                   cur->tm_year + 1900,
                   cur->tm_mon + 1,
                   cur->tm_mday,
                   cur->tm_hour,
                   cur->tm_min,
                   cur->tm_sec);

    /* write signal number */
    write(STDERR_FILENO, ts, len);
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
    /* SIGSEGV is not handled here to preserve stacktrace */
    switch (signal) {
    case SIGINT:
    case SIGTERM:
#ifndef FLB_SYSTEM_WINDOWS
    case SIGQUIT:
    case SIGHUP:
#endif
        if (cf_opts != NULL) {
            flb_cf_destroy(cf_opts);
        }
        flb_stop(ctx);
        flb_destroy(ctx);
        _exit(EXIT_SUCCESS);
    default:
        break;
    }
}

static void flb_signal_handler(int signal)
{
    int len;
    char ts[32];
    char s[] = "[engine] caught signal (";
    time_t now;
    struct tm *cur;
    flb_ctx_t *ctx = flb_context_get();
    struct flb_cf *cf_opts = flb_cf_context_get();

    now = time(NULL);
    cur = localtime(&now);
    len = snprintf(ts, sizeof(ts) - 1, "[%i/%02i/%02i %02i:%02i:%02i] ",
                   cur->tm_year + 1900,
                   cur->tm_mon + 1,
                   cur->tm_mday,
                   cur->tm_hour,
                   cur->tm_min,
                   cur->tm_sec);

    /* write signal number */
    write(STDERR_FILENO, ts, len);
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
        flb_print_signal(SIGFPE);
    };

    flb_signal_init();

    switch(signal) {
    case SIGSEGV:
    case SIGFPE:
#ifdef FLB_HAVE_LIBBACKTRACE
        /* To preserve stacktrace */
        flb_stacktrace_print(&flb_st);
#endif
        abort();
#ifndef FLB_SYSTEM_WINDOWS
    case SIGCONT:
        flb_dump(ctx->config);
        break;
    case SIGHUP:
#ifndef FLB_HAVE_STATIC_CONF
        if (flb_bin_restarting == FLB_RELOAD_IDLE) {
            flb_bin_restarting = FLB_RELOAD_IN_PROGRESS;
            /* reload by using same config files/path */
            flb_reload(ctx, cf_opts);
            flb_bin_restarting = FLB_RELOAD_IDLE;
        }
        else {
            flb_utils_error(FLB_ERR_RELOADING_IN_PROGRESS);
        }
        break;
#endif
#endif
    }
}

static void flb_signal_init()
{
    signal(SIGINT,  &flb_signal_handler_break_loop);
#ifndef FLB_SYSTEM_WINDOWS
    signal(SIGQUIT, &flb_signal_handler_break_loop);
    signal(SIGHUP,  &flb_signal_handler);
    signal(SIGCONT, &flb_signal_handler);
#endif
    signal(SIGTERM, &flb_signal_handler_break_loop);
    signal(SIGSEGV, &flb_signal_handler);
    signal(SIGFPE,  &flb_signal_handler);
}

static int set_property(struct flb_cf *cf, struct flb_cf_section *s, char *kv)
{
    int len;
    int sep;
    char *key;
    char *value;
    struct cfl_variant *tmp;

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

    tmp = flb_cf_section_property_add(cf, s->properties, key, 0, value, 0);
    if (tmp == NULL) {
        fprintf(stderr, "[error] setting up section '%s' plugin property '%s'\n",
                s->name, key);
    }
    mk_mem_free(key);
    return 0;
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

    /* Store the relative file path */
    config->conf_path_file = flb_sds_create(file);

    return 0;
}


static struct flb_cf *service_configure(struct flb_cf *cf,
                                        struct flb_config *config, char *file)
{
    int ret = -1;

#ifdef FLB_HAVE_STATIC_CONF
        cf = flb_config_static_open(file);
#else
    if (file) {
        cf = flb_cf_create_from_file(cf, file);
    }
#endif

    if (!cf) {
        return NULL;
    }


    /* Set configuration root path */
    if (file) {
        flb_service_conf_path_set(config, file);
    }

    ret = flb_config_load_config_format(config, cf);
    if (ret != 0) {
        return NULL;
    }

    config->cf_main = cf;
    return cf;
}

int flb_main(int argc, char **argv)
{
    int opt;
    int ret;
    flb_sds_t json;

    /* handle plugin properties:  -1 = none, 0 = input, 1 = output */
    int last_plugin = -1;

    /* local variables to handle config options */
    char *cfg_file = NULL;

    /* config format context */
    struct flb_cf *cf;
    struct flb_cf *tmp;
    struct flb_cf_section *service;
    struct flb_cf_section *s;
    struct flb_cf_section *section;
    struct flb_cf *cf_opts;

    prog_name = argv[0];

    cf_opts = flb_cf_create();
    if (!cf_opts) {
        exit(EXIT_FAILURE);
    }
    section = flb_cf_section_create(cf_opts, "service", 0);
    if (!section) {
        flb_cf_destroy(cf_opts);
        exit(EXIT_FAILURE);
    }

#ifdef FLB_HAVE_LIBBACKTRACE
    flb_stacktrace_init(argv[0], &flb_st);
#endif

    /* Setup long-options */
    static const struct option long_opts[] = {
        { "storage_path",    required_argument, NULL, 'b' },
        { "config",          required_argument, NULL, 'c' },
#ifdef FLB_HAVE_FORK
        { "daemon",          no_argument      , NULL, 'd' },
#endif
        { "dry-run",         no_argument      , NULL, 'D' },
        { "flush",           required_argument, NULL, 'f' },
        { "http",            no_argument      , NULL, 'H' },
        { "log_file",        required_argument, NULL, 'l' },
        { "port",            required_argument, NULL, 'P' },
        { "custom",          required_argument, NULL, 'C' },
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
        { "workdir",         required_argument, NULL, 'w' },
        { "quiet",           no_argument      , NULL, 'q' },
        { "help",            no_argument      , NULL, 'h' },
        { "help-json",       no_argument      , NULL, 'J' },
        { "coro_stack_size", required_argument, NULL, 's' },
        { "sosreport",       no_argument      , NULL, 'S' },
#ifdef FLB_HAVE_HTTP_SERVER
        { "http_server",     no_argument      , NULL, 'H' },
        { "http_listen",     required_argument, NULL, 'L' },
        { "http_port",       required_argument, NULL, 'P' },
#endif
        { "enable-hot-reload",     no_argument, NULL, 'Y' },
#ifdef FLB_HAVE_CHUNK_TRACE
        { "enable-chunk-trace",    no_argument, NULL, 'Z' },
#endif
        { "disable-thread-safety-on-hot-reload", no_argument, NULL, 'W' },
        { NULL, 0, NULL, 0 }
    };

    /* Signal handler */
    flb_signal_init();

    /* Initialize Monkey Core library */
    mk_core_init();

    /* Create Fluent Bit context */
    ctx = flb_create();
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    config = ctx->config;
    cf = config->cf_main;
    service = cf_opts->service;

    /* Add reference for cf_opts */
    config->cf_opts = cf_opts;

#ifndef FLB_HAVE_STATIC_CONF

    /* Parse the command line options */
    while ((opt = getopt_long(argc, argv,
                              "b:c:dDf:C:i:m:o:R:F:p:e:"
                              "t:T:l:vw:qVhJL:HP:s:SWYZ",
                              long_opts, NULL)) != -1) {

        switch (opt) {
        case 'b':
            flb_cf_section_property_add(cf_opts, service->properties,
                                        "storage.path", 0, optarg, 0);
            break;
        case 'c':
            cfg_file = flb_strdup(optarg);
            break;
#ifdef FLB_HAVE_FORK
        case 'd':
            flb_cf_section_property_add(cf_opts, service->properties,
                                        "daemon", 0, "on", 0);
            config->daemon = FLB_TRUE;
            break;
#endif
        case 'D':
            config->dry_run = FLB_TRUE;
            break;
        case 'e':
            ret = flb_plugin_load_router(optarg, config);
            if (ret == -1) {
                exit(EXIT_FAILURE);
            }
            /* Store the relative file path for external plugin */
            flb_slist_add(&config->external_plugins, optarg);
            break;
        case 'f':
            flb_cf_section_property_add(cf_opts, service->properties,
                                        "flush", 0, optarg, 0);
            break;
        case 'C':
            s = flb_cf_section_create(cf_opts, "custom", 0);
            if (!s) {
                flb_utils_error(FLB_ERR_CUSTOM_INVALID);
            }
            flb_cf_section_property_add(cf_opts, s->properties, "name", 0, optarg, 0);
            last_plugin = PLUGIN_CUSTOM;
            break;
        case 'i':
            s = flb_cf_section_create(cf_opts, "input", 0);
            if (!s) {
                flb_utils_error(FLB_ERR_INPUT_INVALID);
            }
            flb_cf_section_property_add(cf_opts, s->properties, "name", 0, optarg, 0);
            last_plugin = PLUGIN_INPUT;
            break;
        case 'm':
            if (last_plugin == PLUGIN_FILTER || last_plugin == PLUGIN_OUTPUT) {
                flb_cf_section_property_add(cf_opts, s->properties, "match", 0, optarg, 0);
            }
            break;
        case 'o':
            s = flb_cf_section_create(cf_opts, "output", 0);
            if (!s) {
                flb_utils_error(FLB_ERR_OUTPUT_INVALID);
            }
            flb_cf_section_property_add(cf_opts, s->properties, "name", 0, optarg, 0);
            last_plugin = PLUGIN_OUTPUT;
            break;
#ifdef FLB_HAVE_PARSER
        case 'R':
            ret = flb_parser_conf_file_stat(optarg, config);
            if (ret == -1) {
                flb_cf_destroy(cf_opts);
                flb_destroy(ctx);
                exit(EXIT_FAILURE);
            }
            flb_cf_section_property_add(cf_opts, service->properties, FLB_CONF_STR_PARSERS_FILE, 0, optarg, 0);
            break;
#endif
        case 'F':
            s = flb_cf_section_create(cf_opts, "filter", 0);
            if (!s) {
                flb_utils_error(FLB_ERR_FILTER_INVALID);
            }
            flb_cf_section_property_add(cf_opts, s->properties, "name", 0, optarg, 0);
            last_plugin = PLUGIN_FILTER;
            break;
        case 'l':
            flb_cf_section_property_add(cf_opts, service->properties,
                                "log_file", 0, optarg, 0);
            break;
        case 'p':
            if (s) {
                set_property(cf_opts, s, optarg);
            }
            break;
        case 't':
            if (s) {
                flb_cf_section_property_add(cf_opts, s->properties, "tag", 0, optarg, 0);
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
                flb_help_plugin(EXIT_SUCCESS, FLB_HELP_TEXT,
                                config,
                                last_plugin, cf_opts, s);
            }
            break;
        case 'J':
            if (last_plugin == -1) {
                json = flb_help_build_json_schema(config);
                if (!json) {
                    exit(EXIT_FAILURE);
                }

                printf("%s\n", json);
                flb_sds_destroy(json);
                exit(EXIT_SUCCESS);
            }
            else {
                flb_help_plugin(EXIT_SUCCESS, FLB_HELP_JSON, config,
                                last_plugin, cf_opts, s);
            }
            break;
#ifdef FLB_HAVE_HTTP_SERVER
        case 'H':
            flb_cf_section_property_add(cf_opts, service->properties, "http_server", 0, "on", 0);
            break;
        case 'L':
            flb_cf_section_property_add(cf_opts, service->properties, FLB_CONF_STR_HTTP_LISTEN, 0, optarg, 0);
            break;
        case 'P':
            flb_cf_section_property_add(cf_opts, service->properties, FLB_CONF_STR_HTTP_PORT, 0, optarg, 0);
            break;
#endif
        case 'V':
            flb_version();
            exit(EXIT_SUCCESS);
        case 'v':
            config->verbose++;
            break;
        case 'w':
            config->workdir =  flb_strdup(optarg);
            break;
        case 'q':
            config->verbose = FLB_LOG_OFF;
            break;
        case 's':
            flb_cf_section_property_add(cf_opts, service->properties, FLB_CONF_STR_CORO_STACK_SIZE, 0, optarg, 0);
            break;
        case 'S':
            config->support_mode = FLB_TRUE;
            break;
        case 'Y':
            flb_cf_section_property_add(cf_opts, service->properties, FLB_CONF_STR_HOT_RELOAD, 0, "on", 0);
            break;
        case 'W':
            flb_cf_section_property_add(cf_opts, service->properties,
                                        FLB_CONF_STR_HOT_RELOAD_ENSURE_THREAD_SAFETY, 0, "off", 0);
            break;
#ifdef FLB_HAVE_CHUNK_TRACE
        case 'Z':
            flb_cf_section_property_add(cf_opts, service->properties, FLB_CONF_STR_ENABLE_CHUNK_TRACE, 0, "on", 0);
            break;
#endif /* FLB_HAVE_CHUNK_TRACE */
        default:
            flb_help(EXIT_FAILURE, config);
        }
    }
#endif /* !FLB_HAVE_STATIC_CONF */

    set_log_level_from_env(config);

    if (config->verbose != FLB_LOG_OFF) {
        flb_version_banner();
    }

    /* Program name */
    flb_config_set_program_name(config, argv[0]);

    /* Set the current directory */
    if (config->workdir) {
        ret = chdir(config->workdir);
        if (ret == -1) {
            flb_cf_destroy(cf_opts);
            flb_errno();
            return -1;
        }
    }

    /* Validate config file */
#ifndef FLB_HAVE_STATIC_CONF
    if (cfg_file) {
        if (access(cfg_file, R_OK) != 0) {
            flb_free(cfg_file);
            flb_cf_destroy(cf_opts);
            flb_utils_error(FLB_ERR_CFG_FILE);
        }
    }

    if (flb_reload_reconstruct_cf(cf_opts, cf) != 0) {
        flb_free(cfg_file);
        flb_cf_destroy(cf_opts);
        fprintf(stderr, "reconstruct format context is failed\n");
        exit(EXIT_FAILURE);
    }

    /* Load the service configuration file */
    tmp = service_configure(cf, config, cfg_file);
    flb_free(cfg_file);
    if (!tmp) {
        flb_cf_destroy(cf_opts);
        flb_utils_error(FLB_ERR_CFG_FILE_STOP);
    }
#else
    tmp = service_configure(cf, config, "fluent-bit.conf");
    if (!tmp) {
        flb_cf_destroy(cf_opts);
        flb_utils_error(FLB_ERR_CFG_FILE_STOP);
    }

    /* destroy previous context and override */
    flb_cf_destroy(cf);
    config->cf_main = tmp;
    cf = tmp;
#endif

    /* Check co-routine stack size */
    if (config->coro_stack_size < getpagesize()) {
        flb_cf_destroy(cf_opts);
        flb_utils_error(FLB_ERR_CORO_STACK_SIZE);
    }

    /* Validate flush time (seconds) */
    if (config->flush <= (double) 0.0) {
        flb_cf_destroy(cf_opts);
        flb_utils_error(FLB_ERR_CFG_FLUSH);
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

#ifdef FLB_SYSTEM_WINDOWS
    win32_started();
#endif

    if (config->dry_run == FLB_TRUE) {
        fprintf(stderr, "configuration test is successful\n");
        flb_cf_destroy(cf_opts);
        flb_destroy(ctx);
        exit(EXIT_SUCCESS);
    }

    /* start Fluent Bit library */
    ret = flb_start(ctx);
    if (ret != 0) {
        flb_cf_destroy(cf_opts);
        flb_destroy(ctx);
        return ret;
    }

    /* Store the current config format context from command line */
    flb_cf_context_set(cf_opts);

    /*
     * Always re-set the original context that was started, note that during a flb_start() a 'reload' could happen so the context
     * will be different. Use flb_context_get() to get the current context.
     */
    ctx = flb_context_get();

    while (ctx->status == FLB_LIB_OK && exit_signal == 0) {
        sleep(1);

        /* set the context again before checking the status again */
        ctx = flb_context_get();
    }

    if (exit_signal) {
        flb_signal_exit(exit_signal);
    }
    ret = config->exit_status_code;

    cf_opts = flb_cf_context_get();

    if (cf_opts != NULL) {
        flb_cf_destroy(cf_opts);
    }
    flb_stop(ctx);
    flb_destroy(ctx);

    return ret;
}

int main(int argc, char **argv)
{
#ifdef FLB_SYSTEM_WINDOWS
    return win32_main(argc, argv);
#else
    return flb_main(argc, argv);
#endif
}
