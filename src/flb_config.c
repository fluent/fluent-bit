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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stddef.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_plugins.h>
#include <fluent-bit/flb_io_tls.h>
#include <fluent-bit/flb_kernel.h>
#include <fluent-bit/flb_worker.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_plugin_proxy.h>

int flb_regex_init();

struct flb_service_config service_configs[] = {
    {FLB_CONF_STR_FLUSH,
     FLB_CONF_TYPE_INT,
     offsetof(struct flb_config, flush)},

    {FLB_CONF_STR_GRACE,
     FLB_CONF_TYPE_INT,
     offsetof(struct flb_config, grace)},

    {FLB_CONF_STR_DAEMON,
     FLB_CONF_TYPE_BOOL,
     offsetof(struct flb_config, daemon)},

    {FLB_CONF_STR_LOGFILE,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, log_file)},

    {FLB_CONF_STR_PARSERS_FILE,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, parsers_file)},

    {FLB_CONF_STR_PLUGINS_FILE,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, plugins_file)},

    {FLB_CONF_STR_LOGLEVEL,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, log)},

#ifdef FLB_HAVE_HTTP_SERVER
    {FLB_CONF_STR_HTTP_SERVER,
     FLB_CONF_TYPE_BOOL,
     offsetof(struct flb_config, http_server)},
    {FLB_CONF_STR_HTTP_LISTEN,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, http_listen)},

    {FLB_CONF_STR_HTTP_PORT,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, http_port)},
#endif

#ifdef FLB_HAVE_BUFFERING
    {FLB_CONF_STR_BUF_PATH,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, buffer_path)},

    {FLB_CONF_STR_BUF_WORKERS,
     FLB_CONF_TYPE_INT,
     offsetof(struct flb_config, buffer_workers)},
#endif

    {NULL, FLB_CONF_TYPE_OTHER, 0} /* end of array */
};


struct flb_config *flb_config_init()
{
    struct flb_config *config;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        perror("malloc");
        return NULL;
    }
    config->is_running = FLB_TRUE;

    /* Flush */
    config->flush        = FLB_CONFIG_FLUSH_SECS;
#if defined FLB_HAVE_FLUSH_PTHREADS
    config->flush_method = FLB_FLUSH_PTHREADS;
#elif defined FLB_HAVE_FLUSH_LIBCO
    config->flush_method = FLB_FLUSH_LIBCO;
#endif
    config->daemon       = FLB_FALSE;
    config->init_time    = time(NULL);
    config->kernel       = flb_kernel_info();
    config->verbose      = 3;
    config->grace        = 5;

#ifdef FLB_HAVE_HTTP_SERVER
    config->http_ctx     = NULL;
    config->http_server  = FLB_FALSE;
    config->http_listen  = flb_strdup(FLB_CONFIG_HTTP_LISTEN);
    config->http_port    = flb_strdup(FLB_CONFIG_HTTP_PORT);
#endif

#ifdef FLB_HAVE_BUFFERING
    config->buffer_ctx     = NULL;
    config->buffer_path    = NULL;
    config->buffer_workers = 0;
#endif

#ifdef FLB_HAVE_SQLDB
    mk_list_init(&config->sqldb_list);
#endif

#ifdef FLB_HAVE_LUAJIT
    mk_list_init(&config->luajit_list);
#endif

    mk_list_init(&config->collectors);
    mk_list_init(&config->in_plugins);
    mk_list_init(&config->parser_plugins);
    mk_list_init(&config->filter_plugins);
    mk_list_init(&config->out_plugins);
    mk_list_init(&config->inputs);
    mk_list_init(&config->parsers);
    mk_list_init(&config->filters);
    mk_list_init(&config->outputs);
    mk_list_init(&config->proxies);
    mk_list_init(&config->workers);

    memset(&config->tasks_map, '\0', sizeof(config->tasks_map));

    /* Environment */
    config->env = flb_env_create();

    /* Register plugins */
    flb_register_plugins(config);

    /* Ignoring SIGPIPE on Windows (scary) */
#ifndef _WIN32
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Prepare worker interface */
    flb_worker_init(config);

#ifdef FLB_HAVE_REGEX
    /* Regex support */
    flb_regex_init();
#endif

    return config;
}

void flb_config_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_collector *collector;

    if (config->log_file) {
        flb_free(config->log_file);
    }

    if (config->log) {
        flb_log_stop(config->log, config);
    }

    if (config->parsers_file) {
        flb_free(config->parsers_file);
    }

    if (config->plugins_file) {
        flb_free(config->plugins_file);
    }

    if (config->kernel) {
        flb_free(config->kernel->s_version.data);
        flb_free(config->kernel);
    }

    /* release resources */
    if (config->ch_event.fd) {
        close(config->ch_event.fd);
    }

    /* Pipe */
    if (config->ch_data[0]) {
        close(config->ch_data[0]);
        close(config->ch_data[1]);
    }

    /* Channel manager */
    if (config->ch_manager[0] > 0) {
        close(config->ch_manager[0]);
        if (config->ch_manager[0] != config->ch_manager[1]) {
            close(config->ch_manager[1]);
        }
    }

    /* Channel notifications */
    if (config->ch_notif[0] > 0) {
        close(config->ch_notif[0]);
        if (config->ch_notif[0] != config->ch_notif[1]) {
            close(config->ch_notif[1]);
        }
    }

    /* Collectors */
    mk_list_foreach_safe(head, tmp, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        mk_event_del(config->evl, &collector->event);

        if (collector->type == FLB_COLLECT_TIME) {
            mk_event_timeout_destroy(config->evl, &collector->event);
            if (collector->fd_timer > 0) {
                close(collector->fd_timer);
            }
        }

        mk_list_del(&collector->_head);
        flb_free(collector);
    }

    flb_env_destroy(config->env);

    /* Conf path */
    if (config->conf_path) {
        flb_free(config->conf_path);
    }

    /* Workers */
    flb_worker_exit(config);

    /* Event flush */
    if (config->evl) {
        mk_event_del(config->evl, &config->event_flush);
    }
    close(config->flush_fd);

    /* Release scheduler */
    flb_sched_exit(config);

#ifdef FLB_HAVE_HTTP_SERVER
    if (config->http_listen) {
        flb_free(config->http_listen);
    }

    if (config->http_port) {
        flb_free(config->http_port);
    }
#endif

#ifdef FLB_HAVE_STATS
    flb_stats_exit(config);
#endif

#ifdef FLB_HAVE_BUFFERING
    flb_free(config->buffer_path);
#endif

    if (config->evl) {
        mk_event_loop_destroy(config->evl);
    }
    flb_free(config);
}

char *flb_config_prop_get(char *key, struct mk_list *list)
{
    struct mk_list *head;
    struct flb_config_prop *p;

    mk_list_foreach(head, list) {
        p = mk_list_entry(head, struct flb_config_prop, _head);
        if (strcasecmp(key, p->key) == 0) {
            return p->val;
        }
    }

    return NULL;
}

static inline int prop_key_check(char *key, char *kv, int k_len)
{
    size_t len;

    len = strnlen(key,256);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }
    return -1;
}

static int set_log_level(struct flb_config *config, char *v_str)
{
    if (v_str != NULL) {
        if (strcasecmp(v_str, "error") == 0) {
            config->verbose = 1;
        }
        else if (strcasecmp(v_str, "warning") == 0) {
            config->verbose = 2;
        }
        else if (strcasecmp(v_str, "info") == 0) {
            config->verbose = 3;
        }
        else if (strcasecmp(v_str, "debug") == 0) {
            config->verbose = 4;
        }
        else if (strcasecmp(v_str, "trace") == 0) {
            config->verbose = 5;
        }
        else {
            return -1;
        }
    }
    else if (config->log) {
        config->verbose = 3;
    }
    return 0;
}

static inline int atobool(char*v)
{
    return  (strcasecmp("true", v) == 0 ||
             strcasecmp("on", v) == 0 ||
             strcasecmp("yes", v) == 0)
        ? FLB_TRUE
        : FLB_FALSE;
}

int flb_config_set_property(struct flb_config *config,
                            char *k, char *v)
{
    int i=0;
    int ret = -1;
    int *i_val;
    char **s_val;
    size_t len = strnlen(k, 256);
    char *key = service_configs[0].key;
    char *tmp = NULL;

    while (key != NULL) {
        if (prop_key_check(key, k,len) == 0) {
            if (!strncasecmp(key, FLB_CONF_STR_LOGLEVEL, 256)) {
                ret = set_log_level(config, v);
            }
            else if (!strncasecmp(key, FLB_CONF_STR_PARSERS_FILE, 32)) {
#ifdef FLB_HAVE_REGEX
                tmp = flb_env_var_translate(config->env, v);
                ret = flb_parser_conf_file(tmp, config);
                flb_free(tmp);
                tmp = NULL;
#endif
            }
#ifdef FLB_HAVE_PROXY_GO
            else if (!strncasecmp(key, FLB_CONF_STR_PLUGINS_FILE, 32)) {
                tmp = flb_env_var_translate(config->env, v);
                ret = flb_plugin_proxy_conf_file(tmp, config);
                flb_free(tmp);
                tmp = NULL;
            }
#endif
            else {
                ret = 0;
                tmp = flb_env_var_translate(config->env, v);
                switch(service_configs[i].type) {
                case FLB_CONF_TYPE_INT:
                    i_val  = (int*)((char*)config + service_configs[i].offset);
                    *i_val = atoi(tmp);
                    flb_free(tmp);
                    break;
                case FLB_CONF_TYPE_BOOL:
                    i_val = (int*)((char*)config+service_configs[i].offset);
                    *i_val = atobool(tmp);
                    flb_free(tmp);
                    break;
                case FLB_CONF_TYPE_STR:
                    s_val = (char**)((char*)config+service_configs[i].offset);
                    if ( *s_val != NULL ) {
                        flb_free(*s_val); /* release before overwriting */
                    }
                    *s_val = tmp;
                    break;
                default:
                    ret = -1;
                }
            }

            if (ret < 0) {
                if (tmp) {
                    flb_free(tmp);
                }
                return -1;
            }
            return 0;
        }
        key = service_configs[++i].key;
    }
    return 0;
}
