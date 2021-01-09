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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stddef.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_plugins.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_kernel.h>
#include <fluent-bit/flb_worker.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_utils.h>

const char *FLB_CONF_ENV_LOGLEVEL = "FLB_LOG_LEVEL";

int flb_regex_init();

struct flb_service_config service_configs[] = {
    {FLB_CONF_STR_FLUSH,
     FLB_CONF_TYPE_DOUBLE,
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

    /* Storage */
    {FLB_CONF_STORAGE_PATH,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, storage_path)},
    {FLB_CONF_STORAGE_SYNC,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, storage_sync)},
    {FLB_CONF_STORAGE_METRICS,
     FLB_CONF_TYPE_BOOL,
     offsetof(struct flb_config, storage_metrics)},
    {FLB_CONF_STORAGE_CHECKSUM,
     FLB_CONF_TYPE_BOOL,
     offsetof(struct flb_config, storage_checksum)},
    {FLB_CONF_STORAGE_BL_MEM_LIMIT,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, storage_bl_mem_limit)},
    {FLB_CONF_STORAGE_MAX_CHUNKS_UP,
     FLB_CONF_TYPE_INT,
     offsetof(struct flb_config, storage_max_chunks_up)},

    /* Coroutines */
    {FLB_CONF_STR_CORO_STACK_SIZE,
     FLB_CONF_TYPE_INT,
     offsetof(struct flb_config, coro_stack_size)},

#ifdef FLB_HAVE_STREAM_PROCESSOR
    {FLB_CONF_STR_STREAMS_FILE,
     FLB_CONF_TYPE_STR,
     offsetof(struct flb_config, stream_processor_file)},
#endif

    {NULL, FLB_CONF_TYPE_OTHER, 0} /* end of array */
};


struct flb_config *flb_config_init()
{
    int ret;
    struct flb_config *config;

    config = flb_calloc(1, sizeof(struct flb_config));
    if (!config) {
        flb_errno();
        return NULL;
    }

    MK_EVENT_ZERO(&config->ch_event);
    MK_EVENT_ZERO(&config->event_flush);
    MK_EVENT_ZERO(&config->event_shutdown);

    /* is data ingestion active ? */
    config->is_ingestion_active = FLB_TRUE;

    /* Is the engine (event loop) actively running ? */
    config->is_running = FLB_TRUE;

    /* Flush */
    config->flush        = FLB_CONFIG_FLUSH_SECS;
    config->daemon       = FLB_FALSE;
    config->init_time    = time(NULL);
    config->kernel       = flb_kernel_info();
    config->verbose      = 3;
    config->grace        = 5;
    config->exit_status_code = 0;

#ifdef FLB_HAVE_HTTP_SERVER
    config->http_ctx     = NULL;
    config->http_server  = FLB_FALSE;
    config->http_listen  = flb_strdup(FLB_CONFIG_HTTP_LISTEN);
    config->http_port    = flb_strdup(FLB_CONFIG_HTTP_PORT);
#endif

    config->http_proxy = getenv("HTTP_PROXY");
    if (config->http_proxy != NULL && strcmp(config->http_proxy, "") == 0) {
        /* Proxy should not be set when the `HTTP_PROXY` is set to "" */
        config->http_proxy = NULL;
    }

    config->cio          = NULL;
    config->storage_path = NULL;
    config->storage_input_plugin = NULL;

#ifdef FLB_HAVE_SQLDB
    mk_list_init(&config->sqldb_list);
#endif

#ifdef FLB_HAVE_LUAJIT
    mk_list_init(&config->luajit_list);
#endif

#ifdef FLB_HAVE_STREAM_PROCESSOR
    flb_slist_create(&config->stream_processor_tasks);
#endif

    /* Set default coroutines stack size */
    config->coro_stack_size = FLB_CORO_STACK_SIZE;

    /* Initialize linked lists */
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
    mk_list_init(&config->upstreams);

    memset(&config->tasks_map, '\0', sizeof(config->tasks_map));

    /* Environment */
    config->env = flb_env_create();

    /* Register static plugins */
    ret = flb_plugins_register(config);
    if (ret == -1) {
        flb_error("[config] plugins registration failed");
        flb_config_exit(config);
        return NULL;
    }

    /* Create environment for dynamic plugins */
    config->dso_plugins = flb_plugin_create();

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
        flb_log_destroy(config->log, config);
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
        mk_event_closesocket(config->ch_event.fd);
    }

    /* Pipe */
    if (config->ch_data[0]) {
        mk_event_closesocket(config->ch_data[0]);
        mk_event_closesocket(config->ch_data[1]);
    }

    /* Channel manager */
    if (config->ch_manager[0] > 0) {
        mk_event_closesocket(config->ch_manager[0]);
        if (config->ch_manager[0] != config->ch_manager[1]) {
            mk_event_closesocket(config->ch_manager[1]);
        }
    }

    /* Channel notifications */
    if (config->ch_notif[0] > 0) {
        mk_event_closesocket(config->ch_notif[0]);
        if (config->ch_notif[0] != config->ch_notif[1]) {
            mk_event_closesocket(config->ch_notif[1]);
        }
    }

    /* Collectors */
    mk_list_foreach_safe(head, tmp, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);

        if (collector->type == FLB_COLLECT_TIME) {
            if (collector->fd_timer > 0) {
                mk_event_timeout_destroy(config->evl, &collector->event);
                mk_event_closesocket(collector->fd_timer);
            }
        } else {
            mk_event_del(config->evl, &collector->event);
        }

        mk_list_del(&collector->_head);
        flb_free(collector);
    }

    flb_env_destroy(config->env);

    /* Program name */
    if (config->program_name) {
        flb_sds_destroy(config->program_name);
    }

    /* Conf path */
    if (config->conf_path) {
        flb_free(config->conf_path);
    }

    /* Destroy any DSO context */
    flb_plugin_destroy(config->dso_plugins);

    /* Workers */
    flb_worker_exit(config);

    /* Event flush */
    if (config->evl) {
        mk_event_del(config->evl, &config->event_flush);
    }
    mk_event_closesocket(config->flush_fd);

    /* Release scheduler */
    flb_sched_destroy(config->sched);

#ifdef FLB_HAVE_HTTP_SERVER
    if (config->http_listen) {
        flb_free(config->http_listen);
    }

    if (config->http_port) {
        flb_free(config->http_port);
    }
#endif

    if (config->storage_path) {
        flb_free(config->storage_path);
    }
    if (config->storage_sync) {
        flb_free(config->storage_sync);
    }
    if (config->storage_bl_mem_limit) {
        flb_free(config->storage_bl_mem_limit);
    }

#ifdef FLB_HAVE_STREAM_PROCESSOR
    if (config->stream_processor_file) {
        flb_free(config->stream_processor_file);
    }

    flb_slist_destroy(&config->stream_processor_tasks);
#endif

    if (config->evl) {
        mk_event_loop_destroy(config->evl);
    }

    flb_plugins_unregister(config);
    flb_free(config);
}

const char *flb_config_prop_get(const char *key, struct mk_list *list)
{
    return flb_kv_get_key_value(key, list);
}

static inline int prop_key_check(const char *key, const char *kv, int k_len)
{
    size_t len;

    len = strnlen(key,256);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }
    return -1;
}

static int set_log_level(struct flb_config *config, const char *v_str)
{
    if (v_str != NULL) {
        if (strcasecmp(v_str, "error") == 0) {
            config->verbose = 1;
        }
        else if (strcasecmp(v_str, "warn") == 0 ||
                 strcasecmp(v_str, "warning") == 0) {
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

int set_log_level_from_env(struct flb_config *config)
{
    const char *val = NULL;
    val = flb_env_get(config->env, FLB_CONF_ENV_LOGLEVEL);
    if (val) {
        return set_log_level(config, val);
    }
    return -1;
}

int flb_config_set_property(struct flb_config *config,
                            const char *k, const char *v)
{
    int i=0;
    int ret = -1;
    int *i_val;
    double *d_val;
    char **s_val;
    size_t len = strnlen(k, 256);
    char *key = service_configs[0].key;
    flb_sds_t tmp = NULL;

    while (key != NULL) {
        if (prop_key_check(key, k,len) == 0) {
            if (!strncasecmp(key, FLB_CONF_STR_LOGLEVEL, 256)) {
                #ifndef FLB_HAVE_STATIC_CONF
                if (set_log_level_from_env(config) < 0) {
                #endif
                    tmp = flb_env_var_translate(config->env, v);
                    if (tmp) {
                        ret = set_log_level(config, tmp);
                        flb_sds_destroy(tmp);
                        tmp = NULL;
                    }
                    else {
                        ret = set_log_level(config, v);
                    }
                #ifndef FLB_HAVE_STATIC_CONF
                }
                #endif
            }
            else if (!strncasecmp(key, FLB_CONF_STR_PARSERS_FILE, 32)) {
#ifdef FLB_HAVE_PARSER
                tmp = flb_env_var_translate(config->env, v);
                ret = flb_parser_conf_file(tmp, config);
                flb_sds_destroy(tmp);
                tmp = NULL;
#endif
            }
            else if (!strncasecmp(key, FLB_CONF_STR_PLUGINS_FILE, 32)) {
                tmp = flb_env_var_translate(config->env, v);
                ret = flb_plugin_load_config_file(tmp, config);
                flb_sds_destroy(tmp);
                tmp = NULL;
            }
            else {
                ret = 0;
                tmp = flb_env_var_translate(config->env, v);
                switch(service_configs[i].type) {
                case FLB_CONF_TYPE_INT:
                    i_val  = (int*)((char*)config + service_configs[i].offset);
                    *i_val = atoi(tmp);
                    flb_sds_destroy(tmp);
                    break;
                case FLB_CONF_TYPE_DOUBLE:
                    d_val  = (double*)((char*)config + service_configs[i].offset);
                    *d_val = atof(tmp);
                    flb_sds_destroy(tmp);
                    break;
                case FLB_CONF_TYPE_BOOL:
                    i_val = (int*)((char*)config+service_configs[i].offset);
                    *i_val = flb_utils_bool(tmp);
                    flb_sds_destroy(tmp);
                    break;
                case FLB_CONF_TYPE_STR:
                    s_val = (char**)((char*)config+service_configs[i].offset);
                    if ( *s_val != NULL ) {
                        flb_free(*s_val); /* release before overwriting */
                    }

                    *s_val = flb_strdup(tmp);
                    flb_sds_destroy(tmp);
                    break;
                default:
                    ret = -1;
                }
            }

            if (ret < 0) {
                if (tmp) {
                    flb_sds_destroy(tmp);
                }
                return -1;
            }
            return 0;
        }
        key = service_configs[++i].key;
    }
    return 0;
}

int flb_config_set_program_name(struct flb_config *config, char *name)
{
    config->program_name = flb_sds_create(name);

    if (!config->program_name) {
        return -1;
    }

    return 0;
}
