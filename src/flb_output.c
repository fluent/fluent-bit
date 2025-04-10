/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_uri.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_http_client_debug.h>
#include <fluent-bit/flb_output_thread.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_pack.h>

FLB_TLS_DEFINE(struct flb_out_flush_params, out_flush_params);

/* Histogram buckets for output latency in seconds */
static const double output_latency_buckets[] = {
    0.5, 1.0, 1.5, 2.5, 5.0, 10.0, 20.0, 30.0
};

struct flb_config_map output_global_properties[] = {
    {
        FLB_CONFIG_MAP_STR, "match", NULL,
        0, FLB_FALSE, 0,
        "Set a tag pattern to match the records that this output should process. "
        "Supports exact matches or wildcards (e.g., '*')."
    },
#ifdef FLB_HAVE_REGEX
    {
        FLB_CONFIG_MAP_STR, "match_regex", NULL,
        0, FLB_FALSE, 0,
        "Set a regular expression to match tags for output routing. This allows more flexible matching "
        "compared to simple wildcards."
    },
#endif
    {
        FLB_CONFIG_MAP_STR, "alias", NULL,
        0, FLB_FALSE, 0,
        "Sets an alias for the output instance. This is useful when using multiple instances of the same "
        "output plugin. If no alias is set, the instance will be named using the plugin name and a sequence number."
    },
    {
        FLB_CONFIG_MAP_STR, "log_level", "info",
        0, FLB_FALSE, 0,
        "Specifies the log level for this output plugin. If not set, the plugin "
        "will use the global log level defined in the 'service' section. If the global "
        "log level is also not specified, it defaults to 'info'."
    },
    {
        FLB_CONFIG_MAP_TIME, "log_suppress_interval", "0",
        0, FLB_FALSE, 0,
        "Allows suppression of repetitive log messages from the output plugin that appear similar within a specified "
        "time interval. Defaults to 0, meaning no suppression."
    },
    {
        FLB_CONFIG_MAP_STR, "retry_limit", "1",
        0, FLB_FALSE, 0,
        "Set the retry limit for the output plugin when delivery fails. "
        "Accepted values: a positive integer, 'no_limits', 'false', or 'off' to disable retry limits, "
        "or 'no_retries' to disable retries entirely."
    },
    {
        FLB_CONFIG_MAP_STR, "tls.windows.certstore_name", NULL,
        0, FLB_FALSE, 0,
        "Sets the certstore name on an output (Windows)"
    },
    {
        FLB_CONFIG_MAP_STR, "tls.windows.use_enterprise_store", NULL,
        0, FLB_FALSE, 0,
        "Sets whether using enterprise certstore or not on an output (Windows)"
    },

    {0}
};

struct mk_list *flb_output_get_global_config_map(struct flb_config *config)
{
    return flb_config_map_create(config, output_global_properties);
}

void flb_output_prepare()
{
    FLB_TLS_INIT(out_flush_params);
}

/* Validate the the output address protocol */
static int check_protocol(const char *prot, const char *output)
{
    int len;
    char *p;

    p = strstr(output, "://");
    if (p && p != output) {
        len = p - output;
    }
    else {
        len = strlen(output);
    }

    if (strlen(prot) != len) {
        return 0;
    }

    /* Output plugin match */
    if (strncasecmp(prot, output, len) == 0) {
        return 1;
    }

    return 0;
}


/* Invoke pre-run call for the output plugin */
void flb_output_pre_run(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_output_instance *ins;
    struct flb_output_plugin *p;

    mk_list_foreach(head, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        p = ins->p;
        if (p->cb_pre_run) {
            p->cb_pre_run(ins->context, config);
        }
    }
}

static void flb_output_free_properties(struct flb_output_instance *ins)
{

    flb_kv_release(&ins->properties);
    flb_kv_release(&ins->net_properties);

#ifdef FLB_HAVE_TLS
    if (ins->tls_vhost) {
        flb_sds_destroy(ins->tls_vhost);
    }
    if (ins->tls_ca_path) {
        flb_sds_destroy(ins->tls_ca_path);
    }
    if (ins->tls_ca_file) {
        flb_sds_destroy(ins->tls_ca_file);
    }
    if (ins->tls_crt_file) {
        flb_sds_destroy(ins->tls_crt_file);
    }
    if (ins->tls_key_file) {
        flb_sds_destroy(ins->tls_key_file);
    }
    if (ins->tls_key_passwd) {
        flb_sds_destroy(ins->tls_key_passwd);
    }
    if (ins->tls_min_version) {
        flb_sds_destroy(ins->tls_min_version);
    }
    if (ins->tls_max_version) {
        flb_sds_destroy(ins->tls_max_version);
    }
    if (ins->tls_ciphers) {
        flb_sds_destroy(ins->tls_ciphers);
    }
# if defined(FLB_SYSTEM_WINDOWS)
    if (ins->tls_win_certstore_name) {
        flb_sds_destroy(ins->tls_win_certstore_name);
    }
# endif
#endif
}

void flb_output_flush_prepare_destroy(struct flb_output_flush *out_flush)
{
    struct flb_output_instance *ins = out_flush->o_ins;
    struct flb_out_thread_instance *th_ins;

    /* Move output coroutine context from active list to the destroy one */
    if (flb_output_is_threaded(ins) == FLB_TRUE) {
        th_ins = flb_output_thread_instance_get();
        pthread_mutex_lock(&th_ins->flush_mutex);
        mk_list_del(&out_flush->_head);
        mk_list_add(&out_flush->_head, &th_ins->flush_list_destroy);
        pthread_mutex_unlock(&th_ins->flush_mutex);
    }
    else {
        mk_list_del(&out_flush->_head);
        mk_list_add(&out_flush->_head, &ins->flush_list_destroy);
    }
}

int flb_output_flush_id_get(struct flb_output_instance *ins)
{
    int id;
    int max = (2 << 13) - 1; /* max for 14 bits */
    struct flb_out_thread_instance *th_ins;

    if (flb_output_is_threaded(ins) == FLB_TRUE) {
        th_ins = flb_output_thread_instance_get();
        id = th_ins->flush_id;
        th_ins->flush_id++;

        /* reset once it reach the maximum allowed */
        if (th_ins->flush_id > max) {
            th_ins->flush_id = 0;
        }
    }
    else {
        id = ins->flush_id;
        ins->flush_id++;

        /* reset once it reach the maximum allowed */
        if (ins->flush_id > max) {
            ins->flush_id = 0;
        }
    }

    return id;
}

void flb_output_coro_add(struct flb_output_instance *ins, struct flb_coro *coro)
{
    struct flb_output_flush *out_flush;

    out_flush = (struct flb_output_flush *) FLB_CORO_DATA(coro);
    mk_list_add(&out_flush->_head, &ins->flush_list);
}

/*
 * Queue a task to be flushed at a later time
 * Deletes retry context if enqueue fails
 */
static int flb_output_task_queue_enqueue(struct flb_task_queue *queue,
                                         struct flb_task_retry *retry,
                                         struct flb_task *task,
                                         struct flb_output_instance *out_ins,
                                         struct flb_config *config)
{
    struct flb_task_enqueued *queued_task;

    queued_task = flb_malloc(sizeof(struct flb_task_enqueued));
    if (!queued_task) {
        flb_errno();
        if (retry) {
            flb_task_retry_destroy(retry);
        }
        return -1;
    }
    queued_task->retry = retry;
    queued_task->out_instance = out_ins;
    queued_task->task = task;
    queued_task->config = config;

    mk_list_add(&queued_task->_head, &queue->pending);
    return 0;
}

/*
 * Pop task from pending queue and flush it
 * Will delete retry context if flush fails
 */
static int flb_output_task_queue_flush_one(struct flb_task_queue *queue)
{
    struct flb_task_enqueued *queued_task;
    int ret;
    int is_empty;

    is_empty = mk_list_is_empty(&queue->pending) == 0;
    if (is_empty) {
        flb_error("Attempting to flush task from an empty in_progress queue");
        return -1;
    }

    queued_task = mk_list_entry_first(&queue->pending, struct flb_task_enqueued, _head);
    mk_list_del(&queued_task->_head);
    mk_list_add(&queued_task->_head, &queue->in_progress);

    /*
     * Remove temporary user now that task is out of singleplex queue.
     * Flush will add back the user representing queued_task->out_instance if it succeeds.
     */
    flb_task_users_dec(queued_task->task, FLB_FALSE);
    ret = flb_output_task_flush(queued_task->task,
                                queued_task->out_instance,
                                queued_task->config);

    /* Destroy retry context if needed */
    if (ret == -1) {
        if (queued_task->retry) {
            flb_task_retry_destroy(queued_task->retry);
        }
        /* Flush the next task */
        flb_output_task_singleplex_flush_next(queue);
        return -1;
    }

    return ret;
}

/*
 * Will either run or queue running a single task
 * Deletes retry context if enqueue fails
 */
int flb_output_task_singleplex_enqueue(struct flb_task_queue *queue,
                                       struct flb_task_retry *retry,
                                       struct flb_task *task,
                                       struct flb_output_instance *out_ins,
                                       struct flb_config *config)
{
    int ret;
    int is_empty;

    /*
     * Add temporary user to preserve task while in singleplex queue.
     * Temporary user will be removed when task is removed from queue.
     *
     * Note: if we fail to increment now, then the task may be prematurely
     * deleted if the task's users go to 0 while we are waiting in the
     * queue.
     */
    flb_task_users_inc(task);

    /* Enqueue task */
    ret = flb_output_task_queue_enqueue(queue, retry, task, out_ins, config);
    if (ret == -1) {
        return -1;
    }

    /* Launch task if nothing is running */
    is_empty = mk_list_is_empty(&out_ins->singleplex_queue->in_progress) == 0;
    if (is_empty) {
        return flb_output_task_queue_flush_one(out_ins->singleplex_queue);
    }

    return 0;
}

/*
 * Clear in progress task and flush a single queued task if exists
 * Deletes retry context on next flush if flush fails
 */
int flb_output_task_singleplex_flush_next(struct flb_task_queue *queue)
{
    int is_empty;
    struct flb_task_enqueued *ended_task;

    /* Remove in progress task */
    is_empty = mk_list_is_empty(&queue->in_progress) == 0;
    if (!is_empty) {
        ended_task = mk_list_entry_first(&queue->in_progress,
                                        struct flb_task_enqueued, _head);
        mk_list_del(&ended_task->_head);
        flb_free(ended_task);
    }

    /* Flush if there is a pending task queued */
    is_empty = mk_list_is_empty(&queue->pending) == 0;
    if (!is_empty) {
        return flb_output_task_queue_flush_one(queue);
    }
    return 0;
}

/*
 * Flush a task through the output plugin, either using a worker thread + coroutine
 * or a simple co-routine in the current thread.
 */
int flb_output_task_flush(struct flb_task *task,
                          struct flb_output_instance *out_ins,
                          struct flb_config *config)
{
    int ret;
    struct flb_output_flush *out_flush;

    if (flb_output_is_threaded(out_ins) == FLB_TRUE) {
        flb_task_users_inc(task);

        /* Dispatch the task to the thread pool */
        ret = flb_output_thread_pool_flush(task, out_ins, config);
        if (ret == -1) {
            flb_task_users_dec(task, FLB_FALSE);

            /* If we are in synchronous mode, flush one waiting task */
            if (out_ins->flags & FLB_OUTPUT_SYNCHRONOUS) {
                flb_output_task_singleplex_flush_next(out_ins->singleplex_queue);
            }
        }
    }
    else {
        /* Queue co-routine handling */
        out_flush = flb_output_flush_create(task,
                                           task->i_ins,
                                           out_ins,
                                           config);
        if (!out_flush) {
            return -1;
        }

        flb_task_users_inc(task);
        ret = flb_pipe_w(config->ch_self_events[1], &out_flush,
                        sizeof(struct flb_output_flush*));
        if (ret == -1) {
            flb_pipe_error();
            flb_output_flush_destroy(out_flush);
            flb_task_users_dec(task, FLB_FALSE);

            /* If we are in synchronous mode, flush one waiting task */
            if (out_ins->flags & FLB_OUTPUT_SYNCHRONOUS) {
                flb_output_task_singleplex_flush_next(out_ins->singleplex_queue);
            }

            return -1;
        }
    }

    return 0;
}

int flb_output_instance_destroy(struct flb_output_instance *ins)
{
    if (ins->alias) {
        flb_sds_destroy(ins->alias);
    }

    /* Remove URI context */
    if (ins->host.uri) {
        flb_uri_destroy(ins->host.uri);
    }

    flb_sds_destroy(ins->host.name);
    flb_sds_destroy(ins->host.address);
    flb_sds_destroy(ins->host.listen);
    flb_sds_destroy(ins->match);

#ifdef FLB_HAVE_REGEX
        if (ins->match_regex) {
            flb_regex_destroy(ins->match_regex);
        }
#endif

#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        if (ins->tls) {
            flb_tls_destroy(ins->tls);
        }
    }

    if (ins->tls_config_map) {
        flb_config_map_destroy(ins->tls_config_map);
    }
#endif

    /* Remove metrics */
#ifdef FLB_HAVE_METRICS
    if (ins->cmt) {
        cmt_destroy(ins->cmt);
    }

    if (ins->metrics) {
        flb_metrics_destroy(ins->metrics);
    }
#endif

    /* destroy callback context */
    if (ins->callback) {
        flb_callback_destroy(ins->callback);
    }

    /* destroy config map */
    if (ins->config_map) {
        flb_config_map_destroy(ins->config_map);
    }

    if (ins->net_config_map) {
        flb_config_map_destroy(ins->net_config_map);
    }

    if (ins->ch_events[0] > 0) {
        mk_event_closesocket(ins->ch_events[0]);
    }

    if (ins->ch_events[1] > 0) {
        mk_event_closesocket(ins->ch_events[1]);
    }

    /* release properties */
    flb_output_free_properties(ins);

    /* free singleplex queue */
    if (ins->flags & FLB_OUTPUT_SYNCHRONOUS) {
        flb_task_queue_destroy(ins->singleplex_queue);
    }

    mk_list_del(&ins->_head);

    /* processor */
    if (ins->processor) {
        flb_processor_destroy(ins->processor);
    }

    flb_free(ins);

    return 0;
}

/* Invoke exit call for the output plugin */
void flb_output_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_output_instance *ins;
    struct flb_output_plugin *p;
    void *params;

    mk_list_foreach_safe(head, tmp, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        p = ins->p;

        if (ins->is_threaded == FLB_FALSE) {
            if (ins->p->cb_worker_exit) {
                ins->p->cb_worker_exit(ins->context, ins->config);
            }
        }

        /* Stop any worker thread */
        if (flb_output_is_threaded(ins) == FLB_TRUE) {
            flb_output_thread_pool_destroy(ins);
        }

        /* Check a exit callback */
        if (p->cb_exit) {
            p->cb_exit(ins->context, config);
        }
        flb_output_instance_destroy(ins);
    }

    params = FLB_TLS_GET(out_flush_params);
    if (params) {
        flb_free(params);
        FLB_TLS_SET(out_flush_params, NULL);
    }
}

static inline int instance_id(struct flb_config *config)
{
    struct flb_output_instance *ins;

    if (mk_list_size(&config->outputs) == 0) {
        return 0;
    }

    ins = mk_list_entry_last(&config->outputs, struct flb_output_instance,
                             _head);
    return (ins->id + 1);
}

struct flb_output_instance *flb_output_get_instance(struct flb_config *config,
                                                    int out_id)
{
    struct mk_list *head;
    struct flb_output_instance *ins;

    mk_list_foreach(head, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (ins->id == out_id) {
            break;
        }
        ins = NULL;
    }

    if (!ins) {
        return NULL;
    }

    return ins;
}

/*
 * Invoked everytime a flush callback has finished (returned). This function
 * is called from the event loop.
 */
int flb_output_flush_finished(struct flb_config *config, int out_id)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *list;
    struct flb_output_instance *ins;
    struct flb_output_flush *out_flush;
    struct flb_out_thread_instance *th_ins;

    ins = flb_output_get_instance(config, out_id);
    if (!ins) {
        return -1;
    }

    if (flb_output_is_threaded(ins) == FLB_TRUE) {
        th_ins = flb_output_thread_instance_get();
        list = &th_ins->flush_list_destroy;
    }
    else {
        list = &ins->flush_list_destroy;
    }

    /* Look for output coroutines that needs to be destroyed */
    mk_list_foreach_safe(head, tmp, list) {
        out_flush = mk_list_entry(head, struct flb_output_flush, _head);
        flb_output_flush_destroy(out_flush);
    }

    return 0;
}


/*
 * It validate an output type given the string, it return the
 * proper type and if valid, populate the global config.
 */
struct flb_output_instance *flb_output_new(struct flb_config *config,
                                           const char *output, void *data,
                                           int public_only)
{
    int ret = -1;
    int flags = 0;
    struct mk_list *head;
    struct flb_output_plugin *plugin;
    struct flb_output_instance *instance = NULL;

    if (!output) {
        return NULL;
    }

    mk_list_foreach(head, &config->out_plugins) {
        plugin = mk_list_entry(head, struct flb_output_plugin, _head);
        if (!check_protocol(plugin->name, output)) {
            plugin = NULL;
            continue;
        }

        if (public_only && plugin->flags & FLB_OUTPUT_PRIVATE) {
            return NULL;
        }
        break;
    }

    if (!plugin) {
        return NULL;
    }

    /* Create and load instance */
    instance = flb_calloc(1, sizeof(struct flb_output_instance));
    if (!instance) {
        flb_errno();
        return NULL;
    }

    /* Initialize event type, if not set, default to FLB_OUTPUT_LOGS */
    if (plugin->event_type == 0) {
        instance->event_type = FLB_OUTPUT_LOGS;
    }
    else {
        instance->event_type = plugin->event_type;
    }
    instance->config = config;
    instance->log_level = -1;
    instance->log_suppress_interval = -1;
    instance->test_mode = FLB_FALSE;
    instance->is_threaded = FLB_FALSE;
    instance->tp_workers = plugin->workers;

    /* Retrieve an instance id for the output instance */
    instance->id = instance_id(config);

    /* format name (with instance id) */
    snprintf(instance->name, sizeof(instance->name) - 1,
             "%s.%i", plugin->name, instance->id);
    instance->p = plugin;
    instance->callback = flb_callback_create(instance->name);
    if (!instance->callback) {
        if (instance->flags & FLB_OUTPUT_SYNCHRONOUS) {
            flb_task_queue_destroy(instance->singleplex_queue);
        }
        flb_free(instance);
        return NULL;
    }

    if (plugin->type == FLB_OUTPUT_PLUGIN_CORE) {
        instance->context = NULL;
    }
    else {
        struct flb_plugin_proxy_context *ctx;

        ctx = flb_calloc(1, sizeof(struct flb_plugin_proxy_context));
        if (!ctx) {
            flb_errno();
            if (instance->flags & FLB_OUTPUT_SYNCHRONOUS) {
                flb_task_queue_destroy(instance->singleplex_queue);
            }
            flb_free(instance);
            return NULL;
        }

        ctx->proxy = plugin->proxy;

        instance->context = ctx;
    }

    instance->alias       = NULL;
    instance->flags       = instance->p->flags;
    instance->data        = data;
    instance->match       = NULL;
#ifdef FLB_HAVE_REGEX
    instance->match_regex = NULL;
#endif
    instance->retry_limit = 1;
    instance->host.name   = NULL;
    instance->host.address = NULL;
    instance->net_config_map = NULL;

    /* Storage */
    instance->total_limit_size = -1;

    /* Parent plugin flags */
    flags = instance->flags;
    if (flags & FLB_IO_TCP) {
        instance->use_tls = FLB_FALSE;
    }
    else if (flags & FLB_IO_TLS) {
        instance->use_tls = FLB_TRUE;
    }
    else if (flags & FLB_IO_OPT_TLS) {
        /* TLS must be enabled manually in the config */
        instance->use_tls = FLB_FALSE;
        instance->flags |= FLB_IO_TLS;
    }

#ifdef FLB_HAVE_TLS
    instance->tls                   = NULL;
    instance->tls_debug             = -1;
    instance->tls_verify            = FLB_TRUE;
    instance->tls_verify_hostname   = FLB_FALSE;
    instance->tls_vhost             = NULL;
    instance->tls_ca_path           = NULL;
    instance->tls_ca_file           = NULL;
    instance->tls_crt_file          = NULL;
    instance->tls_key_file          = NULL;
    instance->tls_key_passwd        = NULL;
# if defined(FLB_SYSTEM_WINDOWS)
    instance->tls_win_certstore_name = NULL;
    instance->tls_win_use_enterprise_certstore = FLB_FALSE;
# endif
#endif

    if (plugin->flags & FLB_OUTPUT_NET) {
        ret = flb_net_host_set(plugin->name, &instance->host, output);
        if (ret != 0) {
            if (instance->flags & FLB_OUTPUT_SYNCHRONOUS) {
                flb_task_queue_destroy(instance->singleplex_queue);
            }
            flb_free(instance);
            return NULL;
        }
    }

    /* Create singleplex queue if SYNCHRONOUS mode is used */
    instance->singleplex_queue = NULL;
    if (instance->flags & FLB_OUTPUT_SYNCHRONOUS) {
        instance->singleplex_queue = flb_task_queue_create();
        if (!instance->singleplex_queue) {
            flb_free(instance);
            flb_errno();
            return NULL;
        }
    }

    flb_kv_init(&instance->properties);
    flb_kv_init(&instance->net_properties);
    mk_list_init(&instance->upstreams);
    mk_list_init(&instance->flush_list);
    mk_list_init(&instance->flush_list_destroy);

    mk_list_add(&instance->_head, &config->outputs);

    /* processor instance */
    instance->processor = flb_processor_create(config, instance->name, instance, FLB_PLUGIN_OUTPUT);

    /* Tests */
    instance->test_formatter.callback = plugin->test_formatter.callback;
    instance->test_response.callback = plugin->test_response.callback;


    return instance;
}

static inline int prop_key_check(const char *key, const char *kv, int k_len)
{
    int len;

    len = strlen(key);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

/* Override a configuration property for the given input_instance plugin */
int flb_output_set_property(struct flb_output_instance *ins,
                            const char *k, const char *v)
{
    int len;
    int ret;
    ssize_t limit;
    flb_sds_t tmp;
    struct flb_kv *kv;
    struct flb_config *config = ins->config;

    len = strlen(k);
    tmp = flb_env_var_translate(config->env, v);
    if (tmp) {
        if (strlen(tmp) == 0) {
            flb_sds_destroy(tmp);
            tmp = NULL;
        }
    }

    /* Check if the key is a known/shared property */
    if (prop_key_check("match", k, len) == 0) {
        flb_utils_set_plugin_string_property("match", &ins->match, tmp);
    }
#ifdef FLB_HAVE_REGEX
    else if (prop_key_check("match_regex", k, len) == 0 && tmp) {
        ins->match_regex = flb_regex_create(tmp);
        flb_sds_destroy(tmp);
    }
#endif
    else if (prop_key_check("alias", k, len) == 0 && tmp) {
        flb_utils_set_plugin_string_property("alias", &ins->alias, tmp);
    }
    else if (prop_key_check("log_level", k, len) == 0 && tmp) {
        ret = flb_log_get_level_str(tmp);
        flb_sds_destroy(tmp);
        if (ret == -1) {
            return -1;
        }
        ins->log_level = ret;
    }
    else if (prop_key_check("log_suppress_interval", k, len) == 0 && tmp) {
        ret = flb_utils_time_to_seconds(tmp);
        flb_sds_destroy(tmp);
        if (ret == -1) {
            return -1;
        }
        ins->log_suppress_interval = ret;
    }
    else if (prop_key_check("host", k, len) == 0) {
        flb_utils_set_plugin_string_property("host", &ins->host.name, tmp);
    }
    else if (prop_key_check("port", k, len) == 0) {
        if (tmp) {
            ins->host.port = atoi(tmp);
            flb_sds_destroy(tmp);
        }
        else {
            ins->host.port = 0;
        }
    }
    else if (prop_key_check("ipv6", k, len) == 0 && tmp) {
        ins->host.ipv6 = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("retry_limit", k, len) == 0) {
        if (tmp) {
            if (strcasecmp(tmp, "no_limits") == 0 ||
                strcasecmp(tmp, "false") == 0 ||
                strcasecmp(tmp, "off") == 0) {
                /* No limits for retries */
                ins->retry_limit = FLB_OUT_RETRY_UNLIMITED;
            }
            else if (strcasecmp(tmp, "no_retries") == 0) {
                ins->retry_limit = FLB_OUT_RETRY_NONE;
            }
            else {
                ins->retry_limit = atoi(tmp);
                if (ins->retry_limit <= 0) {
                    flb_warn("[config] invalid retry_limit. set default.");
                    /* set default when input is invalid number */
                    ins->retry_limit = 1;
                }
            }
            flb_sds_destroy(tmp);
        }
        else {
            ins->retry_limit = 1;
        }
    }
    else if (strncasecmp("net.", k, 4) == 0 && tmp) {
        kv = flb_kv_item_create(&ins->net_properties, (char *) k, NULL);
        if (!kv) {
            if (tmp) {
                flb_sds_destroy(tmp);
            }
            return -1;
        }
        kv->val = tmp;
    }
#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    else if (strncasecmp("_debug.http.", k, 12) == 0 && tmp) {
        ret = flb_http_client_debug_property_is_valid((char *) k, tmp);
        if (ret == FLB_TRUE) {
            kv = flb_kv_item_create(&ins->properties, (char *) k, NULL);
            if (!kv) {
                if (tmp) {
                    flb_sds_destroy(tmp);
                }
                return -1;
            }
            kv->val = tmp;
        }
        else {
            flb_error("[config] invalid property '%s' on instance '%s'",
                      k, flb_output_name(ins));
            flb_sds_destroy(tmp);
        }
    }
#endif
#ifdef FLB_HAVE_TLS
    else if (prop_key_check("tls", k, len) == 0 && tmp) {
        ins->use_tls = flb_utils_bool(tmp);
        if (ins->use_tls == FLB_TRUE && ((ins->flags & FLB_IO_TLS) == 0)) {
            flb_error("[config] %s does not support TLS", ins->name);
            flb_sds_destroy(tmp);
            return -1;
        }
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.verify", k, len) == 0 && tmp) {
        ins->tls_verify = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.verify_hostname", k, len) == 0 && tmp) {
        ins->tls_verify_hostname = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.debug", k, len) == 0 && tmp) {
        ins->tls_debug = atoi(tmp);
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.vhost", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.vhost", &ins->tls_vhost, tmp);
    }
    else if (prop_key_check("tls.ca_path", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.ca_path", &ins->tls_ca_path, tmp);
    }
    else if (prop_key_check("tls.ca_file", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.ca_file", &ins->tls_ca_file, tmp);
    }
    else if (prop_key_check("tls.crt_file", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.crt_file", &ins->tls_crt_file, tmp);
    }
    else if (prop_key_check("tls.key_file", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.key_file", &ins->tls_key_file, tmp);
    }
    else if (prop_key_check("tls.key_passwd", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.key_passwd", &ins->tls_key_passwd, tmp);
    }
    else if (prop_key_check("tls.min_version", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.min_version", &ins->tls_min_version, tmp);
    }
    else if (prop_key_check("tls.max_version", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.max_version", &ins->tls_max_version, tmp);
    }
    else if (prop_key_check("tls.ciphers", k, len) == 0) {
        flb_utils_set_plugin_string_property("tls.ciphers", &ins->tls_ciphers, tmp);
    }
#  if defined(FLB_SYSTEM_WINDOWS)
    else if (prop_key_check("tls.windows.certstore_name", k, len) == 0 && tmp) {
        flb_utils_set_plugin_string_property("tls.windows.certstore_name", &ins->tls_win_certstore_name, tmp);
    }
    else if (prop_key_check("tls.windows.use_enterprise_store", k, len) == 0 && tmp) {
        ins->tls_win_use_enterprise_certstore = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
    }
#  endif
#endif
    else if (prop_key_check("storage.total_limit_size", k, len) == 0 && tmp) {
        if (strcasecmp(tmp, "off") == 0 ||
            flb_utils_bool(tmp) == FLB_FALSE) {
            /* no limit for filesystem storage */
            limit = -1;
            flb_info("[config] unlimited filesystem buffer for %s plugin",
                     ins->name);
        }
        else {
            limit = flb_utils_size_to_bytes(tmp);
            if (limit == -1) {
                flb_sds_destroy(tmp);
                return -1;
            }

            if (limit == 0) {
                limit = -1;
            }
        }

        flb_sds_destroy(tmp);
        ins->total_limit_size = (size_t) limit;
    }
    else if (prop_key_check("workers", k, len) == 0 && tmp) {
        /* Set the number of workers */
        ins->tp_workers = atoi(tmp);
        flb_sds_destroy(tmp);
    }
    else {
        /*
         * Create the property, we don't pass the value since we will
         * map it directly to avoid an extra memory allocation.
         */
        kv = flb_kv_item_create(&ins->properties, (char *) k, NULL);
        if (!kv) {
            if (tmp) {
                flb_sds_destroy(tmp);
            }
            return -1;
        }
        kv->val = tmp;
    }

    return 0;
}

/* Configure a default hostname and TCP port if they are not set */
void flb_output_net_default(const char *host, const int port,
                            struct flb_output_instance *ins)
{
    /* Set default network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_sds_create(host);
    }
    if (ins->host.port == 0) {
        ins->host.port = port;
    }
}

/* Add thread pool for output plugin if configured with workers */
int flb_output_enable_multi_threading(struct flb_output_instance *ins, struct flb_config *config)
{
    /* Multi-threading enabled ? (through 'workers' property) */
    if (ins->tp_workers > 0) {
        if(flb_output_thread_pool_create(config, ins) != 0) {
            flb_output_instance_destroy(ins);
            return -1;
        }
        flb_output_thread_pool_start(ins);
    }

    return 0;
}

/* Return an instance name or alias */
const char *flb_output_name(struct flb_output_instance *ins)
{
    if (ins->alias) {
        return ins->alias;
    }

    return ins->name;
}

const char *flb_output_get_property(const char *key, struct flb_output_instance *ins)
{
    return flb_config_prop_get(key, &ins->properties);
}

#ifdef FLB_HAVE_METRICS
void *flb_output_get_cmt_instance(struct flb_output_instance *ins)
{
    return (void *)ins->cmt;
}
#endif

int flb_output_net_property_check(struct flb_output_instance *ins,
                                  struct flb_config *config)
{
    int ret = 0;

    /* Get Upstream net_setup configmap */
    ins->net_config_map = flb_upstream_get_config_map(config);
    if (!ins->net_config_map) {
        flb_output_instance_destroy(ins);
        return -1;
    }

    /*
     * Validate 'net.*' properties: if the plugin use the Upstream interface,
     * it might receive some networking settings.
     */
    if (mk_list_size(&ins->net_properties) > 0) {
        ret = flb_config_map_properties_check(ins->p->name,
                                              &ins->net_properties,
                                              ins->net_config_map);
        if (ret == -1) {
            if (config->program_name) {
                flb_helper("try the command: %s -o %s -h\n",
                           config->program_name, ins->p->name);
            }
            return -1;
        }
    }

    return 0;
}

int flb_output_plugin_property_check(struct flb_output_instance *ins,
                                     struct flb_config *config)
{
    int ret = 0;
    struct mk_list *config_map;
    struct flb_output_plugin *p = ins->p;

    if (p->config_map) {
        /*
         * Create a dynamic version of the configmap that will be used by the specific
         * instance in question.
         */
        config_map = flb_config_map_create(config, p->config_map);
        if (!config_map) {
            flb_error("[output] error loading config map for '%s' plugin",
                      p->name);
            return -1;
        }
        ins->config_map = config_map;

        /* Validate incoming properties against config map */
        ret = flb_config_map_properties_check(ins->p->name,
                                              &ins->properties, ins->config_map);
        if (ret == -1) {
            if (config->program_name) {
                flb_helper("try the command: %s -o %s -h\n",
                           config->program_name, ins->p->name);
            }
            return -1;
        }
    }

    return 0;
}

/* Trigger the output plugins setup callbacks to prepare them. */
int flb_output_init_all(struct flb_config *config)
{
    int ret;
#ifdef FLB_HAVE_METRICS
    char *name;
#endif
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_output_instance *ins;
    struct flb_output_plugin *p;
    uint64_t ts;
    struct cmt_histogram_buckets *buckets;

    /* Retrieve the plugin reference */
    mk_list_foreach_safe(head, tmp, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (ins->log_level == -1) {
            ins->log_level = config->log->level;
        }
        p = ins->p;

        /* Output Events Channel */
        ret = mk_event_channel_create(config->evl,
                                      &ins->ch_events[0],
                                      &ins->ch_events[1],
                                      ins);
        if (ret != 0) {
            flb_error("could not create events channels for '%s'",
                      flb_output_name(ins));
            flb_output_instance_destroy(ins);
            return -1;
        }
        flb_debug("[%s:%s] created event channels: read=%i write=%i",
                  ins->p->name, flb_output_name(ins),
                  ins->ch_events[0], ins->ch_events[1]);

        /*
         * Note: mk_event_channel_create() sets a type = MK_EVENT_NOTIFICATION by
         * default, we need to overwrite this value so we can do a clean check
         * into the Engine when the event is triggered.
         */
        ins->event.type = FLB_ENGINE_EV_OUTPUT;

        /* Metrics */
#ifdef FLB_HAVE_METRICS
        /* Get name or alias for the instance */
        name = (char *) flb_output_name(ins);

        /* get timestamp */
        ts = cfl_time_now();

        /* CMetrics */
        ins->cmt = cmt_create();
        if (!ins->cmt) {
            flb_error("[output] could not create cmetrics context");
            return -1;
        }

        /*
         * Register generic output plugin metrics
         */

        /* fluentbit_output_proc_records_total */
        ins->cmt_proc_records = cmt_counter_create(ins->cmt, "fluentbit",
                                                   "output", "proc_records_total",
                                                   "Number of processed output records.",
                                                   1, (char *[]) {"name"});
        cmt_counter_set(ins->cmt_proc_records, ts, 0, 1, (char *[]) {name});


        /* fluentbit_output_proc_bytes_total */
        ins->cmt_proc_bytes = cmt_counter_create(ins->cmt, "fluentbit",
                                                 "output", "proc_bytes_total",
                                                 "Number of processed output bytes.",
                                                 1, (char *[]) {"name"});
        cmt_counter_set(ins->cmt_proc_bytes, ts, 0, 1, (char *[]) {name});


        /* fluentbit_output_errors_total */
        ins->cmt_errors = cmt_counter_create(ins->cmt, "fluentbit",
                                             "output", "errors_total",
                                             "Number of output errors.",
                                             1, (char *[]) {"name"});
        cmt_counter_set(ins->cmt_errors, ts, 0, 1, (char *[]) {name});


        /* fluentbit_output_retries_total */
        ins->cmt_retries = cmt_counter_create(ins->cmt, "fluentbit",
                                             "output", "retries_total",
                                             "Number of output retries.",
                                             1, (char *[]) {"name"});
        cmt_counter_set(ins->cmt_retries, ts, 0, 1, (char *[]) {name});

        /* fluentbit_output_retries_failed_total */
        ins->cmt_retries_failed = cmt_counter_create(ins->cmt, "fluentbit",
                                             "output", "retries_failed_total",
                                             "Number of abandoned batches because "
                                             "the maximum number of re-tries was "
                                             "reached.",
                                             1, (char *[]) {"name"});
        cmt_counter_set(ins->cmt_retries_failed, ts, 0, 1, (char *[]) {name});


        /* fluentbit_output_dropped_records_total */
        ins->cmt_dropped_records = cmt_counter_create(ins->cmt, "fluentbit",
                                             "output", "dropped_records_total",
                                             "Number of dropped records.",
                                             1, (char *[]) {"name"});
        cmt_counter_set(ins->cmt_dropped_records, ts, 0, 1, (char *[]) {name});

        /* fluentbit_output_retried_records_total */
        ins->cmt_retried_records = cmt_counter_create(ins->cmt, "fluentbit",
                                             "output", "retried_records_total",
                                             "Number of retried records.",
                                             1, (char *[]) {"name"});
        cmt_counter_set(ins->cmt_retried_records, ts, 0, 1, (char *[]) {name});

        /* output_upstream_total_connections */
        ins->cmt_upstream_total_connections = cmt_gauge_create(ins->cmt,
                                                               "fluentbit",
                                                               "output",
                                                               "upstream_total_connections",
                                                               "Total Connection count.",
                                                               1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_upstream_total_connections,
                      ts,
                      0,
                      1, (char *[]) {name});

        /* output_upstream_total_connections */
        ins->cmt_upstream_busy_connections = cmt_gauge_create(ins->cmt,
                                                              "fluentbit",
                                                              "output",
                                                              "upstream_busy_connections",
                                                              "Busy Connection count.",
                                                              1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_upstream_busy_connections,
                      ts,
                      0,
                      1, (char *[]) {name});

        /* output_chunk_available_capacity_percent */
        ins->cmt_chunk_available_capacity_percent = cmt_gauge_create(ins->cmt,
                                                        "fluentbit",
                                                        "output",
                                                        "chunk_available_capacity_percent",
                                                        "Available chunk capacity (percent)",
                                                        1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_chunk_available_capacity_percent,
                      ts,
                      100.0,
                      1, (char *[]) {name});

        /* fluentbit_output_latency_seconds */
        buckets = cmt_histogram_buckets_create_size((double *) output_latency_buckets,
                                                    sizeof(output_latency_buckets) / sizeof(double));
        if (!buckets) {
            flb_error("could not create latency histogram buckets for %s", name);
            return -1;
        }

        ins->cmt_latency = cmt_histogram_create(ins->cmt,
                                                "fluentbit",
                                                "output",
                                                "latency_seconds",
                                                "End-to-end latency in seconds",
                                                buckets,
                                                2, (char *[]) {"input", "output"});

        /* old API */
        ins->metrics = flb_metrics_create(name);
        if (ins->metrics) {
            flb_metrics_add(FLB_METRIC_OUT_OK_RECORDS,
                            "proc_records", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_OK_BYTES,
                            "proc_bytes", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_ERROR,
                            "errors", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_RETRY,
                            "retries", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_RETRY_FAILED,
                        "retries_failed", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_DROPPED_RECORDS,
                        "dropped_records", ins->metrics);
            flb_metrics_add(FLB_METRIC_OUT_RETRIED_RECORDS,
                        "retried_records", ins->metrics);
        }
#endif

#ifdef FLB_HAVE_TLS
        if (ins->use_tls == FLB_TRUE) {
            ins->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                      ins->tls_verify,
                                      ins->tls_debug,
                                      ins->tls_vhost,
                                      ins->tls_ca_path,
                                      ins->tls_ca_file,
                                      ins->tls_crt_file,
                                      ins->tls_key_file,
                                      ins->tls_key_passwd);
            if (!ins->tls) {
                flb_error("[output %s] error initializing TLS context",
                          ins->name);
                flb_output_instance_destroy(ins);
                return -1;
            }

            if (ins->tls_verify_hostname == FLB_TRUE) {
                ret = flb_tls_set_verify_hostname(ins->tls, ins->tls_verify_hostname);
                if (ret == -1) {
                    flb_error("[output %s] error set up to verify hostname in TLS context",
                              ins->name);

                    return -1;
                }
            }

            if (ins->tls_min_version != NULL || ins->tls_max_version != NULL) {
                ret = flb_tls_set_minmax_proto(ins->tls, ins->tls_min_version, ins->tls_max_version);
                if (ret != 0) {
                    flb_error("[output %s] error setting up minmax protocol version of TLS",
                              ins->name);
                    flb_output_instance_destroy(ins);
                    return -1;
                }
            }

            if (ins->tls_ciphers != NULL) {
                ret = flb_tls_set_ciphers(ins->tls, ins->tls_ciphers);
                if (ret != 0) {
                    flb_error("[output %s] error setting up TLS ciphers up to TLSv1.2",
                              ins->name);
                    flb_output_instance_destroy(ins);
                    return -1;
                }
            }

# if defined (FLB_SYSTEM_WINDOWS)
            if (ins->tls_win_use_enterprise_certstore) {
                ret = flb_tls_set_use_enterprise_store(ins->tls, ins->tls_win_use_enterprise_certstore);
                if (ret == -1) {
                    flb_error("[input %s] error set up to use enterprise certstore in TLS context",
                              ins->name);

                    return -1;
                }
            }

            if (ins->tls_win_certstore_name) {
                flb_debug("[output %s] starting to load %s certstore in TLS context",
                          ins->name, ins->tls_win_certstore_name);
                ret = flb_tls_set_certstore_name(ins->tls, ins->tls_win_certstore_name);
                if (ret == -1) {
                    flb_error("[output %s] error specify certstore name in TLS context",
                              ins->name);

                    return -1;
                }

                flb_debug("[output %s] attempting to load %s certstore in TLS context",
                          ins->name, ins->tls_win_certstore_name);
                ret = flb_tls_load_system_certificates(ins->tls);
                if (ret == -1) {
                    flb_error("[output %s] error set up to load certstore with a user-defined name in TLS context",
                              ins->name);

                    return -1;
                }
            }
# endif
        }
#endif
        /*
         * Before to call the initialization callback, make sure that the received
         * configuration parameters are valid if the plugin is registering a config map.
         */
        if (flb_output_plugin_property_check(ins, config) == -1) {
            flb_output_instance_destroy(ins);
            return -1;
        }

#ifdef FLB_HAVE_TLS
        struct flb_config_map *m;

        /* TLS config map (just for 'help' formatting purposes) */
        ins->tls_config_map = flb_tls_get_config_map(config);
        if (!ins->tls_config_map) {
            flb_output_instance_destroy(ins);
            return -1;
        }

        /* Override first configmap value based on it plugin flag */
        m = mk_list_entry_first(ins->tls_config_map, struct flb_config_map, _head);
        if (p->flags & FLB_IO_TLS) {
            m->value.val.boolean = FLB_TRUE;
        }
        else {
            m->value.val.boolean = FLB_FALSE;
        }
#endif

        /* Init network defaults */
        flb_net_setup_init(&ins->net_setup);

        if (flb_output_net_property_check(ins, config) == -1) {
            flb_output_instance_destroy(ins);
            return -1;
        }

        /* Initialize plugin through it 'init callback' */
        ret = p->cb_init(ins, config, ins->data);
        if (ret == -1) {
            flb_error("[output] failed to initialize '%s' plugin",
                      p->name);
            flb_output_instance_destroy(ins);
            return -1;
        }

        ins->notification_channel = config->notification_channels[1];

        /* Multi-threading enabled if configured */
        ret = flb_output_enable_multi_threading(ins, config);
        if (ret == -1) {
            flb_error("[output] could not start thread pool for '%s' plugin",
                      flb_output_name(ins));
            return -1;
        }

        if (ins->is_threaded == FLB_FALSE) {
            if (ins->p->cb_worker_init) {
                ret = ins->p->cb_worker_init(ins->context, ins->config);
            }
        }

        ins->processor->notification_channel = ins->notification_channel;

        /* initialize processors */
        ret = flb_processor_init(ins->processor);
        if (ret == -1) {
            flb_error("[output %s] error initializing processor, aborting startup", ins->name);
            return -1;
        }
    }

    return 0;
}

/* Assign an Configuration context to an Output */
void flb_output_set_context(struct flb_output_instance *ins, void *context)
{
    ins->context = context;
}

/* Check that at least one Output is enabled */
int flb_output_check(struct flb_config *config)
{
    if (mk_list_is_empty(&config->outputs) == 0) {
        return -1;
    }
    return 0;
}

/* Check output plugin's log level.
 * Not for core plugins but for Golang plugins.
 * Golang plugins do not have thread-local flb_worker_ctx information. */
int flb_output_log_check(struct flb_output_instance *ins, int l)
{
    if (ins->log_level < l) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

/*
 * Output plugins might have enabled certain features that have not been passed
 * directly to the upstream context. In order to avoid let plugins validate specific
 * variables from the instance context like tls, tls.x, keepalive, etc, we populate
 * them directly through this function.
 */
int flb_output_upstream_set(struct flb_upstream *u, struct flb_output_instance *ins)
{
    int flags = 0;
    int ret;
    char *host;
    int port;
    char *proxy_protocol = NULL;
    char *proxy_host = NULL;
    char *proxy_port = NULL;
    char *proxy_username = NULL;
    char *proxy_password = NULL;

    if (!u) {
        return -1;
    }

    /* TLS */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        flags |= FLB_IO_TLS;
    }
    else {
        flags |= FLB_IO_TCP;
    }
#else
    flags |= FLB_IO_TCP;
#endif

    /* IPv6 */
    if (ins->host.ipv6 == FLB_TRUE) {
        flags |= FLB_IO_IPV6;
    }
        /* keepalive */
    if (ins->net_setup.keepalive == FLB_TRUE) {
        flags |= FLB_IO_TCP_KA;
    }

    if (ins->net_setup.keepalive == FLB_TRUE) {
        flags |= FLB_IO_TCP_KA;
    }

    /* Set flags */
    flb_stream_enable_flags(&u->base, flags);

    flb_upstream_set_total_connections_label(u,
                                             flb_output_name(ins));

    flb_upstream_set_total_connections_gauge(u,
                                             ins->cmt_upstream_total_connections);

    flb_upstream_set_busy_connections_label(u,
                                            flb_output_name(ins));

    flb_upstream_set_busy_connections_gauge(u,
                                            ins->cmt_upstream_busy_connections);

    /*
     * If the output plugin flush callbacks will run in multiple threads, enable
     * the thread safe mode for the Upstream context.
     */
    if (ins->tp_workers > 0) {
        flb_stream_enable_thread_safety(&u->base);

        mk_list_add(&u->base._head, &ins->upstreams);
    }

    /* Set networking options 'net.*' received through instance properties */
    memcpy(&u->base.net, &ins->net_setup, sizeof(struct flb_net_setup));

    /*
     * If the Upstream was created using a proxy from the environment but the
     * final configuration asks to ignore environment proxy variables, restore
     * the original destination host information.
     */
    if (u->base.net.proxy_env_ignore == FLB_TRUE && u->proxied_host) {
        flb_free(u->tcp_host);
        u->tcp_host = flb_strdup(u->proxied_host);
        u->tcp_port = u->proxied_port;

        flb_free(u->proxied_host);
        u->proxied_host = NULL;
        u->proxied_port = 0;

        /*
         * Credentials are only set when the connection was configured via environment
         * variables. Since we just reverted the upstream to the destination configured
         * by the plugin, drop any credentials that may have been parsed.
         */
        if (u->proxy_username) {
            flb_free(u->proxy_username);
            u->proxy_username = NULL;
        }
        if (u->proxy_password) {
            flb_free(u->proxy_password);
            u->proxy_password = NULL;
        }
    }

    /* Set upstream to the http_proxy if it is specified. */
    if (u->base.net.proxy_env_ignore == FLB_FALSE && 
        flb_upstream_needs_proxy(host, ins->net_setup.http_proxy, ins->net_setup.no_proxy) == FLB_TRUE) {

        flb_debug("[upstream] net_setup->http_proxy: %s->%s", ins->net_setup.http_proxy, host);
        ret = flb_utils_proxy_url_split(ins->net_setup.http_proxy, 
                                        &proxy_protocol,
                                        &proxy_username, &proxy_password,
                                        &proxy_host, &proxy_port);
        if (ret == -1) {
            flb_errno();
            return -1;
        }

        if (u->proxy_username) {
            flb_free(u->proxy_username);
            u->proxy_username = NULL;
        }
        if (u->proxy_password) {
            flb_free(u->proxy_password);
            u->proxy_password = NULL;
        }

        if (u->tcp_host != NULL) {
            flb_free(u->tcp_host);
        }

        if (u->proxied_host) {
            flb_free(u->proxied_host);
        }

        u->tcp_host = proxy_host;
        u->tcp_port = atoi(proxy_port);
        u->proxied_host = host;
        u->proxied_port = port;

        if (proxy_username && proxy_password) {
            u->proxy_username = proxy_username;
            u->proxy_password = proxy_password;
        }

        flb_free(proxy_protocol);
        flb_free(proxy_port);
    }
    else {
        flb_free(host);
    }

    return 0;
}

int flb_output_upstream_ha_set(void *ha, struct flb_output_instance *ins)
{
    struct mk_list *head;
    struct flb_upstream_node *node;
    struct flb_upstream_ha *upstream_ha = ha;

    mk_list_foreach(head, &upstream_ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);
        flb_output_upstream_set(node->u, ins);
    }

    return 0;
}

/*
 * Helper function to set HTTP callbacks using the output instance 'callback'
 * context.
 */
int flb_output_set_http_debug_callbacks(struct flb_output_instance *ins)
{
#ifdef FLB_HAVE_HTTP_CLIENT_DEBUG
    return flb_http_client_debug_setup(ins->callback, &ins->properties);
#else
    return 0;
#endif
}
