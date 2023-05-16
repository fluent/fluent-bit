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

#include <stdlib.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_thread.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_ring_buffer.h>
#include <fluent-bit/flb_processor.h>

/* input plugin macro helpers */
#include <fluent-bit/flb_input_plugin.h>

#ifdef FLB_HAVE_CHUNK_TRACE
#include <fluent-bit/flb_chunk_trace.h>
#endif /* FLB_HAVE_CHUNK_TRACE */

struct flb_libco_in_params libco_in_param;
pthread_key_t libco_in_param_key;

#define protcmp(a, b)  strncasecmp(a, b, strlen(a))

/*
 * Ring buffer size: we make space for 512 entries that each input instance can
 * use to enqueue data. Note that this value is fixed and only affect input plugins
 * which runs in threaded mode (separate thread)
 *
 * Ring buffer window: the current window size is set to 5% which means that the
 * ring buffer will emit a flush request whenever there are 51 records or more
 * awaiting to be consumed.
 */

#define FLB_INPUT_RING_BUFFER_SIZE   (sizeof(void *) * 1024)
#define FLB_INPUT_RING_BUFFER_WINDOW (5)


static int check_protocol(const char *prot, const char *output)
{
    int len;

    len = strlen(prot);
    if (len != strlen(output)) {
        return 0;
    }

    if (protcmp(prot, output) != 0) {
        return 0;
    }

    return 1;
}

static inline int instance_id(struct flb_input_plugin *p,
                              struct flb_config *config) \
{
    int c = 0;
    struct mk_list *head;
    struct flb_input_instance *entry;

    mk_list_foreach(head, &config->inputs) {
        entry = mk_list_entry(head, struct flb_input_instance, _head);
        if (entry->id == c) {
            c++;
        }
    }

    return c;
}

/* Generate a new collector ID for the instance in question */
static int collector_id(struct flb_input_instance *ins)
{
    int id = 0;
    struct flb_input_collector *collector;

    if (mk_list_is_empty(&ins->collectors) == 0) {
        return id;
    }

    collector = mk_list_entry_last(&ins->collectors,
                                   struct flb_input_collector,
                                   _head);
    return (collector->id + 1);
}

void flb_input_net_default_listener(const char *listen, int port,
                                    struct flb_input_instance *ins)
{
    /* Set default network configuration */
    if (!ins->host.listen) {
        ins->host.listen = flb_sds_create(listen);
    }
    if (ins->host.port == 0) {
        ins->host.port = port;
    }
}

/* Check input plugin's log level.
 * Not for core plugins but for Golang plugins.
 * Golang plugins do not have thread-local flb_worker_ctx information. */
int flb_input_log_check(struct flb_input_instance *ins, int l)
{
    if (ins->log_level < l) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

/* Create an input plugin instance */
struct flb_input_instance *flb_input_new(struct flb_config *config,
                                         const char *input, void *data,
                                         int public_only)
{
    int id;
    int ret;
    int flags = 0;
    struct mk_list *head;
    struct flb_input_plugin *plugin;
    struct flb_input_instance *instance = NULL;

/* use for locking the use of the chunk trace context. */
#ifdef FLB_HAVE_CHUNK_TRACE
    pthread_mutexattr_t attr = {0};
    pthread_mutexattr_init(&attr);
#endif

    if (!input) {
        return NULL;
    }

    mk_list_foreach(head, &config->in_plugins) {
        plugin = mk_list_entry(head, struct flb_input_plugin, _head);
        if (!check_protocol(plugin->name, input)) {
            plugin = NULL;
            continue;
        }

        /*
         * Check if the plugin is private and validate the 'public_only'
         * requirement.
         */
        if (public_only == FLB_TRUE && plugin->flags & FLB_INPUT_PRIVATE) {
            return NULL;
        }

        /* Create plugin instance */
        instance = flb_calloc(1, sizeof(struct flb_input_instance));
        if (!instance) {
            flb_errno();
            return NULL;
        }
        instance->config = config;

        /* Get an ID */
        id =  instance_id(plugin, config);

        /* Index for log Chunks (hash table) */
        instance->ht_log_chunks = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                                        512, 0);
        if (!instance->ht_log_chunks) {
            flb_free(instance);
            return NULL;
        }

        /* Index for metric Chunks (hash table) */
        instance->ht_metric_chunks = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                                           512, 0);
        if (!instance->ht_metric_chunks) {
            flb_hash_table_destroy(instance->ht_log_chunks);
            flb_free(instance);
            return NULL;
        }

        /* Index for trace Chunks (hash table) */
        instance->ht_trace_chunks = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                                          512, 0);
        if (!instance->ht_trace_chunks) {
            flb_hash_table_destroy(instance->ht_log_chunks);
            flb_hash_table_destroy(instance->ht_metric_chunks);
            flb_free(instance);
            return NULL;
        }

        /* format name (with instance id) */
        snprintf(instance->name, sizeof(instance->name) - 1,
                 "%s.%i", plugin->name, id);

        if (plugin->type == FLB_INPUT_PLUGIN_CORE) {
            instance->context = NULL;
        }
        else {
            struct flb_plugin_proxy_context *ctx;

            ctx = flb_calloc(1, sizeof(struct flb_plugin_proxy_context));
            if (!ctx) {
                flb_errno();
                flb_free(instance);
                return NULL;
            }

            ctx->proxy = plugin->proxy;

            instance->context = ctx;
        }

        /* initialize remaining vars */
        instance->alias    = NULL;
        instance->id       = id;
        instance->flags    = plugin->flags;
        instance->p        = plugin;
        instance->tag      = NULL;
        instance->tag_len  = 0;
        instance->tag_default = FLB_FALSE;
        instance->routable = FLB_TRUE;
        instance->data     = data;
        instance->storage  = NULL;
        instance->storage_type = -1;
        instance->log_level = -1;
        instance->log_suppress_interval = -1;
        instance->runs_in_coroutine = FLB_FALSE;

        /* net */
        instance->host.name    = NULL;
        instance->host.address = NULL;
        instance->host.uri     = NULL;
        instance->host.listen  = NULL;
        instance->host.ipv6    = FLB_FALSE;

        /* Initialize list heads */
        mk_list_init(&instance->routes_direct);
        mk_list_init(&instance->routes);
        mk_list_init(&instance->tasks);
        mk_list_init(&instance->chunks);
        mk_list_init(&instance->collectors);
        mk_list_init(&instance->input_coro_list);
        mk_list_init(&instance->input_coro_list_destroy);
        mk_list_init(&instance->downstreams);
        mk_list_init(&instance->upstreams);

        /* Initialize properties list */
        flb_kv_init(&instance->properties);
        flb_kv_init(&instance->net_properties);

        /* Plugin use networking */
        if (plugin->flags & (FLB_INPUT_NET | FLB_INPUT_NET_SERVER)) {
            ret = flb_net_host_set(plugin->name, &instance->host, input);
            if (ret != 0) {
                flb_free(instance);
                return NULL;
            }
        }

/* initialize lock for access to chunk trace context. */
#ifdef FLB_HAVE_CHUNK_TRACE
        pthread_mutex_init(&instance->chunk_trace_lock, &attr);
#endif

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
        instance->tls_vhost             = NULL;
        instance->tls_ca_path           = NULL;
        instance->tls_ca_file           = NULL;
        instance->tls_crt_file          = NULL;
        instance->tls_key_file          = NULL;
        instance->tls_key_passwd        = NULL;
#endif

        /* Plugin requires a co-routine context ? */
        if (plugin->flags & FLB_INPUT_CORO) {
            instance->runs_in_coroutine = FLB_TRUE;
        }

        /* Plugin will run in a separate thread  ? */
        if (plugin->flags & FLB_INPUT_THREADED) {
            instance->is_threaded = FLB_TRUE;

        }

        /* allocate a ring buffer */
        instance->rb = flb_ring_buffer_create(FLB_INPUT_RING_BUFFER_SIZE);
        if (!instance->rb) {
            flb_error("instance %s could not initialize ring buffer",
                      flb_input_name(instance));
            flb_free(instance);
            return NULL;
        }

        instance->mem_buf_status = FLB_INPUT_RUNNING;
        instance->mem_buf_limit = 0;
        instance->mem_chunks_size = 0;
        instance->storage_buf_status = FLB_INPUT_RUNNING;
        mk_list_add(&instance->_head, &config->inputs);

        /* processor instance */
        instance->processor = flb_processor_create(config, instance->name, instance, FLB_PLUGIN_INPUT);
    }

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

struct flb_input_instance *flb_input_get_instance(struct flb_config *config,
                                                  int ins_id)
{
    struct mk_list *head;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (ins->id == ins_id) {
            break;
        }
        ins = NULL;
    }

    if (!ins) {
        return NULL;
    }

    return ins;
}

static void flb_input_coro_destroy(struct flb_input_coro *input_coro)
{
    flb_debug("[input coro] destroy coro_id=%i", input_coro->id);

    mk_list_del(&input_coro->_head);
    flb_coro_destroy(input_coro->coro);
    flb_free(input_coro);
}

int flb_input_coro_finished(struct flb_config *config, int ins_id)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_instance *ins;
    struct flb_input_coro *input_coro;

    ins = flb_input_get_instance(config, ins_id);
    if (!ins) {
        return -1;
    }

    /* Look for input coroutines that needs to be destroyed */
    mk_list_foreach_safe(head, tmp, &ins->input_coro_list_destroy) {
        input_coro = mk_list_entry(head, struct flb_input_coro, _head);
        flb_input_coro_destroy(input_coro);
    }

    return 0;
}

void flb_input_coro_prepare_destroy(struct flb_input_coro *input_coro)
{
    struct flb_input_instance *ins = input_coro->ins;

    /* move flb_input_coro from 'input_coro_list' to 'input_coro_list_destroy' */
    mk_list_del(&input_coro->_head);
    mk_list_add(&input_coro->_head, &ins->input_coro_list_destroy);
}

int flb_input_name_exists(const char *name, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (strcmp(ins->name, name) == 0) {
            return FLB_TRUE;
        }

        if (ins->alias) {
            if (strcmp(ins->alias, name) == 0) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

struct mk_event_loop *flb_input_event_loop_get(struct flb_input_instance *ins)
{
    struct flb_input_thread_instance *thi;

    if (flb_input_is_threaded(ins)) {
        thi = ins->thi;
        return thi->evl;
    }

    return ins->config->evl;
}

/* Override a configuration property for the given input_instance plugin */
int flb_input_set_property(struct flb_input_instance *ins,
                           const char *k, const char *v)
{
    int len;
    int ret;
    int enabled;
    ssize_t limit;
    flb_sds_t tmp = NULL;
    struct flb_kv *kv;

    len = strlen(k);
    tmp = flb_env_var_translate(ins->config->env, v);
    if (tmp) {
        if (flb_sds_len(tmp) == 0) {
            flb_sds_destroy(tmp);
            tmp = NULL;
        }
    }

    /* Check if the key is a known/shared property */
    if (prop_key_check("tag", k, len) == 0 && tmp) {
        ins->tag     = tmp;
        ins->tag_len = flb_sds_len(tmp);
        ins->tag_default = FLB_FALSE;
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
    else if (prop_key_check("routable", k, len) == 0 && tmp) {
        ins->routable = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("alias", k, len) == 0 && tmp) {
        ins->alias = tmp;
    }
    else if (prop_key_check("mem_buf_limit", k, len) == 0 && tmp) {
        limit = flb_utils_size_to_bytes(tmp);
        flb_sds_destroy(tmp);
        if (limit == -1) {
            return -1;
        }
        ins->mem_buf_limit = (size_t) limit;
    }
    else if (prop_key_check("listen", k, len) == 0) {
        ins->host.listen = tmp;
    }
    else if (prop_key_check("host", k, len) == 0) {
        ins->host.name   = tmp;
    }
    else if (prop_key_check("port", k, len) == 0) {
        if (tmp) {
            ins->host.port = atoi(tmp);
            flb_sds_destroy(tmp);
        }
    }
    else if (prop_key_check("ipv6", k, len) == 0 && tmp) {
        ins->host.ipv6 = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
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

#ifdef FLB_HAVE_TLS
    else if (prop_key_check("tls", k, len) == 0 && tmp) {
        if (strcasecmp(tmp, "true") == 0 || strcasecmp(tmp, "on") == 0) {
            if ((ins->flags & FLB_IO_TLS) == 0) {
                flb_error("[config] %s don't support TLS", ins->name);
                flb_sds_destroy(tmp);
                return -1;
            }

            ins->use_tls = FLB_TRUE;
        }
        else {
            ins->use_tls = FLB_FALSE;
        }
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.verify", k, len) == 0 && tmp) {
        if (strcasecmp(tmp, "true") == 0 || strcasecmp(tmp, "on") == 0) {
            ins->tls_verify = FLB_TRUE;
        }
        else {
            ins->tls_verify = FLB_FALSE;
        }
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.debug", k, len) == 0 && tmp) {
        ins->tls_debug = atoi(tmp);
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("tls.vhost", k, len) == 0) {
        ins->tls_vhost = tmp;
    }
    else if (prop_key_check("tls.ca_path", k, len) == 0) {
        ins->tls_ca_path = tmp;
    }
    else if (prop_key_check("tls.ca_file", k, len) == 0) {
        ins->tls_ca_file = tmp;
    }
    else if (prop_key_check("tls.crt_file", k, len) == 0) {
        ins->tls_crt_file = tmp;
    }
    else if (prop_key_check("tls.key_file", k, len) == 0) {
        ins->tls_key_file = tmp;
    }
    else if (prop_key_check("tls.key_passwd", k, len) == 0) {
        ins->tls_key_passwd = tmp;
    }
#endif
    else if (prop_key_check("storage.type", k, len) == 0 && tmp) {
        /* Set the storage type */
        if (strcasecmp(tmp, "filesystem") == 0) {
            ins->storage_type = FLB_STORAGE_FS;
        }
        else if (strcasecmp(tmp, "memory") == 0) {
            ins->storage_type = FLB_STORAGE_MEM;
        }
        else if (strcasecmp(tmp, "memrb") == 0) {
            ins->storage_type = FLB_STORAGE_MEMRB;
        }
        else {
            flb_sds_destroy(tmp);
            return -1;
        }
        flb_sds_destroy(tmp);
    }
    else if (prop_key_check("threaded", k, len) == 0 && tmp) {
        enabled = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);

        if (enabled == -1) {
            return -1;
        }

        ins->is_threaded = enabled;
    }
    else if (prop_key_check("storage.pause_on_chunks_overlimit", k, len) == 0 && tmp) {
        if (ins->storage_type == FLB_STORAGE_FS) {
            ret = flb_utils_bool(tmp);
            flb_sds_destroy(tmp);
            if (ret == -1) {
                return -1;
            }
            ins->storage_pause_on_chunks_overlimit = ret;
        }
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

const char *flb_input_get_property(const char *key,
                                   struct flb_input_instance *ins)
{
    return flb_config_prop_get(key, &ins->properties);
}

#ifdef FLB_HAVE_METRICS
void *flb_input_get_cmt_instance(struct flb_input_instance *ins)
{
    return (void *)ins->cmt;
}
#endif

/* Return an instance name or alias */
const char *flb_input_name(struct flb_input_instance *ins)
{
    if (ins->alias) {
        return ins->alias;
    }

    return ins->name;
}

void flb_input_instance_destroy(struct flb_input_instance *ins)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_collector *collector;

    if (ins->alias) {
        flb_sds_destroy(ins->alias);
    }

    /* Remove URI context */
    if (ins->host.uri) {
        flb_uri_destroy(ins->host.uri);
    }

    if (ins->host.name) {
        flb_sds_destroy(ins->host.name);
    }
    if (ins->host.address) {
        flb_sds_destroy(ins->host.address);
    }
    if (ins->host.listen) {
        flb_sds_destroy(ins->host.listen);
    }

#ifdef FLB_HAVE_TLS
    if (ins->use_tls) {
        if (ins->tls != NULL) {
            flb_tls_destroy(ins->tls);
        }
    }

    if (ins->tls_config_map) {
        flb_config_map_destroy(ins->tls_config_map);
    }
#endif

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

    /* release the tag if any */
    flb_sds_destroy(ins->tag);

    /* Let the engine remove any pending task */
    flb_engine_destroy_tasks(&ins->tasks);

    /* release properties */
    flb_kv_release(&ins->properties);
    flb_kv_release(&ins->net_properties);


#ifdef FLB_HAVE_CHUNK_TRACE
    flb_chunk_trace_context_destroy(ins);
#endif /* FLB_HAVE_CHUNK_TRACE */

    /* Remove metrics */
#ifdef FLB_HAVE_METRICS
    if (ins->cmt) {
        cmt_destroy(ins->cmt);
    }

    if (ins->metrics) {
        flb_metrics_destroy(ins->metrics);
    }
#endif

    if (ins->storage) {
        flb_storage_input_destroy(ins);
    }

    /* destroy config map */
    if (ins->config_map) {
        flb_config_map_destroy(ins->config_map);
    }

    if (ins->net_config_map) {
        flb_config_map_destroy(ins->net_config_map);
    }

    /* hash table for chunks */
    if (ins->ht_log_chunks) {
        flb_hash_table_destroy(ins->ht_log_chunks);
    }

    if (ins->ht_metric_chunks) {
        flb_hash_table_destroy(ins->ht_metric_chunks);
    }

    if (ins->ht_trace_chunks) {
        flb_hash_table_destroy(ins->ht_trace_chunks);
    }

    if (ins->ch_events[0] > 0) {
        mk_event_closesocket(ins->ch_events[0]);
    }

    if (ins->ch_events[1] > 0) {
        mk_event_closesocket(ins->ch_events[1]);
    }

    /* Collectors */
    mk_list_foreach_safe(head, tmp, &ins->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        mk_list_del(&collector->_head);
        flb_input_collector_destroy(collector);
    }

    /* delete storage context */
    flb_storage_input_destroy(ins);

    mk_list_del(&ins->_head);

    /* ring buffer */
    if (ins->rb) {
        flb_input_chunk_ring_buffer_cleanup(ins);
        flb_ring_buffer_destroy(ins->rb);
    }

    /* processor */
    if (ins->processor) {
        flb_processor_destroy(ins->processor);
    }
    flb_free(ins);
}

int flb_input_coro_id_get(struct flb_input_instance *ins)
{
    int id;
    int max = (2 << 13) - 1; /* max for 14 bits */

    id = ins->input_coro_id;
    ins->input_coro_id++;

    /* reset once it reach the maximum allowed */
    if (ins->input_coro_id > max) {
        ins->input_coro_id = 0;
    }

    return id;
}

static int input_instance_channel_events_init(struct flb_input_instance *ins)
{
    int ret;
    struct mk_event_loop *evl;

    evl = flb_input_event_loop_get(ins);

    /* Input event channel: used for co-routines to report return status */
    ret = mk_event_channel_create(evl,
                                  &ins->ch_events[0],
                                  &ins->ch_events[1],
                                  ins);
    if (ret != 0) {
        flb_error("could not create events channels for '%s'",
                  flb_input_name(ins));
        return -1;
    }

    flb_debug("[%s:%s] created event channels: read=%i write=%i",
              ins->p->name, flb_input_name(ins),
              ins->ch_events[0], ins->ch_events[1]);

    /*
     * Note: mk_event_channel_create() sets a type = MK_EVENT_NOTIFICATION by
     * default, we need to overwrite this value so we can do a clean check
     * into the Engine when the event is triggered.
     */
    ins->event.type = FLB_ENGINE_EV_INPUT;

    return 0;
}

int flb_input_net_property_check(struct flb_input_instance *ins,
                                 struct flb_config *config)
{
    int ret = 0;

    /* Get Downstream net_setup configmap */
    ins->net_config_map = flb_downstream_get_config_map(config);
    if (!ins->net_config_map) {
        flb_input_instance_destroy(ins);
        return -1;
    }

    /*
     * Validate 'net.*' properties: if the plugin use the Downstream interface,
     * it might receive some networking settings.
     */
    if (mk_list_size(&ins->net_properties) > 0) {
        ret = flb_config_map_properties_check(ins->p->name,
                                              &ins->net_properties,
                                              ins->net_config_map);
        if (ret == -1) {
            if (config->program_name) {
                flb_helper("try the command: %s -i %s -h\n",
                           config->program_name, ins->p->name);
            }
            return -1;
        }
    }

    return 0;
}

int flb_input_plugin_property_check(struct flb_input_instance *ins,
                                    struct flb_config *config)
{
    int ret = 0;
    struct mk_list *config_map;
    struct flb_input_plugin *p = ins->p;

    if (p->config_map) {
        /*
         * Create a dynamic version of the configmap that will be used by the specific
         * instance in question.
         */
        config_map = flb_config_map_create(config, p->config_map);
        if (!config_map) {
            flb_error("[input] error loading config map for '%s' plugin",
                      p->name);
            flb_input_instance_destroy(ins);
            return -1;
        }
        ins->config_map = config_map;

        /* Validate incoming properties against config map */
        ret = flb_config_map_properties_check(ins->p->name,
                                              &ins->properties, ins->config_map);
        if (ret == -1) {
            if (config->program_name) {
                flb_helper("try the command: %s -i %s -h\n",
                           config->program_name, ins->p->name);
            }
            return -1;
        }
    }

    return 0;
}

int flb_input_instance_init(struct flb_input_instance *ins,
                            struct flb_config *config)
{
    int ret;
    struct flb_config *ctx = ins->config;
    struct flb_input_plugin *p = ins->p;
    int tls_session_mode;

    if (ins->log_level == -1 && config->log != NULL) {
        ins->log_level = config->log->level;
    }

    /* Skip pseudo input plugins */
    if (!p) {
        return 0;
    }


#ifdef FLB_HAVE_METRICS
    uint64_t ts;
    char *name;

    name = (char *) flb_input_name(ins);
    ts = cfl_time_now();

    /* CMetrics */
    ins->cmt = cmt_create();
    if (!ins->cmt) {
        flb_error("[input] could not create cmetrics context: %s",
                  flb_input_name(ins));
        return -1;
    }

    /*
     * Register generic input plugin metrics
     * -------------------------------------
     */

    /* fluentbit_input_bytes_total */
    ins->cmt_bytes = \
        cmt_counter_create(ins->cmt,
                           "fluentbit", "input", "bytes_total",
                           "Number of input bytes.",
                           1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_bytes, ts, 0, 1, (char *[]) {name});

    /* fluentbit_input_records_total */
    ins->cmt_records = \
        cmt_counter_create(ins->cmt,
                           "fluentbit", "input", "records_total",
                           "Number of input records.",
                           1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_records, ts, 0, 1, (char *[]) {name});

    /* Storage Metrics */
    if (ctx->storage_metrics == FLB_TRUE) {
        /* fluentbit_input_storage_overlimit */
        ins->cmt_storage_overlimit = \
            cmt_gauge_create(ins->cmt,
                             "fluentbit", "input",
                             "storage_overlimit",
                             "Is the input memory usage overlimit ?.",
                             1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_storage_overlimit, ts, 0, 1, (char *[]) {name});

        /* fluentbit_input_storage_memory_bytes */
        ins->cmt_storage_memory_bytes = \
            cmt_gauge_create(ins->cmt,
                             "fluentbit", "input",
                             "storage_memory_bytes",
                             "Memory bytes used by the chunks.",
                             1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_storage_memory_bytes, ts, 0, 1, (char *[]) {name});

        /* fluentbit_input_storage_chunks */
        ins->cmt_storage_chunks = \
            cmt_gauge_create(ins->cmt,
                             "fluentbit", "input",
                             "storage_chunks",
                             "Total number of chunks.",
                             1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_storage_chunks, ts, 0, 1, (char *[]) {name});

        /* fluentbit_input_storage_chunks_up */
        ins->cmt_storage_chunks_up = \
            cmt_gauge_create(ins->cmt,
                             "fluentbit", "input",
                             "storage_chunks_up",
                             "Total number of chunks up in memory.",
                             1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_storage_chunks_up, ts, 0, 1, (char *[]) {name});

        /* fluentbit_input_storage_chunks_down */
        ins->cmt_storage_chunks_down = \
            cmt_gauge_create(ins->cmt,
                             "fluentbit", "input",
                             "storage_chunks_down",
                             "Total number of chunks down.",
                             1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_storage_chunks_down, ts, 0, 1, (char *[]) {name});

        /* fluentbit_input_storage_chunks_busy */
        ins->cmt_storage_chunks_busy = \
            cmt_gauge_create(ins->cmt,
                             "fluentbit", "input",
                             "storage_chunks_busy",
                             "Total number of chunks in a busy state.",
                             1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_storage_chunks_busy, ts, 0, 1, (char *[]) {name});

        /* fluentbit_input_storage_chunks_busy_bytes */
        ins->cmt_storage_chunks_busy_bytes = \
            cmt_gauge_create(ins->cmt,
                             "fluentbit", "input",
                             "storage_chunks_busy_bytes",
                             "Total number of bytes used by chunks in a busy state.",
                             1, (char *[]) {"name"});
        cmt_gauge_set(ins->cmt_storage_chunks_busy_bytes, ts, 0, 1, (char *[]) {name});
    }

    if (ins->storage_type == FLB_STORAGE_MEMRB) {
        /* fluentbit_input_memrb_dropped_chunks */
        ins->cmt_memrb_dropped_chunks = cmt_counter_create(ins->cmt,
                                                          "fluentbit", "input",
                                                          "memrb_dropped_chunks",
                                                          "Number of memrb dropped chunks.",
                                                          1, (char *[]) {"name"});
        cmt_counter_set(ins->cmt_memrb_dropped_chunks, ts, 0, 1, (char *[]) {name});


        /* fluentbit_input_memrb_dropped_bytes */
        ins->cmt_memrb_dropped_bytes = cmt_counter_create(ins->cmt,
                                                          "fluentbit", "input",
                                                          "memrb_dropped_bytes",
                                                          "Number of memrb dropped bytes.",
                                                          1, (char *[]) {"name"});

        cmt_counter_set(ins->cmt_memrb_dropped_bytes, ts, 0, 1, (char *[]) {name});
    }

    /* OLD Metrics */
    ins->metrics = flb_metrics_create(name);
    if (ins->metrics) {
        flb_metrics_add(FLB_METRIC_N_RECORDS, "records", ins->metrics);
        flb_metrics_add(FLB_METRIC_N_BYTES, "bytes", ins->metrics);
    }
#endif

    /*
     * Before to call the initialization callback, make sure that the received
     * configuration parameters are valid if the plugin is registering a config map.
     */
    if (flb_input_plugin_property_check(ins, config) == -1) {
        return -1;
    }

#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        if ((p->flags & FLB_INPUT_NET_SERVER) != 0) {
            if (ins->tls_crt_file == NULL) {
                flb_error("[input %s] error initializing TLS context "
                          "(certificate file missing)",
                          ins->name);

                return -1;
            }
            else if (ins->tls_key_file == NULL) {
                flb_error("[input %s] error initializing TLS context "
                          "(private key file missing)",
                          ins->name);

                return -1;
            }

            tls_session_mode = FLB_TLS_SERVER_MODE;
        }
        else {
            tls_session_mode = FLB_TLS_CLIENT_MODE;
        }

        ins->tls = flb_tls_create(tls_session_mode,
                                  ins->tls_verify,
                                  ins->tls_debug,
                                  ins->tls_vhost,
                                  ins->tls_ca_path,
                                  ins->tls_ca_file,
                                  ins->tls_crt_file,
                                  ins->tls_key_file,
                                  ins->tls_key_passwd);

        if (ins->tls == NULL) {
            flb_error("[input %s] error initializing TLS context",
                      ins->name);

            return -1;
        }
    }

    struct flb_config_map *m;

    /* TLS config map (just for 'help' formatting purposes) */
    ins->tls_config_map = flb_tls_get_config_map(config);

    if (ins->tls_config_map == NULL) {
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

    if (flb_input_net_property_check(ins, config) == -1) {
        return -1;
    }

    /* Initialize the input */
    if (p->cb_init) {
        flb_plg_info(ins, "initializing");
        flb_plg_info(ins, "storage_strategy=%s", flb_storage_get_type(ins->storage_type));

        /* Sanity check: all non-dynamic tag input plugins must have a tag */
        if (!ins->tag) {
            flb_input_set_property(ins, "tag", ins->name);
            ins->tag_default = FLB_TRUE;
        }

        if (flb_input_is_threaded(ins)) {
            /*
             * Create a thread for a new instance. Now the plugin initialization callback will be invoked and report an early failure
             * or an 'ok' status, we will wait for that return value on flb_input_thread_instance_get_status() below.
             */
            ret = flb_input_thread_instance_init(config, ins);
            if (ret != 0) {
                flb_error("failed initialize input %s",
                          ins->name);
                return -1;
            }

            /* initialize channel events */
            ret = input_instance_channel_events_init(ins);
            if (ret != 0) {
                flb_error("failed initialize channel events on input %s",
                          ins->name);
                return -1;
            }

            /* register the ring buffer */
            ret = flb_ring_buffer_add_event_loop(ins->rb, config->evl, FLB_INPUT_RING_BUFFER_WINDOW);
            if (ret) {
                flb_error("failed while registering ring buffer events on input %s",
                          ins->name);
                return -1;
            }
        }
        else {
            /* initialize channel events */
            ret = input_instance_channel_events_init(ins);
            if (ret != 0) {
                flb_error("failed initialize channel events on input %s",
                          ins->name);
            }
            ret = p->cb_init(ins, config, ins->data);
            if (ret != 0) {
                flb_error("failed initialize input %s",
                          ins->name);
                return -1;
            }
        }
    }

    /* initialize processors */
    ret = flb_processor_init(ins->processor);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

int flb_input_instance_pre_run(struct flb_input_instance *ins, struct flb_config *config)
{
    int ret;

    if (flb_input_is_threaded(ins)) {
        return flb_input_thread_instance_pre_run(config, ins);
    }
    else if (ins->p->cb_pre_run) {
            ret = ins->p->cb_pre_run(ins, config, ins->context);
            if (ret == -1) {
                return -1;
            }
            return 0;
    }

    return 0;
}

/* Initialize all inputs */
int flb_input_init_all(struct flb_config *config)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_instance *ins;
    struct flb_input_plugin *p;

    /* Initialize thread-id table */
    memset(&config->in_table_id, '\0', sizeof(config->in_table_id));

    /* Iterate all active input instance plugins */
    mk_list_foreach_safe(head, tmp, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        p = ins->p;

        /* Skip pseudo input plugins */
        if (!p) {
            continue;
        }

        /* Initialize instance */
        ret = flb_input_instance_init(ins, config);
        if (ret == -1) {
            flb_input_instance_destroy(ins);
            return -1;
        }
    }

    return 0;
}

/* Invoke all pre-run input callbacks */
void flb_input_pre_run_all(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_instance *ins;
    struct flb_input_plugin *p;

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        p = ins->p;
        if (!p) {
            continue;
        }

        flb_input_instance_pre_run(ins, config);
    }
}

void flb_input_instance_exit(struct flb_input_instance *ins,
                             struct flb_config *config)
{
    struct flb_input_plugin *p;

    /* if the instance runs in a separate thread, signal the thread */
    if (flb_input_is_threaded(ins)) {
        flb_input_thread_instance_exit(ins);
        return;
    }

    p = ins->p;
    if (p->cb_exit && ins->context) {
        /* Multi-threaded input plugins use the same function signature for exit callbacks. */
        p->cb_exit(ins->context, config);
    }
}

/* Invoke all exit input callbacks */
void flb_input_exit_all(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_instance *ins;
    struct flb_input_plugin *p;

    /* Iterate instances */
    mk_list_foreach_safe_r(head, tmp, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        p = ins->p;
        if (!p) {
            continue;
        }

        /* invoke plugin instance exit callback */
        flb_input_instance_exit(ins, config);

        /* destroy the instance */
        flb_input_instance_destroy(ins);
    }
}

/* Check that at least one Input is enabled */
int flb_input_check(struct flb_config *config)
{
    if (mk_list_is_empty(&config->inputs) == 0) {
        return -1;
    }

    return 0;
}

/*
 * API for Input plugins
 * =====================
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 * The Input interface provides a certain number of functions that can be
 * used by Input plugins to configure it own behavior and request specific
 *
 *  1. flb_input_set_context()
 *
 *     let an Input plugin set a context data reference that can be used
 *     later when invoking other callbacks.
 *
 *  2. flb_input_set_collector_time()
 *
 *     request the Engine to trigger a specific collector callback at a
 *     certain interval time. Note that this callback will run in the main
 *     thread so it computing time must be short, otherwise it will block
 *     the main loop.
 *
 *     The collector can runs in timeouts of the order of seconds.nanoseconds
 *
 *      note: 1 Second = 1000000000 Nanosecond
 *
 *  3. flb_input_set_collector_event()
 *
 *     for a registered file descriptor, associate the READ events to a
 *     specified plugin. Every time there is some data to read, the collector
 *     callback will be triggered. Oriented to a file descriptor that already
 *     have information that may be read through iotctl(..FIONREAD..);
 *
 *  4. flb_input_set_collector_server()
 *
 *     it register a collector based on TCP socket events. It register a socket
 *     who did bind() and listen() and for each event on the socket it triggers
 *     the registered callbacks.
 */

/* Assign an Configuration context to an Input */
void flb_input_set_context(struct flb_input_instance *in, void *context)
{
    in->context = context;
}

int flb_input_channel_init(struct flb_input_instance *in)
{
    return flb_pipe_create(in->channel);
}

static struct flb_input_collector *collector_create(int type,
                                                    struct flb_input_instance *ins,
                                                            int (*cb) (
                                                            struct flb_input_instance *,
                                                            struct flb_config *, void *),
                                                    struct flb_config *config)
{
    struct flb_input_collector *coll;
    struct flb_input_thread_instance *thi;

    coll = flb_calloc(1, sizeof(struct flb_input_collector));
    if (!coll) {
        flb_errno();
        return NULL;
    }

    coll->id          = collector_id(ins);
    coll->type        = type;
    coll->running     = FLB_FALSE;
    coll->fd_event    = -1;
    coll->fd_timer    = -1;
    coll->seconds     = -1;
    coll->nanoseconds = -1;
    coll->cb_collect  = cb;
    coll->instance    = ins;
    MK_EVENT_ZERO(&coll->event);

    if (flb_input_is_threaded(ins)) {
        thi = ins->thi;
        coll->evl = thi->evl;
    }
    else {
        coll->evl = config->evl;
    }

    /*
     * Collectors created from a threaded input instance are only added to the
     * instance `collectors` list. For instances in non-threaded mode, they are
     * added to both lists, the global config collectors list and the instance
     * list.
     */
    mk_list_add(&coll->_head, &ins->collectors);

    return coll;
}


int flb_input_set_collector_time(struct flb_input_instance *ins,
                                 int (*cb_collect) (struct flb_input_instance *,
                                                    struct flb_config *, void *),
                                 time_t seconds,
                                 long   nanoseconds,
                                 struct flb_config *config)
{
    struct flb_input_collector *coll;

    coll = collector_create(FLB_COLLECT_TIME, ins, cb_collect, config);
    if (!coll) {
        return -1;
    }

    /* specific collector initialization */
    coll->seconds     = seconds;
    coll->nanoseconds = nanoseconds;

    return coll->id;
}

int flb_input_set_collector_event(struct flb_input_instance *ins,
                                  int (*cb_collect) (struct flb_input_instance *,
                                                     struct flb_config *, void *),
                                  flb_pipefd_t fd,
                                  struct flb_config *config)
{
    struct flb_input_collector *coll;

    coll = collector_create(FLB_COLLECT_FD_EVENT, ins, cb_collect, config);
    if (!coll) {
        return -1;
    }

    /* specific collector initialization */
    coll->fd_event = fd;

    return coll->id;
}

int flb_input_set_collector_socket(struct flb_input_instance *ins,
                                   int (*cb_new_connection) (struct flb_input_instance *,
                                                             struct flb_config *,
                                                             void *),
                                   flb_pipefd_t fd,
                                   struct flb_config *config)
{
    struct flb_input_collector *coll;


    coll = collector_create(FLB_COLLECT_FD_SERVER, ins, cb_new_connection, config);
    if (!coll) {
        return -1;
    }

    /* specific collector initialization */
    coll->fd_event = fd;

    return coll->id;
}


static int collector_start(struct flb_input_collector *coll,
                           struct flb_config *config)
{
    int fd;
    int ret;
    struct mk_event *event;

    if (coll->running == FLB_TRUE) {
        return 0;
    }

    event = &coll->event;
    event->mask = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    if (coll->type == FLB_COLLECT_TIME) {
        fd = mk_event_timeout_create(coll->evl, coll->seconds,
                                     coll->nanoseconds, event);
        if (fd == -1) {
            flb_error("[input collector] COLLECT_TIME registration failed");
            coll->running = FLB_FALSE;
            return -1;
        }
        coll->fd_timer = fd;
    }
    else if (coll->type & (FLB_COLLECT_FD_EVENT | FLB_COLLECT_FD_SERVER)) {
        event->fd = coll->fd_event;
        ret = mk_event_add(coll->evl,
                           coll->fd_event,
                           FLB_ENGINE_EV_CORE,
                           MK_EVENT_READ, event);
        if (ret == -1) {
            flb_error("[input collector] COLLECT_EVENT registration failed");
            mk_event_closesocket(coll->fd_event);
            coll->running = FLB_FALSE;
            return -1;
        }
    }

    coll->running = FLB_TRUE;
    return 0;
}

int flb_input_collector_start(int coll_id, struct flb_input_instance *in)
{
    int ret;
    int c = 0;
    struct mk_list *head;
    struct flb_input_collector *coll;

    mk_list_foreach(head, &in->collectors) {
        coll = mk_list_entry(head, struct flb_input_collector, _head);
        if (coll->id == coll_id) {
            ret = collector_start(coll, in->config);
            if (ret == -1) {
                flb_error("[input] error starting collector #%i: %s",
                          coll_id, in->name);
            }
            return ret;
        }
        c++;
    }

    return -1;
}

/* start collectors for main thread, no threaded plugins */
int flb_input_collectors_signal_start(struct flb_input_instance *ins)
{
    int ret;
    struct mk_list *head;
    struct flb_input_collector *coll;

    if (flb_input_is_threaded(ins)) {
        flb_error("input plugin '%s' is threaded", flb_input_name(ins));
        return -1;
    }

    mk_list_foreach(head, &ins->collectors) {
        coll = mk_list_entry(head, struct flb_input_collector, _head);
        ret = flb_input_collector_start(coll->id, ins);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Start all collectors: this function is invoked from the engine interface and aim
 * to start the local collectors and also signal the threaded input plugins to start
 * their own collectors.
 */
int flb_input_collectors_start(struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct flb_input_instance *ins;

    /* Signal threaded input plugins to start their collectors */
    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (flb_input_is_threaded(ins)) {
            ret = flb_input_thread_collectors_signal_start(ins);
            if (ret != 0) {
                flb_error("could not start collectors for threaded plugin '%s'",
                          flb_input_name(ins));
            }
        }
        else {
            ret = flb_input_collectors_signal_start(ins);
            if (ret != 0) {
                flb_error("could not start collectors for plugin '%s'",
                          flb_input_name(ins));
            }
        }
    }

    return 0;
}

static struct flb_input_collector *get_collector(int id,
                                                 struct flb_input_instance *in)
{
    struct mk_list *head;
    struct flb_input_collector *coll;

    mk_list_foreach(head, &in->collectors) {
        coll = mk_list_entry(head, struct flb_input_collector, _head);
        if (coll->id == id) {
            return coll;
        }
    }

    return NULL;
}

int flb_input_collector_running(int coll_id, struct flb_input_instance *in)
{
    struct flb_input_collector *coll;

    coll = get_collector(coll_id, in);
    if (!coll) {
        return FLB_FALSE;
    }

    return coll->running;
}

struct mk_event *flb_input_collector_get_event(int coll_id,
                                               struct flb_input_instance *ins)
{
    struct flb_input_collector *collector;

    collector = get_collector(coll_id, ins);

    if (collector == NULL) {
        return NULL;
    }

    return &collector->event;
}

/*
 * TEST: this is a test function that can be used by input plugins to check the
 * 'pause' and 'resume' callback operations.
 *
 * After is invoked, it will schedule an internal event to wake up the instance
 * after 'sleep_seconds'.
 */
int flb_input_test_pause_resume(struct flb_input_instance *ins, int sleep_seconds)
{
    /*
     * This is a fake pause/resume implementation since it's only used to test the plugin
     * callbacks for such purposes.
     */

    /* pause the instance */
    flb_input_pause(ins);

    /* wait */
    sleep(sleep_seconds);

    /* resume again */
    flb_input_resume(ins);

    return 0;
}

int flb_input_pause(struct flb_input_instance *ins)
{
    /* if the instance is already paused, just return */
    if (flb_input_buf_paused(ins)) {
        return -1;
    }

    /* Pause only if a callback is set and a local context exists */
    if (ins->p->cb_pause && ins->context) {
        if (flb_input_is_threaded(ins)) {
            /* signal the thread event loop about the 'pause' operation */
            flb_input_thread_instance_pause(ins);
        }
        else {
            flb_info("[input] pausing %s", flb_input_name(ins));
            ins->p->cb_pause(ins->context, ins->config);
        }
    }

    return 0;
}

int flb_input_resume(struct flb_input_instance *ins)
{
    if (ins->p->cb_resume) {
        ins->p->cb_resume(ins->context, ins->config);
    }

    return 0;
}

int flb_input_pause_all(struct flb_config *config)
{
    int ret;
    int paused = 0;
    struct mk_list *head;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        /*
         * Inform the plugin that is being paused, the source type is set to 'FLB_INPUT_PAUSE_MEM_BUF', no real reason, we
         * just need to get it paused.
         */
        ret = flb_input_pause(ins);
        if (ret == 0) {
            paused++;
        }
    }

    return paused;
}

int flb_input_collector_destroy(struct flb_input_collector *coll)
{
    struct flb_config *config = coll->instance->config;

    if (coll->type == FLB_COLLECT_TIME) {
        if (coll->fd_timer > 0) {
            mk_event_timeout_destroy(config->evl, &coll->event);
            mk_event_closesocket(coll->fd_timer);
        }
    }
    else {
        mk_event_del(config->evl, &coll->event);
    }

    flb_free(coll);

    return 0;
}

int flb_input_collector_pause(int coll_id, struct flb_input_instance *in)
{
    int ret;
    flb_pipefd_t fd;
    struct flb_input_collector *coll;

    coll = get_collector(coll_id, in);
    if (!coll) {
        return -1;
    }

    if (coll->running == FLB_FALSE) {
        return 0;
    }

    if (coll->type == FLB_COLLECT_TIME) {
        /*
         * For a collector time, it's better to just remove the file
         * descriptor associated to the time out, when resumed a new
         * one can be created.
         *
         * Note: Invalidate fd_timer first in case closing a socket
         * invokes another event.
         */
        fd = coll->fd_timer;
        coll->fd_timer = -1;
        mk_event_timeout_destroy(coll->evl, &coll->event);
        mk_event_closesocket(fd);
    }
    else if (coll->type & (FLB_COLLECT_FD_SERVER | FLB_COLLECT_FD_EVENT)) {
        ret = mk_event_del(coll->evl, &coll->event);
        if (ret != 0) {
            flb_warn("[input] cannot disable event for %s", in->name);
            return -1;
        }
    }

    coll->running = FLB_FALSE;

    return 0;
}

int flb_input_collector_delete(int coll_id, struct flb_input_instance *in)
{
    struct flb_input_collector *coll;

    coll = get_collector(coll_id, in);
    if (!coll) {
        return -1;
    }
    if (flb_input_collector_pause(coll_id, in) < 0) {
        return -1;
    }


    pthread_mutex_lock(&in->config->collectors_mutex);
    mk_list_del(&coll->_head);
    pthread_mutex_unlock(&in->config->collectors_mutex);

    flb_free(coll);
    return 0;
}

int flb_input_collector_resume(int coll_id, struct flb_input_instance *in)
{
    int fd;
    int ret;
    struct flb_input_collector *coll;
    struct flb_config *config;
    struct mk_event *event;

    coll = get_collector(coll_id, in);
    if (!coll) {
        return -1;
    }

    if (coll->running == FLB_TRUE) {
        flb_error("[input] cannot resume collector %s:%i, already running",
                  in->name, coll_id);
        return -1;
    }

    config = in->config;
    event = &coll->event;

    /* If data ingestion has been paused, the collector cannot resume */
    if (config->is_ingestion_active == FLB_FALSE) {
        return 0;
    }

    if (coll->type == FLB_COLLECT_TIME) {
        event->mask = MK_EVENT_EMPTY;
        event->status = MK_EVENT_NONE;
        fd = mk_event_timeout_create(coll->evl, coll->seconds,
                                     coll->nanoseconds, event);
        if (fd == -1) {
            flb_error("[input collector] resume COLLECT_TIME failed");
            return -1;
        }
        coll->fd_timer = fd;
    }
    else if (coll->type & (FLB_COLLECT_FD_SERVER | FLB_COLLECT_FD_EVENT)) {
        event->fd     = coll->fd_event;
        event->mask   = MK_EVENT_EMPTY;
        event->status = MK_EVENT_NONE;

        ret = mk_event_add(coll->evl,
                           coll->fd_event,
                           FLB_ENGINE_EV_CORE,
                           MK_EVENT_READ, event);
        if (ret == -1) {
            flb_error("[input] cannot disable/pause event for %s", in->name);
            return -1;
        }
    }

    coll->running = FLB_TRUE;

    return 0;
}

int flb_input_collector_fd(flb_pipefd_t fd, struct flb_config *config)
{
    struct mk_list *head;
    struct mk_list *head_coll;
    struct flb_input_instance *ins;
    struct flb_input_collector *collector = NULL;
    struct flb_input_coro *input_coro;

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        mk_list_foreach(head_coll, &ins->collectors) {
            collector = mk_list_entry(head_coll, struct flb_input_collector, _head);
            if (collector->fd_event == fd) {
                break;
            }
            else if (collector->fd_timer == fd) {
                flb_utils_timer_consume(fd);
                break;
            }
            collector = NULL;
        }

        if (collector) {
            break;
        }
    }

    /* No matches */
    if (!collector) {
        return -1;
    }

    if (collector->running == FLB_FALSE) {
        return -1;
    }

    /* Trigger the collector callback */
    if (collector->instance->runs_in_coroutine) {
        input_coro = flb_input_coro_collect(collector, config);
        if (!input_coro) {
            return -1;
        }
        flb_input_coro_resume(input_coro);
    }
    else {
        if (collector->cb_collect(collector->instance, config,
                                  collector->instance->context) == -1) {
            return -1;
        }
    }

    return 0;
}

int flb_input_upstream_set(struct flb_upstream *u, struct flb_input_instance *ins)
{
    if (!u) {
        return -1;
    }

    /*
     * if the input instance runs in threaded mode, make sure to flag the
     * upstream context so the lists operations are done in thread safe mode
     */
    if (flb_input_is_threaded(ins)) {
        flb_upstream_thread_safe(u);
        mk_list_add(&u->base._head, &ins->upstreams);
    }

    /* Set networking options 'net.*' received through instance properties */
    memcpy(&u->base.net, &ins->net_setup, sizeof(struct flb_net_setup));

    return 0;
}

int flb_input_downstream_set(struct flb_downstream *stream,
                             struct flb_input_instance *ins)
{
    if (stream == NULL) {
        return -1;
    }

    /*
     * If the input plugin will run in multiple threads, enable
     * the thread safe mode for the Downstream context.
     */
    if (flb_input_is_threaded(ins)) {
        flb_stream_enable_thread_safety(&stream->base);

        mk_list_add(&stream->base._head, &ins->downstreams);
    }

    return 0;
}
