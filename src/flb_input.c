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
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_ring_buffer.h>

struct flb_libco_in_params libco_in_param;

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

int flb_input_event_type_is_metric(struct flb_input_instance *ins)
{
    if (ins->event_type == FLB_INPUT_METRICS) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int flb_input_event_type_is_log(struct flb_input_instance *ins)
{
    if (ins->event_type == FLB_INPUT_LOGS) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
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
    struct mk_list *head;
    struct flb_input_plugin *plugin;
    struct flb_input_instance *instance = NULL;

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

        /* format name (with instance id) */
        snprintf(instance->name, sizeof(instance->name) - 1,
                 "%s.%i", plugin->name, id);

        /* set plugin type based on flags: logs or metrics ? */
        if (plugin->event_type == FLB_INPUT_LOGS) {
            instance->event_type = FLB_INPUT_LOGS;
        }
        else if (plugin->event_type == FLB_INPUT_METRICS) {
            instance->event_type = FLB_INPUT_METRICS;
        }
        else {
            flb_error("[input] invalid plugin event type %i on '%s'",
                      plugin->event_type, instance->name);
            flb_hash_table_destroy(instance->ht_log_chunks);
            flb_hash_table_destroy(instance->ht_metric_chunks);
            flb_free(instance);
            return NULL;
        }

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
        instance->routable = FLB_TRUE;
        instance->data     = data;
        instance->storage  = NULL;
        instance->storage_type = -1;
        instance->log_level = -1;
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
        mk_list_init(&instance->upstreams);

        /* Initialize properties list */
        flb_kv_init(&instance->properties);

        /* Plugin use networking */
        if (plugin->flags & FLB_INPUT_NET) {
            ret = flb_net_host_set(plugin->name, &instance->host, input);
            if (ret != 0) {
                flb_free(instance);
                return NULL;
            }
        }

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

        instance->mp_total_buf_size = 0;
        instance->mem_buf_status = FLB_INPUT_RUNNING;
        instance->mem_buf_limit = 0;
        instance->mem_chunks_size = 0;
        instance->storage_buf_status = FLB_INPUT_RUNNING;
        mk_list_add(&instance->_head, &config->inputs);
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
    }
    else if (prop_key_check("log_level", k, len) == 0 && tmp) {
        ret = flb_log_get_level_str(tmp);
        flb_sds_destroy(tmp);
        if (ret == -1) {
            return -1;
        }
        ins->log_level = ret;
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
    else if (prop_key_check("storage.type", k, len) == 0 && tmp) {
        /* Set the storage type */
        if (strcasecmp(tmp, "filesystem") == 0) {
            ins->storage_type = CIO_STORE_FS;
        }
        else if (strcasecmp(tmp, "memory") == 0) {
            ins->storage_type = CIO_STORE_MEM;
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
        if (ins->storage_type == CIO_STORE_FS) {
            ret = flb_utils_bool(tmp);
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

    /* release the tag if any */
    flb_sds_destroy(ins->tag);

    /* Let the engine remove any pending task */
    flb_engine_destroy_tasks(&ins->tasks);

    /* release properties */
    flb_kv_release(&ins->properties);

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

    /* hash table for chunks */
    if (ins->ht_log_chunks) {
        flb_hash_table_destroy(ins->ht_log_chunks);
    }

    if (ins->ht_metric_chunks) {
        flb_hash_table_destroy(ins->ht_metric_chunks);
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

    if (ins->rb) {
        flb_ring_buffer_destroy(ins->rb);
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

int flb_input_instance_init(struct flb_input_instance *ins,
                            struct flb_config *config)
{
    int ret;
    struct mk_list *config_map;
    struct flb_input_plugin *p = ins->p;

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
    ts = cmt_time_now();

    /* CMetrics */
    ins->cmt = cmt_create();
    if (!ins->cmt) {
        flb_error("[input] could not create cmetrics context: %s",
                  flb_input_name(ins));
        return -1;
    }

    /* Register generic input plugin metrics */
    ins->cmt_bytes = cmt_counter_create(ins->cmt,
                                        "fluentbit", "input", "bytes_total",
                                        "Number of input bytes.",
                                        1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_bytes, ts, 0, 1, (char *[]) {name});

    ins->cmt_records = cmt_counter_create(ins->cmt,
                                        "fluentbit", "input", "records_total",
                                        "Number of input records.",
                                        1, (char *[]) {"name"});
    cmt_counter_set(ins->cmt_records, ts, 0, 1, (char *[]) {name});

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
            flb_input_instance_destroy(ins);
            return -1;
        }
    }

    /* Initialize the input */
    if (p->cb_init) {
        /* Sanity check: all non-dynamic tag input plugins must have a tag */
        if (!ins->tag) {
            flb_input_set_property(ins, "tag", ins->name);
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
                flb_input_instance_destroy(ins);
                return -1;
            }

            /* initialize channel events */
            ret = input_instance_channel_events_init(ins);
            if (ret != 0) {
                flb_error("failed initialize channel events on input %s",
                          ins->name);
                flb_input_instance_destroy(ins);
                return -1;
            }

            /* register the ring buffer */
            ret = flb_ring_buffer_add_event_loop(ins->rb, config->evl, FLB_INPUT_RING_BUFFER_WINDOW);
            if (ret) {
                flb_error("failed while registering ring buffer events on input %s",
                          ins->name);
                flb_input_instance_destroy(ins);
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
                flb_input_instance_destroy(ins);
                return -1;
            }
        }
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
            /* do nothing, it's ok if it fails */
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
        mk_list_add(&u->_head, &ins->upstreams);
    }

    return 0;
}
