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

#include <stdlib.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_kv.h>

#define protcmp(a, b)  strncasecmp(a, b, strlen(a))

static int check_protocol(const char *prot, const char *output)
{
    int len;

    len = strlen(prot);
    if (len > strlen(output)) {
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
                                   _head_ins);
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

        /* format name (with instance id) */
        snprintf(instance->name, sizeof(instance->name) - 1,
                 "%s.%i", plugin->name, id);

        instance->alias    = NULL;
        instance->id       = id;
        instance->flags    = plugin->flags;
        instance->p        = plugin;
        instance->tag      = NULL;
        instance->tag_len  = 0;
        instance->routable = FLB_TRUE;
        instance->context  = NULL;
        instance->data     = data;
        instance->threaded = FLB_FALSE;
        instance->storage  = NULL;
        instance->storage_type = -1;
        instance->log_level = -1;

        /* net */
        instance->host.name    = NULL;
        instance->host.address = NULL;
        instance->host.uri     = NULL;
        instance->host.listen  = NULL;
        instance->host.ipv6    = FLB_FALSE;

        /* Initialize list heads */
        mk_list_init(&instance->routes);
        mk_list_init(&instance->tasks);
        mk_list_init(&instance->chunks);
        mk_list_init(&instance->collectors);
        mk_list_init(&instance->threads);

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

        /* Plugin requires a Thread context */
        if (plugin->flags & FLB_INPUT_THREAD) {
            instance->threaded = FLB_TRUE;
        }

        instance->mp_total_buf_size = 0;
        instance->mem_buf_status = FLB_INPUT_RUNNING;
        instance->mem_buf_limit = 0;
        instance->mem_chunks_size = 0;

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

/* Override a configuration property for the given input_instance plugin */
int flb_input_set_property(struct flb_input_instance *ins,
                           const char *k, const char *v)
{
    int len;
    int ret;
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

    /* Unlink and release */
    mk_list_del(&ins->_head);
    flb_free(ins);
}

int flb_input_instance_init(struct flb_input_instance *ins,
                            struct flb_config *config)
{
    int ret;
#ifdef FLB_HAVE_METRICS
    const char *name;
#endif
    struct mk_list *config_map;
    struct flb_input_plugin *p = ins->p;

    if (ins->log_level == -1) {
        ins->log_level = config->log->level;
    }

    /* Skip pseudo input plugins */
    if (!p) {
        return 0;
    }

    /* Metrics */
#ifdef FLB_HAVE_METRICS
    /* Get name or alias for the instance */
    name = flb_input_name(ins);

    /* Create the metrics context */
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
            flb_error("[filter] error loading config map for '%s' plugin",
                      p->name);
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

        ret = p->cb_init(ins, config, ins->data);
        if (ret != 0) {
            flb_error("Failed initialize input %s",
                      ins->name);
            flb_input_instance_destroy(ins);
            return -1;
        }
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

        if (p->cb_pre_run) {
            p->cb_pre_run(ins, config, ins->context);
        }
    }
}

void flb_input_instance_exit(struct flb_input_instance *ins,
                             struct flb_config *config)
{
    struct flb_input_plugin *p;

    p = ins->p;
    if (p->cb_exit && ins->context) {
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

        flb_input_instance_exit(ins, config);
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
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

int flb_input_set_collector_time(struct flb_input_instance *in,
                                 int (*cb_collect) (struct flb_input_instance *,
                                                    struct flb_config *, void *),
                                 time_t seconds,
                                 long   nanoseconds,
                                 struct flb_config *config)
{
    struct flb_input_collector *collector;

    collector = flb_malloc(sizeof(struct flb_input_collector));
    if (!collector) {
        flb_errno();
        return -1;
    }

    collector->id          = collector_id(in);
    collector->type        = FLB_COLLECT_TIME;
    collector->cb_collect  = cb_collect;
    collector->fd_event    = -1;
    collector->fd_timer    = -1;
    collector->seconds     = seconds;
    collector->nanoseconds = nanoseconds;
    collector->instance    = in;
    collector->running     = FLB_FALSE;
    MK_EVENT_ZERO(&collector->event);
    mk_list_add(&collector->_head, &config->collectors);
    mk_list_add(&collector->_head_ins, &in->collectors);

    return collector->id;
}

int flb_input_set_collector_event(struct flb_input_instance *in,
                                  int (*cb_collect) (struct flb_input_instance *,
                                                     struct flb_config *, void *),
                                  flb_pipefd_t fd,
                                  struct flb_config *config)
{
    struct flb_input_collector *collector;

    collector = flb_malloc(sizeof(struct flb_input_collector));
    if (!collector) {
        flb_errno();
        return -1;
    }

    collector->id          = collector_id(in);
    collector->type        = FLB_COLLECT_FD_EVENT;
    collector->cb_collect  = cb_collect;
    collector->fd_event    = fd;
    collector->fd_timer    = -1;
    collector->seconds     = -1;
    collector->nanoseconds = -1;
    collector->instance    = in;
    collector->running     = FLB_FALSE;
    MK_EVENT_ZERO(&collector->event);
    mk_list_add(&collector->_head, &config->collectors);
    mk_list_add(&collector->_head_ins, &in->collectors);

    return collector->id;
}

static int collector_start(struct flb_input_collector *coll,
                           struct flb_config *config)
{
    int fd;
    int ret;
    struct mk_event *event;
    struct mk_event_loop *evl;

    if (coll->running == FLB_TRUE) {
        return 0;
    }

    event = &coll->event;
    evl = config->evl;

    if (coll->type == FLB_COLLECT_TIME) {
        event->mask = MK_EVENT_EMPTY;
        event->status = MK_EVENT_NONE;
        fd = mk_event_timeout_create(evl, coll->seconds,
                                     coll->nanoseconds, event);
        if (fd == -1) {
            flb_error("[input collector] COLLECT_TIME registration failed");
            coll->running = FLB_FALSE;
            return -1;
        }
        coll->fd_timer = fd;
    }
    else if (coll->type & (FLB_COLLECT_FD_EVENT | FLB_COLLECT_FD_SERVER)) {
        event->fd     = coll->fd_event;
        event->mask   = MK_EVENT_EMPTY;
        event->status = MK_EVENT_NONE;

        ret = mk_event_add(evl,
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
        coll = mk_list_entry(head, struct flb_input_collector, _head_ins);
        if (coll->id == coll_id) {
            ret = collector_start(coll, in->config);
            if (ret == -1) {
                flb_error("[input] error starting collector #%i: %s",
                          in->name);
            }
            return ret;
        }
        c++;
    }

    return -1;
}

int flb_input_collectors_start(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_collector *collector;

    /* For each Collector, register the event into the main loop */
    mk_list_foreach(head, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        collector_start(collector, config);
    }

    return 0;
}

static struct flb_input_collector *get_collector(int id,
                                                 struct flb_input_instance *in)
{
    struct mk_list *head;
    struct flb_input_collector *coll;

    mk_list_foreach(head, &in->collectors) {
        coll = mk_list_entry(head, struct flb_input_collector, _head_ins);
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

int flb_input_pause_all(struct flb_config *config)
{
    int paused = 0;
    struct mk_list *head;
    struct flb_input_instance *in;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        if (flb_input_buf_paused(in) == FLB_FALSE) {
            if (in->p->cb_pause && in->context) {
                flb_info("[input] pausing %s", flb_input_name(in));
                in->p->cb_pause(in->context, in->config);
            }
            paused++;
        }
        in->mem_buf_status = FLB_INPUT_PAUSED;
    }

    return paused;
}

int flb_input_collector_pause(int coll_id, struct flb_input_instance *in)
{
    int ret;
    struct flb_config *config;
    struct flb_input_collector *coll;

    coll = get_collector(coll_id, in);
    if (!coll) {
        return -1;
    }

    if (coll->running == FLB_FALSE) {
        return 0;
    }

    config = in->config;
    if (coll->type == FLB_COLLECT_TIME) {
        /*
         * For a collector time, it's better to just remove the file
         * descriptor associated to the time out, when resumed a new
         * one can be created.
         */
        mk_event_timeout_destroy(config->evl, &coll->event);
        mk_event_closesocket(coll->fd_timer);
        coll->fd_timer = -1;
    }
    else if (coll->type & (FLB_COLLECT_FD_SERVER | FLB_COLLECT_FD_EVENT)) {
        ret = mk_event_del(config->evl, &coll->event);
        if (ret != 0) {
            flb_warn("[input] cannot disable event for %s", in->name);
            return -1;
        }
    }

    coll->running = FLB_FALSE;

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

    if (coll->type == FLB_COLLECT_TIME) {
        event->mask = MK_EVENT_EMPTY;
        event->status = MK_EVENT_NONE;
        fd = mk_event_timeout_create(config->evl, coll->seconds,
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

        ret = mk_event_add(config->evl,
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

int flb_input_set_collector_socket(struct flb_input_instance *in,
                                   int (*cb_new_connection) (struct flb_input_instance *,
                                                             struct flb_config *,
                                                             void *),
                                   flb_pipefd_t fd,
                                   struct flb_config *config)
{
    struct flb_input_collector *collector;

    collector = flb_malloc(sizeof(struct flb_input_collector));
    if (!collector) {
        flb_errno();
        return -1;
    }

    collector->id          = collector_id(in);
    collector->type        = FLB_COLLECT_FD_SERVER;
    collector->cb_collect  = cb_new_connection;
    collector->fd_event    = fd;
    collector->fd_timer    = -1;
    collector->seconds     = -1;
    collector->nanoseconds = -1;
    collector->instance    = in;
    collector->running     = FLB_FALSE;
    MK_EVENT_ZERO(&collector->event);
    mk_list_add(&collector->_head, &config->collectors);
    mk_list_add(&collector->_head_ins, &in->collectors);

    return 0;
}

int flb_input_collector_fd(flb_pipefd_t fd, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_collector *collector = NULL;
    struct flb_thread *th;

    mk_list_foreach(head, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        if (collector->fd_event == fd) {
            break;
        }
        else if (collector->fd_timer == fd) {
            flb_utils_timer_consume(fd);
            break;
        }
        collector = NULL;
    }

    /* No matches */
    if (!collector) {
        return -1;
    }

    if (collector->running == FLB_FALSE) {
        return -1;
    }

    /* Trigger the collector callback */
    if (collector->instance->threaded == FLB_TRUE) {
        th = flb_input_thread_collect(collector, config);
        if (!th) {
            return -1;
        }
        flb_thread_resume(th);
    }
    else {
        collector->cb_collect(collector->instance, config,
                              collector->instance->context);
    }

    return 0;
}
