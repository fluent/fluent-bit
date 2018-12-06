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

#define protcmp(a, b)  strncasecmp(a, b, strlen(a))

static int check_protocol(char *prot, char *output)
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
        if (entry->p == p) {
            c++;
        }
    }

    return c;
}

/* Generate a new collector ID for the instance in question */
static int collector_id(struct flb_input_instance *in)
{
    int id = 0;
    struct flb_input_collector *collector;

    if (mk_list_is_empty(&in->collectors) == 0) {
        return id;
    }

    collector = mk_list_entry_last(&in->collectors,
                                   struct flb_input_collector,
                                   _head_ins);
    return (collector->id + 1);
}

/* Create an input plugin instance */
struct flb_input_instance *flb_input_new(struct flb_config *config,
                                         char *input, void *data)
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

        /* Create plugin instance */
        instance = flb_malloc(sizeof(struct flb_input_instance));
        if (!instance) {
            perror("malloc");
            return NULL;
        }
        instance->config = config;

        /* Get an ID */
        id =  instance_id(plugin, config);

        /* format name (with instance id) */
        snprintf(instance->name, sizeof(instance->name) - 1,
                 "%s.%i", plugin->name, id);

        instance->id       = id;
        instance->flags    = plugin->flags;
        instance->p        = plugin;
        instance->tag      = NULL;
        instance->tag_len  = 0;
        instance->context  = NULL;
        instance->data     = data;
        instance->threaded = FLB_FALSE;
        instance->storage  = NULL;

        /* net */
        instance->host.name    = NULL;
        instance->host.address = NULL;
        instance->host.uri     = NULL;
        instance->host.ipv6    = FLB_FALSE;

        /* Initialize list heads */
        mk_list_init(&instance->routes);
        mk_list_init(&instance->tasks);
        mk_list_init(&instance->chunks);
        mk_list_init(&instance->properties);
        mk_list_init(&instance->collectors);
        mk_list_init(&instance->threads);

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

        /* Metrics */
#ifdef FLB_HAVE_METRICS
        instance->metrics = flb_metrics_create(instance->name);
        if (instance->metrics) {
            flb_metrics_add(FLB_METRIC_N_RECORDS, "records", instance->metrics);
            flb_metrics_add(FLB_METRIC_N_BYTES, "bytes", instance->metrics);
        }
#endif
        mk_list_add(&instance->_head, &config->inputs);
    }

    return instance;
}

static inline int prop_key_check(char *key, char *kv, int k_len)
{
    int len;

    len = strlen(key);

    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

/* Override a configuration property for the given input_instance plugin */
int flb_input_set_property(struct flb_input_instance *in, char *k, char *v)
{
    int len;
    ssize_t limit;
    char *tmp;
    struct flb_config_prop *prop;

    len = strlen(k);
    tmp = flb_env_var_translate(in->config->env, v);
    if (tmp) {
        if (strlen(tmp) == 0) {
            flb_free(tmp);
            tmp = NULL;
        }
    }

    /* Check if the key is a known/shared property */
    if (prop_key_check("tag", k, len) == 0 && tmp) {
        in->tag     = tmp;
        in->tag_len = strlen(tmp);
    }
    else if (prop_key_check("mem_buf_limit", k, len) == 0 && tmp) {
        limit = flb_utils_size_to_bytes(tmp);
        flb_free(tmp);
        if (limit == -1) {
            return -1;
        }
        in->mem_buf_limit = (size_t) limit;
    }
    else if (prop_key_check("listen", k, len) == 0) {
        in->host.listen = tmp;
    }
    else if (prop_key_check("host", k, len) == 0) {
        in->host.name   = tmp;
    }
    else if (prop_key_check("port", k, len) == 0) {
        if (tmp) {
            in->host.port = atoi(tmp);
            flb_free(tmp);
        }
    }
    else if (prop_key_check("ipv6", k, len) == 0 && tmp) {
        in->host.ipv6 = flb_utils_bool(tmp);
        flb_free(tmp);
    }
    else {
        /* Append any remaining configuration key to prop list */
        prop = flb_malloc(sizeof(struct flb_config_prop));
        if (!prop) {
            if (tmp) {
                flb_free(tmp);
            }
            return -1;
        }

        prop->key = flb_strdup(k);
        prop->val = tmp;
        mk_list_add(&prop->_head, &in->properties);
    }

    return 0;
}

char *flb_input_get_property(char *key, struct flb_input_instance *i)
{
    return flb_config_prop_get(key, &i->properties);
}

static void flb_input_free(struct flb_input_instance *in)
{
    struct mk_list *head_prop;
    struct flb_config_prop *prop;
    struct mk_list *tmp_prop;
    /* Remove URI context */
    if (in->host.uri) {
        flb_uri_destroy(in->host.uri);
    }
    flb_free(in->host.name);
    flb_free(in->host.address);

    /* release the tag if any */
    flb_free(in->tag);

    /* Let the engine remove any pending task */
    flb_engine_destroy_tasks(&in->tasks);

    /* release properties */
    mk_list_foreach_safe(head_prop, tmp_prop, &in->properties) {
        prop = mk_list_entry(head_prop, struct flb_config_prop, _head);

        flb_free(prop->key);
        flb_free(prop->val);

        mk_list_del(&prop->_head);
        flb_free(prop);
    }

    /* Remove metrics */
#ifdef FLB_HAVE_METRICS
    if (in->metrics) {
        flb_metrics_destroy(in->metrics);
    }
#endif

    if (in->storage) {
        flb_storage_input_destroy(in);
    }

    /* Unlink and release */
    mk_list_del(&in->_head);
    flb_free(in);
}

/* Initialize all inputs */
void flb_input_initialize_all(struct flb_config *config)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_instance *in;
    struct flb_input_plugin *p;

    /* Initialize thread-id table */
    memset(&config->in_table_id, '\0', sizeof(config->in_table_id));

    /* Iterate all active input instance plugins */
    mk_list_foreach_safe(head, tmp, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        p = in->p;

        /* Skip pseudo input plugins */
        if (!p) {
            continue;
        }

        /* Initialize the input */
        if (p->cb_init) {
            /* Sanity check: all non-dynamic tag input plugins must have a tag */
            if (!in->tag) {
                flb_input_set_property(in, "tag", in->name);
            }

            ret = p->cb_init(in, config, in->data);
            if (ret != 0) {
                flb_error("Failed initialize input %s",
                          in->name);
                flb_input_free(in);
            }
        }
    }
}

/* Invoke all pre-run input callbacks */
void flb_input_pre_run_all(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_instance *in;
    struct flb_input_plugin *p;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        p = in->p;
        if (!p) {
            continue;
        }

        if (p->cb_pre_run) {
            p->cb_pre_run(in, config, in->context);
        }
    }
}


/* Invoke all exit input callbacks */
void flb_input_exit_all(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_instance *in;
    struct flb_input_plugin *p;

    /* Iterate instances */
    mk_list_foreach_safe_r(head, tmp, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        p = in->p;
        if (!p) {
            continue;
        }

        if (p->cb_exit && in->context) {
            p->cb_exit(in->context, config);
        }
        flb_input_free(in);
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
            close(coll->fd_event);
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
        flb_info("[input] pausing %s", in->name);
        if (flb_input_buf_paused(in) == FLB_FALSE) {
            if (in->p->cb_pause) {
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

    config = in->config;
    if (coll->type == FLB_COLLECT_TIME) {
        /*
         * For a collector time, it's better to just remove the file
         * descriptor associated to the time out, when resumed a new
         * one can be created.
         */
        mk_event_timeout_destroy(config->evl, &coll->event);
        close(coll->fd_timer);
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
