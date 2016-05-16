/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <string.h>
#include <unistd.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>

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


/* Create an input plugin instance */
struct flb_input_instance *flb_input_new(struct flb_config *config,
                                         char *input, void *data)
{
    int ret;
    struct mk_list *head;
    struct flb_input_plugin *plugin;
    struct flb_input_instance *instance = NULL;

    mk_list_foreach(head, &config->in_plugins) {
        plugin = mk_list_entry(head, struct flb_input_plugin, _head);
        if (!check_protocol(plugin->name, input)) {
            plugin = NULL;
            continue;
        }

        /* Create plugin instance */
        instance = malloc(sizeof(struct flb_input_instance));
        if (!instance) {
            perror("malloc");
            return NULL;
        }

        /* format name (with instance id) */
        snprintf(instance->name, sizeof(instance->name) - 1,
                 "%s.%i", plugin->name, instance_id(plugin, config));
        instance->p = plugin;
        instance->tag = NULL;
        instance->context = NULL;
        instance->data = data;
        instance->host.name = NULL;

        mk_list_init(&instance->routes);
        mk_list_init(&instance->tasks);
        mk_list_init(&instance->dyntags);
        mk_list_init(&instance->properties);

        if (plugin->flags & FLB_INPUT_NET) {
            ret = flb_net_host_set(plugin->name, &instance->host, input);
            if (ret != 0) {
                free(instance);
                return NULL;
            }
        }

        mk_list_add(&instance->_head, &config->inputs);
        break;
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
    struct flb_config_prop *prop;

    len = strlen(k);

    /* Check if the key is a known/shared property */
    if (prop_key_check("tag", k, len) == 0) {
        in->tag     = strdup(v);
        in->tag_len = strlen(v);
    }
    else {
        /* Append any remaining configuration key to prop list */
        prop = malloc(sizeof(struct flb_config_prop));
        if (!prop) {
            return -1;
        }

        prop->key = strdup(k);
        prop->val = strdup(v);
        mk_list_add(&prop->_head, &in->properties);
    }

    return 0;
}

char *flb_input_get_property(char *key, struct flb_input_instance *i)
{
    return flb_config_prop_get(key, &i->properties);
}

/* Initialize all inputs */
void flb_input_initialize_all(struct flb_config *config)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_instance *in;
    struct flb_input_plugin *p;

    /* Iterate all active input instance plugins */
    mk_list_foreach_safe(head, tmp, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        p = in->p;

        /* Initialize the input */
        if (p->cb_init) {
            ret = p->cb_init(in, config, in->data);
            if (ret != 0) {
                flb_error("Failed ininitalize input %s",
                          in->name);
                mk_list_del(&in->_head);
                free(in);
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

        if (p->cb_pre_run) {
            p->cb_pre_run(in->context, config);
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
    mk_list_foreach_safe(head, tmp, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        p = in->p;

        if (p->cb_exit) {
            p->cb_exit(in->context, config);
        }

        /* release the tag if any */
        free(in->tag);

        /* Let the engine remove any pending task */
        flb_engine_destroy_tasks(&in->tasks);

        /* Unlink and release */
        mk_list_del(&in->_head);
        free(in);
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
    return pipe(in->channel);
}

int flb_input_set_collector_time(struct flb_input_instance *in,
                                 int (*cb_collect) (struct flb_config *, void *),
                                 time_t seconds,
                                 long   nanoseconds,
                                 struct flb_config *config)
{
    struct flb_input_collector *collector;

    collector = malloc(sizeof(struct flb_input_collector));
    collector->type        = FLB_COLLECT_TIME;
    collector->cb_collect  = cb_collect;
    collector->fd_event    = -1;
    collector->fd_timer    = -1;
    collector->seconds     = seconds;
    collector->nanoseconds = nanoseconds;
    collector->instance    = in;

    mk_list_add(&collector->_head, &config->collectors);
    return 0;
}

int flb_input_set_collector_event(struct flb_input_instance *in,
                                  int (*cb_collect) (struct flb_config *, void *),
                                  int fd,
                                  struct flb_config *config)
{
    struct flb_input_collector *collector;

    collector = malloc(sizeof(struct flb_input_collector));
    collector->type        = FLB_COLLECT_FD_EVENT;
    collector->cb_collect  = cb_collect;
    collector->fd_event    = fd;
    collector->fd_timer    = -1;
    collector->seconds     = -1;
    collector->nanoseconds = -1;
    collector->instance    = in;

    mk_list_add(&collector->_head, &config->collectors);
    return 0;
}

int flb_input_set_collector_socket(struct flb_input_instance *in,
                                   int (*cb_new_connection) (struct flb_config *, void*),
                                   int fd,
                                   struct flb_config *config)
{
    struct flb_input_collector *collector;

    collector = malloc(sizeof(struct flb_input_collector));
    collector->type        = FLB_COLLECT_FD_SERVER;
    collector->cb_collect  = cb_new_connection;
    collector->fd_event    = fd;
    collector->fd_timer    = -1;
    collector->seconds     = -1;
    collector->nanoseconds = -1;
    collector->instance    = in;

    mk_list_add(&collector->_head, &config->collectors);
    return 0;
}

/* Creates a new dyntag node for the input_instance in question */
struct flb_input_dyntag *flb_input_dyntag_create(struct flb_input_instance *in,
                                                 char *tag, int tag_len)
{
    struct flb_input_dyntag *dt;

    if (tag_len < 1) {
        return NULL;
    }

    /* Allocate node and reset fields */
    dt = malloc(sizeof(struct flb_input_dyntag));
    if (!dt) {
        return NULL;
    }
    dt->in  = in;
    dt->tag = malloc(tag_len + 1);
    memcpy(dt->tag, tag, tag_len);
    dt->tag[tag_len] = '\0';
    dt->tag_len = tag_len;

    /* Initialize MessagePack fields */
    msgpack_sbuffer_init(&dt->mp_sbuf);
    msgpack_packer_init(&dt->mp_pck, &dt->mp_sbuf, msgpack_sbuffer_write);

    /* Link to the list head */
    mk_list_add(&dt->_head, &in->dyntags);
    return dt;
}

/* Destroy an dyntag node */
int flb_input_dyntag_destroy(struct flb_input_dyntag *dt)
{
    flb_trace("[dyntag %s] %p destroy",
              dt->in->name, dt);
    msgpack_sbuffer_destroy(&dt->mp_sbuf);
    mk_list_del(&dt->_head);
    free(dt->tag);
    free(dt);

    return 0;
}

/* Append a MessagPack Map to an active buffer in the input instance */
int flb_input_dyntag_append(struct flb_input_instance *in,
                            char *tag, size_t tag_len,
                            msgpack_object data)
{
    struct mk_list *head;
    struct flb_input_dyntag *dt = NULL;

    /* Try to find a current dyntag node to append the data */
    mk_list_foreach(head, &in->dyntags) {
        dt = mk_list_entry(head, struct flb_input_dyntag, _head);
        if (dt->tag_len != tag_len) {
            dt = NULL;
            continue;
        }

        if (strncmp(dt->tag, tag, tag_len) != 0) {
            dt = NULL;
            continue;
        }
        break;
    }

    /* Found a dyntag node that can append the new info */
    if (dt) {
        msgpack_pack_object(&dt->mp_pck, data);
        return 0;
    }

    /* No dyntag was found, we need to create a new one */
    dt = flb_input_dyntag_create(in, tag, tag_len);
    if (!dt) {
        return -1;
    }
    msgpack_pack_object(&dt->mp_pck, data);
    return 0;
}

/* Retrieve a raw buffer from a dyntag node */
void *flb_input_dyntag_flush(struct flb_input_dyntag *dt, size_t *size)
{
    void *buf;

    buf = malloc(dt->mp_sbuf.size);
    if (!buf) {
        perror("malloc");
        return NULL;
    }

    *size = dt->mp_sbuf.size;
    memcpy(buf, dt->mp_sbuf.data, dt->mp_sbuf.size);

    return buf;
}
