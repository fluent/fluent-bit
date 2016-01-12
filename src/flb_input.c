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

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

static struct flb_input_plugin *plugin_lookup(char *name, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *plugin;

    mk_list_foreach(head, &config->inputs) {
        plugin = mk_list_entry(head, struct flb_input_plugin, _head);
        if (strncmp(plugin->name, name, strlen(name)) == 0) {
            return plugin;
        }
    }

    return NULL;
}

/* Enable an input */
int flb_input_set(struct flb_config *config, char *name, void *data)
{
    struct flb_input_plugin *plugin;

    plugin = plugin_lookup(name, config);
    if (!plugin) {
        return -1;
    }

    plugin->active = FLB_TRUE;
    plugin->data   = data;

    return 0;
}

/* Initialize all inputs */
void flb_input_initialize_all(struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct flb_input_plugin *in;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        /* Initialize the input */
        if (in->active == FLB_TRUE && in->cb_init) {
            ret = in->cb_init(config, in->data);
            if (ret != 0) {
                flb_error("Failed ininitalize input %s",
                in->name);
            }
        }
    }
}

/* Invoke all pre-run input callbacks */
void flb_input_pre_run_all(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *in;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        if (in->active == FLB_TRUE) {
            if (in->cb_pre_run) {
                in->cb_pre_run(in->in_context, config);
            }
        }
    }
}

/* Invoke all exit input callbacks */
void flb_input_exit_all(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *in;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);
        if (in->active == FLB_TRUE) {
            if (in->cb_exit) {
                in->cb_exit(in->in_context, config);
            }
        }
    }
}

/* Check that at least one Input is enabled */
int flb_input_check(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_plugin *plugin;

    mk_list_foreach(head, &config->inputs) {
        plugin = mk_list_entry(head, struct flb_input_plugin, _head);
        if (plugin->active == FLB_TRUE) {
            return 0;
        }
    }

    return -1;
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
int flb_input_set_context(char *name, void *in_context, struct flb_config *config)
{
    struct flb_input_plugin *plugin;

    plugin = plugin_lookup(name, config);
    if (!plugin) {
        return -1;
    }

    plugin->in_context = in_context;
    return 0;
}

int flb_input_set_collector_time(char *name,
                                 int (*cb_collect) (struct flb_config *, void *),
                                 time_t seconds,
                                 long   nanoseconds,
                                 struct flb_config *config)
{
    struct flb_input_plugin *plugin;
    struct flb_input_collector *collector;

    plugin = plugin_lookup(name, config);
    if (!plugin) {
        return -1;
    }

    collector = malloc(sizeof(struct flb_input_collector));
    collector->type        = FLB_COLLECT_TIME;
    collector->cb_collect  = cb_collect;
    collector->fd_event    = -1;
    collector->fd_timer    = -1;
    collector->seconds     = seconds;
    collector->nanoseconds = nanoseconds;
    collector->plugin      = plugin;

    mk_list_add(&collector->_head, &config->collectors);
    return 0;
}

int flb_input_set_collector_event(char *name,
                                  int (*cb_collect) (struct flb_config *, void *),
                                  int fd,
                                  struct flb_config *config)
{
    struct flb_input_plugin *plugin;
    struct flb_input_collector *collector;

    plugin = plugin_lookup(name, config);
    if (!plugin) {
        return -1;
    }

    collector = malloc(sizeof(struct flb_input_collector));
    collector->type        = FLB_COLLECT_FD_EVENT;
    collector->cb_collect  = cb_collect;
    collector->fd_event    = fd;
    collector->fd_timer    = -1;
    collector->seconds     = -1;
    collector->nanoseconds = -1;
    collector->plugin      = plugin;

    mk_list_add(&collector->_head, &config->collectors);
    return 0;
}

int flb_input_set_collector_socket(char *name,
                                   int (*cb_new_connection) (struct flb_config *, void*),
                                   int fd,
                                   struct flb_config *config)
{
    struct flb_input_plugin *plugin;
    struct flb_input_collector *collector;

    plugin = plugin_lookup(name, config);
    if (!plugin) {
        return -1;
    }

    collector = malloc(sizeof(struct flb_input_collector));
    collector->type        = FLB_COLLECT_FD_SERVER;
    collector->cb_collect  = cb_new_connection;
    collector->fd_event    = fd;
    collector->fd_timer    = -1;
    collector->seconds     = -1;
    collector->nanoseconds = -1;
    collector->plugin      = plugin;

    mk_list_add(&collector->_head, &config->collectors);
    return 0;
}
