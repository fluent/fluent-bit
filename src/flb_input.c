/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

/* Inputs */
#include <fluent-bit/in_cpu.h>
#include <fluent-bit/in_kmsg.h>

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

static void add_input(char *name,
                      struct flb_config *config,
                      int (*cb_init)    (struct flb_config *),
                      int (*cb_collect) (void *))
{
    struct flb_input_plugin *in;

    in = calloc(1, sizeof(struct flb_input_plugin));
    in->name = strdup(name);
    in->cb_init    = cb_init;
    in->cb_collect = cb_collect;

    /* Register this Input in the global config */
    mk_list_add(&in->_head, &config->inputs);
}

/* Register all supported inputs */
int flb_input_register_all(struct flb_config *config)
{
    mk_list_init(&config->inputs);
    mk_list_init(&config->collectors);

    add_input("cpu" , config, in_cpu_init, in_cpu_collect);
    add_input("kmsg", config, in_kmsg_start, NULL);
}

/* Enable an input */
int flb_input_enable(char *name, struct flb_config *config)
{
    int ret;
    struct flb_input_plugin *plugin;

    plugin = plugin_lookup(name, config);
    if (!plugin) {
        return -1;
    }

    if (!plugin->cb_init) {
        flb_utils_error(FLB_ERR_INPUT_UNSUP);
    }
    plugin->active = FLB_TRUE;

    /* Initialize the input */
    if (plugin->cb_init) {
        ret = plugin->cb_init(config);
        if (ret != 0) {
            flb_error("Failed ininitalize Input %s",
                      plugin->name);
        }
    }

    return 0;
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
 *  2. flb_input_set_collector()
 *
 *     request the Engine to trigger a specific collector callback at a
 *     certain interval time. Note that this callback will run in the main
 *     thread so it computing time must be short, otherwise it will block
 *     the main loop.
 *
 *     The collector can runs in timeouts of the order of seconds.nanoseconds
 *
 *      note: 1 Second = 1000000000 Nanosecond
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

int flb_input_set_collector(char *name,
                            int (*cb_collect) (void *),
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
    collector->cb_collect  = cb_collect;
    collector->seconds     = seconds;
    collector->nanoseconds = nanoseconds;
    collector->plugin      = plugin;

    mk_list_add(&collector->_head, &config->collectors);
    return 0;
}
