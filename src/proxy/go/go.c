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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_output.h>

#include <dlfcn.h>

/*
 * These functions needs to be moved to a better place, still in
 * experimental mode.
 *
 * ------------------------start------------------------------------------------
 */

/* Go Plugin initialization:

   1. FLBPluginInit(some context)
   2. Iniside FLBPluginInit, it needs to register it self using Fluent Bit API
      where it basically set:

      - name: shortname of the plugin.
      - description: plugin description.
      - type: input, output, filter, whatever.
      - flags: optional flags, not used by Go plugins at the moment.

      this is done through Go Wrapper:

        FLBPluginRegister(ctx, name, description, type, flags);
 */
struct flbgo_plugin {
    char *name;
    int (*cb_init)(struct flbgo_plugin *);
};

struct flbgo_output_plugin {
    char *name;
    int (*cb_init)();
    int (*cb_flush)(void *, size_t, char *);
    int (*cb_exit)(void *);
};
/*------------------------EOF------------------------------------------------*/

int proxy_go_start(struct flb_plugin_proxy *proxy,
                   struct flb_plugin_proxy_def *def)
{
    int ret;
    struct flbgo_output_plugin *plugin;

    plugin = flb_malloc(sizeof(struct flbgo_plugin));
    if (!plugin) {
        return -1;
    }

    /* Lookup the entry point function */
    plugin->cb_init  = flb_plugin_proxy_symbol(proxy, "FLBPluginInit");
    if (!plugin->cb_init) {
        fprintf(stderr, "[go proxy]: could not load FLBPluginInit symbol\n");
        flb_free(plugin);
        return -1;
    }

    /* Initialize the plugin, we expect the Go code perform the registration */
    ret = plugin->cb_init(plugin);
    if (ret == -1) {
        fprintf(stderr, "[go proxy]: plugin failed to initialize\n");
        flb_free(plugin);
        return -1;
    }

    plugin->name     = flb_strdup(def->name);
    plugin->cb_flush = flb_plugin_proxy_symbol(proxy, "FLBPluginFlush");
    plugin->cb_exit  = flb_plugin_proxy_symbol(proxy, "FLBPluginExit");

    proxy->data = plugin;
    return 0;
}

int proxy_go_flush(struct flb_plugin_proxy *proxy, void *data, size_t size,
                   char *tag)
{
    struct flbgo_output_plugin *plugin = proxy->data;
    return plugin->cb_flush(data, size, tag);
}
