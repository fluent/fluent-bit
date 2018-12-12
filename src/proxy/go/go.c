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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_output.h>

/*
 * These functions needs to be moved to a better place, still in
 * experimental mode.
 *
 * ------------------------start------------------------------------------------
 */

/*
 * Go Plugin phases
 * ================
 *
 *  1. FLBPluginRegister(context)
 *  2. Inside FLBPluginRegister, it needs to register it self using Fluent Bit API
 *     where it basically set:
 *
 *      - name: shortname of the plugin.
 *      - description: plugin description.
 *      - type: input, output, filter, whatever.
 *      - flags: optional flags, not used by Go plugins at the moment.
 *
 *     this is done through Go Wrapper:
 *
 *      output.FLBPluginRegister(ctx, name, description, type, flags);
 *
 * 3. Plugin Initialization
 */

struct flbgo_output_plugin {
    char *name;
    void *api;
    void *o_ins;
    int (*cb_init)();
    int (*cb_flush)(void *, size_t, char *);
    int (*cb_exit)(void *);
};
/*------------------------EOF------------------------------------------------*/

int proxy_go_register(struct flb_plugin_proxy *proxy,
                      struct flb_plugin_proxy_def *def)
{
    struct flbgo_output_plugin *plugin;

    plugin = flb_malloc(sizeof(struct flbgo_output_plugin));
    if (!plugin) {
        return -1;
    }

    /*
     * Lookup the entry point function:
     *
     * - FLBPluginInit
     * - FLBPluginFlush
     * - FLBPluginExit
     *
     * note: registration callback FLBPluginRegister() is resolved by the
     * parent proxy interface.
     */

    plugin->cb_init  = flb_plugin_proxy_symbol(proxy, "FLBPluginInit");
    if (!plugin->cb_init) {
        fprintf(stderr, "[go proxy]: could not load FLBPluginInit symbol\n");
        flb_free(plugin);
        return -1;
    }

    plugin->cb_flush = flb_plugin_proxy_symbol(proxy, "FLBPluginFlush");
    plugin->cb_exit  = flb_plugin_proxy_symbol(proxy, "FLBPluginExit");
    plugin->name     = flb_strdup(def->name);

    /* This Go plugin context is an opaque data for the parent proxy */
    proxy->data = plugin;

    return 0;
}

int proxy_go_init(struct flb_plugin_proxy *proxy)
{
    int ret;
    struct flbgo_output_plugin *plugin = proxy->data;

    /* set the API */
    plugin->api   = proxy->api;
    plugin->o_ins = proxy->instance;

    ret = plugin->cb_init(plugin);
    if (ret <= 0) {
        flb_error("[go proxy]: plugin '%s' failed to initialize",
                  plugin->name);
        flb_free(plugin);
        return -1;
    }

    return ret;
}

int proxy_go_flush(struct flb_plugin_proxy *proxy, void *data, size_t size,
                   char *tag, int tag_len)
{
    int ret;
    char *buf;
    struct flbgo_output_plugin *plugin = proxy->data;

    /* temporal buffer for the tag */
    buf = flb_malloc(tag_len + 1);
    if (!buf) {
        flb_errno();
        return -1;
    }

    memcpy(buf, tag, tag_len);
    buf[tag_len] = '\0';

    ret = plugin->cb_flush(data, size, buf);
    flb_free(buf);
    return ret;
}
