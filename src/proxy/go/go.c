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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_custom.h>
#include "./go.h"

/*
 * These functions needs to be moved to a better place, still in
 * experimental mode.
 *
 * ------------------------start------------------------------------------------
 */

/*
 * Go Plugin phases
 * ================
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  1. FLBPluginRegister(context)
 *  2. Inside FLBPluginRegister, it needs to register it self using Fluent Bit API
 *     where it basically set:
 *
 *      - name: shortname of the plugin.
 *      - description: plugin description.
 *      - type: input, output, filter, custom, whatever.
 *      - proxy: type of proxy e.g. GOLANG
 *      - flags: optional flags, not used by Go plugins at the moment.
 *
 *     this is done through Go Wrapper:
 *
 *      output.FLBPluginRegister(ctx, name, description, type, flags);
 *
 * 3. Plugin Initialization
 */
/*------------------------EOF------------------------------------------------*/

int proxy_go_output_register(struct flb_plugin_proxy *proxy,
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
     * - FLBPluginFlushCtx
     * - FLBPluginExit
     *
     * note: registration callback FLBPluginRegister() is resolved by the
     * parent proxy interface.
     */

    plugin->cb_init  = flb_plugin_proxy_symbol(proxy, "FLBPluginInit");
    if (!plugin->cb_init) {
        flb_error("[go proxy]: could not load FLBPluginInit symbol");
        flb_free(plugin);
        return -1;
    }

    plugin->cb_flush = flb_plugin_proxy_symbol(proxy, "FLBPluginFlush");
    plugin->cb_flush_ctx = flb_plugin_proxy_symbol(proxy, "FLBPluginFlushCtx");
    plugin->cb_exit  = flb_plugin_proxy_symbol(proxy, "FLBPluginExit");
    plugin->cb_exit_ctx = flb_plugin_proxy_symbol(proxy, "FLBPluginExitCtx");
    plugin->name     = flb_strdup(def->name);

    /* This Go plugin context is an opaque data for the parent proxy */
    proxy->data = plugin;

    return 0;
}

int proxy_go_output_init(struct flb_plugin_proxy *proxy)
{
    int ret;
    struct flbgo_output_plugin *plugin = proxy->data;

    /* set the API */
    plugin->api   = proxy->api;
    plugin->o_ins = proxy->instance;
    // In order to avoid having the whole instance as part of the ABI we
    // copy the context pointer into the plugin.
    plugin->context = ((struct flb_output_instance *)proxy->instance)->context;

    ret = plugin->cb_init(plugin);
    if (ret <= 0) {
        flb_error("[go proxy]: plugin '%s' failed to initialize",
                  plugin->name);
        return -1;
    }

    return ret;
}

int proxy_go_output_flush(struct flb_plugin_proxy_context *ctx,
                          const void *data, size_t size,
                          const char *tag, int tag_len)
{
    int ret;
    char *buf;
    struct flbgo_output_plugin *plugin = ctx->proxy->data;

    /* temporary buffer for the tag */
    buf = flb_malloc(tag_len + 1);
    if (!buf) {
        flb_errno();
        return -1;
    }

    memcpy(buf, tag, tag_len);
    buf[tag_len] = '\0';

    if (plugin->cb_flush_ctx) {
        ret = plugin->cb_flush_ctx(ctx->remote_context, data, size, buf);
    }
    else {
        ret = plugin->cb_flush(data, size, buf);
    }
    flb_free(buf);
    return ret;
}

int proxy_go_output_destroy(struct flb_plugin_proxy_context *ctx)
{
    int ret = 0;
    struct flbgo_output_plugin *plugin;

    plugin = (struct flbgo_output_plugin *) ctx->proxy->data;
    flb_debug("[GO] running exit callback");

    if (plugin->cb_exit_ctx) {
        ret = plugin->cb_exit_ctx(ctx->remote_context);
    }
    else if (plugin->cb_exit) {
        ret = plugin->cb_exit();
    }
    return ret;
}

void proxy_go_output_unregister(void *data) {
    struct flbgo_output_plugin *plugin;

    plugin = (struct flbgo_output_plugin *) data;
    flb_free(plugin->name);
    flb_free(plugin);
}

int proxy_go_input_register(struct flb_plugin_proxy *proxy,
                            struct flb_plugin_proxy_def *def)
{
    struct flbgo_input_plugin *plugin;

    plugin = flb_malloc(sizeof(struct flbgo_input_plugin));
    if (!plugin) {
        return -1;
    }

    /*
     * Lookup the entry point function:
     *
     * - FLBPluginInit
     * - FLBPluginInputCallback
     * - FLBPluginExit
     *
     * note: registration callback FLBPluginRegister() is resolved by the
     * parent proxy interface.
     */

    plugin->cb_init  = flb_plugin_proxy_symbol(proxy, "FLBPluginInit");
    if (!plugin->cb_init) {
        flb_error("[go proxy]: could not load FLBPluginInit symbol");
        flb_free(plugin);
        return -1;
    }

    plugin->cb_collect = flb_plugin_proxy_symbol(proxy, "FLBPluginInputCallback");
    plugin->cb_cleanup = flb_plugin_proxy_symbol(proxy, "FLBPluginInputCleanupCallback");
    plugin->cb_exit  = flb_plugin_proxy_symbol(proxy, "FLBPluginExit");
    plugin->name     = flb_strdup(def->name);

    /* This Go plugin context is an opaque data for the parent proxy */
    proxy->data = plugin;

    return 0;
}

int proxy_go_input_init(struct flb_plugin_proxy *proxy)
{
    int ret;
    struct flbgo_input_plugin *plugin = proxy->data;

    /* set the API */
    plugin->api   = proxy->api;
    plugin->i_ins = proxy->instance;
    // In order to avoid having the whole instance as part of the ABI we
    // copy the context pointer into the plugin.
    plugin->context = ((struct flb_input_instance *)proxy->instance)->context;

    ret = plugin->cb_init(plugin);
    if (ret <= 0) {
        flb_error("[go proxy]: plugin '%s' failed to initialize",
                  plugin->name);
        return -1;
    }

    return ret;
}

int proxy_go_input_collect(struct flb_plugin_proxy *ctx,
                           void **collected_data, size_t *len)
{
    int ret;
    void *data = NULL;
    struct flbgo_input_plugin *plugin = ctx->data;

    ret = plugin->cb_collect(&data, len);

    *collected_data = data;

    return ret;
}

int proxy_go_input_cleanup(struct flb_plugin_proxy *ctx,
                           void *allocated_data)
{
    int ret = 0;
    struct flbgo_input_plugin *plugin = ctx->data;

    if (plugin->cb_cleanup) {
        ret = plugin->cb_cleanup(allocated_data);
    }
    else {
        /* If cleanup callback is not registered, we need to cleanup
         * allocated memory on fluent-bit side. */
        if (allocated_data != NULL) {
            free(allocated_data);
        }
    }

    return ret;
}

int proxy_go_input_destroy(struct flb_plugin_input_proxy_context *ctx)
{
    int ret = 0;
    struct flbgo_input_plugin *plugin;

    plugin = (struct flbgo_input_plugin *) ctx->proxy->data;
    flb_debug("[GO] running exit callback");

    if (plugin->cb_exit) {
        ret = plugin->cb_exit();
    }
    return ret;
}

void proxy_go_input_unregister(void *data) {
    struct flbgo_input_plugin *plugin;

    plugin = (struct flbgo_input_plugin *) data;
    flb_free(plugin->name);
    flb_free(plugin);
}

int proxy_go_custom_register(struct flb_plugin_proxy *proxy,
                            struct flb_plugin_proxy_def *def)
{
    struct flbgo_custom_plugin *plugin;

    plugin = flb_malloc(sizeof(struct flbgo_custom_plugin));
    if (!plugin) {
        flb_errno();
        return -1;
    }

    /*
     * Lookup the entry point function:
     *
     * - FLBPluginInit
     * - FLBPluginExit
     *
     * note: registration callback FLBPluginRegister() is resolved by the
     * parent proxy interface.
     */

    plugin->cb_init  = flb_plugin_proxy_symbol(proxy, "FLBPluginInit");
    if (!plugin->cb_init) {
        flb_error("[go proxy]: could not load FLBPluginInit symbol");
        flb_free(plugin);
        return -1;
    }

    plugin->cb_exit  = flb_plugin_proxy_symbol(proxy, "FLBPluginExit");

    plugin->name = flb_strdup(def->name);

    /* This Go plugin context is an opaque data for the parent proxy */
    proxy->data = plugin;

    return 0;
}

int proxy_go_custom_init(struct flb_plugin_proxy *proxy)
{
    int ret = 0;
    struct flbgo_custom_plugin *plugin = proxy->data;

    /* set the API */
    plugin->api   = proxy->api;
    plugin->i_ins = proxy->instance;
    /* In order to avoid having the whole instance as part of the ABI we */
    /* copy the context pointer into the plugin. */
    plugin->context = ((struct flb_custom_instance *)proxy->instance)->context;

    ret = plugin->cb_init(plugin);
    if (ret <= 0) {
        flb_error("[go proxy]: plugin '%s' failed to initialize",
                  plugin->name);
        flb_free(plugin);
        return -1;
    }

    return ret;
}

int proxy_go_custom_destroy(struct flb_plugin_proxy_context *ctx)
{
    int ret = 0;
    struct flbgo_custom_plugin *plugin;

    plugin = (struct flbgo_custom_plugin *) ctx->proxy->data;

    if (plugin->cb_exit) {
        ret = plugin->cb_exit();
    }

    return ret;
}

void proxy_go_custom_unregister(void *data) {
    struct flbgo_custom_plugin *plugin;

    plugin = (struct flbgo_custom_plugin *) data;
    flb_free(plugin->name);
    flb_free(plugin);
}

