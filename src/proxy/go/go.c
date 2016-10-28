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
    struct flbgo_output_plugin *plugin;

    plugin = flb_malloc(sizeof(struct flbgo_output_plugin));
    if (!plugin) {
        return -1;
    }

    plugin->name     = flb_strdup(def->name);
    plugin->cb_init  = flb_plugin_proxy_symbol(proxy, "flb_cb_init");
    plugin->cb_flush = flb_plugin_proxy_symbol(proxy, "flb_cb_flush");
    plugin->cb_exit  = flb_plugin_proxy_symbol(proxy, "flb_cb_exit");
    plugin->cb_init();

    proxy->data = plugin;
    return 0;
}

int proxy_go_flush(struct flb_plugin_proxy *proxy, void *data, size_t size,
                   char *tag)
{
    struct flbgo_output_plugin *plugin = proxy->data;
    return plugin->cb_flush(data, size, tag);
}
