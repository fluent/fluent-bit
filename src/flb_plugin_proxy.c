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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_api.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_plugin_proxy.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_custom.h>

/* Proxies */
#include "proxy/go/go.h"

#define PROXY_CALLBACK_TIME    1 /* 1 seconds */

static void proxy_cb_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int ret = FLB_ERROR;
    struct flb_plugin_proxy_context *ctx = out_context;
    (void) i_ins;
    (void) config;

#ifdef FLB_HAVE_PROXY_GO
    if (ctx->proxy->def->proxy == FLB_PROXY_GOLANG) {
        flb_trace("[GO] entering go_flush()");
        ret = proxy_go_output_flush(ctx,
                                    event_chunk->data,
                                    event_chunk->size,
                                    event_chunk->tag,
                                    flb_sds_len(event_chunk->tag));
    }
#else
    (void) ctx;
#endif

    if (ret != FLB_OK && ret != FLB_RETRY && ret != FLB_ERROR) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    FLB_OUTPUT_RETURN(ret);
}

static int flb_proxy_input_cb_collect(struct flb_input_instance *ins,
                                      struct flb_config *config, void *in_context)
{
    int ret = FLB_OK;
    size_t len = 0;
    void *data = NULL;
    struct flb_plugin_input_proxy_context *ctx = (struct flb_plugin_input_proxy_context *) in_context;

#ifdef FLB_HAVE_PROXY_GO
    if (ctx->proxy->def->proxy == FLB_PROXY_GOLANG) {
        flb_trace("[GO] entering go_collect()");
        ret = proxy_go_input_collect(ctx, &data, &len);

        if (len == 0) {
            flb_trace("[GO] No logs are ingested");
            return -1;
        }

        if (ret == -1) {
            flb_errno();
            return -1;
        }

        flb_input_log_append(ins, NULL, 0, data, len);

        ret = proxy_go_input_cleanup(ctx, data);
        if (ret == -1) {
            flb_errno();
            return -1;
        }
    }
#endif

    return 0;
}

static int flb_proxy_input_cb_init(struct flb_input_instance *ins,
                                   struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_plugin_input_proxy_context *pc;

    /* Before to initialize for proxy, set the proxy instance reference */
    pc = (struct flb_plugin_input_proxy_context *)(ins->context);

    /* Before to initialize, set the instance reference */
    pc->proxy->instance = ins;

    /* Based on 'proxy', use the proper handler */
    if (pc->proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        ret = proxy_go_input_init(pc->proxy);

        if (ret == -1) {
            flb_error("Could not initialize proxy for threaded input plugin");
            goto init_error;
        }
#else
        flb_error("Could not find initializing function on proxy for threaded input plugin");
        goto init_error;
#endif
    }
    else {
        flb_error("[proxy] unrecognized input proxy handler %i",
                  pc->proxy->def->proxy);
    }

    /* Set the context */
    flb_input_set_context(ins, pc);

    /* Collect upon data available on timer */
    ret = flb_input_set_collector_time(ins,
                                       flb_proxy_input_cb_collect,
                                       PROXY_CALLBACK_TIME, 0,
                                       config);

    if (ret == -1) {
        flb_error("Could not set collector for threaded proxy input plugin");
        goto init_error;
    }
    pc->coll_fd = ret;

    return ret;

init_error:
    flb_free(pc);

    return -1;
}

static void flb_proxy_input_cb_pause(void *data, struct flb_config *config)
{
    struct flb_plugin_input_proxy_context *ctx = data;
    struct flb_plugin_proxy *proxy = (ctx->proxy);

    /* pause */
    void (*cb_pause)(void);

    cb_pause = flb_plugin_proxy_symbol(proxy, "FLBPluginInputPause");
    if (cb_pause != NULL) {
        cb_pause();
    }

    flb_input_collector_pause(ctx->coll_fd, ctx->proxy->instance);
}

static void flb_proxy_input_cb_resume(void *data, struct flb_config *config)
{
    struct flb_plugin_input_proxy_context *ctx = data;
    struct flb_plugin_proxy *proxy = (ctx->proxy);

    /* resume */
    void (*cb_resume)(void);

    cb_resume = flb_plugin_proxy_symbol(proxy, "FLBPluginInputResume");
    if (cb_resume != NULL) {
        cb_resume();
    }

    flb_input_collector_resume(ctx->coll_fd, ctx->proxy->instance);
}

static void flb_plugin_proxy_destroy(struct flb_plugin_proxy *proxy);

static int flb_proxy_output_cb_exit(void *out_context, struct flb_config *config)
{
    struct flb_plugin_proxy_context *ctx = out_context;
    struct flb_plugin_proxy *proxy = (ctx->proxy);
    /* pre_exit (Golang plugin only) */
    void (*cb_pre_exit)(int);

    if (!out_context) {
        return 0;
    }

    cb_pre_exit = flb_plugin_proxy_symbol(proxy, "FLBPluginOutputPreExit");
    if (cb_pre_exit != NULL) {
        cb_pre_exit(config->shutdown_by_hot_reloading);
    }

    if (proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        proxy_go_output_destroy(ctx);
#endif
    }

    flb_free(ctx);
    return 0;
}

static void flb_proxy_output_cb_destroy(struct flb_output_plugin *plugin)
{
    struct flb_plugin_proxy *proxy = (struct flb_plugin_proxy *) plugin->proxy;
    /* cleanup */
    void (*cb_unregister)(struct flb_plugin_proxy_def *def);

    cb_unregister = flb_plugin_proxy_symbol(proxy, "FLBPluginUnregister");
    if (cb_unregister != NULL) {
        cb_unregister(proxy->def);
    }

    if (plugin->name != NULL) {
        flb_free(plugin->name);

        plugin->name = NULL;
    }

    if (proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
proxy_go_output_unregister(proxy->data);
#endif
    }

    flb_plugin_proxy_destroy(proxy);
}

static int flb_proxy_input_cb_exit(void *in_context, struct flb_config *config)
{
    struct flb_plugin_input_proxy_context *ctx = in_context;
    struct flb_plugin_proxy *proxy = (ctx->proxy);
    /* pre_exit (Golang plugin only) */
    void (*cb_pre_exit)(int);

    if (!in_context) {
        return 0;
    }

    cb_pre_exit = flb_plugin_proxy_symbol(proxy, "FLBPluginInputPreExit");
    if (cb_pre_exit != NULL) {
        cb_pre_exit(config->shutdown_by_hot_reloading);
    }

    if (proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        proxy_go_input_destroy(ctx);
#endif
    }

    flb_free(ctx);
    return 0;
}

static void flb_proxy_input_cb_destroy(struct flb_input_plugin *plugin)
{
    struct flb_plugin_proxy *proxy = (struct flb_plugin_proxy *) plugin->proxy;
    /* cleanup */
    void (*cb_unregister)(struct flb_plugin_proxy_def *def);

    cb_unregister = flb_plugin_proxy_symbol(proxy, "FLBPluginUnregister");
    if (cb_unregister != NULL) {
        cb_unregister(proxy->def);
    }

    if (plugin->name != NULL) {
        flb_free(plugin->name);

        plugin->name = NULL;
    }

    if (proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        proxy_go_input_unregister(proxy->data);
#endif
    }

    flb_plugin_proxy_destroy(proxy);
}

static int flb_proxy_input_cb_pre_run(struct flb_input_instance *ins,
                                      struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_plugin_input_proxy_context *pc;
    struct flb_plugin_proxy *proxy;

    pc = (struct flb_plugin_input_proxy_context *)(ins->context);
    proxy = pc->proxy;

    /* pre_run */
    int (*cb_pre_run)(int);

    cb_pre_run = flb_plugin_proxy_symbol(proxy, "FLBPluginInputPreRun");
    if (cb_pre_run != NULL) {
        ret = cb_pre_run(config->enable_hot_reload);
    }

    return ret;
}

static int flb_proxy_output_cb_pre_run(void *out_context, struct flb_config *config)
{
    int ret = -1;
    struct flb_plugin_proxy_context *ctx = out_context;
    struct flb_plugin_proxy *proxy = (ctx->proxy);

    if (!out_context) {
        return 0;
    }

    /* pre_run */
    int (*cb_pre_run)(int);

    cb_pre_run = flb_plugin_proxy_symbol(proxy, "FLBPluginOutputPreRun");
    if (cb_pre_run != NULL) {
        ret = cb_pre_run(config->enable_hot_reload);
    }

    return ret;
}

int flb_proxy_output_cb_init(struct flb_output_instance *o_ins,
                             struct flb_config *config, void *data);

static int flb_proxy_register_output(struct flb_plugin_proxy *proxy,
                                     struct flb_plugin_proxy_def *def,
                                     struct flb_config *config)
{
    struct flb_output_plugin *out;

    out = flb_calloc(1, sizeof(struct flb_output_plugin));
    if (!out) {
        flb_errno();
        return -1;
    }

    /* Plugin registration */
    out->type  = FLB_OUTPUT_PLUGIN_PROXY;
    out->proxy = proxy;
    out->flags = def->flags;
    out->name  = flb_strdup(def->name);

    /* If event_type is unset (0) then default to logs (this is the current behavior) */
    if (def->event_type == 0) {
        out->event_type = FLB_OUTPUT_LOGS;
    }
    else {
        out->event_type = def->event_type;
    }

    out->description = def->description;
    mk_list_add(&out->_head, &config->out_plugins);

    /*
     * Set proxy callbacks: external plugins which are not following
     * the core plugins specs, have a different callback approach, so
     * we put our proxy-middle callbacks to do the translation properly.
     */
    out->cb_init = flb_proxy_output_cb_init;
    out->cb_flush = proxy_cb_flush;
    out->cb_pre_run = flb_proxy_output_cb_pre_run;
    out->cb_exit = flb_proxy_output_cb_exit;
    out->cb_destroy = flb_proxy_output_cb_destroy;
    return 0;
}

static int flb_proxy_register_input(struct flb_plugin_proxy *proxy,
                                    struct flb_plugin_proxy_def *def,
                                    struct flb_config *config)
{
    struct flb_input_plugin *in;

    in = flb_calloc(1, sizeof(struct flb_input_plugin));
    if (!in) {
        flb_errno();
        return -1;
    }

    /* Plugin registration */
    in->type  = FLB_INPUT_PLUGIN_PROXY;
    in->proxy = proxy;
    in->flags = def->flags | FLB_INPUT_THREADED;
    in->name  = flb_strdup(def->name);
    in->description = def->description;

    mk_list_add(&in->_head, &config->in_plugins);

    /*
     * Set proxy callbacks: external plugins which are not following
     * the core plugins specs, have a different callback approach, so
     * we put our proxy-middle callbacks to do the translation properly.
     */
    in->cb_pre_run = flb_proxy_input_cb_pre_run;
    in->cb_init = flb_proxy_input_cb_init;
    in->cb_collect = flb_proxy_input_cb_collect;
    in->cb_flush_buf = NULL;
    in->cb_exit = flb_proxy_input_cb_exit;
    in->cb_destroy = flb_proxy_input_cb_destroy;
    in->cb_pause = flb_proxy_input_cb_pause;
    in->cb_resume = flb_proxy_input_cb_resume;
    return 0;
}

int flb_proxy_custom_cb_init(struct flb_custom_instance *c_ins,
                             struct flb_config *config, void *data);

static int flb_proxy_custom_cb_exit(void *custom_context,
                                    struct flb_config *config);
static void flb_proxy_custom_cb_destroy(struct flb_custom_plugin *plugin);

static int flb_proxy_register_custom(struct flb_plugin_proxy *proxy,
                                     struct flb_plugin_proxy_def *def,
                                     struct flb_config *config)
{
    struct flb_custom_plugin *custom;

    custom = flb_calloc(1, sizeof(struct flb_custom_plugin));
    if (!custom) {
        flb_errno();
        return -1;
    }

    /* Plugin registration */
    custom->type  = FLB_CUSTOM_PLUGIN_PROXY;
    custom->proxy = proxy;
    custom->flags = def->flags;
    custom->name  = flb_strdup(def->name);
    custom->description = def->description;
    mk_list_add(&custom->_head, &config->custom_plugins);

    /*
     * Set proxy callbacks: external plugins which are not following
     * the core plugins specs, have a different callback approach, so
     * we put our proxy-middle callbacks to do the translation properly.
     */
    custom->cb_init = flb_proxy_custom_cb_init;
    custom->cb_exit = flb_proxy_custom_cb_exit;
    custom->cb_destroy = flb_proxy_custom_cb_destroy;
    return 0;
}

void *flb_plugin_proxy_symbol(struct flb_plugin_proxy *proxy,
                              const char *symbol)
{
    void *s;

    dlerror();
    s = dlsym(proxy->dso_handler, symbol);
    if (dlerror() != NULL) {
        return NULL;
    }
    return s;
}

int flb_plugin_proxy_register(struct flb_plugin_proxy *proxy,
                              struct flb_config *config)
{
    int ret;
    int (*cb_register)(struct flb_plugin_proxy_def *);
    int (*cb_pre_register)(int);
    struct flb_plugin_proxy_def *def = proxy->def;

    /* Lookup the pre registration callback */
    cb_pre_register = flb_plugin_proxy_symbol(proxy, "FLBPluginPreRegister");
    if (cb_pre_register != NULL) {
        /* Prepare the registration if available */
        ret = cb_pre_register(config->hot_reloading);
        if (ret == -1) {
            return -1;
        }
    }

    /* Lookup the registration callback */
    cb_register = flb_plugin_proxy_symbol(proxy, "FLBPluginRegister");
    if (!cb_register) {
        return -1;
    }

    /*
     * Create a temporary definition used for registration. This definition
     * aims to be be populated by plugin in the registration phase with:
     *
     * - plugin type (or proxy type, e.g: Golang)
     * - plugin name
     * - plugin description
     */

    /* Do the registration */
    ret = cb_register(def);
    if (ret == -1) {
        flb_free(def);
        return -1;
    }

    /*
     * Each plugin proxy/type, have their own handler, based on the data
     * provided in the registration invoke the proper handler.
     */
    ret = -1;
    if (def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        if (def->type == FLB_PROXY_OUTPUT_PLUGIN) {
            ret = proxy_go_output_register(proxy, def);
        }
        else if (def->type == FLB_PROXY_INPUT_PLUGIN) {
            ret = proxy_go_input_register(proxy, def);
        } 
        else if (def->type == FLB_PROXY_CUSTOM_PLUGIN) {
            ret = proxy_go_custom_register(proxy, def);
        }
#endif
    }
    if (ret == 0) {
        /*
         * We got a plugin that can do it job, now we need to create the
         * real link to the 'output' interface
         */
        if (def->type == FLB_PROXY_OUTPUT_PLUGIN) {
            flb_proxy_register_output(proxy, def, config);
        }
        else if (def->type == FLB_PROXY_INPUT_PLUGIN) {
            flb_proxy_register_input(proxy, def, config);
        }
        else if (def->type == FLB_PROXY_CUSTOM_PLUGIN) {
            flb_proxy_register_custom(proxy, def, config);
        }
    }

    return 0;
}

int flb_proxy_output_cb_init(struct flb_output_instance *o_ins,
                             struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_plugin_proxy_context *pc;

    /* Before to initialize for proxy, set the proxy instance reference */
    pc = (struct flb_plugin_proxy_context *)(o_ins->context);

    /* Before to initialize, set the instance reference */
    pc->proxy->instance = o_ins;

    /* Based on 'proxy', use the proper handler */
    if (pc->proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        ret = proxy_go_output_init(pc->proxy);
#endif
    }
    else {
        flb_error("[proxy] unrecognized proxy handler %i",
                  pc->proxy->def->proxy);
    }

    if (ret == -1) {
        flb_error("[output] could not initialize '%s' plugin",
                  o_ins->p->name);
        return -1;
    }

    /* Multi-threading enabled if configured */
    ret = flb_output_enable_multi_threading(o_ins, config);
    if (ret == -1) {
        flb_error("[output] could not start thread pool for '%s' plugin",
                  o_ins->p->name);
        return -1;
    }

    return ret;
}

struct flb_plugin_proxy *flb_plugin_proxy_create(const char *dso_path, int type,
                                                 struct flb_config *config)
{
    void *handle;
    struct flb_plugin_proxy *proxy;

    /* Load shared library */
    handle = dlopen(dso_path, RTLD_LAZY);
    if (!handle) {
        flb_error("[proxy] error opening plugin %s: '%s'",
                  dso_path, dlerror());
        return NULL;
    }

    /* Proxy Context */
    proxy = flb_malloc(sizeof(struct flb_plugin_proxy));
    if (!proxy) {
        flb_errno();
        dlclose(handle);
        return NULL;
    }

    /* API Context */
    proxy->api = flb_api_create();
    if (!proxy->api) {
        dlclose(handle);
        flb_free(proxy);
        return NULL;
    }

    proxy->def = flb_calloc(1, sizeof(struct flb_plugin_proxy_def));
    if (!proxy->def) {
        flb_errno();
        dlclose(handle);
        flb_api_destroy(proxy->api);
        flb_free(proxy);
        return NULL;
    }

    /* Set fields and add it to the list */
    proxy->def->type        = type;
    proxy->dso_handler = handle;
    proxy->data        = NULL;
    mk_list_add(&proxy->_head, &config->proxies);

    /* Register plugin */
    flb_plugin_proxy_register(proxy, config);

    return proxy;
}

static void flb_plugin_proxy_destroy(struct flb_plugin_proxy *proxy)
{
    flb_free(proxy->def);
    flb_api_destroy(proxy->api);
    dlclose(proxy->dso_handler);
    mk_list_del(&proxy->_head);
    flb_free(proxy);
}

int flb_plugin_proxy_set(struct flb_plugin_proxy_def *def, int type,
                         int proxy, char *name, char *description)
{
    def->type  = type;
    def->proxy = proxy;
    def->name  = flb_strdup(name);
    def->description = flb_strdup(description);

    return 0;
}

int flb_proxy_custom_cb_init(struct flb_custom_instance *c_ins,
                             struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_plugin_proxy_context *pc;
    struct flb_plugin_proxy *proxy;

    pc = (struct flb_plugin_proxy_context *)(c_ins->context);
    proxy = pc->proxy;

    /* Before to initialize, set the instance reference */
    pc->proxy->instance = c_ins;

    if (proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        ret = proxy_go_custom_init(proxy);
#endif
    }

    if (ret == -1) {
        flb_error("[custom] could not initialize '%s' plugin",
                  c_ins->p->name);
        return -1;
    }

    return 0;
}

int flb_proxy_custom_cb_exit(void *custom_context, 
                             struct flb_config *config)
{
    int ret = -1;
    struct flb_plugin_proxy_context *ctx = custom_context;
    struct flb_plugin_proxy *proxy = (ctx->proxy);
    if (!custom_context) {
        return ret;
    }

    if (proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        ret = proxy_go_custom_destroy(ctx);
#endif
    }

    flb_free(ctx);
    return ret;
}

static void flb_proxy_custom_cb_destroy(struct flb_custom_plugin *plugin)
{
    struct flb_plugin_proxy *proxy = (struct flb_plugin_proxy *) plugin->proxy;

    if (plugin->name != NULL) {
        flb_free(plugin->name);

        plugin->name = NULL;
    }

    if (proxy->def->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        proxy_go_custom_unregister(proxy->data);
#endif
    }

    flb_plugin_proxy_destroy(proxy);
}
