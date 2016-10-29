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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_plugin_proxy.h>

/* Proxies */
#include "proxy/go/go.h"


static int proxy_cb_flush(void *data, size_t bytes,
                          char *tag, int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    struct flb_plugin_proxy *p = out_context;
    (void) tag_len;
    (void) i_ins;
    (void) config;

#ifdef FLB_HAVE_PROXY_GO
    if (p->proxy == FLB_PROXY_GOLANG) {
        flb_trace("[GO] entering go_flush()");
        proxy_go_flush(p, data, bytes, tag);
    }
#else
    (void) p;
#endif

    FLB_OUTPUT_RETURN(FLB_OK);
}


static int proxy_register_output(struct flb_plugin_proxy *proxy,
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
    out->description = flb_strdup(def->description);
    mk_list_add(&out->_head, &config->out_plugins);

    /*
     * Set proxy callbacks: external plugins which are not following
     * the core plugins specs, have a different callback approach, so
     * we put our proxy-middle callbacks to do the translatation properly.
     *
     */
    out->cb_flush    = proxy_cb_flush;
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

int flb_plugin_proxy_load(struct flb_plugin_proxy *proxy,
                          struct flb_config *config)
{
    int ret;
    struct flb_plugin_proxy_def *tmp;
    struct flb_plugin_proxy_def *(*cb_register)();

    /* Lookup and invoke registration callback */
    cb_register = flb_plugin_proxy_symbol(proxy, "flb_cb_register");
    if (!cb_register) {
        return -1;
    }

    /* Obtain registration information */
    tmp = cb_register();
    if (!tmp) {
        return -1;
    }

    fprintf(stderr,
            "[proxy plugin] type=%i proxy=%i name=%s desc='%s'\n",
            tmp->type, tmp->proxy, tmp->name, tmp->description);

    /* Based on 'proxy', use the proper handler */
    ret = -1;
    if (tmp->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        ret = proxy_go_start(proxy, tmp);
#endif
    }

    if (ret == 0) {
        /*
         * We got a plugin that can do it job, now we need to create the
         * real link to the 'output' interface
         */
        if (tmp->type == FLB_PROXY_OUTPUT_PLUGIN) {
            proxy->proxy = tmp->proxy;
            proxy_register_output(proxy, tmp, config);
        }
    }

    return 0;
}

struct flb_plugin_proxy *flb_plugin_proxy_create(const char *dso_path, int type,
                                                 struct flb_config *config)
{
    void *handle;
    struct flb_plugin_proxy *proxy;

    /* Load shared library */
    handle = dlopen(dso_path, RTLD_LAZY);
    if (!handle) {
        flb_errno();
        return NULL;
    }

    /* Context */
    proxy = flb_malloc(sizeof(struct flb_plugin_proxy));
    if (!proxy) {
        flb_errno();
        dlclose(handle);
        return NULL;
    }

    /* Set fields */
    proxy->type        = type;
    proxy->dso_handler = handle;
    proxy->data        = NULL;
    mk_list_add(&proxy->_head, &config->proxies);

    flb_plugin_proxy_load(proxy, config);

    return proxy;
}

void flb_plugin_proxy_destroy(struct flb_plugin_proxy *proxy)
{
    /* cleanup */
    dlclose(proxy->dso_handler);
    mk_list_del(&proxy->_head);
    flb_free(proxy);
}
