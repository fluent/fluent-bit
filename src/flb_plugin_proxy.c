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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_api.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_plugin_proxy.h>

/* Proxies */
#include "proxy/go/go.h"

static void flb_proxy_cb_flush(void *data, size_t bytes,
                               char *tag, int tag_len,
                               struct flb_input_instance *i_ins,
                               void *out_context,
                               struct flb_config *config)
{
    int ret = FLB_ERROR;
    struct flb_plugin_proxy *p = out_context;
    (void) tag_len;
    (void) i_ins;
    (void) config;

#ifdef FLB_HAVE_PROXY_GO
    if (p->proxy == FLB_PROXY_GOLANG) {
        flb_trace("[GO] entering go_flush()");
        ret = proxy_go_flush(p, data, bytes, tag, tag_len);
    }
#else
    (void) p;
#endif

    if (ret != FLB_OK && ret != FLB_RETRY && ret != FLB_ERROR) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    FLB_OUTPUT_RETURN(ret);
}


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
    out->description = flb_strdup(def->description);
    mk_list_add(&out->_head, &config->out_plugins);

    /*
     * Set proxy callbacks: external plugins which are not following
     * the core plugins specs, have a different callback approach, so
     * we put our proxy-middle callbacks to do the translation properly.
     */
    out->cb_flush = flb_proxy_cb_flush;
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
    struct flb_plugin_proxy_def *def;

    /* Lookup the registration callback */
    cb_register = flb_plugin_proxy_symbol(proxy, "FLBPluginRegister");

    /*
     * Create a temporal definition used for registration. This definition
     * aims to be be populated by plugin in the registration phase with:
     *
     * - plugin type (or proxy type, e.g: Golang)
     * - plugin name
     * - plugin description
     */
    def = flb_malloc(sizeof(struct flb_plugin_proxy_def));
    if (!def) {
        return -1;
    }

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
        ret = proxy_go_register(proxy, def);
#endif
    }
    if (ret == 0) {
        /*
         * We got a plugin that can do it job, now we need to create the
         * real link to the 'output' interface
         */
        if (def->type == FLB_PROXY_OUTPUT_PLUGIN) {
            proxy->proxy = def->proxy;
            flb_proxy_register_output(proxy, def, config);
        }
    }

    return 0;
}

int flb_plugin_proxy_init(struct flb_plugin_proxy *proxy,
                          struct flb_output_instance *o_ins,
                          struct flb_config *config)
{
    int ret = -1;

    /* Before to initialize, set the instance reference */
    proxy->instance = o_ins;

    /* Based on 'proxy', use the proper handler */
    if (proxy->proxy == FLB_PROXY_GOLANG) {
#ifdef FLB_HAVE_PROXY_GO
        ret = proxy_go_init(proxy);
#endif
    }
    else {
        fprintf(stderr, "[proxy] unrecognized proxy handler %i\n",
                proxy->proxy);
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
        fprintf(stderr, "[proxy] error opening plugin %s: \"%s\"\n", dso_path, dlerror());
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

    /* Set fields and add it to the list */
    proxy->type        = type;
    proxy->dso_handler = handle;
    proxy->data        = NULL;
    mk_list_add(&proxy->_head, &config->proxies);

    /* Register plugin */
    flb_plugin_proxy_register(proxy, config);

    return proxy;
}

/* Load plugins from a configuration file */
int flb_plugin_proxy_conf_file(char *file, struct flb_config *config)
{
    int ret;
    char tmp[PATH_MAX + 1];
    char *cfg = NULL;
    struct mk_rconf *fconf;
    struct mk_rconf_section *section;
    struct mk_rconf_entry *entry;
    struct mk_list *head;
    struct mk_list *head_e;
    struct stat st;

#ifndef FLB_HAVE_STATIC_CONF
    ret = stat(file, &st);
    if (ret == -1 && errno == ENOENT) {
        /* Try to resolve the real path (if exists) */
        if (file[0] == '/') {
            flb_utils_error(FLB_ERR_CFG_PLUGIN_FILE);
            return -1;
        }

        if (config->conf_path) {
            snprintf(tmp, PATH_MAX, "%s%s", config->conf_path, file);
            cfg = tmp;
        }
    }
    else {
        cfg = file;
    }

    flb_debug("[plugin] opening configuration file %s", cfg);
    fconf = mk_rconf_open(cfg);
#else
    fconf = flb_config_static_open(file);
#endif

    if (!fconf) {
        return -1;
    }

    /* Read all [PLUGINS] sections */
    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "PLUGINS") != 0) {
            continue;
        }

        mk_list_foreach(head_e, &section->entries) {
            entry = mk_list_entry(head_e, struct mk_rconf_entry, _head);
            if (strcmp(entry->key, "Path") != 0) {
                continue;
            }

            if (flb_plugin_proxy_create(entry->val, 0, config) == NULL) {
                return -1;
            }
        }
    }

    mk_rconf_free(fconf);
    return 0;
}

void flb_plugin_proxy_destroy(struct flb_plugin_proxy *proxy)
{
    /* cleanup */
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
