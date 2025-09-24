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

#ifndef FLB_PLUGIN_PROXY_H
#define FLB_PLUGIN_PROXY_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_input_thread.h>

/* Plugin Types */
#define FLB_PROXY_INPUT_PLUGIN     1
#define FLB_PROXY_OUTPUT_PLUGIN    2
#define FLB_PROXY_CUSTOM_PLUGIN    3

/* Proxies available */
#define FLB_PROXY_GOLANG          11

struct flb_plugin_proxy_def {
    /* Fields populated once remote flb_cb_register() is called */
    int type;                 /* defined by FLB_PROXY_[INPUT|OUTPUT]_PLUGIN  */
    int proxy;                /* proxy type                                  */
    int flags;
    char *name;               /* plugin short name                           */
    char *description;        /* plugin description                          */
};

/* Proxy context */
struct flb_plugin_proxy {
    /* Fields populated once remote flb_cb_register() is called */
    struct flb_plugin_proxy_def *def;

    /* Internal */
    struct flb_api *api;      /* API context to export functions             */
    void *instance;           /* input/output instance                       */
    void *dso_handler;        /* dso handler - dlopen(2)                     */
    void *data;               /* opaque data type for specific proxy handler */
    struct mk_list _head;     /* link to parent config->proxies              */
};

/* This is the context for proxy plugins */
struct flb_plugin_proxy_context {
    /* This context is set by the remote init and is passed to remote flush */
    void *remote_context;
    /* A proxy ptr is needed to detect the proxy type/lang (OUTPUT/GOLANG) */
    struct flb_plugin_proxy *proxy;
};

struct flb_plugin_input_proxy_context {
    int coll_fd;
    /* This context is set by the remote init and is passed to remote collect */
    void *remote_context;
    /* A proxy ptr is needed to store the proxy type/lang (OUTPUT/GOLANG) */
    struct flb_plugin_proxy *proxy;
};

void *flb_plugin_proxy_symbol(struct flb_plugin_proxy *proxy,
                              const char *symbol);

int flb_plugin_proxy_register(struct flb_plugin_proxy *proxy,
                              struct flb_config *config);

struct flb_plugin_proxy *flb_plugin_proxy_create(const char *dso_path, int type,
                                                 struct flb_config *config);
int flb_plugin_proxy_load_all(struct flb_config *config);

#endif
