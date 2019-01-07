/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_PLUGIN_PROXY_H
#define FLB_PLUGIN_PROXY_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>

/* Plugin Types */
#define FLB_PROXY_INPUT_PLUGIN     1
#define FLB_PROXY_OUTPUT_PLUGIN    2

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
    int type;                 /* defined by FLB_PROXY_[INPUT|OUTPUT]_PLUGIN  */
    int proxy;                /* proxy type                                  */
    char *name;               /* plugin short name                           */
    char *description;        /* plugin description                          */

    /* Internal */
    struct flb_api *api;      /* API context to export functions             */
    void *instance;           /* input/output instance                       */
    void *dso_handler;        /* dso handler - dlopen(2)                     */
    void *data;               /* opaque data type for specific proxy handler */
    struct mk_list _head;     /* link to parent config->proxies              */
};

void *flb_plugin_proxy_symbol(struct flb_plugin_proxy *proxy,
                              const char *symbol);

int flb_plugin_proxy_init(struct flb_plugin_proxy *proxy,
                          struct flb_output_instance *o_ins,
                          struct flb_config *config);

int flb_plugin_proxy_register(struct flb_plugin_proxy *proxy,
                              struct flb_config *config);

struct flb_plugin_proxy *flb_plugin_proxy_create(const char *dso_path, int type,
                                                 struct flb_config *config);
int flb_plugin_proxy_load_all(struct flb_config *config);
int flb_plugin_proxy_conf_file(char *file, struct flb_config *config);

#endif
