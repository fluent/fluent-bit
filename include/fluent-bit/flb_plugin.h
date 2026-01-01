/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#ifndef FLB_PLUGIN_H
#define FLB_PLUGIN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>

#define FLB_PLUGIN_INPUT     1
#define FLB_PLUGIN_FILTER    2
#define FLB_PLUGIN_OUTPUT    3
#define FLB_PLUGIN_PROCESSOR 4

/* Informational contexts for discovered dynamic plugins */
struct flb_plugin {
    int type;                     /* plugin type                */
    flb_sds_t path;               /* path for .so file          */
    void *dso_handle;             /* shared object handler      */
    struct mk_list _head;         /* link to struct flb_plugins */
};

struct flb_plugins {
    struct mk_list input;
    struct mk_list processor;
    struct mk_list filter;
    struct mk_list output;
};

struct flb_plugins *flb_plugin_create();
int flb_plugin_load(char *path, struct flb_plugins *ctx,
                    struct flb_config *config);

int flb_plugin_load_router(char *path, struct flb_config *config);

int flb_plugin_load_config_file(const char *file, struct flb_config *config);
int flb_plugin_load_config_format(struct flb_cf *cf, struct flb_config *config);

void flb_plugin_destroy(struct flb_plugins *ctx);

#endif
