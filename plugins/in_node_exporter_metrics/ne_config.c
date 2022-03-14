/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include "ne.h"

struct flb_ne *flb_ne_config_create(struct flb_input_instance *ins,
                                    struct flb_config *config)
{
    int ret;
    struct flb_ne *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_ne));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* mount points */
    flb_plg_info(ins, "path.procfs = %s", ctx->path_procfs);
    flb_plg_info(ins, "path.sysfs  = %s", ctx->path_sysfs);

    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_plg_error(ins, "could not initialize CMetrics");
        flb_free(ctx);
        return NULL;
    }


    return ctx;
}

void flb_ne_config_destroy(struct flb_ne *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->cmt) {
        cmt_destroy(ctx->cmt);
    }

    flb_free(ctx);
}
