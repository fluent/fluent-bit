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

#include <fluent-bit/flb_output_plugin.h>
#include "td_config.h"
#include <stdlib.h>

struct flb_td *td_config_init(struct flb_output_instance *ins)
{
    int ret;
    struct flb_td *ctx;

    
    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_td));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins      = ins;
    ctx->fd       = -1;
    
    ret = flb_output_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);
        return NULL;
    }
    
    if (ctx->api == NULL) {
        flb_plg_error(ins, "error reading API key value");
        flb_free(ctx);
        return NULL;
    }

    if (ctx->db_name == NULL) {
        flb_plg_error(ins, "error reading Database name");
        flb_free(ctx);
        return NULL;
    }

    if (ctx->db_table == NULL) {
        flb_plg_error(ins, "error reading Table name");
        flb_free(ctx);
        return NULL;
    }

    /* Lookup desired region */
    if (ctx->region_str) {
        if (strcasecmp(ctx->region_str, "us") == 0) {
            ctx->region = FLB_TD_REGION_US;
        }
        else if (strcasecmp(ctx->region_str, "jp") == 0) {
            ctx->region = FLB_TD_REGION_JP;
        }
        else {
            flb_plg_error(ctx->ins, "invalid region in configuration");
            flb_free(ctx);
            return NULL;
        }
    }
    else {
        ctx->region = FLB_TD_REGION_US;
    }

    flb_plg_info(ctx->ins, "Treasure Data / database='%s' table='%s'",
                 ctx->db_name, ctx->db_table);

    return ctx;
}
