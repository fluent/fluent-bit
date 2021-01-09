/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include "td_config.h"
#include <stdlib.h>

struct flb_td *td_config_init(struct flb_output_instance *ins)
{
    const char *tmp;
    const char *api;
    const char *db_name;
    const char *db_table;
    struct flb_td *ctx;

    /* Validate TD section keys */
    api = flb_output_get_property("API", ins);
    db_name = flb_output_get_property("Database", ins);
    db_table = flb_output_get_property("Table", ins);

    if (!api) {
        flb_plg_error(ins, "error reading API key value");
        return NULL;
    }

    if (!db_name) {
        flb_plg_error(ins, "error reading Database name");
        return NULL;
    }

    if (!db_table) {
        flb_plg_error(ins, "error reading Table name");
        return NULL;
    }

    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_td));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins      = ins;
    ctx->fd       = -1;
    ctx->api      = api;
    ctx->db_name  = db_name;
    ctx->db_table = db_table;

    /* Lookup desired region */
    tmp = flb_output_get_property("region", ins);
    if (tmp) {
        if (strcasecmp(tmp, "us") == 0) {
            ctx->region = FLB_TD_REGION_US;
        }
        else if (strcasecmp(tmp, "jp") == 0) {
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
