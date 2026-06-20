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

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_mem.h>

#include "sql.h"
#include "parser/sql_parser.h"

struct sql_ctx *sql_config_create(struct flb_processor_instance *ins,
                                  struct flb_config *config)
{
    int ret;
    struct sql_ctx *ctx;

    ctx = flb_calloc(1, sizeof(struct sql_ctx));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Initialize the config map */
    ret = flb_processor_instance_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    if (!ctx->query_str) {
        flb_plg_error(ctx->ins, "no SQL query provided");
        flb_free(ctx);
        return NULL;
    }

    /* create query context */
    ctx->query = sql_parser_query_create(ctx->query_str);
    if (!ctx->query) {
        flb_plg_error(ctx->ins, "failed to parse SQL query: %s", ctx->query_str);
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

void sql_config_destroy(struct sql_ctx *ctx)
{
    if (ctx->query) {
        sql_parser_query_destroy(ctx->query);
    }

    flb_free(ctx);
}

