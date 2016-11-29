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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input.h>

#include <stdlib.h>

#include "tail_fs.h"
#include "tail_db.h"
#include "tail_config.h"
#include "tail_scan.h"

struct flb_tail_config *flb_tail_config_create(struct flb_input_instance *i_ins,
                                               struct flb_config *config)
{
    int ret;
    char *tmp;
    struct flb_tail_config *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_tail_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Create the communication pipe(2) */
    ret = pipe(ctx->ch_manager);
    if (ret == -1) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    /* Read properties */
    ctx->path = flb_input_get_property("path", i_ins);
    if (!ctx->path) {
        flb_error("[in_tail] no input 'path' was given");
        flb_free(ctx);
        return NULL;
    }
    ctx->exclude_path = flb_input_get_property("exclude_path", i_ins);
    ctx->exclude_list = NULL;

    tmp = flb_input_get_property("refresh_interval", i_ins);
    if (!tmp) {
        ctx->refresh_interval = FLB_TAIL_REFRESH;
    }
    else {
        ctx->refresh_interval = atoi(tmp);
        if (ctx->refresh_interval <= 0) {
            flb_error("[in_tail] invalid refresh_interval");
            flb_free(ctx);
            return NULL;
        }
    }

    mk_list_init(&ctx->files_static);
    mk_list_init(&ctx->files_event);

    /* initialize MessagePack buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);
    ctx->db_track = NULL;

    /* Initialize database */
    tmp = flb_input_get_property("db", i_ins);
    if (tmp) {
        ctx->db_track = flb_tail_db_open(tmp, i_ins, config);
        if (!ctx->db_track) {
            flb_error("[in_tail] could not open/create database");
        }
    }

    flb_tail_scan(ctx->path, ctx);
    return ctx;
}

int flb_tail_config_destroy(struct flb_tail_config *config)
{
    /* Close pipe ends */
    close(config->ch_manager[0]);
    close(config->ch_manager[0]);

    flb_free(config);
    return 0;
}
