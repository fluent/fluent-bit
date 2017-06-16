/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include "tail_multiline.h"

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
    ctx->dynamic_tag = FLB_FALSE;
    ctx->ignore_older = 0;

    /* Create the channel manager */
    ret = pipe(ctx->ch_manager);
    if (ret == -1) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    /* Create the pending channel */
    ret = pipe(ctx->ch_pending);
    if (ret == -1) {
        close(ctx->ch_manager[0]);
        close(ctx->ch_manager[1]);
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    /* Config: path/pattern to read files */
    ctx->path = flb_input_get_property("path", i_ins);
    if (!ctx->path) {
        flb_error("[in_tail] no input 'path' was given");
        flb_free(ctx);
        return NULL;
    }

    /* Config: exclude path/pattern to skip files */
    ctx->exclude_path = flb_input_get_property("exclude_path", i_ins);
    ctx->exclude_list = NULL;

    /* Config: seconds interval before to re-scan the path */
    tmp = flb_input_get_property("refresh_interval", i_ins);
    if (!tmp) {
        ctx->refresh_interval = FLB_TAIL_REFRESH;
    }
    else {
        ctx->refresh_interval = atoi(tmp);
        if (ctx->refresh_interval <= 0) {
            flb_error("[in_tail] invalid 'refresh_interval' config value");
            flb_free(ctx);
            return NULL;
        }
    }

    /* Config: seconds interval to monitor file after rotation */
    tmp = flb_input_get_property("rotate_wait", i_ins);
    if (!tmp) {
        ctx->rotate_wait = FLB_TAIL_ROTATE_WAIT;
    }
    else {
        ctx->rotate_wait = atoi(tmp);
        if (ctx->rotate_wait <= 0) {
            flb_error("[in_tail] invalid 'rotate_wait' config value");
            flb_free(ctx);
            return NULL;
        }
    }

    /* Config: multi-line support */
    tmp = flb_input_get_property("multiline", i_ins);
    if (tmp) {
        ret = flb_utils_bool(tmp);
        if (ret == FLB_TRUE) {
            ctx->multiline = FLB_TRUE;
            ret = flb_tail_mult_create(ctx, i_ins, config);
            if (ret == -1) {
                flb_free(ctx);
                return NULL;
            }
        }
    }

    /* Config: determine whether appending or not */
    ctx->path_key = flb_input_get_property("path_key", i_ins);
    if (ctx->path_key != NULL) {
        ctx->path_key_len = strlen(ctx->path_key);
    }
    else {
        ctx->path_key_len = 0;
    }

    tmp = flb_input_get_property("ignore_older", i_ins);
    if (tmp) {
        ctx->ignore_older = flb_utils_time_to_seconds(tmp);
    }
    else {
        ctx->ignore_older = 0;
    }

#ifdef FLB_HAVE_REGEX
    /* Parser / Format */
    tmp = flb_input_get_property("parser", i_ins);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
        if (!ctx->parser) {
            flb_error("[in_tail] parser '%s' is not registered", tmp);
        }
    }
#endif

    mk_list_init(&ctx->files_static);
    mk_list_init(&ctx->files_event);
    mk_list_init(&ctx->files_rotated);
    ctx->db = NULL;

    /* Check if it should use dynamic tags */
    tmp = strchr(i_ins->tag, '*');
    if (tmp) {
        ctx->dynamic_tag = FLB_TRUE;
    }
    i_ins->flags |= FLB_INPUT_DYN_TAG;

    /* Initialize database */
    tmp = flb_input_get_property("db", i_ins);
    if (tmp) {
        ctx->db = flb_tail_db_open(tmp, i_ins, config);
        if (!ctx->db) {
            flb_error("[in_tail] could not open/create database");
        }
    }

    return ctx;
}

int flb_tail_config_destroy(struct flb_tail_config *config)
{
    flb_tail_mult_destroy(config);

    /* Close pipe ends */
    close(config->ch_manager[0]);
    close(config->ch_manager[1]);
    close(config->ch_pending[0]);
    close(config->ch_pending[1]);

    if (config->db != NULL) {
        flb_tail_db_close(config->db);
    }

    flb_free(config);
    return 0;
}
