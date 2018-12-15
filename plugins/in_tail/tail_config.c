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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input.h>

#include <stdlib.h>
#include <fcntl.h>

#include "tail_fs.h"
#include "tail_db.h"
#include "tail_config.h"
#include "tail_scan.h"
#include "tail_dockermode.h"
#include "tail_multiline.h"

struct flb_tail_config *flb_tail_config_create(struct flb_input_instance *i_ins,
                                               struct flb_config *config)
{
    int ret;
    int sec;
    int i;
    long nsec;
    ssize_t bytes;
    char *tmp;
    struct flb_tail_config *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_tail_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->i_ins = i_ins;
    ctx->ignore_older = 0;
    ctx->skip_long_lines = FLB_FALSE;
    ctx->db_sync = -1;

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
        flb_errno();
        flb_tail_config_destroy(ctx);
        return NULL;
    }
    /* Make pending channel non-blocking */
    for (i = 0; i <= 1; i++) {
        ret = fcntl(ctx->ch_pending[i], F_SETFL, fcntl(ctx->ch_pending[i], F_GETFL) | O_NONBLOCK);
        if (ret == -1) {
            flb_errno();
            flb_tail_config_destroy(ctx);
            return NULL;
        }
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

    /* Config: key for unstructured log */
    tmp = flb_input_get_property("key", i_ins);
    if (tmp) {
        ctx->key = flb_strdup(tmp);
        ctx->key_len = strlen(tmp);
    }
    else {
        ctx->key = flb_strdup("log");
        ctx->key_len = 3;
    }

    /* Config: seconds interval before to re-scan the path */
    tmp = flb_input_get_property("refresh_interval", i_ins);
    if (!tmp) {
        ctx->refresh_interval_sec = FLB_TAIL_REFRESH;
        ctx->refresh_interval_nsec = 0;
    }
    else {
        ret = flb_utils_time_split(tmp, &sec, &nsec);
        if (ret == 0) {
            ctx->refresh_interval_sec = sec;
            ctx->refresh_interval_nsec = nsec;

            if (sec == 0 && nsec == 0) {
                flb_error("[in_tail] invalid 'refresh_interval' config value (%s)",
                          tmp);
                flb_free(ctx);
                return NULL;
            }

            if (sec == 0 && nsec <= 1000000) {
                flb_warn("[in_tail] very low refresh_interval (%i.%lu nanoseconds) "
                         "might cause high CPU usage", sec, nsec);
            }
        }
        else {
            flb_error("[in_tail] invalid 'refresh_interval' config value (%s)",
                      tmp);
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
                flb_tail_config_destroy(ctx);
                return NULL;
            }
        }
    }

    /* Config: Docker mode */
    tmp = flb_input_get_property("docker_mode", i_ins);
    if (tmp) {
        ret = flb_utils_bool(tmp);
        if (ret == FLB_TRUE) {
            ctx->docker_mode = FLB_TRUE;
            ret = flb_tail_dmode_create(ctx, i_ins, config);
            if (ret == -1) {
                flb_tail_config_destroy(ctx);
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

    /* Config: buffer chunk size */
    tmp = flb_input_get_property("buffer_chunk_size", i_ins);
    if (tmp) {
        bytes = flb_utils_size_to_bytes(tmp);
        if (bytes > 0) {
            ctx->buf_chunk_size = (size_t) bytes;
        }
        else {
            ctx->buf_chunk_size = FLB_TAIL_CHUNK;
        }
    }
    else {
        ctx->buf_chunk_size = FLB_TAIL_CHUNK;
    }

    /* Config: buffer maximum size */
    tmp = flb_input_get_property("buffer_max_size", i_ins);
    if (tmp) {
        bytes = flb_utils_size_to_bytes(tmp);
        if (bytes > 0) {
            ctx->buf_max_size = (size_t) bytes;
        }
        else {
            ctx->buf_max_size = FLB_TAIL_CHUNK;
        }
    }
    else {
        ctx->buf_max_size = FLB_TAIL_CHUNK;
    }

    /* Config: skip long lines */
    tmp = flb_input_get_property("skip_long_lines", i_ins);
    if (tmp) {
        ctx->skip_long_lines = flb_utils_bool(tmp);
    }

    /* Config: Exit on EOF (for testing) */
    tmp = flb_input_get_property("exit_on_eof", i_ins);
    if (tmp) {
        ctx->exit_on_eof = flb_utils_bool(tmp);
    }

    /* Validate buffer limit */
    if (ctx->buf_chunk_size > ctx->buf_max_size) {
        flb_error("[in_tail] buffer_max_size must be >= buffer_chunk");
        flb_free(ctx);
        return NULL;
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

#ifdef FLB_HAVE_REGEX
    tmp = flb_input_get_property("tag_regex", i_ins);
    if (tmp) {
        ctx->tag_regex = flb_regex_create((unsigned char *) tmp);
        if (ctx->tag_regex) {
            ctx->dynamic_tag = FLB_TRUE;
        }
        else {
            flb_error("[in_tail] invalid 'tag_regex' config value");
        }
    }
    else {
        ctx->tag_regex = NULL;
    }
#endif

    /* Check if it should use dynamic tags */
    tmp = strchr(i_ins->tag, '*');
    if (tmp) {
        ctx->dynamic_tag = FLB_TRUE;
    }

    /* Database options (needs to be set before the context) */
    tmp = flb_input_get_property("db.sync", i_ins);
    if (tmp) {
        if (strcasecmp(tmp, "extra") == 0) {
            ctx->db_sync = 3;
        }
        else if (strcasecmp(tmp, "full") == 0) {
            ctx->db_sync = 2;
            }
        else if (strcasecmp(tmp, "normal") == 0) {
            ctx->db_sync = 1;
        }
        else if (strcasecmp(tmp, "off") == 0) {
            ctx->db_sync = 0;
        }
        else {
            flb_error("[in_tail] invalid database 'db.sync' value");
        }
    }

    /* Initialize database */
    tmp = flb_input_get_property("db", i_ins);
    if (tmp) {
        ctx->db = flb_tail_db_open(tmp, i_ins, ctx, config);
        if (!ctx->db) {
            flb_error("[in_tail] could not open/create database");
        }
    }

#ifdef FLB_HAVE_METRICS
    flb_metrics_add(FLB_TAIL_METRIC_F_OPENED,
                    "files_opened", ctx->i_ins->metrics);
    flb_metrics_add(FLB_TAIL_METRIC_F_CLOSED,
                    "files_closed", ctx->i_ins->metrics);
    flb_metrics_add(FLB_TAIL_METRIC_F_ROTATED,
                    "files_rotated", ctx->i_ins->metrics);
#endif

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

#ifdef FLB_HAVE_REGEX
    if (config->tag_regex) {
        flb_regex_destroy(config->tag_regex);
    }
#endif

    if (config->db != NULL) {
        flb_tail_db_close(config->db);
    }

    if (config->key != NULL) {
        flb_free(config->key);
    }
    flb_free(config);
    return 0;
}
