/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_input_plugin.h>

#include <stdlib.h>
#include <fcntl.h>

#include "tail_fs.h"
#include "tail_db.h"
#include "tail_config.h"
#include "tail_scan.h"
#include "tail_sql.h"
#include "tail_dockermode.h"

#ifdef FLB_HAVE_PARSER
#include "tail_multiline.h"
#endif

struct flb_tail_config *flb_tail_config_create(struct flb_input_instance *ins,
                                               struct flb_config *config)
{
    int ret;
    int sec;
    int i;
    long nsec;
    const char *tmp;
    struct flb_tail_config *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_tail_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->ignore_older = 0;
    ctx->skip_long_lines = FLB_FALSE;
#ifdef FLB_HAVE_SQLDB
    ctx->db_sync = 1;  /* sqlite sync 'normal' */
#endif
#ifdef FLB_HAVE_UTF8_ENCODER
    ctx->encoding = NULL;
#endif

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }


    /* Create the channel manager */
    ret = flb_pipe_create(ctx->ch_manager);
    if (ret == -1) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }
    ctx->ch_reads = 0;
    ctx->ch_writes = 0;

    /* Create the pending channel */
    ret = flb_pipe_create(ctx->ch_pending);
    if (ret == -1) {
        flb_errno();
        flb_tail_config_destroy(ctx);
        return NULL;
    }
    /* Make pending channel non-blocking */
    for (i = 0; i <= 1; i++) {
        ret = flb_pipe_set_nonblocking(ctx->ch_pending[i]);
        if (ret == -1) {
            flb_errno();
            flb_tail_config_destroy(ctx);
            return NULL;
        }
    }

    /* Config: path/pattern to read files */
    if (!ctx->path_list || mk_list_size(ctx->path_list) == 0) {
        flb_plg_error(ctx->ins, "no input 'path' was given");
        flb_free(ctx);
        return NULL;
    }

    /* Config: seconds interval before to re-scan the path */
    tmp = flb_input_get_property("refresh_interval", ins);
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
                flb_plg_error(ctx->ins, "invalid 'refresh_interval' config "
                              "value (%s)", tmp);
                flb_free(ctx);
                return NULL;
            }

            if (sec == 0 && nsec <= 1000000) {
                flb_plg_warn(ctx->ins, "very low refresh_interval "
                             "(%i.%lu nanoseconds) might cause high CPU usage",
                             sec, nsec);
            }
        }
        else {
            flb_plg_error(ctx->ins,
                          "invalid 'refresh_interval' config value (%s)",
                      tmp);
            flb_free(ctx);
            return NULL;
        }
    }

    /* Config: seconds interval to monitor file after rotation */
    if (ctx->rotate_wait <= 0) {
        flb_plg_error(ctx->ins, "invalid 'rotate_wait' config value");
        flb_free(ctx);
        return NULL;
    }

#ifdef FLB_HAVE_PARSER
    /* Config: multi-line support */
    if (ctx->multiline == FLB_TRUE) {
        ret = flb_tail_mult_create(ctx, ins, config);
        if (ret == -1) {
            flb_tail_config_destroy(ctx);
            return NULL;
        }
    }
#endif

#ifdef FLB_HAVE_UTF8_ENCODER
    tmp = flb_input_get_property("encoding", ins);
    if (tmp) {
        ctx->encoding = flb_encoding_open(tmp);
        if (!ctx->encoding) {
            flb_plg_error(ctx->ins,"illegal encoding: %s", tmp);
            flb_tail_config_destroy(ctx);
            return NULL;
        }
    }
#endif

    /* Config: Docker mode */
    if(ctx->docker_mode == FLB_TRUE) {
        ret = flb_tail_dmode_create(ctx, ins, config);
        if (ret == -1) {
            flb_tail_config_destroy(ctx);
            return NULL;
        }
    }

    /* Validate buffer limit */
    if (ctx->buf_chunk_size > ctx->buf_max_size) {
        flb_plg_error(ctx->ins, "buffer_max_size must be >= buffer_chunk");
        flb_free(ctx);
        return NULL;
    }

#ifdef FLB_HAVE_REGEX
    /* Parser / Format */
    tmp = flb_input_get_property("parser", ins);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
        if (!ctx->parser) {
            flb_plg_error(ctx->ins, "parser '%s' is not registered", tmp);
        }
    }
#endif

    mk_list_init(&ctx->files_static);
    mk_list_init(&ctx->files_event);
    mk_list_init(&ctx->files_rotated);
#ifdef FLB_HAVE_SQLDB
    ctx->db = NULL;
#endif

#ifdef FLB_HAVE_REGEX
    tmp = flb_input_get_property("tag_regex", ins);
    if (tmp) {
        ctx->tag_regex = flb_regex_create(tmp);
        if (ctx->tag_regex) {
            ctx->dynamic_tag = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "invalid 'tag_regex' config value");
        }
    }
    else {
        ctx->tag_regex = NULL;
    }
#endif

    /* Check if it should use dynamic tags */
    tmp = strchr(ins->tag, '*');
    if (tmp) {
        ctx->dynamic_tag = FLB_TRUE;
    }

#ifdef FLB_HAVE_SQLDB
    /* Database options (needs to be set before the context) */
    tmp = flb_input_get_property("db.sync", ins);
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
            flb_plg_error(ctx->ins, "invalid database 'db.sync' value");
        }
    }

    /* Initialize database */
    tmp = flb_input_get_property("db", ins);
    if (tmp) {
        ctx->db = flb_tail_db_open(tmp, ins, ctx, config);
        if (!ctx->db) {
            flb_plg_error(ctx->ins, "could not open/create database");
        }
    }

    /* Prepare Statement */
    if (ctx->db) {
        /* SQL_GET_FILE */
        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_GET_FILE,
                                 -1,
                                 &ctx->stmt_get_file,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement");
            flb_tail_config_destroy(ctx);
            return NULL;
        }

        /* SQL_INSERT_FILE */
        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_INSERT_FILE,
                                 -1,
                                 &ctx->stmt_insert_file,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement");
            flb_tail_config_destroy(ctx);
            return NULL;
        }

        /* SQL_ROTATE_FILE */
        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_ROTATE_FILE,
                                 -1,
                                 &ctx->stmt_rotate_file,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement");
            flb_tail_config_destroy(ctx);
            return NULL;
        }

        /* SQL_UPDATE_OFFSET */
        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_UPDATE_OFFSET,
                                 -1,
                                 &ctx->stmt_offset,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement");
            flb_tail_config_destroy(ctx);
            return NULL;
        }

        /* SQL_DELETE_FILE */
        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_DELETE_FILE,
                                 -1,
                                 &ctx->stmt_delete_file,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement");
            flb_tail_config_destroy(ctx);
            return NULL;
        }

    }
#endif

#ifdef FLB_HAVE_METRICS
    flb_metrics_add(FLB_TAIL_METRIC_F_OPENED,
                    "files_opened", ctx->ins->metrics);
    flb_metrics_add(FLB_TAIL_METRIC_F_CLOSED,
                    "files_closed", ctx->ins->metrics);
    flb_metrics_add(FLB_TAIL_METRIC_F_ROTATED,
                    "files_rotated", ctx->ins->metrics);
#endif

    return ctx;
}

int flb_tail_config_destroy(struct flb_tail_config *config)
{

#ifdef FLB_HAVE_PARSER
    flb_tail_mult_destroy(config);
#endif

    /* Close pipe ends */
    flb_pipe_close(config->ch_manager[0]);
    flb_pipe_close(config->ch_manager[1]);
    flb_pipe_close(config->ch_pending[0]);
    flb_pipe_close(config->ch_pending[1]);

#ifdef FLB_HAVE_REGEX
    if (config->tag_regex) {
        flb_regex_destroy(config->tag_regex);
    }
#endif

#ifdef FLB_HAVE_SQLDB
    if (config->db != NULL) {
        sqlite3_finalize(config->stmt_get_file);
        sqlite3_finalize(config->stmt_insert_file);
        sqlite3_finalize(config->stmt_delete_file);
        sqlite3_finalize(config->stmt_rotate_file);
        sqlite3_finalize(config->stmt_offset);
        flb_tail_db_close(config->db);
    }
#endif

#ifdef FLB_HAVE_UTF8_ENCODER
    if(config->encoding) {
        flb_encoding_close(config->encoding);
    }
#endif

    flb_free(config);
    return 0;
}
