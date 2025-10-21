/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

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

#include <fluent-bit/flb_unicode.h>

static int multiline_load_parsers(struct flb_tail_config *ctx)
{
    struct mk_list *head;
    struct mk_list *head_p;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *val = NULL;
    struct flb_ml_parser_ins *parser_i;

    if (!ctx->multiline_parsers) {
        return 0;
    }

    /* Create Multiline context using the plugin instance name */
    ctx->ml_ctx = flb_ml_create(ctx->config, ctx->ins->name);
    if (!ctx->ml_ctx) {
        return -1;
    }

    /*
     * Iterate all 'multiline.parser' entries. Every entry is considered
     * a group which can have multiple multiline parser instances.
     */
    flb_config_map_foreach(head, mv, ctx->multiline_parsers) {
        mk_list_foreach(head_p, mv->val.list) {
            val = mk_list_entry(head_p, struct flb_slist_entry, _head);

            /* Create an instance of the defined parser */
            parser_i = flb_ml_parser_instance_create(ctx->ml_ctx, val->str);
            if (!parser_i) {
                return -1;
            }
        }
    }

    return 0;
}

static void adjust_buffer_for_2bytes_alignments(struct flb_tail_config *ctx)
{
    if ((ctx->buf_max_size - 1) % 2) {
        ctx->buf_max_size++;
        flb_plg_info(ctx->ins, "adjusted buf_max_size to %zd", ctx->buf_max_size);
    }
    if ((ctx->buf_chunk_size - 1) % 2) {
        ctx->buf_chunk_size++;
        flb_plg_info(ctx->ins, "adjusted buf_chunk_size to %zd", ctx->buf_chunk_size);
    }
}

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
    ctx->config = config;
    ctx->ins = ins;
    ctx->ignore_older = 0;
    ctx->skip_long_lines = FLB_FALSE;
#ifdef FLB_HAVE_SQLDB
    ctx->db_sync = 1;  /* sqlite sync 'normal' */
#endif
#ifdef FLB_HAVE_UNICODE_ENCODER
    ctx->preferred_input_encoding = FLB_UNICODE_ENCODING_UNSPECIFIED;
#endif
    ctx->generic_input_encoding_type = FLB_GENERIC_UNSPECIFIED; /* Default is unspecified */

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
        flb_tail_config_destroy(ctx);
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
            flb_tail_config_destroy(ctx);
            return NULL;
        }
    }

    /* Config: seconds interval to monitor file after rotation */
    if (ctx->rotate_wait <= 0) {
        flb_plg_error(ctx->ins, "invalid 'rotate_wait' config value");
        flb_free(ctx);
        return NULL;
    }

#ifdef FLB_HAVE_UNICODE_ENCODER
    tmp = flb_input_get_property("unicode.encoding", ins);
    if (tmp) {
        if (strcasecmp(tmp, "auto") == 0) {
            ctx->preferred_input_encoding = FLB_UNICODE_ENCODING_AUTO;
            adjust_buffer_for_2bytes_alignments(ctx);
        }
        else if (strcasecmp(tmp, "utf-16le") == 0 ||
                 strcasecmp(tmp, "utf16-le") == 0) {
            ctx->preferred_input_encoding = FLB_UNICODE_ENCODING_UTF16_LE;
            adjust_buffer_for_2bytes_alignments(ctx);
        }
        else if (strcasecmp(tmp, "utf-16be") == 0 ||
                 strcasecmp(tmp, "utf16-be") == 0) {
            ctx->preferred_input_encoding = FLB_UNICODE_ENCODING_UTF16_BE;
            adjust_buffer_for_2bytes_alignments(ctx);
        }
        else {
            flb_plg_error(ctx->ins, "invalid encoding 'unicode.encoding' value");
            flb_free(ctx);
            return NULL;
        }
    }
#endif

    tmp = flb_input_get_property("generic.encoding", ins);
    if (tmp) {
        ret = flb_unicode_generic_select_encoding_type(tmp);
        if (ret != FLB_GENERIC_UNSPECIFIED) {
            ctx->generic_input_encoding_type = ret;
            ctx->generic_input_encoding_name = tmp;
        }
        else {
            flb_plg_error(ctx->ins, "invalid encoding 'generic.encoding' value %s", tmp);
            flb_free(ctx);
            return NULL;
        }
    }

#ifdef FLB_HAVE_UNICODE_ENCODER
    if (ctx->preferred_input_encoding != FLB_UNICODE_ENCODING_UNSPECIFIED &&
        ctx->generic_input_encoding_type != FLB_GENERIC_UNSPECIFIED) {
        flb_plg_error(ctx->ins,
                      "'unicode.encoding' and 'generic.encoding' cannot be specified at the same time");
        flb_tail_config_destroy(ctx);
        return NULL;
    }
#endif
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

    /* hash table for files lookups */
    ctx->static_hash = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1000, 0);
    if (!ctx->static_hash) {
        flb_plg_error(ctx->ins, "could not create static hash");
        flb_tail_config_destroy(ctx);
        return NULL;
    }

    ctx->event_hash = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1000, 0);
    if (!ctx->event_hash) {
        flb_plg_error(ctx->ins, "could not create event hash");
        flb_tail_config_destroy(ctx);
        return NULL;
    }

    /* hash table for files lookups */
    ctx->ignored_file_sizes = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1000, 0);
    if (ctx->ignored_file_sizes == NULL) {
        flb_plg_error(ctx->ins, "could not create ignored file size hash table");
        flb_tail_config_destroy(ctx);
        return NULL;
    }

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
            flb_tail_config_destroy(ctx);
            return NULL;
        }
    }

    /* Journal mode check */
    tmp = flb_input_get_property("db.journal_mode", ins);
    if (tmp) {
        if (strcasecmp(tmp, "DELETE") != 0 &&
            strcasecmp(tmp, "TRUNCATE") != 0 &&
            strcasecmp(tmp, "PERSIST") != 0 &&
            strcasecmp(tmp, "MEMORY") != 0 &&
            strcasecmp(tmp, "WAL") != 0 &&
            strcasecmp(tmp, "OFF") != 0) {

            flb_plg_error(ctx->ins, "invalid db.journal_mode=%s", tmp);
            flb_tail_config_destroy(ctx);
            return NULL;
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

#ifdef FLB_HAVE_PARSER
    /* Multiline core API */
    if (ctx->multiline_parsers && mk_list_size(ctx->multiline_parsers) > 0) {
        ret = multiline_load_parsers(ctx);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "could not load multiline parsers");
            flb_tail_config_destroy(ctx);
            return NULL;
        }

        /* Enable auto-flush routine */
        ret = flb_ml_auto_flush_init(ctx->ml_ctx);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not start multiline auto-flush");
            flb_tail_config_destroy(ctx);
            return NULL;
        }
        flb_plg_info(ctx->ins, "multiline core started");
    }
#endif

#ifdef FLB_HAVE_METRICS
    ctx->cmt_files_opened = cmt_counter_create(ins->cmt,
                                               "fluentbit", "input",
                                               "files_opened_total",
                                               "Total number of opened files",
                                               1, (char *[]) {"name"});

    ctx->cmt_files_closed = cmt_counter_create(ins->cmt,
                                               "fluentbit", "input",
                                               "files_closed_total",
                                               "Total number of closed files",
                                               1, (char *[]) {"name"});

    ctx->cmt_files_rotated = cmt_counter_create(ins->cmt,
                                                "fluentbit", "input",
                                                "files_rotated_total",
                                                "Total number of rotated files",
                                                1, (char *[]) {"name"});

    ctx->cmt_multiline_truncated = \
            cmt_counter_create(ins->cmt,
                               "fluentbit", "input",
                               "multiline_truncated_total",
                               "Total number of truncated occurences for multilines",
                               1, (char *[]) {"name"});
    ctx->cmt_long_line_truncated = \
            cmt_counter_create(ins->cmt,
                               "fluentbit", "input",
                               "long_line_truncated_total",
                               "Total number of truncated occurences for long lines",
                               1, (char *[]) {"name"});

    /* OLD metrics */
    flb_metrics_add(FLB_TAIL_METRIC_F_OPENED,
                    "files_opened", ctx->ins->metrics);
    flb_metrics_add(FLB_TAIL_METRIC_F_CLOSED,
                    "files_closed", ctx->ins->metrics);
    flb_metrics_add(FLB_TAIL_METRIC_F_ROTATED,
                    "files_rotated", ctx->ins->metrics);
    flb_metrics_add(FLB_TAIL_METRIC_M_TRUNCATED,
                    "multiline_truncated", ctx->ins->metrics);
    flb_metrics_add(FLB_TAIL_METRIC_L_TRUNCATED,
                    "long_line_truncated", ctx->ins->metrics);
#endif

    return ctx;
}

int flb_tail_config_destroy(struct flb_tail_config *config)
{

#ifdef FLB_HAVE_PARSER
    flb_tail_mult_destroy(config);

    if (config->ml_ctx) {
        flb_ml_destroy(config->ml_ctx);
    }
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

    if (config->static_hash) {
        flb_hash_table_destroy(config->static_hash);
    }

    if (config->event_hash) {
        flb_hash_table_destroy(config->event_hash);
    }

    if (config->ignored_file_sizes != NULL) {
        flb_hash_table_destroy(config->ignored_file_sizes);
    }

    flb_free(config);

    return 0;
}
