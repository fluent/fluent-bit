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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_kv.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef FLB_HAVE_SQLDB
#include "systemd_db.h"
#endif

#include "systemd_config.h"

static uint64_t realtime_since_n_minutes_ago(int minutes_ago);

struct flb_systemd_config *flb_systemd_config_create(struct flb_input_instance *ins,
                                                     struct flb_config *config)
{
    int ret;
    const char *tmp;
    char *cursor = NULL;
    struct stat st;
    struct mk_list *head;
    struct flb_systemd_config *ctx;
    int journal_filter_is_and;
    size_t size;
    struct flb_config_map_val *mv;


    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_systemd_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
#ifdef FLB_HAVE_SQLDB
    ctx->db_sync = -1;
#endif

    /* Load the config_map */
    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(config);
        return NULL;
    }

    /* Create the channel manager */
    ret = pipe(ctx->ch_manager);
    if (ret == -1) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    /* Config: path */
    if (ctx->path) {
        ret = stat(ctx->path, &st);
        if (ret == -1) {
            flb_errno();
            flb_plg_error(ctx->ins, "given path %s is invalid", ctx->path);
            flb_free(ctx);
            return NULL;
        }

        if (!S_ISDIR(st.st_mode)) {
            flb_errno();
            flb_plg_error(ctx->ins, "given path is not a directory: %s", ctx->path);
            flb_free(ctx);
            return NULL;
        }
    }
    else {
        ctx->path = NULL;
    }

    /* Open the Journal */
    if (ctx->path) {
        ret = sd_journal_open_directory(&ctx->j, ctx->path, 0);
    }
    else {
        ret = sd_journal_open(&ctx->j, SD_JOURNAL_LOCAL_ONLY);
    }
    if (ret != 0) {
        flb_plg_error(ctx->ins, "could not open the Journal");
        flb_free(ctx);
        return NULL;
    }
    ctx->fd = sd_journal_get_fd(ctx->j);

    /* Tag settings */
    tmp = strchr(ins->tag, '*');
    if (tmp) {
        ctx->dynamic_tag = FLB_TRUE;
    }
    else {
        ctx->dynamic_tag = FLB_FALSE;
    }

#ifdef FLB_HAVE_SQLDB
    /* Database options (needs to be set before the context) */
    if (ctx->db_sync_mode) {
        if (strcasecmp(ctx->db_sync_mode, "extra") == 0) {
            ctx->db_sync = 3;
        }
        else if (strcasecmp(ctx->db_sync_mode, "full") == 0) {
            ctx->db_sync = 2;
            }
        else if (strcasecmp(ctx->db_sync_mode, "normal") == 0) {
            ctx->db_sync = 1;
        }
        else if (strcasecmp(ctx->db_sync_mode, "off") == 0) {
            ctx->db_sync = 0;
        }
        else {
            flb_plg_error(ctx->ins, "invalid database 'db.sync' value: %s", ctx->db_sync_mode);
        }
    }

    /* Database file */
    if (ctx->db_path) {
        ctx->db = flb_systemd_db_open(ctx->db_path, ins, ctx, config);
        if (!ctx->db) {
            flb_plg_error(ctx->ins, "could not open/create database '%s'", ctx->db_path);
        }
    }

#endif

    if (ctx->filter_type) {
        if (strcasecmp(ctx->filter_type, "and") == 0) {
            journal_filter_is_and = FLB_TRUE;
        }
        else if (strcasecmp(ctx->filter_type, "or") == 0) {
            journal_filter_is_and = FLB_FALSE;
        }
        else {
            flb_plg_error(ctx->ins,
                          "systemd_filter_type must be 'and' or 'or'. Got %s",
                          ctx->filter_type);
            flb_free(ctx);
            return NULL;
        }
    }
    else {
        journal_filter_is_and = FLB_FALSE;
    }

    /* Load Systemd filters */
    if (ctx->systemd_filters) {
        flb_config_map_foreach(head, mv, ctx->systemd_filters) {
            flb_plg_debug(ctx->ins, "add filter: %s (%s)", mv->val.str,
                journal_filter_is_and ? "and" : "or");
            ret = sd_journal_add_match(ctx->j, mv->val.str, 0);
            if (ret < 0) {
                if (ret == -EINVAL) {
                    flb_plg_error(ctx->ins,
                                  "systemd_filter error: invalid input '%s'",
                                  mv->val.str);
                }
                else {
                    flb_plg_error(ctx->ins,
                                  "systemd_filter error: status=%d input '%s'",
                                  ret, mv->val.str);
                }
                flb_systemd_config_destroy(ctx);
                return NULL;
            }
            if (journal_filter_is_and) {
                ret = sd_journal_add_conjunction(ctx->j);
                if (ret < 0) {
                    flb_plg_error(ctx->ins,
                                  "sd_journal_add_conjunction failed. ret=%d",
                                  ret);
                    flb_systemd_config_destroy(ctx);
                    return NULL;
                }
            }
            else {
                ret = sd_journal_add_disjunction(ctx->j);
                if (ret < 0) {
                    flb_plg_error(ctx->ins,
                                  "sd_journal_add_disjunction failed. ret=%d",
                                  ret);
                    flb_systemd_config_destroy(ctx);
                    return NULL;
                }
            }
        }
    }

    if (ctx->read_from_tail == FLB_TRUE) {
        sd_journal_seek_tail(ctx->j);
        sd_journal_previous(ctx->j);
        /*
        * Skip up to 350 records until the end of journal is found.
        * Workaround for bug https://github.com/systemd/systemd/issues/9934
        * Due to the bug, sd_journal_next() returns 2 last records of each journal file.
        * 4 GB is the default journal limit, so with 25 MB/file we may get
        * up to 4096/25*2 ~= 350 old log messages. See also fluent-bit PR #1565.
        */
        ret = sd_journal_next_skip(ctx->j, 350);
        flb_plg_debug(ctx->ins,
                      "jump to the end of journal and skip %d last entries", ret);
    }
    else if (ctx->read_since_minutes_ago > 0) {
        uint64_t ts = realtime_since_n_minutes_ago(ctx->read_since_minutes_ago);
        if (ts == 0) {
            flb_plg_error(ctx->ins, "failed to fetch wall clock");
        } else {
            sd_journal_seek_realtime_usec(ctx->j, ts);
        }
    }
    else {
        ret = sd_journal_seek_head(ctx->j);
    }

#ifdef FLB_HAVE_SQLDB
    /* Check if we have a cursor in our database */
    if (ctx->db) {
        /* Initialize prepared statement */
        ret = sqlite3_prepare_v2(ctx->db->handler,
                                 SQL_UPDATE_CURSOR,
                                 -1,
                                 &ctx->stmt_cursor,
                                 0);
        if (ret != SQLITE_OK) {
            flb_plg_error(ctx->ins, "error preparing database SQL statement");
            flb_systemd_config_destroy(ctx);
            return NULL;
        }

        /* Get current cursor */
        cursor = flb_systemd_db_get_cursor(ctx);
        if (cursor) {
            ret = sd_journal_seek_cursor(ctx->j, cursor);
            if (ret == 0) {
                flb_plg_info(ctx->ins, "seek_cursor=%.40s... OK", cursor);

                /* Skip the first entry, already processed */
                sd_journal_next_skip(ctx->j, 1);
            }
            else {
                flb_plg_warn(ctx->ins, "seek_cursor failed");
            }
            flb_free(cursor);
        }
        else {
            /* Insert the first row */
            cursor = NULL;
            flb_systemd_db_init_cursor(ctx, cursor);
            if (cursor) {
                flb_free(cursor);
            }
        }
    }
#endif

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(ctx->ins, "could not initialize event encoder");
        flb_systemd_config_destroy(ctx);

        return NULL;
    }


    sd_journal_get_data_threshold(ctx->j, &size);
    flb_plg_debug(ctx->ins,
                  "sd_journal library may truncate values "
                  "to sd_journal_get_data_threshold() bytes: %zu", size);

    return ctx;
}

int flb_systemd_config_destroy(struct flb_systemd_config *ctx)
{
    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);

        ctx->log_encoder = NULL;
    }

    /* Close context */
    if (ctx->j) {
        sd_journal_close(ctx->j);
    }

#ifdef FLB_HAVE_SQLDB
    if (ctx->db) {
        sqlite3_finalize(ctx->stmt_cursor);
        flb_systemd_db_close(ctx->db);
    }
#endif

    close(ctx->ch_manager[0]);
    close(ctx->ch_manager[1]);

    flb_free(ctx);
    return 0;
}

static uint64_t realtime_since_n_minutes_ago(int minutes_ago)
{
    struct timespec tp = {
        .tv_sec  = 0,
        .tv_nsec = 0,
    };
    clockid_t clk_id = CLOCK_REALTIME;
    if (clock_gettime(clk_id, &tp) != 0) {
        return 0;
    }

    // Add minutes ago and return microseconds
    time_t time_sec = tp.tv_sec - (minutes_ago * 60);
    return (uint64_t)time_sec * 1000000 + tp.tv_nsec / 1000;
}
