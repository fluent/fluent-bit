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

struct flb_systemd_config *flb_systemd_config_create(struct flb_input_instance *ins,
                                                     struct flb_config *config)
{
    int ret;
    const char *tmp;
    char *cursor = NULL;
    struct stat st;
    struct mk_list *head;
    struct flb_kv *kv;
    struct flb_systemd_config *ctx;
    int journal_filter_is_and;
    size_t size;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_systemd_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Create the channel manager */
    ret = pipe(ctx->ch_manager);
    if (ret == -1) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    /* Config: path */
    tmp = flb_input_get_property("path", ins);
    if (tmp) {
        ret = stat(tmp, &st);
        if (ret == -1) {
            flb_errno();
            flb_plg_error(ctx->ins, "given path %s is invalid", tmp);
            flb_free(ctx);
            return NULL;
        }

        if (!S_ISDIR(st.st_mode)) {
            flb_errno();
            flb_plg_error(ctx->ins, "given path is not a directory: %s", tmp);
            flb_free(ctx);
            return NULL;
        }

        ctx->path = flb_strdup(tmp);
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
    /* Database file */
    tmp = flb_input_get_property("db", ins);
    if (tmp) {
        ctx->db = flb_systemd_db_open(tmp, ins, config);
        if (!ctx->db) {
            flb_plg_error(ctx->ins, "could not open/create database '%s'", tmp);
        }
    }
#endif

    /* Max number of fields per record/entry */
    tmp = flb_input_get_property("max_fields", ins);
    if (tmp) {
        ctx->max_fields = atoi(tmp);
    }
    else {
        ctx->max_fields = FLB_SYSTEMD_MAX_FIELDS;
    }

    /* Max number of entries per notification */
    tmp = flb_input_get_property("max_entries", ins);
    if (tmp) {
        ctx->max_entries = atoi(tmp);
    }
    else {
        ctx->max_entries = FLB_SYSTEMD_MAX_ENTRIES;
    }

    tmp = flb_input_get_property("systemd_filter_type", ins);
    if (tmp) {
        if (strcasecmp(tmp, "and") == 0) {
            journal_filter_is_and = FLB_TRUE;
        } else if (strcasecmp(tmp, "or") == 0) {
            journal_filter_is_and = FLB_FALSE;
        } else {
            flb_plg_error(ctx->ins,
                          "systemd_filter_type must be 'and' or 'or'. Got %s",
                          tmp);
            flb_free(ctx);
            return NULL;
        }
    } else {
        journal_filter_is_and = FLB_FALSE;
    }

    /* Load Systemd filters, iterate all properties */
    mk_list_foreach(head, &ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp(kv->key, "systemd_filter") != 0) {
            continue;
        }

        flb_plg_debug(ctx->ins, "add filter: %s (%s)", kv->val,
                      journal_filter_is_and ? "and" : "or");

        /* Apply filter/match */
        sd_journal_add_match(ctx->j, kv->val, 0);
        if (journal_filter_is_and) {
            sd_journal_add_conjunction(ctx->j);
        } else {
            sd_journal_add_disjunction(ctx->j);
        }
    }

    /* Seek to head by default or tail if specified in configuration */
    tmp = flb_input_get_property("read_from_tail", ins);
    if (tmp) {
        ctx->read_from_tail = flb_utils_bool(tmp);
    }
    else {
        ctx->read_from_tail = FLB_FALSE;
    }

    if (ctx->read_from_tail == FLB_TRUE) {
        sd_journal_seek_tail(ctx->j);
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
    else {
        sd_journal_seek_head(ctx->j);
    }

#ifdef FLB_HAVE_SQLDB
    /* Check if we have a cursor in our database */
    if (ctx->db) {
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
    }
#endif

    tmp = flb_input_get_property("strip_underscores", ins);
    if (tmp != NULL && flb_utils_bool(tmp)) {
        ctx->strip_underscores = FLB_TRUE;
    } else {
        ctx->strip_underscores = FLB_FALSE;
    }

    sd_journal_get_data_threshold(ctx->j, &size);
    flb_plg_debug(ctx->ins,
                  "sd_journal library may truncate values "
                  "to sd_journal_get_data_threshold() bytes: %i", size);

    return ctx;
}

int flb_systemd_config_destroy(struct flb_systemd_config *ctx)
{
    /* Close context */
    if (ctx->j) {
        sd_journal_close(ctx->j);
    }

    if (ctx->path) {
        flb_free(ctx->path);
    }

#ifdef FLB_HAVE_SQLDB
    if (ctx->db) {
        flb_systemd_db_close(ctx->db);
    }
#endif

    close(ctx->ch_manager[0]);
    close(ctx->ch_manager[1]);

    flb_free(ctx);
    return 0;
}
