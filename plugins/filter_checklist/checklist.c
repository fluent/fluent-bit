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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "checklist.h"
#include <ctype.h>

#ifdef FLB_HAVE_SQLDB
static int db_init(struct checklist *ctx)
{
    int ret;

    /* initialize databse */
    ctx->db = flb_sqldb_open(":memory:", "filter_check", ctx->config);
    if (!ctx->db) {
        flb_plg_error(ctx->ins, "could not create in-memory database");
        return -1;
    }

    /* create table */
    ret = flb_sqldb_query(ctx->db, SQL_CREATE_TABLE, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: could not create table");
        return -1;
    }

    /* create table */
    ret = flb_sqldb_query(ctx->db, SQL_CASE_SENSITIVE, NULL, NULL);
    if (ret != FLB_OK) {
        flb_plg_error(ctx->ins, "db: could not set CASE SENSITIVE");
        return -1;
    }

    /*
     * Prepare SQL statements
     * -----------------------
     */

    /* SQL_INSERT */
    ret = sqlite3_prepare_v2(ctx->db->handler,
                             SQL_INSERT,
                             -1,
                             &ctx->stmt_insert,
                             0);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "error preparing database SQL statement: insert");
        return -1;
    }

    /* SQL_CHECK */
    ret = sqlite3_prepare_v2(ctx->db->handler,
                             SQL_CHECK,
                             -1,
                             &ctx->stmt_check,
                             0);
    if (ret != SQLITE_OK) {
        flb_plg_error(ctx->ins, "error preparing database SQL statement: check");
        return -1;
    }

    return 0;
}

static int db_insert(struct checklist *ctx, char *buf, int len)
{
    int ret;

    /* Bind parameter */
    sqlite3_bind_text(ctx->stmt_insert, 1, buf, len, 0);

    /* Run the insert */
    ret = sqlite3_step(ctx->stmt_insert);
    if (ret != SQLITE_DONE) {
        sqlite3_clear_bindings(ctx->stmt_insert);
        sqlite3_reset(ctx->stmt_insert);
        flb_plg_warn(ctx->ins, "cannot execute insert for value: %s", buf);
        return -1;
    }

    sqlite3_clear_bindings(ctx->stmt_insert);
    sqlite3_reset(ctx->stmt_insert);

    return flb_sqldb_last_id(ctx->db);
}

static int db_check(struct checklist *ctx, char *buf, size_t size)
{
    int ret;
    int match = FLB_FALSE;

    /* Bind parameter */
    sqlite3_bind_text(ctx->stmt_check, 1, buf, size, 0);

    /* Run the check */
    ret = sqlite3_step(ctx->stmt_check);
    if (ret == SQLITE_ROW) {
        match = FLB_TRUE;
    }

    sqlite3_clear_bindings(ctx->stmt_check);
    sqlite3_reset(ctx->stmt_check);

    return match;
}
#endif

static int load_file_patterns(struct checklist *ctx)
{
    int i;
    int ret;
    int len;
    int line = 0;
    int size = LINE_SIZE;
    char buf[LINE_SIZE];
    FILE *f;

    /* open file */
    f = fopen(ctx->file, "r");
    if (!f) {
        flb_errno();
        flb_plg_error(ctx->ins, "could not open file: %s", ctx->file);
        return -1;
    }

    /* read and process rules on lines */
    while (fgets(buf, size - 1, f)) {
        len = strlen(buf);
        if (buf[len - 1] == '\n') {
            buf[--len] = 0;
            if (len && buf[len - 1] == '\r') {
                buf[--len] = 0;
            }
        }
        else if (!feof(f)) {
            flb_plg_error(ctx->ins, "length of content has exceeded limit");
            fclose(f);
            return -1;
        }

        /* skip empty and commented lines */
        if (!buf[0] || buf[0] == '#') {
            line++;
            continue;
        }

        /* convert to lowercase if needed */
        if (ctx->ignore_case) {
            for (i = 0; i < len; i++) {
                buf[i] = tolower(buf[i]);
            }
        }

        /* add the entry as a hash table key, no value reference is needed */
        if (ctx->mode == CHECK_EXACT_MATCH) {
            ret = flb_hash_table_add(ctx->ht, buf, len, "", 0);
        }
#ifdef FLB_HAVE_SQLDB
        else if (ctx->mode == CHECK_PARTIAL_MATCH) {
            ret = db_insert(ctx, buf, len);
        }
#endif

        if (ret >= 0) {
            flb_plg_debug(ctx->ins, "file list: line=%i adds value='%s'", line, buf);
        }
        line++;
    }

    fclose(f);
    return 0;
}

static int init_config(struct checklist *ctx)
{
    int ret;
    char *tmp;
    struct flb_time t0;
    struct flb_time t1;
    struct flb_time t_diff;

    /* check if we have 'records' to add */
    if (mk_list_size(ctx->records) == 0) {
        flb_plg_warn(ctx->ins, "no 'record' options has been specified");
    }

    /* lookup mode */
    ctx->mode = CHECK_EXACT_MATCH;
    tmp = (char *) flb_filter_get_property("mode", ctx->ins);
    if (tmp) {
        if (strcasecmp(tmp, "exact") == 0) {
            ctx->mode = CHECK_EXACT_MATCH;
        }
        else if (strcasecmp(tmp, "partial") == 0) {
#ifdef FLB_HAVE_SQLDB
            ctx->mode = CHECK_PARTIAL_MATCH;
#else
            flb_plg_error(ctx->ins,
                          "'mode=partial' requires FLB_HAVE_SQLDB enabled at build time");
            return -1;
#endif
        }
    }

    if (ctx->mode == CHECK_EXACT_MATCH) {
        /* create hash table */
        ctx->ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                        CHECK_HASH_TABLE_SIZE, -1);
        if (!ctx->ht) {
            flb_plg_error(ctx->ins, "could not create hash table");
            return -1;
        }
    }
#ifdef FLB_HAVE_SQLDB
    else if (ctx->mode == CHECK_PARTIAL_MATCH) {
        ret = db_init(ctx);
        if (ret < 0) {
            return -1;
        }
    }
#endif

    /* record accessor pattern / key name */
    ctx->ra_lookup_key = flb_ra_create(ctx->lookup_key, FLB_TRUE);
    if (!ctx->ra_lookup_key) {
        flb_plg_error(ctx->ins, "invalid lookup_key pattern: %s",
                      ctx->lookup_key);
        return -1;
    }

    /* validate file */
    if (!ctx->file) {
        flb_plg_error(ctx->ins, "option 'file' is not set");
        return -1;
    }


    /* load file content */
    flb_time_get(&t0);
    ret = load_file_patterns(ctx);
    flb_time_get(&t1);

    /* load time */
    flb_time_diff(&t1, &t0, &t_diff);
    flb_plg_info(ctx->ins, "load file elapsed time (sec.ns): %lu.%lu",
                 t_diff.tm.tv_sec, t_diff.tm.tv_nsec);

    return ret;
}

static int cb_checklist_init(struct flb_filter_instance *ins,
                             struct flb_config *config,
                             void *data)
{
    int ret;
    struct checklist *ctx;

    ctx = flb_calloc(1, sizeof(struct checklist));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->config = config;

    /* set context */
    flb_filter_set_context(ins, ctx);

    /* Set config_map properties in our local context */
    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ret = init_config(ctx);
    if (ret == -1) {
        flb_filter_set_context(ins, NULL);
        flb_free(ctx);
        return -1;
    }

    return 0;
}

static int set_record(struct checklist *ctx,
                      struct flb_log_event_encoder *log_encoder,
                      struct flb_log_event *log_event)
{
    int i;
    int len;
    int ret;
    int skip;
    msgpack_object k;
    msgpack_object v;
    msgpack_object *map;
    struct mk_list *head;
    struct flb_slist_entry *r_key;
    struct flb_slist_entry *r_val;
    struct flb_config_map_val *mv;

    ret = flb_log_event_encoder_begin_record(log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_set_timestamp(log_encoder, &log_event->timestamp);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -2;
    }

    ret = flb_log_event_encoder_set_metadata_from_msgpack_object(log_encoder,
            log_event->metadata);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -3;
    }

    map = log_event->body;

    for (i = 0; i < map->via.map.size; i++) {
        k = map->via.map.ptr[i].key;
        v = map->via.map.ptr[i].val;

        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        /* iterate 'records' list, check if this key is a duplicated */
        skip = FLB_FALSE;
        flb_config_map_foreach(head, mv, ctx->records) {
            r_key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
            r_val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

            len = flb_sds_len(r_key->str);
            if (k.via.str.size != len) {
                continue;
            }

            if (strncmp(k.via.str.ptr, r_key->str, len) == 0) {
                skip = FLB_TRUE;
                break;
            }
        }

        /*
         * skip is true if the current key will be overrided by some entry of
         * the 'records' list.
         */
        if (skip) {
            continue;
        }

        ret = flb_log_event_encoder_append_body_values(
                log_encoder,
                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&k),
                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&v));

        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            return -4;
        }
    }

    /* Pack custom records */
    flb_config_map_foreach(head, mv, ctx->records) {
        r_key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        r_val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        ret = flb_log_event_encoder_append_body_string(
                log_encoder, r_key->str, flb_sds_len(r_key->str));

        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            return -5;
        }

        if (strcasecmp(r_val->str, "true") == 0) {
            ret = flb_log_event_encoder_append_body_boolean(
                    log_encoder, FLB_TRUE);
        }
        else if (strcasecmp(r_val->str, "false") == 0) {
            ret = flb_log_event_encoder_append_body_boolean(
                    log_encoder, FLB_FALSE);
        }
        else if (strcasecmp(r_val->str, "null") == 0) {
            ret = flb_log_event_encoder_append_body_null(
                    log_encoder);
        }
        else {
            ret = flb_log_event_encoder_append_body_string(
                    log_encoder, r_val->str, flb_sds_len(r_val->str));
        }

        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            return -3;
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(log_encoder);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -4;
    }

    return 0;
}

static int cb_checklist_filter(const void *data, size_t bytes,
                               const char *tag, int tag_len,
                               void **out_buf, size_t *out_bytes,
                               struct flb_filter_instance *ins,
                               struct flb_input_instance *i_ins,
                               void *filter_context,
                               struct flb_config *config)
{
    int i;
    int id;
    int found;
    int matches = 0;
    size_t pre = 0;
    size_t off = 0;
    size_t cmp_size;
    char *cmp_buf;
    char *tmp_buf;
    size_t tmp_size;
    struct checklist *ctx = filter_context;
    struct flb_ra_value *rval;
    struct flb_time t0;
    struct flb_time t1;
    struct flb_time t_diff;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    (void) ins;
    (void) i_ins;
    (void) config;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ins, "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        off = log_decoder.offset;
        found = FLB_FALSE;

        rval = flb_ra_get_value_object(ctx->ra_lookup_key, *log_event.body);
        if (rval) {
            if (ctx->print_query_time) {
                flb_time_get(&t0);
            }

            cmp_buf = NULL;
            if (rval->type == FLB_RA_STRING) {
                /* convert to lowercase */
                if (ctx->ignore_case) {
                    cmp_buf = flb_calloc(1, rval->o.via.str.size + 1);
                    if (!cmp_buf) {
                        flb_errno();
                        flb_ra_key_value_destroy(rval);
                        continue;
                    }
                    memcpy(cmp_buf, rval->o.via.str.ptr, rval->o.via.str.size);
                    for (i = 0; i < rval->o.via.str.size; i++) {
                        cmp_buf[i] = tolower(cmp_buf[i]);
                    }
                }
                else {
                    cmp_buf = (char *) rval->o.via.str.ptr;
                }
                cmp_size = rval->o.via.str.size;

                if (ctx->mode == CHECK_EXACT_MATCH) {
                    id = flb_hash_table_get(ctx->ht, cmp_buf, cmp_size,
                                            (void *) &tmp_buf, &tmp_size);
                    if (id >= 0) {
                        found = FLB_TRUE;
                    }
                }
#ifdef FLB_HAVE_SQLDB
                else if (ctx->mode == CHECK_PARTIAL_MATCH) {
                    found = db_check(ctx, cmp_buf, cmp_size);
                }
#endif

                if (cmp_buf && cmp_buf != (char *) rval->o.via.str.ptr) {
                    flb_free(cmp_buf);
                }
            }

            /* print elapsed time */
            if (ctx->print_query_time && found) {
                flb_time_get(&t1);
                flb_time_diff(&t1, &t0, &t_diff);

                flb_plg_info(ctx->ins,
                             "query time (sec.ns): %lu.%lu : '%.*s'",
                             t_diff.tm.tv_sec,
                             t_diff.tm.tv_nsec,
                             (int) rval->o.via.str.size,
                             rval->o.via.str.ptr);
            }

            flb_ra_key_value_destroy(rval);
        }

        if (found) {
            /* add any previous content that not matched */
            if (log_encoder.output_length == 0 && pre > 0) {
                ret = flb_log_event_encoder_emit_raw_record(
                        &log_encoder,
                        data,
                        pre);
            }

            ret = set_record(ctx, &log_encoder, &log_event);

            if (ret < -1) {
                flb_log_event_encoder_rollback_record(&log_encoder);
            }

            matches++;
        }
        else {
            if (log_encoder.output_length > 0) {
                /* append current record to new buffer */
                ret = flb_log_event_encoder_emit_raw_record(
                        &log_encoder,
                        &((char *) data)[pre],
                        off - pre);
            }
        }
        pre = off;
    }

    if (log_encoder.output_length > 0 && matches > 0) {
        *out_buf   = log_encoder.output_buffer;
        *out_bytes = log_encoder.output_length;

        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);

        ret = FLB_FILTER_MODIFIED;
    }
    else {
        ret = FLB_FILTER_NOTOUCH;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

static int cb_exit(void *data, struct flb_config *config)
{
    struct checklist *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->ra_lookup_key) {
        flb_ra_destroy(ctx->ra_lookup_key);
    }

    if (ctx->ht) {
        flb_hash_table_destroy(ctx->ht);
    }

#ifdef FLB_HAVE_SQLDB
    if (ctx->db) {
        sqlite3_finalize(ctx->stmt_insert);
        sqlite3_finalize(ctx->stmt_check);
        flb_sqldb_close(ctx->db);
    }
#endif

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "file", NULL,
     0, FLB_TRUE, offsetof(struct checklist, file),
     "Specify the file that contains the patterns to lookup."
    },

    {
     FLB_CONFIG_MAP_STR, "mode", "exact",
     0, FLB_FALSE, 0,
     "Set the check mode: 'exact' or 'partial'."
    },

    {
     FLB_CONFIG_MAP_BOOL, "print_query_time", "false",
     0, FLB_TRUE, offsetof(struct checklist, print_query_time),
     "Print to stdout the elapseed query time for every matched record"
    },

    {
     FLB_CONFIG_MAP_BOOL, "ignore_case", "false",
     0, FLB_TRUE, offsetof(struct checklist, ignore_case),
     "Compare strings by ignoring case."
    },

    {
     FLB_CONFIG_MAP_STR, "lookup_key", "log",
     0, FLB_TRUE, offsetof(struct checklist, lookup_key),
     "Name of the key to lookup."
    },

    {
     FLB_CONFIG_MAP_SLIST_2, "record", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct checklist, records),
     "Name of record key to add and its value, it accept two values,e.g "
     "'record mykey my val'. You can add many 'record' entries as needed."
    },

    /* EOF */
    {0}
};

struct flb_filter_plugin filter_checklist_plugin = {
    .name         = "checklist",
    .description  = "Check records and flag them",
    .cb_init      = cb_checklist_init,
    .cb_filter    = cb_checklist_filter,
    .cb_exit      = cb_exit,
    .config_map   = config_map,
    .flags        = 0
};
