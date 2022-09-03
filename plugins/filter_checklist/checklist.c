/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_sqldb.h>

#include "checklist.h"
#include <ctype.h>

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
        else if (ctx->mode == CHECK_PARTIAL_MATCH) {
            ret = db_insert(ctx, buf, len);
        }

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
            ctx->mode = CHECK_PARTIAL_MATCH;
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
    else if (ctx->mode == CHECK_PARTIAL_MATCH) {
        ret = db_init(ctx);
        if (ret < 0) {
            return -1;
        }
    }

    /* record accessor pattern / key name */
    ctx->ra_lookup_key = flb_ra_create(ctx->lookup_key, FLB_TRUE);
    if (!ctx->ra_lookup_key) {
        flb_plg_error(ctx->ins, "invalid ra_lookup_key pattern: %s",
                      ctx->ra_lookup_key);
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

    return 0;
}

static int set_record(struct checklist *ctx, msgpack_packer *mp_pck,
                      struct flb_time *tm, msgpack_object *map)
{
    int i;
    int len;
    int skip;
    msgpack_object k;
    msgpack_object v;
    struct mk_list *head;
    struct flb_slist_entry *r_key;
    struct flb_slist_entry *r_val;
    struct flb_mp_map_header mh;
    struct flb_config_map_val *mv;

    /* array: timestamp + map */
    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(tm, mp_pck, 0);

    /* append map header */
    flb_mp_map_header_init(&mh, mp_pck);

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

        /* pack current key/value pair */
        flb_mp_map_header_append(&mh);
        msgpack_pack_object(mp_pck, k);
        msgpack_pack_object(mp_pck, v);
    }

    /* Pack custom records */
    flb_config_map_foreach(head, mv, ctx->records) {
        r_key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        r_val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_mp_map_header_append(&mh);
        len = flb_sds_len(r_key->str);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, r_key->str, len);


        if (strcasecmp(r_val->str, "true") == 0) {
            msgpack_pack_true(mp_pck);
        }
        else if (strcasecmp(r_val->str, "false") == 0) {
            msgpack_pack_false(mp_pck);
        }
        else if (strcasecmp(r_val->str, "null") == 0) {
            msgpack_pack_nil(mp_pck);
        }
        else {
            len = flb_sds_len(r_val->str);
            msgpack_pack_str(mp_pck, len);
            msgpack_pack_str_body(mp_pck, r_val->str, len);
        }
    }

    flb_mp_map_header_end(&mh);
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
    struct flb_time tm;
    struct checklist *ctx = filter_context;
    msgpack_object *map;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_ra_value *rval;
    struct flb_time t0;
    struct flb_time t1;
    struct flb_time t_diff;

    (void) ins;
    (void) i_ins;
    (void) config;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        found = FLB_FALSE;

        flb_time_pop_from_msgpack(&tm, &result, &map);
        rval = flb_ra_get_value_object(ctx->ra_lookup_key, *map);
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
                else if (ctx->mode == CHECK_PARTIAL_MATCH) {
                    found = db_check(ctx, cmp_buf, cmp_size);
                }

                if (cmp_buf && cmp_buf != (char *) rval->o.via.str.ptr) {
                    flb_free(cmp_buf);
                }
            }

            /* print elapsed time */
            if (ctx->print_query_time && found) {
                flb_time_get(&t1);
                flb_time_diff(&t1, &t0, &t_diff);

                tmp_buf = flb_calloc(1, rval->o.via.str.size + 1);
                if (!tmp_buf) {
                    flb_errno();
                }
                memcpy(tmp_buf, rval->o.via.str.ptr, rval->o.via.str.size);
                flb_plg_info(ctx->ins, "query time (sec.ns): %lu.%lu : '%s'",
                             t_diff.tm.tv_sec, t_diff.tm.tv_nsec, tmp_buf);
                flb_free(tmp_buf);
            }

            flb_ra_key_value_destroy(rval);
        }

        if (found) {
            /* add any previous content that not matched */
            if (mp_sbuf.size == 0 && pre > 0) {
                msgpack_sbuffer_write(&mp_sbuf, data, pre);
            }
            set_record(ctx, &mp_pck, &tm, map);
            matches++;
        }
        else {
            if (mp_sbuf.size > 0) {
                /* append current record to new buffer */
                msgpack_sbuffer_write(&mp_sbuf, (char *) data + pre, off - pre);
            }
        }
        pre = off;
    }
    msgpack_unpacked_destroy(&result);

    if (matches > 0) {
        *out_buf = mp_sbuf.data;
        *out_bytes = mp_sbuf.size;
        return FLB_FILTER_MODIFIED;
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    return FLB_FILTER_NOTOUCH;
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

    if (ctx->db) {
        sqlite3_finalize(ctx->stmt_insert);
        sqlite3_finalize(ctx->stmt_check);
        flb_sqldb_close(ctx->db);
    }

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
