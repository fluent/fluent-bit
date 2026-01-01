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
#include <fluent-bit/flb_hash_table.h>

#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#define VMSTAT_ENTRIES   "^(oom_kill|pgpg|pswp|pg.*fault).*"

static int keep_field(struct flb_ne *ctx, flb_sds_t field)
{
    return flb_regex_match(ctx->vml_regex_fields,
                           (unsigned char *) field, flb_sds_len(field));
}

static int vmstat_configure(struct flb_ne *ctx)
{
    int ret;
    int parts;
    char tmp[256];
    struct mk_list *head;
    struct mk_list list;
    struct mk_list split_list;
    struct flb_slist_entry *line;
    struct flb_slist_entry *key;
    struct cmt_counter *c;

    /* Initialize regex for skipped devices */
    ctx->vml_regex_fields = flb_regex_create(VMSTAT_ENTRIES);
    if (!ctx->vml_regex_fields) {
        flb_plg_error(ctx->ins,
                      "could not initialize regex pattern for matching "
                      "fields: '%s'",
                      VMSTAT_ENTRIES);
        return -1;
    }

    /* Initialize hash table */
    ctx->vml_ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, 0);
    if (!ctx->vml_ht) {
        return -1;
    }

    mk_list_init(&list);
    mk_list_init(&split_list);

    ret = ne_utils_file_read_lines(ctx->path_procfs, "/vmstat", &list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        mk_list_init(&split_list);
        ret = flb_slist_split_string(&split_list, line->str, ' ', 2);
        if (ret == -1) {
            continue;
        }
        parts = ret;

        parts = ret;
        if (parts < 2) {
            flb_slist_destroy(&split_list);
            continue;
        }

        /* retrieve key and value */
        key = flb_slist_entry_get(&split_list, 0);

        /* keep field ? */
        if (!keep_field(ctx, key->str)) {
            flb_slist_destroy(&split_list);
            continue;
        }

        snprintf(tmp, sizeof(tmp) - 1,
                 "/proc/vmstat information field %s.", key->str);
        c = cmt_counter_create(ctx->cmt, "node", "vmstat", key->str,
                               tmp, 0, NULL);
        if (!c) {
            flb_slist_destroy(&split_list);
            flb_slist_destroy(&list);
            return -1;
        }

        ret = flb_hash_table_add(ctx->vml_ht,
                                 key->str, flb_sds_len(key->str), c, 0);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "could not add hash for vmstat metric: %s", key->str);
            flb_slist_destroy(&split_list);
            flb_slist_destroy(&list);
            return -1;
        }

        flb_slist_destroy(&split_list);
    }

    flb_slist_destroy(&list);
    return 0;
}

static int vmstat_update(struct flb_ne *ctx)
{
    int ret;
    int parts;
    double v;
    uint64_t ts;
    size_t out_size = 0;
    struct mk_list *head;
    struct mk_list list;
    struct mk_list split_list;
    struct flb_slist_entry *line;
    struct flb_slist_entry *key;
    struct flb_slist_entry *val;
    struct cmt_untyped *u;

    mk_list_init(&list);
    mk_list_init(&split_list);

    ret = ne_utils_file_read_lines(ctx->path_procfs, "/vmstat", &list);
    if (ret == -1) {
        return -1;
    }

    ts = cfl_time_now();
    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        mk_list_init(&split_list);
        ret = flb_slist_split_string(&split_list, line->str, ' ', 2);
        if (ret == -1) {
            continue;
        }

        parts = ret;
        if (parts == 0) {
            flb_slist_destroy(&split_list);
            continue;
        }

        /* retrieve key and value */
        key = flb_slist_entry_get(&split_list, 0);
        val = flb_slist_entry_get(&split_list, 1);

        /* keep field ? */
        if (!keep_field(ctx, key->str)) {
            flb_slist_destroy(&split_list);
            continue;
        }

        ret = flb_hash_table_get(ctx->vml_ht,
                                 key->str, flb_sds_len(key->str),
                                 (void *) &u, &out_size);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "could not retrieve vmstat hash metric: '%s'", key->str);
            flb_slist_destroy(&split_list);
            continue;
        }

        /* set metric */
        ne_utils_str_to_double(val->str, &v);
        cmt_untyped_set(u, ts, v, 0, NULL);

        flb_slist_destroy(&split_list);
    }

    flb_slist_destroy(&list);
    return 0;
}

static int ne_vmstat_init(struct flb_ne *ctx)
{
    vmstat_configure(ctx);
    return 0;
}

static int ne_vmstat_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    vmstat_update(ctx);
    return 0;
}

static int ne_vmstat_exit(struct flb_ne *ctx)
{
    if (ctx->vml_regex_fields) {
        flb_regex_destroy(ctx->vml_regex_fields);
    }

    if (ctx->vml_ht) {
        flb_hash_table_destroy(ctx->vml_ht);
    }
    return 0;
}

struct flb_ne_collector vmstat_collector = {
    .name = "vmstat",
    .cb_init = ne_vmstat_init,
    .cb_update = ne_vmstat_update,
    .cb_exit = ne_vmstat_exit
};
