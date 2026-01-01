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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>

static int meminfo_configure(struct flb_ne *ctx)
{
    int ret;
    int parts;
    int len;
    char *p;
    flb_sds_t tmp;
    char desc[] = "Memory information field ";
    struct cmt_gauge *g;
    struct mk_list *head;
    struct mk_list list;
    struct mk_list split_list;
    struct flb_slist_entry *entry;
    struct flb_slist_entry *line;
    flb_sds_t metric_name;
    flb_sds_t metric_desc;

    /* Initialize hash table */
    ctx->meminfo_ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, 0);
    if (!ctx->meminfo_ht) {
        return -1;
    }

    mk_list_init(&list);
    mk_list_init(&split_list);

    ret = ne_utils_file_read_lines(ctx->path_procfs, "/meminfo", &list);
    if (ret == -1) {
        return -1;
    }
    metric_name = flb_sds_create_size(128);
    if (!metric_name) {
        flb_hash_table_destroy(ctx->meminfo_ht);
        flb_slist_destroy(&list);
        return -1;
    }

    metric_desc = flb_sds_create_size(256);
    if (!metric_desc) {
        flb_hash_table_destroy(ctx->meminfo_ht);
        flb_slist_destroy(&list);
        return -1;
    }

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        mk_list_init(&split_list);
        ret = flb_slist_split_string(&split_list, line->str, ' ', -1);
        if (ret == -1) {
            continue;
        }
        parts = ret;

        /* set metric name */
        entry = mk_list_entry_first(&split_list, struct flb_slist_entry, _head);

        if ((p = strstr(entry->str, "(anon)")) ||
            (p = strstr(entry->str, "(file)"))) {
            *p = '_';
            len = flb_sds_len(entry->str) - 2;
            flb_sds_len_set(entry->str, len);
        }
        else {
            len = flb_sds_len(entry->str) - 1;
            flb_sds_len_set(entry->str, len);
        }
        entry->str[len] = '\0';

        flb_sds_len_set(metric_name, 0);
        flb_sds_cat(metric_name, entry->str, flb_sds_len(entry->str));

        /* Metric description */
        flb_sds_len_set(metric_desc, 0);
        ret = flb_sds_cat_safe(&metric_desc, desc, sizeof(desc) - 1);

        if (ret != 0) {
            flb_slist_destroy(&split_list);
            goto error;
        }

        if (parts == 2) {
            /* No unit */
            tmp = flb_sds_printf(&metric_desc, "%s.", metric_name);

            if (tmp == NULL) {
                flb_slist_destroy(&split_list);
                goto error;
            }

            g = cmt_gauge_create(ctx->cmt, "node", "memory", metric_name,
                                 metric_desc,
                                 0, NULL);
            if (!g) {
                flb_slist_destroy(&split_list);
                goto error;
            }
        }
        else if (parts == 3) {
            /* It has an extra 'kB' string in the line */
            ret = flb_sds_cat_safe(&metric_name, "_bytes", 6);

            if (ret != 0) {
                flb_slist_destroy(&split_list);
                goto error;
            }

            tmp = flb_sds_printf(&metric_desc, "%s.", metric_name);

            if (tmp == NULL) {
                flb_slist_destroy(&split_list);
                goto error;
            }

            g = cmt_gauge_create(ctx->cmt, "node", "memory", metric_name,
                                 metric_desc,
                                 0, NULL);
            if (!g) {
                flb_slist_destroy(&split_list);
                goto error;
            }
        }
        else {
            flb_slist_destroy(&split_list);
            continue;
        }

        flb_slist_destroy(&split_list);

        /*
         * Register the gauge context into the hash table: note that depending
         * of the number of parts in the list, if it contains the extra 'kB'
         * the metric name gets appended the '_bytes' string.
         */
        ret = flb_hash_table_add(ctx->meminfo_ht,
                                 metric_name, flb_sds_len(metric_name), g, 0);
        if (ret == -1) {
            flb_plg_error(ctx->ins,
                          "could not add hash for metric: %s", metric_name);
            goto error;
        }
    }

    flb_sds_destroy(metric_name);
    flb_sds_destroy(metric_desc);
    flb_slist_destroy(&list);
    return 0;

 error:
    flb_sds_destroy(metric_name);
    flb_sds_destroy(metric_desc);
    flb_slist_destroy(&list);
    return -1;
}

static int meminfo_update(struct flb_ne *ctx)
{
    int i = 0;
    int ret;
    int len;
    int parts;
    uint64_t ts;
    double val;
    size_t out_size;
    char *p;
    flb_sds_t tmp;
    flb_sds_t metric_name = NULL;
    struct cmt_gauge *g;
    struct mk_list *head;
    struct mk_list list;
    struct mk_list split_list;
    struct flb_slist_entry *line;
    struct flb_slist_entry *entry;

    mk_list_init(&list);
    ret = ne_utils_file_read_lines(ctx->path_procfs, "/meminfo", &list);
    if (ret == -1) {
        return -1;
    }

    ts = cfl_time_now();

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        mk_list_init(&split_list);
        ret = flb_slist_split_string(&split_list, line->str, ' ', -1);
        if (ret == -1) {
            continue;
        }
        parts = ret;
        if (parts == 0) {
            flb_slist_destroy(&split_list);
            continue;
        }

        /* Metric name */
        entry = mk_list_entry_first(&split_list, struct flb_slist_entry, _head);
        metric_name = entry->str;

        if ((p = strstr(entry->str, "(anon)")) ||
            (p = strstr(entry->str, "(file)"))) {
            *p = '_';
            len = flb_sds_len(metric_name) - 1;
            flb_sds_len_set(metric_name, len);
        }

        /* Metric value */
        entry = mk_list_entry_next(&split_list, struct flb_slist_entry, _head,
                                   &entry->_head);

        ret = ne_utils_str_to_double(entry->str, &val);
        if (ret == -1) {
            i++;
            flb_slist_destroy(&split_list);
        }

        g = NULL;
        if (parts == 2) {
            /* Metric name is the same, no extra bytes */
            ret = flb_hash_table_get(ctx->meminfo_ht,
                                     metric_name, flb_sds_len(metric_name) - 1,
                                     (void *) &g, &out_size);
        }
        else if (parts == 3) {
            /* Compose new metric name */
            tmp = flb_sds_create_size(256);
            flb_sds_cat_safe(&tmp, metric_name, flb_sds_len(metric_name) - 1);
            flb_sds_cat_safe(&tmp, "_bytes", 6);

            /* Get metric context */
            ret = flb_hash_table_get(ctx->meminfo_ht,
                                     tmp, flb_sds_len(tmp),
                                     (void *) &g, &out_size);
            flb_sds_destroy(tmp);

            /* Value is in kB, convert to bytes */
            val *= 1024;
        }

        if (!g) {
            flb_plg_error(ctx->ins,
                          "gauge content for metric '%s' not found",
                          metric_name);
            flb_slist_destroy(&split_list);
            continue;
        }

        /* Update metric */
        cmt_gauge_set(g, ts, val, 0, NULL);
        flb_slist_destroy(&split_list);
    }

    flb_slist_destroy(&list);
    return 0;
}

static int ne_meminfo_init(struct flb_ne *ctx)
{
    meminfo_configure(ctx);
    return 0;
}

static int ne_meminfo_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;
    meminfo_update(ctx);
    return 0;
}

static int ne_meminfo_exit(struct flb_ne *ctx)
{
    if (ctx->meminfo_ht) {
        flb_hash_table_destroy(ctx->meminfo_ht);
    }
    return 0;
}

struct flb_ne_collector meminfo_collector = {
    .name = "meminfo",
    .cb_init = ne_meminfo_init,
    .cb_update = ne_meminfo_update,
    .cb_exit = ne_meminfo_exit
};
