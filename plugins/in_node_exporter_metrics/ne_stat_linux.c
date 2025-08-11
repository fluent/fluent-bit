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

#define _GNU_SOURCE

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

static int stat_configure(struct flb_ne *ctx)
{
    struct cmt_counter *c;
    struct cmt_gauge *g;

    /* node_intr_total */
    c = cmt_counter_create(ctx->cmt, "node", "", "intr_total",
                           "Total number of interrupts serviced.",
                           0, NULL);
    ctx->st_intr = c;

    /* node_context_switches_total */
    c = cmt_counter_create(ctx->cmt, "node", "", "context_switches_total",
                           "Total number of context switches.",
                           0, NULL);
    ctx->st_context_switches = c;

    /* node_forks_total */
    c = cmt_counter_create(ctx->cmt, "node", "", "forks_total",
                           "Total number of forks.",
                           0, NULL);
    ctx->st_forks = c;

    /* node_boot_time_seconds */
    g = cmt_gauge_create(ctx->cmt, "node", "", "boot_time_seconds",
                         "Node boot time, in unixtime.",
                         0, NULL);
    ctx->st_boot_time = g;

    /* node_procs_running */
    g = cmt_gauge_create(ctx->cmt, "node", "", "procs_running",
                         "Number of processes in runnable state.",
                         0, NULL);
    ctx->st_procs_running = g;

    /* node_procs_blocked */
    g = cmt_gauge_create(ctx->cmt, "node", "", "procs_blocked",
                         "Number of processes blocked waiting for I/O to complete.",
                         0, NULL);
    ctx->st_procs_blocked = g;

    return 0;
}

static int stat_update(struct flb_ne *ctx)
{
    int ret;
    int parts;
    uint64_t ts;
    double d_val;
    struct mk_list *head;
    struct mk_list list;
    struct mk_list split_list;
    struct flb_slist_entry *line;
    struct flb_slist_entry *entry;
    struct flb_slist_entry *s_val;

    mk_list_init(&list);
    ret = ne_utils_file_read_lines(ctx->path_procfs, "/stat", &list);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed to read %s/stat", ctx->path_procfs);
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

        /* metric name and value */
        entry = flb_slist_entry_get(&split_list, 0);
        s_val = flb_slist_entry_get(&split_list, 1);

        if (strcmp(entry->str, "intr") == 0) {
            ne_utils_str_to_double(s_val->str, &d_val);
            cmt_counter_set(ctx->st_intr, ts, d_val, 0, NULL);
        }
        else if (strcmp(entry->str, "ctxt") == 0) {
            ne_utils_str_to_double(s_val->str, &d_val);
            cmt_counter_set(ctx->st_context_switches, ts, d_val, 0, NULL);
        }
        else if (strcmp(entry->str, "btime") == 0) {
            ne_utils_str_to_double(s_val->str, &d_val);
            cmt_gauge_set(ctx->st_boot_time, ts, d_val, 0, NULL);
        }
        else if (strcmp(entry->str, "processes") == 0) {
            ne_utils_str_to_double(s_val->str, &d_val);
            cmt_counter_set(ctx->st_forks, ts, d_val, 0, NULL);
        }
        else if (strcmp(entry->str, "procs_running") == 0) {
            ne_utils_str_to_double(s_val->str, &d_val);
            cmt_gauge_set(ctx->st_procs_running, ts, d_val, 0, NULL);
        }
        else if (strcmp(entry->str, "procs_blocked") == 0) {
            ne_utils_str_to_double(s_val->str, &d_val);
            cmt_gauge_set(ctx->st_procs_blocked, ts, d_val, 0, NULL);
        }
        flb_slist_destroy(&split_list);
    }
    flb_slist_destroy(&list);

    return 0;
}

static int ne_stat_init(struct flb_ne *ctx)
{
    stat_configure(ctx);
    return 0;
}

static int ne_stat_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    stat_update(ctx);
    return 0;
}

struct flb_ne_collector stat_collector = {
    .name = "stat",
    .cb_init = ne_stat_init,
    .cb_update = ne_stat_update,
    .cb_exit = NULL
};
