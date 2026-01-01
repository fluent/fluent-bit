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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>

/* Setup metrics contexts */
static int ne_loadavg_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    /* loadavg 1m */
    g = cmt_gauge_create(ctx->cmt, "node", "", "load1",
                         "1m load average.",
                         0, NULL);
    ctx->lavg_1 = g;

    /* loadavg 5m */
    g = cmt_gauge_create(ctx->cmt, "node", "", "load5",
                         "5m load average.",
                         0, NULL);
    ctx->lavg_5 = g;

    /* loadavg 15m */
    g = cmt_gauge_create(ctx->cmt, "node", "", "load15",
                         "15m load average.",
                         0, NULL);
    ctx->lavg_15 = g;

    return 0;
}

static int loadavg_update(struct flb_ne *ctx)
{
    int ret;
    int parts;
    double val;
    uint64_t ts;
    struct mk_list *head;
    struct mk_list list;
    struct mk_list split_list;
    struct flb_slist_entry *line;
    struct flb_slist_entry *load;

    mk_list_init(&list);
    mk_list_init(&split_list);

    ret = ne_utils_file_read_lines(ctx->path_procfs, "/loadavg", &list);
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

        parts = ret;
        if (parts == 0) {
            flb_slist_destroy(&split_list);
            continue;
        }

        /* 1m */
        load = flb_slist_entry_get(&split_list, 0);
        ne_utils_str_to_double(load->str, &val);
        cmt_gauge_set(ctx->lavg_1, ts, val, 0, NULL);

        /* 5m */
        load = flb_slist_entry_get(&split_list, 1);
        ne_utils_str_to_double(load->str, &val);
        cmt_gauge_set(ctx->lavg_5, ts, val, 0, NULL);

        /* 15m */
        load = flb_slist_entry_get(&split_list, 2);
        ne_utils_str_to_double(load->str, &val);
        cmt_gauge_set(ctx->lavg_15, ts, val, 0, NULL);

        flb_slist_destroy(&split_list);

        break;
    }

    flb_slist_destroy(&list);
    return 0;
}

static int ne_loadavg_init(struct flb_ne *ctx)
{
    ne_loadavg_configure(ctx);
    return 0;
}

static int ne_loadavg_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    loadavg_update(ctx);
    return 0;
}

struct flb_ne_collector loadavg_collector = {
    .name = "loadavg",
    .cb_init = ne_loadavg_init,
    .cb_update = ne_loadavg_update,
    .cb_exit = NULL
};
