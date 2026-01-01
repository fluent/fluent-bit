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

#define _GNU_SOURCE

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

static int filefd_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    /* node_filefd_allocated */
    g = cmt_gauge_create(ctx->cmt, "node", "filefd", "allocated",
                         "File descriptor statistics: allocated.",
                         0, NULL);
    ctx->filefd_allocated = g;

    /* node_filefd_maximum */
    g = cmt_gauge_create(ctx->cmt, "node", "filefd", "maximum",
                         "File descriptor statistics: maximum.",
                         0, NULL);
    ctx->filefd_maximum = g;

    return 0;
}

static int filefd_update(struct flb_ne *ctx)
{
    int ret;
    int parts;
    uint64_t ts;
    double d_val;
    struct mk_list *head;
    struct mk_list list;
    struct mk_list split_list;
    struct flb_slist_entry *line;
    struct flb_slist_entry *alloc;
    struct flb_slist_entry *max;

    mk_list_init(&list);
    ret = ne_utils_file_read_lines(ctx->path_procfs, "/sys/fs/file-nr", &list);
    if (ret == -1) {
        return -1;
    }

    ts = cfl_time_now();

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        mk_list_init(&split_list);
        ret = flb_slist_split_string(&split_list, line->str, '\t', -1);
        if (ret == -1) {
            continue;
        }
        parts = ret;
        if (parts == 0) {
            flb_slist_destroy(&split_list);
            continue;
        }
        else if (parts != 3) {
            flb_plg_warn(ctx->ins, "/sys/fs/file-nr: invalid number of fields");
            flb_slist_destroy(&split_list);
            break;
        }

        /* allocated (0) */
        alloc = flb_slist_entry_get(&split_list, 0);
        ne_utils_str_to_double(alloc->str, &d_val);
        cmt_gauge_set(ctx->filefd_allocated, ts, d_val, 0, NULL);

        /* maximum (2) */
        max = flb_slist_entry_get(&split_list, 2);
        ne_utils_str_to_double(max->str, &d_val);
        cmt_gauge_set(ctx->filefd_maximum, ts, d_val, 0, NULL);

        flb_slist_destroy(&split_list);
        break;
    }
    flb_slist_destroy(&list);

    return 0;
}

static int ne_filefd_init(struct flb_ne *ctx)
{
    filefd_configure(ctx);
    return 0;
}

static int ne_filefd_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    filefd_update(ctx);
    return 0;
}

struct flb_ne_collector filefd_collector = {
    .name = "filefd",
    .cb_init = ne_filefd_init,
    .cb_update = ne_filefd_update,
    .cb_exit = NULL
};
