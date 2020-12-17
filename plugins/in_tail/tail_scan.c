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

#include <fluent-bit/flb_input_plugin.h>
#include "tail.h"
#include "tail_config.h"

/*
 * Include proper scan backend
 */
#ifdef FLB_SYSTEM_WINDOWS
#include "tail_scan_win32.c"
#else
#include "tail_scan_glob.c"
#endif

int flb_tail_scan(struct mk_list *path_list, struct flb_tail_config *ctx)
{
    int ret;
    struct mk_list *head;
    struct flb_slist_entry *pattern;

    mk_list_foreach(head, path_list) {
        pattern = mk_list_entry(head, struct flb_slist_entry, _head);
        ret = tail_scan_path(pattern->str, ctx);
        if (ret == -1) {
            flb_plg_warn(ctx->ins, "error scanning path: %s", pattern->str);
        }
        else {
            flb_plg_debug(ctx->ins, "%i new files found on path '%s'",
                          ret, pattern->str);
        }
    }

    return 0;
}

/*
 * Triggered by refresh_interval, it re-scan the path looking for new files
 * that match the original path pattern.
 */
int flb_tail_scan_callback(struct flb_input_instance *ins,
                           struct flb_config *config, void *context)
{
    int ret;
    struct flb_tail_config *ctx = context;
    (void) config;

    ret = flb_tail_scan(ctx->path_list, ctx);
    if (ret > 0) {
        flb_plg_debug(ins, "%i new files found", ret);
    }

    return ret;
}
