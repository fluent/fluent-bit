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

#include <fluent-bit/flb_input_plugin.h>
#include "pe.h"

struct flb_pe *flb_pe_config_create(struct flb_input_instance *ins,
                                    struct flb_config *config)
{
    int ret;
    struct flb_pe *ctx;
    struct mk_list *head;
    struct flb_slist_entry *entry;

    ctx = flb_calloc(1, sizeof(struct flb_pe));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->process_regex_include_list = NULL;
    ctx->process_regex_exclude_list = NULL;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Check and initialize enabled metrics */
    if (ctx->metrics) {
        mk_list_foreach(head, ctx->metrics) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            if (strncasecmp(entry->str, "cpu", 3) == 0) {
                ctx->enabled_flag |= METRIC_CPU;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else if (strncasecmp(entry->str, "io", 2) == 0) {
                ctx->enabled_flag |= METRIC_IO;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else if (strncasecmp(entry->str, "memory", 6) == 0) {
                ctx->enabled_flag |= METRIC_MEMORY;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else if (strncasecmp(entry->str, "state", 5) == 0) {
                ctx->enabled_flag |= METRIC_STATE;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else if (strncasecmp(entry->str, "context_switches", 16) == 0) {
                ctx->enabled_flag |= METRIC_CTXT;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else if (strncasecmp(entry->str, "fd", 2) == 0) {
                ctx->enabled_flag |= METRIC_FD;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else if (strncasecmp(entry->str, "start_time", 9) == 0) {
                ctx->enabled_flag |= METRIC_START_TIME;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else if (strncasecmp(entry->str, "thread_wchan", 12) == 0) {
                ctx->enabled_flag |= METRIC_THREAD_WCHAN;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else if (strncasecmp(entry->str, "thread", 6) == 0) {
                ctx->enabled_flag |= METRIC_THREAD;
                flb_plg_debug(ctx->ins, "enabled metrics %s", entry->str);
            }
            else {
                flb_plg_warn(ctx->ins, "Unknown metrics: %s", entry->str);
            }
        }
    }

    /* mount points */
    flb_plg_info(ins, "path.procfs = %s", ctx->path_procfs);

    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_plg_error(ins, "could not initialize CMetrics");
        flb_free(ctx);
        return NULL;
    }

    ctx->page_size = sysconf(_SC_PAGESIZE);

    return ctx;
}

void flb_pe_config_destroy(struct flb_pe *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->cmt) {
        cmt_destroy(ctx->cmt);
    }

    flb_free(ctx);
}
