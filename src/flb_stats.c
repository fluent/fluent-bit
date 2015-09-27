/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

/*
 * Initial draft of the stats interface, it basically aims to collect:
 *
 * - Number of events per second
 * - Number of bytes per second
 *
 * Each input/output plugin must have that counter in place
 */

#include <time.h>

#include <mk_core.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

/* Collect statistics from different components */
int flb_stats_collect(struct flb_config *config)
{
    time_t t;
    struct mk_list *head;
    struct flb_output_plugin *out;
    struct flb_stats *stats;

    t = time(NULL);

    /* Active output plugins */
    mk_list_foreach(head, &config->outputs) {
        out = mk_list_entry(head, struct flb_output_plugin, _head);
        if (out->active == FLB_FALSE) {
            continue;
        }

        stats = &out->stats;
        stats->n++;
        if (stats->n == FLB_STATS_SIZE) {
            stats->n = 0;
        }

        stats->data[stats->n].time    = t;
        stats->data[stats->n].bytes   = 0;
        stats->data[stats->n].events  = 0;

        /* FIXME: Dummy dump, needs to be removed later */
        int i;
        char s[256];
        struct tm t;

        for (i = 0; i < stats->n; i++) {
            localtime_r(&stats->data[i].time, &t);
            strftime(s, sizeof(s) - 1, "%H:%M:%S", &t);
            printf("%i) %s -> bytes=%zd\n",
                   i, s, stats->data[i].bytes);
        }


    }
}

int flb_stats_register(struct mk_event_loop *evl, struct flb_config *config)
{
    int fd;
    struct mk_event *event;

    event = malloc(sizeof(struct mk_event));
    event->mask = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    /* Create a timeout caller every one second */
    fd = mk_event_timeout_create(evl, 1, event);
    if (fd == -1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH_CREATE);
        return -1;
    }

    config->stats_fd = fd;
    return fd;
}
