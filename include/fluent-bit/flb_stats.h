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

#ifdef HAVE_STATS

#ifndef FLB_STATS_H
#define FLB_STATS_H

#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>

#define FLB_STATS_SIZE    60        /* Latest 60 entries */

struct flb_stats_table {
    time_t  time;
    ssize_t events;
    ssize_t bytes;
};

struct flb_stats {
    int n;
    struct flb_stats_table data[FLB_STATS_SIZE];
};

/* Simple function to update the stats counters */
static inline void flb_stats_update(ssize_t bytes, ssize_t events,
                                    struct flb_stats *st)
{
    struct flb_stats_table *table;

    table = &st->data[st->n];
    table->bytes  += bytes;
    table->events += events;
}

/*
 * Reset the stats counter, this function is used everytime the stats
 * are collected.
 */
static inline void flb_stats_reset(struct flb_stats *st)
{
    st->n = 0;
}

int flb_stats_collect(struct flb_config *config);
int flb_stats_register(struct mk_event_loop *evl, struct flb_config *config);

#endif /* FLB_STATS_H */
#else

/* A dummy define to avoid some macros conditions into the core */
#define flb_stats_update(a, b, c) do {} while(0)
#define flb_stats_reset(a) do {} while(0)
#define flb_stats_register(a, b) do{} while(0)

#endif /* HAVE_STATS  */
