/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2025 The Fluent Bit Authors
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

#ifndef FLB_TDA_H
#define FLB_TDA_H

#include <fluent-bit/ripser/flb_ripser_wrapper.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_map.h>
#include <cfl/cfl_sds.h>

struct tda_window;
struct tda_proc_ctx;

/* time-series samples (aggregated metrics snapshot) */
struct tda_sample {
    uint64_t ts;
    double   values[];
};

struct tda_group {
    cfl_sds_t ns;
    cfl_sds_t subsystem;
    int       index;   /* 0 .. feature_dim-1 */
};

struct tda_window {
    lwrb_t  rb;
    uint8_t *buf;
    size_t  sample_size;  /* sizeof(uint64_t) + feature_dim * sizeof(double) */
    int     feature_dim;
};

/* processor context */
struct tda_proc_ctx {
    struct tda_window *window;
    int window_size;   /* max number of samples in window */
    int min_points;    /* minimum samples before running ripser */

    int feature_dim;               /* # of (ns,subsystem) groups */
    struct flb_hash_table *groups; /* key="ns.subsystem" -> struct tda_group* */
    struct tda_group      **group_list; /* for safe free() */

    /* delay embedding parameters */
    int embed_dim;    /* m: number of delays (1 = no embedding) */
    int embed_delay;  /* tau: delay in samples */
    double threshold;

    /* exposed betti-number gauges (created lazily) */
    struct cmt_gauge *g_betti0;
    struct cmt_gauge *g_betti1;
    struct cmt_gauge *g_betti2;

    /* for counter → rate conversion */
    double   *last_vec;  /* last raw snapshot for each feature_dim */
    uint64_t  last_ts;   /* last snapshot timestamp (nanoseconds)   */

    struct flb_processor_instance *ins;
};

#endif /* FLB_TDA_H */
