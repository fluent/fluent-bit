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

#include <sys/timex.h>

/* 1 second in */
#define NANOSECONDS     1000000000.0
#define MICROSECONDS    1000000.0

/* See NOTES in adjtimex(2) */
#define PPM16FRAC       (1000000.0 * 65536.0)

static int timex_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;
    struct cmt_counter *c;

    /* node_timex_offset_seconds */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "offset_seconds",
                         "Time offset in between local system and reference clock.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_offset = g;

    /* node_timex_frequency_adjustment_ratio */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "frequency_adjustment_ratio",
                         "Local clock frequency adjustment.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_freq = g;

    /* node_timex_maxerror_seconds */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "maxerror_seconds",
                         "Maximum error in seconds.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_maxerror = g;

    /* node_timex_estimated_error_seconds */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "estimated_error_seconds",
                         "Estimated error in seconds.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_esterror = g;

    /* node_timex_status */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "status",
                         "Value of the status array bits.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_status = g;

    /* node_timex_loop_time_constant */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "loop_time_constant",
                         "Phase-locked loop time constant.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_constant = g;

    /* node_timex_tick_seconds */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "tick_seconds",
                         "Seconds between clock ticks.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_tick = g;

    /* node_timex_pps_frequency_hertz */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "pps_frequency_hertz",
                         "Pulse per second frequency.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_pps_freq = g;

    /* node_timex_pps_jitter_seconds */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "pps_jitter_seconds",
                         "Pulse per second jitter.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_jitter = g;

    /* node_timex_pps_shift_seconds */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "pps_shift_seconds",
                         "Pulse per second interval duration.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_shift = g;

    /* node_timex_pps_stability_hertz */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "pps_stability_hertz",
                         "Pulse per second stability, average of recent frequency changes.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_stabil = g;

    /* node_timex_pps_jitter_total */
    c = cmt_counter_create(ctx->cmt, "node", "timex", "pps_jitter_total",
                         "Pulse per second count of jitter limit exceeded events",
                         0, NULL);
    if (!c) {
        return -1;
    }
    ctx->timex_jitcnt = c;

    /* node_timex_pps_calibration_total */
    c = cmt_counter_create(ctx->cmt, "node", "timex", "pps_calibration_total",
                         "Pulse per second count of calibration intervals.",
                         0, NULL);
    if (!c) {
        return -1;
    }
    ctx->timex_calcnt = c;

    /* node_timex_pps_error_total */
    c = cmt_counter_create(ctx->cmt, "node", "timex", "pps_error_total",
                         "Pulse per second count of calibration errors.",
                         0, NULL);
    if (!c) {
        return -1;
    }
    ctx->timex_errcnt = c;

    /* node_timex_pps_stability_exceeded_total */
    c = cmt_counter_create(ctx->cmt, "node", "timex", "pps_stability_exceeded_total",
                         "Pulse per second count of stability limit exceeded events.",
                         0, NULL);
    if (!c) {
        return -1;
    }
    ctx->timex_stbcnt = c;

    /* node_timex_pps_tai_offset_seconds */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "tai_offset_seconds",
                         "International Atomic Time (TAI) offset.",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_tai = g;

    /* node_timex_sync_status */
    g = cmt_gauge_create(ctx->cmt, "node", "timex", "sync_status",
                         "Is clock synchronized to a reliable server (1 = yes, 0 = no).",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->timex_sync_status = g;

    return 0;
}

static int timex_update(struct flb_ne *ctx, uint64_t ts)
{
    struct timex tx = {};
    int ret = 0;

    double sync_status = 0;
    double divisor = 0;

    ret = adjtimex(&tx);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "error on  adjtimex: error: %d, %s", errno, strerror(errno));
        return -1;
    }

    if (ret == TIME_ERROR) {
        sync_status = 0;
    }
    else {
        sync_status = 1;
    }

    if (tx.status & STA_NANO) {
        divisor = NANOSECONDS;
    }
    else {
        divisor = MICROSECONDS;
    }

    cmt_gauge_set(ctx->timex_sync_status, ts, sync_status, 0, NULL);
    cmt_gauge_set(ctx->timex_offset, ts, tx.offset / divisor, 0, NULL);
    cmt_gauge_set(ctx->timex_freq, ts, 1.0 + tx.freq / PPM16FRAC, 0, NULL);
    cmt_gauge_set(ctx->timex_maxerror, ts, tx.maxerror / MICROSECONDS, 0, NULL);
    cmt_gauge_set(ctx->timex_esterror, ts, tx.esterror / MICROSECONDS, 0, NULL);
    cmt_gauge_set(ctx->timex_status, ts, tx.status, 0, NULL);
    cmt_gauge_set(ctx->timex_constant, ts, tx.constant, 0, NULL);
    cmt_gauge_set(ctx->timex_tick, ts, tx.tick / MICROSECONDS, 0, NULL);
    cmt_gauge_set(ctx->timex_pps_freq, ts, tx.ppsfreq / PPM16FRAC, 0, NULL);
    cmt_gauge_set(ctx->timex_jitter, ts, tx.jitter / divisor, 0, NULL);
    cmt_gauge_set(ctx->timex_shift, ts, tx.shift, 0, NULL);
    cmt_gauge_set(ctx->timex_stabil, ts, tx.stabil / PPM16FRAC, 0, NULL);
    cmt_counter_set(ctx->timex_jitcnt, ts, tx.jitcnt, 0, NULL);
    cmt_counter_set(ctx->timex_calcnt, ts, tx.calcnt, 0, NULL);
    cmt_counter_set(ctx->timex_errcnt, ts, tx.errcnt, 0, NULL);
    cmt_counter_set(ctx->timex_stbcnt, ts, tx.stbcnt, 0, NULL);
    cmt_gauge_set(ctx->timex_tai, ts, tx.tai, 0, NULL);

    return 0;
}

static int ne_timex_init(struct flb_ne *ctx)
{
    return timex_configure(ctx);
}

static int ne_timex_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    uint64_t ts;
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    ts = cfl_time_now();

    return timex_update(ctx, ts);
}

struct flb_ne_collector timex_collector = {
    .name = "timex",
    .cb_init = ne_timex_init,
    .cb_update = ne_timex_update,
    .cb_exit = NULL
};
