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

#include <fluent-bit/flb_processor_plugin.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_map.h>
#include <fluent-bit/ripser/flb_ripser_wrapper.h>

/* lwrb header */
#include <lwrb/lwrb.h>

#include <math.h>

struct tda_window;
struct tda_proc_ctx;

/* single time-series sample (aggregated metrics snapshot) */
struct tda_sample {
    uint64_t ts;
    double   value;
};

struct tda_window {
    lwrb_t  rb;
    uint8_t *buf;
    size_t  sample_size;
};

/* processor context */
struct tda_proc_ctx {
    struct tda_window *window;
    int window_size;   /* max number of samples in window */
    int min_points;    /* minimum samples before running ripser */

    /* exposed betti-number gauges (created lazily) */
    struct cmt_gauge *g_betti0;
    struct cmt_gauge *g_betti1;
};

struct tda_window *tda_window_create(size_t capacity)
{
    struct tda_window *w;

    w = flb_calloc(1, sizeof(*w));
    if (!w) {
        return NULL;
    }

    w->sample_size = sizeof(struct tda_sample);

    size_t buf_size = capacity * w->sample_size;

    w->buf = flb_malloc(buf_size);
    if (!w->buf) {
        flb_free(w);
        return NULL;
    }

    if (lwrb_init(&w->rb, w->buf, buf_size) != 1) {
        flb_free(w->buf);
        flb_free(w);
        return NULL;
    }

    return w;
}

void tda_window_destroy(struct tda_window *w)
{
    if (!w) {
        return;
    }

    flb_free(w->buf);
    flb_free(w);
}

static int tda_window_push(struct tda_window *w,
                           uint64_t ts, double value)
{
    struct tda_sample s;
    size_t wlen = 0;
    size_t r = 0;
    size_t needed = sizeof(struct tda_sample);

    s.ts    = ts;
    s.value = value;

    while (lwrb_get_free(&w->rb) < needed) {
        uint8_t tmp[sizeof(struct tda_sample)];
        r = lwrb_read(&w->rb, tmp, sizeof(tmp));
        if (r < sizeof(struct tda_sample)) {
            lwrb_reset(&w->rb);
            break;
        }
    }

    wlen = lwrb_write(&w->rb, &s, sizeof(s));
    if (wlen != sizeof(s)) {
        return -1;
    }

    return 0;
}

/* ---- metrics aggregation ---------------------------------------------- */

/* sum all numeric counter/gauge/untyped values in the context */
static double cmt_sum_all_numeric(struct cmt *cmt)
{
    double sum = 0.0;
    struct cfl_list *head;
    struct cfl_list *metric_head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_metric *metric;
    struct cmt_map *map;

    if (!cmt) {
        return 0.0;
    }

    /* counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        map = counter->map;

        if (map->metric_static_set) {
            metric = &map->metric;
            sum += cmt_metric_get_value(metric);
        }

        cfl_list_foreach(metric_head, &map->metrics) {
            metric = cfl_list_entry(metric_head, struct cmt_metric, _head);
            sum += cmt_metric_get_value(metric);
        }
    }

    /* gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        map = gauge->map;

        if (map->metric_static_set) {
            metric = &map->metric;
            sum += cmt_metric_get_value(metric);
        }

        cfl_list_foreach(metric_head, &map->metrics) {
            metric = cfl_list_entry(metric_head, struct cmt_metric, _head);
            sum += cmt_metric_get_value(metric);
        }
    }

    /* untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        map = untyped->map;

        if (map->metric_static_set) {
            metric = &map->metric;
            sum += cmt_metric_get_value(metric);
        }

        cfl_list_foreach(metric_head, &map->metrics) {
            metric = cfl_list_entry(metric_head, struct cmt_metric, _head);
            sum += cmt_metric_get_value(metric);
        }
    }

    return sum;
}

void tda_window_ingest(struct tda_window *w, struct cmt *cmt)
{
    uint64_t ts;
    double v;

    ts = cfl_time_now();
    v = cmt_sum_all_numeric(cmt);
    tda_window_push(w, ts, v);
}

static size_t tda_window_length(struct tda_window *w)
{
    size_t full;

    if (!w) {
        return 0;
    }

    full = lwrb_get_full(&w->rb);
    return full / sizeof(struct tda_sample);
}

/* non-destructive snapshot of the last max_samples samples into out[] */
static size_t tda_window_snapshot(struct tda_window *w,
                                  struct tda_sample *out,
                                  size_t max_samples)
{
    size_t full_bytes;
    size_t sample_bytes;
    size_t total_count;
    size_t copy_count;
    size_t start_index;
    uint8_t *tmp;
    size_t r;

    if (!w || !out || max_samples == 0) {
        return 0;
    }

    full_bytes = lwrb_get_full(&w->rb);
    sample_bytes = sizeof(struct tda_sample);

    total_count = full_bytes / sample_bytes;
    if (total_count == 0) {
        return 0;
    }

    /* only whole samples are interesting */
    full_bytes = total_count * sample_bytes;

    tmp = flb_malloc(full_bytes);
    if (!tmp) {
        flb_errno();
        return 0;
    }

    /* read out all data ... */
    r = lwrb_read(&w->rb, tmp, full_bytes);
    if (r != full_bytes) {
        /* inconsistent state, reset */
        lwrb_reset(&w->rb);
        flb_free(tmp);
        return 0;
    }

    /* ... and immediately write it back to keep the logical window */
    if (lwrb_write(&w->rb, tmp, full_bytes) != full_bytes) {
        /* this should not fail; if it does, reset */
        lwrb_reset(&w->rb);
        flb_free(tmp);
        return 0;
    }

    /* keep only the last max_samples */
    copy_count = total_count;
    if (copy_count > max_samples) {
        copy_count = max_samples;
    }

    start_index = total_count - copy_count;

    memcpy(out,
           tmp + start_index * sample_bytes,
           copy_count * sample_bytes);

    flb_free(tmp);

    return copy_count;
}

static int ensure_betti_gauges(struct tda_proc_ctx *ctx, struct cmt *cmt)
{
    if (!ctx || !cmt) {
        return -1;
    }

    /* β0 */
    ctx->g_betti0 = cmt_gauge_create(cmt,
                                     "fluentbit", "tda",
                                     "betti0",
                                     "Betti_0 over TDA sliding window",
                                     0, NULL);
    if (!ctx->g_betti0) {
        return -1;
    }

    /* β1 */
    ctx->g_betti1 = cmt_gauge_create(cmt,
                                     "fluentbit", "tda",
                                     "betti1",
                                     "Betti_1 over TDA sliding window",
                                     0, NULL);
    if (!ctx->g_betti1) {
        return -1;
    }

    return 0;
}


static void tda_window_run_ripser(struct tda_window *w,
                                  struct tda_proc_ctx *ctx,
                                  struct cmt *cmt)
{
    size_t n;
    size_t mat_size;
    float *dist;
    struct tda_sample *samples;
    flb_ripser_betti betti;
    int ret;
    size_t i;
    size_t j;
    uint64_t ts;

    if (!w || !ctx || !cmt) {
        return;
    }

    n = tda_window_length(w);
    if (n < 2) {
        return;
    }

    if (ensure_betti_gauges(ctx, cmt) != 0) {
        flb_warn("[tda] failed to create betti gauges");
        return;
    }

    samples = flb_malloc(n * sizeof(struct tda_sample));
    if (!samples) {
        flb_errno();
        return;
    }

    n = tda_window_snapshot(w, samples, n);
    if (n < 2) {
        flb_free(samples);
        return;
    }

    mat_size = n * n;
    dist = flb_calloc(mat_size, sizeof(float));
    if (!dist) {
        flb_errno();
        flb_free(samples);
        return;
    }

    /* simple 1-D distance: |v_i - v_j| */
    for (i = 0; i < n; i++) {
        dist[i * n + i] = 0.0f;
        for (j = 0; j < i; j++) {
            float d = (float) fabs(samples[i].value - samples[j].value);
            dist[i * n + j] = d;
            dist[j * n + i] = d;
        }
    }

    /* H_0, H_1; threshold <= 0 means "auto threshold" inside wrapper */
    ret = flb_ripser_compute_betti_from_dense_distance(dist,
                                                       n,
                                                       1 /* max_dim */,
                                                       0.0f /* threshold */,
                                                       &betti);
    if (ret != 0) {
        flb_warn("[tda_metrics] ripser computation failed (ret=%d)", ret);
        flb_free(dist);
        flb_free(samples);
        return;
    }

    ts = cfl_time_now();

    /* betti.betti[0] -> β0, betti.betti[1] -> β1 */
    if (betti.num_dims > 0 && ctx->g_betti0) {
        cmt_gauge_set(ctx->g_betti0, ts,
                      (double) betti.betti[0],
                      0, NULL);
    }

    if (betti.num_dims > 1 && ctx->g_betti1) {
        cmt_gauge_set(ctx->g_betti1, ts,
                      (double) betti.betti[1],
                      0, NULL);
    }

    flb_free(dist);
    flb_free(samples);
}

static int tda_proc_init(struct flb_processor_instance *ins,
                         void *source_plugin_instance,
                         int source_plugin_type,
                         struct flb_config *config)
{
    struct tda_proc_ctx *ctx;

    (void) source_plugin_instance;
    (void) source_plugin_type;
    (void) config;

    ctx = flb_calloc(1, sizeof(*ctx));
    if (!ctx) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }

    ctx->window_size = 60;
    ctx->min_points  = 10;

    ctx->window = tda_window_create(ctx->window_size);
    if (!ctx->window) {
        flb_free(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ins->context = ctx;

    return FLB_PROCESSOR_SUCCESS;
}

static int tda_proc_exit(struct flb_processor_instance *ins, void *data)
{
    struct tda_proc_ctx *ctx;

    (void) ins;

    ctx = (struct tda_proc_ctx *) data;
    if (!ctx) {
        return FLB_PROCESSOR_SUCCESS;
    }

    tda_window_destroy(ctx->window);
    flb_free(ctx);

    return FLB_PROCESSOR_SUCCESS;
}

static int tda_proc_process_metrics(struct flb_processor_instance *ins,
                                    struct cmt *metrics_context,
                                    struct cmt **out_context,
                                    const char *tag,
                                    int tag_len)
{
    struct tda_proc_ctx *ctx;

    (void) tag;
    (void) tag_len;

    ctx = (struct tda_proc_ctx *) ins->context;
    if (!ctx) {
        return FLB_PROCESSOR_FAILURE;
    }

    if (!metrics_context) {
        *out_context = NULL;
        return FLB_PROCESSOR_SUCCESS;
    }

    tda_window_ingest(ctx->window, metrics_context);

    if (tda_window_length(ctx->window) >= ctx->min_points) {
        tda_window_run_ripser(ctx->window, ctx, metrics_context);
    }

    *out_context = metrics_context;

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {0}
};

struct flb_processor_plugin processor_tda_plugin = {
    .name               = "tda_metrics",
    .description        = "TDA (persistent homology) metrics processor",
    .cb_init            = tda_proc_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = tda_proc_process_metrics,
    .cb_process_traces  = NULL,
    .cb_exit            = tda_proc_exit,
    .config_map         = config_map,
    .flags              = 0
};
