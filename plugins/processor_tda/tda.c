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
#include <fluent-bit/flb_hash_table.h>

/* lwrb header */
#include <lwrb/lwrb.h>

#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "tda.h"

/* Choose a distance threshold from a dense (n x n) distance matrix.
 * We collect all off-diagonal distances (i > j), sort them, and
 * return the given quantile (e.g. q=0.5 → median).
 *
 * If anything goes wrong, we return 0.0f and let the wrapper fall
 * back to "automatic" (enclosing radius) mode.
 */
static int cmp_float_asc(const void *a, const void *b)
{
    const float fa = *(const float *) a;
    const float fb = *(const float *) b;

    if (fa < fb) {
        return -1;
    }
    else if (fa > fb) {
        return 1;
    }
    else {
        return 0;
    }
}

static float tda_choose_threshold_from_dist(struct tda_proc_ctx *ctx,
                                            const float *dist,
                                            size_t n,
                                            double quantile)
{
    size_t m;
    float *vals;
    size_t idx;
    size_t i;
    size_t j;
    size_t k = 0;
    float thr = 0.0f;
    double pos;
    double q;

    if (!dist || n < 2) {
        return 0.0f;
    }

    /* if user specified threshold as quantile (0 < q < 1),
     * override the default quantile argument.
     */
    if (ctx && ctx->threshold > 0.0 && ctx->threshold < 1.0) {
        q = ctx->threshold;
    }
    else {
        q = quantile;
    }

    if (q <= 0.0) {
        q = 0.0;
    }
    else if (q >= 1.0) {
        q = 1.0;
    }

    /* number of unique off-diagonal distances */
    m = n * (n - 1) / 2;
    if (m == 0) {
        return 0.0f;
    }

    vals = (float *) flb_malloc(sizeof(float) * m);
    if (!vals) {
        flb_errno();
        return 0.0f;
    }

    /* collect i > j entries */
    for (i = 0; i < n; i++) {
        for (j = 0; j < i; j++) {
            vals[k++] = dist[i * n + j];
        }
    }

    if (k == 0) {
        flb_free(vals);
        return 0.0f;
    }

    qsort(vals, k, sizeof(float), cmp_float_asc);

    /* pick quantile index (e.g. 0.5 → median) */
    if (k == 1) {
        idx = 0;
    }
    else {
        pos = q * (double) (k - 1);
        if (pos < 0.0) {
            pos = 0.0;
        }
        if (pos > (double) (k - 1)) {
            pos = (double) (k - 1);
        }
        idx = (size_t) pos;
    }

    thr = vals[idx];

    flb_debug("[tda] chosen distance threshold=%.6f (quantile=%.2f, m=%zu)",
              thr, q, k);

    flb_free(vals);

    return thr;
}

struct tda_window *tda_window_create(size_t capacity, int feature_dim)
{
    struct tda_window *w;
    size_t sample_size;
    size_t buf_size;

    w = flb_calloc(1, sizeof(*w));
    if (!w) {
        return NULL;
    }

    w->feature_dim = feature_dim;
    /* struct tda_sample { uint64_t ts; double values[]; } */
    sample_size = sizeof(uint64_t) + (size_t) feature_dim * sizeof(double);
    w->sample_size = sample_size;

    buf_size = capacity * sample_size;

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

/* ---------------------------------------------------------------------- */
/* small helpers                                                          */
/* ---------------------------------------------------------------------- */

static inline int tda_append_group_to_list(struct tda_group ***plist,
                                           int *plist_cap,
                                           int *pnext_index,
                                           struct tda_group *g)
{
    int next_index;
    int list_cap;
    struct tda_group **list;
    int new_cap;

    if (!plist || !plist_cap || !pnext_index || !g) {
        return -1;
    }

    list       = *plist;
    list_cap   = *plist_cap;
    next_index = *pnext_index;

    if (next_index >= list_cap) {
        new_cap = (list_cap == 0) ? 16 : list_cap * 2;

        list = flb_realloc(list,
                           sizeof(struct tda_group *) * (size_t) new_cap);
        if (!list) {
            flb_errno();
            return -1;
        }

        *plist     = list;
        *plist_cap = new_cap;
    }

    list       = *plist;
    next_index = *pnext_index;

    list[next_index] = g;
    *pnext_index     = next_index + 1;

    return 0;
}

static inline int tda_register_map_group(struct flb_hash_table *ht,
                                         struct tda_group ***plist,
                                         int *plist_cap,
                                         int *pnext_index,
                                         struct cmt_map *map)
{
    const char *ns;
    const char *sub;
    char key[256];
    int  len;
    void *out;
    struct tda_group *g;
    int idx;

    if (!ht || !plist || !plist_cap || !pnext_index || !map || !map->opts) {
        return -1;
    }

    ns  = map->opts->ns        ? map->opts->ns        : "";
    sub = map->opts->subsystem ? map->opts->subsystem : "";

    len = snprintf(key, sizeof(key), "%s.%s", ns, sub);
    if (len < 0 || (size_t) len >= sizeof(key)) {
        return 0;
    }

    out = flb_hash_table_get_ptr(ht, key, len);
    if (out) {
        return 0;
    }

    g = flb_calloc(1, sizeof(*g));
    if (!g) {
        flb_errno();
        return -1;
    }

    g->ns        = cfl_sds_create(ns);
    g->subsystem = cfl_sds_create(sub);

    if (!g->ns || !g->subsystem) {
        if (g->ns) {
            cfl_sds_destroy(g->ns);
        }
        if (g->subsystem) {
            cfl_sds_destroy(g->subsystem);
        }
        flb_free(g);
        flb_errno();
        return -1;
    }

    g->index = *pnext_index;
    if (tda_append_group_to_list(plist, plist_cap, pnext_index, g) != 0) {
        cfl_sds_destroy(g->ns);
        cfl_sds_destroy(g->subsystem);
        flb_free(g);
        return -1;
    }

    if (flb_hash_table_add(ht, key, len, g, 0) < 0) {
        idx = g->index;

        if (*pnext_index > 0 && *pnext_index - 1 == idx) {
            (*pnext_index)--;
        }

        cfl_sds_destroy(g->ns);
        cfl_sds_destroy(g->subsystem);
        flb_free(g);
        flb_errno();
        return -1;
    }

    return 0;
}

static inline void tda_accumulate_map_metrics(struct tda_proc_ctx *ctx,
                                              struct cmt_map *map,
                                              double *out_vec)
{
    const char *ns;
    const char *sub;
    char key[256];
    int  len;
    void *out;
    struct tda_group *g;
    int idx;
    struct cfl_list *metric_head;
    struct cmt_metric *metric;

    if (!ctx || !ctx->groups || !map || !map->opts || !out_vec) {
        return;
    }

    ns  = map->opts->ns        ? map->opts->ns        : "";
    sub = map->opts->subsystem ? map->opts->subsystem : "";

    len = snprintf(key, sizeof(key), "%s.%s", ns, sub);
    if (len < 0 || (size_t) len >= sizeof(key)) {
        return;
    }

    out = flb_hash_table_get_ptr(ctx->groups, key, len);
    if (!out) {
        return;
    }

    g = (struct tda_group *) out;
    idx = g->index;

    if (idx < 0 || idx >= ctx->feature_dim) {
        return;
    }

    if (map->metric_static_set) {
        metric = &map->metric;
        out_vec[idx] += cmt_metric_get_value(metric);
    }

    cfl_list_foreach(metric_head, &map->metrics) {
        metric = cfl_list_entry(metric_head, struct cmt_metric, _head);
        out_vec[idx] += cmt_metric_get_value(metric);
    }
}

/* ---------------------------------------------------------------------- */
/* group building: allocate dimensions each of (ns,subsystem)             */
/* ---------------------------------------------------------------------- */

static int tda_build_groups(struct tda_proc_ctx *ctx, struct cmt *cmt)
{
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_map *map;
    struct flb_hash_table *ht;
    struct tda_group **list = NULL;
    int list_cap = 0;
    int next_index = 0;
    int i;
    int ret = -1;
    struct tda_group *g;

    if (!ctx || !cmt) {
        return -1;
    }

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 64, 0);
    if (!ht) {
        flb_errno();
        return -1;
    }

    /* counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        map = counter->map;

        if (tda_register_map_group(ht,
                                   &list,
                                   &list_cap,
                                   &next_index,
                                   map) != 0) {
            goto error;
        }
    }

    /* gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        map = gauge->map;

        if (tda_register_map_group(ht,
                                   &list,
                                   &list_cap,
                                   &next_index,
                                   map) != 0) {
            goto error;
        }
    }

    /* untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        map = untyped->map;

        if (tda_register_map_group(ht,
                                   &list,
                                   &list_cap,
                                   &next_index,
                                   map) != 0) {
            goto error;
        }
    }

    ctx->groups      = ht;
    ctx->group_list  = list;
    ctx->feature_dim = next_index;

    /* allocate last_vec for rate calculation */
    ctx->last_vec = flb_calloc(ctx->feature_dim, sizeof(double));
    if (!ctx->last_vec) {
        flb_errno();
        /* Clean up what we just assigned */
        ctx->groups = NULL;
        ctx->group_list = NULL;
        ctx->feature_dim = 0;
        goto error;
    }
    ctx->last_ts = 0;

    flb_plg_info(ctx->ins, "built TDA groups: feature_dim=%d", ctx->feature_dim);

    return 0;

error:
    if (list) {
        for (i = 0; i < next_index; i++) {
            g = list[i];
            if (!g) {
                continue;
            }
            if (g->ns) {
                cfl_sds_destroy(g->ns);
            }
            if (g->subsystem) {
                cfl_sds_destroy(g->subsystem);
            }
            flb_free(g);
        }
        flb_free(list);
    }
    if (ht) {
        flb_hash_table_destroy(ht);
    }
    if (ctx->last_vec) {
        flb_free(ctx->last_vec);
        ctx->last_vec = NULL;
    }
    return ret;
}

void tda_window_destroy(struct tda_window *w)
{
    if (!w) {
        return;
    }

    flb_free(w->buf);
    flb_free(w);
}

/* ---- metrics aggregation ---------------------------------------------- */

static int tda_build_vector_from_cmt(struct tda_proc_ctx *ctx,
                                     struct cmt *cmt,
                                     double *out_vec,
                                     uint64_t ts)
{
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_map *map;

    int i;
    double dt_sec;
    double raw_now;
    double raw_prev;
    double diff;
    double rate;
    double mag;
    double norm;

    /* zero-initialize vector */
    for (i = 0; i < ctx->feature_dim; i++) {
        out_vec[i] = 0.0;
    }

    if (!cmt || !ctx->groups) {
        return -1;
    }

    /* counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        map = counter->map;
        tda_accumulate_map_metrics(ctx, map, out_vec);
    }

    /* gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        map = gauge->map;
        tda_accumulate_map_metrics(ctx, map, out_vec);
    }

    /* untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        map = untyped->map;
        tda_accumulate_map_metrics(ctx, map, out_vec);
    }

    /* At this point, out_vec contains the aggregated value for each (ns, subsystem).
     *
     * Next, we use the difference from the previous snapshot and dt to compute:
     *   rate = diff / dt
     * and then apply log1p for a light normalization.
     */

    if (!ctx->last_vec || ctx->feature_dim <= 0) {
        return -1;
    }

    if (ctx->last_ts == 0) {
        /* First call: we cannot compute rates yet, so we return 0
         * and store the current values in last_vec.
         */
        for (i = 0; i < ctx->feature_dim; i++) {
            ctx->last_vec[i] = out_vec[i];
            out_vec[i]       = 0.0;
        }
        ctx->last_ts = ts;
        return 0;
    }

    if (ts > ctx->last_ts) {
        dt_sec = (double) (ts - ctx->last_ts) / 1e9; /* cfl_time_now() returns ns */
    }
    else {
        /* safeguard in case time goes backwards */
        dt_sec = 1.0;
    }

    if (dt_sec <= 0.0) {
        dt_sec = 1.0;
    }

    for (i = 0; i < ctx->feature_dim; i++) {
        raw_now  = out_vec[i];
        raw_prev = ctx->last_vec[i];
        diff     = raw_now - raw_prev;
        rate     = diff / dt_sec;
        mag      = fabs(rate);
        norm     = log1p(mag);     /* squash into [0, +∞) */

        out_vec[i]       = (rate >= 0.0) ? norm : -norm;
        ctx->last_vec[i] = raw_now;       /* store raw value for next time */
    }
    ctx->last_ts = ts;

    return 0;
}

void tda_window_ingest(struct tda_window *w,
                       struct tda_proc_ctx *ctx,
                       struct cmt *cmt)
{
    uint64_t ts;
    size_t needed;
    size_t r;
    uint8_t *buf;
    uint8_t *drop = NULL;
    double *vec;
    struct tda_sample *s;

    if (!w || !ctx || !cmt) {
        return;
    }

    ts = cfl_time_now();
    needed = w->sample_size;

    buf = flb_malloc(needed);
    if (!buf) {
        flb_errno();
        return;
    }

    s = (struct tda_sample *) buf;
    s->ts = ts;

    vec = s->values;
    if (tda_build_vector_from_cmt(ctx, cmt, vec, ts) != 0) {
        flb_free(buf);
        return;
    }

    /* ring buffer full -> drop oldest sample(s) */
    while (lwrb_get_free(&w->rb) < needed) {
        if (drop == NULL) {
            drop = flb_malloc(w->sample_size);
            if (!drop) {
                flb_errno();
                lwrb_reset(&w->rb);
                flb_free(buf);
                return;
            }
        }

        r = lwrb_read(&w->rb, drop, w->sample_size);
        if (r != w->sample_size) {
            lwrb_reset(&w->rb);
            break;
        }
    }

    if (lwrb_write(&w->rb, buf, needed) != needed) {
        lwrb_reset(&w->rb);
    }

    if (drop) {
        flb_free(drop);
    }
    flb_free(buf);
}

static size_t tda_window_length(struct tda_window *w)
{
    size_t full;

    if (!w) {
        return 0;
    }

    full = lwrb_get_full(&w->rb);
    return (w->sample_size > 0) ? full / w->sample_size : 0;
}

/* non-destructive snapshot of the last max_samples samples into out_buf.
 * out_buf must have at least max_samples * w->sample_size bytes.
 */
static size_t tda_window_snapshot(struct tda_window *w,
                                  uint8_t *out_buf,
                                  size_t max_samples)
{
    size_t full_bytes;
    size_t sample_bytes;
    size_t total_count;
    size_t copy_count;
    size_t start_index;
    uint8_t *tmp;
    size_t r;

    if (!w || !out_buf || max_samples == 0) {
        return 0;
    }

    sample_bytes = w->sample_size;
    full_bytes   = lwrb_get_full(&w->rb);

    total_count = full_bytes / sample_bytes;
    if (total_count == 0) {
        return 0;
    }

    /* only whole samples are interesting */
    full_bytes = total_count * sample_bytes;

    tmp = flb_calloc(1, full_bytes);
    if (!tmp) {
        flb_errno();
        return 0;
    }

    /* Note: lwrb doesn't support peek, so we read and restore.
     * In the unlikely event write-back fails, data is lost.
     */
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

    memcpy(out_buf,
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

    if (!ctx->g_betti0) {
        ctx->g_betti0 = cmt_gauge_create(cmt,
                                         "fluentbit", "tda",
                                         "betti0",
                                         "Betti_0 over TDA sliding window",
                                         0, NULL);
        if (!ctx->g_betti0) {
            return -1;
        }
    }

    if (!ctx->g_betti1) {
        ctx->g_betti1 = cmt_gauge_create(cmt,
                                         "fluentbit", "tda",
                                         "betti1",
                                         "Betti_1 over TDA sliding window",
                                         0, NULL);
        if (!ctx->g_betti1) {
            return -1;
        }
    }

    if (!ctx->g_betti2) {
        ctx->g_betti2 = cmt_gauge_create(cmt,
                                         "fluentbit", "tda",
                                         "betti2",
                                         "Betti_2 over TDA sliding window",
                                         0, NULL);
        if (!ctx->g_betti2) {
            return -1;
        }
    }

    return 0;
}

static void tda_window_run_ripser(struct tda_window *w,
                                  struct tda_proc_ctx *ctx,
                                  struct cmt *cmt)
{
    size_t n_raw;
    size_t mat_size;
    float *dist;
    uint8_t *raw_samples;
    flb_ripser_betti betti;
    uint64_t ts;
    float threshold;

    size_t i, j, k;
    size_t lag;
    size_t m;
    size_t tau;
    size_t min_required;
    size_t n_embed;

    double q;

    double accum;
    size_t base_i;
    size_t base_j;
    size_t idx_i;
    size_t idx_j;

    uint8_t *si;
    uint8_t *sj;

    struct tda_sample *s_i = NULL;
    struct tda_sample *s_j = NULL;

    double *xi;
    double *xj;

    double diff;
    float d;

    /* --- search for H1 structures across multiple scales --- */
    static const double q_candidates[] = {
        0.10, 0.20, 0.30, 0.40, 0.50,
        0.60, 0.70, 0.80, 0.90
    };

    int nq;

    int best_b0 = 0;
    int best_b1 = 0;
    int best_b2 = 0;
    double best_q_for_b1 = 0.0;

    int qi;
    double qc;
    float thr;
    flb_ripser_betti tmp;
    int ret_local;

    if (!w || !ctx || !cmt) {
        return;
    }

    n_raw = tda_window_length(w);
    if (n_raw < 2) {
        return;
    }

    if (ensure_betti_gauges(ctx, cmt) != 0) {
        flb_plg_warn(ctx->ins, "failed to create betti gauges");
        return;
    }

    raw_samples = flb_calloc(1, n_raw * w->sample_size);
    if (!raw_samples) {
        flb_errno();
        return;
    }

    /* snapshot of the latest n_raw samples into raw_samples */
    n_raw = tda_window_snapshot(w, raw_samples, n_raw);
    if (n_raw < 2) {
        flb_free(raw_samples);
        return;
    }

    /* --- delay embedding settings --- */
    m   = (ctx->embed_dim   > 0) ? (size_t) ctx->embed_dim   : 1;
    tau = (ctx->embed_delay > 0) ? (size_t) ctx->embed_delay : 1;

    /* When m == 1, disable delay embedding to match the original behavior. */
    if (m == 1) {
        tau = 1;
    }

    /* Minimum number of samples required for the embedding:
     * index: t, t - tau, ..., t - (m-1)tau → t >= (m-1)tau
     * number of valid t = n_raw - (m - 1)tau
     */
    min_required = (m - 1) * tau + 1;
    if (n_raw < min_required) {
        /* Not enough samples to construct the delay embedding yet. */
        flb_free(raw_samples);
        return;
    }

    n_embed = n_raw - (m - 1) * tau;

    flb_plg_debug(ctx->ins, "n_raw=%zu, embed_dim=%d, embed_delay=%d, n_embed=%zu",
                  n_raw, ctx->embed_dim, ctx->embed_delay, n_embed);

    mat_size = n_embed * n_embed;
    dist = flb_calloc(mat_size, sizeof(float));
    if (!dist) {
        flb_errno();
        flb_free(raw_samples);
        return;
    }

    /* Build the distance matrix as an (n × m)-dimensional Euclidean distance.
     *
     * Embedded point p (0..n_embed-1) corresponds to the actual sample indices:
     *   base_p = p + (m - 1) * tau;
     *   for lag l: index = base_p - l * tau;
     */
    for (i = 0; i < n_embed; i++) {
        dist[i * n_embed + i] = 0.0f;

        for (j = 0; j < i; j++) {
            accum = 0.0;

            base_i = i + (m - 1) * tau;
            base_j = j + (m - 1) * tau;

            for (lag = 0; lag < m; lag++) {
                idx_i = base_i - lag * tau;
                idx_j = base_j - lag * tau;

                si = raw_samples + idx_i * w->sample_size;
                sj = raw_samples + idx_j * w->sample_size;

                s_i = (struct tda_sample *) si;
                s_j = (struct tda_sample *) sj;

                xi = s_i->values;
                xj = s_j->values;

                /* feature_dim (≈ 8 collapsed metrics) × m (lags) */
                for (k = 0; k < (size_t) ctx->feature_dim; k++) {
                    diff = xi[k] - xj[k];
                    accum += diff * diff;
                }
            }

            d = (float) sqrt(accum);
            dist[i * n_embed + j] = d;
            dist[j * n_embed + i] = d;
        }
    }

    if (m == 1) {
        q = 0.5;      /* No delay embedding: use something like the median. */
    }
    else {
        q = 0.2;      /* With delay embedding: look at a smaller scale. */
    }

    /* --- choose a scale for TDA ---
     * Use the number of embedded points n_embed to determine the threshold.
     */
    threshold = tda_choose_threshold_from_dist(ctx, dist, n_embed, q);
    if (threshold <= 0.0f) {
        threshold = 0.0f;
    }

    memset(&betti, 0, sizeof(betti));

    nq = sizeof(q_candidates) / sizeof(q_candidates[0]);

    for (qi = 0; qi < nq; qi++) {
        qc = q_candidates[qi];
        thr = tda_choose_threshold_from_dist(ctx, dist, n_embed, qc);

        if (thr < 0.0f) {
            thr = 0.0f;
        }

        memset(&tmp, 0, sizeof(tmp));

        ret_local = flb_ripser_compute_betti_from_dense_distance(dist,
                                                                 n_embed,
                                                                 2 /* max_dim */,
                                                                 thr,
                                                                 &tmp);
        if (ret_local != 0) {
            continue;
        }

        /* Prefer H1 (loops) as the primary signal.
         * If needed, H0/H2 can be used as additional indicators.
         */
        if (tmp.num_dims > 1 && tmp.betti[1] > best_b1) {
            best_b1 = tmp.betti[1];
            best_b0 = tmp.betti[0];
            best_b2 = (tmp.num_dims > 2) ? tmp.betti[2] : 0;

            /* if user forced ctx->threshold as quantile, report that,
             * otherwise report the candidate quantile qc.
             */
            if (ctx && ctx->threshold > 0.0 && ctx->threshold < 1.0) {
                best_q_for_b1 = ctx->threshold;
            }
            else {
                best_q_for_b1 = qc;
            }
        }
        /* If all H1 are zero, fall back to H0. */
        else if (best_b1 == 0 && tmp.betti[0] > best_b0) {
            best_b0 = tmp.betti[0];
            best_b2 = (tmp.num_dims > 2) ? tmp.betti[2] : 0;

            if (ctx && ctx->threshold > 0.0 && ctx->threshold < 1.0) {
                best_q_for_b1 = ctx->threshold;
            }
            else {
                best_q_for_b1 = qc;
            }
        }
    }

    /* After the loop, copy the "most plausible" values into betti. */
    betti.num_dims = 3;  /* we track b0, b1, b2 */
    betti.betti[0] = best_b0;
    betti.betti[1] = best_b1;
    betti.betti[2] = best_b2;

    flb_plg_debug(ctx->ins, "betti dims=%d, b0=%d, b1=%d, b2=%d (best_q=%.2f)",
                  betti.num_dims,
                  betti.betti[0],
                  betti.betti[1],
                  betti.betti[2],
                  best_q_for_b1);

    ts = cfl_time_now();

    if (ctx->g_betti0) {
        cmt_gauge_set(ctx->g_betti0, ts,
                      (double) betti.betti[0],
                      0, NULL);
    }

    if (ctx->g_betti1) {
        cmt_gauge_set(ctx->g_betti1, ts,
                      (double) betti.betti[1],
                      0, NULL);
    }

    if (ctx->g_betti2) {
        cmt_gauge_set(ctx->g_betti2, ts,
                      (double) betti.betti[2],
                      0, NULL);
    }

    flb_free(dist);
    flb_free(raw_samples);
}


/* ---------------------------------------------------------------------- */
/* processor plugin glue                                                  */
/* ---------------------------------------------------------------------- */

static int tda_proc_init(struct flb_processor_instance *ins,
                         void *source_plugin_instance,
                         int source_plugin_type,
                         struct flb_config *config)
{
    int ret = -1;
    struct tda_proc_ctx *ctx;

    (void) source_plugin_instance;
    (void) source_plugin_type;
    (void) config;

    ctx = flb_calloc(1, sizeof(*ctx));
    if (!ctx) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }

    ctx->feature_dim = 0;
    ctx->groups      = NULL;
    ctx->group_list  = NULL;
    ctx->window      = NULL;
    ctx->last_vec    = NULL;
    ctx->last_ts     = 0;
    ctx->ins         = ins;

    /* load configuration from config_map (override defaults if present) */
    ret = flb_processor_instance_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);
        return FLB_PROCESSOR_FAILURE;
    }

    ins->context = ctx;

    return FLB_PROCESSOR_SUCCESS;
}

static void tda_free_groups(struct tda_proc_ctx *ctx)
{
    int i;
    struct tda_group *g = NULL;

    if (!ctx) {
        return;
    }

    if (ctx->group_list) {
        for (i = 0; i < ctx->feature_dim; i++) {
            g = ctx->group_list[i];
            if (!g) {
                continue;
            }
            if (g->ns) {
                cfl_sds_destroy(g->ns);
            }
            if (g->subsystem) {
                cfl_sds_destroy(g->subsystem);
            }
            flb_free(g);
        }
        flb_free(ctx->group_list);
        ctx->group_list = NULL;
    }

    if (ctx->groups) {
        flb_hash_table_destroy(ctx->groups);
        ctx->groups = NULL;
    }

    ctx->feature_dim = 0;
}

static int tda_proc_exit(struct flb_processor_instance *ins, void *data)
{
    struct tda_proc_ctx *ctx;

    (void) ins;

    ctx = (struct tda_proc_ctx *) data;
    if (!ctx) {
        return FLB_PROCESSOR_SUCCESS;
    }

    if (ctx->window) {
        tda_window_destroy(ctx->window);
    }

    tda_free_groups(ctx);

    if (ctx->last_vec) {
        flb_free(ctx->last_vec);
    }

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

    ctx->g_betti0 = NULL;
    ctx->g_betti1 = NULL;
    ctx->g_betti2 = NULL;

    /* initial: construct groups and window */
    if (ctx->groups == NULL) {
        if (tda_build_groups(ctx, metrics_context) != 0) {
            flb_plg_warn(ins, "[tda] failed to build TDA groups");
            *out_context = metrics_context;
            return FLB_PROCESSOR_SUCCESS;
        }

        ctx->window = tda_window_create(ctx->window_size, ctx->feature_dim);
        if (!ctx->window) {
            flb_plg_warn(ins, "[tda] failed to create TDA window");
            *out_context = metrics_context;
            return FLB_PROCESSOR_SUCCESS;
        }
    }

    tda_window_ingest(ctx->window, ctx, metrics_context);

    if (tda_window_length(ctx->window) >= ctx->min_points) {
        tda_window_run_ripser(ctx->window, ctx, metrics_context);
    }

    *out_context = metrics_context;

    return FLB_PROCESSOR_SUCCESS;
}


static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_INT, "window_size", "60",
        0, FLB_TRUE, offsetof(struct tda_proc_ctx, window_size),
        "Number of samples to keep in the TDA sliding window"
    },
    {
        FLB_CONFIG_MAP_INT, "min_points", "10",
        0, FLB_TRUE, offsetof(struct tda_proc_ctx, min_points),
        "Minimum number of samples required before running Ripser"
    },
    {
        FLB_CONFIG_MAP_INT, "embed_dim", "3",
        0, FLB_TRUE, offsetof(struct tda_proc_ctx, embed_dim),
        "Delay embedding dimension m (m=1 disables delay embedding)."
        "For example, m = 3 → x_t, x_{t-1}, x_{t-2}."
    },
    {
        FLB_CONFIG_MAP_INT, "embed_delay", "1",
        0, FLB_TRUE, offsetof(struct tda_proc_ctx, embed_delay),
        "Delay embedding lag tau in samples. This means that 1 delaying sample."
    },
    {
        FLB_CONFIG_MAP_DOUBLE, "threshold", "0",
        0, FLB_TRUE, offsetof(struct tda_proc_ctx, threshold),
        "Distance scale selector. 0 = auto multi-quantile scan; "
        "(0,1) = use as quantile to pick the distance threshold."
    },
    /* EOF */
    {0}
};

struct flb_processor_plugin processor_tda_plugin = {
    .name               = "tda",
    .description        = "TDA (persistent homology) processor",
    .cb_init            = tda_proc_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = tda_proc_process_metrics,
    .cb_process_traces  = NULL,
    .cb_exit            = tda_proc_exit,
    .config_map         = config_map,
    .flags              = 0
};
