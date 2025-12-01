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
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_map.h>
#include <cfl/cfl_sds.h>
#include <fluent-bit/ripser/flb_ripser_wrapper.h>

/* lwrb header */
#include <lwrb/lwrb.h>

#include <math.h>
#include <string.h>

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

    /* exposed betti-number gauges (created lazily) */
    struct cmt_gauge *g_betti0;
    struct cmt_gauge *g_betti1;
    struct cmt_gauge *g_betti2;
};

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

    if (!ctx || !cmt) {
        return -1;
    }

    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 64, 0);
    if (!ht) {
        flb_errno();
        return -1;
    }

    /* helper: append new group pointer into list */
#define APPEND_GROUP_TO_LIST(_g)                                             \
    do {                                                                     \
        if (next_index >= list_cap) {                                        \
            int new_cap = (list_cap == 0) ? 16 : list_cap * 2;               \
            struct tda_group **tmp = flb_realloc(list,                       \
                sizeof(struct tda_group *) * (size_t) new_cap);              \
            if (!tmp) {                                                      \
                flb_errno();                                                 \
                goto error;                                                  \
            }                                                                \
            list = tmp;                                                      \
            list_cap = new_cap;                                              \
        }                                                                    \
        list[next_index] = (_g);                                             \
    } while (0)

    /* helper macro: register (ns,subsystem) from a map */
#define REGISTER_MAP_GROUP(_map)                                                     \
    do {                                                                             \
        const char *ns  = (_map)->opts->ns        ? (_map)->opts->ns        : "";    \
        const char *sub = (_map)->opts->subsystem ? (_map)->opts->subsystem : "";    \
        char key[256];                                                               \
        int  len;                                                                    \
        void *out;                                                                   \
                                                                                    \
        len = snprintf(key, sizeof(key), "%s.%s", ns, sub);                          \
        if (len < 0 || (size_t) len >= sizeof(key)) {                                \
            break;                                                                   \
        }                                                                            \
                                                                                    \
        out = flb_hash_table_get_ptr(ht, key, len);                                  \
        if (!out) {                                                                  \
            struct tda_group *g = flb_calloc(1, sizeof(*g));                         \
            if (!g) {                                                                \
                flb_errno();                                                         \
                goto error;                                                          \
            }                                                                        \
            g->ns        = cfl_sds_create(ns);                                       \
            g->subsystem = cfl_sds_create(sub);                                      \
            g->index     = next_index;                                              \
                                                                                    \
            if (!g->ns || !g->subsystem) {                                           \
                if (g->ns)        cfl_sds_destroy(g->ns);                            \
                if (g->subsystem) cfl_sds_destroy(g->subsystem);                     \
                flb_free(g);                                                         \
                goto error;                                                          \
            }                                                                        \
                                                                                    \
            /* hash table: store pointer as value (val_size=0 -> refering pointer ) */    \
            if (flb_hash_table_add(ht, key, len, g, 0) < 0) {                        \
                cfl_sds_destroy(g->ns);                                              \
                cfl_sds_destroy(g->subsystem);                                       \
                flb_free(g);                                                         \
                goto error;                                                          \
            }                                                                        \
                                                                                    \
            APPEND_GROUP_TO_LIST(g);                                                 \
            next_index++;                                                            \
        }                                                                            \
    } while (0)

    /* counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        map = counter->map;
        REGISTER_MAP_GROUP(map);
    }

    /* gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        map = gauge->map;
        REGISTER_MAP_GROUP(map);
    }

    /* untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        map = untyped->map;
        REGISTER_MAP_GROUP(map);
    }

#undef REGISTER_MAP_GROUP
#undef APPEND_GROUP_TO_LIST

    ctx->groups      = ht;
    ctx->group_list  = list;
    ctx->feature_dim = next_index;

    flb_info("[tda] built TDA groups: feature_dim=%d", ctx->feature_dim);

    return 0;

error:
    if (list) {
        for (i = 0; i < next_index; i++) {
            struct tda_group *g = list[i];
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
                                     double *out_vec)
{
    struct cfl_list *head;
    struct cfl_list *metric_head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_metric *metric;
    struct cmt_map *map;

    int i;

    /* zero-initialize vector */
    for (i = 0; i < ctx->feature_dim; i++) {
        out_vec[i] = 0.0;
    }

    if (!cmt || !ctx->groups) {
        return -1;
    }

#define ACCUMULATE_MAP_METRICS(_map)                                              \
    do {                                                                          \
        const char *ns  = (_map)->opts->ns        ? (_map)->opts->ns        : ""; \
        const char *sub = (_map)->opts->subsystem ? (_map)->opts->subsystem : ""; \
        char key[256];                                                            \
        int  len;                                                                 \
        void *out;                                                                \
                                                                                  \
        len = snprintf(key, sizeof(key), "%s.%s", ns, sub);                       \
        if (len < 0 || (size_t) len >= sizeof(key)) {                             \
            break;                                                                \
        }                                                                         \
                                                                                  \
        out = flb_hash_table_get_ptr(ctx->groups, key, len);                      \
        if (out) {                                                                \
            struct tda_group *g = (struct tda_group *) out;                       \
            int idx = g->index;                                                   \
            if (idx >= 0 && idx < ctx->feature_dim) {                             \
                if ((_map)->metric_static_set) {                                  \
                    metric = &(_map)->metric;                                     \
                    out_vec[idx] += cmt_metric_get_value(metric);                 \
                }                                                                 \
                cfl_list_foreach(metric_head, &(_map)->metrics) {                 \
                    metric = cfl_list_entry(metric_head,                          \
                                            struct cmt_metric, _head);            \
                    out_vec[idx] += cmt_metric_get_value(metric);                 \
                }                                                                 \
            }                                                                     \
        }                                                                         \
    } while (0)

    /* counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        map = counter->map;
        ACCUMULATE_MAP_METRICS(map);
    }

    /* gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        map = gauge->map;
        ACCUMULATE_MAP_METRICS(map);
    }

    /* untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        map = untyped->map;
        ACCUMULATE_MAP_METRICS(map);
    }

#undef ACCUMULATE_MAP_METRICS

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
    if (tda_build_vector_from_cmt(ctx, cmt, vec) != 0) {
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
    size_t n;
    size_t mat_size;
    float *dist;
    uint8_t *raw_samples;
    flb_ripser_betti betti;
    int ret;
    size_t i;
    size_t j;
    size_t k;
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

    raw_samples = flb_calloc(1, n * w->sample_size);
    if (!raw_samples) {
        flb_errno();
        return;
    }

    n = tda_window_snapshot(w, raw_samples, n);
    if (n < 2) {
        flb_free(raw_samples);
        return;
    }

    mat_size = n * n;
    dist = flb_calloc(mat_size, sizeof(float));
    if (!dist) {
        flb_errno();
        flb_free(raw_samples);
        return;
    }

    /* many dimensional Euclid distance */
    for (i = 0; i < n; i++) {
        uint8_t *si = raw_samples + i * w->sample_size;
        struct tda_sample *s_i = (struct tda_sample *) si;
        double *xi = s_i->values;

        dist[i * n + i] = 0.0f;

        for (j = 0; j < i; j++) {
            uint8_t *sj = raw_samples + j * w->sample_size;
            struct tda_sample *s_j = (struct tda_sample *) sj;
            double *xj = s_j->values;

            double accum = 0.0;

            for (k = 0; k < (size_t) ctx->feature_dim; k++) {
                double diff = xi[k] - xj[k];
                accum += diff * diff;
            }

            float d = (float) sqrt(accum);
            dist[i * n + j] = d;
            dist[j * n + i] = d;
        }
    }

    /* ★ ここでゼロ初期化してからラッパに渡す */
    memset(&betti, 0, sizeof(betti));

    /* H_0, H_1, H_2; threshold <= 0 means "auto threshold" inside wrapper */
    ret = flb_ripser_compute_betti_from_dense_distance(dist,
                                                       n,
                                                       2 /* max_dim */,
                                                       0.0f /* threshold */,
                                                       &betti);
    if (ret != 0) {
        flb_warn("[tda_metrics] ripser computation failed (ret=%d)", ret);
        flb_free(dist);
        flb_free(raw_samples);
        return;
    }

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
    ctx->feature_dim = 0;
    ctx->groups      = NULL;
    ctx->group_list  = NULL;
    ctx->window      = NULL;

    ins->context = ctx;

    return FLB_PROCESSOR_SUCCESS;
}

static void tda_free_groups(struct tda_proc_ctx *ctx)
{
    int i;

    if (!ctx) {
        return;
    }

    if (ctx->group_list) {
        for (i = 0; i < ctx->feature_dim; i++) {
            struct tda_group *g = ctx->group_list[i];
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
            flb_warn("[tda] failed to build TDA groups");
            *out_context = metrics_context;
            return FLB_PROCESSOR_SUCCESS;
        }

        ctx->window = tda_window_create(ctx->window_size, ctx->feature_dim);
        if (!ctx->window) {
            flb_warn("[tda] failed to create TDA window");
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
