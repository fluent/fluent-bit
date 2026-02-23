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

/*
 * Metrics interface is a helper to gather general metrics from the core or
 * plugins at runtime.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_metrics.h>
#include <msgpack.h>

static int id_exists(int id, struct flb_metrics *metrics)
{
    struct mk_list *head;
    struct flb_metric *metric;

    mk_list_foreach(head, &metrics->list) {
        metric = mk_list_entry(head, struct flb_metric, _head);
        if (metric->id == id) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int id_get(struct flb_metrics *metrics)
{
    int id;
    int ret = FLB_FALSE;

    /* Try to use 'count' as an id */
    id = metrics->count;

    while ((ret = id_exists(id, metrics)) == FLB_TRUE) {
        id++;
    }

    return id;
}

struct flb_metric *flb_metrics_get_id(int id, struct flb_metrics *metrics)
{
    struct mk_list *head;
    struct flb_metric *m;

    mk_list_foreach(head, &metrics->list) {
        m = mk_list_entry(head, struct flb_metric, _head);
        if (m->id == id) {
            return m;
        }
    }

    return NULL;
}

struct flb_metrics *flb_metrics_create(const char *title)
{
    int ret;
    struct flb_metrics *metrics;

    /* Create a metrics parent context */
    metrics = flb_calloc(1, sizeof(struct flb_metrics));
    if (!metrics) {
        flb_errno();
        return NULL;
    }
    metrics->count = 0;

    /* Set metrics title */
    ret = flb_metrics_title(title, metrics);
    if (ret == -1) {
        flb_free(metrics);
        return NULL;
    }

    /* List head for specific metrics under the context */
    mk_list_init(&metrics->list);
    return metrics;
}

int flb_metrics_title(const char *title, struct flb_metrics *metrics)
{
    int len;

    len  = strlen(title);
    if (len > FLB_METRIC_LENGTH_LIMIT) {
        flb_warn("[%s] title '%s' was truncated", __FUNCTION__, title);
        len = FLB_METRIC_LENGTH_LIMIT;
    }

    if (metrics->title) {
        flb_sds_destroy(metrics->title);
    }

    metrics->title = flb_sds_create_len(title, len);
    if (!metrics->title) {
        flb_errno();
        return -1;
    }

    return 0;
}

int flb_metrics_add(int id, const char *title, struct flb_metrics *metrics)
{
    int len;
    struct flb_metric *m;
    size_t threshold = FLB_METRIC_LENGTH_LIMIT;

    /* Create context */
    m = flb_malloc(sizeof(struct flb_metric));
    if (!m) {
        flb_errno();
        return -1;
    }
    m->val = 0;
    len = strlen(title);

    if (len > threshold) {
        len = threshold;
        flb_warn("[%s] title '%s' was truncated", __FUNCTION__, title);
    }

    m->title = flb_sds_create_len(title, len);
    if (!m->title) {
        flb_errno();
        flb_free(m);
        return -1;
    }

    /* Assign an ID */
    if (id >= 0) {
        /* Check this new ID is available */
        if (id_exists(id, metrics) == FLB_TRUE) {
            flb_error("[metrics] id=%i already exists for metric '%s'",
                      id, metrics->title);
            flb_sds_destroy(m->title);
            flb_free(m);
            return -1;
        }
    }
    else {
        id = id_get(metrics);
    }

    /* Link to parent list */
    mk_list_add(&m->_head, &metrics->list);
    m->id = id;
    metrics->count++;

    return id;
}

int flb_metrics_sum(int id, size_t val, struct flb_metrics *metrics)
{
    struct flb_metric *m;

    m = flb_metrics_get_id(id, metrics);
    if (!m) {
        return -1;
    }

    m->val += val;
    return 0;
}

int flb_metrics_destroy(struct flb_metrics *metrics)
{
    int count = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_metric *m;

    mk_list_foreach_safe(head, tmp, &metrics->list) {
        m = mk_list_entry(head, struct flb_metric, _head);
        mk_list_del(&m->_head);
        flb_sds_destroy(m->title);
        flb_free(m);
        count++;
    }

    flb_sds_destroy(metrics->title);
    flb_free(metrics);
    return count;
}

int flb_metrics_print(struct flb_metrics *metrics)
{
    struct mk_list *head;
    struct flb_metric *m;

    printf("[metric dump] title => '%s'", metrics->title);

    mk_list_foreach(head, &metrics->list) {
        m = mk_list_entry(head, struct flb_metric, _head);
        printf(", '%s' => %lu", m->title, m->val);
    }
    printf("\n");

    return 0;
}

/* Write metrics in messagepack format */
int flb_metrics_dump_values(char **out_buf, size_t *out_size,
                            struct flb_metrics *me)
{
    struct mk_list *head;
    struct flb_metric *m;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, me->count);

    mk_list_foreach(head, &me->list) {
        m = mk_list_entry(head, struct flb_metric, _head);
        msgpack_pack_str(&mp_pck, flb_sds_len(m->title));
        msgpack_pack_str_body(&mp_pck, m->title, flb_sds_len(m->title));
        msgpack_pack_uint64(&mp_pck, m->val);
    }

    *out_buf  = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static int attach_uptime(struct flb_config *ctx, struct cmt *cmt,
                         uint64_t ts, char *hostname)
{
    double uptime;
    struct cmt_counter *c;

    /* uptime */
    c = cmt_counter_create(cmt, "fluentbit", "", "uptime",
                           "Number of seconds that Fluent Bit has been running.",
                           1, (char *[]) {"hostname"});
    if (!c) {
        return -1;
    }

    uptime = time(NULL) - ctx->init_time;

    cmt_counter_set(c, ts, uptime, 1, (char *[]) {hostname});
    return 0;
}

static int attach_process_start_time_seconds(struct flb_config *ctx,
                                             struct cmt *cmt,
                                             uint64_t ts, char *hostname)
{
    double val;
    struct cmt_gauge *g;

    g = cmt_gauge_create(cmt, "fluentbit", "", "process_start_time_seconds",
                         "Start time of the process since unix epoch in seconds.",
                         1, (char *[]) {"hostname"});
    if (!g) {
        return -1;
    }

    val = (double) ctx->init_time;
    cmt_gauge_set(g, ts, val, 1, (char *[]) {hostname});
    return 0;
}

static char *get_os_name()
{
#ifdef _WIN64
    return "win64";
#elif _WIN32
    return "win32";
#elif __APPLE__ || __MACH__
    return "macos";
#elif __linux__
    return "linux";
#elif __FreeBSD__
    return "freebsd";
#elif __unix || __unix__
    return "unix";
#else
    return "other";
#endif
}

static int attach_build_info(struct flb_config *ctx, struct cmt *cmt, uint64_t ts,
                             char *hostname)
{
    double val;
    char *os;
    struct cmt_gauge *g;

    g = cmt_gauge_create(cmt, "fluentbit", "build", "info",
                         "Build version information.",
                         3, (char *[]) {"hostname", "version", "os"});
    if (!g) {
        return -1;
    }

    val = (double) ctx->init_time;
    os = get_os_name();

    cmt_gauge_set(g, ts, val, 3, (char *[]) {hostname, FLB_VERSION_STR, os});
    return 0;
}

static int attach_hot_reload_info(struct flb_config *ctx, struct cmt *cmt, uint64_t ts,
                                  char *hostname)
{
    double val;
    struct cmt_gauge *g;

    g = cmt_gauge_create(cmt, "fluentbit", "", "hot_reloaded_times",
                         "Collect the count of hot reloaded times.",
                         1, (char *[]) {"hostname"});
    if (!g) {
        return -1;
    }

    val = (double) ctx->hot_reloaded_count;

    cmt_gauge_set(g, ts, val, 1, (char *[]) {hostname});
    return 0;
}

/* Append internal Fluent Bit metrics to context */
int flb_metrics_fluentbit_add(struct flb_config *ctx, struct cmt *cmt)
{
    int ret;
    size_t ts;
    char hostname[128];

    /* current timestamp */
    ts = cfl_time_now();

    /* get hostname */
    ret = gethostname(hostname, sizeof(hostname) - 1);
    if (ret == -1) {
        strcpy(hostname, "unknown");
    }

    /* Attach metrics to cmetrics context */
    attach_uptime(ctx, cmt, ts, hostname);
    attach_process_start_time_seconds(ctx, cmt, ts, hostname);
    attach_build_info(ctx, cmt, ts, hostname);
    attach_hot_reload_info(ctx, cmt, ts, hostname);

    return 0;
}

bool flb_metrics_is_empty(struct cmt *cmt)
{
    return cfl_list_is_empty(&cmt->counters) &&
           cfl_list_is_empty(&cmt->gauges) &&
           cfl_list_is_empty(&cmt->histograms) &&
           cfl_list_is_empty(&cmt->summaries) &&
           cfl_list_is_empty(&cmt->untypeds);
}
