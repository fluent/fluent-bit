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
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <ctraces/ctraces.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>

#define DEFAULT_INTERVAL_SEC  "2"
#define DEFAULT_INTERVAL_NSEC "0"

#define OTEL_SPAN_ID_LEN   8

struct event_type {
    int coll_fd;
    int type;

    int interval_sec;
    int interval_nsec;
    struct flb_input_instance *ins;
};

static struct ctrace_id *create_random_span_id()
{
    char *buf;
    ssize_t ret;
    struct ctrace_id *cid;

    buf = flb_malloc(OTEL_SPAN_ID_LEN);
    if (!buf) {
        ctr_errno();
        return NULL;
    }

    ret = ctr_random_get(buf, OTEL_SPAN_ID_LEN);
    if (ret < 0) {
        flb_free(buf);
        return NULL;
    }

    cid = ctr_id_create(buf, OTEL_SPAN_ID_LEN);
    flb_free(buf);

    return cid;

}

static int send_logs(struct flb_input_instance *ins)
{
    struct flb_log_event_encoder log_encoder;
    int                          ret;

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ins, "error initializing event encoder : %d", ret);

        return -1;
    }

    ret = flb_log_event_encoder_begin_record(&log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(
                &log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(
                &log_encoder, "event_type");
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(
                &log_encoder, "some logs");
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ins, NULL, 0,
                             log_encoder.output_buffer,
                             log_encoder.output_length);

        ret = 0;
    }
    else {
        flb_plg_error(ins, "Error encoding record : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_destroy(&log_encoder);

    return 0;
}

static int send_metrics(struct flb_input_instance *ins)
{
    int ret;
    double                        quantiles[5];
    struct cmt_histogram_buckets *buckets;
    double                        val;
    struct cmt                   *cmt;
    uint64_t                      ts;
    struct cmt_gauge             *g1;
    struct cmt_counter           *c1;
    struct cmt_summary           *s1;
    struct cmt_histogram         *h1;

    ts = cfl_time_now();
    cmt = cmt_create();

    c1 = cmt_counter_create(cmt, "kubernetes", "network", "load_counter", "Network load counter",
                            2, (char *[]) {"hostname", "app"});

    cmt_counter_get_val(c1, 0, NULL, &val);
    cmt_counter_inc(c1, ts, 0, NULL);
    cmt_counter_add(c1, ts, 2, 0, NULL);
    cmt_counter_get_val(c1, 0, NULL, &val);

    cmt_counter_inc(c1, ts, 2, (char *[]) {"localhost", "cmetrics"});
    cmt_counter_get_val(c1, 2, (char *[]) {"localhost", "cmetrics"}, &val);
    cmt_counter_add(c1, ts, 10.55, 2, (char *[]) {"localhost", "test"});
    cmt_counter_get_val(c1, 2, (char *[]) {"localhost", "test"}, &val);
    cmt_counter_set(c1, ts, 12.15, 2, (char *[]) {"localhost", "test"});
    cmt_counter_set(c1, ts, 1, 2, (char *[]) {"localhost", "test"});

    g1 = cmt_gauge_create(cmt, "kubernetes", "network", "load_gauge", "Network load gauge", 0, NULL);

    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_set(g1, ts, 2.0, 0, NULL);
    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_inc(g1, ts, 0, NULL);
    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_sub(g1, ts, 2, 0, NULL);
    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_dec(g1, ts, 0, NULL);
    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_inc(g1, ts, 0, NULL);

    buckets = cmt_histogram_buckets_create(3, 0.05, 5.0, 10.0);

    h1 = cmt_histogram_create(cmt,
                              "k8s", "network", "load_histogram", "Network load histogram",
                              buckets,
                              1, (char *[]) {"my_label"});

    cmt_histogram_observe(h1, ts, 0.001, 0, NULL);
    cmt_histogram_observe(h1, ts, 0.020, 0, NULL);
    cmt_histogram_observe(h1, ts, 5.0, 0, NULL);
    cmt_histogram_observe(h1, ts, 8.0, 0, NULL);
    cmt_histogram_observe(h1, ts, 1000, 0, NULL);

    cmt_histogram_observe(h1, ts, 0.001, 1, (char *[]) {"my_val"});
    cmt_histogram_observe(h1, ts, 0.020, 1, (char *[]) {"my_val"});
    cmt_histogram_observe(h1, ts, 5.0, 1, (char *[]) {"my_val"});
    cmt_histogram_observe(h1, ts, 8.0, 1, (char *[]) {"my_val"});
    cmt_histogram_observe(h1, ts, 1000, 1, (char *[]) {"my_val"});;

    quantiles[0] = 0.1;
    quantiles[1] = 0.2;
    quantiles[2] = 0.3;
    quantiles[3] = 0.4;
    quantiles[4] = 0.5;

    s1 = cmt_summary_create(cmt,
                            "k8s", "disk", "load_summary", "Disk load summary",
                            5, quantiles,
                            1, (char *[]) {"my_label"});

    quantiles[0] = 1.1;
    quantiles[1] = 2.2;
    quantiles[2] = 3.3;
    quantiles[3] = 4.4;
    quantiles[4] = 5.5;

    cmt_summary_set_default(s1, ts, quantiles, 51.612894511314444, 10, 0, NULL);

    quantiles[0] = 11.11;
    quantiles[1] = 0;
    quantiles[2] = 33.33;
    quantiles[3] = 44.44;
    quantiles[4] = 55.55;

    cmt_summary_set_default(s1, ts, quantiles, 51.612894511314444, 10, 1, (char *[]) {"my_val"});

    ret = flb_input_metrics_append(ins, NULL, 0, cmt);

    cmt_destroy(cmt);
    return ret;
}

static int send_traces(struct flb_input_instance *ins)
{
    int ret;
    struct ctrace *ctx;
    struct ctrace_opts opts;
    struct ctrace_span *span_root;
    struct ctrace_span *span_child;
    struct ctrace_span_event *event;
    struct ctrace_resource_span *resource_span;
    struct ctrace_resource *resource;
    struct ctrace_scope_span *scope_span;
    struct ctrace_instrumentation_scope *instrumentation_scope;
    struct ctrace_link *link;
    struct ctrace_id *span_id;
    struct ctrace_id *trace_id;
    struct cfl_array *array;
    struct cfl_array *sub_array;
    struct cfl_kvlist *kv;

    ctr_opts_init(&opts);

    /* ctrace context */
    ctx = ctr_create(&opts);
    if (!ctx) {
        return -1;
    }

    /* resource span */
    resource_span = ctr_resource_span_create(ctx);
    ctr_resource_span_set_schema_url(resource_span, "https://ctraces/resource_span_schema_url");

    /* create a 'resource' for the 'resource span' in question */
    resource = ctr_resource_span_get_resource(resource_span);
    ctr_resource_set_dropped_attr_count(resource, 5);

    ctr_attributes_set_string(resource->attr, "service.name", "Fluent Bit Test Service");

    /* scope span */
    scope_span = ctr_scope_span_create(resource_span);
    ctr_scope_span_set_schema_url(scope_span, "https://ctraces/scope_span_schema_url");

    /* create an optional instrumentation scope */
    instrumentation_scope = ctr_instrumentation_scope_create("ctrace", "a.b.c", 3, NULL);
    ctr_scope_span_set_instrumentation_scope(scope_span, instrumentation_scope);

    /* generate a random trace_id */
    trace_id = ctr_id_create_random(CTR_ID_OTEL_TRACE_SIZE);

    /* generate a random ID for the new span */
    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);

    /* Create a root span */
    span_root = ctr_span_create(ctx, scope_span, "main", NULL);
    if (!span_root) {
        ctr_destroy(ctx);
        ctr_id_destroy(span_id);
        ctr_opts_exit(&opts);
        return -1;
    }

    /* assign the random ID */
    ctr_span_set_span_id_with_cid(span_root, span_id);

    /* set random trace_id */
    ctr_span_set_trace_id_with_cid(span_root, trace_id);

    /* add some attributes to the span */
    ctr_span_set_attribute_string(span_root, "agent", "Fluent Bit");
    ctr_span_set_attribute_int64(span_root, "year", 2022);
    ctr_span_set_attribute_bool(span_root, "open_source", CTR_TRUE);
    ctr_span_set_attribute_double(span_root, "temperature", 25.5);

    /* pack an array: create an array context by using the CFL api */
    array = cfl_array_create(4);
    cfl_array_append_string(array, "first");
    cfl_array_append_double(array, 2.0);
    cfl_array_append_bool(array, CFL_FALSE);

    sub_array = cfl_array_create(3);
    cfl_array_append_double(sub_array, 3.1);
    cfl_array_append_double(sub_array, 5.2);
    cfl_array_append_double(sub_array, 6.3);
    cfl_array_append_array(array, sub_array);

    /* add array to the attribute list */
    ctr_span_set_attribute_array(span_root, "my_array", array);

    /* event: add one event and set attributes to it */
    event = ctr_span_event_add(span_root, "connect to remote server");

    ctr_span_event_set_attribute_string(event, "syscall 1", "open()");
    ctr_span_event_set_attribute_string(event, "syscall 2", "connect()");
    ctr_span_event_set_attribute_string(event, "syscall 3", "write()");

    /* add a key/value pair list */
    kv = cfl_kvlist_create();
    cfl_kvlist_insert_string(kv, "language", "c");

    ctr_span_set_attribute_kvlist(span_root, "my-list", kv);

    /* create a child span */
    span_child = ctr_span_create(ctx, scope_span, "do-work", span_root);
    if (!span_child) {
        ctr_destroy(ctx);
        ctr_opts_exit(&opts);
        return -1;
    }

    /* set trace_id */
    ctr_span_set_trace_id_with_cid(span_child, trace_id);

    /* use span_root ID as parent_span_id */
    ctr_span_set_parent_span_id_with_cid(span_child, span_id);

    /* delete old span id and generate a new one */
    ctr_id_destroy(span_id);
    span_id = create_random_span_id();
    ctr_span_set_span_id_with_cid(span_child, span_id);

    /* destroy the IDs since is not longer needed */
    ctr_id_destroy(span_id);
    ctr_id_destroy(trace_id);

    /* change span kind to client */
    ctr_span_kind_set(span_child, CTRACE_SPAN_CLIENT);

    /* create a Link (no valid IDs of course) */
    trace_id = ctr_id_create_random(CTR_ID_OTEL_TRACE_SIZE);
    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);

    link = ctr_link_create_with_cid(span_child, trace_id, span_id);
    ctr_link_set_trace_state(link, "aaabbbccc");
    ctr_link_set_dropped_attr_count(link, 2);

    /* delete IDs */
    ctr_id_destroy(span_id);
    ctr_id_destroy(trace_id);

    ret = flb_input_trace_append(ins, NULL, 0, ctx);
    if (ret == -1) {
        /* destroy the context */
        ctr_destroy(ctx);
    }

    /* exit options (it release resources allocated) */
    ctr_opts_exit(&opts);

    return ret;
}

static int cb_collector_time(struct flb_input_instance *ins,
                            struct flb_config *config, void *in_context)
{
    int ret;
    struct event_type *ctx = (struct event_type *) in_context;

    if (ctx->type == FLB_EVENT_TYPE_LOGS) {
        ret = send_logs(ins);
        flb_plg_debug(ins, "logs, ret=%i", ret);
    }
    else if (ctx->type == FLB_EVENT_TYPE_METRICS) {
        ret = send_metrics(ins);
        flb_plg_debug(ins, "metrics, ret=%i", ret);
    }
    else if (ctx->type == FLB_EVENT_TYPE_TRACES) {
        ret = send_traces(ins);
        flb_plg_debug(ins, "traces, ret=%i", ret);
    }

    flb_plg_info(ins, "[OK] collector_time");
    FLB_INPUT_RETURN(0);
}

/* Initialize plugin */
static int cb_event_type_init(struct flb_input_instance *ins,
                              struct flb_config *config, void *data)
{
    int ret;
    char *tmp;
    struct event_type *ctx = NULL;

    ctx = flb_calloc(1, sizeof(struct event_type));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);

        return -1;
    }

    flb_input_set_context(ins, ctx);

    ctx->type = FLB_EVENT_TYPE_LOGS;
    tmp = (char *) flb_input_get_property("type", ins);
    if (tmp) {
        if (strcasecmp(tmp, "logs") == 0) {
            ctx->type = FLB_EVENT_TYPE_LOGS;
        }
        else if (strcasecmp(tmp, "metrics") == 0) {
            ctx->type = FLB_EVENT_TYPE_METRICS;
        }
        else if (strcasecmp(tmp, "traces") == 0) {
            ctx->type = FLB_EVENT_TYPE_TRACES;
        }
    }

    /* unit test 0: collector_time */
    ret = flb_input_set_collector_time(ins, cb_collector_time,
                                       ctx->interval_sec, ctx->interval_nsec, config);
    if (ret < 0) {
        flb_free(ctx);

        return -1;
    }

    ctx->coll_fd = ret;

    return 0;
}

static int cb_event_type_exit(void *data, struct flb_config *config)
{
    struct event_type *ctx = data;

    flb_free(ctx);
    return 0;
}

static void cb_event_type_pause(void *data, struct flb_config *config)
{
    struct event_type *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void cb_event_type_resume(void *data, struct flb_config *config)
{
    struct event_type *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "type", "logs",
     0, FLB_FALSE, 0,
     "Set the type of event to deliver, optionsa are: logs, metrics or traces"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct event_type, interval_sec),
      "Set the interval seconds between events generation"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct event_type, interval_nsec),
      "Set the nanoseconds interval (sub seconds)"
    },

   /* EOF */
   {0}
};

struct flb_input_plugin in_event_type_plugin = {
    .name         = "event_type",
    .description  = "Event tests for input plugins",
    .cb_init      = cb_event_type_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_event_type_pause,
    .cb_resume    = cb_event_type_resume,
    .cb_exit      = cb_event_type_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_CORO | FLB_INPUT_THREADED
};
