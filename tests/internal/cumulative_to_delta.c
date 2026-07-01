/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <math.h>

#include <fluent-bit/flb_compat.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cfl/cfl_kvlist.h>

#include "../../plugins/processor_cumulative_to_delta/cumulative_to_delta.h"

#include "flb_tests_internal.h"

static struct cmt_counter *get_first_counter(struct cmt *context)
{
    return cfl_list_entry(context->counters.next, struct cmt_counter, _head);
}

static struct cmt_histogram *get_first_histogram(struct cmt *context)
{
    return cfl_list_entry(context->histograms.next, struct cmt_histogram, _head);
}

static int map_sample_count(struct cmt_map *map)
{
    int count;

    count = cfl_list_size(&map->metrics);

    if (map->metric_static_set == FLB_TRUE) {
        count++;
    }

    return count;
}

static struct cmt *create_counter_context(char *name,
                                          uint64_t timestamp,
                                          double value,
                                          int allow_reset)
{
    struct cmt *context;
    struct cmt_counter *counter;

    context = cmt_create();
    if (context == NULL) {
        return NULL;
    }

    counter = cmt_counter_create(context, "", "", name, "help", 0, NULL);
    if (counter == NULL) {
        cmt_destroy(context);
        return NULL;
    }

    counter->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;

    if (allow_reset == FLB_TRUE) {
        cmt_counter_allow_reset(counter);
    }

    if (cmt_counter_set(counter, timestamp, value, 0, NULL) != 0) {
        cmt_destroy(context);
        return NULL;
    }

    return context;
}

static struct cmt *create_histogram_context(char *name,
                                            uint64_t timestamp,
                                            uint64_t *buckets,
                                            double sum,
                                            uint64_t count)
{
    double upper_bounds[2];
    struct cmt *context;
    struct cmt_histogram *histogram;
    struct cmt_histogram_buckets *bucket_definition;

    upper_bounds[0] = 1.0;
    upper_bounds[1] = 2.0;

    context = cmt_create();
    if (context == NULL) {
        return NULL;
    }

    bucket_definition = cmt_histogram_buckets_create_size(upper_bounds, 2);
    if (bucket_definition == NULL) {
        cmt_destroy(context);
        return NULL;
    }

    histogram = cmt_histogram_create(context, "", "", name, "help",
                                     bucket_definition, 0, NULL);
    if (histogram == NULL) {
        cmt_destroy(context);
        return NULL;
    }

    histogram->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;

    if (cmt_histogram_set_default(histogram, timestamp, buckets, sum, count,
                                  0, NULL) != 0) {
        cmt_destroy(context);
        return NULL;
    }

    return context;
}

static struct cmt_exp_histogram *get_first_exp_histogram(struct cmt *context)
{
    return cfl_list_entry(context->exp_histograms.next,
                          struct cmt_exp_histogram,
                          _head);
}

static struct cmt *roundtrip_context_through_otlp(struct cmt *input)
{
    size_t offset;
    cfl_sds_t payload;
    struct cfl_list contexts;
    struct cmt *context;

    payload = cmt_encode_opentelemetry_create(input);
    if (payload == NULL) {
        return NULL;
    }

    offset = 0;
    if (cmt_decode_opentelemetry_create(&contexts,
                                        payload,
                                        cfl_sds_len(payload),
                                        &offset) != 0) {
        cmt_encode_opentelemetry_destroy(payload);
        return NULL;
    }

    cmt_encode_opentelemetry_destroy(payload);

    if (cfl_list_size(&contexts) != 1) {
        cmt_decode_opentelemetry_destroy(&contexts);
        return NULL;
    }

    context = cfl_list_entry_first(&contexts, struct cmt, _head);
    cfl_list_del(&context->_head);

    return context;
}

static struct cmt *create_exp_histogram_context(char *name,
                                                uint64_t timestamp,
                                                int32_t scale,
                                                uint64_t zero_count,
                                                double zero_threshold,
                                                int32_t positive_offset,
                                                size_t positive_count,
                                                uint64_t *positive_buckets,
                                                int32_t negative_offset,
                                                size_t negative_count,
                                                uint64_t *negative_buckets,
                                                int sum_set,
                                                double sum,
                                                uint64_t count)
{
    struct cmt *context;
    struct cmt_exp_histogram *exp_histogram;

    context = cmt_create();
    if (context == NULL) {
        return NULL;
    }

    exp_histogram = cmt_exp_histogram_create(context, "", "", name, "help", 0, NULL);
    if (exp_histogram == NULL) {
        cmt_destroy(context);
        return NULL;
    }

    exp_histogram->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;

    if (cmt_exp_histogram_set_default(exp_histogram,
                                      timestamp,
                                      scale,
                                      zero_count,
                                      zero_threshold,
                                      positive_offset,
                                      positive_count,
                                      positive_buckets,
                                      negative_offset,
                                      negative_count,
                                      negative_buckets,
                                      sum_set,
                                      sum,
                                      count,
                                      0,
                                      NULL) != 0) {
        cmt_destroy(context);
        return NULL;
    }

    return context;
}

static int set_context_resource_attributes(struct cmt *context,
                                           char *first_key,
                                           char *first_value,
                                           char *second_key,
                                           char *second_value)
{
    struct cfl_variant *root_variant;
    struct cfl_kvlist *resource_root;
    struct cfl_kvlist *attributes;

    root_variant = cfl_kvlist_fetch(context->external_metadata, "resource");
    if (root_variant == NULL || root_variant->type != CFL_VARIANT_KVLIST) {
        resource_root = cfl_kvlist_create();
        if (resource_root == NULL) {
            return -1;
        }

        if (cfl_kvlist_insert_kvlist(context->external_metadata,
                                     "resource",
                                     resource_root) != 0) {
            cfl_kvlist_destroy(resource_root);
            return -1;
        }
    }
    else {
        resource_root = root_variant->data.as_kvlist;
    }

    attributes = cfl_kvlist_create();
    if (attributes == NULL) {
        return -1;
    }

    if (cfl_kvlist_insert_string(attributes, first_key, first_value) != 0 ||
        cfl_kvlist_insert_string(attributes, second_key, second_value) != 0 ||
        cfl_kvlist_insert_kvlist(resource_root, "attributes", attributes) != 0) {
        cfl_kvlist_destroy(attributes);
        return -1;
    }

    return 0;
}

static void test_counter_drop_first_and_delta()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_DROP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_counter_context("requests_total", 100, 10.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 0);
    cmt_destroy(context);

    context = create_counter_context("requests_total", 200, 16.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    counter = get_first_counter(context);
    TEST_CHECK(counter->aggregation_type == CMT_AGGREGATION_TYPE_DELTA);
    TEST_CHECK(map_sample_count(counter->map) == 1);

    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 6.0) < 0.0001);
    TEST_CHECK(cmt_metric_has_start_timestamp(&counter->map->metric) == CMT_TRUE);
    TEST_CHECK(cmt_metric_get_start_timestamp(&counter->map->metric) == 100);

    cmt_destroy(context);
    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_counter_reset_drop_and_keep()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_KEEP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_counter_context("errors_total", 100, 10.0, FLB_FALSE);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("errors_total", 200, 2.0, FLB_FALSE);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 0);
    cmt_destroy(context);

    context = create_counter_context("errors_total", 300, 8.0, FLB_FALSE);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 6.0) < 0.0001);
    cmt_destroy(context);
    flb_cumulative_to_delta_ctx_destroy(converter);

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_KEEP,
                                                   FLB_FALSE, 0);
    TEST_CHECK(converter != NULL);

    context = create_counter_context("errors_total_keep", 100, 10.0, FLB_FALSE);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("errors_total_keep", 200, 2.0, FLB_FALSE);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 2.0) < 0.0001);
    TEST_CHECK(cmt_metric_has_start_timestamp(&counter->map->metric) == CMT_TRUE);
    TEST_CHECK(cmt_metric_get_start_timestamp(&counter->map->metric) == 200);
    cmt_destroy(context);
    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_histogram_drop_first_and_delta()
{
    double sum;
    uint64_t count;
    uint64_t buckets_1[3];
    uint64_t buckets_2[3];
    struct cmt *context;
    struct cmt_histogram *histogram;
    struct flb_cumulative_to_delta_ctx *converter;

    buckets_1[0] = 1;
    buckets_1[1] = 2;
    buckets_1[2] = 3;

    buckets_2[0] = 3;
    buckets_2[1] = 5;
    buckets_2[2] = 8;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_DROP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_histogram_context("latency_seconds", 100, buckets_1, 2.0, 3);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    histogram = get_first_histogram(context);
    TEST_CHECK(map_sample_count(histogram->map) == 0);
    cmt_destroy(context);

    context = create_histogram_context("latency_seconds", 200, buckets_2, 7.0, 8);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    histogram = get_first_histogram(context);
    TEST_CHECK(histogram->aggregation_type == CMT_AGGREGATION_TYPE_DELTA);
    TEST_CHECK(map_sample_count(histogram->map) == 1);
    TEST_CHECK(cmt_metric_has_start_timestamp(&histogram->map->metric) == CMT_TRUE);
    TEST_CHECK(cmt_metric_get_start_timestamp(&histogram->map->metric) == 100);
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 0) == 2);
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 1) == 3);
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 2) == 5);

    count = cmt_metric_hist_get_count_value(&histogram->map->metric);
    sum = cmt_metric_hist_get_sum_value(&histogram->map->metric);
    TEST_CHECK(count == 5);
    TEST_CHECK(fabs(sum - 5.0) < 0.0001);

    cmt_destroy(context);
    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_counter_out_of_order_is_dropped()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_KEEP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_counter_context("out_of_order_total", 200, 5.0, FLB_FALSE);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("out_of_order_total", 100, 9.0, FLB_FALSE);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 0);
    cmt_destroy(context);

    context = create_counter_context("out_of_order_total", 300, 12.0, FLB_FALSE);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 7.0) < 0.0001);
    cmt_destroy(context);

    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_counter_initial_value_auto()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_AUTO,
                                                   FLB_TRUE, 150);
    TEST_CHECK(converter != NULL);

    context = create_counter_context("auto_drop_total", 100, 10.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 0);
    cmt_destroy(context);

    context = create_counter_context("auto_drop_total", 300,
                                     18.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 8.0) < 0.0001);
    cmt_destroy(context);

    context = create_counter_context("auto_keep_total", 200,
                                     7.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 1);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 7.0) < 0.0001);
    cmt_destroy(context);

    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_counter_initial_value_auto_uses_start_timestamp()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_AUTO,
                                                   FLB_TRUE, 150);
    TEST_CHECK(converter != NULL);

    context = create_counter_context("auto_start_time_total", 200, 10.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    counter = get_first_counter(context);
    cmt_metric_set_start_timestamp(&counter->map->metric, 100);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    TEST_CHECK(map_sample_count(counter->map) == 0);
    cmt_destroy(context);

    context = create_counter_context("auto_start_time_total", 300, 18.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    counter = get_first_counter(context);
    cmt_metric_set_start_timestamp(&counter->map->metric, 100);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    TEST_CHECK(map_sample_count(counter->map) == 1);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 8.0) < 0.0001);
    cmt_destroy(context);

    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_histogram_sum_decrease_without_reset()
{
    double sum;
    uint64_t count;
    uint64_t buckets_1[3];
    uint64_t buckets_2[3];
    struct cmt *context;
    struct cmt_histogram *histogram;
    struct flb_cumulative_to_delta_ctx *converter;

    buckets_1[0] = 1;
    buckets_1[1] = 2;
    buckets_1[2] = 3;

    buckets_2[0] = 2;
    buckets_2[1] = 4;
    buckets_2[2] = 6;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_KEEP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_histogram_context("negative_sum_histogram",
                                       100, buckets_1, 10.0, 3);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_histogram_context("negative_sum_histogram",
                                       200, buckets_2, 8.0, 6);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    histogram = get_first_histogram(context);
    TEST_CHECK(map_sample_count(histogram->map) == 1);
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 0) == 1);
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 1) == 2);
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 2) == 3);

    count = cmt_metric_hist_get_count_value(&histogram->map->metric);
    sum = cmt_metric_hist_get_sum_value(&histogram->map->metric);
    TEST_CHECK(count == 3);
    TEST_CHECK(fabs(sum - (-2.0)) < 0.0001);

    cmt_destroy(context);
    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_non_monotonic_sum_is_not_converted()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_KEEP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_counter_context("non_monotonic_sum", 100, 10.0, FLB_TRUE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    counter = get_first_counter(context);
    TEST_CHECK(counter->aggregation_type == CMT_AGGREGATION_TYPE_CUMULATIVE);
    TEST_CHECK(map_sample_count(counter->map) == 1);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 10.0) < 0.0001);
    cmt_destroy(context);

    context = create_counter_context("non_monotonic_sum", 200, 3.0, FLB_TRUE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    counter = get_first_counter(context);
    TEST_CHECK(counter->aggregation_type == CMT_AGGREGATION_TYPE_CUMULATIVE);
    TEST_CHECK(map_sample_count(counter->map) == 1);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 3.0) < 0.0001);
    cmt_destroy(context);

    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_context_attribute_order_does_not_split_series()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_KEEP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_counter_context("ordered_resource_total", 100, 10.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(set_context_resource_attributes(context,
                                               "service.name", "checkout",
                                               "host.name", "node-a") == 0);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("ordered_resource_total", 200, 16.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(set_context_resource_attributes(context,
                                               "host.name", "node-a",
                                               "service.name", "checkout") == 0);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 1);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 6.0) < 0.0001);

    cmt_destroy(context);
    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_max_series_evicts_least_recently_used()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_DROP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_configure(converter, 0, 2) == 0);

    context = create_counter_context("series_a_total", 100, 1.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("series_b_total", 100, 10.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_counter_context("series_a_total", 200, 3.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 2.0) < 0.0001);
    cmt_destroy(context);

    context = create_counter_context("series_c_total", 100, 20.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 0);
    cmt_destroy(context);

    context = create_counter_context("series_a_total", 300, 6.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 1);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 3.0) < 0.0001);
    cmt_destroy(context);

    context = create_counter_context("series_b_total", 200, 14.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 0);
    cmt_destroy(context);

    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_max_staleness_evicts_series()
{
    double value;
    struct cmt *context;
    struct cmt_counter *counter;
    struct flb_cumulative_to_delta_ctx *converter;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_KEEP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_configure(converter, 1, 0) == 0);

    context = create_counter_context("stale_series_total", 100, 10.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    sleep(2);

    context = create_counter_context("stale_series_total", 200, 16.0, FLB_FALSE);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    counter = get_first_counter(context);
    TEST_CHECK(map_sample_count(counter->map) == 1);
    value = cmt_metric_get_value(&counter->map->metric);
    TEST_CHECK(fabs(value - 16.0) < 0.0001);
    cmt_destroy(context);

    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_exp_histogram_scale_change_is_coarsened()
{
    double sum;
    uint64_t positive_a[2];
    uint64_t positive_b[4];
    struct cmt *context;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric *metric;
    struct flb_cumulative_to_delta_ctx *converter;

    positive_a[0] = 4;
    positive_a[1] = 8;

    positive_b[0] = 5;
    positive_b[1] = 8;
    positive_b[2] = 11;
    positive_b[3] = 15;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_DROP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_exp_histogram_context("exp_scale_total",
                                           100,
                                           1,
                                           2,
                                           0.0,
                                           0,
                                           2,
                                           positive_a,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           40.0,
                                           10);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    exp_histogram = get_first_exp_histogram(context);
    TEST_CHECK(map_sample_count(exp_histogram->map) == 0);
    cmt_destroy(context);

    context = create_exp_histogram_context("exp_scale_total",
                                           200,
                                           2,
                                           3,
                                           0.0,
                                           0,
                                           4,
                                           positive_b,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           58.0,
                                           18);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    exp_histogram = get_first_exp_histogram(context);
    TEST_CHECK(exp_histogram->aggregation_type == CMT_AGGREGATION_TYPE_DELTA);
    TEST_CHECK(map_sample_count(exp_histogram->map) == 1);

    metric = &exp_histogram->map->metric;
    TEST_CHECK(metric->exp_hist_scale == 1);
    TEST_CHECK(metric->exp_hist_positive_offset == 0);
    TEST_CHECK(metric->exp_hist_positive_count == 2);
    TEST_CHECK(metric->exp_hist_positive_buckets[0] == 9);
    TEST_CHECK(metric->exp_hist_positive_buckets[1] == 18);
    TEST_CHECK(metric->exp_hist_zero_count == 1);
    TEST_CHECK(metric->exp_hist_count == 8);
    sum = cmt_math_uint64_to_d64(metric->exp_hist_sum);
    TEST_CHECK(fabs(sum - 18.0) < 0.0001);
    TEST_CHECK(cmt_metric_has_start_timestamp(metric) == CMT_TRUE);
    TEST_CHECK(cmt_metric_get_start_timestamp(metric) == 100);

    cmt_destroy(context);
    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_exp_histogram_scale_change_is_coarsened_after_otlp_roundtrip()
{
    double sum;
    uint64_t positive_a[2];
    uint64_t positive_b[4];
    struct cmt *context;
    struct cmt *roundtrip;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric *metric;
    struct flb_cumulative_to_delta_ctx *converter;

    positive_a[0] = 4;
    positive_a[1] = 8;

    positive_b[0] = 5;
    positive_b[1] = 8;
    positive_b[2] = 11;
    positive_b[3] = 15;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_DROP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_exp_histogram_context("exp_scale_roundtrip_total",
                                           100,
                                           1,
                                           2,
                                           0.0,
                                           0,
                                           2,
                                           positive_a,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           40.0,
                                           10);
    TEST_CHECK(context != NULL);
    roundtrip = roundtrip_context_through_otlp(context);
    TEST_CHECK(roundtrip != NULL);
    cmt_destroy(context);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, roundtrip) == 0);
    exp_histogram = get_first_exp_histogram(roundtrip);
    TEST_CHECK(map_sample_count(exp_histogram->map) == 0);
    cmt_destroy(roundtrip);

    context = create_exp_histogram_context("exp_scale_roundtrip_total",
                                           200,
                                           2,
                                           3,
                                           0.0,
                                           0,
                                           4,
                                           positive_b,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           58.0,
                                           18);
    TEST_CHECK(context != NULL);
    roundtrip = roundtrip_context_through_otlp(context);
    TEST_CHECK(roundtrip != NULL);
    cmt_destroy(context);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, roundtrip) == 0);

    exp_histogram = get_first_exp_histogram(roundtrip);
    TEST_CHECK(exp_histogram->aggregation_type == CMT_AGGREGATION_TYPE_DELTA);
    TEST_CHECK(map_sample_count(exp_histogram->map) == 1);

    metric = &exp_histogram->map->metric;
    TEST_CHECK(metric->exp_hist_scale == 1);
    TEST_CHECK(metric->exp_hist_positive_offset == 0);
    TEST_CHECK(metric->exp_hist_positive_count == 2);
    TEST_CHECK(metric->exp_hist_positive_buckets[0] == 9);
    TEST_CHECK(metric->exp_hist_positive_buckets[1] == 18);
    TEST_CHECK(metric->exp_hist_zero_count == 1);
    TEST_CHECK(metric->exp_hist_count == 8);
    sum = cmt_math_uint64_to_d64(metric->exp_hist_sum);
    TEST_CHECK(fabs(sum - 18.0) < 0.0001);

    cmt_destroy(roundtrip);
    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_exp_histogram_scale_change_reset_detection()
{
    uint64_t positive_a[2];
    uint64_t positive_b[4];
    uint64_t positive_c[4];
    struct cmt *context;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric *metric;
    struct flb_cumulative_to_delta_ctx *converter;

    positive_a[0] = 4;
    positive_a[1] = 8;

    positive_b[0] = 3;
    positive_b[1] = 0;
    positive_b[2] = 11;
    positive_b[3] = 15;

    positive_c[0] = 4;
    positive_c[1] = 1;
    positive_c[2] = 12;
    positive_c[3] = 17;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_DROP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_exp_histogram_context("exp_scale_reset_total",
                                           100,
                                           1,
                                           0,
                                           0.0,
                                           0,
                                           2,
                                           positive_a,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           10.0,
                                           12);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_exp_histogram_context("exp_scale_reset_total",
                                           200,
                                           2,
                                           0,
                                           0.0,
                                           0,
                                           4,
                                           positive_b,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           16.0,
                                           16);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    exp_histogram = get_first_exp_histogram(context);
    TEST_CHECK(map_sample_count(exp_histogram->map) == 0);
    cmt_destroy(context);

    context = create_exp_histogram_context("exp_scale_reset_total",
                                           300,
                                           2,
                                           0,
                                           0.0,
                                           0,
                                           4,
                                           positive_c,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           20.0,
                                           19);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);

    exp_histogram = get_first_exp_histogram(context);
    metric = &exp_histogram->map->metric;
    TEST_CHECK(map_sample_count(exp_histogram->map) == 1);
    TEST_CHECK(metric->exp_hist_scale == 2);
    TEST_CHECK(metric->exp_hist_positive_count == 4);
    TEST_CHECK(metric->exp_hist_positive_buckets[0] == 1);
    TEST_CHECK(metric->exp_hist_positive_buckets[1] == 1);
    TEST_CHECK(metric->exp_hist_positive_buckets[2] == 1);
    TEST_CHECK(metric->exp_hist_positive_buckets[3] == 2);
    TEST_CHECK(metric->exp_hist_count == 3);

    cmt_destroy(context);
    flb_cumulative_to_delta_ctx_destroy(converter);
}

static void test_exp_histogram_malformed_sample_is_dropped()
{
    uint64_t positive_a[2];
    uint64_t positive_c[2];
    struct cmt *context;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric *metric;
    struct flb_cumulative_to_delta_ctx *converter;

    positive_a[0] = 4;
    positive_a[1] = 8;

    positive_c[0] = 7;
    positive_c[1] = 13;

    converter = flb_cumulative_to_delta_ctx_create(FLB_C2D_INITIAL_VALUE_DROP,
                                                   FLB_TRUE, 0);
    TEST_CHECK(converter != NULL);

    context = create_exp_histogram_context("exp_malformed_total",
                                           100,
                                           1,
                                           1,
                                           0.0,
                                           0,
                                           2,
                                           positive_a,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           20.0,
                                           13);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    cmt_destroy(context);

    context = create_exp_histogram_context("exp_malformed_total",
                                           200,
                                           1,
                                           2,
                                           0.0,
                                           0,
                                           2,
                                           positive_a,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           22.0,
                                           14);
    TEST_CHECK(context != NULL);
    exp_histogram = get_first_exp_histogram(context);
    metric = &exp_histogram->map->metric;
    flb_free(metric->exp_hist_positive_buckets);
    metric->exp_hist_positive_buckets = NULL;
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    TEST_CHECK(map_sample_count(exp_histogram->map) == 0);
    cmt_destroy(context);

    context = create_exp_histogram_context("exp_malformed_total",
                                           300,
                                           1,
                                           3,
                                           0.0,
                                           0,
                                           2,
                                           positive_c,
                                           0,
                                           0,
                                           NULL,
                                           CMT_TRUE,
                                           30.0,
                                           21);
    TEST_CHECK(context != NULL);
    TEST_CHECK(flb_cumulative_to_delta_ctx_process(converter, context) == 0);
    exp_histogram = get_first_exp_histogram(context);
    metric = &exp_histogram->map->metric;
    TEST_CHECK(map_sample_count(exp_histogram->map) == 1);
    TEST_CHECK(metric->exp_hist_positive_buckets[0] == 3);
    TEST_CHECK(metric->exp_hist_positive_buckets[1] == 5);
    TEST_CHECK(metric->exp_hist_zero_count == 2);
    TEST_CHECK(metric->exp_hist_count == 8);
    cmt_destroy(context);

    flb_cumulative_to_delta_ctx_destroy(converter);
}

TEST_LIST = {
    {"counter_drop_first_and_delta", test_counter_drop_first_and_delta},
    {"counter_reset_drop_and_keep", test_counter_reset_drop_and_keep},
    {"histogram_drop_first_and_delta", test_histogram_drop_first_and_delta},
    {"counter_out_of_order_is_dropped", test_counter_out_of_order_is_dropped},
    {"counter_initial_value_auto", test_counter_initial_value_auto},
    {"counter_initial_value_auto_uses_start_timestamp",
     test_counter_initial_value_auto_uses_start_timestamp},
    {"histogram_sum_decrease_without_reset", test_histogram_sum_decrease_without_reset},
    {"non_monotonic_sum_is_not_converted", test_non_monotonic_sum_is_not_converted},
    {"context_attribute_order_does_not_split_series",
     test_context_attribute_order_does_not_split_series},
    {"max_series_evicts_least_recently_used",
     test_max_series_evicts_least_recently_used},
    {"max_staleness_evicts_series",
     test_max_staleness_evicts_series},
    {"exp_histogram_scale_change_is_coarsened",
     test_exp_histogram_scale_change_is_coarsened},
    {"exp_histogram_scale_change_is_coarsened_after_otlp_roundtrip",
     test_exp_histogram_scale_change_is_coarsened_after_otlp_roundtrip},
    {"exp_histogram_scale_change_reset_detection",
     test_exp_histogram_scale_change_reset_detection},
    {"exp_histogram_malformed_sample_is_dropped",
     test_exp_histogram_malformed_sample_is_dropped},
    {0}
};
