/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <math.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_map.h>

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
    {0}
};
