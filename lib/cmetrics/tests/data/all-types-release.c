/*
 * Generator for all-types-v5.0.0.msgpack, all-types-v5.0.11.msgpack and
 * all-types-v5.1.5.msgpack: one context with every metric type, written by the
 * CMetrics library bundled with that Fluent Bit release (2.0.5, 2.1.5 and
 * 2.2.5). These are the payloads those agents send over forward and keep in
 * filesystem chunks, so current readers must keep decoding them.
 *
 * Build it against the headers and static libraries of lib/cmetrics, lib/cfl
 * and lib/fluent-otel-proto from the Fluent Bit release tag and redirect stdout
 * to the fixture. The fixtures are versioned on purpose: tests must never
 * regenerate them with the current encoder. tests/msgpack_compat.c asserts
 * the values below.
 */
#include <stdio.h>
#include <stdint.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_encode_msgpack.h>

int main(void)
{
    struct cmt *ctx = cmt_create();
    struct cmt_counter *counter;
    struct cmt_counter *delta;
    struct cmt_gauge *gauge;
    struct cmt_gauge *signed_gauge;
    struct cmt_gauge *unsigned_gauge;
    struct cmt_untyped *untyped;
    struct cmt_histogram *histogram;
    struct cmt_summary *summary;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric *metric;
    double quantiles[] = {0.5, 0.9};
    double quantile_values[] = {0.2, 0.8};
    uint64_t buckets[] = {1, 3, 4, 5};
    uint64_t positive[] = {1, 2};
    uint64_t negative[] = {3};
    char *buffer;
    size_t size;

    cmt_label_add(ctx, "cluster", "prod");

    counter = cmt_counter_create(ctx, "fixture", "http", "requests_total", "requests",
                                 1, (char *[]) {"method"});
    cmt_counter_set(counter, 1000, 10, 1, (char *[]) {"GET"});
    cmt_counter_set(counter, 1000, 4, 1, (char *[]) {"POST"});
    metric = cmt_map_metric_get(&counter->opts, counter->map, 1, (char *[]) {"GET"}, 0);
    cmt_metric_set_start_timestamp(metric, 500);

    delta = cmt_counter_create(ctx, "", "", "fixture_delta_total", "delta", 0, NULL);
    delta->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
    cmt_counter_allow_reset(delta);
    cmt_counter_set(delta, 1000, 3, 0, NULL);

    gauge = cmt_gauge_create(ctx, "", "", "fixture_temperature", "temperature",
                             1, (char *[]) {"room"});
    cmt_gauge_set(gauge, 1000, -12.5, 1, (char *[]) {"lab"});
    cmt_gauge_set(gauge, 1000, 21, 1, (char *[]) {""});

    signed_gauge = cmt_gauge_create(ctx, "", "", "fixture_signed", "signed", 0, NULL);
    cmt_gauge_set(signed_gauge, 1000, 0, 0, NULL);
    cmt_metric_set_int64(&signed_gauge->map->metric, 1000, -9007199254740993LL);

    unsigned_gauge = cmt_gauge_create(ctx, "", "", "fixture_unsigned", "unsigned", 0, NULL);
    cmt_gauge_set(unsigned_gauge, 1000, 0, 0, NULL);
    cmt_metric_set_uint64(&unsigned_gauge->map->metric, 1000, UINT64_MAX);

    untyped = cmt_untyped_create(ctx, "", "", "fixture_untyped", "untyped",
                                 1, (char *[]) {"k"});
    cmt_untyped_set(untyped, 1000, 1.5, 1, (char *[]) {"v"});

    histogram = cmt_histogram_create(ctx, "", "", "fixture_latency_seconds", "latency",
                                     cmt_histogram_buckets_create(3, 0.1, 1.0, 10.0),
                                     1, (char *[]) {"route"});
    histogram->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;
    histogram->map->unit = cfl_sds_create("s");
    cmt_histogram_set_default(histogram, 1000, buckets, 6.5, 5, 1, (char *[]) {"/"});

    summary = cmt_summary_create(ctx, "", "", "fixture_rpc_seconds", "rpc", 2, quantiles,
                                 1, (char *[]) {"svc"});
    cmt_summary_set_default(summary, 1000, quantile_values, 10, 20, 1, (char *[]) {"api"});

    exp_histogram = cmt_exp_histogram_create(ctx, "", "", "fixture_exp", "exp",
                                             1, (char *[]) {"op"});
    exp_histogram->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
    cmt_exp_histogram_set_default(exp_histogram, 1000, 2, 1, 0.001, -1, 2, positive,
                                  0, 1, negative, 1, 4.5, 7, 1, (char *[]) {"read"});

    if (cmt_encode_msgpack_create(ctx, &buffer, &size) != 0) {
        return 1;
    }
    fwrite(buffer, 1, size, stdout);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
    return 0;
}
