#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_histogram.h>

static uint64_t monotonic_ns(void)
{
#ifdef _WIN32
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;

    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (uint64_t) (counter.QuadPart / frequency.QuadPart) * 1000000000ULL +
           (uint64_t) (counter.QuadPart % frequency.QuadPart) * 1000000000ULL /
           frequency.QuadPart;
#else
    struct timespec timestamp;

    clock_gettime(CLOCK_MONOTONIC, &timestamp);

    return (uint64_t) timestamp.tv_sec * 1000000000ULL + timestamp.tv_nsec;
#endif
}

static size_t parse_size(const char *text, const char *name)
{
    char *end;
    unsigned long long value;

    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || *text == '\0' || *end != '\0' || value == 0) {
        fprintf(stderr, "invalid %s: %s\n", name, text);
        exit(EXIT_FAILURE);
    }

    return (size_t) value;
}

static struct cmt_counter *create_series(struct cmt *cmt, size_t cardinality)
{
    size_t index;
    int result;
    char label[32];
    char *values[] = {label};
    struct cmt_counter *counter;

    counter = cmt_counter_create(cmt, "bench", "", "counter", "benchmark",
                                 1, (char *[]) {"series"});
    if (counter == NULL) {
        return NULL;
    }

    for (index = 0; index < cardinality; index++) {
        snprintf(label, sizeof(label), "series-%zu", index);
        result = cmt_counter_set(counter, 1, 1.0, 1, values);
        if (result != 0) {
            return NULL;
        }
    }

    return counter;
}

static int create_mixed_series(struct cmt *cmt, size_t cardinality)
{
    size_t index;
    char label[32];
    char *values[] = {label};
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_histogram *histogram;
    struct cmt_histogram_buckets *buckets;

    counter = cmt_counter_create(cmt, "bench", "", "requests_total",
                                 "benchmark counter", 1,
                                 (char *[]) {"series"});
    gauge = cmt_gauge_create(cmt, "bench", "", "queue_depth",
                             "benchmark gauge", 1,
                             (char *[]) {"series"});
    buckets = cmt_histogram_buckets_create(4, 0.01, 0.1, 1.0, 10.0);
    histogram = cmt_histogram_create(cmt, "bench", "", "latency_seconds",
                                     "benchmark histogram", buckets, 1,
                                     (char *[]) {"series"});
    if (counter == NULL || gauge == NULL || buckets == NULL ||
        histogram == NULL) {
        return -1;
    }

    for (index = 0; index < cardinality; index++) {
        snprintf(label, sizeof(label), "series-%zu", index);
        if (cmt_counter_set(counter, index + 1, 1.0, 1, values) != 0 ||
            cmt_gauge_set(gauge, index + 1, (double) index, 1, values) != 0 ||
            cmt_histogram_observe(histogram, index + 1,
                                  (double) (index % 100) / 10.0,
                                  1, values) != 0) {
            return -1;
        }
    }

    return 0;
}

static int benchmark_lookup(size_t cardinality, size_t operations)
{
    size_t index;
    int result;
    double value;
    uint64_t start;
    uint64_t elapsed;
    char label[32];
    char *values[] = {label};
    struct cmt *cmt;
    struct cmt_counter *counter;

    cmt = cmt_create();
    if (cmt == NULL) {
        return -1;
    }

    counter = create_series(cmt, cardinality);
    if (counter == NULL) {
        cmt_destroy(cmt);
        return -1;
    }

    start = monotonic_ns();
    for (index = 0; index < operations; index++) {
        snprintf(label, sizeof(label), "series-%zu", index % cardinality);
        result = cmt_counter_get_val(counter, 1, values, &value);
        if (result != 0 || value != 1.0) {
            cmt_destroy(cmt);
            return -1;
        }
    }
    elapsed = monotonic_ns() - start;

    printf("benchmark=lookup cardinality=%zu operations=%zu elapsed_ns=%" PRIu64
           " ns_per_op=%.2f ops_per_second=%.2f\n",
           cardinality, operations, elapsed, (double) elapsed / operations,
           (double) operations * 1000000000.0 / elapsed);
    cmt_destroy(cmt);
    return 0;
}

static int benchmark_update(size_t cardinality, size_t operations)
{
    size_t index;
    int result;
    uint64_t start;
    uint64_t elapsed;
    char label[32];
    char *values[] = {label};
    struct cmt *cmt;
    struct cmt_counter *counter;

    cmt = cmt_create();
    if (cmt == NULL) {
        return -1;
    }

    counter = create_series(cmt, cardinality);
    if (counter == NULL) {
        cmt_destroy(cmt);
        return -1;
    }

    start = monotonic_ns();
    for (index = 0; index < operations; index++) {
        snprintf(label, sizeof(label), "series-%zu", index % cardinality);
        result = cmt_counter_inc(counter, index + 2, 1, values);
        if (result != 0) {
            cmt_destroy(cmt);
            return -1;
        }
    }
    elapsed = monotonic_ns() - start;

    printf("benchmark=update cardinality=%zu operations=%zu elapsed_ns=%" PRIu64
           " ns_per_op=%.2f ops_per_second=%.2f\n",
           cardinality, operations, elapsed, (double) elapsed / operations,
           (double) operations * 1000000000.0 / elapsed);
    cmt_destroy(cmt);
    return 0;
}

static int benchmark_prometheus(size_t cardinality, size_t operations)
{
    size_t index;
    size_t bytes = 0;
    uint64_t start;
    uint64_t elapsed;
    cfl_sds_t output;
    struct cmt *cmt;

    cmt = cmt_create();
    if (cmt == NULL) {
        return -1;
    }

    if (create_series(cmt, cardinality) == NULL) {
        cmt_destroy(cmt);
        return -1;
    }

    start = monotonic_ns();
    for (index = 0; index < operations; index++) {
        output = cmt_encode_prometheus_create(cmt, CMT_FALSE);
        if (output == NULL) {
            cmt_destroy(cmt);
            return -1;
        }
        bytes += cfl_sds_len(output);
        cmt_encode_prometheus_destroy(output);
    }
    elapsed = monotonic_ns() - start;

    printf("benchmark=prometheus cardinality=%zu operations=%zu bytes=%zu "
           "elapsed_ns=%" PRIu64 " ns_per_op=%.2f mb_per_second=%.2f\n",
           cardinality, operations, bytes, elapsed, (double) elapsed / operations,
           ((double) bytes / (1024.0 * 1024.0)) /
           ((double) elapsed / 1000000000.0));
    cmt_destroy(cmt);
    return 0;
}

static int benchmark_opentelemetry(size_t cardinality, size_t operations)
{
    size_t index;
    size_t bytes;
    uint64_t start;
    uint64_t elapsed;
    cfl_sds_t output;
    struct cmt *cmt;

    bytes = 0;
    cmt = cmt_create();
    if (cmt == NULL) {
        return -1;
    }

    if (create_series(cmt, cardinality) == NULL) {
        cmt_destroy(cmt);
        return -1;
    }

    start = monotonic_ns();
    for (index = 0; index < operations; index++) {
        output = cmt_encode_opentelemetry_create(cmt);
        if (output == NULL) {
            cmt_destroy(cmt);
            return -1;
        }
        bytes += cfl_sds_len(output);
        cmt_encode_opentelemetry_destroy(output);
    }
    elapsed = monotonic_ns() - start;

    printf("benchmark=opentelemetry cardinality=%zu operations=%zu bytes=%zu "
           "elapsed_ns=%" PRIu64 " ns_per_op=%.2f mb_per_second=%.2f\n",
           cardinality, operations, bytes, elapsed, (double) elapsed / operations,
           ((double) bytes / (1024.0 * 1024.0)) /
           ((double) elapsed / 1000000000.0));
    cmt_destroy(cmt);
    return 0;
}

static int benchmark_opentelemetry_mixed(size_t cardinality, size_t operations)
{
    size_t index;
    size_t bytes;
    uint64_t start;
    uint64_t elapsed;
    cfl_sds_t output;
    struct cmt *cmt;

    bytes = 0;
    cmt = cmt_create();
    if (cmt == NULL || create_mixed_series(cmt, cardinality) != 0) {
        cmt_destroy(cmt);
        return -1;
    }

    start = monotonic_ns();
    for (index = 0; index < operations; index++) {
        output = cmt_encode_opentelemetry_create(cmt);
        if (output == NULL) {
            cmt_destroy(cmt);
            return -1;
        }
        bytes += cfl_sds_len(output);
        cmt_encode_opentelemetry_destroy(output);
    }
    elapsed = monotonic_ns() - start;

    printf("benchmark=opentelemetry-mixed cardinality=%zu operations=%zu "
           "bytes=%zu elapsed_ns=%" PRIu64 " ns_per_op=%.2f "
           "mb_per_second=%.2f\n",
           cardinality, operations, bytes, elapsed,
           (double) elapsed / operations,
           ((double) bytes / (1024.0 * 1024.0)) /
           ((double) elapsed / 1000000000.0));
    cmt_destroy(cmt);
    return 0;
}

static int benchmark_cat(size_t cardinality, size_t operations)
{
    size_t source_index;
    size_t series_index;
    size_t total;
    int result = -1;
    uint64_t start;
    uint64_t elapsed;
    double value;
    char source_label[32];
    char series_label[32];
    char *keys[] = {"source", "series"};
    char *values[] = {source_label, series_label};
    struct cmt **sources;
    struct cmt *destination;
    struct cmt_counter *counter;

    if (operations > SIZE_MAX / cardinality) {
        return -1;
    }
    total = operations * cardinality;
    sources = calloc(operations, sizeof(*sources));
    destination = cmt_create();
    if (sources == NULL || destination == NULL) {
        free(sources);
        if (destination != NULL) {
            cmt_destroy(destination);
        }
        return -1;
    }
    for (source_index = 0; source_index < operations; source_index++) {
        sources[source_index] = cmt_create();
        if (sources[source_index] == NULL) {
            goto cleanup;
        }
        counter = cmt_counter_create(sources[source_index], "bench", "", "counter",
                                     "benchmark", 2, keys);
        if (counter == NULL) {
            goto cleanup;
        }
        snprintf(source_label, sizeof(source_label), "%zu", source_index);
        for (series_index = 0; series_index < cardinality; series_index++) {
            snprintf(series_label, sizeof(series_label), "%zu", series_index);
            if (cmt_counter_set(counter, 1, (double) series_index, 2, values) != 0) {
                goto cleanup;
            }
        }
    }
    start = monotonic_ns();
    for (source_index = 0; source_index < operations; source_index++) {
        if (cmt_cat(destination, sources[source_index]) != 0) {
            goto cleanup;
        }
    }
    elapsed = monotonic_ns() - start;
    counter = cfl_list_entry(destination->counters.next, struct cmt_counter, _head);
    if ((size_t) cfl_list_size(&counter->map->metrics) != total) {
        goto cleanup;
    }
    for (source_index = 0; source_index < operations; source_index++) {
        snprintf(source_label, sizeof(source_label), "%zu", source_index);
        for (series_index = 0; series_index < cardinality; series_index++) {
            snprintf(series_label, sizeof(series_label), "%zu", series_index);
            if (cmt_counter_get_val(counter, 2, values, &value) != 0 ||
                value != (double) series_index) {
                goto cleanup;
            }
        }
    }
    printf("benchmark=cat cardinality=%zu operations=%zu series=%zu elapsed_ns=%"
           PRIu64 " ns_per_series=%.2f\n", cardinality, operations, total,
           elapsed, (double) elapsed / total);
    result = 0;

cleanup:
    for (source_index = 0; source_index < operations; source_index++) {
        if (sources[source_index] != NULL) {
            cmt_destroy(sources[source_index]);
        }
    }
    free(sources);
    cmt_destroy(destination);
    return result;
}

int main(int argc, char **argv)
{
    size_t cardinality;
    size_t operations;

    if (argc != 4) {
        fprintf(stderr, "usage: %s cat|lookup|update|prometheus|opentelemetry|"
                        "opentelemetry-mixed "
                        "CARDINALITY OPERATIONS\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    cardinality = parse_size(argv[2], "cardinality");
    operations = parse_size(argv[3], "operations");
    cmt_initialize();

    if (strcmp(argv[1], "cat") == 0) {
        return benchmark_cat(cardinality, operations) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (strcmp(argv[1], "lookup") == 0) {
        return benchmark_lookup(cardinality, operations) == 0 ?
               EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (strcmp(argv[1], "update") == 0) {
        return benchmark_update(cardinality, operations) == 0 ?
               EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (strcmp(argv[1], "prometheus") == 0) {
        return benchmark_prometheus(cardinality, operations) == 0 ?
               EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (strcmp(argv[1], "opentelemetry") == 0) {
        return benchmark_opentelemetry(cardinality, operations) == 0 ?
               EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (strcmp(argv[1], "opentelemetry-mixed") == 0) {
        return benchmark_opentelemetry_mixed(cardinality, operations) == 0 ?
               EXIT_SUCCESS : EXIT_FAILURE;
    }

    fprintf(stderr, "unknown benchmark: %s\n", argv[1]);
    return EXIT_FAILURE;
}
