/*
 * Generator for histogram-cumulative-v5.1.0.msgpack, a fixture written by the
 * bundled CMetrics library of Fluent Bit v5.1.0. It holds the native layout
 * that release used for histograms built with cmt_histogram_observe() or
 * decoded from Prometheus: cumulative buckets [1, 3, 5, 6], bounds
 * [0.1, 0.5, 1] and count 6, once as the static sample and once labeled
 * path="/a". The chunk is unmarked; readers infer the layout per sample.
 *
 * Build it against the headers and static libraries of a v5.1.0 checkout and
 * redirect stdout to the fixture. The fixture is versioned on purpose: tests
 * must never regenerate it with the current encoder.
 */
#include <stdio.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_encode_msgpack.h>
int main(void)
{
    struct cmt *ctx = cmt_create();
    struct cmt_histogram *h;
    char *keys[] = {"path"};
    char *vals[] = {"/a"};
    double samples[] = {0.05, 0.2, 0.3, 0.7, 0.8, 2.0};
    char *buffer;
    size_t size;
    int i;
    h = cmt_histogram_create(ctx, "", "", "req_seconds", "request latency",
                             cmt_histogram_buckets_create(3, 0.1, 0.5, 1.0), 1, keys);
    for (i = 0; i < 6; i++) {
        cmt_histogram_observe(h, 100, samples[i], 1, vals);
        cmt_histogram_observe(h, 100, samples[i], 0, NULL);
    }
    if (cmt_encode_msgpack_create(ctx, &buffer, &size) != 0) { return 1; }
    fwrite(buffer, 1, size, stdout);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
    return 0;
}
