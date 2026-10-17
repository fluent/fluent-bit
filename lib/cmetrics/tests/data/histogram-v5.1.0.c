/*
 * Generator for histogram-v5.1.0.msgpack, a fixture written by the bundled
 * CMetrics library of Fluent Bit v5.1.0. It holds an OTLP-style histogram with
 * independent bucket counts [5, 1, 3], count 9, sum 12 and bounds [1, 2]; that
 * release stored OTLP-decoded histograms in this representation and wrote no
 * bucket-layout marker.
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
    uint64_t buckets[] = {5, 1, 3};
    char *buffer;
    size_t size;
    h = cmt_histogram_create(ctx, "", "", "legacy_histogram", "legacy", 
                            cmt_histogram_buckets_create(2, 1.0, 2.0), 0, NULL);
    h->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
    cmt_histogram_set_default(h, 100, buckets, 12.0, 9, 0, NULL);
    if (cmt_encode_msgpack_create(ctx, &buffer, &size) != 0) { return 1; }
    fwrite(buffer, 1, size, stdout);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
    return 0;
}
