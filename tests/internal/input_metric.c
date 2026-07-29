/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_input_chunk.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_label.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>

#include <cfl/cfl.h>

#include "flb_tests_internal.h"

/*
 * Test: copy_static_labels round-trip
 *
 * Create a cmt with static labels, copy them to a new cmt using
 * cmt_label_add, and verify they match.
 */
static void test_static_labels_copy()
{
    int ret;
    struct cmt *src;
    struct cmt *dst;
    struct cfl_list *head;
    struct cmt_label *label;
    int count;

    src = cmt_create();
    TEST_CHECK(src != NULL);

    /* Add static labels to source */
    ret = cmt_label_add(src, "env", "production");
    TEST_CHECK(ret == 0);
    ret = cmt_label_add(src, "region", "eu-west-1");
    TEST_CHECK(ret == 0);

    /* Create destination and copy labels */
    dst = cmt_create();
    TEST_CHECK(dst != NULL);

    cfl_list_foreach(head, &src->static_labels->list) {
        label = cfl_list_entry(head, struct cmt_label, _head);
        ret = cmt_label_add(dst, label->key, label->val);
        TEST_CHECK(ret == 0);
    }

    /* Verify destination has the same labels */
    count = 0;
    cfl_list_foreach(head, &dst->static_labels->list) {
        count++;
    }
    TEST_CHECK(count == 2);

    cmt_destroy(src);
    cmt_destroy(dst);
}

/*
 * Test: cmt_cat_counter copies a single counter family correctly
 *
 * Create a counter in one cmt, copy it to another via cmt_cat_counter,
 * encode both, and verify the copy has the same data.
 */
static void test_cat_single_counter()
{
    int ret;
    struct cmt *src;
    struct cmt *dst;
    struct cmt_counter *c;
    struct cmt *decoded;
    size_t off;
    char *buf_src = NULL;
    char *buf_dst = NULL;
    size_t size_src;
    size_t size_dst;

    src = cmt_create();
    TEST_CHECK(src != NULL);

    /* Create a counter with 2 label keys */
    c = cmt_counter_create(src, "test", "ns", "requests_total",
                           "Total requests", 2,
                           (char *[]){"method", "status"});
    TEST_CHECK(c != NULL);

    ret = cmt_counter_set(c, 1000000000, 42.0, 2,
                          (char *[]){"GET", "200"});
    TEST_CHECK(ret == 0);

    ret = cmt_counter_set(c, 1000000000, 7.0, 2,
                          (char *[]){"POST", "500"});
    TEST_CHECK(ret == 0);

    /* Copy to destination */
    dst = cmt_create();
    TEST_CHECK(dst != NULL);

    ret = cmt_cat_counter(dst, c, NULL);
    TEST_CHECK(ret == 0);

    /* Encode the destination and decode it back */
    ret = cmt_encode_msgpack_create(dst, &buf_dst, &size_dst);
    TEST_CHECK(ret == 0);

    off = 0;
    ret = cmt_decode_msgpack_create(&decoded, buf_dst, size_dst, &off);
    TEST_CHECK(ret == 0);

    /* Verify the decoded context has exactly 1 counter family */
    TEST_CHECK(cfl_list_size(&decoded->counters) == 1);

    /* Verify the counter values by encoding source and comparing payloads */
    ret = cmt_encode_msgpack_create(src, &buf_src, &size_src);
    TEST_CHECK(ret == 0);
    TEST_CHECK(size_src == size_dst);
    TEST_CHECK(memcmp(buf_src, buf_dst, size_src) == 0);

    cmt_decode_msgpack_destroy(decoded);
    cmt_encode_msgpack_destroy(buf_src);
    cmt_encode_msgpack_destroy(buf_dst);
    cmt_destroy(src);
    cmt_destroy(dst);
}

/*
 * Test: batch splitting preserves all metric families
 *
 * Create a cmt with many counter families, simulate the splitting logic
 * (same as input_metrics_split_and_append), and verify that re-assembling
 * all batches yields the same total number of families.
 */
static void test_batch_split_preserves_families()
{
    int i;
    int ret;
    int total_families = 20;
    int families_per_batch = 5;
    int batch_count = 0;
    int total_batches = 0;
    int total_recovered = 0;
    char name[64];
    struct cmt *src;
    struct cmt *batch = NULL;
    struct cmt_counter *c;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_counter *counter;
    char *mt_buf;
    size_t mt_size;
    struct cmt *decoded;
    size_t off;

    src = cmt_create();
    TEST_CHECK(src != NULL);

    /* Create many counter families */
    for (i = 0; i < total_families; i++) {
        snprintf(name, sizeof(name), "metric_%d", i);
        c = cmt_counter_create(src, "test", "ns", name,
                               "A test counter", 0, NULL);
        TEST_CHECK(c != NULL);
        ret = cmt_counter_set(c, 1000000000, (double) i, 0, NULL);
        TEST_CHECK(ret == 0);
    }

    /* Verify source has the expected number of counter families */
    TEST_CHECK(cfl_list_size(&src->counters) == total_families);

    /* Simulate the splitting logic from input_metrics_split_and_append */
    cfl_list_foreach_safe(head, tmp, &src->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);

        if (batch == NULL) {
            batch = cmt_create();
            TEST_CHECK(batch != NULL);
            batch_count = 0;
        }

        ret = cmt_cat_counter(batch, counter, NULL);
        TEST_CHECK(ret == 0);
        batch_count++;

        if (batch_count >= families_per_batch) {
            /* Encode the batch */
            ret = cmt_encode_msgpack_create(batch, &mt_buf, &mt_size);
            TEST_CHECK(ret == 0);

            /* Decode it back and count families */
            off = 0;
            ret = cmt_decode_msgpack_create(&decoded, mt_buf, mt_size, &off);
            TEST_CHECK(ret == 0);

            total_recovered += cfl_list_size(&decoded->counters);

            cmt_decode_msgpack_destroy(decoded);
            cmt_encode_msgpack_destroy(mt_buf);
            cmt_destroy(batch);
            batch = NULL;
            total_batches++;
        }
    }

    /* Flush remaining */
    if (batch != NULL) {
        ret = cmt_encode_msgpack_create(batch, &mt_buf, &mt_size);
        TEST_CHECK(ret == 0);

        off = 0;
        ret = cmt_decode_msgpack_create(&decoded, mt_buf, mt_size, &off);
        TEST_CHECK(ret == 0);

        total_recovered += cfl_list_size(&decoded->counters);

        cmt_decode_msgpack_destroy(decoded);
        cmt_encode_msgpack_destroy(mt_buf);
        cmt_destroy(batch);
        batch = NULL;
        total_batches++;
    }

    /* Verify all families were recovered across all batches */
    TEST_CHECK(total_recovered == total_families);

    /* Verify expected number of batches (20 families / 5 per batch = 4) */
    TEST_CHECK(total_batches == 4);

    cmt_destroy(src);
}

/*
 * Test: batch splitting with mixed metric types
 *
 * Create a cmt with counters and gauges, split into batches, and verify
 * the total family count across all batches matches the original.
 */
static void test_batch_split_mixed_types()
{
    int i;
    int ret;
    int total_families;
    int families_per_batch = 3;
    int batch_count = 0;
    int total_recovered = 0;
    char name[64];
    struct cmt *src;
    struct cmt *batch = NULL;
    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    char *mt_buf;
    size_t mt_size;
    struct cmt *decoded;
    size_t off;

    src = cmt_create();
    TEST_CHECK(src != NULL);

    /* Create 5 counters and 5 gauges = 10 total families */
    for (i = 0; i < 5; i++) {
        snprintf(name, sizeof(name), "counter_%d", i);
        c = cmt_counter_create(src, "test", "ns", name,
                               "A counter", 0, NULL);
        TEST_CHECK(c != NULL);
        cmt_counter_set(c, 1000000000, (double) i, 0, NULL);
    }
    for (i = 0; i < 5; i++) {
        snprintf(name, sizeof(name), "gauge_%d", i);
        g = cmt_gauge_create(src, "test", "ns", name,
                             "A gauge", 0, NULL);
        TEST_CHECK(g != NULL);
        cmt_gauge_set(g, 1000000000, (double) (i * 10), 0, NULL);
    }

    total_families = cfl_list_size(&src->counters) +
                     cfl_list_size(&src->gauges);
    TEST_CHECK(total_families == 10);

    /*
     * Simulate split: process counters first, then gauges.
     * Same order as input_metrics_split_and_append.
     */
    cfl_list_foreach_safe(head, tmp, &src->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);

        if (batch == NULL) {
            batch = cmt_create();
            TEST_CHECK(batch != NULL);
            batch_count = 0;
        }

        ret = cmt_cat_counter(batch, counter, NULL);
        TEST_CHECK(ret == 0);
        batch_count++;

        if (batch_count >= families_per_batch) {
            ret = cmt_encode_msgpack_create(batch, &mt_buf, &mt_size);
            TEST_CHECK(ret == 0);
            off = 0;
            ret = cmt_decode_msgpack_create(&decoded, mt_buf, mt_size, &off);
            TEST_CHECK(ret == 0);
            total_recovered += cfl_list_size(&decoded->counters) +
                               cfl_list_size(&decoded->gauges);
            cmt_decode_msgpack_destroy(decoded);
            cmt_encode_msgpack_destroy(mt_buf);
            cmt_destroy(batch);
            batch = NULL;
        }
    }

    cfl_list_foreach_safe(head, tmp, &src->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);

        if (batch == NULL) {
            batch = cmt_create();
            TEST_CHECK(batch != NULL);
            batch_count = 0;
        }

        ret = cmt_cat_gauge(batch, gauge, NULL);
        TEST_CHECK(ret == 0);
        batch_count++;

        if (batch_count >= families_per_batch) {
            ret = cmt_encode_msgpack_create(batch, &mt_buf, &mt_size);
            TEST_CHECK(ret == 0);
            off = 0;
            ret = cmt_decode_msgpack_create(&decoded, mt_buf, mt_size, &off);
            TEST_CHECK(ret == 0);
            total_recovered += cfl_list_size(&decoded->counters) +
                               cfl_list_size(&decoded->gauges);
            cmt_decode_msgpack_destroy(decoded);
            cmt_encode_msgpack_destroy(mt_buf);
            cmt_destroy(batch);
            batch = NULL;
        }
    }

    /* Flush remaining */
    if (batch != NULL) {
        ret = cmt_encode_msgpack_create(batch, &mt_buf, &mt_size);
        TEST_CHECK(ret == 0);
        off = 0;
        ret = cmt_decode_msgpack_create(&decoded, mt_buf, mt_size, &off);
        TEST_CHECK(ret == 0);
        total_recovered += cfl_list_size(&decoded->counters) +
                           cfl_list_size(&decoded->gauges);
        cmt_decode_msgpack_destroy(decoded);
        cmt_encode_msgpack_destroy(mt_buf);
        cmt_destroy(batch);
        batch = NULL;
    }

    /* All 10 families must be recovered */
    TEST_CHECK(total_recovered == 10);

    cmt_destroy(src);
}

/*
 * Test: empty cmt context produces zero families
 */
static void test_empty_context()
{
    struct cmt *src;

    src = cmt_create();
    TEST_CHECK(src != NULL);

    TEST_CHECK(cfl_list_size(&src->counters) == 0);
    TEST_CHECK(cfl_list_size(&src->gauges) == 0);
    TEST_CHECK(cfl_list_size(&src->histograms) == 0);
    TEST_CHECK(cfl_list_size(&src->summaries) == 0);
    TEST_CHECK(cfl_list_size(&src->untypeds) == 0);
    TEST_CHECK(cfl_list_size(&src->exp_histograms) == 0);

    cmt_destroy(src);
}

/*
 * Test: families_per_batch calculation
 *
 * Verify the batch size estimation: given total_families, total_encoded_size,
 * and FLB_INPUT_CHUNK_FS_MAX_SIZE (2MB), the formula should produce sensible
 * batch sizes.
 */
static void test_families_per_batch_calculation()
{
    int families_per_batch;
    uint64_t numerator;

    /* Case 1: 100 families, 10MB total -> ~20 families per 2MB batch */
    numerator = (uint64_t) 100 * FLB_INPUT_CHUNK_FS_MAX_SIZE;
    families_per_batch = (int) (numerator / (10 * 1024 * 1024));
    TEST_CHECK(families_per_batch == 19);  /* 100 * 2048000 / 10485760 = 19 */

    /* Case 2: 1 family, 5MB total -> clamp to 1 */
    numerator = (uint64_t) 1 * FLB_INPUT_CHUNK_FS_MAX_SIZE;
    families_per_batch = (int) (numerator / (5 * 1024 * 1024));
    if (families_per_batch < 1) {
        families_per_batch = 1;
    }
    TEST_CHECK(families_per_batch == 1);

    /* Case 3: 1000 families, 4MB total -> ~500 families per 2MB batch */
    numerator = (uint64_t) 1000 * FLB_INPUT_CHUNK_FS_MAX_SIZE;
    families_per_batch = (int) (numerator / (4 * 1024 * 1024));
    TEST_CHECK(families_per_batch == 488);  /* 1000 * 2048000 / 4194304 = 488 */
}

TEST_LIST = {
    { "static_labels_copy",             test_static_labels_copy},
    { "cat_single_counter",             test_cat_single_counter},
    { "batch_split_preserves_families", test_batch_split_preserves_families},
    { "batch_split_mixed_types",        test_batch_split_mixed_types},
    { "empty_context",                  test_empty_context},
    { "families_per_batch_calculation", test_families_per_batch_calculation},
    { 0 }
};
