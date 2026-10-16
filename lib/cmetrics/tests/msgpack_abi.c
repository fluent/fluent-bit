/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2026 The CMetrics Authors
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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <string.h>

#include "cmt_tests.h"

static int contains_bytes(const char *buffer, size_t buffer_length,
                          const char *needle, size_t needle_length)
{
    size_t index;

    if (buffer == NULL || needle == NULL || needle_length == 0 ||
        buffer_length < needle_length) {
        return CMT_FALSE;
    }

    for (index = 0; index <= buffer_length - needle_length; index++) {
        if (memcmp(&buffer[index], needle, needle_length) == 0) {
            return CMT_TRUE;
        }
    }

    return CMT_FALSE;
}

static int patch_nth_key_array_size(char *buffer, size_t buffer_size,
                                    const char *key, int occurrence,
                                    uint8_t new_array_tag)
{
    size_t index;
    size_t key_len;
    int found_count;

    if (buffer == NULL || key == NULL || occurrence <= 0) {
        return -1;
    }

    key_len = strlen(key);
    found_count = 0;

    for (index = 0; index + key_len < buffer_size; index++) {
        if (memcmp(&buffer[index], key, key_len) == 0) {
            int is_key_token = CMT_FALSE;

            if (index >= 1 &&
                (unsigned char) buffer[index - 1] == (0xa0 | key_len)) {
                is_key_token = CMT_TRUE;
            }
            else if (index >= 2 &&
                     (unsigned char) buffer[index - 2] == 0xd9 &&
                     (unsigned char) buffer[index - 1] == key_len) {
                is_key_token = CMT_TRUE;
            }
            else if (index >= 3 &&
                     (unsigned char) buffer[index - 3] == 0xda &&
                     (((unsigned char) buffer[index - 2] << 8) |
                      (unsigned char) buffer[index - 1]) == key_len) {
                is_key_token = CMT_TRUE;
            }

            if (!is_key_token) {
                continue;
            }

            found_count++;
            if (found_count == occurrence) {
                if (index + key_len >= buffer_size) {
                    return -1;
                }

                if (((unsigned char) buffer[index + key_len] & 0xf0) != 0x90) {
                    return -1;
                }

                buffer[index + key_len] = (char) new_array_tag;
                return 0;
            }
        }
    }

    return -1;
}

void test_msgpack_abi_legacy_value_only_decode()
{
    int ret;
    size_t offset;
    char *payload;
    size_t payload_size;
    struct cmt *input_cmt;
    struct cmt *output_cmt;
    struct cmt_gauge *input_gauge;
    struct cmt_gauge *output_gauge;

    cmt_initialize();

    input_cmt = cmt_create();
    TEST_CHECK(input_cmt != NULL);
    if (input_cmt == NULL) {
        return;
    }

    input_gauge = cmt_gauge_create(input_cmt, "ns", "sub", "legacy_value", "legacy", 0, NULL);
    TEST_CHECK(input_gauge != NULL);
    if (input_gauge == NULL) {
        cmt_destroy(input_cmt);
        return;
    }

    cmt_gauge_set(input_gauge, 111, 42.25, 0, NULL);

    payload = NULL;
    payload_size = 0;
    ret = cmt_encode_msgpack_create(input_cmt, &payload, &payload_size);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cmt_destroy(input_cmt);
        return;
    }

    TEST_CHECK(contains_bytes(payload, payload_size, "value_int64", 11) == CMT_FALSE);
    TEST_CHECK(contains_bytes(payload, payload_size, "value_uint64", 12) == CMT_FALSE);

    offset = 0;
    output_cmt = NULL;
    ret = cmt_decode_msgpack_create(&output_cmt, payload, payload_size, &offset);
    TEST_CHECK(ret == 0);
    TEST_CHECK(output_cmt != NULL);

    if (ret == 0 && output_cmt != NULL) {
        output_gauge = cfl_list_entry_first(&output_cmt->gauges, struct cmt_gauge, _head);
        TEST_CHECK(output_gauge != NULL);
        if (output_gauge != NULL) {
            TEST_CHECK(output_gauge->map->metric_static_set == CMT_TRUE);
            TEST_CHECK(cmt_metric_get_value_type(&output_gauge->map->metric) == CMT_METRIC_VALUE_DOUBLE);
            TEST_CHECK(cmt_metric_get_value(&output_gauge->map->metric) == 42.25);
        }
    }

    cmt_destroy(input_cmt);
    if (output_cmt != NULL) {
        cmt_decode_msgpack_destroy(output_cmt);
    }
    cmt_encode_msgpack_destroy(payload);
}

void test_msgpack_abi_typed_int64_decode()
{
    int ret;
    size_t offset;
    char *payload;
    size_t payload_size;
    struct cmt *input_cmt;
    struct cmt *output_cmt;
    struct cmt_gauge *input_gauge;
    struct cmt_gauge *output_gauge;
    int64_t expected_value;

    cmt_initialize();

    input_cmt = cmt_create();
    TEST_CHECK(input_cmt != NULL);
    if (input_cmt == NULL) {
        return;
    }

    input_gauge = cmt_gauge_create(input_cmt, "ns", "sub", "typed_int", "typed", 0, NULL);
    TEST_CHECK(input_gauge != NULL);
    if (input_gauge == NULL) {
        cmt_destroy(input_cmt);
        return;
    }

    expected_value = 9007199254740993LL;
    cmt_gauge_set(input_gauge, 123, 0, 0, NULL);
    cmt_metric_set_int64(&input_gauge->map->metric, 123, expected_value);
    input_gauge->map->metric_static_set = CMT_TRUE;

    payload = NULL;
    payload_size = 0;
    ret = cmt_encode_msgpack_create(input_cmt, &payload, &payload_size);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cmt_destroy(input_cmt);
        return;
    }

    TEST_CHECK(contains_bytes(payload, payload_size, "value_type", 10) == CMT_TRUE);
    TEST_CHECK(contains_bytes(payload, payload_size, "value_int64", 11) == CMT_TRUE);

    offset = 0;
    output_cmt = NULL;
    ret = cmt_decode_msgpack_create(&output_cmt, payload, payload_size, &offset);
    TEST_CHECK(ret == 0);
    TEST_CHECK(output_cmt != NULL);

    if (ret == 0 && output_cmt != NULL) {
        output_gauge = cfl_list_entry_first(&output_cmt->gauges, struct cmt_gauge, _head);
        TEST_CHECK(output_gauge != NULL);
        if (output_gauge != NULL) {
            TEST_CHECK(output_gauge->map->metric_static_set == CMT_TRUE);
            TEST_CHECK(cmt_metric_get_value_type(&output_gauge->map->metric) == CMT_METRIC_VALUE_INT64);
            TEST_CHECK(cmt_metric_get_int64_value(&output_gauge->map->metric) == expected_value);
        }
    }

    cmt_destroy(input_cmt);
    if (output_cmt != NULL) {
        cmt_decode_msgpack_destroy(output_cmt);
    }
    cmt_encode_msgpack_destroy(payload);
}

void test_msgpack_abi_summary_quantiles_reject_mismatch()
{
    int ret;
    size_t offset;
    char *payload;
    size_t payload_size;
    double quantiles[2];
    struct cmt *cmt;
    struct cmt_summary *summary;
    struct cmt *decoded_cmt;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);
    if (cmt == NULL) {
        return;
    }

    quantiles[0] = 0.5;
    quantiles[1] = 0.9;

    summary = cmt_summary_create(cmt, "ns", "sub", "sum", "summary", 2, quantiles, 0, NULL);
    TEST_CHECK(summary != NULL);
    if (summary == NULL) {
        cmt_destroy(cmt);
        return;
    }

    cmt_summary_set_default(summary, 123, quantiles, 1.4, 2, 0, NULL);

    ret = cmt_encode_msgpack_create(cmt, &payload, &payload_size);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cmt_destroy(cmt);
        return;
    }

    ret = patch_nth_key_array_size(payload, payload_size, "quantiles", 2, 0x93);
    if (ret != 0) {
        ret = patch_nth_key_array_size(payload, payload_size, "quantiles", 1, 0x93);
    }
    TEST_CHECK(ret == 0);

    offset = 0;
    decoded_cmt = NULL;
    ret = cmt_decode_msgpack_create(&decoded_cmt, payload, payload_size, &offset);
    TEST_CHECK(ret != CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(decoded_cmt == NULL);

    cmt_encode_msgpack_destroy(payload);
    cmt_destroy(cmt);
}

void test_msgpack_abi_histogram_buckets_reject_mismatch()
{
    int ret;
    size_t offset;
    char *payload;
    size_t payload_size;
    struct cmt *cmt;
    struct cmt_histogram_buckets *buckets;
    struct cmt_histogram *histogram;
    struct cmt *decoded_cmt;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);
    if (cmt == NULL) {
        return;
    }

    buckets = cmt_histogram_buckets_create(2, 1.0, 2.0);
    TEST_CHECK(buckets != NULL);
    if (buckets == NULL) {
        cmt_destroy(cmt);
        return;
    }

    histogram = cmt_histogram_create(cmt, "ns", "sub", "hist", "hist", buckets, 0, NULL);
    TEST_CHECK(histogram != NULL);
    if (histogram == NULL) {
        cmt_destroy(cmt);
        return;
    }

    cmt_histogram_observe(histogram, 100, 0.5, 0, NULL);
    cmt_histogram_observe(histogram, 100, 1.5, 0, NULL);
    cmt_histogram_observe(histogram, 100, 3.0, 0, NULL);

    ret = cmt_encode_msgpack_create(cmt, &payload, &payload_size);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cmt_destroy(cmt);
        return;
    }

    ret = patch_nth_key_array_size(payload, payload_size, "buckets", 2, 0x94);
    TEST_CHECK(ret == 0);

    offset = 0;
    decoded_cmt = NULL;
    ret = cmt_decode_msgpack_create(&decoded_cmt, payload, payload_size, &offset);
    TEST_CHECK(ret != CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(decoded_cmt == NULL);

    cmt_encode_msgpack_destroy(payload);
    cmt_destroy(cmt);
}

static struct cmt *create_static_gauge_with_metadata(void)
{
    struct cmt *source;
    struct cmt_gauge *gauge;
    struct cfl_kvlist *metadata;

    source = cmt_create();
    if (source == NULL) {
        return NULL;
    }

    gauge = cmt_gauge_create(source, "", "", "windows", "windows", 0, NULL);
    if (gauge == NULL || cmt_gauge_set(gauge, 1, 1.0, 0, NULL) != 0) {
        cmt_destroy(source);
        return NULL;
    }

    metadata = cfl_kvlist_create();
    gauge->map->metric.otlp_metadata = metadata;
    if (metadata == NULL ||
        cfl_kvlist_insert_uint64(metadata, "flags", 7) != 0 ||
        cfl_kvlist_insert_string(metadata, "text", "value") != 0 ||
        cfl_kvlist_insert_bytes(metadata, "binary", "\0\xff", 2, CFL_FALSE) != 0) {
        cmt_destroy(source);
        return NULL;
    }

    return source;
}

static void test_point_metadata_and_unlabeled_windows(void)
{
    struct cmt *source;
    struct cmt *decoded;
    struct cmt_gauge *gauge;
    struct cmt_gauge *result;
    struct cmt_metric *point;
    struct cfl_variant *value;
    char *buffer;
    size_t size;
    size_t offset;
    int ret;

    /* Typed static point metadata survives a round trip. */
    source = create_static_gauge_with_metadata();
    TEST_ASSERT(source != NULL);
    TEST_CHECK(cmt_encode_msgpack_create(source, &buffer, &size) == 0);
    offset = 0;
    ret = cmt_decode_msgpack_create(&decoded, buffer, size, &offset);
    TEST_ASSERT(ret == CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(offset == size);
    result = cfl_list_entry_first(&decoded->gauges, struct cmt_gauge, _head);
    TEST_ASSERT(result != NULL);
    TEST_CHECK(cmt_metric_get_timestamp(&result->map->metric) == 1);
    value = cfl_kvlist_fetch(result->map->metric.otlp_metadata, "flags");
    TEST_ASSERT(value != NULL);
    TEST_CHECK((value->type == CFL_VARIANT_UINT && value->data.as_uint64 == 7) ||
               (value->type == CFL_VARIANT_INT && value->data.as_int64 == 7));
    value = cfl_kvlist_fetch(result->map->metric.otlp_metadata, "text");
    TEST_ASSERT(value != NULL);
    TEST_CHECK(value->type == CFL_VARIANT_STRING && cfl_variant_size_get(value) == 5);
    TEST_CHECK(memcmp(value->data.as_string, "value", 5) == 0);
    value = cfl_kvlist_fetch(result->map->metric.otlp_metadata, "binary");
    TEST_ASSERT(value != NULL);
    TEST_CHECK(value->type == CFL_VARIANT_BYTES && cfl_variant_size_get(value) == 2);
    TEST_CHECK(memcmp(value->data.as_bytes, "\0\xff", 2) == 0);
    TEST_CHECK(cfl_list_size(&result->map->metrics) == 0);
    cmt_decode_msgpack_destroy(decoded);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(source);

    /* A further label-less point is the same series: like released readers,
     * it replaces the static metric (last one wins) instead of creating a
     * duplicate series. Its point metadata no longer lines up with the
     * sidecar and is skipped, while the values and the chunk survive. */
    source = create_static_gauge_with_metadata();
    TEST_ASSERT(source != NULL);
    gauge = cfl_list_entry_first(&source->gauges, struct cmt_gauge, _head);
    point = calloc(1, sizeof(*point));
    TEST_ASSERT(point != NULL);
    cfl_list_init(&point->labels);
    point->otlp_metadata = cfl_kvlist_create();
    TEST_ASSERT(point->otlp_metadata != NULL);
    TEST_CHECK(cfl_kvlist_insert_uint64(point->otlp_metadata, "flags", 3) == 0);
    cmt_metric_set_double(point, 2, 2.0);
    cfl_list_add(&point->_head, &gauge->map->metrics);
    TEST_CHECK(cmt_encode_msgpack_create(source, &buffer, &size) == 0);
    offset = 0;
    ret = cmt_decode_msgpack_create(&decoded, buffer, size, &offset);
    TEST_ASSERT(ret == CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(offset == size);
    result = cfl_list_entry_first(&decoded->gauges, struct cmt_gauge, _head);
    TEST_ASSERT(result != NULL);
    TEST_CHECK(cfl_list_size(&result->map->metrics) == 0);
    TEST_CHECK(cmt_metric_get_timestamp(&result->map->metric) == 2);
    TEST_CHECK(cmt_metric_get_value(&result->map->metric) == 2.0);
    TEST_CHECK(result->map->metric.otlp_metadata == NULL);
    cmt_decode_msgpack_destroy(decoded);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(source);
}

static void test_index_resize_preserves_family_metadata(void)
{
    struct cmt *ctx;
    struct cmt_gauge *gauge;
    struct cfl_variant *value;
    char label[32];
    char *values[] = {label};
    char *keys[] = {"series"};
    size_t index;
    char *buffer;
    size_t size;

    ctx = cmt_create();
    TEST_ASSERT(ctx != NULL);
    gauge = cmt_gauge_create(ctx, "", "", "resize", "resize", 1, keys);
    TEST_ASSERT(gauge != NULL);
    gauge->map->otlp_metadata = cfl_kvlist_create();
    TEST_ASSERT(gauge->map->otlp_metadata != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(gauge->map->otlp_metadata, "family", "retained") == 0);
    for (index = 0; index < 300; index++) {
        snprintf(label, sizeof(label), "%zu", index);
        TEST_ASSERT(cmt_gauge_set(gauge, 100, index, 1, values) == 0);
    }
    TEST_CHECK(gauge->map->metric_bucket_count > 64);
    value = cfl_kvlist_fetch(gauge->map->otlp_metadata, "family");
    TEST_CHECK(value != NULL && value->type == CFL_VARIANT_STRING);
    if (value != NULL && value->type == CFL_VARIANT_STRING) {
        TEST_CHECK(strcmp(value->data.as_string, "retained") == 0);
    }
    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

static void test_stale_metadata_sidecar_does_not_drop_chunk(void)
{
    struct cmt *ctx;
    struct cmt *decoded;
    struct cmt_gauge *gauge;
    struct cfl_array *sidecar;
    char *buffer;
    size_t size;
    size_t offset = 0;
    int result;

    ctx = cmt_create();
    TEST_ASSERT(ctx != NULL);
    gauge = cmt_gauge_create(ctx, "", "", "retained", "retained", 0, NULL);
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_gauge_set(gauge, 100, 42, 0, NULL) == 0);
    /* An intermediary removed a family without updating the optional sidecar. */
    sidecar = cfl_array_create(0);
    TEST_ASSERT(sidecar != NULL);
    TEST_ASSERT(cfl_kvlist_insert_array(ctx->internal_metadata,
                                      "__cmetrics_native_metadata_v1", sidecar) == 0);
    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    decoded = NULL;
    result = cmt_decode_msgpack_create(&decoded, buffer, size, &offset);
    TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);
    if (decoded != NULL) {
        gauge = cfl_list_entry_first(&decoded->gauges, struct cmt_gauge, _head);
        TEST_ASSERT(gauge != NULL);
        TEST_CHECK(cmt_metric_get_value(&gauge->map->metric) == 42);
        TEST_CHECK(cfl_kvlist_fetch(decoded->internal_metadata,
                                  "__cmetrics_native_metadata_v1") == NULL);
        cmt_destroy(decoded);
    }
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

static void test_invalid_optional_metadata_does_not_drop_chunk(void)
{
    struct cmt *ctx;
    struct cmt *decoded;
    struct cmt_gauge *gauge;
    struct cfl_array *sidecar;
    struct cfl_array *points;
    struct cfl_kvlist *family;
    char *buffer;
    size_t size;
    size_t offset = 0;
    int result;

    ctx = cmt_create();
    TEST_ASSERT(ctx != NULL);
    gauge = cmt_gauge_create(ctx, "", "", "retained", "retained", 0, NULL);
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_gauge_set(gauge, 100, 42, 0, NULL) == 0);
    sidecar = cfl_array_create(1);
    points = cfl_array_create(1);
    family = cfl_kvlist_create();
    TEST_ASSERT(sidecar != NULL && points != NULL && family != NULL);
    TEST_ASSERT(cfl_array_append_null(points) == 0);
    TEST_ASSERT(cfl_kvlist_insert_array(family, "points", points) == 0);
    TEST_ASSERT(cfl_kvlist_insert_bool(family, "allow_reset", CFL_FALSE) == 0);
    TEST_ASSERT(cfl_kvlist_insert_bytes(family, "family", "\xc1", 1, CFL_FALSE) == 0);
    TEST_ASSERT(cfl_array_append_kvlist(sidecar, family) == 0);
    TEST_ASSERT(cfl_kvlist_insert_array(ctx->internal_metadata,
                                      "__cmetrics_native_metadata_v1", sidecar) == 0);
    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    decoded = NULL;
    result = cmt_decode_msgpack_create(&decoded, buffer, size, &offset);
    TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);
    if (decoded != NULL) {
        gauge = cfl_list_entry_first(&decoded->gauges, struct cmt_gauge, _head);
        TEST_ASSERT(gauge != NULL);
        TEST_CHECK(cmt_metric_get_value(&gauge->map->metric) == 42);
        TEST_CHECK(gauge->map->otlp_metadata == NULL);
        cmt_destroy(decoded);
    }
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

TEST_LIST = {
    {"invalid_optional_metadata_retains_chunk", test_invalid_optional_metadata_does_not_drop_chunk},
    {"stale_metadata_sidecar_does_not_drop_chunk", test_stale_metadata_sidecar_does_not_drop_chunk},
    {"index_resize_preserves_family_metadata", test_index_resize_preserves_family_metadata},
    {"point_metadata_and_unlabeled_windows", test_point_metadata_and_unlabeled_windows},
    {"msgpack_abi_legacy_value_only_decode", test_msgpack_abi_legacy_value_only_decode},
    {"msgpack_abi_typed_int64_decode",        test_msgpack_abi_typed_int64_decode},
    {"msgpack_abi_summary_quantiles_reject_mismatch", test_msgpack_abi_summary_quantiles_reject_mismatch},
    {"msgpack_abi_histogram_buckets_reject_mismatch", test_msgpack_abi_histogram_buckets_reject_mismatch},
    {0}
};
