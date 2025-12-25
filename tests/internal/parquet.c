/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parquet.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

/* Compression types from flb_aws_compress.h */
#define FLB_AWS_COMPRESS_NONE    0
#define FLB_AWS_COMPRESS_GZIP    1
#define FLB_AWS_COMPRESS_SNAPPY  2
#define FLB_AWS_COMPRESS_ZSTD    3

/* =============================================================================
 * TEST ORGANIZATION
 * =============================================================================
 * This test suite is organized into the following categories:
 *
 * 1. BASIC FUNCTIONALITY (5 tests)
 *    - Basic conversion, multiple records, array containers
 *
 * 2. DATA TYPE COVERAGE (6 tests)
 *    - All supported Arrow types, binary type, timestamp units
 *
 * 3. SCHEMA TESTS (2 tests)
 *    - String notation, object notation
 *
 * 4. TYPE CONVERSION (6 tests)
 *    - String parsing, type coercion, cross-type conversions
 *
 * 5. BOUNDARY VALUES (5 tests)
 *    - Integer limits, zero values, empty values, NULL handling
 *
 * 6. NULLABLE HANDLING (3 tests)
 *    - Required vs optional fields, missing fields, all NULL
 *
 * 7. COMPLEX TYPES (3 tests)
 *    - MAP/ARRAY serialization, empty complex types, nested structures
 *
 * 8. COMPRESSION (3 tests)
 *    - GZIP, Snappy, ZSTD
 *
 * 9. ERROR HANDLING (5 tests)
 *    - Invalid inputs, schema errors, parse failures
 *
 * Total: 38 tests covering all code paths and edge cases
 * ============================================================================= */

/* =============================================================================
 * CATEGORY 1: BASIC FUNCTIONALITY TESTS (5 tests)
 * Core conversion capabilities and record handling
 * ============================================================================= */

/* Test 1.1: Single record with simple schema */
static void test_basic_conversion(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"message\",\"type\":\"utf8\"},{\"name\":\"level\",\"type\":\"int32\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "message", 7);
    msgpack_pack_str(&packer, 11);
    msgpack_pack_str_body(&packer, "hello world", 11);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "level", 5);
    msgpack_pack_int(&packer, 1);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 1.2: Multiple sequential records */
static void test_multiple_records(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    int i;
    const char *schema = "{\"fields\":[{\"name\":\"id\",\"type\":\"int32\"},{\"name\":\"message\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    for (i = 0; i < 10; i++) {
        msgpack_pack_map(&packer, 2);
        msgpack_pack_str(&packer, 2);
        msgpack_pack_str_body(&packer, "id", 2);
        msgpack_pack_int(&packer, i);
        msgpack_pack_str(&packer, 7);
        msgpack_pack_str_body(&packer, "message", 7);
        msgpack_pack_str(&packer, 4);
        msgpack_pack_str_body(&packer, "test", 4);
    }

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 1.3: Records in msgpack array container */
static void test_array_container(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    int i;
    const char *schema = "{\"fields\":[{\"name\":\"id\",\"type\":\"int32\"},{\"name\":\"msg\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&packer, 5);
    for (i = 0; i < 5; i++) {
        msgpack_pack_map(&packer, 2);
        msgpack_pack_str(&packer, 2);
        msgpack_pack_str_body(&packer, "id", 2);
        msgpack_pack_int(&packer, i);
        msgpack_pack_str(&packer, 3);
        msgpack_pack_str_body(&packer, "msg", 3);
        msgpack_pack_str(&packer, 7);
        msgpack_pack_str_body(&packer, "message", 7);
    }

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 1.4: Large record count (stress test) */
static void test_large_record_count(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    int i;
    const char *schema = "{\"fields\":[{\"name\":\"id\",\"type\":\"int32\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    for (i = 0; i < 1000; i++) {
        msgpack_pack_map(&packer, 1);
        msgpack_pack_str(&packer, 2);
        msgpack_pack_str_body(&packer, "id", 2);
        msgpack_pack_int(&packer, i);
    }

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 1.5: Single field schema */
static void test_single_field(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"value\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "value", 5);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "test", 4);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* =============================================================================
 * CATEGORY 2: DATA TYPE COVERAGE (6 tests)
 * All supported Arrow/Parquet data types
 * ============================================================================= */

/* Test 2.1: All basic types in one record */
static void test_all_types(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema =
        "{\"fields\":["
        "{\"name\":\"bool_field\",\"type\":\"bool\"},"
        "{\"name\":\"int32_field\",\"type\":\"int32\"},"
        "{\"name\":\"int64_field\",\"type\":\"int64\"},"
        "{\"name\":\"float_field\",\"type\":\"float\"},"
        "{\"name\":\"double_field\",\"type\":\"double\"},"
        "{\"name\":\"string_field\",\"type\":\"utf8\"}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 6);
    msgpack_pack_str(&packer, 10);
    msgpack_pack_str_body(&packer, "bool_field", 10);
    msgpack_pack_true(&packer);
    msgpack_pack_str(&packer, 11);
    msgpack_pack_str_body(&packer, "int32_field", 11);
    msgpack_pack_int(&packer, 42);
    msgpack_pack_str(&packer, 11);
    msgpack_pack_str_body(&packer, "int64_field", 11);
    msgpack_pack_int64(&packer, 9223372036854775807LL);
    msgpack_pack_str(&packer, 11);
    msgpack_pack_str_body(&packer, "float_field", 11);
    msgpack_pack_float(&packer, 3.14f);
    msgpack_pack_str(&packer, 12);
    msgpack_pack_str_body(&packer, "double_field", 12);
    msgpack_pack_double(&packer, 2.718281828);
    msgpack_pack_str(&packer, 12);
    msgpack_pack_str_body(&packer, "string_field", 12);
    msgpack_pack_str(&packer, 11);
    msgpack_pack_str_body(&packer, "test string", 11);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 2.2: Binary type with BIN msgpack type */
static void test_binary_type(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"data\",\"type\":\"binary\"}]}";
    const char binary_data[] = {0x00, 0x01, 0x02, 0xFF};

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);
    msgpack_pack_bin(&packer, sizeof(binary_data));
    msgpack_pack_bin_body(&packer, binary_data, sizeof(binary_data));

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 2.3: Binary type accepting STR msgpack type */
static void test_binary_from_string(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"data\",\"type\":\"binary\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "hello", 5);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 2.4: Binary rejection of non-binary types */
static void test_binary_type_rejection(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"bin1\",\"type\":\"binary\",\"nullable\":true},{\"name\":\"bin2\",\"type\":\"binary\",\"nullable\":false}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "bin1", 4);
    msgpack_pack_int(&packer, 123);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "bin2", 4);
    msgpack_pack_true(&packer);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 2.5: Timestamp with different units */
static void test_timestamp_units(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema =
        "{\"fields\":["
        "{\"name\":\"ts_sec\",\"type\":{\"name\":\"timestamp\",\"unit\":\"s\"}},"
        "{\"name\":\"ts_ms\",\"type\":{\"name\":\"timestamp\",\"unit\":\"ms\"}},"
        "{\"name\":\"ts_us\",\"type\":{\"name\":\"timestamp\",\"unit\":\"us\"}}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 3);
    msgpack_pack_str(&packer, 6);
    msgpack_pack_str_body(&packer, "ts_sec", 6);
    msgpack_pack_int64(&packer, 1609459200LL);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "ts_ms", 5);
    msgpack_pack_int64(&packer, 1609459200000LL);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "ts_us", 5);
    msgpack_pack_int64(&packer, 1609459200000000LL);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 2.6: Timestamp float truncation */
static void test_timestamp_float(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"ts\",\"type\":{\"name\":\"timestamp\",\"unit\":\"ms\"}}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "ts", 2);
    msgpack_pack_double(&packer, 1735088400123.456);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* =============================================================================
 * CATEGORY 3: SCHEMA TESTS (2 tests)
 * Schema format variations
 * ============================================================================= */

/* Test 3.1: Schema with object notation for types */
static void test_schema_object_notation(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema =
        "{\"fields\":["
        "{\"name\":\"msg\",\"type\":{\"name\":\"utf8\"}},"
        "{\"name\":\"ts\",\"type\":{\"name\":\"timestamp\",\"unit\":\"s\"}}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "msg", 3);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "test", 4);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "ts", 2);
    msgpack_pack_int64(&packer, 1735088400);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 3.2: Schema with many fields */
static void test_schema_many_fields(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema =
        "{\"fields\":["
        "{\"name\":\"f1\",\"type\":\"int32\"},"
        "{\"name\":\"f2\",\"type\":\"int32\"},"
        "{\"name\":\"f3\",\"type\":\"int32\"},"
        "{\"name\":\"f4\",\"type\":\"int32\"},"
        "{\"name\":\"f5\",\"type\":\"int32\"},"
        "{\"name\":\"f6\",\"type\":\"int32\"},"
        "{\"name\":\"f7\",\"type\":\"int32\"},"
        "{\"name\":\"f8\",\"type\":\"int32\"},"
        "{\"name\":\"f9\",\"type\":\"int32\"},"
        "{\"name\":\"f10\",\"type\":\"int32\"}"
        "]}";
    int i;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 10);
    for (i = 1; i <= 10; i++) {
        char field_name[4];
        snprintf(field_name, sizeof(field_name), "f%d", i);
        msgpack_pack_str(&packer, strlen(field_name));
        msgpack_pack_str_body(&packer, field_name, strlen(field_name));
        msgpack_pack_int(&packer, i);
    }

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* =============================================================================
 * CATEGORY 4: TYPE CONVERSION (6 tests)
 * Type coercion and cross-type conversions
 * ============================================================================= */

/* Test 4.1: String to number/bool parsing */
static void test_type_conversion(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema =
        "{\"fields\":["
        "{\"name\":\"int_str\",\"type\":\"int32\"},"
        "{\"name\":\"float_str\",\"type\":\"double\"},"
        "{\"name\":\"bool_str\",\"type\":\"bool\"}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 3);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "int_str", 7);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "123", 3);
    msgpack_pack_str(&packer, 9);
    msgpack_pack_str_body(&packer, "float_str", 9);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "3.14", 4);
    msgpack_pack_str(&packer, 8);
    msgpack_pack_str_body(&packer, "bool_str", 8);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "true", 4);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 4.2: All basic types to string */
static void test_all_to_string(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"s1\",\"type\":\"utf8\"},{\"name\":\"s2\",\"type\":\"utf8\"},{\"name\":\"s3\",\"type\":\"utf8\"},{\"name\":\"s4\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 4);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "s1", 2);
    msgpack_pack_true(&packer);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "s2", 2);
    msgpack_pack_int(&packer, 42);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "s3", 2);
    msgpack_pack_double(&packer, 3.14);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "s4", 2);
    msgpack_pack_bin(&packer, 4);
    msgpack_pack_bin_body(&packer, "data", 4);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 4.3: Boolean string variations */
static void test_bool_string_variations(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"b1\",\"type\":\"bool\"},{\"name\":\"b2\",\"type\":\"bool\"},{\"name\":\"b3\",\"type\":\"bool\"},{\"name\":\"b4\",\"type\":\"bool\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 4);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "b1", 2);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "yes", 3);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "b2", 2);
    msgpack_pack_str(&packer, 1);
    msgpack_pack_str_body(&packer, "y", 1);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "b3", 2);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "no", 2);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "b4", 2);
    msgpack_pack_str(&packer, 1);
    msgpack_pack_str_body(&packer, "n", 1);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 4.4: String parsing failures */
static void test_string_parse_failure(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"num\",\"type\":\"int32\",\"nullable\":true},{\"name\":\"flt\",\"type\":\"double\",\"nullable\":true}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "num", 3);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "abc", 3);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "flt", 3);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "xyz", 3);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 4.5: Timestamp string parsing */
static void test_timestamp_string_parse(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"ts\",\"type\":{\"name\":\"timestamp\",\"unit\":\"s\"}}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "ts", 2);
    msgpack_pack_str(&packer, 10);
    msgpack_pack_str_body(&packer, "1735088400", 10);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 4.6: Complex types to non-string field */
static void test_complex_to_non_string(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"num\",\"type\":\"int32\",\"nullable\":true},{\"name\":\"flt\",\"type\":\"double\",\"nullable\":false}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "num", 3);
    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "key", 3);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "val", 3);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "flt", 3);
    msgpack_pack_array(&packer, 2);
    msgpack_pack_int(&packer, 1);
    msgpack_pack_int(&packer, 2);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* =============================================================================
 * CATEGORY 5: BOUNDARY VALUES
 * Integer limits, zero values, empty values, NULL handling
 * ============================================================================= */

/* Test 5.1: Integer overflow handling */
static void test_int_overflow(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"big_num\",\"type\":\"int32\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "big_num", 7);
    msgpack_pack_int64(&packer, 9999999999LL);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 5.2: INT32_MAX and INT32_MIN boundary values */
static void test_int32_boundaries(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"max_val\",\"type\":\"int32\"},{\"name\":\"min_val\",\"type\":\"int32\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "max_val", 7);
    msgpack_pack_int64(&packer, INT32_MAX);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "min_val", 7);
    msgpack_pack_int64(&packer, INT32_MIN);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 5.3: Zero values in all numeric types */
static void test_zero_values(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"i32\",\"type\":\"int32\"},{\"name\":\"i64\",\"type\":\"int64\"},{\"name\":\"f32\",\"type\":\"float\"},{\"name\":\"f64\",\"type\":\"double\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 4);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "i32", 3);
    msgpack_pack_int(&packer, 0);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "i64", 3);
    msgpack_pack_int64(&packer, 0);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "f32", 3);
    msgpack_pack_float(&packer, 0.0f);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "f64", 3);
    msgpack_pack_double(&packer, 0.0);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 5.4: Empty string */
static void test_empty_string(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"str\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "str", 3);
    msgpack_pack_str(&packer, 0);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 5.5: All fields are NULL */
static void test_all_null_values(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"f1\",\"type\":\"int32\",\"nullable\":true},{\"name\":\"f2\",\"type\":\"utf8\",\"nullable\":true}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "f1", 2);
    msgpack_pack_nil(&packer);
    msgpack_pack_str(&packer, 2);
    msgpack_pack_str_body(&packer, "f2", 2);
    msgpack_pack_nil(&packer);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* =============================================================================
 * CATEGORY 6: NULLABLE HANDLING
 * Required vs optional fields, missing fields
 * ============================================================================= */

/* Test 6.1: Nullable fields with missing optional */
static void test_nullable_fields(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema =
        "{\"fields\":["
        "{\"name\":\"required\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"optional\",\"type\":\"utf8\",\"nullable\":true}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 8);
    msgpack_pack_str_body(&packer, "required", 8);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "present", 7);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 6.2: All fields missing */
static void test_all_fields_missing(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"field1\",\"type\":\"int32\",\"nullable\":false},{\"name\":\"field2\",\"type\":\"utf8\",\"nullable\":true}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 0);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* =============================================================================
 * CATEGORY 7: COMPLEX TYPES
 * MAP/ARRAY serialization, empty complex types
 * ============================================================================= */

/* Test 7.1: MAP/ARRAY to string serialization */
static void test_complex_types(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema =
        "{\"fields\":["
        "{\"name\":\"simple\",\"type\":\"utf8\"},"
        "{\"name\":\"nested\",\"type\":\"utf8\"}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 6);
    msgpack_pack_str_body(&packer, "simple", 6);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "text", 4);
    msgpack_pack_str(&packer, 6);
    msgpack_pack_str_body(&packer, "nested", 6);
    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 3);
    msgpack_pack_str_body(&packer, "key", 3);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "value", 5);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 7.2: Empty map and array */
static void test_empty_complex_types(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"empty_map\",\"type\":\"utf8\"},{\"name\":\"empty_arr\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 9);
    msgpack_pack_str_body(&packer, "empty_map", 9);
    msgpack_pack_map(&packer, 0);
    msgpack_pack_str(&packer, 9);
    msgpack_pack_str_body(&packer, "empty_arr", 9);
    msgpack_pack_array(&packer, 0);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* =============================================================================
 * CATEGORY 8: COMPRESSION
 * GZIP, Snappy, ZSTD
 * ============================================================================= */

/* Test 8.1: GZIP compression */
static void test_compression_gzip(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"data\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);
    msgpack_pack_str(&packer, 11);
    msgpack_pack_str_body(&packer, "compress me", 11);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_GZIP, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 8.2: Snappy compression */
static void test_compression_snappy(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"data\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);
    msgpack_pack_str(&packer, 11);
    msgpack_pack_str_body(&packer, "snappy test", 11);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_SNAPPY, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* Test 8.3: ZSTD compression */
static void test_compression_zstd(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"data\",\"type\":\"utf8\"}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);
    msgpack_pack_str(&packer, 9);
    msgpack_pack_str_body(&packer, "zstd test", 9);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_ZSTD, &parquet_size);

    TEST_CHECK(parquet_data != NULL);
    TEST_CHECK(parquet_size > 0);

    msgpack_sbuffer_destroy(&sbuf);
    if (parquet_data) {
        flb_free(parquet_data);
    }
}

/* =============================================================================
 * CATEGORY 9: ERROR HANDLING
 * Invalid inputs, schema errors, parse failures
 * ============================================================================= */

/* Test 9.1: NULL input buffer */
static void test_error_null_input(void)
{
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"test\",\"type\":\"utf8\"}]}";

    parquet_data = flb_msgpack_raw_to_parquet(NULL, 100, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data == NULL);
}

/* Test 9.2: NULL schema */
static void test_error_null_schema(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "test", 4);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, NULL, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data == NULL);

    msgpack_sbuffer_destroy(&sbuf);
}

/* Test 9.3: Empty msgpack data */
static void test_error_empty_data(void)
{
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"fields\":[{\"name\":\"test\",\"type\":\"utf8\"}]}";

    parquet_data = flb_msgpack_raw_to_parquet("", 0, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data == NULL);
}

/* Test 9.4: Invalid schema JSON */
static void test_error_invalid_schema(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *invalid_schema = "{invalid json}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "test", 4);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, invalid_schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data == NULL);

    msgpack_sbuffer_destroy(&sbuf);
}

/* Test 9.5: Schema without fields array */
static void test_error_no_fields(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    void *parquet_data;
    size_t parquet_size;
    const char *schema = "{\"no_fields\":true}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "test", 4);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);

    parquet_data = flb_msgpack_raw_to_parquet(sbuf.data, sbuf.size, schema, FLB_AWS_COMPRESS_NONE, &parquet_size);

    TEST_CHECK(parquet_data == NULL);

    msgpack_sbuffer_destroy(&sbuf);
}

TEST_LIST = {
    /* Category 1: Basic Functionality */
    {"basic_conversion", test_basic_conversion},
    {"multiple_records", test_multiple_records},
    {"array_container", test_array_container},
    {"large_record_count", test_large_record_count},
    {"single_field", test_single_field},

    /* Category 2: Data Type Coverage */
    {"all_types", test_all_types},
    {"binary_type", test_binary_type},
    {"binary_from_string", test_binary_from_string},
    {"binary_type_rejection", test_binary_type_rejection},
    {"timestamp_units", test_timestamp_units},
    {"timestamp_float", test_timestamp_float},

    /* Category 3: Schema Tests */
    {"schema_object_notation", test_schema_object_notation},
    {"schema_many_fields", test_schema_many_fields},

    /* Category 4: Type Conversion */
    {"type_conversion", test_type_conversion},
    {"all_to_string", test_all_to_string},
    {"bool_string_variations", test_bool_string_variations},
    {"string_parse_failure", test_string_parse_failure},
    {"timestamp_string_parse", test_timestamp_string_parse},
    {"complex_to_non_string", test_complex_to_non_string},

    /* Category 5: Boundary Values */
    {"int_overflow", test_int_overflow},
    {"int32_boundaries", test_int32_boundaries},
    {"zero_values", test_zero_values},
    {"empty_string", test_empty_string},
    {"all_null_values", test_all_null_values},

    /* Category 6: Nullable Handling */
    {"nullable_fields", test_nullable_fields},
    {"all_fields_missing", test_all_fields_missing},

    /* Category 7: Complex Types */
    {"complex_types", test_complex_types},
    {"empty_complex_types", test_empty_complex_types},

    /* Category 8: Compression */
    {"compression_gzip", test_compression_gzip},
    {"compression_snappy", test_compression_snappy},
    {"compression_zstd", test_compression_zstd},

    /* Category 9: Error Handling */
    {"error_null_input", test_error_null_input},
    {"error_null_schema", test_error_null_schema},
    {"error_empty_data", test_error_empty_data},
    {"error_invalid_schema", test_error_invalid_schema},
    {"error_no_fields", test_error_no_fields},

    {NULL, NULL}
};
