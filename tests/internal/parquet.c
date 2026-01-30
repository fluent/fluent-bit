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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parquet.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <msgpack.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

#include "flb_tests_internal.h"

/* Parquet validation function - implemented in C++ */
#ifdef __cplusplus
extern "C" {
#endif

int validate_parquet_file(const char *file_path,
                          int expected_records,
                          const char *field_name,
                          const char *expected_type,
                          const char *expected_value,
                          int row_index);

#ifdef __cplusplus
}
#endif

/*
 * Helper: Write msgpack data to file in ChunkIO format
 *
 * ChunkIO file layout (from lib/chunkio/include/chunkio/cio_file_st.h):
 *   Bytes  0-1:   Magic (0xC1 0x00)
 *   Bytes  2-5:   CRC32 of content section
 *   Bytes  6-9:   CRC32 of padding (reserved)
 *   Bytes 10-13:  Content length (4 bytes, big-endian)
 *   Bytes 14-21:  Padding (8 bytes, reserved)
 *   Bytes 22-23:  Metadata length (2 bytes, big-endian)
 *   Bytes 24+:    [Metadata][User Data]
 *
 * Content = metadata + user data
 * Content length = metadata_len + data_size
 */
static int write_msgpack_to_chunk_file(const char *file_path, const char *data, size_t size)
{
    FILE *fp;
    unsigned char header[24];
    const char *tag = "test";
    size_t tag_len = strlen(tag);
    uint16_t metadata_len = (uint16_t)tag_len;
    uint32_t content_len;

    fp = fopen(file_path, "wb");
    if (!fp) {
        return -1;
    }

    /*
     * Initialize header from template matching cio_file_init_bytes
     * All fields are initialized to ensure compatibility with ChunkIO validation
     */
    memset(header, 0, sizeof(header));

    /* Bytes 0-1: Magic identification bytes */
    header[0] = 0xC1;  /* CIO_FILE_ID_00 */
    header[1] = 0x00;  /* CIO_FILE_ID_01 */

    /* Bytes 2-5: CRC32 of content (set to 0 - validation typically disabled in tests) */
    /* header[2..5] = 0 (already zeroed) */

    /* Bytes 6-9: CRC32 of padding (reserved, set to 0) */
    /* header[6..9] = 0 (already zeroed) */

    /* Bytes 10-13: Content length (big-endian)
     * Content = metadata + msgpack data
     * Using helper logic from cio_file_st_set_content_len() */
    content_len = (uint32_t)(metadata_len + size);
    header[10] = (uint8_t)((content_len >> 24) & 0xFF);
    header[11] = (uint8_t)((content_len >> 16) & 0xFF);
    header[12] = (uint8_t)((content_len >>  8) & 0xFF);
    header[13] = (uint8_t)((content_len >>  0) & 0xFF);

    /* Bytes 14-21: Padding (reserved, set to 0) */
    /* header[14..21] = 0 (already zeroed) */

    /* Bytes 22-23: Metadata length (big-endian)
     * Using helper logic from cio_file_st_set_meta_len() */
    header[22] = (uint8_t)((metadata_len >> 8) & 0xFF);
    header[23] = (uint8_t)((metadata_len >> 0) & 0xFF);

    /* Write header */
    if (fwrite(header, 1, sizeof(header), fp) != sizeof(header)) {
        fclose(fp);
        return -1;
    }

    /* Write metadata (tag name) */
    if (fwrite(tag, 1, tag_len, fp) != tag_len) {
        fclose(fp);
        return -1;
    }

    /* Write msgpack data */
    if (fwrite(data, 1, size, fp) != size) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/* Helper: Check if parquet file exists and has content */
static int check_parquet_file(const char *file_path, size_t *out_size)
{
    struct stat st;
    if (stat(file_path, &st) != 0) {
        return -1;
    }
    if (st.st_size == 0) {
        return -1;
    }
    if (out_size) {
        *out_size = st.st_size;
    }
    return 0;
}

/* Helper: Pack Fluent Bit format [timestamp, map] */
static void pack_fluent_bit_record(msgpack_packer *packer, int64_t ts)
{
    msgpack_pack_array(packer, 2);
    msgpack_pack_int64(packer, ts);
}

/* Helper: Pack JSON data into msgpack format [timestamp, map] */
static int pack_json_record(msgpack_sbuffer *sbuf, msgpack_packer *packer,
                            int64_t timestamp, const char *json_data)
{
    char *msgpack_buf = NULL;
    size_t msgpack_size = 0;
    int root_type;
    size_t consumed;
    int ret;

    ret = flb_pack_json(json_data, strlen(json_data),
                        &msgpack_buf, &msgpack_size,
                        &root_type, &consumed);
    if (ret != 0) {
        return -1;
    }

    msgpack_pack_array(packer, 2);
    msgpack_pack_int64(packer, timestamp);
    msgpack_sbuffer_write(sbuf, msgpack_buf, msgpack_size);
    flb_free(msgpack_buf);

    return 0;
}

/* Helper: Validate parquet with expected data */
typedef struct {
    const char *field_name;
    const char *expected_type;
    const char *expected_value;
    int row_index;
} field_expectation;

static int validate_parquet_data(const char *parquet_file, int expected_records,
                                  const field_expectation *expectations, int num_expectations)
{
    int i, ret;

    /* Validate record count */
    if (expected_records > 0) {
        ret = validate_parquet_file(parquet_file, expected_records, NULL, NULL, NULL, 0);
        if (ret != 0) return ret;
    }

    /* Validate each field expectation flexibly:
     * - If both type and value provided: validate both in one call
     * - If only type provided: validate type only
     * - If only value provided: validate value only
     */
    for (i = 0; i < num_expectations; i++) {
        const field_expectation *exp = &expectations[i];

        if (exp->expected_type && exp->expected_value) {
            /* Validate both type and value together - most strict */
            ret = validate_parquet_file(parquet_file, -1, exp->field_name,
                                        exp->expected_type, exp->expected_value, exp->row_index);
            if (ret != 0) return ret;
        } else if (exp->expected_type) {
            /* Validate type only */
            ret = validate_parquet_file(parquet_file, -1, exp->field_name,
                                        exp->expected_type, NULL, exp->row_index);
            if (ret != 0) return ret;
        } else if (exp->expected_value) {
            /* Validate value only */
            ret = validate_parquet_file(parquet_file, -1, exp->field_name,
                                        NULL, exp->expected_value, exp->row_index);
            if (ret != 0) return ret;
        }
    }

    return 0;
}

/* ============================================================================
 * TEST CONTEXT FRAMEWORK - Reduces boilerplate code
 * ============================================================================ */

/* Test context structure with resource management */
typedef struct {
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    char msgpack_file[256];
    char parquet_file[256];
    size_t parquet_size;
    const char *schema;
    int compression;
    flb_parquet_schema *cached_schema;  /* Cached schema for new API */
} test_context;

/* Helper wrapper for new cached API - manages schema lifecycle automatically */
static int flb_msgpack_raw_to_parquet_file_streaming(const char *msgpack_file_path,
                                                      const char *schema_str,
                                                      int compression,
                                                      const char *output_file,
                                                      size_t *out_file_size,
                                                      size_t total_file_size)
{
    char error_msg[512];
    flb_parquet_schema *cached_schema = NULL;
    int ret;

    if (!schema_str) {
        return -1;
    }

    /* Parse and cache schema */
    cached_schema = flb_parquet_schema_create(schema_str, error_msg, sizeof(error_msg));
    if (!cached_schema) {
        return -1;
    }

    /* Call cached version */
    ret = flb_msgpack_to_parquet_streaming(
        msgpack_file_path,
        cached_schema,
        compression,
        output_file,
        out_file_size,
        total_file_size
    );

    /* Cleanup */
    flb_parquet_schema_destroy(cached_schema);

    return ret;
}

/* Initialize test context */
static int init_test_context(test_context *ctx, const char *test_name)
{
    pid_t pid = getpid();
    struct timespec ts;
    
    msgpack_sbuffer_init(&ctx->sbuf);
    msgpack_packer_init(&ctx->packer, &ctx->sbuf, msgpack_sbuffer_write);

    /* Use PID and nanosecond timestamp to avoid file collisions in parallel tests */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    snprintf(ctx->msgpack_file, sizeof(ctx->msgpack_file),
             "/tmp/flb_test_%s_%d_%ld%09ld.msgpack", 
             test_name, pid, ts.tv_sec, ts.tv_nsec);
    snprintf(ctx->parquet_file, sizeof(ctx->parquet_file),
             "/tmp/flb_test_%s_%d_%ld%09ld.parquet", 
             test_name, pid, ts.tv_sec, ts.tv_nsec);

    ctx->parquet_size = 0;
    ctx->schema = NULL;
    ctx->compression = FLB_AWS_COMPRESS_NONE;

    return 0;
}

/* Run standard conversion: write msgpack -> convert to parquet -> validate file exists */
static int run_conversion(test_context *ctx)
{
    int ret;

    ret = write_msgpack_to_chunk_file(ctx->msgpack_file,
                                      ctx->sbuf.data,
                                      ctx->sbuf.size);
    if (ret != 0) return ret;

    ret = flb_msgpack_raw_to_parquet_file_streaming(ctx->msgpack_file,
                                                      ctx->schema,
                                                      ctx->compression,
                                                      ctx->parquet_file,
                                                      &ctx->parquet_size,
                                                      0);
    if (ret != 0) return ret;

    return check_parquet_file(ctx->parquet_file, NULL);
}

/* Cleanup test context */
static void cleanup_test_context(test_context *ctx)
{
    msgpack_sbuffer_destroy(&ctx->sbuf);
    unlink(ctx->msgpack_file);
    unlink(ctx->parquet_file);
}

/* Pack JSON record with context (convenience wrapper) */
static int ctx_pack_json(test_context *ctx, int64_t timestamp, const char *json_data)
{
    return pack_json_record(&ctx->sbuf, &ctx->packer, timestamp, json_data);
}

/* Validate parquet data with context (convenience wrapper) */
static int ctx_validate(test_context *ctx, int expected_records,
                       const field_expectation *expectations, int num_expectations)
{
    return validate_parquet_data(ctx->parquet_file, expected_records,
                                expectations, num_expectations);
}


/* Single record basic conversion */
static void test_basic_conversion(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_basic");
    ctx.schema = "{\"fields\":[{\"name\":\"message\",\"type\":\"utf8\"},{\"name\":\"level\",\"type\":\"int32\"}]}";

    ret = ctx_pack_json(&ctx, 1609459200, "{\"message\":\"hello world\",\"level\":1}");
    TEST_CHECK(ret == 0);

    TEST_CHECK(run_conversion(&ctx) == 0);

    ret = validate_parquet_file(ctx.parquet_file, 1, "message", "string", "hello world", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "level", "int32", "1", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Multiple records */
static void test_multiple_records(void)
{
    test_context ctx;
    int i, ret;

    init_test_context(&ctx, "parquet_multi");
    ctx.schema = "{\"fields\":[{\"name\":\"id\",\"type\":\"int32\"},{\"name\":\"message\",\"type\":\"utf8\"}]}";

    /* Pack 100 records */
    for (i = 0; i < 100; i++) {
        char json_buf[256];
        snprintf(json_buf, sizeof(json_buf), "{\"id\":%d,\"message\":\"test\"}", i);
        ret = ctx_pack_json(&ctx, 1609459200 + i, json_buf);
        TEST_CHECK(ret == 0);
    }

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Define key validation points */
    field_expectation expectations[] = {
        {"id", "int32", "0", 0},       /* First record */
        {"message", "string", "test", 0},
        {"id", "int32", "50", 50},     /* Middle record */
        {"message", "string", "test", 50},
        {"id", "int32", "99", 99},     /* Last record */
        {"message", "string", "test", 99}
    };

    ret = ctx_validate(&ctx, 100, expectations, 6);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Large record count (trigger multiple batches) */
static void test_large_record_count(void)
{
    test_context ctx;
    int i, ret;
    const int record_count = 70000;

    init_test_context(&ctx, "parquet_large");
    ctx.schema = "{\"fields\":[{\"name\":\"id\",\"type\":\"int32\"}]}";

    /* Pack 70000 records to trigger multiple batches */
    for (i = 0; i < record_count; i++) {
        char json_buf[64];
        snprintf(json_buf, sizeof(json_buf), "{\"id\":%d}", i);
        ret = ctx_pack_json(&ctx, 1609459200 + i, json_buf);
        TEST_CHECK(ret == 0);
    }

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Define key validation points across batches */
    field_expectation expectations[] = {
        {"id", "int32", "0", 0},           /* First record */
        {"id", "int32", "35000", 35000},   /* Middle record */
        {"id", "int32", "65535", 65535},   /* Last of first batch */
        {"id", "int32", "65536", 65536},   /* First of second batch */
        {"id", "int32", "69999", 69999}    /* Last record */
    };

    ret = ctx_validate(&ctx, record_count, expectations, 5);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Boolean type - all conversion paths */
static void test_bool_conversions(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_bool");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"bool_val\",\"type\":\"bool\"},"
        "{\"name\":\"int_to_bool\",\"type\":\"bool\"},"
        "{\"name\":\"float_to_bool\",\"type\":\"bool\"},"
        "{\"name\":\"str_to_bool\",\"type\":\"bool\"}"
        "]}";

    ret = ctx_pack_json(&ctx, 1609459200,
        "{\"bool_val\":true,\"int_to_bool\":1,\"float_to_bool\":1.0,\"str_to_bool\":\"true\"}");
    TEST_CHECK(ret == 0);

    ret = ctx_pack_json(&ctx, 1609459201,
        "{\"bool_val\":false,\"int_to_bool\":0,\"float_to_bool\":0.0,\"str_to_bool\":\"no\"}");
    TEST_CHECK(ret == 0);

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Define expected conversions - verify ALL conversion paths */
    field_expectation expectations[] = {
        /* Record 0 - all true conversions */
        {"bool_val", "bool", "true", 0},
        {"int_to_bool", "bool", "true", 0},      /* int 1 -> true */
        {"float_to_bool", "bool", "true", 0},    /* float 1.0 -> true */
        {"str_to_bool", "bool", "true", 0},      /* string "true" -> true */
        /* Record 1 - all false conversions */
        {"bool_val", "bool", "false", 1},
        {"int_to_bool", "bool", "false", 1},     /* int 0 -> false */
        {"float_to_bool", "bool", "false", 1},   /* float 0.0 -> false */
        {"str_to_bool", "bool", "false", 1}      /* string "no" -> false */
    };

    ret = ctx_validate(&ctx, 2, expectations, 8);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Integer conversions with overflow/underflow */
static void test_integer_conversions(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_int");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"int32_normal\",\"type\":\"int32\"},"
        "{\"name\":\"int32_from_float\",\"type\":\"int32\"},"
        "{\"name\":\"int32_from_string\",\"type\":\"int32\"},"
        "{\"name\":\"int32_from_bool\",\"type\":\"int32\"},"
        "{\"name\":\"int64_val\",\"type\":\"int64\"}"
        "]}";

    ret = ctx_pack_json(&ctx, 1609459200,
        "{\"int32_normal\":42,\"int32_from_float\":123.456,\"int32_from_string\":\"999\",\"int32_from_bool\":true,\"int64_val\":9223372036854775807}");
    TEST_CHECK(ret == 0);

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Define expected conversions */
    field_expectation expectations[] = {
        {"int32_normal", "int32", "42", 0},
        {"int32_from_float", "int32", "123", 0},      /* float 123.456 -> int 123 (truncate) */
        {"int32_from_string", "int32", "999", 0},     /* string "999" -> int 999 */
        {"int32_from_bool", "int32", "1", 0},         /* bool true -> int 1 */
        {"int64_val", "int64", NULL, 0}               /* Type check only */
    };

    ret = ctx_validate(&ctx, 1, expectations, 5);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Float conversions */
static void test_float_conversions(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_float");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"float_val\",\"type\":\"float\"},"
        "{\"name\":\"float_from_int\",\"type\":\"float\"},"
        "{\"name\":\"float_from_string\",\"type\":\"float\"},"
        "{\"name\":\"float_from_bool\",\"type\":\"float\"},"
        "{\"name\":\"double_val\",\"type\":\"double\"}"
        "]}";

    ret = ctx_pack_json(&ctx, 1609459200,
        "{\"float_val\":3.14,\"float_from_int\":42,\"float_from_string\":\"2.71\",\"float_from_bool\":true,\"double_val\":2.718281828}");
    TEST_CHECK(ret == 0);

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Define expected conversions - type validation */
    field_expectation expectations[] = {
        {"float_val", "float", NULL, 0},          /* Type check only */
        {"float_from_int", "float", NULL, 0},     /* int 42 -> float */
        {"float_from_string", "float", NULL, 0},  /* string "2.71" -> float */
        {"float_from_bool", "float", NULL, 0},    /* bool true -> float */
        {"double_val", "double", NULL, 0}         /* Type check only */
    };

    ret = ctx_validate(&ctx, 1, expectations, 5);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* String conversions */
static void test_string_conversions(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_string");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"str_val\",\"type\":\"utf8\"},"
        "{\"name\":\"str_from_int\",\"type\":\"utf8\"},"
        "{\"name\":\"str_from_float\",\"type\":\"utf8\"},"
        "{\"name\":\"str_from_bool\",\"type\":\"utf8\"},"
        "{\"name\":\"str_from_obj\",\"type\":\"utf8\"},"     /* Object -> JSON string */
        "{\"name\":\"str_from_array\",\"type\":\"utf8\"}"    /* Array -> JSON string */
        "]}";

    ret = ctx_pack_json(&ctx, 1609459200,
        "{\"str_val\":\"test\",\"str_from_int\":42,\"str_from_float\":3.14,\"str_from_bool\":true,\"str_from_obj\":{\"key\":\"val\"},\"str_from_array\":[1,2,3]}");
    TEST_CHECK(ret == 0);

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Define expected conversions */
    field_expectation expectations[] = {
        {"str_val", "string", "test", 0},                   /* string -> string */
        {"str_from_int", "string", "42", 0},                /* int 42 -> string "42" */
        {"str_from_float", "string", "3.140000", 0},        /* float 3.14 -> string "3.140000" */
        {"str_from_bool", "string", "true", 0},             /* bool true -> string "true" */
        {"str_from_obj", "string", "{\"key\":\"val\"}", 0}, /* object -> JSON string */
        {"str_from_array", "string", "[1,2,3]", 0}          /* array -> JSON string */
    };

    ret = ctx_validate(&ctx, 1, expectations, 6);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Binary type */
static void test_binary_type(void)
{
    test_context ctx;
    const char binary_data[] = {0x00, 0x01, 0x02, 0xFF};
    int ret;

    init_test_context(&ctx, "parquet_binary");
    ctx.schema = "{\"fields\":[{\"name\":\"data\",\"type\":\"binary\"}]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "data", 4);
    msgpack_pack_bin(&ctx.packer, sizeof(binary_data));
    msgpack_pack_bin_body(&ctx.packer, binary_data, sizeof(binary_data));

    TEST_CHECK(run_conversion(&ctx) == 0);

    ret = validate_parquet_file(ctx.parquet_file, 1, "data", "binary", NULL, 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Timestamp type with conversions */
static void test_timestamp_type(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_timestamp");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"ts_int\",\"type\":{\"name\":\"timestamp\",\"unit\":\"s\"}},"
        "{\"name\":\"ts_float\",\"type\":{\"name\":\"timestamp\",\"unit\":\"ms\"}},"
        "{\"name\":\"ts_string\",\"type\":{\"name\":\"timestamp\",\"unit\":\"us\"}},"
        "{\"name\":\"ts_bool\",\"type\":{\"name\":\"timestamp\",\"unit\":\"ns\"}}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 4);

    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "ts_int", 6);
    msgpack_pack_int64(&ctx.packer, 1609459200LL);

    msgpack_pack_str(&ctx.packer, 8);
    msgpack_pack_str_body(&ctx.packer, "ts_float", 8);
    msgpack_pack_double(&ctx.packer, 1609459200000.0);

    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "ts_string", 9);
    msgpack_pack_str(&ctx.packer, 16);
    msgpack_pack_str_body(&ctx.packer, "1609459200000000", 16);

    msgpack_pack_str(&ctx.packer, 7);
    msgpack_pack_str_body(&ctx.packer, "ts_bool", 7);
    msgpack_pack_true(&ctx.packer);

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate timestamp types with different units
     * Note: Parquet format does not support second-precision timestamps.
     * Arrow automatically converts timestamp[s] to timestamp[ms].
     */
    ret = validate_parquet_file(ctx.parquet_file, -1, "ts_int", "timestamp[ms]", NULL, 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "ts_float", "timestamp[ms]", NULL, 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "ts_string", "timestamp[us]", NULL, 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "ts_bool", "timestamp[ns]", NULL, 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Nullable fields with NULL values */
static void test_nullable_fields(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_nullable");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"required_field\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"optional_field\",\"type\":\"utf8\",\"nullable\":true}"
        "]}";

    /* Record with only required field */
    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 14);
    msgpack_pack_str_body(&ctx.packer, "required_field", 14);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "test", 4);

    /* Record with NIL in optional field */
    pack_fluent_bit_record(&ctx.packer, 1609459201);
    msgpack_pack_map(&ctx.packer, 2);
    msgpack_pack_str(&ctx.packer, 14);
    msgpack_pack_str_body(&ctx.packer, "required_field", 14);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "test", 4);
    msgpack_pack_str(&ctx.packer, 14);
    msgpack_pack_str_body(&ctx.packer, "optional_field", 14);
    msgpack_pack_nil(&ctx.packer);

    TEST_CHECK(run_conversion(&ctx) == 0);

    cleanup_test_context(&ctx);
}

/* Non-nullable field with default value */
static void test_default_values(void)
{
    test_context ctx;

    init_test_context(&ctx, "parquet_defaults");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"int_field\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"str_field\",\"type\":\"utf8\",\"nullable\":false}"
        "]}";

    /* Record missing str_field - should get default empty string */
    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "int_field", 9);
    msgpack_pack_int(&ctx.packer, 42);

    TEST_CHECK(run_conversion(&ctx) == 0);

    cleanup_test_context(&ctx);
}

/* All compression types - tests GZIP, Snappy, ZSTD, and None */
static void test_all_compression_types(void)
{
    const int compressions[] = {
        FLB_AWS_COMPRESS_NONE,
        FLB_AWS_COMPRESS_GZIP,
        FLB_AWS_COMPRESS_SNAPPY,
        FLB_AWS_COMPRESS_ZSTD
    };
    const char *names[] = {"none", "gzip", "snappy", "zstd"};
    const char *test_data[] = {
        "{\"data\":\"uncompressed\"}",
        "{\"data\":\"gzip compressed\"}",
        "{\"data\":\"snappy compressed\"}",
        "{\"data\":\"zstd compressed\"}"
    };
    const char *schema = "{\"fields\":[{\"name\":\"data\",\"type\":\"utf8\"}]}";
    int i;

    for (i = 0; i < 4; i++) {
        msgpack_sbuffer sbuf;
        msgpack_packer packer;
        char msgpack_file[256], parquet_file[256];
        size_t parquet_size = 0;
        int ret;

        snprintf(msgpack_file, sizeof(msgpack_file),
                 "/tmp/flb_test_compress_%s.msgpack", names[i]);
        snprintf(parquet_file, sizeof(parquet_file),
                 "/tmp/flb_test_compress_%s.parquet", names[i]);

        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

        ret = pack_json_record(&sbuf, &packer, 1609459200, test_data[i]);
        TEST_CHECK(ret == 0);

        ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
        TEST_CHECK(ret == 0);

        ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                          compressions[i],
                                                          parquet_file, &parquet_size, 0);
        TEST_CHECK(ret == 0);
        TEST_CHECK(check_parquet_file(parquet_file, NULL) == 0);

        /* Validate data can be read back correctly */
        ret = validate_parquet_file(parquet_file, 1, "data", "string", NULL, 0);
        TEST_CHECK(ret == 0);

        msgpack_sbuffer_destroy(&sbuf);
        unlink(msgpack_file);
        unlink(parquet_file);
    }
}

/* Empty strings and binary data */
static void test_boundary_empty_data(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_empty");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"empty_str\",\"type\":\"utf8\"},"
        "{\"name\":\"empty_bin\",\"type\":\"binary\"}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 2);

    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "empty_str", 9);
    msgpack_pack_str(&ctx.packer, 0);

    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "empty_bin", 9);
    msgpack_pack_bin(&ctx.packer, 0);

    TEST_CHECK(run_conversion(&ctx) == 0);

    ret = validate_parquet_file(ctx.parquet_file, 1, "empty_str", "string", "", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Extreme integer values */
static void test_boundary_extreme_integers(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_extreme_int");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"int32_min\",\"type\":\"int32\"},"
        "{\"name\":\"int32_max\",\"type\":\"int32\"},"
        "{\"name\":\"int64_min\",\"type\":\"int64\"},"
        "{\"name\":\"int64_max\",\"type\":\"int64\"}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 4);

    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "int32_min", 9);
    msgpack_pack_int64(&ctx.packer, -2147483648LL);  /* INT32_MIN */

    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "int32_max", 9);
    msgpack_pack_int64(&ctx.packer, 2147483647LL);  /* INT32_MAX */

    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "int64_min", 9);
    msgpack_pack_int64(&ctx.packer, -9223372036854775807LL - 1);  /* INT64_MIN */

    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "int64_max", 9);
    msgpack_pack_int64(&ctx.packer, 9223372036854775807LL);  /* INT64_MAX */

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate extreme integer values */
    ret = validate_parquet_file(ctx.parquet_file, 1, "int32_min", "int32", "-2147483648", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "int32_max", "int32", "2147483647", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "int64_min", "int64", "-9223372036854775808", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "int64_max", "int64", "9223372036854775807", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Special floating point values */
static void test_boundary_special_floats(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_special_float");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"zero\",\"type\":\"double\"},"
        "{\"name\":\"neg_zero\",\"type\":\"double\"},"
        "{\"name\":\"very_small\",\"type\":\"double\"},"
        "{\"name\":\"very_large\",\"type\":\"double\"}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 4);

    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "zero", 4);
    msgpack_pack_double(&ctx.packer, 0.0);

    msgpack_pack_str(&ctx.packer, 8);
    msgpack_pack_str_body(&ctx.packer, "neg_zero", 8);
    msgpack_pack_double(&ctx.packer, -0.0);

    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "very_small", 10);
    msgpack_pack_double(&ctx.packer, 1.0e-308);  /* Near DBL_MIN */

    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "very_large", 10);
    msgpack_pack_double(&ctx.packer, 1.0e308);  /* Near DBL_MAX */

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate zero values */
    ret = validate_parquet_file(ctx.parquet_file, 1, "zero", "double", "0.000000", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Very long strings */
static void test_boundary_long_string(void)
{
    test_context ctx;
    int ret, i;
    const size_t long_str_size = 100000;  /* 100KB string */
    char *long_str = (char *)malloc(long_str_size);

    if (!long_str) {
        TEST_CHECK(0);  /* Memory allocation failed */
        return;
    }

    /* Fill with repeating pattern */
    for (i = 0; i < long_str_size; i++) {
        long_str[i] = 'A' + (i % 26);
    }

    init_test_context(&ctx, "parquet_long_str");
    ctx.schema = "{\"fields\":[{\"name\":\"long_text\",\"type\":\"utf8\"}]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "long_text", 9);
    msgpack_pack_str(&ctx.packer, long_str_size);
    msgpack_pack_str_body(&ctx.packer, long_str, long_str_size);

    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate record count for long string */
    ret = validate_parquet_file(ctx.parquet_file, 1, NULL, NULL, NULL, 0);
    TEST_CHECK(ret == 0);

    free(long_str);
    cleanup_test_context(&ctx);
}

/* Empty map (no fields) */
static void test_boundary_empty_map(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_empty_map");
    ctx.schema = "{\"fields\":[{\"name\":\"field1\",\"type\":\"utf8\",\"nullable\":true}]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 0);

    TEST_CHECK(run_conversion(&ctx) == 0);

    ret = validate_parquet_file(ctx.parquet_file, 1, NULL, NULL, NULL, 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Zero value boundary for all numeric types */
static void test_boundary_zero_values(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_zeros");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"int32_zero\",\"type\":\"int32\"},"
        "{\"name\":\"int64_zero\",\"type\":\"int64\"},"
        "{\"name\":\"float_zero\",\"type\":\"float\"},"
        "{\"name\":\"double_zero\",\"type\":\"double\"}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 4);

    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "int32_zero", 10);
    msgpack_pack_int(&ctx.packer, 0);

    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "int64_zero", 10);
    msgpack_pack_int64(&ctx.packer, 0LL);

    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "float_zero", 10);
    msgpack_pack_float(&ctx.packer, 0.0f);

    msgpack_pack_str(&ctx.packer, 11);
    msgpack_pack_str_body(&ctx.packer, "double_zero", 11);
    msgpack_pack_double(&ctx.packer, 0.0);

    TEST_CHECK(run_conversion(&ctx) == 0);

    ret = validate_parquet_file(ctx.parquet_file, 1, "int32_zero", "int32", "0", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "int64_zero", "int64", "0", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Truncated/corrupted msgpack data */
static void test_destructive_truncated_data(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_truncated");
    ctx.schema = "{\"fields\":[{\"name\":\"message\",\"type\":\"utf8\"}]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 7);
    msgpack_pack_str_body(&ctx.packer, "message", 7);
    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "test", 4);  /* Only write 4 bytes but claim 10 */

    /* Write truncated data */
    ret = write_msgpack_to_chunk_file(ctx.msgpack_file, ctx.sbuf.data, ctx.sbuf.size / 2);
    TEST_CHECK(ret == 0);

    ret = flb_msgpack_raw_to_parquet_file_streaming(ctx.msgpack_file, ctx.schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      ctx.parquet_file, &ctx.parquet_size, 0);
    TEST_CHECK(ret == -1);  /* Should fail */

    cleanup_test_context(&ctx);
}

/* Invalid JSON schema */
static void test_destructive_invalid_schema_json(void)
{
    test_context ctx;
    int ret;
    const char *bad_schema = "{\"fields\":[{\"name\":\"test\",\"type\":\"utf8\"";  /* Missing closing braces */

    init_test_context(&ctx, "parquet_bad_schema");

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "test", 4);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "data", 4);

    ret = write_msgpack_to_chunk_file(ctx.msgpack_file, ctx.sbuf.data, ctx.sbuf.size);
    TEST_CHECK(ret == 0);

    ret = flb_msgpack_raw_to_parquet_file_streaming(ctx.msgpack_file, bad_schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      ctx.parquet_file, &ctx.parquet_size, 0);
    TEST_CHECK(ret == -1);  /* Should fail */

    cleanup_test_context(&ctx);
}

/* Empty schema (no fields) */
static void test_destructive_empty_schema(void)
{
    test_context ctx;
    int ret;
    const char *empty_schema = "{\"fields\":[]}";  /* No fields */

    init_test_context(&ctx, "parquet_empty_schema");

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "test", 4);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "data", 4);

    ret = write_msgpack_to_chunk_file(ctx.msgpack_file, ctx.sbuf.data, ctx.sbuf.size);
    TEST_CHECK(ret == 0);

    ret = flb_msgpack_raw_to_parquet_file_streaming(ctx.msgpack_file, empty_schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      ctx.parquet_file, &ctx.parquet_size, 0);
    TEST_CHECK(ret == -1);  /* Should fail */

    cleanup_test_context(&ctx);
}

/* Schema with unsupported type */
static void test_destructive_unsupported_type(void)
{
    test_context ctx;

    init_test_context(&ctx, "parquet_unsupported");
    ctx.schema = "{\"fields\":[{\"name\":\"test\",\"type\":\"unknown_type\"}]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "test", 4);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "data", 4);

    /* Should fall back to utf8 type and succeed */
    TEST_CHECK(run_conversion(&ctx) == 0);

    cleanup_test_context(&ctx);
}

/* Invalid compression type */
static void test_destructive_invalid_compression(void)
{
    test_context ctx;

    init_test_context(&ctx, "parquet_bad_compress");
    ctx.schema = "{\"fields\":[{\"name\":\"test\",\"type\":\"utf8\"}]}";
    ctx.compression = 999;  /* Invalid compression type */

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "test", 4);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "data", 4);

    /* Use invalid compression type (should default to UNCOMPRESSED) */
    TEST_CHECK(run_conversion(&ctx) == 0);  /* Should succeed with default compression */

    cleanup_test_context(&ctx);
}

/* Type conversion failure - unparseable string */
static void test_destructive_unparseable_conversion(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_bad_convert");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"int_field\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"float_field\",\"type\":\"float\",\"nullable\":false},"
        "{\"name\":\"bool_field\",\"type\":\"bool\",\"nullable\":false}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 3);

    /* Strings that cannot be parsed to respective types */
    msgpack_pack_str(&ctx.packer, 9);
    msgpack_pack_str_body(&ctx.packer, "int_field", 9);
    msgpack_pack_str(&ctx.packer, 12);
    msgpack_pack_str_body(&ctx.packer, "not_a_number", 12);

    msgpack_pack_str(&ctx.packer, 11);
    msgpack_pack_str_body(&ctx.packer, "float_field", 11);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "xyz123", 6);

    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "bool_field", 10);
    msgpack_pack_str(&ctx.packer, 7);
    msgpack_pack_str_body(&ctx.packer, "invalid", 7);

    /* Should use default values (0, 0.0, false) */
    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate default values are used for unparseable conversions */
    ret = validate_parquet_file(ctx.parquet_file, -1, "int_field", "int32", "0", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "float_field", "float", "0.000000", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "bool_field", "bool", "false", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* NULL input parameters */
static void test_error_null_input(void)
{
    const char *parquet_file = "/tmp/flb_test_parquet_error.parquet";
    size_t parquet_size = 0;
    int ret;
    const char *schema = "{\"fields\":[{\"name\":\"test\",\"type\":\"utf8\"}]}";

    ret = flb_msgpack_raw_to_parquet_file_streaming(NULL, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == -1);
    unlink(parquet_file);
}

/* NULL schema */
static void test_error_null_schema(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_parquet_noschema.msgpack";
    const char *parquet_file = "/tmp/flb_test_parquet_noschema.parquet";
    size_t parquet_size = 0;
    int ret;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    pack_fluent_bit_record(&packer, 1609459200);
    msgpack_pack_map(&packer, 1);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "test", 4);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "data", 4);

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, NULL,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == -1);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Nonexistent input file */
static void test_error_missing_file(void)
{
    const char *msgpack_file = "/tmp/flb_test_parquet_nonexistent.msgpack";
    const char *parquet_file = "/tmp/flb_test_parquet_nonexistent.parquet";
    size_t parquet_size = 0;
    int ret;
    const char *schema = "{\"fields\":[{\"name\":\"test\",\"type\":\"utf8\"}]}";

    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == -1);
    unlink(parquet_file);
}

/* Invalid record format (not array) */
static void test_error_invalid_format(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "parquet_invalid");
    ctx.schema = "{\"fields\":[{\"name\":\"test\",\"type\":\"utf8\"}]}";

    /* Pack just a map, not [timestamp, map] */
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "test", 4);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "data", 4);

    ret = write_msgpack_to_chunk_file(ctx.msgpack_file, ctx.sbuf.data, ctx.sbuf.size);
    TEST_CHECK(ret == 0);

    /* Should skip invalid records, resulting in no records */
    ret = flb_msgpack_raw_to_parquet_file_streaming(ctx.msgpack_file, ctx.schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      ctx.parquet_file, &ctx.parquet_size, 0);
    TEST_CHECK(ret == -1);  /* No records processed */

    cleanup_test_context(&ctx);
}

/* Schema has MORE fields than data - Critical for crash fix validation */
static void test_edge_schema_more_fields(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "edge_more_schema");
    /* Schema has 5 fields */
    ctx.schema = "{\"fields\":["
        "{\"name\":\"field1\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"field2\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"field3\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"field4\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"field5\",\"type\":\"utf8\",\"nullable\":false}"
        "]}";

    /* Data only has 2 fields - field3, field4, field5 missing */
    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 2);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "field1", 6);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "val1", 4);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "field2", 6);
    msgpack_pack_int(&ctx.packer, 42);

    /* Should succeed - missing fields get default values */
    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate present fields */
    ret = validate_parquet_file(ctx.parquet_file, 1, "field2", "int32", "42", 0);
    TEST_CHECK(ret == 0);

    /* Validate missing fields got default values */
    ret = validate_parquet_file(ctx.parquet_file, -1, "field3", "string", "", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "field4", "int32", "0", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Schema has LESS fields than data */
static void test_edge_schema_less_fields(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "edge_less_schema");
    /* Schema only has 2 fields */
    ctx.schema = "{\"fields\":["
        "{\"name\":\"field1\",\"type\":\"utf8\"},"
        "{\"name\":\"field2\",\"type\":\"int32\"}"
        "]}";

    /* Data has 5 fields - extra fields should be ignored */
    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 5);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "field1", 6);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "val1", 4);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "field2", 6);
    msgpack_pack_int(&ctx.packer, 42);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "field3", 6);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "val3", 4);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "field4", 6);
    msgpack_pack_int(&ctx.packer, 99);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "field5", 6);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "val5", 4);

    /* Should succeed - extra data fields ignored */
    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate only schema fields are present */
    ret = validate_parquet_file(ctx.parquet_file, 1, "field1", "string", "val1", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "field2", "int32", "42", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Field name mismatch */
static void test_edge_field_name_mismatch(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "edge_name_mismatch");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"expected_field\",\"type\":\"utf8\",\"nullable\":false}"
        "]}";

    /* Data has different field name */
    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 12);
    msgpack_pack_str_body(&ctx.packer, "actual_field", 12);
    msgpack_pack_str(&ctx.packer, 4);
    msgpack_pack_str_body(&ctx.packer, "data", 4);

    /* Should succeed - missing field gets default */
    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate default value used */
    ret = validate_parquet_file(ctx.parquet_file, 1, "expected_field", "string", "", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* ALL fields missing from data */
static void test_edge_all_fields_missing(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "edge_all_missing");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"field1\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"field2\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"field3\",\"type\":\"bool\",\"nullable\":false}"
        "]}";

    /* Data has completely different fields */
    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 2);
    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "unrelated1", 10);
    msgpack_pack_str(&ctx.packer, 3);
    msgpack_pack_str_body(&ctx.packer, "xyz", 3);
    msgpack_pack_str(&ctx.packer, 10);
    msgpack_pack_str_body(&ctx.packer, "unrelated2", 10);
    msgpack_pack_int(&ctx.packer, 999);

    /* Should succeed - all fields get defaults */
    TEST_CHECK(run_conversion(&ctx) == 0);

    /* Validate all default values */
    ret = validate_parquet_file(ctx.parquet_file, 1, "field1", "string", "", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "field2", "int32", "0", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(ctx.parquet_file, -1, "field3", "bool", "false", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

/* Mixed present and missing fields */
static void test_edge_mixed_present_missing(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_edge_mixed.msgpack";
    const char *parquet_file = "/tmp/flb_test_edge_mixed.parquet";
    size_t parquet_size = 0;
    int ret, i;
    const char *schema = "{\"fields\":["
        "{\"name\":\"id\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"name\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"score\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"status\",\"type\":\"utf8\",\"nullable\":false}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    /* Multiple records with different field patterns */
    for (i = 0; i < 10; i++) {
        pack_fluent_bit_record(&packer, 1609459200 + i);

        if (i % 3 == 0) {
            /* All fields present */
            msgpack_pack_map(&packer, 4);
            msgpack_pack_str(&packer, 2);
            msgpack_pack_str_body(&packer, "id", 2);
            msgpack_pack_int(&packer, i);
            msgpack_pack_str(&packer, 4);
            msgpack_pack_str_body(&packer, "name", 4);
            msgpack_pack_str(&packer, 4);
            msgpack_pack_str_body(&packer, "test", 4);
            msgpack_pack_str(&packer, 5);
            msgpack_pack_str_body(&packer, "score", 5);
            msgpack_pack_int(&packer, i * 10);
            msgpack_pack_str(&packer, 6);
            msgpack_pack_str_body(&packer, "status", 6);
            msgpack_pack_str(&packer, 2);
            msgpack_pack_str_body(&packer, "ok", 2);
        } else if (i % 3 == 1) {
            /* Only id and name */
            msgpack_pack_map(&packer, 2);
            msgpack_pack_str(&packer, 2);
            msgpack_pack_str_body(&packer, "id", 2);
            msgpack_pack_int(&packer, i);
            msgpack_pack_str(&packer, 4);
            msgpack_pack_str_body(&packer, "name", 4);
            msgpack_pack_str(&packer, 7);
            msgpack_pack_str_body(&packer, "partial", 7);
        } else {
            /* Only id */
            msgpack_pack_map(&packer, 1);
            msgpack_pack_str(&packer, 2);
            msgpack_pack_str_body(&packer, "id", 2);
            msgpack_pack_int(&packer, i);
        }
    }

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    /* Should succeed */
    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == 0);
    TEST_CHECK(check_parquet_file(parquet_file, NULL) == 0);

    /* Validate record count */
    ret = validate_parquet_file(parquet_file, 10, NULL, NULL, NULL, 0);
    TEST_CHECK(ret == 0);

    /* Validate some values */
    ret = validate_parquet_file(parquet_file, -1, "id", "int32", "0", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "name", "string", "partial", 1);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Schema with many fields (50+) */
static void test_boundary_many_schema_fields(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_many_schema_fields.msgpack";
    const char *parquet_file = "/tmp/flb_test_many_schema_fields.parquet";
    size_t parquet_size = 0;
    int ret, i;
    char schema_buf[8192];
    int offset = 0;

    /* Build schema with 50 fields */
    offset += snprintf(schema_buf + offset, sizeof(schema_buf) - offset, "{\"fields\":[");
    for (i = 0; i < 50; i++) {
        if (i > 0) offset += snprintf(schema_buf + offset, sizeof(schema_buf) - offset, ",");
        offset += snprintf(schema_buf + offset, sizeof(schema_buf) - offset,
                          "{\"name\":\"field%d\",\"type\":\"int32\",\"nullable\":false}", i);
    }
    offset += snprintf(schema_buf + offset, sizeof(schema_buf) - offset, "]}");

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    /* Data only has first 10 fields */
    pack_fluent_bit_record(&packer, 1609459200);
    msgpack_pack_map(&packer, 10);
    for (i = 0; i < 10; i++) {
        char field_name[20];
        snprintf(field_name, sizeof(field_name), "field%d", i);
        msgpack_pack_str(&packer, strlen(field_name));
        msgpack_pack_str_body(&packer, field_name, strlen(field_name));
        msgpack_pack_int(&packer, i * 10);
    }

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    /* Should succeed - missing 40 fields get defaults */
    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema_buf,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Data with many fields (100+) but schema only has few */
static void test_boundary_many_data_fields(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_many_data_fields.msgpack";
    const char *parquet_file = "/tmp/flb_test_many_data_fields.parquet";
    size_t parquet_size = 0;
    int ret, i;
    const char *schema = "{\"fields\":["
        "{\"name\":\"field0\",\"type\":\"int32\"},"
        "{\"name\":\"field50\",\"type\":\"int32\"}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    /* Data has 100 fields */
    pack_fluent_bit_record(&packer, 1609459200);
    msgpack_pack_map(&packer, 100);
    for (i = 0; i < 100; i++) {
        char field_name[20];
        snprintf(field_name, sizeof(field_name), "field%d", i);
        msgpack_pack_str(&packer, strlen(field_name));
        msgpack_pack_str_body(&packer, field_name, strlen(field_name));
        msgpack_pack_int(&packer, i);
    }

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    /* Should succeed - only field0 and field50 extracted */
    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == 0);

    /* Validate correct fields extracted */
    ret = validate_parquet_file(parquet_file, 1, "field0", "int32", "0", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "field50", "int32", "50", 0);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Single field with many records */
static void test_boundary_single_field_many_records(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_single_field.msgpack";
    const char *parquet_file = "/tmp/flb_test_single_field.parquet";
    size_t parquet_size = 0;
    int ret, i;
    const char *schema = "{\"fields\":[{\"name\":\"value\",\"type\":\"int32\",\"nullable\":false}]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    /* 1000 records with single field */
    for (i = 0; i < 1000; i++) {
        pack_fluent_bit_record(&packer, 1609459200 + i);
        msgpack_pack_map(&packer, 1);
        msgpack_pack_str(&packer, 5);
        msgpack_pack_str_body(&packer, "value", 5);
        msgpack_pack_int(&packer, i);
    }

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == 0);

    /* Validate count and some values */
    ret = validate_parquet_file(parquet_file, 1000, NULL, NULL, NULL, 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "value", "int32", "0", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "value", "int32", "999", 999);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Schema evolution (new schema with old data) */
static void test_realworld_schema_evolution(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_schema_evolution.msgpack";
    const char *parquet_file = "/tmp/flb_test_schema_evolution.parquet";
    size_t parquet_size = 0;
    int ret;
    /* New schema with added fields */
    const char *schema = "{\"fields\":["
        "{\"name\":\"message\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"level\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"timestamp\",\"type\":\"int64\",\"nullable\":false},"  /* New field */
        "{\"name\":\"source\",\"type\":\"utf8\",\"nullable\":false}"       /* New field */
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    /* Old data format (only message and level) */
    pack_fluent_bit_record(&packer, 1609459200);
    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "message", 7);
    msgpack_pack_str(&packer, 8);
    msgpack_pack_str_body(&packer, "old data", 8);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "level", 5);
    msgpack_pack_int(&packer, 1);

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    /* Should succeed with defaults for new fields */
    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == 0);

    /* Validate old fields preserved */
    ret = validate_parquet_file(parquet_file, 1, "message", "string", "old data", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "level", "int32", "1", 0);
    TEST_CHECK(ret == 0);

    /* Validate new fields have defaults */
    ret = validate_parquet_file(parquet_file, -1, "timestamp", "int64", "0", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "source", "string", "", 0);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Partial record (simulates crashed fluent-bit) */
static void test_realworld_partial_record(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_partial.msgpack";
    const char *parquet_file = "/tmp/flb_test_partial.parquet";
    size_t parquet_size = 0;
    int ret;
    const char *schema = "{\"fields\":["
        "{\"name\":\"field1\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"field2\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"field3\",\"type\":\"utf8\",\"nullable\":false}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    /* Complete record */
    pack_fluent_bit_record(&packer, 1609459200);
    msgpack_pack_map(&packer, 3);
    msgpack_pack_str(&packer, 6);
    msgpack_pack_str_body(&packer, "field1", 6);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "val1", 4);
    msgpack_pack_str(&packer, 6);
    msgpack_pack_str_body(&packer, "field2", 6);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "val2", 4);
    msgpack_pack_str(&packer, 6);
    msgpack_pack_str_body(&packer, "field3", 6);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "val3", 4);

    /* Partial record (missing field3) */
    pack_fluent_bit_record(&packer, 1609459201);
    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 6);
    msgpack_pack_str_body(&packer, "field1", 6);
    msgpack_pack_str(&packer, 8);
    msgpack_pack_str_body(&packer, "partial1", 8);
    msgpack_pack_str(&packer, 6);
    msgpack_pack_str_body(&packer, "field2", 6);
    msgpack_pack_str(&packer, 8);
    msgpack_pack_str_body(&packer, "partial2", 8);

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    /* Should succeed */
    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == 0);

    /* Validate both records */
    ret = validate_parquet_file(parquet_file, 2, NULL, NULL, NULL, 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "field1", "string", "val1", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "field1", "string", "partial1", 1);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "field3", "string", "", 1);  /* Default */
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Extra data fields not in schema */
static void test_realworld_extra_data_fields(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_extra_fields.msgpack";
    const char *parquet_file = "/tmp/flb_test_extra_fields.parquet";
    size_t parquet_size = 0;
    int ret, i;
    /* Schema only defines 3 important fields */
    const char *schema = "{\"fields\":["
        "{\"name\":\"log_level\",\"type\":\"int32\",\"nullable\":false},"
        "{\"name\":\"message\",\"type\":\"utf8\",\"nullable\":false},"
        "{\"name\":\"timestamp\",\"type\":\"int64\",\"nullable\":false}"
        "]}";

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    /* Multiple records with many extra fields */
    for (i = 0; i < 5; i++) {
        pack_fluent_bit_record(&packer, 1609459200 + i);
        msgpack_pack_map(&packer, 10);  /* 10 fields but schema only has 3 */

        /* Schema fields */
        msgpack_pack_str(&packer, 9);
        msgpack_pack_str_body(&packer, "log_level", 9);
        msgpack_pack_int(&packer, i % 3);

        msgpack_pack_str(&packer, 7);
        msgpack_pack_str_body(&packer, "message", 7);
        msgpack_pack_str(&packer, 8);
        msgpack_pack_str_body(&packer, "test msg", 8);

        msgpack_pack_str(&packer, 9);
        msgpack_pack_str_body(&packer, "timestamp", 9);
        msgpack_pack_int64(&packer, 1609459200LL + i);

        /* Extra fields not in schema */
        msgpack_pack_str(&packer, 8);
        msgpack_pack_str_body(&packer, "hostname", 8);
        msgpack_pack_str(&packer, 7);
        msgpack_pack_str_body(&packer, "server1", 7);

        msgpack_pack_str(&packer, 3);
        msgpack_pack_str_body(&packer, "pid", 3);
        msgpack_pack_int(&packer, 1234);

        msgpack_pack_str(&packer, 4);
        msgpack_pack_str_body(&packer, "user", 4);
        msgpack_pack_str(&packer, 4);
        msgpack_pack_str_body(&packer, "root", 4);

        msgpack_pack_str(&packer, 7);
        msgpack_pack_str_body(&packer, "service", 7);
        msgpack_pack_str(&packer, 3);
        msgpack_pack_str_body(&packer, "web", 3);

        msgpack_pack_str(&packer, 7);
        msgpack_pack_str_body(&packer, "version", 7);
        msgpack_pack_str(&packer, 5);
        msgpack_pack_str_body(&packer, "1.0.0", 5);

        msgpack_pack_str(&packer, 11);
        msgpack_pack_str_body(&packer, "environment", 11);
        msgpack_pack_str(&packer, 4);
        msgpack_pack_str_body(&packer, "prod", 4);

        msgpack_pack_str(&packer, 6);
        msgpack_pack_str_body(&packer, "region", 6);
        msgpack_pack_str(&packer, 7);
        msgpack_pack_str_body(&packer, "us-west", 7);
    }

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    /* Should succeed - only schema fields extracted */
    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == 0);

    /* Validate schema fields present */
    ret = validate_parquet_file(parquet_file, 5, NULL, NULL, NULL, 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "log_level", "int32", "0", 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "log_level", "int32", "1", 1);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Batch boundary tests - tests 65536 boundary and multiple batches */
static void test_batch_boundaries(void)
{
    const int test_counts[] = {65535, 65536, 65537, 131072};
    const char *names[] = {"below", "exact", "above", "double"};
    const char *schema = "{\"fields\":[{\"name\":\"id\",\"type\":\"int32\"}]}";
    int t, i, ret;

    for (t = 0; t < 4; t++) {
        msgpack_sbuffer sbuf;
        msgpack_packer packer;
        char msgpack_file[256], parquet_file[256];
        size_t parquet_size = 0;
        const int record_count = test_counts[t];

        snprintf(msgpack_file, sizeof(msgpack_file),
                 "/tmp/flb_test_batch_%s.msgpack", names[t]);
        snprintf(parquet_file, sizeof(parquet_file),
                 "/tmp/flb_test_batch_%s.parquet", names[t]);

        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

        for (i = 0; i < record_count; i++) {
            pack_fluent_bit_record(&packer, 1609459200 + i);
            msgpack_pack_map(&packer, 1);
            msgpack_pack_str(&packer, 2);
            msgpack_pack_str_body(&packer, "id", 2);
            msgpack_pack_int(&packer, i);
        }

        ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
        TEST_CHECK(ret == 0);

        ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                          FLB_AWS_COMPRESS_NONE,
                                                          parquet_file, &parquet_size, 0);
        TEST_CHECK(ret == 0);
        TEST_CHECK(check_parquet_file(parquet_file, NULL) == 0);

        /* Validate count */
        ret = validate_parquet_file(parquet_file, record_count, NULL, NULL, NULL, 0);
        TEST_CHECK(ret == 0);

        /* Validate boundary records */
        ret = validate_parquet_file(parquet_file, -1, "id", "int32", "0", 0);
        TEST_CHECK(ret == 0);

        if (record_count > 65535) {
            ret = validate_parquet_file(parquet_file, -1, "id", "int32", "65535", 65535);
            TEST_CHECK(ret == 0);
        }

        if (record_count > 65536) {
            ret = validate_parquet_file(parquet_file, -1, "id", "int32", "65536", 65536);
            TEST_CHECK(ret == 0);
        }

        char last_val[20];
        snprintf(last_val, sizeof(last_val), "%d", record_count - 1);
        ret = validate_parquet_file(parquet_file, -1, "id", "int32", last_val, record_count - 1);
        TEST_CHECK(ret == 0);

        msgpack_sbuffer_destroy(&sbuf);
        unlink(msgpack_file);
        unlink(parquet_file);
    }
}

/* Special floating point values - NaN, +Infinity, -Infinity */
static void test_special_float_values(void)
{
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    const char *msgpack_file = "/tmp/flb_test_special_floats.msgpack";
    const char *parquet_file = "/tmp/flb_test_special_floats.parquet";
    size_t parquet_size = 0;
    int ret;
    const char *schema = "{\"fields\":["
        "{\"name\":\"float_nan\",\"type\":\"float\"},"
        "{\"name\":\"float_inf\",\"type\":\"float\"},"
        "{\"name\":\"float_neg_inf\",\"type\":\"float\"},"
        "{\"name\":\"double_nan\",\"type\":\"double\"},"
        "{\"name\":\"double_inf\",\"type\":\"double\"},"
        "{\"name\":\"double_neg_inf\",\"type\":\"double\"}"
        "]}";

    /* Use standard macros from math.h instead of division-by-zero
     * which can trap (SIGFPE) if FP exceptions are enabled */
    const double nan_val = NAN;
    const double inf_val = INFINITY;
    const double neg_inf_val = -INFINITY;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);

    pack_fluent_bit_record(&packer, 1609459200);
    msgpack_pack_map(&packer, 6);

    msgpack_pack_str(&packer, 9);
    msgpack_pack_str_body(&packer, "float_nan", 9);
    msgpack_pack_float(&packer, (float)nan_val);

    msgpack_pack_str(&packer, 9);
    msgpack_pack_str_body(&packer, "float_inf", 9);
    msgpack_pack_float(&packer, (float)inf_val);

    msgpack_pack_str(&packer, 13);
    msgpack_pack_str_body(&packer, "float_neg_inf", 13);
    msgpack_pack_float(&packer, (float)neg_inf_val);

    msgpack_pack_str(&packer, 10);
    msgpack_pack_str_body(&packer, "double_nan", 10);
    msgpack_pack_double(&packer, nan_val);

    msgpack_pack_str(&packer, 10);
    msgpack_pack_str_body(&packer, "double_inf", 10);
    msgpack_pack_double(&packer, inf_val);

    msgpack_pack_str(&packer, 14);
    msgpack_pack_str_body(&packer, "double_neg_inf", 14);
    msgpack_pack_double(&packer, neg_inf_val);

    ret = write_msgpack_to_chunk_file(msgpack_file, sbuf.data, sbuf.size);
    TEST_CHECK(ret == 0);

    /* Should succeed - NaN and Infinity are valid IEEE 754 */
    ret = flb_msgpack_raw_to_parquet_file_streaming(msgpack_file, schema,
                                                      FLB_AWS_COMPRESS_NONE,
                                                      parquet_file, &parquet_size, 0);
    TEST_CHECK(ret == 0);
    TEST_CHECK(check_parquet_file(parquet_file, NULL) == 0);

    /* Validate all special values are present (type check only) */
    ret = validate_parquet_file(parquet_file, 1, "float_nan", "float", NULL, 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "float_inf", "float", NULL, 0);
    TEST_CHECK(ret == 0);
    ret = validate_parquet_file(parquet_file, -1, "double_nan", "double", NULL, 0);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_destroy(&sbuf);
    unlink(msgpack_file);
    unlink(parquet_file);
}

/* Negative timestamp */
static void test_timestamp_negative(void)
{
    test_context ctx;

    init_test_context(&ctx, "ts_negative");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"ts_negative\",\"type\":{\"name\":\"timestamp\",\"unit\":\"s\"}}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 11);
    msgpack_pack_str_body(&ctx.packer, "ts_negative", 11);
    msgpack_pack_int64(&ctx.packer, -1609459200LL);

    TEST_CHECK(run_conversion(&ctx) == 0);

    cleanup_test_context(&ctx);
}

/* Zero timestamp (Unix epoch) */
static void test_timestamp_zero(void)
{
    test_context ctx;

    init_test_context(&ctx, "ts_zero");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"ts_zero\",\"type\":{\"name\":\"timestamp\",\"unit\":\"ms\"}}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 7);
    msgpack_pack_str_body(&ctx.packer, "ts_zero", 7);
    msgpack_pack_int64(&ctx.packer, 0LL);

    TEST_CHECK(run_conversion(&ctx) == 0);

    cleanup_test_context(&ctx);
}

/* Maximum int64 timestamp */
static void test_timestamp_max_int64(void)
{
    test_context ctx;
    int ret;

    init_test_context(&ctx, "ts_max");
    ctx.schema = "{\"fields\":["
        "{\"name\":\"ts_max\",\"type\":{\"name\":\"timestamp\",\"unit\":\"ns\"}}"
        "]}";

    pack_fluent_bit_record(&ctx.packer, 1609459200);
    msgpack_pack_map(&ctx.packer, 1);
    msgpack_pack_str(&ctx.packer, 6);
    msgpack_pack_str_body(&ctx.packer, "ts_max", 6);
    msgpack_pack_int64(&ctx.packer, 9223372036854775807LL);

    TEST_CHECK(run_conversion(&ctx) == 0);

    ret = validate_parquet_file(ctx.parquet_file, 1, "ts_max", "timestamp[ns]", "9223372036854775807", 0);
    TEST_CHECK(ret == 0);

    cleanup_test_context(&ctx);
}

TEST_LIST = {
    /* =========================================================================
     * CATEGORY 1: FUNCTIONAL TESTS (9 tests)
     * Basic functionality and type conversion tests
     * ========================================================================= */
    {"basic_conversion", test_basic_conversion},
    {"multiple_records", test_multiple_records},
    {"large_record_count", test_large_record_count},
    {"bool_conversions", test_bool_conversions},
    {"integer_conversions", test_integer_conversions},
    {"float_conversions", test_float_conversions},
    {"string_conversions", test_string_conversions},
    {"binary_type", test_binary_type},
    {"timestamp_type", test_timestamp_type},

    /* =========================================================================
     * CATEGORY 2: DATA QUALITY TESTS (12 tests)
     * NULL handling, schema mismatches, and data integrity
     * ========================================================================= */
    {"nullable_fields", test_nullable_fields},
    {"default_values", test_default_values},
    {"edge_schema_more_fields", test_edge_schema_more_fields},
    {"edge_schema_less_fields", test_edge_schema_less_fields},
    {"edge_field_name_mismatch", test_edge_field_name_mismatch},
    {"edge_all_fields_missing", test_edge_all_fields_missing},
    {"edge_mixed_present_missing", test_edge_mixed_present_missing},
    {"boundary_many_schema_fields", test_boundary_many_schema_fields},
    {"boundary_many_data_fields", test_boundary_many_data_fields},
    {"boundary_single_field_many_records", test_boundary_single_field_many_records},
    {"boundary_empty_data", test_boundary_empty_data},
    {"boundary_empty_map", test_boundary_empty_map},

    /* =========================================================================
     * CATEGORY 3: SCALE & BOUNDARY TESTS (9 tests - OPTIMIZED)
     * Batch processing, extreme values, and boundary conditions
     * ========================================================================= */
    {"batch_boundaries", test_batch_boundaries},               /* Tests 65535, 65536, 65537, 131072 */
    {"boundary_extreme_integers", test_boundary_extreme_integers},
    {"boundary_special_floats", test_boundary_special_floats},
    {"boundary_zero_values", test_boundary_zero_values},
    {"boundary_long_string", test_boundary_long_string},
    {"special_float_values", test_special_float_values},       /* Tests NaN, +Inf, -Inf */
    {"timestamp_negative", test_timestamp_negative},
    {"timestamp_zero", test_timestamp_zero},
    {"timestamp_max_int64", test_timestamp_max_int64},

    /* =========================================================================
     * CATEGORY 4: COMPRESSION TESTS (1 test - OPTIMIZED)
     * ========================================================================= */
    {"all_compression_types", test_all_compression_types},     /* Tests NONE, GZIP, Snappy, ZSTD */

    /* =========================================================================
     * CATEGORY 5: NEGATIVE TESTS (10 tests)
     * Destructive tests and error handling
     * ========================================================================= */
    {"destructive_truncated_data", test_destructive_truncated_data},
    {"destructive_invalid_schema_json", test_destructive_invalid_schema_json},
    {"destructive_empty_schema", test_destructive_empty_schema},
    {"destructive_unsupported_type", test_destructive_unsupported_type},
    {"destructive_invalid_compression", test_destructive_invalid_compression},
    {"destructive_unparseable_conversion", test_destructive_unparseable_conversion},
    {"error_null_input", test_error_null_input},
    {"error_null_schema", test_error_null_schema},
    {"error_missing_file", test_error_missing_file},
    {"error_invalid_format", test_error_invalid_format},

    /* =========================================================================
     * CATEGORY 6: REAL-WORLD SCENARIOS (3 tests)
     * Production-like scenarios and integration patterns
     * ========================================================================= */
    {"realworld_schema_evolution", test_realworld_schema_evolution},
    {"realworld_partial_record", test_realworld_partial_record},
    {"realworld_extra_data_fields", test_realworld_extra_data_fields},

    {NULL, NULL}
};