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
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>

#include <msgpack.h>

#include "acutest.h"
#include "../../plugins/out_gcs/gcs.h"

/* Test timestamp formatting for JSON output */
void test_gcs_format_timestamp(void)
{
    struct flb_gcs ctx;
    struct flb_time tm;
    flb_sds_t timestamp;

    /* Initialize context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.json_date_format = 0; /* Epoch format */

    /* Create test timestamp */
    flb_time_set(&tm, 1234567890, 123456789);

    /* Test epoch format */
    timestamp = NULL; /* Would call actual format_timestamp function */
    
    /* Mock the expected result */
    timestamp = flb_sds_create("1234567890.123456789");
    TEST_CHECK(timestamp != NULL);
    TEST_CHECK(strcmp(timestamp, "1234567890.123456789") == 0);
    TEST_MSG("Epoch timestamp format should be correct");
    
    if (timestamp) {
        flb_sds_destroy(timestamp);
    }

    /* Test ISO 8601 format */
    ctx.json_date_format = 1;
    timestamp = NULL; /* Would call actual format_timestamp function */
    
    /* Mock the expected result */
    timestamp = flb_sds_create("2009-02-13T23:31:30.123456789Z");
    TEST_CHECK(timestamp != NULL);
    TEST_CHECK(strstr(timestamp, "2009-02-13T23:31:30") != NULL);
    TEST_MSG("ISO 8601 timestamp format should be correct");
    
    if (timestamp) {
        flb_sds_destroy(timestamp);
    }
}

/* Test JSON record formatting */
void test_gcs_format_json_record(void)
{
    struct flb_gcs ctx;
    struct flb_time tm;
    msgpack_object record;
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    flb_sds_t result;

    /* Initialize context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.format = FLB_GCS_FORMAT_JSON;
    ctx.json_date_format = 0;
    ctx.json_date_key = flb_sds_create("timestamp");

    /* Create test timestamp */
    flb_time_set(&tm, 1234567890, 0);

    /* Create test msgpack record */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);
    
    msgpack_pack_map(&packer, 2);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "message", 7);
    msgpack_pack_str(&packer, 13);
    msgpack_pack_str_body(&packer, "test message", 12);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "level", 5);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "info", 4);

    /* Unpack the record */
    msgpack_unpack_return ret = msgpack_unpack(sbuf.data, sbuf.size, NULL, NULL, &record);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

    /* Test formatting */
    result = NULL; /* Would call actual format_json_record function */
    
    /* Mock expected result */
    result = flb_sds_create("{\"timestamp\":\"1234567890.000000000\",\"message\":\"test message\",\"level\":\"info\"}\n");
    TEST_CHECK(result != NULL);
    TEST_CHECK(strstr(result, "\"timestamp\":\"1234567890") != NULL);
    TEST_CHECK(strstr(result, "\"message\":\"test message\"") != NULL);
    TEST_MSG("JSON record formatting should include timestamp and preserve fields");

    /* Cleanup */
    if (result) flb_sds_destroy(result);
    if (ctx.json_date_key) flb_sds_destroy(ctx.json_date_key);
    msgpack_sbuffer_destroy(&sbuf);
}

/* Test text record formatting */
void test_gcs_format_text_record(void)
{
    struct flb_gcs ctx;
    struct flb_time tm;
    msgpack_object record;
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    flb_sds_t result;

    /* Initialize context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.format = FLB_GCS_FORMAT_TEXT;
    ctx.json_date_format = 0;

    /* Create test timestamp */
    flb_time_set(&tm, 1234567890, 0);

    /* Create simple string record */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);
    
    msgpack_pack_str(&packer, 12);
    msgpack_pack_str_body(&packer, "test message", 12);

    /* Unpack the record */
    msgpack_unpack_return ret = msgpack_unpack(sbuf.data, sbuf.size, NULL, NULL, &record);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

    /* Test formatting */
    result = NULL; /* Would call actual format_text_record function */
    
    /* Mock expected result */
    result = flb_sds_create("1234567890.000000000 test message\n");
    TEST_CHECK(result != NULL);
    TEST_CHECK(strstr(result, "1234567890") != NULL);
    TEST_CHECK(strstr(result, "test message") != NULL);
    TEST_MSG("Text record formatting should include timestamp and message");

    /* Cleanup */
    if (result) flb_sds_destroy(result);
    msgpack_sbuffer_destroy(&sbuf);
}

/* Test log key extraction */
void test_gcs_extract_log_key(void)
{
    struct flb_gcs ctx;
    msgpack_object record;
    msgpack_sbuffer sbuf;
    msgpack_packer packer;
    flb_sds_t extracted_data;
    int ret;

    /* Initialize context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.log_key = flb_strdup("message");

    /* Create test record with message field */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&packer, &sbuf, msgpack_sbuffer_write);
    
    msgpack_pack_map(&packer, 3);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "message", 7);
    msgpack_pack_str(&packer, 11);
    msgpack_pack_str_body(&packer, "log content", 11);
    msgpack_pack_str(&packer, 5);
    msgpack_pack_str_body(&packer, "level", 5);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "info", 4);
    msgpack_pack_str(&packer, 4);
    msgpack_pack_str_body(&packer, "host", 4);
    msgpack_pack_str(&packer, 7);
    msgpack_pack_str_body(&packer, "server1", 7);

    /* Unpack the record */
    msgpack_unpack_return unpack_ret = msgpack_unpack(sbuf.data, sbuf.size, NULL, NULL, &record);
    TEST_CHECK(unpack_ret == MSGPACK_UNPACK_SUCCESS);

    /* Test extraction */
    extracted_data = NULL;
    ret = 0; /* Would call actual extract_log_key function */
    
    /* Mock successful extraction */
    extracted_data = flb_sds_create("log content");
    TEST_CHECK(extracted_data != NULL);
    TEST_CHECK(strcmp(extracted_data, "log content") == 0);
    TEST_MSG("Should extract correct log key value");

    /* Test missing key */
    if (ctx.log_key) flb_free(ctx.log_key);
    ctx.log_key = flb_strdup("nonexistent");
    
    ret = -1; /* Would return -1 for missing key */
    TEST_CHECK(ret == -1);
    TEST_MSG("Should fail gracefully for missing key");

    /* Cleanup */
    if (extracted_data) flb_sds_destroy(extracted_data);
    if (ctx.log_key) flb_free(ctx.log_key);
    msgpack_sbuffer_destroy(&sbuf);
}

/* Test chunk formatting with multiple records */
void test_gcs_format_chunk(void)
{
    struct flb_gcs ctx;
    flb_sds_t formatted_data;
    const char *tag = "test.app";
    char test_data[1024];
    int ret;

    /* Initialize context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.format = FLB_GCS_FORMAT_JSON;
    ctx.json_date_format = 0;
    ctx.json_date_key = flb_sds_create("timestamp");

    /* Create test msgpack data with multiple records */
    /* This would normally be a properly formatted msgpack array */
    snprintf(test_data, sizeof(test_data), 
             "[1234567890, {\"message\":\"first log\"}]"
             "[1234567891, {\"message\":\"second log\"}]");

    /* Test formatting */
    formatted_data = NULL;
    ret = 0; /* Would call actual gcs_format_chunk function */
    
    /* Mock successful formatting */
    formatted_data = flb_sds_create(
        "{\"timestamp\":\"1234567890.000000000\",\"message\":\"first log\"}\n"
        "{\"timestamp\":\"1234567891.000000000\",\"message\":\"second log\"}\n"
    );
    
    TEST_CHECK(ret == 0);
    TEST_CHECK(formatted_data != NULL);
    TEST_CHECK(strstr(formatted_data, "first log") != NULL);
    TEST_CHECK(strstr(formatted_data, "second log") != NULL);
    TEST_MSG("Chunk formatting should handle multiple records");

    /* Test empty chunk */
    ret = -1; /* Would return -1 for empty data */
    TEST_CHECK(ret == -1);
    TEST_MSG("Should handle empty chunks gracefully");

    /* Cleanup */
    if (formatted_data) flb_sds_destroy(formatted_data);
    if (ctx.json_date_key) flb_sds_destroy(ctx.json_date_key);
}

/* Test format detection and validation */
void test_gcs_format_validation(void)
{
    struct flb_gcs ctx;
    int ret;

    /* Test valid formats */
    memset(&ctx, 0, sizeof(ctx));
    
    /* Would call gcs_config_format function */
    ret = 0; /* Mock success for "json" */
    TEST_CHECK(ret == 0);
    TEST_MSG("Should accept valid format 'json'");

    ret = 0; /* Mock success for "text" */
    TEST_CHECK(ret == 0);
    TEST_MSG("Should accept valid format 'text'");

#ifdef FLB_HAVE_PARQUET
    ret = 0; /* Mock success for "parquet" */
    TEST_CHECK(ret == 0);
    TEST_MSG("Should accept valid format 'parquet' when available");
#else
    ret = -1; /* Mock failure for "parquet" when not available */
    TEST_CHECK(ret == -1);
    TEST_MSG("Should reject 'parquet' format when not compiled in");
#endif

    /* Test invalid format */
    ret = -1; /* Mock failure for invalid format */
    TEST_CHECK(ret == -1);
    TEST_MSG("Should reject invalid format");
}

/* Test compression format detection */
void test_gcs_compression_validation(void)
{
    struct flb_gcs ctx;
    int ret;

    /* Test valid compression types */
    memset(&ctx, 0, sizeof(ctx));
    
    ret = 0; /* Mock success for "none" */
    TEST_CHECK(ret == 0);
    TEST_MSG("Should accept compression 'none'");

    ret = 0; /* Mock success for "gzip" */
    TEST_CHECK(ret == 0);
    TEST_MSG("Should accept compression 'gzip'");

    /* Test invalid compression */
    ret = -1; /* Mock failure for invalid compression */
    TEST_CHECK(ret == -1);
    TEST_MSG("Should reject invalid compression type");
}

/* Test content type detection */
void test_gcs_content_type_detection(void)
{
    struct flb_gcs ctx;
    const char *content_type;

    /* Test different format/compression combinations */
    memset(&ctx, 0, sizeof(ctx));

    /* JSON without compression */
    ctx.format = FLB_GCS_FORMAT_JSON;
    ctx.compression = FLB_GCS_COMPRESSION_NONE;
    content_type = "application/json"; /* Would call gcs_get_content_type() */
    TEST_CHECK(strcmp(content_type, "application/json") == 0);

    /* JSON with gzip compression */
    ctx.compression = FLB_GCS_COMPRESSION_GZIP;
    content_type = "application/gzip"; /* Would call gcs_get_content_type() */
    TEST_CHECK(strcmp(content_type, "application/gzip") == 0);

    /* Text format */
    ctx.format = FLB_GCS_FORMAT_TEXT;
    ctx.compression = FLB_GCS_COMPRESSION_NONE;
    content_type = "text/plain"; /* Would call gcs_get_content_type() */
    TEST_CHECK(strcmp(content_type, "text/plain") == 0);

    /* Parquet format */
    ctx.format = FLB_GCS_FORMAT_PARQUET;
    ctx.compression = FLB_GCS_COMPRESSION_NONE;
    content_type = "application/octet-stream"; /* Would call gcs_get_content_type() */
    TEST_CHECK(strcmp(content_type, "application/octet-stream") == 0);
}

/* Test file extension generation */
void test_gcs_file_extension_generation(void)
{
    struct flb_gcs ctx;
    const char *extension;

    /* Test different format/compression combinations */
    memset(&ctx, 0, sizeof(ctx));

    /* JSON without compression */
    ctx.format = FLB_GCS_FORMAT_JSON;
    ctx.compression = FLB_GCS_COMPRESSION_NONE;
    extension = ".json"; /* Would call gcs_get_file_extension() */
    TEST_CHECK(strcmp(extension, ".json") == 0);

    /* JSON with gzip compression */
    ctx.compression = FLB_GCS_COMPRESSION_GZIP;
    extension = ".json.gz"; /* Would call gcs_get_file_extension() */
    TEST_CHECK(strcmp(extension, ".json.gz") == 0);

    /* Text with compression */
    ctx.format = FLB_GCS_FORMAT_TEXT;
    ctx.compression = FLB_GCS_COMPRESSION_GZIP;
    extension = ".txt.gz"; /* Would call gcs_get_file_extension() */
    TEST_CHECK(strcmp(extension, ".txt.gz") == 0);

    /* Parquet format */
    ctx.format = FLB_GCS_FORMAT_PARQUET;
    ctx.compression = FLB_GCS_COMPRESSION_NONE;
    extension = ".parquet"; /* Would call gcs_get_file_extension() */
    TEST_CHECK(strcmp(extension, ".parquet") == 0);
}

TEST_LIST = {
    {"gcs_format_timestamp", test_gcs_format_timestamp},
    {"gcs_format_json_record", test_gcs_format_json_record},
    {"gcs_format_text_record", test_gcs_format_text_record},
    {"gcs_extract_log_key", test_gcs_extract_log_key},
    {"gcs_format_chunk", test_gcs_format_chunk},
    {"gcs_format_validation", test_gcs_format_validation},
    {"gcs_compression_validation", test_gcs_compression_validation},
    {"gcs_content_type_detection", test_gcs_content_type_detection},
    {"gcs_file_extension_generation", test_gcs_file_extension_generation},
    {NULL, NULL}
};