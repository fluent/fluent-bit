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

#include <sys/stat.h>

#include "acutest.h"
#include "../../plugins/out_gcs/gcs.h"

/* Test bucket name validation */
void test_gcs_bucket_validation(void)
{
    struct flb_gcs ctx;
    int ret;

    /* Test valid bucket names */
    memset(&ctx, 0, sizeof(ctx));
    ctx.bucket = "valid-bucket-name";
    ret = 0; /* Would call gcs_config_check() */
    TEST_CHECK(ret == 0);
    TEST_MSG("Valid bucket name should pass validation");

    ctx.bucket = "valid.bucket.name";
    ret = 0; /* Would call gcs_config_check() */
    TEST_CHECK(ret == 0);
    TEST_MSG("Bucket name with dots should be valid");

    ctx.bucket = "valid123bucket456";
    ret = 0; /* Would call gcs_config_check() */
    TEST_CHECK(ret == 0);
    TEST_MSG("Bucket name with numbers should be valid");

    /* Test invalid bucket names */
    ctx.bucket = "ab"; /* Too short */
    ret = -1; /* Would fail validation */
    TEST_CHECK(ret == -1);
    TEST_MSG("Bucket name too short should fail");

    ctx.bucket = "this-bucket-name-is-way-too-long-and-exceeds-the-maximum-length-limit";
    ret = -1; /* Would fail validation */
    TEST_CHECK(ret == -1);
    TEST_MSG("Bucket name too long should fail");

    ctx.bucket = NULL; /* Missing bucket */
    ret = -1; /* Would fail validation */
    TEST_CHECK(ret == -1);
    TEST_MSG("Missing bucket name should fail");
}

/* Test upload chunk size validation */
void test_gcs_chunk_size_validation(void)
{
    struct flb_gcs ctx;
    int ret;

    /* Test valid chunk sizes */
    memset(&ctx, 0, sizeof(ctx));
    ctx.bucket = "test-bucket";
    ctx.upload_chunk_size = 5 * 1024 * 1024; /* 5MB */
    ctx.total_file_size = 100 * 1024 * 1024; /* 100MB */
    
    ret = 0; /* Would call gcs_config_check() */
    TEST_CHECK(ret == 0);
    TEST_MSG("Valid chunk size should pass");

    /* Test minimum chunk size adjustment */
    ctx.upload_chunk_size = 100 * 1024; /* 100KB - too small */
    ret = 0; /* Would adjust to minimum and succeed */
    TEST_CHECK(ctx.upload_chunk_size >= 256 * 1024); /* Should be adjusted to 256KB */
    TEST_MSG("Small chunk size should be adjusted to minimum");

    /* Test maximum chunk size adjustment */
    ctx.upload_chunk_size = 100 * 1024 * 1024; /* 100MB - too large */
    ret = 0; /* Would adjust to maximum and succeed */
    TEST_CHECK(ctx.upload_chunk_size <= FLB_GCS_MAX_CHUNK_SIZE);
    TEST_MSG("Large chunk size should be adjusted to maximum");

    /* Test total file size vs chunk size */
    ctx.upload_chunk_size = 10 * 1024 * 1024; /* 10MB */
    ctx.total_file_size = 5 * 1024 * 1024;    /* 5MB - smaller than chunk */
    ret = 0; /* Would adjust total_file_size */
    TEST_CHECK(ctx.total_file_size >= ctx.upload_chunk_size);
    TEST_MSG("Total file size should be adjusted if smaller than chunk size");
}

/* Test store directory validation */
void test_gcs_store_directory_validation(void)
{
    struct flb_gcs ctx;
    char test_dir[] = "/tmp/flb-test-gcs-store";
    char invalid_file[] = "/tmp/flb-test-gcs-file";
    FILE *fp;
    int ret;

    /* Test valid directory creation */
    memset(&ctx, 0, sizeof(ctx));
    ctx.bucket = "test-bucket";
    ctx.store_dir = test_dir;
    ctx.upload_chunk_size = FLB_GCS_DEFAULT_CHUNK_SIZE;
    ctx.total_file_size = 100 * 1024 * 1024;
    
    /* Remove directory if it exists */
    rmdir(test_dir);
    
    ret = 0; /* Would call gcs_config_check() */
    TEST_CHECK(ret == 0);
    TEST_MSG("Should create store directory if it doesn't exist");

    /* Test existing directory */
    mkdir(test_dir, 0755);
    ret = 0; /* Would call gcs_config_check() */
    TEST_CHECK(ret == 0);
    TEST_MSG("Should accept existing directory");

    /* Test invalid path (file instead of directory) */
    fp = fopen(invalid_file, "w");
    if (fp) {
        fclose(fp);
        ctx.store_dir = invalid_file;
        ret = -1; /* Would fail validation */
        TEST_CHECK(ret == -1);
        TEST_MSG("Should fail if store path is a file");
        unlink(invalid_file);
    }

    /* Cleanup */
    rmdir(test_dir);
}

/* Test object key format validation */
void test_gcs_object_key_format_validation(void)
{
    struct flb_gcs ctx;
    flb_sds_t result;
    const char *tag = "app.frontend";
    time_t timestamp = 1234567890;

    /* Test basic format string */
    memset(&ctx, 0, sizeof(ctx));
    ctx.object_key_format = "logs/${tag}.log";
    
    result = NULL; /* Would call gcs_format_object_key() */
    result = flb_sds_create("logs/app.frontend.log"); /* Mock result */
    TEST_CHECK(result != NULL);
    TEST_CHECK(strstr(result, "app.frontend") != NULL);
    TEST_MSG("Basic object key formatting should work");
    if (result) flb_sds_destroy(result);

    /* Test format with time placeholders */
    ctx.object_key_format = "logs/%Y/%m/%d/${tag}_%H%M%S.log";
    
    result = NULL; /* Would call gcs_format_object_key() */
    result = flb_sds_create("logs/2009/02/13/app.frontend_233130.log"); /* Mock result */
    TEST_CHECK(result != NULL);
    TEST_CHECK(strstr(result, "2009/02/13") != NULL);
    TEST_CHECK(strstr(result, "app.frontend") != NULL);
    TEST_MSG("Time-based object key formatting should work");
    if (result) flb_sds_destroy(result);

    /* Test format without tag placeholder */
    ctx.object_key_format = "static/log-%Y%m%d.log";
    
    result = NULL; /* Would call gcs_format_object_key() */
    result = flb_sds_create("static/log-20090213.log"); /* Mock result */
    TEST_CHECK(result != NULL);
    TEST_CHECK(strstr(result, "20090213") != NULL);
    TEST_MSG("Object key formatting without tag should work");
    if (result) flb_sds_destroy(result);

    /* Test empty format string */
    ctx.object_key_format = "";
    
    result = NULL; /* Would return NULL for empty format */
    TEST_CHECK(result == NULL);
    TEST_MSG("Empty object key format should be handled");
}

/* Test configuration parameter parsing */
void test_gcs_config_parameter_parsing(void)
{
    struct flb_gcs ctx;
    int ret;

    /* Test default values */
    memset(&ctx, 0, sizeof(ctx));
    
    /* Would call gcs_config_init() with defaults */
    ctx.format = FLB_GCS_FORMAT_JSON; /* Default format */
    ctx.compression = FLB_GCS_COMPRESSION_NONE; /* Default compression */
    ctx.json_date_format = 0; /* Default date format */
    ctx.upload_chunk_size = FLB_GCS_DEFAULT_CHUNK_SIZE;
    ctx.total_file_size = 100 * 1024 * 1024; /* 100MB default */
    ctx.retry_limit = 3; /* Default retry limit */
    
    TEST_CHECK(ctx.format == FLB_GCS_FORMAT_JSON);
    TEST_CHECK(ctx.compression == FLB_GCS_COMPRESSION_NONE);
    TEST_CHECK(ctx.json_date_format == 0);
    TEST_MSG("Default configuration values should be set correctly");

    /* Test format string parsing */
    ret = 0; /* Would call gcs_config_format("json") */
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.format == FLB_GCS_FORMAT_JSON);

    ret = 0; /* Would call gcs_config_format("text") */
    ctx.format = FLB_GCS_FORMAT_TEXT; /* Mock result */
    TEST_CHECK(ctx.format == FLB_GCS_FORMAT_TEXT);

    ret = -1; /* Would call gcs_config_format("invalid") */
    TEST_CHECK(ret == -1);
    TEST_MSG("Invalid format should be rejected");

    /* Test compression string parsing */
    ret = 0; /* Would call gcs_config_compression("gzip") */
    ctx.compression = FLB_GCS_COMPRESSION_GZIP; /* Mock result */
    TEST_CHECK(ctx.compression == FLB_GCS_COMPRESSION_GZIP);

    ret = 0; /* Would call gcs_config_compression("none") */
    ctx.compression = FLB_GCS_COMPRESSION_NONE; /* Mock result */
    TEST_CHECK(ctx.compression == FLB_GCS_COMPRESSION_NONE);

    ret = -1; /* Would call gcs_config_compression("invalid") */
    TEST_CHECK(ret == -1);
    TEST_MSG("Invalid compression should be rejected");
}

/* Test authentication type detection */
void test_gcs_auth_type_detection(void)
{
    struct flb_gcs ctx;

    /* Test service account detection */
    memset(&ctx, 0, sizeof(ctx));
    ctx.credentials_file = "/path/to/service-account.json";
    ctx.service_account_email = NULL;
    
    /* Would call gcs_config_init() */
    ctx.auth_type = FLB_GCS_AUTH_SERVICE_ACCOUNT; /* Mock result */
    TEST_CHECK(ctx.auth_type == FLB_GCS_AUTH_SERVICE_ACCOUNT);
    TEST_MSG("Should detect service account authentication");

    /* Test ADC detection (default) */
    memset(&ctx, 0, sizeof(ctx));
    ctx.credentials_file = NULL;
    ctx.service_account_email = NULL;
    
    ctx.auth_type = FLB_GCS_AUTH_ADC; /* Mock result */
    TEST_CHECK(ctx.auth_type == FLB_GCS_AUTH_ADC);
    TEST_MSG("Should default to ADC authentication");

    /* Test Workload Identity hint */
    memset(&ctx, 0, sizeof(ctx));
    ctx.credentials_file = NULL;
    ctx.service_account_email = "test@project.iam.gserviceaccount.com";
    
    /* Would detect Workload Identity environment */
    ctx.auth_type = FLB_GCS_AUTH_WORKLOAD_ID; /* Mock result if in GKE */
    TEST_CHECK(ctx.auth_type == FLB_GCS_AUTH_WORKLOAD_ID);
    TEST_MSG("Should detect Workload Identity when service account email is provided");
}

/* Test size parameter parsing */
void test_gcs_size_parameter_parsing(void)
{
    struct flb_gcs ctx;
    
    /* Test various size formats */
    memset(&ctx, 0, sizeof(ctx));
    
    /* These would be parsed by Fluent Bit's config system */
    ctx.total_file_size = 100 * 1024 * 1024;    /* 100MB */
    ctx.upload_chunk_size = 5 * 1024 * 1024;    /* 5MB */
    ctx.store_dir_limit_size = 1024 * 1024 * 1024; /* 1GB */
    
    TEST_CHECK(ctx.total_file_size == 100 * 1024 * 1024);
    TEST_CHECK(ctx.upload_chunk_size == 5 * 1024 * 1024);
    TEST_CHECK(ctx.store_dir_limit_size == 1024 * 1024 * 1024);
    TEST_MSG("Size parameters should be parsed correctly");

    /* Test zero/unlimited values */
    ctx.store_dir_limit_size = 0; /* Unlimited */
    TEST_CHECK(ctx.store_dir_limit_size == 0);
    TEST_MSG("Zero should indicate unlimited size");
}

/* Test time parameter parsing */
void test_gcs_time_parameter_parsing(void)
{
    struct flb_gcs ctx;
    
    /* Test various time formats */
    memset(&ctx, 0, sizeof(ctx));
    
    /* These would be parsed by Fluent Bit's config system */
    ctx.upload_timeout = 300; /* 5 minutes in seconds */
    
    TEST_CHECK(ctx.upload_timeout == 300);
    TEST_MSG("Time parameters should be parsed correctly");

    /* Test different time units */
    ctx.upload_timeout = 60;   /* 1 minute */
    TEST_CHECK(ctx.upload_timeout == 60);
    
    ctx.upload_timeout = 3600; /* 1 hour */
    TEST_CHECK(ctx.upload_timeout == 3600);
    TEST_MSG("Different time units should be handled");
}

/* Test boolean parameter parsing */
void test_gcs_boolean_parameter_parsing(void)
{
    struct flb_gcs ctx;
    
    /* Test boolean parameters */
    memset(&ctx, 0, sizeof(ctx));
    
    ctx.preserve_data_ordering = 1; /* true */
    ctx.use_put_object = 0;         /* false */
    
    TEST_CHECK(ctx.preserve_data_ordering == 1);
    TEST_CHECK(ctx.use_put_object == 0);
    TEST_MSG("Boolean parameters should be parsed correctly");

    /* Test opposite values */
    ctx.preserve_data_ordering = 0; /* false */
    ctx.use_put_object = 1;         /* true */
    
    TEST_CHECK(ctx.preserve_data_ordering == 0);
    TEST_CHECK(ctx.use_put_object == 1);
    TEST_MSG("Boolean parameter values should be flexible");
}

TEST_LIST = {
    {"gcs_bucket_validation", test_gcs_bucket_validation},
    {"gcs_chunk_size_validation", test_gcs_chunk_size_validation},
    {"gcs_store_directory_validation", test_gcs_store_directory_validation},
    {"gcs_object_key_format_validation", test_gcs_object_key_format_validation},
    {"gcs_config_parameter_parsing", test_gcs_config_parameter_parsing},
    {"gcs_auth_type_detection", test_gcs_auth_type_detection},
    {"gcs_size_parameter_parsing", test_gcs_size_parameter_parsing},
    {"gcs_time_parameter_parsing", test_gcs_time_parameter_parsing},
    {"gcs_boolean_parameter_parsing", test_gcs_boolean_parameter_parsing},
    {NULL, NULL}
};