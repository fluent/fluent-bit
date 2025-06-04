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

#ifndef FLB_TEST_GCS_DATA_H
#define FLB_TEST_GCS_DATA_H

/* Test data for GCS plugin tests */

/* Sample log entry in MessagePack format */
static const char gcs_test_json_log[] = 
    "[1234567890, {\"message\":\"test log entry\", \"level\":\"info\", \"host\":\"test-host\"}]";

/* Sample log entry with structured data */
static const char gcs_test_structured_log[] = 
    "[1234567890, {\"timestamp\":\"2024-01-15T10:30:45Z\", \"level\":\"ERROR\", "
    "\"service\":\"web-api\", \"message\":\"Database connection failed\", "
    "\"error_code\":\"DB_CONN_TIMEOUT\", \"duration_ms\":5000}]";

/* Sample metrics data */
static const char gcs_test_metrics_log[] = 
    "[1234567890, {\"metric_name\":\"cpu_usage\", \"value\":75.5, \"unit\":\"percent\", "
    "\"tags\":{\"host\":\"server01\", \"region\":\"us-west-2\"}, \"timestamp\":1234567890}]";

/* Large log entry for testing file size limits */
static const char gcs_test_large_log[] = 
    "[1234567890, {\"message\":\"This is a very long log message that contains a lot of text "
    "to simulate real-world scenarios where log entries can be quite large. This message "
    "includes details about a complex operation that was performed by the system, including "
    "multiple steps, intermediate results, and final outcomes. The message also contains "
    "structured data like timestamps, user IDs, session information, and other metadata "
    "that would typically be found in production log entries. Additionally, this message "
    "includes some repetitive content to increase its size for testing purposes: "
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\", "
    "\"level\":\"info\", \"component\":\"test-component\", \"operation_id\":\"op-12345\", "
    "\"user_id\":\"user-67890\", \"session_id\":\"sess-abcdef\", "
    "\"request_id\":\"req-123456789\", \"trace_id\":\"trace-abcdef123456\"}]";

/* Multi-line log entry */
static const char gcs_test_multiline_log[] = 
    "[1234567890, {\"message\":\"Application stack trace:\\nException in thread 'main' "
    "java.lang.NullPointerException\\n\\tat com.example.Application.main(Application.java:15)\\n"
    "\\tat java.base/java.lang.Thread.run(Thread.java:834)\", \"level\":\"error\", "
    "\"thread\":\"main\", \"class\":\"com.example.Application\"}]";

/* Binary data test (base64 encoded) */
static const char gcs_test_binary_log[] = 
    "[1234567890, {\"message\":\"Binary data received\", \"data\":\"SGVsbG8gV29ybGQ=\", "
    "\"encoding\":\"base64\", \"size\":11}]";

/* Unicode test data */
static const char gcs_test_unicode_log[] = 
    "[1234567890, {\"message\":\"测试中文日志消息\", \"emoji\":\"🚀🎉💻\", "
    "\"unicode_text\":\"αβγδε ñáéíóú àèìòù\", \"level\":\"info\"}]";

/* Array of test log entries for batch testing */
static const char *gcs_test_log_batch[] = {
    "[1234567890, {\"message\":\"First log entry\", \"id\":1}]",
    "[1234567891, {\"message\":\"Second log entry\", \"id\":2}]", 
    "[1234567892, {\"message\":\"Third log entry\", \"id\":3}]",
    "[1234567893, {\"message\":\"Fourth log entry\", \"id\":4}]",
    "[1234567894, {\"message\":\"Fifth log entry\", \"id\":5}]",
    NULL
};

/* Sample service account credentials (fake/test only) */
static const char gcs_test_service_account_json[] = 
"{"
"\"type\": \"service_account\","
"\"project_id\": \"test-project-123\","
"\"private_key_id\": \"test-key-id-12345\","
"\"private_key\": \"-----BEGIN PRIVATE KEY-----\\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7vL7q8kJ9QlQP\\n"
"7k2RjQzVx1C2o4vF8nY3pQ7U5aWmR9xC0L1nP8uZ6qH3mT4rJ8sK5eD9fB2wA1eN\\n"
"-----END PRIVATE KEY-----\\n\","
"\"client_email\": \"test-service-account@test-project-123.iam.gserviceaccount.com\","
"\"client_id\": \"123456789012345678901\","
"\"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\","
"\"token_uri\": \"https://oauth2.googleapis.com/token\","
"\"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\","
"\"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/test-service-account%40test-project-123.iam.gserviceaccount.com\","
"\"universe_domain\": \"googleapis.com\""
"}";

/* Test OAuth2 responses */
static const char gcs_test_oauth_success_response[] = 
"{"
"\"access_token\": \"ya29.test-access-token-123456789abcdef\","
"\"expires_in\": 3599,"
"\"token_type\": \"Bearer\""
"}";

static const char gcs_test_oauth_error_response[] = 
"{"
"\"error\": \"invalid_grant\","
"\"error_description\": \"Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe. Check your iat and exp values in the JWT claim.\""
"}";

/* Test GCS API responses */
static const char gcs_test_upload_success_response[] = 
"{"
"\"kind\": \"storage#object\","
"\"id\": \"test-bucket/test-object/1234567890\","
"\"selfLink\": \"https://www.googleapis.com/storage/v1/b/test-bucket/o/test-object\","
"\"name\": \"test-object\","
"\"bucket\": \"test-bucket\","
"\"generation\": \"1234567890\","
"\"contentType\": \"application/json\","
"\"timeCreated\": \"2024-01-15T10:30:45.123Z\","
"\"updated\": \"2024-01-15T10:30:45.123Z\","
"\"size\": \"1024\","
"\"md5Hash\": \"dGVzdC1oYXNo\","
"\"crc32c\": \"testcrc==\""
"}";

static const char gcs_test_upload_error_response[] = 
"{"
"\"error\": {"
"\"code\": 403,"
"\"message\": \"Insufficient Permission\","
"\"errors\": [{"
"\"message\": \"Insufficient Permission\","
"\"domain\": \"global\","
"\"reason\": \"insufficientPermissions\""
"}]"
"}"
"}";

static const char gcs_test_bucket_not_found_response[] = 
"{"
"\"error\": {"
"\"code\": 404,"
"\"message\": \"Not Found\","
"\"errors\": [{"
"\"message\": \"Not Found\","
"\"domain\": \"global\","
"\"reason\": \"notFound\""
"}]"
"}"
"}";

/* Test resumable upload responses */
static const char gcs_test_resumable_init_response[] = 
"{"
"\"kind\": \"storage#object\","
"\"id\": \"test-bucket/test-object/upload-session-123\","
"\"name\": \"test-object\","
"\"bucket\": \"test-bucket\""
"}";

/* Test metadata server response (for ADC) */
static const char gcs_test_metadata_server_response[] = 
"{"
"\"access_token\": \"ya29.metadata-token-123456789abcdef\","
"\"expires_in\": 3599,"
"\"token_type\": \"Bearer\""
"}";

/* Test configuration values */
#define GCS_TEST_BUCKET_NAME        "test-bucket-12345"
#define GCS_TEST_PROJECT_ID         "test-project-123"
#define GCS_TEST_SERVICE_ACCOUNT    "test-service-account@test-project-123.iam.gserviceaccount.com"
#define GCS_TEST_REGION             "us-central1"
#define GCS_TEST_OBJECT_KEY_FORMAT  "logs/%Y/%m/%d/${tag}_%H%M%S.json"
#define GCS_TEST_STORE_DIR          "/tmp/flb-test-gcs-store"

/* Helper macros for test data sizes */
#define GCS_TEST_JSON_LOG_SIZE          (sizeof(gcs_test_json_log) - 1)
#define GCS_TEST_STRUCTURED_LOG_SIZE    (sizeof(gcs_test_structured_log) - 1)
#define GCS_TEST_METRICS_LOG_SIZE       (sizeof(gcs_test_metrics_log) - 1)
#define GCS_TEST_LARGE_LOG_SIZE         (sizeof(gcs_test_large_log) - 1)
#define GCS_TEST_MULTILINE_LOG_SIZE     (sizeof(gcs_test_multiline_log) - 1)
#define GCS_TEST_BINARY_LOG_SIZE        (sizeof(gcs_test_binary_log) - 1)
#define GCS_TEST_UNICODE_LOG_SIZE       (sizeof(gcs_test_unicode_log) - 1)

#endif /* FLB_TEST_GCS_DATA_H */