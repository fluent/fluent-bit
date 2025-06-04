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

#ifndef FLB_TEST_GCS_MOCK_SERVER_H
#define FLB_TEST_GCS_MOCK_SERVER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_client.h>

/*
 * GCS Mock Server for Testing
 * 
 * This mock server simulates Google Cloud Storage and OAuth2 API responses
 * for testing the GCS output plugin. It uses environment variables to 
 * control responses and simulate different scenarios.
 */

/* Environment variables for controlling mock responses */
#define GCS_MOCK_ENV_TEST_MODE          "FLB_GCS_PLUGIN_UNDER_TEST"
#define GCS_MOCK_ENV_TOKEN_RESPONSE     "FLB_GCS_MOCK_TOKEN_RESPONSE"
#define GCS_MOCK_ENV_UPLOAD_RESPONSE    "FLB_GCS_MOCK_UPLOAD_RESPONSE"
#define GCS_MOCK_ENV_ERROR_CODE         "FLB_GCS_MOCK_ERROR_CODE"
#define GCS_MOCK_ENV_ERROR_RESPONSE     "FLB_GCS_MOCK_ERROR_RESPONSE"
#define GCS_MOCK_ENV_METADATA_RESPONSE  "FLB_GCS_MOCK_METADATA_RESPONSE"
#define GCS_MOCK_ENV_RESUMABLE_SESSION  "FLB_GCS_MOCK_RESUMABLE_SESSION"

/* Mock response types */
typedef enum {
    GCS_MOCK_OAUTH_TOKEN,
    GCS_MOCK_METADATA_TOKEN,
    GCS_MOCK_UPLOAD_OBJECT,
    GCS_MOCK_RESUMABLE_INIT,
    GCS_MOCK_RESUMABLE_UPLOAD,
    GCS_MOCK_ERROR_RESPONSE
} gcs_mock_response_type_t;

/* Mock server state */
struct gcs_mock_server {
    int enabled;
    int call_count;
    char *last_request_uri;
    char *last_request_method;
    char *last_request_body;
    int last_response_code;
    char *last_response_body;
};

/* Default mock responses */
#define GCS_MOCK_DEFAULT_TOKEN_RESPONSE \
    "{\n" \
    "  \"access_token\": \"ya29.mock-access-token-123456789\",\n" \
    "  \"expires_in\": 3599,\n" \
    "  \"token_type\": \"Bearer\"\n" \
    "}"

#define GCS_MOCK_DEFAULT_UPLOAD_RESPONSE \
    "{\n" \
    "  \"kind\": \"storage#object\",\n" \
    "  \"id\": \"test-bucket/test-object/1234567890\",\n" \
    "  \"name\": \"test-object\",\n" \
    "  \"bucket\": \"test-bucket\",\n" \
    "  \"generation\": \"1234567890\",\n" \
    "  \"contentType\": \"application/json\",\n" \
    "  \"size\": \"1024\",\n" \
    "  \"timeCreated\": \"2024-01-15T10:30:45.123Z\",\n" \
    "  \"updated\": \"2024-01-15T10:30:45.123Z\"\n" \
    "}"

#define GCS_MOCK_DEFAULT_RESUMABLE_INIT_RESPONSE \
    "{\n" \
    "  \"kind\": \"storage#object\",\n" \
    "  \"name\": \"test-object\",\n" \
    "  \"bucket\": \"test-bucket\"\n" \
    "}"

#define GCS_MOCK_DEFAULT_ERROR_RESPONSE \
    "{\n" \
    "  \"error\": {\n" \
    "    \"code\": 500,\n" \
    "    \"message\": \"Internal Server Error\",\n" \
    "    \"errors\": [{\n" \
    "      \"message\": \"Internal Server Error\",\n" \
    "      \"domain\": \"global\",\n" \
    "      \"reason\": \"internalError\"\n" \
    "    }]\n" \
    "  }\n" \
    "}"

/* OAuth2 error responses */
#define GCS_MOCK_OAUTH_INVALID_GRANT_RESPONSE \
    "{\n" \
    "  \"error\": \"invalid_grant\",\n" \
    "  \"error_description\": \"Invalid JWT: Token must be a short-lived token\"\n" \
    "}"

#define GCS_MOCK_OAUTH_INVALID_CLIENT_RESPONSE \
    "{\n" \
    "  \"error\": \"invalid_client\",\n" \
    "  \"error_description\": \"The OAuth client was not found.\"\n" \
    "}"

/* GCS specific error responses */
#define GCS_MOCK_BUCKET_NOT_FOUND_RESPONSE \
    "{\n" \
    "  \"error\": {\n" \
    "    \"code\": 404,\n" \
    "    \"message\": \"Not Found\",\n" \
    "    \"errors\": [{\n" \
    "      \"message\": \"The specified bucket does not exist.\",\n" \
    "      \"domain\": \"global\",\n" \
    "      \"reason\": \"notFound\"\n" \
    "    }]\n" \
    "  }\n" \
    "}"

#define GCS_MOCK_PERMISSION_DENIED_RESPONSE \
    "{\n" \
    "  \"error\": {\n" \
    "    \"code\": 403,\n" \
    "    \"message\": \"Forbidden\",\n" \
    "    \"errors\": [{\n" \
    "      \"message\": \"Insufficient Permission\",\n" \
    "      \"domain\": \"global\",\n" \
    "      \"reason\": \"insufficientPermissions\"\n" \
    "    }]\n" \
    "  }\n" \
    "}"

#define GCS_MOCK_QUOTA_EXCEEDED_RESPONSE \
    "{\n" \
    "  \"error\": {\n" \
    "    \"code\": 429,\n" \
    "    \"message\": \"Too Many Requests\",\n" \
    "    \"errors\": [{\n" \
    "      \"message\": \"User project quota exceeded\",\n" \
    "      \"domain\": \"usageLimits\",\n" \
    "      \"reason\": \"quotaExceeded\"\n" \
    "    }]\n" \
    "  }\n" \
    "}"

/* Mock server function prototypes */

/**
 * Initialize the mock server for testing
 * @return 0 on success, -1 on error
 */
int gcs_mock_server_init(void);

/**
 * Cleanup the mock server
 */
void gcs_mock_server_cleanup(void);

/**
 * Check if the mock server is enabled
 * @return 1 if enabled, 0 if disabled
 */
int gcs_mock_server_enabled(void);

/**
 * Mock HTTP request handler
 * This function should be called by the GCS plugin's HTTP client
 * when in test mode to simulate GCS API responses.
 * 
 * @param method HTTP method (GET, POST, PUT, etc.)
 * @param uri Request URI
 * @param headers Request headers
 * @param body Request body
 * @param body_size Size of request body
 * @param response_code Output parameter for response code
 * @param response_body Output parameter for response body
 * @param response_size Output parameter for response body size
 * @return 0 on success, -1 on error
 */
int gcs_mock_server_handle_request(const char *method,
                                   const char *uri,
                                   const char *headers,
                                   const char *body,
                                   size_t body_size,
                                   int *response_code,
                                   char **response_body,
                                   size_t *response_size);

/**
 * Get the number of requests received by the mock server
 * @return Number of requests
 */
int gcs_mock_server_get_request_count(void);

/**
 * Reset the mock server state
 */
void gcs_mock_server_reset(void);

/**
 * Set up mock environment for OAuth2 success
 */
void gcs_mock_setup_oauth_success(void);

/**
 * Set up mock environment for OAuth2 failure
 */
void gcs_mock_setup_oauth_failure(void);

/**
 * Set up mock environment for upload success
 */
void gcs_mock_setup_upload_success(void);

/**
 * Set up mock environment for upload failure
 */
void gcs_mock_setup_upload_failure(void);

/**
 * Set up mock environment for metadata server success (ADC)
 */
void gcs_mock_setup_metadata_success(void);

/**
 * Set up mock environment for metadata server failure
 */
void gcs_mock_setup_metadata_failure(void);

/**
 * Set up mock environment for resumable upload
 */
void gcs_mock_setup_resumable_upload(void);

/**
 * Helper function to validate request headers
 * @param headers Request headers string
 * @param expected_header Header name to look for
 * @param expected_value Expected header value (can be NULL to just check presence)
 * @return 1 if header is found and matches, 0 otherwise
 */
int gcs_mock_validate_header(const char *headers, 
                            const char *expected_header,
                            const char *expected_value);

/**
 * Helper function to validate request body content
 * @param body Request body
 * @param body_size Size of request body
 * @param expected_content Expected content (substring)
 * @return 1 if content is found, 0 otherwise
 */
int gcs_mock_validate_body_content(const char *body,
                                   size_t body_size,
                                   const char *expected_content);

/**
 * Helper function to extract value from JSON response
 * @param json_response JSON response string
 * @param key Key to extract
 * @return Extracted value (caller must free), or NULL if not found
 */
char *gcs_mock_extract_json_value(const char *json_response, const char *key);

/* Test scenario setup macros */
#define GCS_MOCK_SCENARIO_SUCCESS() do { \
    gcs_mock_setup_oauth_success(); \
    gcs_mock_setup_upload_success(); \
} while(0)

#define GCS_MOCK_SCENARIO_AUTH_FAILURE() do { \
    gcs_mock_setup_oauth_failure(); \
} while(0)

#define GCS_MOCK_SCENARIO_UPLOAD_FAILURE() do { \
    gcs_mock_setup_oauth_success(); \
    gcs_mock_setup_upload_failure(); \
} while(0)

#define GCS_MOCK_SCENARIO_NETWORK_ERROR() do { \
    setenv(GCS_MOCK_ENV_ERROR_CODE, "0", 1); \
    setenv(GCS_MOCK_ENV_ERROR_RESPONSE, "Network timeout", 1); \
} while(0)

#define GCS_MOCK_SCENARIO_BUCKET_NOT_FOUND() do { \
    gcs_mock_setup_oauth_success(); \
    setenv(GCS_MOCK_ENV_ERROR_CODE, "404", 1); \
    setenv(GCS_MOCK_ENV_ERROR_RESPONSE, GCS_MOCK_BUCKET_NOT_FOUND_RESPONSE, 1); \
} while(0)

#define GCS_MOCK_SCENARIO_PERMISSION_DENIED() do { \
    gcs_mock_setup_oauth_success(); \
    setenv(GCS_MOCK_ENV_ERROR_CODE, "403", 1); \
    setenv(GCS_MOCK_ENV_ERROR_RESPONSE, GCS_MOCK_PERMISSION_DENIED_RESPONSE, 1); \
} while(0)

#define GCS_MOCK_SCENARIO_QUOTA_EXCEEDED() do { \
    gcs_mock_setup_oauth_success(); \
    setenv(GCS_MOCK_ENV_ERROR_CODE, "429", 1); \
    setenv(GCS_MOCK_ENV_ERROR_RESPONSE, GCS_MOCK_QUOTA_EXCEEDED_RESPONSE, 1); \
} while(0)

/* Cleanup macro */
#define GCS_MOCK_CLEANUP() do { \
    unsetenv(GCS_MOCK_ENV_TEST_MODE); \
    unsetenv(GCS_MOCK_ENV_TOKEN_RESPONSE); \
    unsetenv(GCS_MOCK_ENV_UPLOAD_RESPONSE); \
    unsetenv(GCS_MOCK_ENV_ERROR_CODE); \
    unsetenv(GCS_MOCK_ENV_ERROR_RESPONSE); \
    unsetenv(GCS_MOCK_ENV_METADATA_RESPONSE); \
    unsetenv(GCS_MOCK_ENV_RESUMABLE_SESSION); \
    gcs_mock_server_cleanup(); \
} while(0)

#endif /* FLB_TEST_GCS_MOCK_SERVER_H */