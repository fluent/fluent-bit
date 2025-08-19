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

#ifdef FLB_HAVE_AWS

#ifndef FLB_AWS_UTIL_H

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_time.h>

#define FLB_AWS_UTIL_H

#define FLB_AWS_CREDENTIAL_REFRESH_LIMIT       60

/*
 * The AWS HTTP Client is a wrapper around the Fluent Bit's http library.
 * It handles tasks which are common to all AWS API requests (retries,
 * error processing, etc).
 * It is also easily mockable in unit tests.
 */

 struct flb_aws_client;

 struct flb_aws_header {
     char *key;
     size_t key_len;
     char *val;
     size_t val_len;
 };

typedef struct flb_http_client *(flb_aws_client_request_fn)
                                (struct flb_aws_client *aws_client,
                                int method, const char *uri,
                                const char *body, size_t body_len,
                                struct flb_aws_header *dynamic_headers,
                                size_t dynamic_headers_len);

/* TODO: Eventually will need to add a way to call flb_http_buffer_size */

/*
 * Virtual table for aws http client behavior.
 * This makes the client's functionality mockable in unit tests.
 */
struct flb_aws_client_vtable {
    flb_aws_client_request_fn *request;
};

struct flb_aws_client {
    struct flb_aws_client_vtable *client_vtable;

    /* Name to identify this client: used in log messages and tests */
    char *name;

    /* Sigv4 */
    int has_auth;
    int s3_mode;
    struct flb_aws_provider *provider;
    char *region;
    char *service;

    struct flb_upstream *upstream;

    char *host;
    int port;
    char *proxy;
    int flags;
    flb_sds_t extra_user_agent;

    /*
     * Additional headers which will be added to all requests.
     * The AWS client will add auth headers, content length,
     * and user agent.
     */
     struct flb_aws_header *static_headers;
     size_t static_headers_len;

    /* Are requests to AWS services retried? */
    int retry_requests;

    /*
     * If an API responds with auth error, we refresh creds and retry.
     * For safety, credential refresh can only happen once per
     * FLB_AWS_CREDENTIAL_REFRESH_LIMIT.
     */
    time_t refresh_limit;

    /* Send all log messages as debug; used in AWS Cred Providers on init */
    int debug_only;
};

/* frees dynamic_headers */
struct flb_http_client *flb_aws_client_request_basic_auth(
                                               struct flb_aws_client *aws_client,
                                               int method, const char *uri,
                                               const char *body, size_t body_len,
                                               struct flb_aws_header
                                               *dynamic_headers,
                                               size_t dynamic_headers_len,
                                               char *header_name,
                                               char* auth_token);

/*
 * Frees the aws_client, the internal flb_http_client, error_code,
 * and flb_upstream.
 * Caller code must free any other memory.
 * (Why? - Because all other memory may be static.)
 */
void flb_aws_client_destroy(struct flb_aws_client *aws_client);

typedef struct flb_aws_client*(flb_aws_client_create_fn)();

/*
 * HTTP Client Generator creates a new client structure and sets the vtable.
 * Unit tests can implement a custom flb_aws_client_generator which returns a mock client.
 * This structure is a virtual table.
 * Client code should not free it.
 */
struct flb_aws_client_generator {
    flb_aws_client_create_fn *create;
};

/* Remove protocol from endpoint */
char *removeProtocol (char *endpoint, char *protocol);

/* Get the flb_aws_client_generator */
struct flb_aws_client_generator *flb_aws_client_generator();

/*
 * Format an AWS regional API endpoint
 */
char *flb_aws_endpoint(char* service, char* region);

/* Parses AWS XML API Error responses and returns the value of the <code> tag */
flb_sds_t flb_aws_xml_error(char *response, size_t response_len);

/*
 * Parses an AWS JSON API error type returned by a request.
 */
flb_sds_t flb_aws_error(char *response, size_t response_len);

/*
 * Similar to 'flb_aws_error', except it prints the JSON error __type and message
 * field values to the user in a error log.
 * 'api' is the name of the API that was called; this is used in the error log.
 */
void flb_aws_print_error(char *response, size_t response_len,
                         char *api, struct flb_output_instance *ins);

/*
 * Error parsing for json APIs that respond with a
 * Code and Message fields for error responses.
 */
void flb_aws_print_error_code(char *response, size_t response_len,
                              char *api);

/* Similar to 'flb_aws_print_error', but for APIs that return XML */
void flb_aws_print_xml_error(char *response, size_t response_len,
                             char *api, struct flb_output_instance *ins);

/*
 * Parses the JSON and gets the value for 'key'
 */
flb_sds_t flb_json_get_val(char *response, size_t response_len, char *key);

/*
 * Parses an XML document and returns the value of the given tag
 * Param `tag` should include angle brackets; ex "<code>"
 * And param `end` should include end brackets: "</code>"
 */
flb_sds_t flb_aws_xml_get_val(char *response, size_t response_len, char *tag, char *tag_end);

/*
 * Checks if a response contains an AWS Auth error
 */
int flb_aws_is_auth_error(char *payload, size_t payload_size);

int flb_read_file(const char *path, char **out_buf, size_t *out_size);

/* Constructs S3 object key as per the format. */
flb_sds_t flb_get_s3_key(const char *format, time_t time, const char *tag,
                         char *tag_delimiter, uint64_t seq_index, const char *time_offset);

/* Constructs S3 object key as per the blob format. */
flb_sds_t flb_get_s3_blob_key(const char *format, const char *tag,
                              char *tag_delimiter, const char *blob_path);

/*
 * This function is an extension to strftime which can support milliseconds with %3N,
 * support nanoseconds with %9N or %L. The return value is the length of formatted
 * time string.
 */
size_t flb_aws_strftime_precision(char **out_buf, const char *time_format,
                                  struct flb_time *tms);


/*
 * Parses the time offset and returns the offset in seconds.
 */
size_t flb_aws_parse_tz_offset(const char *time_offset);


#endif
#endif /* FLB_HAVE_AWS */
