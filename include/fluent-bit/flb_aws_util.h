/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2020      The Fluent Bit Authors
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

#define FLB_AWS_UTIL_H

#define AWS_SERVICE_ENDPOINT_FORMAT            "%s.%s.amazonaws.com"
#define AWS_SERVICE_ENDPOINT_BASE_LEN          15

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
    struct flb_aws_provider *provider;
    char *region;
    char *service;

    struct flb_upstream *upstream;

    char *host;
    int port;
    char *proxy;
    int flags;

    /*
     * Additional headers which will be added to all requests.
     * The AWS client will add auth headers, content length,
     * and user agent.
     */
     struct flb_aws_header *static_headers;
     size_t static_headers_len;

    /*
     * If an API responds with auth error, we refresh creds and retry.
     * For safety, credential refresh can only happen once per
     * FLB_AWS_CREDENTIAL_REFRESH_LIMIT.
     */
    time_t refresh_limit;

    /* Send all log messages as debug; used in AWS Cred Providers on init */
    int debug_only;
};

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

/* Get the flb_aws_client_generator */
struct flb_aws_client_generator *flb_aws_client_generator();

/*
 * Format an AWS regional API endpoint
 */
char *flb_aws_endpoint(char* service, char* region);

/*
 * Parses an AWS API error type returned by a request.
 */
flb_sds_t flb_aws_error(char *response, size_t response_len);

/*
 * Similar to 'flb_aws_error', except it prints the error type and message
 * to the user in a error log.
 * 'api' is the name of the API that was called; this is used in the error log.
 */
void flb_aws_print_error(char *response, size_t response_len,
                         char *api, struct flb_output_instance *ins);

/*
 * Parses the JSON and gets the value for 'key'
 */
flb_sds_t flb_json_get_val(char *response, size_t response_len, char *key);

/*
 * Request data from an IMDS path.
 */
int flb_imds_request(struct flb_aws_client *client, char *metadata_path,
                     flb_sds_t *metadata, size_t *metadata_len);

/*
 * Checks if a response contains an AWS Auth error
 */
int flb_aws_is_auth_error(char *payload, size_t payload_size);


#endif
#endif /* FLB_HAVE_AWS */
