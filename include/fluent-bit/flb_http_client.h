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

#ifndef FLB_HTTP_CLIENT_H
#define FLB_HTTP_CLIENT_H

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_lock.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_callback.h>
#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/flb_http_client_http1.h>
#include <fluent-bit/flb_http_client_http2.h>
#include <time.h>

#define HTTP_CLIENT_TEMPORARY_BUFFER_SIZE (1024 * 64)

#define HTTP_CLIENT_SUCCESS         0
#define HTTP_CLIENT_PROVIDER_ERROR -1

#define FLB_HTTP_CLIENT_FLAG_KEEPALIVE    (((uint64_t) 1) << 0)
#define FLB_HTTP_CLIENT_FLAG_AUTO_DEFLATE (((uint64_t) 1) << 1)
#define FLB_HTTP_CLIENT_FLAG_AUTO_INFLATE (((uint64_t) 1) << 2)
#define FLB_HTTP_CLIENT_FLAG_STREAM_BODY  (((uint64_t) 1) << 3)

/* Buffer size */
#define FLB_HTTP_BUF_SIZE        2048
#define FLB_HTTP_DATA_SIZE_MAX   4096
#define FLB_HTTP_DATA_CHUNK     32768

/* HTTP Methods */
#define FLB_HTTP_GET         0
#define FLB_HTTP_POST        1
#define FLB_HTTP_PUT         2
#define FLB_HTTP_HEAD        3
#define FLB_HTTP_CONNECT     4
#define FLB_HTTP_PATCH       5
#define FLB_HTTP_DELETE      6

/* HTTP Flags */
#define FLB_HTTP_10          1
#define FLB_HTTP_11          2
#define FLB_HTTP_KA         16

/* Proxy */
#define FLB_HTTP_PROXY_NONE       0
#define FLB_HTTP_PROXY_HTTP       1
#define FLB_HTTP_PROXY_HTTPS      2

/* Internal codes */
#define FLB_HTTP_ERROR           -1
#define FLB_HTTP_MORE             0
#define FLB_HTTP_OK               1
#define FLB_HTTP_NOT_FOUND        2 /* header not found */
#define FLB_HTTP_CHUNK_AVAILABLE  3 /* means chunk is available, but there is more data. end of all chunks returns FLB_HTTP_OK */

/* Useful headers */
#define FLB_HTTP_HEADER_AUTH             "Authorization"
#define FLB_HTTP_HEADER_PROXY_AUTH       "Proxy-Authorization"
#define FLB_HTTP_HEADER_CONTENT_TYPE     "Content-Type"
#define FLB_HTTP_HEADER_CONTENT_ENCODING "Content-Encoding"
#define FLB_HTTP_HEADER_CONNECTION       "Connection"
#define FLB_HTTP_HEADER_KA               "keep-alive"

#define FLB_HTTP_CLIENT_HEADER_ARRAY                      0
#define FLB_HTTP_CLIENT_HEADER_LIST                       1
#define FLB_HTTP_CLIENT_HEADER_CONFIG_MAP_LIST            2

#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_TERMINATOR          0
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_METHOD              1
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_HOST                2
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_URI                 3
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_URL                 4
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_USER_AGENT          5
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_CONTENT_TYPE        6
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_BODY                7
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_HEADERS             8
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_BASIC          9
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_BEARER_TOKEN   10
#define FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_SIGNV4         11

#ifdef FLB_SYSTEM_WINDOWS
#ifdef _WIN64
typedef size_t * flb_http_client_size_t;
typedef size_t * flb_http_client_int64_t;
typedef size_t * flb_http_client_uint64_t;
#else
typedef size_t * flb_http_client_size_t;
typedef int64_t  flb_http_client_int64_t;
typedef uint64_t flb_http_client_uint64_t;
#endif
#else
typedef size_t   flb_http_client_size_t;
typedef int64_t  flb_http_client_int64_t;
typedef uint64_t flb_http_client_uint64_t;
#endif

struct flb_http_client_response {
    int status;                /* HTTP response status          */
    int content_length;        /* Content length set by headers */
    int chunked_encoding;      /* Chunked transfer encoding ?   */
    int connection_close;      /* connection: close ?           */
    char *chunk_processed_end; /* Position to mark last chunk   */
    char *headers_end;         /* Headers end (\r\n\r\n)        */

    /* Payload: body response: reference to 'data' */
    char *payload;
    size_t payload_size;

    /* Buffer to store server response */
    char   *data;
    size_t data_len;
    size_t data_size;
    size_t data_size_max;
};

/* It hold information about a possible HTTP proxy set by the caller */
struct flb_http_proxy {
    int type;               /* One of FLB_HTTP_PROXY_ macros */
    int port;               /* TCP Port */
    const char *host;       /* Proxy Host */
};

/* HTTP Debug context */
struct flb_http_debug {
    /* HTTP request headers */
    int debug_request_headers;          /* debug HTTP request headers   */
    void (*cb_debug_request_headers);   /* callback to pass raw headers */

    /* HTTP request payload */
    int debug_request_payload;          /* debug HTTP request payload   */
    int (*cb_debug_request_payload);
};

/* To make opaque struct */
struct flb_http_client;

/*
 * Tests callbacks
 * ===============
 */
struct flb_test_http_response {
    /*
     * Response Test Mode
     * ====================
     * When the response test enable the test response mode, it needs to
     * keep a reference of the context and other information:
     *
     * - rt_ctx : flb_http_client context
     *
     * - rt_status : HTTP response code
     *
     * - rt_in_callback: intermediary function to receive the results of
     *                  the http response test function.
     *
     * - rt_data: opaque data type for rt_in_callback()
     */

    /* runtime library context */
    void *rt_ctx;

    /* HTTP status */
    int rt_status;

    /* optional response context */
    void *response_ctx;

    /*
     * "response test callback": this function pointer is used by Fluent Bit
     * http client testing mode to reference a test function that must retrieve the
     * results of 'callback'. Consider this an intermediary function to
     * transfer the results to the runtime test.
     *
     * This function is private and should not be set manually in the plugin
     * code, it's set on src/flb_http_client.c .
     */
    void (*rt_resp_callback) (void *, int, void *, size_t, void *);

    /*
     * opaque data type passed by the runtime library to be used on
     * rt_in_callback().
     */
    void *rt_data;

    /*
     * Callback
     * =========
     * "HTTP response callback": it references the plugin function that performs
     * to validate HTTP response by HTTP client. This entry is mostly to
     * expose the plugin local function.
     */
    int (*callback) (/* plugin that ingested the records */
                     struct flb_http_client *,
                     const void *,   /* incoming response data */
                     size_t,         /* incoming response size */
                     void **,        /* output buffer      */
                     size_t *);      /* output buffer size */
};

/* Set a request type */
struct flb_http_client {
    /* Upstream connection */
    struct flb_connection *u_conn;

    /* Request data */
    int method;
    int flags;
    int header_len;
    int base_header_len;
    int header_size;
    char *header_buf;

    /* Config */
    int allow_dup_headers;          /* allow duplicated headers      */

    /* incoming parameters */
    const char *uri;
    const char *query_string;
    const char *host;
    int port;

    /* payload */
    int body_len;
    const char *body_buf;

    struct mk_list headers;

    /* Proxy */
    struct flb_http_proxy proxy;

    /* Response */
    struct flb_http_client_response resp;

    /* State tracking */
    time_t ts_start;
    time_t last_read_ts;

    int response_timeout;
    int read_idle_timeout;

    /* Tests */
    int test_mode;
    struct flb_test_http_response test_response;

    /* Reference to Callback context */
    void *cb_ctx;
};

struct flb_oauth2;

struct flb_http_client_ng {
    struct cfl_list         sessions;

    uint16_t                port;
    uint64_t                flags;
    int                     protocol_version;
    cfl_sds_t               temporary_buffer;

    int                     releasable;
    void                   *user_data;

    struct flb_upstream    *upstream;
    struct flb_upstream_ha *upstream_ha;

    flb_lock_t              lock;
};

struct flb_http_client_session {
    struct flb_http1_client_session http1;
    struct flb_http2_client_session http2;
    struct cfl_list                 streams;

    int                             protocol_version;

    cfl_sds_t                       incoming_data;
    cfl_sds_t                       outgoing_data;

    int                             releasable;

    struct cfl_list                 response_queue;

    int                             stream_sequence_number;

    struct flb_upstream_node       *upstream_node;
    struct flb_connection          *connection;
    struct flb_http_client_ng      *parent;

    struct cfl_list                 _head;
};

struct flb_aws_provider;

int flb_http_client_ng_init(struct flb_http_client_ng *client,
                            struct flb_upstream_ha *upstream_ha,
                            struct flb_upstream *upstream,
                            int protocol_version,
                            uint64_t flags);

struct flb_http_client_ng *flb_http_client_ng_create(
                                struct flb_upstream_ha *upstream_ha,
                                struct flb_upstream *upstream,
                                int protocol_version,
                                uint64_t flags);

void flb_http_client_ng_destroy(struct flb_http_client_ng *client);

int flb_http_client_session_init(struct flb_http_client_session *session,
                                 struct flb_http_client_ng *client,
                                 int protocol_version,
                                 struct flb_connection  *connection);

struct flb_http_client_session *flb_http_client_session_create(
                                    struct flb_http_client_ng *client,
                                    int protocol_version,
                                    struct flb_connection  *connection);

struct flb_http_client_session *flb_http_client_session_begin(
                                    struct flb_http_client_ng *client);

void flb_http_client_session_destroy(struct flb_http_client_session *session);

struct flb_http_request *flb_http_client_request_begin(
                            struct flb_http_client_session *session);

struct flb_http_response *flb_http_client_request_execute(
                            struct flb_http_request *request);

struct flb_http_response *flb_http_client_request_execute_step(
                            struct flb_http_request *request);

void flb_http_client_request_destroy(struct flb_http_request *request,
                                     int destroy_session);

int flb_http_client_session_ingest(struct flb_http_client_session *session,
                                   unsigned char *buffer,
                                   size_t length);



void flb_http_client_debug(struct flb_http_client *c,
                           struct flb_callback *cb_ctx);

struct flb_http_client *flb_http_client(struct flb_connection *u_conn,
                                        int method, const char *uri,
                                        const char *body, size_t body_len,
                                        const char *host, int port,
                                        const char *proxy, int flags);

/* For fulfilling HTTP response testing (dummy client) */
struct flb_http_client *flb_http_dummy_client(struct flb_connection *u_conn,
                                              int method, const char *uri,
                                              const char *body, size_t body_len,
                                              const char *host, int port,
                                              const char *proxy, int flags);

int flb_http_add_header(struct flb_http_client *c,
                        const char *key, size_t key_len,
                        const char *val, size_t val_len);
flb_sds_t flb_http_get_header(struct flb_http_client *c,
                              const char *key, size_t key_len);
int flb_http_basic_auth(struct flb_http_client *c,
                        const char *user, const char *passwd);
int flb_http_proxy_auth(struct flb_http_client *c,
                        const char *user, const char *passwd);
int flb_http_bearer_auth(struct flb_http_client *c,
                        const char *token);
int flb_http_remove_header(struct flb_http_client *c,
                          const char *key, size_t key_len);
int flb_http_set_keepalive(struct flb_http_client *c);
int flb_http_set_content_encoding_gzip(struct flb_http_client *c);
int flb_http_set_content_encoding_zstd(struct flb_http_client *c);
int flb_http_set_content_encoding_snappy(struct flb_http_client *c);
int flb_http_set_read_idle_timeout(struct flb_http_client *c, int timeout);
int flb_http_set_response_timeout(struct flb_http_client *c, int timeout);

int flb_http_set_callback_context(struct flb_http_client *c,
                                  struct flb_callback *cb_ctx);
int flb_http_set_response_test(struct flb_http_client *c, char *test_name,
                               const void *data, size_t len,
                               int status,
                               void (*resp_callback) (void *, int, void *, size_t, void *),
                               void *resp_callback_data);
int flb_http_push_response(struct flb_http_client *c, const void *data, size_t len);

int flb_http_get_response_data(struct flb_http_client *c, size_t bytes_consumed);
int flb_http_do_request(struct flb_http_client *c, size_t *bytes);

int flb_http_do(struct flb_http_client *c, size_t *bytes);
int flb_http_do_with_oauth2(struct flb_http_client *c, size_t *bytes,
                            struct flb_oauth2 *oauth2);
int flb_http_client_proxy_connect(struct flb_connection *u_conn);
void flb_http_client_destroy(struct flb_http_client *c);
int flb_http_buffer_size(struct flb_http_client *c, size_t size);
size_t flb_http_buffer_available(struct flb_http_client *c);
int flb_http_buffer_increase(struct flb_http_client *c, size_t size,
                             size_t *out_size);
int flb_http_strip_port_from_host(struct flb_http_client *c);
int flb_http_allow_duplicated_headers(struct flb_http_client *c, int allow);
int flb_http_client_debug_property_is_valid(char *key, char *val);


#define FLB_HTTP_CLIENT_ARGUMENT(argument_type, ...) \
            (flb_http_client_size_t) argument_type, __VA_ARGS__

#define FLB_HTTP_CLIENT_ARGUMENT_TERMINATOR() \
            (flb_http_client_size_t) FLB_HTTP_CLIENT_ARGUMENT_TYPE_TERMINATOR

#define FLB_HTTP_CLIENT_ARGUMENT_METHOD(method) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_METHOD, \
                                     (flb_http_client_size_t) method)

#define FLB_HTTP_CLIENT_ARGUMENT_HOST(host) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_HOST, \
                                     host)

#define FLB_HTTP_CLIENT_ARGUMENT_URL(url) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_URL, \
                                     url)

#define FLB_HTTP_CLIENT_ARGUMENT_URI(uri) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_URI, \
                                     uri)

#define FLB_HTTP_CLIENT_ARGUMENT_USER_AGENT(user_agent) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_USER_AGENT, \
                                     user_agent)

#define FLB_HTTP_CLIENT_ARGUMENT_CONTENT_TYPE(content_type) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_CONTENT_TYPE, \
                                     content_type)

#define FLB_HTTP_CLIENT_ARGUMENT_BODY(buffer, length, compression_algorithm) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_BODY, \
                                     buffer, \
                                     (flb_http_client_size_t) length, \
                                     compression_algorithm)

#define FLB_HTTP_CLIENT_ARGUMENT_HEADERS(data_type, headers) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_HEADERS, \
                                     (flb_http_client_size_t) data_type, \
                                     headers)

#define FLB_HTTP_CLIENT_ARGUMENT_BASIC_AUTHORIZATION(username, password) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_BASIC, \
                                     username, \
                                     password)

#define FLB_HTTP_CLIENT_ARGUMENT_BEARER_TOKEN(token) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_BEARER_TOKEN, \
                                     token)

#define FLB_HTTP_CLIENT_ARGUMENT_SIGNV4(aws_region, aws_service, aws_provider) \
            FLB_HTTP_CLIENT_ARGUMENT(FLB_HTTP_CLIENT_ARGUMENT_TYPE_AUTH_SIGNV4, \
                                     aws_region, \
                                     aws_service, \
                                     aws_provider)

int flb_http_request_set_parameters_internal(
    struct flb_http_request *request,
    va_list arguments);

int flb_http_request_set_parameters_unsafe(
    struct flb_http_request *request,
    ...);

struct flb_http_request *flb_http_client_request_builder_unsafe(
    struct flb_http_client_ng *client,
    ...);

#define flb_http_client_request_builder(client, ...) \
            flb_http_client_request_builder_unsafe( \
                client, \
                __VA_ARGS__, \
                FLB_HTTP_CLIENT_ARGUMENT_TERMINATOR());

#define flb_http_request_set_parameters(request, ...) \
            flb_http_request_set_parameters_unsafe( \
                request, \
                __VA_ARGS__, \
                FLB_HTTP_CLIENT_ARGUMENT_TERMINATOR());

#endif
