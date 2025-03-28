/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_mem.h>

#include <fluent-bit/http_server/flb_http_server.h>
#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/flb_signv4_ng.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_zstd.h>

/* PRIVATE */

static \
int uncompress_zlib(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size);

static \
int uncompress_zstd(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size);

static \
int uncompress_deflate(char **output_buffer,
                       size_t *output_size,
                       char *input_buffer,
                       size_t input_size);

static \
int uncompress_snappy(char **output_buffer,
                      size_t *output_size,
                      char *input_buffer,
                      size_t input_size);

static \
int uncompress_gzip(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size);

static \
int uncompress_zstd(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size);

static \
int compress_zlib(char **output_buffer,
                  size_t *output_size,
                  char *input_buffer,
                  size_t input_size);

static \
int compress_zstd(char **output_buffer,
                  size_t *output_size,
                  char *input_buffer,
                  size_t input_size);

static \
int compress_deflate(char **output_buffer,
                     size_t *output_size,
                     char *input_buffer,
                     size_t input_size);

static \
int compress_snappy(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size);

static \
int compress_gzip(char **output_buffer,
                  size_t *output_size,
                  char *input_buffer,
                  size_t input_size);

static \
int compress_zstd(char **output_buffer,
                  size_t *output_size,
                  char *input_buffer,
                  size_t input_size);

/* HTTP REQUEST */

static int flb_http_request_get_version(struct flb_http_request *request)
{
    int version;

    if (request->stream->role == HTTP_STREAM_ROLE_SERVER) {
        version = ((struct flb_http_server_session *) request->stream->parent)->version;
    }
    else {
        version = ((struct flb_http_client_session *) request->stream->parent)->protocol_version;
    }

    return version;
}

int flb_http_request_init(struct flb_http_request *request)
{
    flb_http_request_destroy(request);

    cfl_list_entry_init(&request->_head);

    request->headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (request->headers == NULL) {
        return -1;
    }

    flb_hash_table_set_case_sensitivity(request->headers, FLB_FALSE);

    request->trailer_headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (request->trailer_headers == NULL) {
        return -1;
    }

    flb_hash_table_set_case_sensitivity(request->trailer_headers, FLB_FALSE);

    return 0;
}

struct flb_http_request *flb_http_request_create()
{
    struct flb_http_request *request;
    int                      result;

    request = flb_calloc(1, sizeof(struct flb_http_request));

    if (request == NULL) {
        return NULL;
    }

    request->releasable = FLB_TRUE;

    result = flb_http_request_init(request);

    if (result != 0) {
        flb_http_request_destroy(request);

        return NULL;
    }

    return request;
}

void flb_http_request_destroy(struct flb_http_request *request)
{
    if (request->authority != NULL) {
         cfl_sds_destroy(request->authority);
    }

    if (request->path != NULL) {
         cfl_sds_destroy(request->path);
    }

    if (request->host != NULL) {
         cfl_sds_destroy(request->host);
    }

    if (request->content_type != NULL) {
         cfl_sds_destroy(request->content_type);
    }

    if (request->user_agent != NULL) {
         cfl_sds_destroy(request->user_agent);
    }

    if (request->query_string != NULL) {
         cfl_sds_destroy(request->query_string);
    }

    if (request->body != NULL) {
         cfl_sds_destroy(request->body);
    }

    if (request->headers != NULL) {
         flb_hash_table_destroy(request->headers);
    }

    if (request->trailer_headers != NULL) {
         flb_hash_table_destroy(request->trailer_headers);
    }

    if (!cfl_list_entry_is_orphan(&request->_head)) {
        cfl_list_del(&request->_head);
    }

    memset(request, 0, sizeof(struct flb_http_request));

    if (request->releasable == FLB_TRUE) {
        flb_free(request);
    }
}

int flb_http_request_commit(struct flb_http_request *request)
{
    int version;

    version = flb_http_request_get_version(request);

    if (version == HTTP_PROTOCOL_VERSION_20) {
        return flb_http2_request_commit(request);
    }

    return flb_http1_request_commit(request);
}

char *flb_http_request_get_header(struct flb_http_request *request,
                                  char *name)
{
    char   *lowercase_name;
    size_t value_length;
    int    result;
    void  *value;

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, strlen(name));

    if (lowercase_name == NULL) {
        return NULL;
    }

    result = flb_hash_table_get(request->headers,
                                lowercase_name,
                                strlen(lowercase_name),
                                &value, &value_length);

    flb_free(lowercase_name);

    if (result == -1) {
        return NULL;
    }

    return (char *) value;
}

int flb_http_request_set_header(struct flb_http_request *request,
                                char *name, size_t name_length,
                                char *value, size_t value_length)
{
    char  *lowercase_name;
    int    result;

    if (name_length == 0) {
        name_length = strlen(name);
    }

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, name_length);

    if (lowercase_name == NULL) {
        return -1;
    }

    if (value_length == 0) {
        if (value[0] == '\0') {
            value_length = 1;
        }
        else {
            value_length = strlen(value);
        }
    }

    result = flb_hash_table_add(request->headers,
                                (const char *) name,
                                name_length,
                                (void *) value,
                                value_length);

    flb_free(lowercase_name);

    if (result == -1) {
        return -1;
    }

    return 0;
}

int flb_http_request_unset_header(struct flb_http_request *request,
                                  char *name)
{
    int result;

    result = flb_hash_table_del(request->headers,
                                (const char *) name);

    if (result == -1) {
        return -1;
    }

    return 0;
}

int flb_http_request_compress_body(
    struct flb_http_request *request,
    char *content_encoding_header_value)
{
    char       new_content_length[21];
    cfl_sds_t  inflated_body;
    char      *output_buffer;
    size_t     output_size;
    int        result;

    result = 0;

    if (request->body == NULL) {
        return 0;
    }

    if (content_encoding_header_value == NULL) {
        return 0;
    }

    if (strncasecmp(content_encoding_header_value, "gzip", 4) == 0) {
        result = compress_gzip(&output_buffer,
                               &output_size,
                               request->body,
                               cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zlib", 4) == 0) {
        result = compress_zlib(&output_buffer,
                               &output_size,
                               request->body,
                               cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zstd", 4) == 0) {
        result = compress_zstd(&output_buffer,
                               &output_size,
                               request->body,
                               cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "snappy", 6) == 0) {
        result = compress_snappy(&output_buffer,
                                 &output_size,
                                 request->body,
                                 cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "deflate", 7) == 0) {
        result = compress_deflate(&output_buffer,
                                  &output_size,
                                  request->body,
                                  cfl_sds_len(request->body));
    }

    if (result == 1) {
        inflated_body = cfl_sds_create_len(output_buffer, output_size);

        flb_free(output_buffer);

        if (inflated_body == NULL) {
            return -1;
        }

        cfl_sds_destroy(request->body);

        request->body = inflated_body;

        snprintf(new_content_length,
                 sizeof(new_content_length),
                 "%zu",
                 output_size);

        flb_http_request_set_header(request,
                                    "Content-Encoding", 0,
                                    content_encoding_header_value, 0);

        request->content_length = output_size;
    }

    return 0;
}

int flb_http_request_uncompress_body(
    struct flb_http_request *request)
{
    char      *content_encoding_header_value;
    char       new_content_length[21];
    cfl_sds_t  inflated_body;
    char      *output_buffer;
    size_t     output_size;
    int        result;

    result = 0;

    if (request->body == NULL) {
        return 0;
    }

    content_encoding_header_value = flb_http_request_get_header(
                                        request,
                                        "Content-Encoding");

    if (content_encoding_header_value == NULL) {
        return 0;
    }

    if (strncasecmp(content_encoding_header_value, "gzip", 4) == 0) {
        result = uncompress_gzip(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zlib", 4) == 0) {
        result = uncompress_zlib(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zstd", 4) == 0) {
        result = uncompress_zstd(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "snappy", 6) == 0) {
        result = uncompress_snappy(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }
    else if (strncasecmp(content_encoding_header_value, "deflate", 7) == 0) {
        result = uncompress_deflate(&output_buffer,
                                    &output_size,
                                    request->body,
                                    cfl_sds_len(request->body));
    }

    if (result == 1) {
        inflated_body = cfl_sds_create_len(output_buffer, output_size);

        flb_free(output_buffer);

        if (inflated_body == NULL) {
            return -1;
        }

        cfl_sds_destroy(request->body);

        request->body = inflated_body;

        snprintf(new_content_length,
                 sizeof(new_content_length),
                 "%zu",
                 output_size);

        flb_http_request_unset_header(request, "Content-Encoding");
        flb_http_request_set_header(request,
                                    "Content-Length", 0,
                                    new_content_length, 0);

        request->content_length = output_size;
    }

    return 0;
}


int flb_http_request_set_method(struct flb_http_request *request,
                                int method)
{
    request->method = method;

    return 0;
}

int flb_http_request_set_host(struct flb_http_request *request,
                              char *host)
{
    request->host = cfl_sds_create(host);

    if (request->host == NULL) {
        return -1;
    }

    return 0;
}

int flb_http_request_set_port(struct flb_http_request *request,
                              uint16_t port)
{
    request->port = port;

    return 0;
}

int flb_http_request_set_url(struct flb_http_request *request,
                             char *url)
{
    char      *start_of_authorization;
    char      *start_of_query_string;
    char      *start_of_authority;
    char      *start_of_username;
    char      *start_of_password;
    char      *start_of_port;
    char      *start_of_host;
    char      *start_of_path;
    flb_sds_t  local_url;
    int        result;
    uint16_t   port;

    local_url = cfl_sds_create(url);

    if (local_url == NULL) {
        return -1;
    }

    start_of_authorization = NULL;
    start_of_query_string = NULL;
    start_of_authority = NULL;
    start_of_username = NULL;
    start_of_password = NULL;
    start_of_port = NULL;
    start_of_host = NULL;
    start_of_path = NULL;

    start_of_authority = strstr(local_url, "://");

    if (start_of_authority == NULL) {
        cfl_sds_destroy(local_url);

        return -1;
    }

    start_of_authority = &start_of_authority[3];

    start_of_path = strstr(start_of_authority, "/");

    if (start_of_path == NULL) {
        cfl_sds_destroy(local_url);

        return -1;
    }

    start_of_query_string = strstr(start_of_path, "?");

    if (start_of_query_string != NULL) {
        result = flb_http_request_set_query_string(request, &start_of_query_string[1]);

        if (result != 0) {
            cfl_sds_destroy(local_url);

            return -1;
        }

        start_of_query_string[0] = '\0';
    }

    if (start_of_path != NULL) {
        result = flb_http_request_set_uri(request, start_of_path);

        if (result != 0) {
            cfl_sds_destroy(local_url);

            return -1;
        }

        start_of_path[0] = '\0';
    }

    start_of_host = strstr(start_of_authority, "@");

    if (start_of_host == NULL) {
        start_of_host = start_of_authority;

        start_of_authorization = NULL;
    }
    else {
        start_of_authorization = start_of_authority;
    }

    if (start_of_host[0] == '@') {
        start_of_host[0] = '\0';
    }

    if (start_of_authorization != NULL) {
        start_of_password = strstr(start_of_authorization, ":");

        if (start_of_password != NULL) {
            start_of_password[0] = '\0';

            start_of_password = &start_of_password[1];
        }

        start_of_username = start_of_authorization;
    }

    start_of_port = strstr(start_of_host, ":");

    if (start_of_port != NULL) {
        start_of_port[0] = '\0';

        start_of_port = &start_of_port[1];

        port = (uint16_t) strtoul(start_of_port, NULL, 10);

        result = flb_http_request_set_port(
                    request,
                    port);

        if (result != 0) {
            cfl_sds_destroy(local_url);

            return -1;
        }
    }

    if (start_of_username != NULL &&
        start_of_password != NULL) {
        result = flb_http_request_set_authorization(
                    request,
                    HTTP_WWW_AUTHORIZATION_SCHEME_BASIC,
                    start_of_username,
                    start_of_password);

        if (result != 0) {
            cfl_sds_destroy(local_url);

            return -1;
        }
    }

    if (start_of_host != NULL) {
        result = flb_http_request_set_host(
                    request,
                    start_of_host);

        if (result != 0) {
            cfl_sds_destroy(local_url);

            return -1;
        }
    }

    cfl_sds_destroy(local_url);

    return 0;
}

int flb_http_request_set_uri(struct flb_http_request *request,
                             char *uri)
{
    if (request->path != NULL) {
        cfl_sds_destroy(request->path);

        request->path = NULL;
    }

    request->path = cfl_sds_create(uri);

    if (request->path == NULL) {
        return -1;
    }

    return 0;
}

int flb_http_request_set_query_string(struct flb_http_request *request,
                                      char *query_string)
{
    if (request->query_string != NULL) {
        cfl_sds_destroy(request->query_string);

        request->query_string = NULL;
    }

    request->query_string = cfl_sds_create(query_string);

    if (request->query_string == NULL) {
        return -1;
    }

    return 0;
}

int flb_http_request_set_content_type(struct flb_http_request *request,
                                      char *content_type)
{
    if (request->content_type != NULL) {
        cfl_sds_destroy(request->content_type);

        request->content_type = NULL;
    }

    request->content_type = cfl_sds_create(content_type);

    if (request->content_type == NULL) {
        return -1;
    }

    return 0;
}

int flb_http_request_set_user_agent(struct flb_http_request *request,
                                    char *user_agent)
{
    if (request->user_agent != NULL) {
        cfl_sds_destroy(request->user_agent);

        request->user_agent = NULL;
    }

    request->user_agent = cfl_sds_create(user_agent);

    if (request->user_agent == NULL) {
        return -1;
    }

    return 0;
}

int flb_http_request_set_content_length(struct flb_http_request *request,
                                        size_t content_length)
{
    request->content_length = content_length;

    return 0;
}

int flb_http_request_set_content_encoding(struct flb_http_request *request,
                                          char *encoding)
{
    return flb_http_request_set_header(request,
                                       "Content-Encoding", 0,
                                       encoding, 0);

}

int flb_http_request_set_body(struct flb_http_request *request,
                              unsigned char *body, size_t body_length,
                              char *compression_algorithm)
{
    int      compress;
    uint64_t flags;

    if (request->stream->role == HTTP_STREAM_ROLE_SERVER) {
        flags = ((struct flb_http_server_session *) request->stream->parent)->parent->flags;

        compress = flags & FLB_HTTP_SERVER_FLAG_AUTO_DEFLATE;
    }
    else {
        flags = ((struct flb_http_client_session *) request->stream->parent)->parent->flags;

        compress = flags & FLB_HTTP_CLIENT_FLAG_AUTO_DEFLATE;
    }

    request->body = cfl_sds_create_len((const char *) body, body_length);

    if (request->body == NULL) {
        return -1;
    }

    if (compress != 0 && compression_algorithm != NULL) {
        return flb_http_request_compress_body(request, compression_algorithm);
    }
    else {
        flb_http_request_set_content_length(request, body_length);
    }

    return 0;
}

int flb_http_request_perform_signv4_signature(
        struct flb_http_request *request,
        const char *aws_region,
        const char *aws_service,
        struct flb_aws_provider *aws_provider)
{
    flb_sds_t signature;

#ifdef FLB_HAVE_SIGNV4
#ifdef FLB_HAVE_AWS
    flb_debug("signing request with AWS Sigv4");

    signature = flb_signv4_ng_do(request,
                                 FLB_TRUE,  /* normalize URI ? */
                                 FLB_TRUE,  /* add x-amz-date header ? */
                                 time(NULL),
                                 (char *) aws_region,
                                 (char *) aws_service,
                                 0, NULL,
                                 aws_provider);

    if (signature == NULL) {
        flb_error("could not sign request with sigv4");

        return -1;
    }

    flb_sds_destroy(signature);
#endif
#endif

    return 0;
}

/* HTTP RESPONSE */

static int flb_http_response_get_version(struct flb_http_response *response)
{
    int version;

    if (response->stream->role == HTTP_STREAM_ROLE_SERVER) {
        version = ((struct flb_http_server_session *) response->stream->parent)->version;
    }
    else {
        version = ((struct flb_http_client_session *) response->stream->parent)->protocol_version;
    }

    return version;
}

int flb_http_response_init(struct flb_http_response *response)
{
    flb_http_response_destroy(response);

    cfl_list_entry_init(&response->_head);

    response->headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (response->headers == NULL) {
        return -1;
    }

    flb_hash_table_set_case_sensitivity(response->headers, FLB_FALSE);

    response->trailer_headers = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 16, -1);

    if (response->trailer_headers == NULL) {
        flb_http_response_destroy(response);

        return -1;
    }

    flb_hash_table_set_case_sensitivity(response->trailer_headers, FLB_FALSE);

    return 0;
}

struct flb_http_response *flb_http_response_create()
{
    struct flb_http_response *response;
    int                       result;

    response = flb_calloc(1, sizeof(struct flb_http_response));

    if (response == NULL) {
        return NULL;
    }

    response->releasable = FLB_TRUE;

    result = flb_http_response_init(response);

    if (result != 0) {
        flb_http_response_destroy(response);

        return NULL;
    }

    return response;
}

void flb_http_response_destroy(struct flb_http_response *response)
{
    if (response->message != NULL) {
         cfl_sds_destroy(response->message);
    }

    if (response->body != NULL) {
         cfl_sds_destroy(response->body);
    }

    if (response->content_type != NULL) {
         cfl_sds_destroy(response->content_type);
    }

    if (response->headers != NULL) {
        flb_hash_table_destroy(response->headers);
    }

    if (response->trailer_headers != NULL) {
         flb_hash_table_destroy(response->trailer_headers);
    }

    if (!cfl_list_entry_is_orphan(&response->_head)) {
        cfl_list_del(&response->_head);
    }

    memset(response, 0, sizeof(struct flb_http_response));
}

struct flb_http_response *flb_http_response_begin(
                                struct flb_http_server_session *session,
                                void *stream)
{
    if (session->version == HTTP_PROTOCOL_VERSION_20) {
        return flb_http2_response_begin(&session->http2, stream);
    }
    else {
        return flb_http1_response_begin(&session->http1, stream);
    }
}

int flb_http_response_commit(struct flb_http_response *response)
{
    int len;
    char tmp[64];
    int version;

    version = flb_http_response_get_version(response);

    if (response->body == NULL) {
        flb_http_response_set_header(response,
                                     "content-length",
                                     strlen("content-length"),
                                     "0",
                                     1);
    }
    else {
        /* if the session is HTTP/1.x, always set the content-length header */
        if (version < HTTP_PROTOCOL_VERSION_20) {
            len = snprintf(tmp, sizeof(tmp) - 1, "%zu", cfl_sds_len(response->body));
            flb_http_response_set_header(response,
                                         "content-length",
                                         strlen("content-length"),
                                         tmp, len);
        }
    }

    if (version == HTTP_PROTOCOL_VERSION_20) {
        return flb_http2_response_commit(response);
    }

    return flb_http1_response_commit(response);
}

char *flb_http_response_get_header(struct flb_http_response *response,
                                  char *name)
{
    char   *lowercase_name;
    size_t value_length;
    int    result;
    void  *value;

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, strlen(name));

    if (lowercase_name == NULL) {
        return NULL;
    }

    result = flb_hash_table_get(response->headers,
                                lowercase_name,
                                strlen(lowercase_name),
                                &value, &value_length);

    flb_free(lowercase_name);

    if (result == -1) {
        return NULL;
    }

    return (char *) value;
}

int flb_http_response_set_header(struct flb_http_response *response,
                             char *name, size_t name_length,
                             char *value, size_t value_length)
{
    char *lowercase_name;
    int   version;
    int   result;

    if (name_length == 0) {
        name_length = strlen(name);
    }

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, name_length);

    if (lowercase_name == NULL) {
        return -1;
    }

    if (value_length == 0) {
        if (value[0] == '\0') {
            value_length = 1;
        }
        else {
            value_length = strlen(value);
        }
    }

    version = flb_http_response_get_version(response);

    if (version == HTTP_PROTOCOL_VERSION_20) {
        result = flb_http2_response_set_header(response,
                                               lowercase_name, name_length,
                                               value, value_length);
    }
    else {
        result = flb_http1_response_set_header(response,
                                               lowercase_name, name_length,
                                               value, value_length);
    }

    flb_free(lowercase_name);

    return result;
}

int flb_http_response_unset_header(struct flb_http_response *response,
                                  char *name)
{
    char  *lowercase_name;
    int    result;

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, strlen(name));

    if (lowercase_name == NULL) {
        return -1;
    }

    result = flb_hash_table_del(response->headers,
                                (const char *) lowercase_name);

    flb_free(lowercase_name);

    if (result == -1) {
        return -1;
    }

    return 0;
}

int flb_http_response_set_trailer_header(struct flb_http_response *response,
                                         char *name, size_t name_length,
                                         char *value, size_t value_length)
{
    char  *lowercase_name;
    int    result;

    if (name_length == 0) {
        name_length = strlen(name);
    }

    if (value_length == 0) {
        if (value[0] == '\0') {
            value_length = 1;
        }
        else {
            value_length = strlen(value);
        }
    }

    lowercase_name = flb_http_server_convert_string_to_lowercase(
                        name, name_length);

    if (lowercase_name == NULL) {
        return -1;
    }

    result = flb_hash_table_add(response->trailer_headers,
                                (const char *) lowercase_name,
                                name_length,
                                (void *) value,
                                value_length);

    flb_free(lowercase_name);

    if (result == -1) {
        return -1;
    }

    return 0;
}

int flb_http_response_set_status(struct flb_http_response *response,
                             int status)
{
    int version;

    version = flb_http_response_get_version(response);

    response->status = status;

    if (version == HTTP_PROTOCOL_VERSION_20) {
        return flb_http2_response_set_status(response, status);
    }

    return flb_http1_response_set_status(response, status);
}

int flb_http_response_set_message(struct flb_http_response *response,
                                     char *message)
{
    if (response->message != NULL) {
        cfl_sds_destroy(response->message);

        response->message = NULL;
    }

    response->message = cfl_sds_create((const char *) message);

    if (response->message == NULL) {
        return -1;
    }

    return 0;
}

int flb_http_response_set_body(struct flb_http_response *response,
                               unsigned char *body, size_t body_length)
{
    if (response->body != NULL) {
       cfl_sds_destroy(response->body);
    }

    response->body = cfl_sds_create_len((const char *) body, body_length);

    if (response->body == NULL) {
        return -1;
    }

    return 0;
}

int flb_http_response_append_to_body(struct flb_http_response *response,
                                     unsigned char *body, size_t body_length)
{
    cfl_sds_t resized_buffer;

    if (response->body == NULL) {
        return flb_http_response_set_body(response, body, body_length);
    }
    else {
        resized_buffer = cfl_sds_cat(response->body,
                                    (const char *) body,
                                    body_length);

        if (resized_buffer == NULL) {
            return -1;
        }

        response->body = resized_buffer;
    }

    return 0;
}


int flb_http_response_compress_body(
    struct flb_http_response *response,
    char *content_encoding_header_value)
{
    char       new_content_length[21];
    cfl_sds_t  inflated_body;
    char      *output_buffer;
    size_t     output_size;
    int        result;

    result = 0;

    if (response->body == NULL) {
        return 0;
    }

    if (content_encoding_header_value == NULL) {
        return 0;
    }

    if (strncasecmp(content_encoding_header_value, "gzip", 4) == 0) {
        result = compress_gzip(&output_buffer,
                               &output_size,
                               response->body,
                               cfl_sds_len(response->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zlib", 4) == 0) {
        result = compress_zlib(&output_buffer,
                               &output_size,
                               response->body,
                               cfl_sds_len(response->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zstd", 4) == 0) {
        result = compress_zstd(&output_buffer,
                               &output_size,
                               response->body,
                               cfl_sds_len(response->body));
    }
    else if (strncasecmp(content_encoding_header_value, "snappy", 6) == 0) {
        result = compress_snappy(&output_buffer,
                                 &output_size,
                                 response->body,
                                 cfl_sds_len(response->body));
    }
    else if (strncasecmp(content_encoding_header_value, "deflate", 4) == 0) {
        result = compress_deflate(&output_buffer,
                                  &output_size,
                                  response->body,
                                  cfl_sds_len(response->body));
    }

    if (result == 1) {
        inflated_body = cfl_sds_create_len(output_buffer, output_size);

        flb_free(output_buffer);

        if (inflated_body == NULL) {
            return -1;
        }

        cfl_sds_destroy(response->body);

        response->body = inflated_body;

        snprintf(new_content_length,
                 sizeof(new_content_length),
                 "%zu",
                 output_size);

        flb_http_response_set_header(response,
                                     "content-encoding", 0,
                                     content_encoding_header_value, 0);

        flb_http_response_set_header(response,
                                     "content-length", 0,
                                     new_content_length, 0);

        response->content_length = output_size;
    }

    return 0;
}

int flb_http_response_uncompress_body(
    struct flb_http_response *response)
{
    char      *content_encoding_header_value;
    char       new_content_length[21];
    cfl_sds_t  inflated_body;
    char      *output_buffer;
    size_t     output_size;
    int        result;

    result = 0;

    if (response->body == NULL) {
        return 0;
    }

    content_encoding_header_value = flb_http_response_get_header(
                                        response,
                                        "content-encoding");

    if (content_encoding_header_value == NULL) {
        return 0;
    }

    if (strncasecmp(content_encoding_header_value, "gzip", 4) == 0) {
        result = uncompress_gzip(&output_buffer,
                                    &output_size,
                                    response->body,
                                    cfl_sds_len(response->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zlib", 4) == 0) {
        result = uncompress_zlib(&output_buffer,
                                    &output_size,
                                    response->body,
                                    cfl_sds_len(response->body));
    }
    else if (strncasecmp(content_encoding_header_value, "zstd", 4) == 0) {
        result = uncompress_zstd(&output_buffer,
                                    &output_size,
                                    response->body,
                                    cfl_sds_len(response->body));
    }
    else if (strncasecmp(content_encoding_header_value, "snappy", 6) == 0) {
        result = uncompress_snappy(&output_buffer,
                                    &output_size,
                                    response->body,
                                    cfl_sds_len(response->body));
    }
    else if (strncasecmp(content_encoding_header_value, "deflate", 4) == 0) {
        result = uncompress_deflate(&output_buffer,
                                    &output_size,
                                    response->body,
                                    cfl_sds_len(response->body));
    }

    if (result == 1) {
        inflated_body = cfl_sds_create_len(output_buffer, output_size);

        flb_free(output_buffer);

        if (inflated_body == NULL) {
            return -1;
        }

        cfl_sds_destroy(response->body);

        response->body = inflated_body;

        snprintf(new_content_length,
                 sizeof(new_content_length),
                 "%zu",
                 output_size);

        flb_http_response_unset_header(response, "Content-Encoding");
        flb_http_response_set_header(response,
                                     "Content-Length", 0,
                                     new_content_length, 0);

        response->content_length = output_size;
    }

    return 0;
}


/* HTTP STREAM */

int flb_http_stream_init(struct flb_http_stream *stream,
                     void *parent,
                     int32_t stream_id,
                     int role,
                     void *user_data)
{
    int result;

    stream->id = stream_id;

    if (role == HTTP_STREAM_ROLE_SERVER) {
        stream->status = HTTP_STREAM_STATUS_RECEIVING_HEADERS;
    }
    else {
        stream->status = HTTP_STREAM_STATUS_SENDING_HEADERS;
    }

    result = flb_http_request_init(&stream->request);

    if (result != 0) {
        return -1;
    }

    result = flb_http_response_init(&stream->response);

    if (result != 0) {
        return -2;
    }

    stream->role = role;
    stream->parent = parent;
    stream->user_data = user_data;

    stream->request.stream  = stream;
    stream->response.stream = stream;

    return 0;
}

struct flb_http_stream *flb_http_stream_create(void *parent,
                                               int32_t stream_id,
                                               int role,
                                               void *user_data)
{
    struct flb_http_stream *stream;
    int                     result;

    stream = flb_calloc(1, sizeof(struct flb_http_stream));

    if (stream == NULL) {
        return NULL;
    }

    stream->releasable = FLB_TRUE;

    result = flb_http_stream_init(stream, parent, stream_id, role, user_data);

    if (result != 0) {
        flb_http_stream_destroy(stream);
    }

    return stream;
}

void flb_http_stream_destroy(struct flb_http_stream *stream)
{
    if (stream != NULL) {
        if (!cfl_list_entry_is_orphan(&stream->_head)) {
            cfl_list_del(&stream->_head);
        }

        flb_http_request_destroy(&stream->request);
        flb_http_response_destroy(&stream->response);

        if (stream->releasable) {
          flb_free(stream);
        }
    }
}


const char *flb_http_get_method_string_from_id(int method)
{
    switch (method) {
    case HTTP_METHOD_GET:
        return "GET";
    case HTTP_METHOD_POST:
        return "POST";
    case HTTP_METHOD_HEAD:
        return "HEAD";
    case HTTP_METHOD_PUT:
        return "PUT";
    case HTTP_METHOD_DELETE:
        return "DELETE";
    case HTTP_METHOD_OPTIONS:
        return "OPTIONS";
    case HTTP_METHOD_CONNECT:
        return "CONNECT";
    }

    return NULL;
}

char *flb_http_server_convert_string_to_lowercase(char *input_buffer,
                                                  size_t length)
{
    char  *output_buffer;
    size_t index;

    output_buffer = flb_calloc(1, length + 1);

    if (output_buffer != NULL) {
        for (index = 0 ; index < length ; index++) {
            output_buffer[index] = tolower(input_buffer[index]);
        }

    }

    return output_buffer;
}


int flb_http_server_strncasecmp(const uint8_t *first_buffer,
                                size_t first_length,
                                const char *second_buffer,
                                size_t second_length)
{
    const char *first_buffer_;
    const char *second_buffer_;

    first_buffer_  = (const char *) first_buffer;
    second_buffer_ = (const char *) second_buffer;

    if (first_length == 0) {
        first_length = strlen(first_buffer_);
    }

    if (second_length == 0) {
        second_length = strlen(second_buffer_);
    }

    if (first_length < second_length) {
        return -1;
    }
    else if (first_length > second_length) {
        return 1;
    }

    return strncasecmp(first_buffer_, second_buffer_, first_length);
}

/* PRIVATE */

static \
int uncompress_zlib(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    return 0;
}

static \
int uncompress_zstd(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    int ret;

    ret = flb_zstd_uncompress(input_buffer,
                              input_size,
                              (void **) output_buffer,
                              output_size);

    if (ret != 0) {
        flb_error("[http zstd] decompression failed");
        return -1;
    }

    return 1;
}

static \
int uncompress_deflate(char **output_buffer,
                       size_t *output_size,
                       char *input_buffer,
                       size_t input_size)
{
    return 0;
}

static \
int uncompress_snappy(char **output_buffer,
                      size_t *output_size,
                      char *input_buffer,
                      size_t input_size)
{
    int ret;

    ret = flb_snappy_uncompress_framed_data(input_buffer,
                                            input_size,
                                            output_buffer,
                                            output_size);

    if (ret != 0) {
        flb_error("[http snappy] decompression failed");
        return -1;
    }

    return 1;
}

static \
int uncompress_gzip(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    int ret;

    ret = flb_gzip_uncompress(input_buffer,
                              input_size,
                              (void **) output_buffer,
                              output_size);

    if (ret == -1) {
        flb_error("[http gzip] decompression failed");
        return -1;
    }

    return 1;
}


static \
int compress_zlib(char **output_buffer,
                  size_t *output_size,
                  char *input_buffer,
                  size_t input_size)
{
    return 0;
}

static \
int compress_zstd(char **output_buffer,
                  size_t *output_size,
                  char *input_buffer,
                  size_t input_size)
{
    int ret;

    ret = flb_zstd_compress(input_buffer,
                            input_size,
                            (void **) output_buffer,
                            output_size);

    if (ret != 0) {
        flb_error("[http zstd] compression failed");
        return -1;
    }

    return 1;
}

static \
int compress_deflate(char **output_buffer,
                     size_t *output_size,
                     char *input_buffer,
                     size_t input_size)
{
    return 0;
}

static \
int compress_snappy(char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    return 0;
}

static \
int compress_gzip(char **output_buffer,
                  size_t *output_size,
                  char *input_buffer,
                  size_t input_size)
{
    int ret;

    ret = flb_gzip_compress((void *) input_buffer,
                            input_size,
                            (void **) output_buffer,
                            output_size);

    if (ret == -1) {
        flb_error("http client gzip compression failed");
        return -1;
    }

    return 1;
}

