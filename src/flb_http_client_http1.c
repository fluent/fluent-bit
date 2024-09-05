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

#define _GNU_SOURCE
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_http_client_debug.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/tls/flb_tls.h>

static inline size_t http2_lower_value(size_t left_value, size_t right_value);


static int compose_request_line(cfl_sds_t *output_buffer,
                                struct flb_http_request *request);


static int compose_header_line(cfl_sds_t *output_buffer,
                               char *name,
                               size_t name_length,
                               char *value,
                               size_t value_length);

static int parse_term(char **term_start,
                      size_t *term_length,
                      char **next_term,
                      char *current_term,
                      char delimiter_character,
                      int trim_leading_spaces,
                      int trim_trailing_spaces);

static int parse_headers(struct flb_http_response *response, char *headers);


int flb_http1_client_session_init(struct flb_http1_client_session *session)
{
    return 0;
}

void flb_http1_client_session_destroy(struct flb_http1_client_session *session)
{
    if (session != NULL) {
        if (session->initialized) {
            session->initialized = FLB_FALSE;
        }
    }
}

int flb_http1_client_session_ingest(struct flb_http1_client_session *session,
                                    unsigned char *buffer,
                                    size_t length)
{
    char                           *transfer_encoding;
    int                             chunked_transfer;
    char                            status_code[4];
    struct flb_http_client_session *parent_session;
    cfl_sds_t                       incoming_data;
    uintptr_t                       body_offset;
    size_t                          body_length;
    char                           *status_line;
    char                           *headers;
    struct flb_http_response       *response;
    struct flb_http_request        *request;
    int                             result;
    struct flb_http_stream         *stream;
    char                           *body;

    stream = cfl_list_entry_first(&session->parent->streams,
                                  struct flb_http_stream,
                                  _head);

    request = &stream->request;
    response = &stream->response;
    parent_session = session->parent;
    incoming_data = parent_session->incoming_data;

    /* We need at least 8 characters to differentiate
     * HTTP/1.x from HTTP/0.9
     */
    if (cfl_sds_len(incoming_data) < 8) {
        return 0;
    }

    status_line = incoming_data;

    if (strncasecmp(status_line, "HTTP/1.", 7) != 0) {
        body = strstr(status_line, "\r\n\r\n");

        if (body == NULL) {
            return 0;
        }

        body_offset = (uintptr_t) body -
                      (uintptr_t) status_line;

        flb_http_response_set_status(response, 200);

        flb_http_response_set_message(response, "");

        flb_http_response_set_body(response,
                                   body,
                                   cfl_sds_len(incoming_data) - body_offset);

        response->protocol_version = HTTP_PROTOCOL_VERSION_09;

        response->stream->status = HTTP_STREAM_STATUS_READY;

        return 0;
    }

    if (cfl_sds_len(incoming_data) < 15) {
        return 0;
    }

    if (strncasecmp(status_line, "HTTP/1.1 ", 9) == 0) {
        response->protocol_version = HTTP_PROTOCOL_VERSION_11;
    }
    else if (strncasecmp(status_line, "HTTP/1.0 ", 9) == 0) {
        response->protocol_version = HTTP_PROTOCOL_VERSION_11;
    }
    else {
        response->stream->status = HTTP_STREAM_STATUS_ERROR;

        return -1;
    }

    /* By delaying the status line parsing until the header
     * seccion is complete we can work around a state machine
     * design error in this iteration of the code.
     */
    headers = strstr(status_line, "\r\n");

    if (headers == NULL) {
        return 0;
    }

    headers = &headers[2];

    body = strstr(headers, "\r\n\r\n");

    if (body == NULL) {
        return 0;
    }

    body = &body[4];

    body_length = (size_t) ((uintptr_t) body - (uintptr_t) status_line);
    body_length = cfl_sds_len(incoming_data) - body_length;

    /* HTTP response status */
    if (response->status <= 0) {
        strncpy(status_code, &status_line[9], 3);
        status_code[3] = '\0';

        response->status = atoi(status_code);

        if (response->status < 100 || response->status > 599) {
            response->stream->status = HTTP_STREAM_STATUS_ERROR;

            return -1;
        }

        result = parse_headers(response, headers);

        if (result != 0) {
            response->stream->status = HTTP_STREAM_STATUS_ERROR;

            return -1;
        }
    }

    chunked_transfer = FLB_FALSE;

    if (response->content_length == 0) {
        transfer_encoding = flb_http_response_get_header(response, "transfer-encoding");

        if (transfer_encoding != NULL) {
            if (strncasecmp(transfer_encoding, "chunked", 7) == 0) {
                chunked_transfer = FLB_TRUE;
            }
        }
    }

    if (!chunked_transfer) {
        if (response->content_length > 0) {
            if (body_length < response->content_length) {
                return 0;
            }
            else {
                result = flb_http_response_set_body(response, body, body_length);
                response->stream->status = HTTP_STREAM_STATUS_READY;
            }
        }
        else {
            response->stream->status = HTTP_STREAM_STATUS_READY;
        }
    }
    else {
        size_t  chunk_length_length;
        char   *chunk_length_end;
        char   *chunk_header;
        char   *chunk_data;
        size_t  chunk_length;
        size_t  body_remainder;
        size_t  required_size;
        cfl_sds_t sds_result;

        body_remainder = body_length - response->body_read_offset;

        while (body_remainder > 0) {
            chunk_header = &body[response->body_read_offset];

            if (strchr(chunk_header, '\r') == NULL) {
                return 0;
            }

            chunk_length = strtoull(chunk_header, &chunk_length_end, 16);

            chunk_length_length = (size_t) ((uintptr_t) chunk_length_end - (uintptr_t) chunk_header);

            required_size = chunk_length_length + 2 + chunk_length + 2;

            if (body_remainder >= required_size) {
                chunk_data = chunk_header + chunk_length_length + 2;

                if (chunk_length > 0) {
                    if (response->body == NULL) {
                        flb_http_response_set_body(response, chunk_data, chunk_length);
                    }
                    else {
                        sds_result = cfl_sds_cat(response->body, chunk_data, chunk_length);

                        if (sds_result == NULL) {
                            response->stream->status = HTTP_STREAM_STATUS_ERROR;

                            return -1;
                        }

                        response->body = sds_result;
                    }
                }
                else {
                    response->stream->status = HTTP_STREAM_STATUS_READY;
                }

                response->body_read_offset += required_size;
                body_remainder -= required_size;
            }
            else {
                return 0;
            }
        }
    }

    return 0;
}

int flb_http1_request_begin(struct flb_http_request *request)
{
    return 0;
}


int flb_http1_request_commit(struct flb_http_request *request)
{
    char                             content_length_string[16];
    struct mk_list                  *header_iterator;
    cfl_sds_t                        request_buffer;
    struct flb_http_client_session  *parent_session;
    struct flb_hash_table_entry     *header_entry;
    cfl_sds_t                        sds_result;
    struct flb_http1_client_session *session;
    struct flb_http_stream          *stream;
    int                              result;

    parent_session = (struct flb_http_client_session *) request->stream->parent;

    if (parent_session == NULL) {
        return -1;
    }

    session = &parent_session->http1;

    if (session == NULL) {
        return -1;
    }

    stream  = (struct flb_http_stream *) request->stream;

    if (stream == NULL) {
        return -2;
    }

    request_buffer = cfl_sds_create_size(128);

    if (request_buffer == NULL) {
        return -3;
    }

    result = compose_request_line(&request_buffer, request);

    if (result != 0) {
        cfl_sds_destroy(request_buffer);

        return -4;
    }

    mk_list_foreach(header_iterator, &request->headers->entries) {
        header_entry = mk_list_entry(header_iterator,
                                     struct flb_hash_table_entry,
                                     _head_parent);

        if (header_entry == NULL) {
            cfl_sds_destroy(request_buffer);

            return -5;
        }

        result = compose_header_line(&request_buffer,
                                      header_entry->key,
                                      header_entry->key_len,
                                      header_entry->val,
                                      header_entry->val_size);

        if (result != 0) {
            cfl_sds_destroy(request_buffer);

            return -6;
        }
    }

    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11) {
        if(request->host != NULL) {
            result = compose_header_line(&request_buffer,
                                        "Host", 0,
                                        request->host, 0);

            if (result != 0) {
                cfl_sds_destroy(request_buffer);

                return -7;
            }
        }
    }

    if(request->user_agent != NULL) {
        result = compose_header_line(&request_buffer,
                                     "User-agent", 0,
                                     request->user_agent, 0);

        if (result != 0) {
            cfl_sds_destroy(request_buffer);

            return -8;
        }
    }

    if(request->content_type != NULL) {
        result = compose_header_line(&request_buffer,
                                     "Content-type", 0,
                                     request->content_type, 0);

        if (result != 0) {
            cfl_sds_destroy(request_buffer);

            return -9;
        }
    }

    if (request->method == HTTP_METHOD_POST ||
        request->method == HTTP_METHOD_PUT ) {
        snprintf(content_length_string,
                 sizeof(content_length_string) - 1,
                 "%zu",
                 request->content_length);

        content_length_string[sizeof(content_length_string) - 1] = '\0';

        result = compose_header_line(&request_buffer,
                                     "Content-length", 0,
                                     content_length_string, 0);

        if (result != 0) {
            cfl_sds_destroy(request_buffer);

            return -7;
        }
    }

    sds_result = cfl_sds_cat(request_buffer, "\r\n", 2);

    if (sds_result == NULL) {
        cfl_sds_destroy(request_buffer);

        return -7;
    }

    if (request->body != NULL) {
        sds_result = cfl_sds_cat(request_buffer,
                                 request->body,
                                 cfl_sds_len(request->body));

        if (sds_result == NULL) {
            cfl_sds_destroy(request_buffer);

            return -8;
        }

        request_buffer = sds_result;
    }

    sds_result = cfl_sds_cat(session->parent->outgoing_data,
                             request_buffer,
                             cfl_sds_len(request_buffer));

    cfl_sds_destroy(request_buffer);

    if (sds_result == NULL) {
        return -9;
    }

    session->parent->outgoing_data = sds_result;

    return 0;
}

static int compose_request_line(cfl_sds_t *output_buffer,
                                struct flb_http_request *request)
{
    const char *protocol_version_string;
    const char *method_name;
    cfl_sds_t   sds_result;

    sds_result = NULL;

    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11) {
        protocol_version_string = " HTTP/1.1";
    }
    else if (request->protocol_version == HTTP_PROTOCOL_VERSION_10) {
        protocol_version_string = " HTTP/1.0";
    }
    else if (request->protocol_version == HTTP_PROTOCOL_VERSION_09) {
        protocol_version_string = "";
    }

    method_name = flb_http_get_method_string_from_id(request->method);

    if (method_name == NULL) {
        printf("FAILURE 1\n\n");
        return -1;
    }

    if (request->method == HTTP_METHOD_CONNECT) {
        sds_result = cfl_sds_printf(output_buffer,
                                    "CONNECT %s:%u%s\r\n",
                                    request->host,
                                    request->port,
                                    protocol_version_string);
    }
    else {
        if (request->query_string != NULL) {
            sds_result = cfl_sds_printf(output_buffer,
                                        "%s %s?%s%s\r\n",
                                        method_name,
                                        request->path,
                                        request->query_string,
                                        protocol_version_string);
        }
        else {
            sds_result = cfl_sds_printf(output_buffer,
                                        "%s %s%s\r\n",
                                        method_name,
                                        request->path,
                                        protocol_version_string);
        }
    }

    if (sds_result == NULL) {
        printf("FAILURE 2\n\n");
        return -1;
    }

    *output_buffer = sds_result;

    return 0;
}

static int compose_header_line(cfl_sds_t *output_buffer,
                               char *name,
                               size_t name_length,
                               char *value,
                               size_t value_length)
{
    cfl_sds_t sds_result;

    if (name_length == 0) {
        name_length = strlen(name);
    }

    if (value_length == 0) {
        value_length = strlen(value);
    }

    sds_result = cfl_sds_printf(output_buffer,
                                "%.*s: %.*s\r\n",
                                (int) name_length,
                                name,
                                (int) value_length,
                                value);

    if (sds_result == NULL) {
        return -1;
    }

    return 0;
}




static int parse_term(char **term_start,
                      size_t *term_length,
                      char **next_term,
                      char *current_term,
                      char delimiter_character,
                      int trim_leading_spaces,
                      int trim_trailing_spaces)
{
    char  *term_delimiter;

    if (trim_leading_spaces) {
        while (current_term[0] == ' ') {
            current_term++;
        }
    }

    if (current_term[0] == '\0') {
        return -1;
    }

    term_delimiter = strchr(current_term, delimiter_character);

    if (term_delimiter == NULL) {
        return -1;
    }

    *term_start = current_term;
    *term_length = (size_t) ((uintptr_t) term_delimiter -
                             (uintptr_t) current_term);

    *next_term = &term_delimiter[1];

    if (trim_trailing_spaces) {
        while (*term_length > 0 && current_term[*term_length - 1] == ' ') {
            (*term_length)--;
        }
    }

    return 0;
}

static int parse_headers(struct flb_http_response *response, char *headers)
{
    char    temporary_buffer[21];
    char    *word_delimiter;
    char    *term_delimiter;
    char    *current_term;
    char    *current_line;
    size_t   value_length;
    size_t   name_length;
    int      result;
    ssize_t  index;
    char    *value;
    char    *name;

    current_term = headers;

    while (current_term != NULL && current_term[0] != '\r') {
        result = parse_term(&name,
                            &name_length,
                            &current_term,
                            current_term,
                            ':',
                            FLB_TRUE,
                            FLB_TRUE);

        if (result != 0) {
            return -1;
        }

        result = parse_term(&value,
                            &value_length,
                            &current_term,
                            current_term,
                            '\r',
                            FLB_TRUE,
                            FLB_TRUE);

        if (result != 0) {
            return -1;
        }

        if (flb_http_server_strncasecmp(name,
                                        name_length,
                                        "content-type", 0) == 0) {
            response->content_type = \
                cfl_sds_create_len((const char *) value,
                                    value_length);

            if (response->content_type == NULL) {
                return -1;
            }
        }
        else if (flb_http_server_strncasecmp(name,
                                             name_length,
                                             "content-length", 0) == 0) {
            strncpy(temporary_buffer,
                    (const char *) value,
                    http2_lower_value(sizeof(temporary_buffer), value_length + 1));

            temporary_buffer[sizeof(temporary_buffer) - 1] = '\0';

            response->content_length = strtoull(temporary_buffer, NULL, 10);
        }

        result = flb_http_response_set_header(response,
                                              name,
                                              name_length,
                                              (void *) value,
                                              value_length);

        if (result != 0) {
            return -1;
        }

        current_term = &current_term[1];
    }

    return 0;
}

static inline size_t http2_lower_value(size_t left_value, size_t right_value)
{
    if (left_value < right_value) {
        return left_value;
    }

    return right_value;
}
