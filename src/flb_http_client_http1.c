/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

static int cfl_sds_shift_left(cfl_sds_t *buffer, size_t positions)
{
    size_t buffer_length;
    size_t remainder;

    buffer_length = cfl_sds_len(*buffer);
    remainder = 0;

    if (positions < buffer_length) {
        remainder = buffer_length - positions;

        memmove(*buffer,
                &((*buffer)[positions]),
                remainder);
    }

    cfl_sds_len_set(*buffer, remainder);

    (*buffer)[remainder] = '\0';

    return 0;
}

static int flb_http1_client_session_process_headers(struct flb_http_client_session *session,
                                                    struct flb_http_response *response)
{
    char   *header_block_begining;
    size_t  header_block_length;
    size_t  status_line_length;
    char   *header_block_end;
    char   *status_line;
    int     result;

    status_line = session->incoming_data;

    /* We need at least 8 characters to differentiate
    * HTTP/1.x from HTTP/0.9
    */
    if (cfl_sds_len(status_line) < 9) {
        return 0;
    }

    if (strncasecmp(status_line, "HTTP/1.1 ", 9) == 0) {
        response->protocol_version = HTTP_PROTOCOL_VERSION_11;
    }
    else if (strncasecmp(status_line, "HTTP/1.0 ", 9) == 0) {
        response->protocol_version = HTTP_PROTOCOL_VERSION_11;
    }
    else {
        response->protocol_version = HTTP_PROTOCOL_VERSION_09;
    }

    if (response->protocol_version == HTTP_PROTOCOL_VERSION_09) {
        flb_http_response_set_status(response, 200);

        flb_http_response_set_message(response, "");

        response->stream->status = HTTP_STREAM_STATUS_RECEIVING_DATA;
    }
    else {
        header_block_begining = strstr(status_line, "\r\n");

        if (header_block_begining == NULL) {
            return 0;
        }

        status_line_length = (size_t) (((uintptr_t) header_block_begining) -
                                       ((uintptr_t) status_line));

        header_block_begining = &header_block_begining[2];

        header_block_end = strstr(header_block_begining, "\r\n\r\n");

        if (header_block_end == NULL) {
            return 0;
        }

        header_block_length = (size_t) ((uintptr_t) header_block_end -
                                        (uintptr_t) header_block_begining);

        if (response->status <= 0) {
            response->status = (int) strtoul(&status_line[9], NULL, 10);

            if (response->status < 100 || response->status > 599) {
                response->stream->status = HTTP_STREAM_STATUS_ERROR;

                return -1;
            }

            result = parse_headers(response, header_block_begining);

            if (result != 0) {
                response->stream->status = HTTP_STREAM_STATUS_ERROR;

                return -1;
            }
        }

        cfl_sds_shift_left(&session->incoming_data,
                           status_line_length + 2 +
                           header_block_length + 4);

        response->stream->status = HTTP_STREAM_STATUS_RECEIVING_DATA;
    }

    return 0;
}

static int flb_http1_client_session_process_data(struct flb_http_client_session *session,
                                                 struct flb_http_response *response)
{
    char                           *body;
    int                             body_streaming_flag;
    int                             chunked_transfer;
    char                           *transfer_encoding;
    size_t                          body_length;
    size_t                         body_remainder;
    int     result;
    size_t                         chunk_length_length;
    char                          *chunk_length_end;
    char                          *chunk_header;
    char                          *chunk_data;
    size_t                         chunk_length;
    size_t                         required_size;

    body = session->incoming_data;

    body_streaming_flag = (session->parent->flags &
                           FLB_HTTP_CLIENT_FLAG_STREAM_BODY) != 0;

    chunked_transfer = FLB_FALSE;

    if (response->content_length == 0) {
        transfer_encoding = flb_http_response_get_header(response, "transfer-encoding");

        if (transfer_encoding != NULL) {
            if (strncasecmp(transfer_encoding, "chunked", 7) == 0) {
                chunked_transfer = FLB_TRUE;
            }
        }
    }

    body_length = cfl_sds_len(body);

    if (chunked_transfer == FLB_FALSE) {
        if (response->content_length > 0) {
            if ((response->body_read_offset + body_length) <
                response->content_length) {
                if (body_streaming_flag == FLB_FALSE) {
                    return 0;
                }

                response->body_read_offset += body_length;

                result = flb_http_response_append_to_body(
                            response,
                            (unsigned char *) body,
                            body_length);
            }
            else {
                result = flb_http_response_append_to_body(
                            response,
                            (unsigned char *) body,
                            body_length);

                response->stream->status = HTTP_STREAM_STATUS_READY;
            }

            cfl_sds_shift_left(&session->incoming_data, body_length);
        }
        else {
            response->stream->status = HTTP_STREAM_STATUS_READY;
        }
    }
    else {
        body_remainder = body_length;

        while (body_remainder > 0) {
            chunk_header = session->incoming_data;

            if (strchr(chunk_header, '\r') == NULL) {
                return 0;
            }

            errno = 0;

            chunk_length = strtoull(chunk_header, &chunk_length_end, 16);

            if (errno != 0) {
                response->stream->status = HTTP_STREAM_STATUS_ERROR;

                return -1;
            }

            chunk_length_length = (size_t) ((uintptr_t) chunk_length_end -
                                            (uintptr_t) chunk_header);

            required_size = chunk_length_length + 2 + chunk_length + 2;

            if (body_remainder < required_size) {
                return 0;
            }

            chunk_data = chunk_header + chunk_length_length + 2;

            if (chunk_length > 0) {
                result = flb_http_response_append_to_body(
                            response,
                            (unsigned char *) chunk_data,
                            chunk_length);

                if (result != 0) {
                    response->stream->status = HTTP_STREAM_STATUS_ERROR;

                    return -1;
                }
            }
            else {
                response->stream->status = HTTP_STREAM_STATUS_READY;
            }

            cfl_sds_shift_left(&session->incoming_data, required_size);

            response->body_read_offset += required_size;
            body_remainder -= required_size;
        }
    }

    return 0;
}

int flb_http1_client_session_ingest(struct flb_http1_client_session *session,
                                    unsigned char *buffer,
                                    size_t length)
{
    cfl_sds_t                      resized_buffer;
    int                             result;
    struct flb_http_stream         *stream;

    stream = cfl_list_entry_first(&session->parent->streams,
                                  struct flb_http_stream,
                                  _head);

    resized_buffer = cfl_sds_cat(session->parent->incoming_data,
                                 (const char *) buffer,
                                 length);

    if (resized_buffer == NULL) {
        return -1;
    }

    session->parent->incoming_data = resized_buffer;
    result = 0;

    if (stream->response.stream->status == HTTP_STREAM_STATUS_RECEIVING_HEADERS) {
        result = flb_http1_client_session_process_headers(
                    session->parent,
                    &stream->response);
    }

    if (result == 0 &&
        stream->response.stream->status == HTTP_STREAM_STATUS_RECEIVING_DATA) {
        result = flb_http1_client_session_process_data(
                    session->parent,
                    &stream->response);
    }

    return result;
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
                                     "Content-Type", 0,
                                     request->content_type, 0);

        if (result != 0) {
            cfl_sds_destroy(request_buffer);

            return -9;
        }
    }

    if (request->method == HTTP_METHOD_POST ||
        request->method == HTTP_METHOD_PUT) {
        snprintf(content_length_string,
                 sizeof(content_length_string) - 1,
                 "%zu",
                 request->content_length);

        content_length_string[sizeof(content_length_string) - 1] = '\0';

        result = compose_header_line(&request_buffer,
                                     "Content-Length", 0,
                                     content_length_string, 0);

        if (result != 0) {
            cfl_sds_destroy(request_buffer);

            return -7;
        }
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

    sds_result = cfl_sds_cat(request_buffer, "\r\n", 2);

    if (sds_result == NULL) {
        cfl_sds_destroy(request_buffer);

        return -7;
    }

    request_buffer = sds_result;

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
    else {
        return -1;
    }

    method_name = flb_http_get_method_string_from_id(request->method);

    if (method_name == NULL) {
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
    char    *current_term;
    size_t   value_length;
    size_t   name_length;
    int      result;
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

        if (flb_http_server_strncasecmp((uint8_t *) name,
                                        name_length,
                                        "content-type", 0) == 0) {
            response->content_type = \
                cfl_sds_create_len((const char *) value,
                                    value_length);

            if (response->content_type == NULL) {
                return -1;
            }
        }
        else if (flb_http_server_strncasecmp((uint8_t *) name,
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
