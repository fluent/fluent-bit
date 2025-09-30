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

#include <fluent-bit/http_server/flb_http_server.h>
#include <string.h>

/* PRIVATE */

static void dummy_mk_http_session_init(struct mk_http_session *session,
                                       struct mk_server *server)
{
    session->_sched_init = MK_TRUE;
    session->pipelined   = MK_FALSE;
    session->counter_connections = 0;
    session->close_now = MK_FALSE;
    session->status = MK_REQUEST_STATUS_INCOMPLETE;
    session->server = server;
    session->socket = -1;

    /* creation time in unix time */
    session->init_time = time(NULL);

    session->channel = mk_channel_new(MK_CHANNEL_SOCKET, -1);
    session->channel->io = session->server->network;

    /* Init session request list */
    mk_list_init(&session->request_list);

    /* Initialize the parser */
    mk_http_parser_init(&session->parser);
}

static void dummy_mk_http_request_init(struct mk_http_session *session,
                                       struct mk_http_request *request)
{
    if (request->stream.channel != NULL) {
        mk_stream_release(&request->stream);
    }

    memset(request, 0, sizeof(struct mk_http_request));

    mk_http_request_init(session, request, session->server);
}

static int http1_evict_request(struct flb_http1_server_session *session)
{
    size_t    session_buffer_length;
    cfl_sds_t session_buffer;
    size_t    request_length;

    session_buffer = session->parent->incoming_data;

    if (session_buffer == NULL) {
        return -1;
    }

    session_buffer_length = cfl_sds_len(session_buffer);

    request_length = mk_http_parser_request_size(&session->inner_parser,
                                                 session_buffer,
                                                 session_buffer_length);

    if (request_length == -1 ||
        request_length > session_buffer_length) {
        cfl_sds_set_len(session_buffer, 0);

        return -1;
    }

    if ((session_buffer_length - request_length) > 0) {
        session_buffer_length -= request_length;

        memmove(session_buffer,
                &session_buffer[request_length],
                session_buffer_length);

        session_buffer[session_buffer_length] = '\0';
    }
    else {
        cfl_sds_set_len(session_buffer, 0);
    }

    return 0;
}

static int http1_session_process_request(struct flb_http1_server_session *session)
{
    struct mk_list         *iterator;
    struct mk_http_header  *header;
    int                     result;
    size_t chunked_size;
    size_t written_bytes = 0;

    result = flb_http_request_init(&session->stream.request);

    if (result != 0) {
      return -1;
    }

    session->stream.request.stream = &session->stream;

    if (session->inner_request.uri_processed.data != NULL) {
        session->stream.request.path = \
            cfl_sds_create_len(session->inner_request.uri_processed.data,
                               session->inner_request.uri_processed.len);
    }
    else {
        session->stream.request.path = \
            cfl_sds_create_len(session->inner_request.uri.data,
                               session->inner_request.uri.len);
    }

    if (session->stream.request.path == NULL) {
        return -1;
    }

    switch (session->inner_request.protocol) {
        case MK_HTTP_PROTOCOL_09:
            session->stream.request.protocol_version = HTTP_PROTOCOL_VERSION_09;
            break;
        case MK_HTTP_PROTOCOL_10:
            session->stream.request.protocol_version = HTTP_PROTOCOL_VERSION_10;
            break;
        case MK_HTTP_PROTOCOL_11:
            session->stream.request.protocol_version = HTTP_PROTOCOL_VERSION_11;
            break;
        default:
            session->stream.request.protocol_version = HTTP_PROTOCOL_VERSION_10;
    }

    switch (session->inner_request.method) {
        case MK_METHOD_GET:
            session->stream.request.method = HTTP_METHOD_GET;
            break;
        case MK_METHOD_POST:
            session->stream.request.method = HTTP_METHOD_POST;
            break;
        case MK_METHOD_HEAD:
            session->stream.request.method = HTTP_METHOD_HEAD;
            break;
        case MK_METHOD_PUT:
            session->stream.request.method = HTTP_METHOD_PUT;
            break;
        case MK_METHOD_DELETE:
            session->stream.request.method = HTTP_METHOD_DELETE;
            break;
        case MK_METHOD_OPTIONS:
            session->stream.request.method = HTTP_METHOD_OPTIONS;
            break;
        default:
            session->stream.request.method = HTTP_METHOD_UNKNOWN;
            break;
    }

    session->stream.request.content_length = session->inner_request.content_length;

    mk_list_foreach(iterator,
                    &session->inner_parser.header_list) {
        header = mk_list_entry(iterator, struct mk_http_header, _head);

        if (header->key.data != NULL && header->key.len > 0 &&
            header->val.data != NULL && header->val.len > 0) {

            if (flb_http_server_strncasecmp(
                    (const uint8_t *) header->key.data,
                    header->key.len,
                    "host", 0) == 0) {
                session->stream.request.host = \
                    cfl_sds_create_len((const char *) header->val.data,
                                       header->val.len);

                if (session->stream.request.host == NULL) {
                    return -1;
                }
            }
            else if (flb_http_server_strncasecmp(
                        (const uint8_t *) header->key.data,
                        header->key.len,
                        "content-type", 0) == 0) {
                session->stream.request.content_type = \
                    cfl_sds_create_len((const char *) header->val.data,
                                       header->val.len);

                if (session->stream.request.content_type == NULL) {
                    return -1;
                }
            }

            result = flb_http_request_set_header(&session->stream.request,
                                                 header->key.data,
                                                 header->key.len,
                                                 (void *) header->val.data,
                                                 header->val.len);

            if (result != 0) {
                return -1;
            }
        }
    }

    if (session->stream.request.host == NULL) {
        session->stream.request.host = cfl_sds_create("");

        if (session->stream.request.host == NULL) {
            return -1;
        }
    }

    /* If the content comes in chunks (transfer-encoding: chunked) */
    if (mk_http_parser_is_content_chunked(&session->inner_parser)) {
        /* Get the total size of all the chunks */
        chunked_size = mk_http_parser_content_length(&session->inner_parser);
        if (chunked_size == 0) {
            session->stream.status = HTTP_STREAM_STATUS_ERROR;
            return -1;
        }

        /* allocate a buffer to get a copy of the decoded chunks */
        session->stream.request.body = cfl_sds_create_size(chunked_size);
        if (!session->stream.request.body) {
            session->stream.status = HTTP_STREAM_STATUS_ERROR;
            return -1;
        }

        /* decode the data into the new buffer */
        result = mk_http_parser_chunked_decode_buf(&session->inner_parser,
                                                   session->parent->incoming_data,
                                                   cfl_sds_len(session->parent->incoming_data),
                                                   session->stream.request.body,
                                                   chunked_size,
                                                   &written_bytes);
        if (result == -1) {
            session->stream.status = HTTP_STREAM_STATUS_ERROR;
            cfl_sds_destroy(session->stream.request.body);
            session->stream.request.body = NULL;
            return -1;
        }

        cfl_sds_len_set(session->stream.request.body, written_bytes);
    }
    else if (session->inner_request.data.data != NULL) {
        session->stream.request.body = \
            cfl_sds_create_len(session->inner_request.data.data,
                               session->inner_request.data.len);

        if (session->stream.request.body == NULL) {
            session->stream.status = HTTP_STREAM_STATUS_ERROR;

            return -1;
        }
    }

    session->stream.status = HTTP_STREAM_STATUS_READY;

    if (!cfl_list_entry_is_orphan(&session->stream.request._head)) {
        cfl_list_del(&session->stream.request._head);
    }

    cfl_list_add(&session->stream.request._head,
                 &session->parent->request_queue);

    return 0;
}

/* RESPONSE */

struct flb_http_response *flb_http1_response_begin(
                                struct flb_http1_server_session *session,
                                struct flb_http_stream *stream)
{
    int result;

    result = flb_http_response_init(&stream->response);

    if (result != 0) {
        return NULL;
    }

    stream->response.stream = stream;

    return &stream->response;
}

int flb_http1_response_commit(struct flb_http_response *response)
{
    struct mk_list                  *header_iterator;
    cfl_sds_t                        response_buffer;
    struct flb_http_server_session  *parent_session;
    struct flb_hash_table_entry     *header_entry;
    cfl_sds_t                        sds_result;
    struct flb_http1_server_session *session;
    struct flb_http_stream          *stream;

    parent_session = (struct flb_http_server_session *) response->stream->parent;

    if (parent_session == NULL) {
        return -1;
    }

    session = &parent_session->http1;

    if (session == NULL) {
        return -1;
    }

    stream  = (struct flb_http_stream *) response->stream;

    if (stream == NULL) {
        return -2;
    }

    response_buffer = cfl_sds_create_size(128);

    if (response_buffer == NULL) {
        return -3;
    }

    if (response->message != NULL) {
        sds_result = cfl_sds_printf(&response_buffer, "HTTP/1.1 %d %s\r\n", response->status, response->message);
    }
    else {
        sds_result = cfl_sds_printf(&response_buffer, "HTTP/1.1 %d\r\n", response->status);
    }

    if (sds_result == NULL) {
        cfl_sds_destroy(response_buffer);

        return -4;
    }

    mk_list_foreach(header_iterator, &response->headers->entries) {
        header_entry = mk_list_entry(header_iterator,
                                     struct flb_hash_table_entry,
                                     _head_parent);

        if (header_entry == NULL) {
            cfl_sds_destroy(response_buffer);

            return -5;
        }

        sds_result = cfl_sds_printf(&response_buffer,
                                    "%.*s: %.*s\r\n",
                                    (int) header_entry->key_len,
                                    (const char *) header_entry->key,
                                    (int) header_entry->val_size,
                                    (const char *) header_entry->val);

        if (sds_result == NULL) {
            cfl_sds_destroy(response_buffer);

            return -6;
        }
    }

    sds_result = cfl_sds_cat(response_buffer, "\r\n", 2);

    if (sds_result == NULL) {
        cfl_sds_destroy(response_buffer);

        return -7;
    }

    if (response->body != NULL) {
        sds_result = cfl_sds_cat(response_buffer,
                                 response->body,
                                 cfl_sds_len(response->body));

        if (sds_result == NULL) {
            cfl_sds_destroy(response_buffer);

            return -8;
        }

        response_buffer = sds_result;
    }

    sds_result = cfl_sds_cat(session->parent->outgoing_data,
                             response_buffer,
                             cfl_sds_len(response_buffer));

    cfl_sds_destroy(response_buffer);

    if (sds_result == NULL) {
        return -9;
    }

    session->parent->outgoing_data = sds_result;

    return 0;
}


int flb_http1_response_set_header(struct flb_http_response *response,
                              char *name, size_t name_length,
                              char *value, size_t value_length)
{
    int result;

    result = flb_hash_table_add(response->headers,
                                (const char *) name, (int) name_length,
                                (void *) value, (ssize_t) value_length);

    if (result < 0) {
        return -1;
    }

    return 0;
}

int flb_http1_response_set_status(struct flb_http_response *response,
                              int status)
{
    return 0;
}

int flb_http1_response_set_body(struct flb_http_response *response,
                            unsigned char *body, size_t body_length)
{
    return 0;
}

/* SESSION */

int flb_http1_server_session_init(struct flb_http1_server_session *session,
                       struct flb_http_server_session *parent)
{
    void *user_data;
    int   result;

    if (parent != NULL && parent->parent != NULL) {
        user_data = parent->parent->user_data;
    }
    else {
        user_data = NULL;
    }

    session->initialized = FLB_TRUE;

    dummy_mk_http_session_init(&session->inner_session, &session->inner_server);

    memset(&session->inner_request, 0, sizeof(struct mk_http_request));
    dummy_mk_http_request_init(&session->inner_session, &session->inner_request);

    mk_http_parser_init(&session->inner_parser);

    result = flb_http_stream_init(&session->stream, parent, 0, HTTP_STREAM_ROLE_SERVER,
                                  user_data);

    if (result != 0) {
        return -1;
    }

    session->parent = parent;

    return 0;
}

void flb_http1_server_session_destroy(struct flb_http1_server_session *session)
{
    if (session->initialized) {
        if (session->inner_session.channel != NULL) {
            mk_channel_release(session->inner_session.channel);

            session->inner_session.channel = NULL;
        }

        flb_http_stream_destroy(&session->stream);

        session->initialized = FLB_FALSE;
    }
}

int flb_http1_server_session_ingest(struct flb_http1_server_session *session,
                                    unsigned char *buffer,
                                    size_t length)
{
    int result;

    result = mk_http_parser(&session->inner_request,
                            &session->inner_parser,
                            session->parent->incoming_data,
                            cfl_sds_len(session->parent->incoming_data),
                            &session->inner_server);

    if (result == MK_HTTP_PARSER_OK) {
        result = http1_session_process_request(session);

        if (result != 0) {
            session->stream.status = HTTP_STREAM_STATUS_ERROR;

            return HTTP_SERVER_PROVIDER_ERROR;
        }

        http1_evict_request(session);
    }
    else if (result == MK_HTTP_PARSER_PENDING) {
        /*
         * No significant actions are taken here until we reach MK_HTTP_PARSER_OK.
         * The primary reason is that the caller may need to expand the buffer size
         * when payloads exceed the current buffer's capacity. In such cases, parser
         * pointers could end up referencing incorrect memory locations.
         * To prevent this, we reset the parser state, which introduces a minimal
         * performance overhead in exchange for ensuring safety.
         */
    }

    dummy_mk_http_request_init(&session->inner_session, &session->inner_request);
    mk_http_parser_init(&session->inner_parser);

    return HTTP_SERVER_SUCCESS;
}
