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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_compression.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_input_ingest.h>
#include <fluent-bit/http_server/flb_http_server.h>

#include <string.h>
#include <strings.h>

/*
 * Request processing shared by the socket path and by host-driven ingestion:
 * authorization, body inflation and the request handler, in that order.
 */
struct flb_http_server_stage_context {
    flb_http_server_request_processor_callback callback;
    struct flb_http_request *request;
    struct flb_http_response *response;
};

static int flb_http_server_stage_dispatch(void *data)
{
    struct flb_http_server_stage_context *context;

    context = data;

    return context->callback(context->request, context->response);
}

/* Handlers of a socket request run on the parent stack of its coroutine */
static int flb_http_server_stage_call(struct flb_connection *connection,
                                      flb_http_server_request_processor_callback callback,
                                      struct flb_http_request *request,
                                      struct flb_http_response *response)
{
    struct flb_http_server_stage_context context;

    if (connection == NULL) {
        return callback(request, response);
    }

    context.callback = callback;
    context.request = request;
    context.response = response;

    return flb_downstream_conn_event_call_parent(connection,
                                                 flb_http_server_stage_dispatch,
                                                 &context);
}

static int flb_http_server_inflate_request(struct flb_http_server *server,
                                           struct flb_http_request *request,
                                           struct flb_http_response *response)
{
    int result;
    int status;

    result = flb_http_request_uncompress_body(request, server->max_decoded_body_size);
    if (result != 0) {
        status = 400;
        if (result == FLB_DECOMPRESSOR_LIMIT_EXCEEDED) {
            status = 413;
        }
        else if (result == FLB_DECOMPRESSOR_ALLOCATION_FAILURE) {
            status = 503;
        }
        flb_http_response_set_status(response, status);
        flb_http_response_commit(response);
    }

    return result;
}

int flb_http_server_request_process(struct flb_http_server *server,
                                    struct flb_connection *connection,
                                    struct flb_http_request *request,
                                    struct flb_http_response *response)
{
    int result;

    result = 0;

    if (request->body != NULL && request->content_length == 0) {
        request->content_length = cfl_sds_len(request->body);
    }

    if (server->authorization_callback != NULL) {
        result = flb_http_server_stage_call(connection,
                                            server->authorization_callback,
                                            request, response);
        if (result != 0) {
            return result;
        }
    }

    if ((server->flags & FLB_HTTP_SERVER_FLAG_AUTO_INFLATE) != 0) {
        result = flb_http_server_inflate_request(server, request, response);
        if (result != 0) {
            return result;
        }
    }

    if (server->request_callback != NULL) {
        result = flb_http_server_stage_call(connection,
                                            server->request_callback,
                                            request, response);
    }

    return result;
}

/*
 * Host-driven ingestion
 * =====================
 * The host program supplies an assembled request. There is no connection:
 * the request is processed on a stand-in stream and the response the handler
 * commits is handed back as the reply of the submission.
 */
static int ingest_method_id(const char *method, size_t length)
{
    static const struct {
        const char *name;
        int id;
    } methods[] = {
        { "GET", HTTP_METHOD_GET },
        { "POST", HTTP_METHOD_POST },
        { "HEAD", HTTP_METHOD_HEAD },
        { "PUT", HTTP_METHOD_PUT },
        { "DELETE", HTTP_METHOD_DELETE },
        { "OPTIONS", HTTP_METHOD_OPTIONS }
    };
    size_t i;

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        if (strlen(methods[i].name) == length &&
            strncasecmp(methods[i].name, method, length) == 0) {
            return methods[i].id;
        }
    }

    return HTTP_METHOD_UNKNOWN;
}

static int ingest_hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

/* The wire parser hands the handlers a path with its escapes decoded */
static cfl_sds_t ingest_path_decode(const char *path, size_t length)
{
    int high;
    int low;
    size_t i;
    size_t out;
    cfl_sds_t decoded;

    decoded = cfl_sds_create_len(path, length);
    if (decoded == NULL) {
        return NULL;
    }

    out = 0;
    for (i = 0; i < length; i++) {
        if (path[i] == '%' && i + 2 < length) {
            high = ingest_hex_value(path[i + 1]);
            low = ingest_hex_value(path[i + 2]);
            if (high >= 0 && low >= 0 && (high != 0 || low != 0)) {
                decoded[out++] = (char) ((high << 4) | low);
                i += 2;
                continue;
            }
        }
        decoded[out++] = path[i];
    }

    decoded[out] = '\0';
    cfl_sds_set_len(decoded, out);

    return decoded;
}

static int ingest_header_is(const struct flb_input_ingest_header *header,
                            const char *name)
{
    return header->name_len == strlen(name) &&
           strncasecmp(header->name, name, header->name_len) == 0;
}

static int ingest_request_fill(struct flb_http_request *request,
                               const struct flb_input_ingest_event *event)
{
    int result;
    size_t i;
    size_t path_length;
    const char *query;
    const struct flb_input_ingest_header *header;

    if (event->path == NULL || event->path_len == 0 || event->path[0] != '/') {
        return -1;
    }

    /* The fields below are the ones the wire parser derives for handlers */
    request->protocol_version = HTTP_PROTOCOL_VERSION_11;
    request->method = ingest_method_id(event->method, event->method_len);

    query = memchr(event->path, '?', event->path_len);
    path_length = event->path_len;
    if (query != NULL) {
        path_length = (size_t) (query - event->path);
        if (path_length + 1 < event->path_len) {
            request->query_string = cfl_sds_create_len(
                                        query + 1,
                                        event->path_len - path_length - 1);
            if (request->query_string == NULL) {
                return -1;
            }
        }
    }

    request->path = ingest_path_decode(event->path, path_length);
    if (request->path == NULL) {
        return -1;
    }

    for (i = 0; i < event->header_count; i++) {
        header = &event->headers[i];

        if (header->name_len == 0 || header->value_len == 0) {
            continue;
        }

        if (flb_http_header_validate(header->name, header->name_len,
                                     header->value, header->value_len) != 0) {
            return -1;
        }

        if (ingest_header_is(header, "host")) {
            if (request->host != NULL) {
                cfl_sds_destroy(request->host);
            }
            request->host = cfl_sds_create_len(header->value, header->value_len);
            if (request->host == NULL) {
                return -1;
            }
        }
        else if (ingest_header_is(header, "content-type")) {
            if (request->content_type != NULL) {
                cfl_sds_destroy(request->content_type);
            }
            request->content_type = cfl_sds_create_len(header->value,
                                                       header->value_len);
            if (request->content_type == NULL) {
                return -1;
            }
        }

        result = flb_http_request_set_header(request,
                                             (char *) header->name,
                                             header->name_len,
                                             (char *) header->value,
                                             header->value_len);
        if (result != 0) {
            return -1;
        }
    }

    if (request->host == NULL) {
        request->host = cfl_sds_create("");
        if (request->host == NULL) {
            return -1;
        }
    }

    /* The body is complete: its size is the content length */
    request->content_length = event->size;
    if (event->size > 0) {
        request->body = cfl_sds_create_len(event->data, event->size);
        if (request->body == NULL) {
            return -1;
        }
    }

    return 0;
}

/* Invoked when the handler commits its response: hand it back as the reply */
static void ingest_reply_deliver(struct flb_http_response *response, void *data)
{
    size_t count;
    const struct flb_input_ingest_event *event;
    struct flb_http_request *request;
    struct mk_list *head;
    struct flb_hash_table_entry *entry;
    struct flb_input_ingest_header *headers;
    struct flb_input_ingest_reply reply;

    event = data;
    request = &response->stream->request;
    headers = NULL;
    count = 0;

    if (response->headers != NULL) {
        mk_list_foreach(head, &response->headers->entries) {
            count++;
        }
    }

    if (count > 0) {
        headers = flb_calloc(count, sizeof(struct flb_input_ingest_header));
        if (headers == NULL) {
            /* No reply can be built: the core reports the request as failed */
            flb_errno();
            return;
        }

        count = 0;
        mk_list_foreach(head, &response->headers->entries) {
            entry = mk_list_entry(head, struct flb_hash_table_entry, _head_parent);
            headers[count].name = entry->key;
            headers[count].name_len = entry->key_len;
            headers[count].value = entry->val;
            headers[count].value_len = entry->val_size;
            count++;
        }
    }

    memset(&reply, 0, sizeof(reply));
    reply.status = response->status;
    reply.headers = headers;
    reply.header_count = count;

    /* A HEAD response carries no body on the wire either */
    if (response->body != NULL && request->method != HTTP_METHOD_HEAD) {
        reply.body = response->body;
        reply.body_size = cfl_sds_len(response->body);
    }

    flb_input_ingest_event_reply(event, &reply);

    if (headers != NULL) {
        flb_free(headers);
    }
}

int flb_http_server_ingest(struct flb_http_server *server,
                           const struct flb_input_ingest_event *event)
{
    int result;
    struct flb_http_stream stream;

    if (server == NULL || event == NULL ||
        event->kind != FLB_INPUT_INGEST_HTTP_REQUEST ||
        server->status != HTTP_SERVER_RUNNING) {
        return -1;
    }

    memset(&stream, 0, sizeof(stream));

    result = flb_http_stream_init(&stream, NULL, 1, HTTP_STREAM_ROLE_HOST,
                                  server->user_data);
    if (result != 0) {
        flb_http_stream_destroy(&stream);
        return -1;
    }

    result = ingest_request_fill(&stream.request, event);
    if (result != 0) {
        flb_http_stream_destroy(&stream);
        return -1;
    }

    stream.status = HTTP_STREAM_STATUS_PROCESSING;
    stream.cb_host_response = ingest_reply_deliver;
    stream.host_data = (void *) event;

    if (stream.request.content_type != NULL &&
        strncasecmp(stream.request.content_type, "application/grpc", 16) == 0) {
        /* gRPC needs HTTP/2 framing, which an assembled request does not have */
        flb_http_response_set_status(&stream.response, 415);
        flb_http_response_set_message(&stream.response, "Unsupported Media Type");
        flb_http_response_commit(&stream.response);
        result = -1;
    }
    else {
        result = flb_http_server_request_process(server, NULL,
                                                 &stream.request, &stream.response);
    }

    /*
     * Handlers commit an error response and then return an error as well, so
     * the committed response and not the return value tells whether there is
     * a reply: it was delivered when it was committed. Without one the core
     * reports the request as failed.
     */
    flb_http_stream_destroy(&stream);

    return result;
}
