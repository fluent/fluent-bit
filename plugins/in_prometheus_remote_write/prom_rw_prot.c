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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/http_server/flb_http_server.h>

#include <cmetrics/cmt_decode_prometheus_remote_write.h>

#include "prom_rw.h"

static int send_response_ng(struct flb_http_response *response,
                            int http_status,
                            char *message)
{
    flb_http_response_set_status(response, http_status);

    if (http_status == 201) {
        flb_http_response_set_message(response, "Created");
    }
    else if (http_status == 200) {
        flb_http_response_set_message(response, "OK");
    }
    else if (http_status == 204) {
        flb_http_response_set_message(response, "No Content");
    }
    else if (http_status == 400) {
        flb_http_response_set_message(response, "Bad Request");
    }
    else if (http_status == 500) {
        flb_http_response_set_message(response, "Internal Server Error");
    }

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int process_payload_metrics_ng(struct flb_prom_remote_write *ctx,
                                      struct flb_http_request *request)
{
    struct cmt *context;
    int         result;

    result = cmt_decode_prometheus_remote_write_create(&context,
                                                       request->body,
                                                       cfl_sds_len(request->body));

    if (result != CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        return 400;
    }

    result = flb_input_metrics_append(ctx->ins, NULL, 0, context);
    cmt_decode_prometheus_remote_write_destroy(context);

    if (result != 0) {
        flb_plg_error(ctx->ins, "could not ingest metrics : %d", result);
        return 500;
    }

    return 0;
}

int prom_rw_prot_handle_ng(struct flb_http_request *request,
                           struct flb_http_response *response)
{
    struct flb_prom_remote_write *ctx;
    int                           result;

    ctx = (struct flb_prom_remote_write *) response->stream->user_data;

    if (request->path == NULL || request->path[0] != '/') {
        send_response_ng(response, 400, "error: invalid request\n");
        return -1;
    }

    if (ctx->uri != NULL && strcmp(request->path, ctx->uri) != 0) {
        send_response_ng(response, 400, "error: invalid endpoint\n");
        return -1;
    }

    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {
        send_response_ng(response, 400, "error: missing host header\n");
        return -1;
    }

    if (request->method != HTTP_METHOD_POST) {
        send_response_ng(response, 400, "error: invalid HTTP method\n");
        return -1;
    }

    if (request->body == NULL || cfl_sds_len(request->body) == 0) {
        send_response_ng(response, 400, "error: invalid payload\n");
        return -1;
    }

    result = process_payload_metrics_ng(ctx, request);
    if (result != 0) {
        if (result >= 500) {
            send_response_ng(response, result, "error: could not ingest metrics\n");
        }
        else {
            send_response_ng(response, result, "error: invalid request\n");
        }
        return -1;
    }

    send_response_ng(response, ctx->successful_response_code, NULL);

    return 0;
}
