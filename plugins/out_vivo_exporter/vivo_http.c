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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_metrics_exporter.h>
#include <fluent-bit/http_server/flb_hs_utils.h>

#include <cmetrics/cmt_encode_msgpack.h>

#include "vivo.h"
#include "vivo_http.h"
#include "vivo_stream.h"

#define VIVO_ACCESS_CONTROL_ALLOW_HEADERS_VALUE \
    "Origin, X-Requested-With, Content-Type, Accept"
#define VIVO_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE \
    "vivo-stream-start-id, vivo-stream-end-id, vivo-stream-next-id"

static int stream_get_query_properties(struct flb_http_request *request,
                                       int64_t *from,
                                       int64_t *to,
                                       int64_t *limit)
{
    char *ptr;
    flb_sds_t buf;

    *from = -1;
    *to = -1;
    *limit = -1;

    if (request->query_string == NULL) {
        return 0;
    }

    buf = flb_sds_create_len(request->query_string, cfl_sds_len(request->query_string));
    if (!buf) {
        return -1;
    }

    ptr = strstr(buf, "from=");
    if (ptr) {
        *from = atol(ptr + 5);
    }

    ptr = strstr(buf, "to=");
    if (ptr) {
        *to = atol(ptr + 3);
    }

    ptr = strstr(buf, "limit=");
    if (ptr) {
        *limit = atol(ptr + 6);
    }

    flb_sds_destroy(buf);

    return 0;
}

static int headers_set_common(struct flb_http_response *response,
                              struct vivo_exporter *ctx)
{
    flb_hs_response_set_content_type(response, FLB_HS_CONTENT_TYPE_JSON);

    if (ctx->http_cors_allow_origin != NULL) {
        flb_http_response_set_header(
            response,
            "Access-Control-Allow-Origin",
            sizeof("Access-Control-Allow-Origin") - 1,
            ctx->http_cors_allow_origin,
            flb_sds_len(ctx->http_cors_allow_origin));

        flb_http_response_set_header(
            response,
            "Access-Control-Allow-Headers",
            sizeof("Access-Control-Allow-Headers") - 1,
            VIVO_ACCESS_CONTROL_ALLOW_HEADERS_VALUE,
            sizeof(VIVO_ACCESS_CONTROL_ALLOW_HEADERS_VALUE) - 1);
    }

    return 0;
}

static int headers_set(struct flb_http_response *response, struct vivo_stream *vs)
{
    struct vivo_exporter *ctx;

    ctx = vs->parent;
    headers_set_common(response, ctx);

    if (ctx->http_cors_allow_origin != NULL) {
        flb_http_response_set_header(
            response,
            "Access-Control-Expose-Headers",
            sizeof("Access-Control-Expose-Headers") - 1,
            VIVO_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE,
            sizeof(VIVO_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE) - 1);
    }

    return 0;
}

static int vivo_http_serve_content(struct flb_http_request *request,
                                   struct flb_http_response *response,
                                   struct vivo_stream *vs)
{
    int64_t from;
    int64_t to;
    int64_t limit;
    int64_t stream_start_id;
    int64_t stream_end_id;
    int64_t stream_next_id;
    flb_sds_t payload;
    flb_sds_t str_start;
    flb_sds_t str_end;
    flb_sds_t str_next;

    if (stream_get_query_properties(request, &from, &to, &limit) != 0) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    payload = vivo_stream_get_content(vs, from, to, limit,
                                      &stream_start_id, &stream_end_id,
                                      &stream_next_id);
    if (!payload) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    flb_http_response_set_status(response, 200);
    headers_set(response, vs);

    str_next = flb_sds_create_size(32);
    if (str_next == NULL) {
        flb_sds_destroy(payload);
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    flb_sds_printf(&str_next, "%" PRId64, stream_next_id);
    flb_http_response_set_header(response,
                                 VIVO_STREAM_NEXT_ID,
                                 sizeof(VIVO_STREAM_NEXT_ID) - 1,
                                 str_next,
                                 flb_sds_len(str_next));

    if (flb_sds_len(payload) == 0) {
        flb_sds_destroy(payload);
        flb_sds_destroy(str_next);
        flb_http_response_set_body(response, NULL, 0);
        return flb_http_response_commit(response);
    }

    str_start = flb_sds_create_size(32);
    str_end = flb_sds_create_size(32);

    if (str_start == NULL || str_end == NULL) {
        flb_sds_destroy(payload);
        flb_sds_destroy(str_next);

        if (str_start != NULL) {
            flb_sds_destroy(str_start);
        }

        if (str_end != NULL) {
            flb_sds_destroy(str_end);
        }

        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    flb_sds_printf(&str_start, "%" PRId64, stream_start_id);
    flb_sds_printf(&str_end, "%" PRId64, stream_end_id);

    flb_http_response_set_header(response,
                                 VIVO_STREAM_START_ID,
                                 sizeof(VIVO_STREAM_START_ID) - 1,
                                 str_start,
                                 flb_sds_len(str_start));

    flb_http_response_set_header(response,
                                 VIVO_STREAM_END_ID,
                                 sizeof(VIVO_STREAM_END_ID) - 1,
                                 str_end,
                                 flb_sds_len(str_end));

    flb_http_response_set_body(response,
                               (unsigned char *) payload,
                               flb_sds_len(payload));

    flb_sds_destroy(payload);
    flb_sds_destroy(str_start);
    flb_sds_destroy(str_end);
    flb_sds_destroy(str_next);

    return flb_http_response_commit(response);
}

static int cb_internal_metrics(struct flb_http_response *response,
                               struct vivo_exporter *ctx)
{
    int ret;
    char *mp_buf;
    size_t mp_size;
    flb_sds_t json;
    struct cmt *cmt;

    mp_buf = NULL;
    mp_size = 0;
    json = NULL;

    cmt = flb_me_get_cmetrics(ctx->config);
    if (!cmt) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    ret = cmt_encode_msgpack_create(cmt, &mp_buf, &mp_size);
    if (ret != 0) {
        cmt_destroy(cmt);
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    json = flb_msgpack_raw_to_json_sds(mp_buf, mp_size,
                                       ctx->config->json_escape_unicode);

    cmt_encode_msgpack_destroy(mp_buf);
    cmt_destroy(cmt);

    if (!json) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    flb_http_response_set_status(response, 200);
    headers_set_common(response, ctx);
    flb_http_response_set_body(response,
                               (unsigned char *) json,
                               flb_sds_len(json));
    flb_sds_destroy(json);

    return flb_http_response_commit(response);
}

static int vivo_http_request_handler(struct flb_http_request *request,
                                     struct flb_http_response *response)
{
    struct vivo_exporter *ctx;

    ctx = response->stream->user_data;
    if (ctx == NULL) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    if (strcmp(request->path, "/api/v1/logs") == 0) {
        return vivo_http_serve_content(request, response, ctx->stream_logs);
    }

    if (strcmp(request->path, "/api/v1/metrics") == 0) {
        return vivo_http_serve_content(request, response, ctx->stream_metrics);
    }

    if (strcmp(request->path, "/api/v1/traces") == 0) {
        return vivo_http_serve_content(request, response, ctx->stream_traces);
    }

    if (strcmp(request->path, "/api/v1/internal/metrics") == 0) {
        return cb_internal_metrics(response, ctx);
    }

    if (strcmp(request->path, "/") == 0) {
        return flb_hs_response_send_string(response,
                                           200,
                                           FLB_HS_CONTENT_TYPE_OTHER,
                                           "Fluent Bit Vivo Exporter\n");
    }

    flb_http_response_set_status(response, 404);

    return flb_http_response_commit(response);
}

struct vivo_http *vivo_http_server_create(struct vivo_exporter *ctx,
                                          struct flb_config *config)
{
    int ret;
    int protocol_version;
    struct vivo_http *ph;
    struct flb_output_instance *ins;
    struct flb_http_server_options options;

    ph = flb_calloc(1, sizeof(struct vivo_http));
    if (!ph) {
        flb_errno();
        return NULL;
    }

    ph->config = config;
    ins = ctx->ins;

    if (ins->http_server_config != NULL &&
        ins->http_server_config->http2 == FLB_FALSE) {
        protocol_version = HTTP_PROTOCOL_VERSION_11;
    }
    else {
        protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    }

    flb_http_server_options_init(&options);
    options.protocol_version = protocol_version;
    options.request_callback = vivo_http_request_handler;
    options.user_data = ctx;
    options.address = ins->host.name;
    options.port = ins->host.port;
    options.networking_flags = ins->flags;
    options.networking_setup = &ins->net_setup;
    options.event_loop = config->evl;
    options.system_context = config;
    options.use_caller_event_loop = FLB_TRUE;

    if (ins->http_server_config != NULL) {
        options.buffer_max_size = ins->http_server_config->buffer_max_size;
        options.max_connections = ins->http_server_config->max_connections;
    }

    ret = flb_http_server_init_with_options(&ph->server, &options);
    if (ret != 0) {
        flb_free(ph);
        return NULL;
    }

    return ph;
}

void vivo_http_server_destroy(struct vivo_http *ph)
{
    if (ph != NULL) {
        flb_http_server_destroy(&ph->server);
        flb_free(ph);
    }
}

int vivo_http_server_start(struct vivo_http *ph)
{
    return flb_http_server_start(&ph->server);
}

int vivo_http_server_stop(struct vivo_http *ph)
{
    return flb_http_server_stop(&ph->server);
}

int vivo_http_server_mq_push_metrics(struct vivo_http *ph,
                                     void *data, size_t size)
{
    (void) ph;
    (void) data;
    (void) size;

    return 0;
}
