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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_metrics_exporter.h>

#include <cmetrics/cmt_encode_msgpack.h>

#include "vivo.h"
#include "vivo_http.h"
#include "vivo_stream.h"

#define VIVO_CONTENT_TYPE       "Content-Type"
#define VIVO_CONTENT_TYPE_JSON  "application/json"
#define VIVO_STREAM_START_ID    "Vivo-Stream-Start-ID"
#define VIVO_STREAM_END_ID      "Vivo-Stream-End-ID"

static int stream_get_uri_properties(mk_request_t *request,
                                     int64_t *from, int64_t *to, int64_t *limit)
{
    char *ptr;
    flb_sds_t buf;

    *from = -1;
    *to = -1;
    *limit = -1;

    buf = flb_sds_create_len(request->query_string.data, request->query_string.len);
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

static void headers_set_common(struct vivo_exporter *ctx, mk_request_t *request)
{
    /* content type */
    mk_http_header(request,
                   VIVO_CONTENT_TYPE, sizeof(VIVO_CONTENT_TYPE) - 1,
                   VIVO_CONTENT_TYPE_JSON, sizeof(VIVO_CONTENT_TYPE_JSON) - 1);

    /* CORS */
    if (ctx->http_cors_allow_origin) {
        mk_http_header(request,
                       "Access-Control-Allow-Origin",
                       sizeof("Access-Control-Allow-Origin") - 1,
                       ctx->http_cors_allow_origin,
                       flb_sds_len(ctx->http_cors_allow_origin));

        mk_http_header(request,
                       "Access-Control-Allow-Headers",
                       sizeof("Access-Control-Allow-Headers") - 1,
                       "Origin, X-Requested-With, Content-Type, Accept",
                       sizeof("Origin, X-Requested-With, Content-Type, Accept") - 1);
    }
}

static void headers_set(mk_request_t *request, struct vivo_stream *vs)
{
    struct vivo_exporter *ctx;


    /* parent context */
    ctx = vs->parent;

    headers_set_common(ctx, request);

    if (ctx->http_cors_allow_origin) {
        mk_http_header(request,
                       "Access-Control-Expose-Headers",
                       sizeof("Access-Control-Expose-Headers") - 1,
                       "vivo-stream-start-id, vivo-stream-end-id",
                       sizeof("vivo-stream-start-id, vivo-stream-end-id") - 1);
    }
}

static void serve_content(mk_request_t *request, struct vivo_stream *vs)
{
    int64_t from = -1;
    int64_t to = -1;
    int64_t limit = -1;
    int64_t stream_start_id = -1;
    int64_t stream_end_id = -1;
    flb_sds_t payload;
    flb_sds_t str_start;
    flb_sds_t str_end;


    if (request->query_string.len > 0) {
        stream_get_uri_properties(request, &from, &to, &limit);
    }

    payload = vivo_stream_get_content(vs, from, to, limit,
                                      &stream_start_id, &stream_end_id);
    if (!payload) {
        mk_http_status(request, 500);
        return;
    }

    if (flb_sds_len(payload) == 0) {
        mk_http_status(request, 200);
        headers_set(request, vs);
        flb_sds_destroy(payload);
        return;
    }

    mk_http_status(request, 200);

    /* set response headers */
    headers_set(request, vs);

    /* stream ids served: compose buffer and set headers */
    str_start = flb_sds_create_size(32);
    flb_sds_printf(&str_start, "%" PRId64, stream_start_id);

    str_end = flb_sds_create_size(32);
    flb_sds_printf(&str_end, "%" PRId64, stream_end_id);

    mk_http_header(request,
                   VIVO_STREAM_START_ID, sizeof(VIVO_STREAM_START_ID) - 1,
                   str_start, flb_sds_len(str_start));

    mk_http_header(request,
                   VIVO_STREAM_END_ID, sizeof(VIVO_STREAM_END_ID) - 1,
                   str_end, flb_sds_len(str_end));

    /* send payload */
    mk_http_send(request, payload, flb_sds_len(payload), NULL);

    /* release */
    flb_sds_destroy(payload);
    flb_sds_destroy(str_start);
    flb_sds_destroy(str_end);
}

/* HTTP endpoint: /api/v1/logs */
static void cb_logs(mk_request_t *request, void *data)
{
    struct vivo_exporter *ctx;

    ctx = (struct vivo_exporter *) data;

    serve_content(request, ctx->stream_logs);
    mk_http_done(request);
}

/* HTTP endpoint: /api/v1/metrics */
static void cb_metrics(mk_request_t *request, void *data)
{
    struct vivo_exporter *ctx;

    ctx = (struct vivo_exporter *) data;

    serve_content(request, ctx->stream_metrics);
    mk_http_done(request);
}

/* HTTP endpoint: /api/v1/traces */
static void cb_traces(mk_request_t *request, void *data)
{
    struct vivo_exporter *ctx;

    ctx = (struct vivo_exporter *) data;

    serve_content(request, ctx->stream_traces);
    mk_http_done(request);
}

/* HTTP endpoint: /api/v1/internal/metrics */
static void cb_internal_metrics(mk_request_t *request, void *data)
{
    int ret;
    char *mp_buf = NULL;
    size_t mp_size = 0;
    flb_sds_t json = NULL;
    struct cmt *cmt = NULL;
    struct vivo_exporter *ctx;

    ctx = (struct vivo_exporter *) data;

    cmt = flb_me_get_cmetrics(ctx->config);
    if (!cmt) {
        mk_http_status(request, 500);
        mk_http_done(request);
        return;
    }

    ret = cmt_encode_msgpack_create(cmt, &mp_buf, &mp_size);
    if (ret != 0) {
        cmt_destroy(cmt);
        mk_http_status(request, 500);
        mk_http_done(request);
        return;
    }

    json = flb_msgpack_raw_to_json_sds(mp_buf, mp_size,
                                       ctx->config->json_escape_unicode);

    cmt_encode_msgpack_destroy(mp_buf);
    cmt_destroy(cmt);

    if (!json) {
        mk_http_status(request, 500);
        mk_http_done(request);
        return;
    }

    mk_http_status(request, 200);
    headers_set_common(ctx, request);
    mk_http_send(request, json, flb_sds_len(json), NULL);
    mk_http_done(request);

    flb_sds_destroy(json);
}

/* HTTP endpoint: / (root) */
static void cb_root(mk_request_t *request, void *data)
{
    (void) data;

    mk_http_status(request, 200);
    mk_http_send(request, "Fluent Bit Vivo Exporter\n", 24, NULL);
    mk_http_done(request);
}

struct vivo_http *vivo_http_server_create(struct vivo_exporter *ctx,
                                          const char *listen,
                                          int tcp_port,
                                          struct flb_config *config)
{
    int vid;
    char tmp[32];
    struct vivo_http *ph;

    ph = flb_malloc(sizeof(struct vivo_http));
    if (!ph) {
        flb_errno();
        return NULL;
    }
    ph->config = config;

    /* HTTP Server context */
    ph->ctx = mk_create();
    if (!ph->ctx) {
        flb_free(ph);
        return NULL;
    }

    /* Compose listen address */
    snprintf(tmp, sizeof(tmp) -1, "%s:%d", listen, tcp_port);
    mk_config_set(ph->ctx,
                  "Listen", tmp,
                  "Workers", "1",
                  NULL);

    /* Virtual host */
    vid = mk_vhost_create(ph->ctx, NULL);
    ph->vid = vid;

    /* Set HTTP URI callbacks */
    mk_vhost_handler(ph->ctx, vid, "/api/v1/logs", cb_logs, ctx);
    mk_vhost_handler(ph->ctx, vid, "/api/v1/metrics", cb_metrics, ctx);
    mk_vhost_handler(ph->ctx, vid, "/api/v1/traces", cb_traces, ctx);
    mk_vhost_handler(ph->ctx, vid, "/api/v1/internal/metrics", cb_internal_metrics, ctx);
    mk_vhost_handler(ph->ctx, vid, "/", cb_root, NULL);

    return ph;
}

void vivo_http_server_destroy(struct vivo_http *ph)
{
    if (ph) {
        /* TODO: release mk_vhost */
        if (ph->ctx) {
            mk_destroy(ph->ctx);
        }
        flb_free(ph);
    }
}

int vivo_http_server_start(struct vivo_http *ph)
{
    return mk_start(ph->ctx);
}

int vivo_http_server_stop(struct vivo_http *ph)
{
    return mk_stop(ph->ctx);
}
