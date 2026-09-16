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
#include <fluent-bit/flb_gzip.h>
#include <ctype.h>
#include <fluent-bit/flb_metrics_exporter.h>
#include <fluent-bit/http_server/flb_hs_utils.h>

#include <cmetrics/cmt_encode_msgpack.h>

#include "vivo.h"
#include "vivo_http.h"
#include "vivo_stream.h"
#include "vivo_otlp.h"

#define VIVO_ACCESS_CONTROL_ALLOW_HEADERS_VALUE \
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
#define VIVO_ACCESS_CONTROL_EXPOSE_HEADERS_VALUE \
    "vivo-stream-start-id, vivo-stream-end-id, vivo-stream-next-id, " \
    "vivo-stream-generation, vivo-stream-oldest-id, vivo-stream-tail-id, vivo-stream-gap, " \
    "vivo-stream-retained-bytes, vivo-stream-retained-entries, vivo-stream-evicted-entries, " \
    "vivo-stream-evicted-bytes, vivo-stream-rejected-entries"

static int stream_get_query_properties(struct flb_http_request *request,
                                       int64_t *from,
                                       int64_t *to,
                                       int64_t *limit)
{
    const char *cursor;
    const char *end;
    const char *equal;
    const char *digit;
    int64_t value;
    int64_t *target;
    size_t key_len;

    *from = -1;
    *to = -1;
    *limit = -1;
    cursor = request->query_string;
    while (cursor && *cursor) {
        end = strchr(cursor, '&');
        if (!end) {
            end = cursor + strlen(cursor);
        }
        equal = memchr(cursor, '=', end - cursor);
        if (!equal || equal + 1 == end) {
            return -1;
        }
        key_len = equal - cursor;
        if (key_len == 4 && memcmp(cursor, "from", 4) == 0) {
            target = from;
        }
        else if (key_len == 2 && memcmp(cursor, "to", 2) == 0) {
            target = to;
        }
        else if (key_len == 5 && memcmp(cursor, "limit", 5) == 0) {
            target = limit;
        }
        else {
            return -1;
        }
        if (*target != -1) {
            return -1;
        }
        value = 0;
        for (digit = equal + 1; digit < end; digit++) {
            if (*digit < '0' || *digit > '9' ||
                value > (INT64_MAX - (*digit - '0')) / 10) {
                return -1;
            }
            value = value * 10 + (*digit - '0');
        }
        *target = value;
        cursor = *end ? end + 1 : end;
        if (*end && !*cursor) {
            return -1;
        }
    }
    if (*limit == 0 || (*from >= 0 && *to >= 0 && *from > *to)) {
        return -1;
    }
    return 0;
}

static int headers_set_common(struct flb_http_response *response,
                              struct vivo_exporter *ctx)
{
    flb_hs_response_set_content_type(response, FLB_HS_CONTENT_TYPE_JSON);
    flb_http_response_set_header(response, "Cache-Control", 13, "no-store", 8);
    flb_http_response_set_header(response, "Access-Control-Allow-Methods", 28,
                                 "GET, HEAD, OPTIONS", 18);

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
    flb_http_response_set_header(response, "Content-Type", 12, "application/x-ndjson", 20);

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

static void header_number(struct flb_http_response *response, const char *name, uint64_t value)
{
    char text[32];
    int length;

    length = snprintf(text, sizeof(text), "%" PRIu64, value);
    flb_http_response_set_header(response, (char *) name, strlen(name), text, length);
}

/* Parse an HTTP qvalue without accepting junk, exponents or out-of-range values. */
static int encoding_quality(const char *start, const char *end)
{
    int quality;
    int factor = 100;

    if (start == end || (*start != '0' && *start != '1')) {
        return 0;
    }
    quality = (*start++ - '0') * 1000;
    if (start != end) {
        if (*start++ != '.') {
            return 0;
        }
        while (start < end) {
            if (*start < '0' || *start > '9' || factor == 0 ||
                (quality >= 1000 && *start != '0')) {
                return 0;
            }
            quality += (*start++ - '0') * factor;
            factor /= 10;
        }
    }
    return quality;
}

/* Return 1 for gzip, 0 for identity and -1 when neither representation is acceptable. */
static int response_encoding(struct flb_http_request *request, struct vivo_exporter *ctx)
{
    const char *cursor;
    const char *end;
    const char *token_end;
    const char *parameter;
    int quality;
    int gzip_quality = -1;
    int wildcard_quality = -1;
    int identity_quality = -1;
    size_t length;

    cursor = flb_http_request_get_header(request, "accept-encoding");
    while (cursor && *cursor) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == ',') {
            cursor++;
        }
        end = strchr(cursor, ',');
        if (!end) {
            end = cursor + strlen(cursor);
        }
        token_end = cursor;
        while (token_end < end && *token_end != ';' && !isspace((unsigned char) *token_end)) {
            token_end++;
        }
        length = token_end - cursor;
        quality = 1000;
        parameter = token_end;
        while (parameter < end && isspace((unsigned char) *parameter)) {
            parameter++;
        }
        if (parameter < end) {
            if (*parameter++ != ';') {
                quality = 0;
            }
            else {
                while (parameter < end && isspace((unsigned char) *parameter)) {
                    parameter++;
                }
                if (end - parameter < 2 || tolower((unsigned char) parameter[0]) != 'q' ||
                    parameter[1] != '=') {
                    quality = 0;
                }
                else {
                    parameter += 2;
                    while (end > parameter && isspace((unsigned char) end[-1])) {
                        end--;
                    }
                    quality = encoding_quality(parameter, end);
                }
            }
        }
        if (length == 4 && strncasecmp(cursor, "gzip", 4) == 0) {
            gzip_quality = quality;
        }
        else if (length == 8 && strncasecmp(cursor, "identity", 8) == 0) {
            identity_quality = quality;
        }
        else if (length == 1 && *cursor == '*') {
            wildcard_quality = quality;
        }
        cursor = strchr(cursor, ',');
        if (cursor) {
            cursor++;
        }
    }
    if (gzip_quality < 0) {
        gzip_quality = wildcard_quality;
    }
    if (ctx->compress && gzip_quality > 0 && gzip_quality >= identity_quality) {
        return 1;
    }
    if (identity_quality == 0 || (identity_quality < 0 && wildcard_quality == 0)) {
        return -1;
    }
    return 0;
}

static int send_payload(struct flb_http_request *request, struct flb_http_response *response,
                         struct vivo_exporter *ctx, const char *payload, size_t size)
{
    int encoding;
    int result;
    void *compressed = NULL;
    size_t compressed_size;

    flb_http_response_set_header(response, "Vary", 4, "Accept-Encoding", 15);
    encoding = response_encoding(request, ctx);
    if (encoding < 0) {
        flb_http_response_set_status(response, 406);
        return flb_http_response_commit(response);
    }
    if (encoding == 1 && size > 0) {
        if (flb_gzip_compress((void *) payload, size, &compressed, &compressed_size) != 0) {
            flb_http_response_set_status(response, 500);
            return flb_http_response_commit(response);
        }
        result = flb_http_response_set_body(response, compressed, compressed_size);
        flb_free(compressed);
        if (result == 0) {
            flb_http_response_set_header(response, "Content-Encoding", 16, "gzip", 4);
        }
    }
    else {
        result = flb_http_response_set_body(response, (unsigned char *) payload, size);
    }
    if (result != 0) {
        flb_http_response_set_status(response, 500);
    }
    return flb_http_response_commit(response);
}

static flb_sds_t page_envelope(struct vivo_exporter *ctx, const char *signal, flb_sds_t entries,
                               int64_t from, int64_t next, struct vivo_stream_snapshot *snapshot)
{
    flb_sds_t page;
    const char *gap;

    gap = from >= 0 && (from < snapshot->oldest || from > snapshot->next) ? "true" : "false";
    page = flb_sds_create_size(flb_sds_len(entries) + 512);
    if (!page) {
        return NULL;
    }
    if (!flb_sds_printf(&page,
        "{\"schemaVersion\":2,\"signal\":\"%s\",\"generation\":\"%s\","
        "\"nextCursor\":\"%" PRId64 "\",\"oldestCursor\":\"%" PRIu64 "\","
        "\"tailCursor\":\"%" PRIu64 "\",\"gap\":%s,\"entries\":[%s]}",
        signal, ctx->generation, next, snapshot->oldest, snapshot->next, gap, entries)) {
        flb_sds_destroy(page);
        return NULL;
    }
    return page;
}

static int vivo_http_serve_content(struct flb_http_request *request,
                                   struct flb_http_response *response,
                                   struct vivo_stream *vs)
{
    int result;
    int version;
    const char *signal;
    int64_t from;
    int64_t to;
    int64_t limit;
    int64_t stream_start_id;
    int64_t stream_end_id;
    int64_t stream_next_id;
    flb_sds_t payload;
    flb_sds_t converted;
    flb_sds_t str_start;
    flb_sds_t str_end;
    flb_sds_t str_next;
    struct vivo_stream_snapshot snapshot;
    struct vivo_exporter *ctx = vs->parent;

    if (stream_get_query_properties(request, &from, &to, &limit) != 0) {
        flb_http_response_set_status(response, 400);
        return flb_http_response_commit(response);
    }

    version = strncmp(request->path, "/api/v2/", 8) == 0 ? 2 : 1;
    signal = vs == ctx->stream_logs ? "logs" : (vs == ctx->stream_metrics ? "metrics" : "traces");
    payload = vivo_stream_get_content(vs, version, from, to, limit,
                                      &stream_start_id, &stream_end_id,
                                      &stream_next_id, &snapshot);
    if (!payload) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    if (version == 2) {
        converted = page_envelope(ctx, signal, payload, from, stream_next_id, &snapshot);
        flb_sds_destroy(payload);
        payload = converted;
        if (!payload) {
            flb_http_response_set_status(response, 500);
            return flb_http_response_commit(response);
        }
    }

    flb_http_response_set_status(response, 200);
    headers_set(response, vs);
    if (version == 2) {
        flb_hs_response_set_content_type(response, FLB_HS_CONTENT_TYPE_JSON);
    }

    flb_http_response_set_header(response, "vivo-stream-generation", 22, ctx->generation, 36);
    header_number(response, "vivo-stream-oldest-id", snapshot.oldest);
    header_number(response, "vivo-stream-tail-id", snapshot.next);
    header_number(response, "vivo-stream-retained-bytes", snapshot.retained_bytes);
    header_number(response, "vivo-stream-retained-entries", snapshot.retained_entries);
    header_number(response, "vivo-stream-evicted-entries", snapshot.evicted_entries);
    header_number(response, "vivo-stream-evicted-bytes", snapshot.evicted_bytes);
    header_number(response, "vivo-stream-rejected-entries", snapshot.rejected_entries);
    flb_http_response_set_header(response, "vivo-stream-gap", 15,
        from >= 0 && (from < snapshot.oldest || from > snapshot.next) ? "true" : "false",
        from >= 0 && (from < snapshot.oldest || from > snapshot.next) ? 4 : 5);

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

    if (stream_start_id < 0) {
        result = send_payload(request, response, ctx, payload, flb_sds_len(payload));
        flb_sds_destroy(payload);
        flb_sds_destroy(str_next);
        return result;
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

    result = send_payload(request, response, ctx, payload, flb_sds_len(payload));

    flb_sds_destroy(payload);
    flb_sds_destroy(str_start);
    flb_sds_destroy(str_end);
    flb_sds_destroy(str_next);

    return result;
}

static int cb_internal_metrics(struct flb_http_request *request,
                               struct flb_http_response *response,
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

    if (strncmp(request->path, "/api/v2/", 8) == 0) {
        json = vivo_otlp_metrics(cmt);
    }
    else {
        ret = cmt_encode_msgpack_create(cmt, &mp_buf, &mp_size);
        if (ret == 0) {
            json = vivo_json(mp_buf, mp_size, ctx->config->json_escape_unicode);
            cmt_encode_msgpack_destroy(mp_buf);
        }
    }
    cmt_destroy(cmt);

    if (!json) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    flb_http_response_set_status(response, 200);
    headers_set_common(response, ctx);
    ret = send_payload(request, response, ctx, json, flb_sds_len(json));
    flb_sds_destroy(json);

    return ret;
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

    headers_set_common(response, ctx);
    if (request->method == HTTP_METHOD_OPTIONS) {
        flb_http_response_set_status(response, 204);
        return flb_http_response_commit(response);
    }
    if (request->method != HTTP_METHOD_GET && request->method != HTTP_METHOD_HEAD) {
        flb_http_response_set_header(response, "Allow", 5, "GET, HEAD, OPTIONS", 18);
        flb_http_response_set_status(response, 405);
        return flb_http_response_commit(response);
    }
    if (strcmp(request->path, "/api/v1/health") == 0 ||
        strcmp(request->path, "/api/v2/health") == 0) {
        if (request->method == HTTP_METHOD_HEAD) {
            flb_http_response_set_status(response, 200);
            return flb_http_response_commit(response);
        }
        return flb_hs_response_send_string(response, 200, FLB_HS_CONTENT_TYPE_JSON,
            "{\"service\":\"vivo_exporter\",\"versions\":[1,2],"
            "\"v1Framing\":\"ndjson\",\"v2Framing\":\"json\",\"delivery\":\"best_effort\","
            "\"v2Payload\":\"otlp-json\",\"compression\":[\"gzip\",\"identity\"],"
            "\"non_finite\":[\"NaN\",\"Infinity\",\"-Infinity\"]}");
    }
    if (request->method == HTTP_METHOD_HEAD) {
        flb_http_response_set_status(response,
            strcmp(request->path, "/") == 0 ||
            (strcmp(request->path, "/api/v1/logs") == 0 ||
             strcmp(request->path, "/api/v2/logs") == 0) ||
            (strcmp(request->path, "/api/v1/metrics") == 0 ||
             strcmp(request->path, "/api/v2/metrics") == 0) ||
            (strcmp(request->path, "/api/v1/traces") == 0 ||
             strcmp(request->path, "/api/v2/traces") == 0) ||
            (strcmp(request->path, "/api/v1/internal/metrics") == 0 ||
             strcmp(request->path, "/api/v2/internal/metrics") == 0) ? 200 : 404);
        return flb_http_response_commit(response);
    }

    if ((strcmp(request->path, "/api/v1/logs") == 0 ||
             strcmp(request->path, "/api/v2/logs") == 0)) {
        return vivo_http_serve_content(request, response, ctx->stream_logs);
    }

    if ((strcmp(request->path, "/api/v1/metrics") == 0 ||
             strcmp(request->path, "/api/v2/metrics") == 0)) {
        return vivo_http_serve_content(request, response, ctx->stream_metrics);
    }

    if ((strcmp(request->path, "/api/v1/traces") == 0 ||
             strcmp(request->path, "/api/v2/traces") == 0)) {
        return vivo_http_serve_content(request, response, ctx->stream_traces);
    }

    if ((strcmp(request->path, "/api/v1/internal/metrics") == 0 ||
             strcmp(request->path, "/api/v2/internal/metrics") == 0)) {
        return cb_internal_metrics(request, response, ctx);
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
        options.idle_timeout = ins->http_server_config->idle_timeout;
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
