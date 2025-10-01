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
#include <fluent-bit/flb_input_event.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_ra_key.h>

#include <cfl/cfl.h>
#include <fluent-otel-proto/fluent-otel.h>

#include <cmetrics/cmetrics.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_zstd.h>
#include <cmetrics/cmt_encode_opentelemetry.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>

#include <cprofiles/cprofiles.h>
#include <cprofiles/cprof_decode_msgpack.h>
#include <cprofiles/cprof_encode_opentelemetry.h>

extern cfl_sds_t cmt_encode_opentelemetry_create(struct cmt *cmt);
extern void cmt_encode_opentelemetry_destroy(cfl_sds_t text);

#include "opentelemetry.h"
#include "opentelemetry_conf.h"
#include "opentelemetry_utils.h"

static int is_http_status_code_retrayable(int http_code)
{
    /*
     * Retrayable HTTP code according to OTLP spec:
     *
     * https://opentelemetry.io/docs/specs/otlp/#retryable-response-codes
     */
    if (http_code == 429 || http_code == 502 ||
        http_code == 503 || http_code == 504) {
        /*
         * a note on HTTP status 500, the document says: "All other 4xx or 5xx
         * response status codes MUST NOT be retried." -- I personally think
         * 500 should be retried in case a proxy fails, but let's honor the docs
         * for now.
         */
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int opentelemetry_legacy_post(struct opentelemetry_context *ctx,
                              const void *body, size_t body_len,
                              const char *tag, int tag_len,
                              const char *uri)
{
    size_t                     final_body_len;
    void                      *final_body;
    int                        compressed;
    int                        out_ret;
    size_t                     b_sent;
    struct flb_connection     *u_conn;
    struct mk_list            *head;
    int                        ret;
    struct flb_slist_entry    *key;
    struct flb_slist_entry    *val;
    struct flb_config_map_val *mv;
    struct flb_http_client    *c;

    compressed = FLB_FALSE;

    u_conn = flb_upstream_conn_get(ctx->u);

    if (u_conn == NULL) {
        flb_plg_error(ctx->ins,
                      "no upstream connections available to %s:%i",
                      ctx->u->tcp_host,
                      ctx->u->tcp_port);

        return FLB_RETRY;
    }

    if (ctx->compress_gzip) {
        ret = flb_gzip_compress((void *) body, body_len,
                                &final_body, &final_body_len);

        if (ret == 0) {
            compressed = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "cannot gzip payload, disabling compression");
        }
    }
    else if (ctx->compress_zstd) {
        ret = flb_zstd_compress((void *) body, body_len,
                                &final_body, &final_body_len);

        if (ret == 0) {
            compressed = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "cannot zstd payload, disabling compression");
        }
    }
    else {
        final_body = (void *) body;
        final_body_len = body_len;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, uri,
                        final_body, final_body_len,
                        ctx->host, ctx->port,
                        ctx->proxy, 0);

    if (c == NULL) {
        flb_plg_error(ctx->ins, "error initializing http client");

        if (compressed) {
            flb_free(final_body);
        }

        flb_upstream_conn_release(u_conn);

        return FLB_RETRY;
    }

    if (c->proxy.host != NULL) {
        flb_plg_debug(ctx->ins, "[http_client] proxy host: %s port: %i",
                      c->proxy.host, c->proxy.port);
    }

    /* Allow duplicated headers ? */
    flb_http_allow_duplicated_headers(c, FLB_FALSE);

    /*
     * Direct assignment of the callback context to the HTTP client context.
     * This needs to be improved through a more clean API.
     */
    c->cb_ctx = ctx->ins->callback;

    flb_http_add_header(c,
                        FLB_OPENTELEMETRY_CONTENT_TYPE_HEADER_NAME,
                        sizeof(FLB_OPENTELEMETRY_CONTENT_TYPE_HEADER_NAME) - 1,
                        FLB_OPENTELEMETRY_MIME_PROTOBUF_LITERAL,
                        sizeof(FLB_OPENTELEMETRY_MIME_PROTOBUF_LITERAL) - 1);

    /* Basic Auth headers */
    if (ctx->http_user != NULL &&
        ctx->http_passwd != NULL) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    flb_config_map_foreach(head, mv, ctx->headers) {
        key = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        val = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        flb_http_add_header(c,
                            key->str, flb_sds_len(key->str),
                            val->str, flb_sds_len(val->str));
    }

    if (compressed) {
        if (ctx->compress_gzip) {
            flb_http_set_content_encoding_gzip(c);
        }
        else if (ctx->compress_zstd) {
            flb_http_set_content_encoding_zstd(c);
        }
    }

    /* Map debug callbacks */
    flb_http_client_debug(c, ctx->ins->callback);

    ret = flb_http_do(c, &b_sent);

    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         * - 200: OK
         * - 201: Created
         * - 202: Accepted
         * - 203: no authorative resp
         * - 204: No Content
         * - 205: Reset content
         *
         */
        if (c->resp.status < 200 || c->resp.status > 205) {
            if (ctx->log_response_payload &&
                c->resp.payload != NULL &&
                c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%.*s",
                              ctx->host, ctx->port,
                              c->resp.status,
                              (int) c->resp.payload_size,
                              c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->host, ctx->port, c->resp.status);
            }

            /* Retryable status codes according to OTLP spec */
            if (is_http_status_code_retrayable(c->resp.status) == FLB_TRUE) {
                out_ret = FLB_RETRY;
            }
            else {
                out_ret = FLB_ERROR;
            }
        }
        else {
            if (ctx->log_response_payload && c->resp.payload != NULL && c->resp.payload_size > 2) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i%.*s",
                             ctx->host, ctx->port,
                             c->resp.status,
                             (int) c->resp.payload_size,
                             c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                             ctx->host, ctx->port,
                             c->resp.status);
            }

            out_ret = FLB_OK;
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->host, ctx->port, ret);

        out_ret = FLB_RETRY;
    }

    if (compressed) {
        flb_free(final_body);
    }

    /* Destroy HTTP client context */
    flb_http_client_destroy(c);

    /* Release the TCP connection */
    flb_upstream_conn_release(u_conn);

    return out_ret;
}

int opentelemetry_post(struct opentelemetry_context *ctx,
                       const void *body, size_t body_len,
                       const char *tag, int tag_len,
                       const char *http_uri,
                       const char *grpc_uri)
{
    const char               *compression_algorithm;
    uint32_t                  wire_message_length;
    size_t                    grpc_body_length;
    cfl_sds_t                 sds_result;
    cfl_sds_t                 grpc_body;
    struct flb_http_response *response;
    struct flb_http_request  *request;
    int                       out_ret;
    int                       result;

    if (!ctx->enable_http2_flag) {
        return opentelemetry_legacy_post(ctx,
                                         body, body_len,
                                         tag, tag_len,
                                         http_uri);
    }

    compression_algorithm = NULL;

    request = flb_http_client_request_builder(
                    &ctx->http_client,
                    FLB_HTTP_CLIENT_ARGUMENT_METHOD(FLB_HTTP_POST),
                    FLB_HTTP_CLIENT_ARGUMENT_HOST(ctx->host),
                    FLB_HTTP_CLIENT_ARGUMENT_USER_AGENT("Fluent-Bit"),
                    FLB_HTTP_CLIENT_ARGUMENT_HEADERS(
                        FLB_HTTP_CLIENT_HEADER_CONFIG_MAP_LIST,
                        ctx->headers));

    if (request == NULL) {
        flb_plg_error(ctx->ins, "error initializing http request");

        return FLB_RETRY;
    }

    if (request->protocol_version == HTTP_PROTOCOL_VERSION_20 &&
        ctx->enable_grpc_flag) {

        grpc_body = cfl_sds_create_size(body_len + 5);

        if (grpc_body == NULL) {
            flb_http_client_request_destroy(request, FLB_TRUE);

            return FLB_RETRY;
        }

        wire_message_length = (uint32_t) body_len;

        sds_result = cfl_sds_cat(grpc_body, "\x00----", 5);

        if (sds_result == NULL) {
            flb_http_client_request_destroy(request, FLB_TRUE);

            cfl_sds_destroy(grpc_body);

            return FLB_RETRY;
        }

        grpc_body = sds_result;

        ((uint8_t *) grpc_body)[1] = (wire_message_length & 0xFF000000) >> 24;
        ((uint8_t *) grpc_body)[2] = (wire_message_length & 0x00FF0000) >> 16;
        ((uint8_t *) grpc_body)[3] = (wire_message_length & 0x0000FF00) >> 8;
        ((uint8_t *) grpc_body)[4] = (wire_message_length & 0x000000FF) >> 0;

        sds_result = cfl_sds_cat(grpc_body, body, body_len);

        if (sds_result == NULL) {
            flb_http_client_request_destroy(request, FLB_TRUE);

            cfl_sds_destroy(grpc_body);

            return FLB_RETRY;
        }

        grpc_body = sds_result;

        grpc_body_length = cfl_sds_len(grpc_body);

        result = flb_http_request_set_parameters(request,
                    FLB_HTTP_CLIENT_ARGUMENT_URI(grpc_uri),
                    FLB_HTTP_CLIENT_ARGUMENT_CONTENT_TYPE(
                    "application/grpc"),
                    FLB_HTTP_CLIENT_ARGUMENT_BODY(grpc_body,
                                                  grpc_body_length,
                                                  compression_algorithm));

        cfl_sds_destroy(grpc_body);

        if (result  != 0) {
            flb_http_client_request_destroy(request, FLB_TRUE);

            return FLB_RETRY;
        }
    }
    else {
        if (ctx->compress_gzip == FLB_TRUE) {
            compression_algorithm = "gzip";
        }
        else if (ctx->compress_zstd == FLB_TRUE) {
            compression_algorithm = "zstd";
        }

        result = flb_http_request_set_parameters(request,
                        FLB_HTTP_CLIENT_ARGUMENT_URI(http_uri),
                        FLB_HTTP_CLIENT_ARGUMENT_CONTENT_TYPE(
                            FLB_OPENTELEMETRY_MIME_PROTOBUF_LITERAL),
                        FLB_HTTP_CLIENT_ARGUMENT_BODY(body,
                                                      body_len,
                                                      compression_algorithm));

        if (result  != 0) {
            flb_http_client_request_destroy(request, FLB_TRUE);

            return FLB_RETRY;
        }
    }

    if (ctx->http_user != NULL &&
        ctx->http_passwd != NULL) {
        result = flb_http_request_set_parameters(request,
                    FLB_HTTP_CLIENT_ARGUMENT_BASIC_AUTHORIZATION(
                                                    ctx->http_user,
                                                    ctx->http_passwd));

        if (result  != 0) {
            flb_plg_error(ctx->ins, "error setting http authorization data");

            return FLB_RETRY;
        }

        flb_http_request_set_authorization(request,
                                           HTTP_WWW_AUTHORIZATION_SCHEME_BASIC,
                                           ctx->http_user,
                                           ctx->http_passwd);
    }

    response = flb_http_client_request_execute(request);
    if (response == NULL) {
        flb_plg_warn(ctx->ins, "error performing HTTP request, remote host=%s:%i connection error",
                     ctx->host, ctx->port);
        flb_http_client_request_destroy(request, FLB_TRUE);

        return FLB_RETRY;
    }

    /*
     * Only allow the following HTTP status:
     *
     * - 200: OK
     * - 201: Created
     * - 202: Accepted
     * - 203: no authorative resp
     * - 204: No Content
     * - 205: Reset content
     *
     */
    if (response->status < 200 || response->status > 205) {
        if (ctx->log_response_payload &&
            response->body != NULL &&
            cfl_sds_len(response->body) > 0) {
            flb_plg_error(ctx->ins,
                          "%s:%i, HTTP status=%i\n%s",
                          ctx->host,
                          ctx->port,
                          response->status,
                          response->body);
        }
        else {
            flb_plg_error(ctx->ins,
                          "%s:%i, HTTP status=%i",
                          ctx->host,
                          ctx->port,
                          response->status);
        }

        if (is_http_status_code_retrayable(response->status) == FLB_TRUE) {
            out_ret = FLB_RETRY;
        }
        else {
            out_ret = FLB_ERROR;
        }
    }
    else {
        if (ctx->log_response_payload &&
            response->body != NULL &&
            cfl_sds_len(response->body) > 0) {
            flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i%s",
                            ctx->host, ctx->port,
                            response->status, response->body);
        }
        else {
            flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                            ctx->host, ctx->port,
                            response->status);
        }

        out_ret = FLB_OK;
    }

    flb_http_client_request_destroy(request, FLB_TRUE);

    return out_ret;
}

int otel_process_logs(struct flb_event_chunk *event_chunk,
                      struct flb_output_flush *out_flush,
                      struct flb_input_instance *ins, void *out_context,
                      struct flb_config *config);


static void append_labels(struct opentelemetry_context *ctx,
                          struct cmt *cmt)
{
    struct flb_kv *kv;
    struct mk_list *head;

    mk_list_foreach(head, &ctx->kv_labels) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        cmt_label_add(cmt, kv->key, kv->val);
    }
}

static int opentelemetry_format_test(struct flb_config *config,
                                     struct flb_input_instance *ins,
                                     void *plugin_context,
                                     void *flush_ctx,
                                     int event_type,
                                     const char *tag, int tag_len,
                                     const void *data, size_t bytes,
                                     void **out_data, size_t *out_size)
{
    if (event_type == FLB_INPUT_LOGS) {

    }
    else if (event_type == FLB_INPUT_METRICS) {

    }
    else if (event_type == FLB_INPUT_TRACES) {

    }

    return 0;
}

static int process_metrics(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out1_flush,
                           struct flb_input_instance *ins, void *out_context,
                           struct flb_config *config)
{
    int c = 0;
    int ok;
    int ret;
    int result;
    cfl_sds_t encoded_chunk;
    flb_sds_t buf = NULL;
    size_t diff = 0;
    size_t off = 0;
    struct cmt *cmt;
    struct opentelemetry_context *ctx = out_context;

    /* Initialize vars */
    ctx = out_context;
    ok = CMT_DECODE_MSGPACK_SUCCESS;
    result = FLB_OK;

    /* Buffer to concatenate multiple metrics contexts */
    buf = flb_sds_create_size(event_chunk->size);
    if (!buf) {
        flb_plg_error(ctx->ins, "could not allocate outgoing buffer");
        return FLB_RETRY;
    }

    flb_plg_debug(ctx->ins, "cmetrics msgpack size: %lu",
                  event_chunk->size);

    /* Decode and encode every CMetric context */
    diff = 0;
    while ((ret = cmt_decode_msgpack_create(&cmt,
                                            (char *) event_chunk->data,
                                            event_chunk->size, &off)) == ok) {
        /* append labels set by config */
        append_labels(ctx, cmt);

        /* Create a OpenTelemetry payload */
        encoded_chunk = cmt_encode_opentelemetry_create(cmt);
        if (encoded_chunk == NULL) {
            flb_plg_error(ctx->ins,
                          "Error encoding context as opentelemetry");
            result = FLB_ERROR;
            cmt_destroy(cmt);
            goto exit;
        }

        flb_plg_debug(ctx->ins, "cmetric_id=%i decoded %lu-%lu payload_size=%lu",
                      c, diff, off, flb_sds_len(encoded_chunk));
        c++;
        diff = off;

        /* concat buffer */
        flb_sds_cat_safe(&buf, encoded_chunk, flb_sds_len(encoded_chunk));

        /* release */
        cmt_encode_opentelemetry_destroy(encoded_chunk);
        cmt_destroy(cmt);
    }

    if (ret == CMT_DECODE_MSGPACK_INSUFFICIENT_DATA && c > 0) {
        flb_plg_debug(ctx->ins, "final payload size: %lu", flb_sds_len(buf));
        if (buf && flb_sds_len(buf) > 0) {
            /* Send HTTP request */
            result = opentelemetry_post(ctx, buf, flb_sds_len(buf),
                                        event_chunk->tag,
                                        flb_sds_len(event_chunk->tag),
                                        ctx->metrics_uri_sanitized,
                                        ctx->grpc_metrics_uri);

            /* Debug http_post() result statuses */
            if (result == FLB_OK) {
                flb_plg_debug(ctx->ins, "http_post result FLB_OK");
            }
            else if (result == FLB_ERROR) {
                flb_plg_debug(ctx->ins, "http_post result FLB_ERROR");
            }
            else if (result == FLB_RETRY) {
                flb_plg_debug(ctx->ins, "http_post result FLB_RETRY");
            }
        }
        flb_sds_destroy(buf);
        buf = NULL;
        return result;
    }
    else {
        flb_plg_error(ctx->ins, "Error decoding msgpack encoded context");
        flb_sds_destroy(buf);
        return FLB_ERROR;
    }

exit:
    if (buf) {
        flb_sds_destroy(buf);
    }
    return result;
}

static int process_traces(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *ins, void *out_context,
                          struct flb_config *config)
{
    int ret;
    int result;
    cfl_sds_t encoded_chunk;
    flb_sds_t buf = NULL;
    size_t off = 0;
    struct ctrace *ctr;
    struct opentelemetry_context *ctx = out_context;

    /* Initialize vars */
    ctx = out_context;
    result = FLB_OK;

    buf = flb_sds_create_size(event_chunk->size);
    if (!buf) {
        flb_plg_error(ctx->ins, "could not allocate outgoing buffer");
        return FLB_RETRY;
    }

    flb_plg_debug(ctx->ins, "ctraces msgpack size: %lu",
                  event_chunk->size);

    while (ctr_decode_msgpack_create(&ctr,
                                     (char *) event_chunk->data,
                                     event_chunk->size, &off) == 0) {
        /* Create a OpenTelemetry payload */
        encoded_chunk = ctr_encode_opentelemetry_create(ctr);
        if (encoded_chunk == NULL) {
            flb_plg_error(ctx->ins,
                          "Error encoding context as opentelemetry");
            result = FLB_ERROR;
            ctr_destroy(ctr);
            goto exit;
        }

        /* concat buffer */
        ret = flb_sds_cat_safe(&buf, encoded_chunk, flb_sds_len(encoded_chunk));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "Error appending encoded trace to buffer");
            result = FLB_ERROR;
            ctr_encode_opentelemetry_destroy(encoded_chunk);
            ctr_destroy(ctr);
            goto exit;
        }

        /* release */
        ctr_encode_opentelemetry_destroy(encoded_chunk);
        ctr_destroy(ctr);
    }

    flb_plg_debug(ctx->ins, "final payload size: %lu", flb_sds_len(buf));
    if (buf && flb_sds_len(buf) > 0) {
        /* Send HTTP request */
        result = opentelemetry_post(ctx, buf, flb_sds_len(buf),
                                    event_chunk->tag,
                                    flb_sds_len(event_chunk->tag),
                                    ctx->traces_uri_sanitized,
                                    ctx->grpc_traces_uri);

        /* Debug http_post() result statuses */
        if (result == FLB_OK) {
            flb_plg_debug(ctx->ins, "http_post result FLB_OK");
        }
        else if (result == FLB_ERROR) {
            flb_plg_debug(ctx->ins, "http_post result FLB_ERROR");
        }
        else if (result == FLB_RETRY) {
            flb_plg_debug(ctx->ins, "http_post result FLB_RETRY");
        }
    }

exit:
    if (buf) {
        flb_sds_destroy(buf);
    }
    return result;
}

static int process_profiles(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *ins, void *out_context,
                            struct flb_config *config)
{
    int ret;
    int result;
    cfl_sds_t encoded_chunk;
    flb_sds_t buf = NULL;
    size_t off = 0;
    struct cprof *profiles_context;
    struct opentelemetry_context *ctx = out_context;

    /* Initialize vars */
    ctx = out_context;
    result = FLB_OK;

    buf = flb_sds_create_size(event_chunk->size);
    if (!buf) {
        flb_plg_error(ctx->ins, "could not allocate outgoing buffer");
        return FLB_RETRY;
    }

    flb_plg_debug(ctx->ins, "cprofiles msgpack size: %lu",
                  event_chunk->size);

    while (cprof_decode_msgpack_create(&profiles_context,
                                       (unsigned char *) event_chunk->data,
                                       event_chunk->size, &off) == 0) {
        /* Create a OpenTelemetry payload */
        ret = cprof_encode_opentelemetry_create(&encoded_chunk, profiles_context);
        if (ret != CPROF_ENCODE_OPENTELEMETRY_SUCCESS) {
            flb_plg_error(ctx->ins,
                          "Error encoding context as opentelemetry");
            result = FLB_ERROR;
            cprof_decode_msgpack_destroy(profiles_context);
            goto exit;
        }

        /* concat buffer */
        ret = flb_sds_cat_safe(&buf, encoded_chunk, flb_sds_len(encoded_chunk));
        if (ret != 0) {
            flb_plg_error(ctx->ins, "Error appending encoded profiles to buffer");
            result = FLB_ERROR;
            cprof_encode_opentelemetry_destroy(encoded_chunk);
            cprof_decode_msgpack_destroy(profiles_context);
            goto exit;
        }

        /* release */
        cprof_encode_opentelemetry_destroy(encoded_chunk);
        cprof_decode_msgpack_destroy(profiles_context);
    }

    flb_plg_debug(ctx->ins, "final payload size: %lu", flb_sds_len(buf));
    if (buf && flb_sds_len(buf) > 0) {
        /* Send HTTP request */
        result = opentelemetry_post(ctx, buf, flb_sds_len(buf),
                                    event_chunk->tag,
                                    flb_sds_len(event_chunk->tag),
                                    ctx->profiles_uri_sanitized,
                                    ctx->grpc_profiles_uri);

        /* Debug http_post() result statuses */
        if (result == FLB_OK) {
            flb_plg_debug(ctx->ins, "http_post result FLB_OK");
        }
        else if (result == FLB_ERROR) {
            flb_plg_debug(ctx->ins, "http_post result FLB_ERROR");
        }
        else if (result == FLB_RETRY) {
            flb_plg_debug(ctx->ins, "http_post result FLB_RETRY");
        }
    }

exit:
    if (buf) {
        flb_sds_destroy(buf);
    }
    return result;
}

static int cb_opentelemetry_exit(void *data, struct flb_config *config)
{
    struct opentelemetry_context *ctx;

    ctx = (struct opentelemetry_context *) data;

    flb_opentelemetry_context_destroy(ctx);

    return 0;
}

static int cb_opentelemetry_init(struct flb_output_instance *ins,
                                 struct flb_config *config,
                                 void *data)
{
    struct opentelemetry_context *ctx;

    ctx = flb_opentelemetry_context_create(ins, config);
    if (!ctx) {
        return -1;
    }

    if (ctx->batch_size <= 0){
        ctx->batch_size = atoi(DEFAULT_LOG_RECORD_BATCH_SIZE);
    }

    flb_output_set_context(ins, ctx);

    /*
     * This plugin instance uses the HTTP client interface, let's register
     * it debugging callbacks.
     */
    flb_output_set_http_debug_callbacks(ins);

    return 0;
}

static void cb_opentelemetry_flush(struct flb_event_chunk *event_chunk,
                                   struct flb_output_flush *out_flush,
                                   struct flb_input_instance *ins, void *out_context,
                                   struct flb_config *config)
{
    int result = FLB_RETRY;

    if (event_chunk->type == FLB_INPUT_METRICS){
        result = process_metrics(event_chunk, out_flush, ins, out_context, config);
    }
    else if (event_chunk->type == FLB_INPUT_LOGS){
        result = otel_process_logs(event_chunk, out_flush, ins, out_context, config);
    }
    else if (event_chunk->type == FLB_INPUT_TRACES){
        result = process_traces(event_chunk, out_flush, ins, out_context, config);
    }
    else if (event_chunk->type == FLB_INPUT_PROFILES){
        result = process_profiles(event_chunk, out_flush, ins, out_context, config);
    }

    FLB_OUTPUT_RETURN(result);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SLIST_1, "add_label", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct opentelemetry_context,
                                             add_labels),
     "Adds a custom label to the metrics use format: 'add_label name value'"
    },
    {
     FLB_CONFIG_MAP_STR, "http2", "off",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, enable_http2),
     "Enable, disable or force HTTP/2 usage. Accepted values : on, off, force"
    },
    {
     FLB_CONFIG_MAP_BOOL, "grpc", "off",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, enable_grpc_flag),
     "Enable, disable or force gRPC usage. Accepted values : on, off, auto"
    },
    {
     FLB_CONFIG_MAP_STR, "proxy", NULL,
     0, FLB_FALSE, 0,
     "Specify an HTTP Proxy. The expected format of this value is http://host:port. "
    },
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct opentelemetry_context, http_user),
     "Set HTTP auth user"
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, http_passwd),
     "Set HTTP auth password"
    },
    {
     FLB_CONFIG_MAP_SLIST_1, "header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct opentelemetry_context, headers),
     "Add a HTTP header key/value pair. Multiple headers can be set"
    },
    {
     FLB_CONFIG_MAP_STR, "metrics_uri", "/v1/metrics",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, metrics_uri),
     "Specify an optional HTTP URI for the target OTel endpoint."
    },
    {
     FLB_CONFIG_MAP_STR, "grpc_metrics_uri", "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, grpc_metrics_uri),
     "Specify an optional gRPC URI for the target OTel endpoint."
    },

    {
     FLB_CONFIG_MAP_INT, "batch_size", DEFAULT_LOG_RECORD_BATCH_SIZE,
      0, FLB_TRUE, offsetof(struct opentelemetry_context, batch_size),
      "Set the maximum number of log records to be flushed at a time"
    },
    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Set payload compression mechanism. Options available are 'gzip' and 'zstd'."
    },

    /*
     * Logs Properties
     * ---------------
     */
    {
     FLB_CONFIG_MAP_INT, "logs_max_resources", DEFAULT_MAX_RESOURCE_EXPORT,
     0, FLB_TRUE, offsetof(struct opentelemetry_context, max_resources),
     "Set the maximum number of OTLP log resources per export request (0 disables the limit; default: 0)"
    },

    {
     FLB_CONFIG_MAP_INT, "logs_max_scopes", DEFAULT_MAX_SCOPE_EXPORT,
     0, FLB_TRUE, offsetof(struct opentelemetry_context, max_scopes),
     "Set the maximum number of OTLP log scopes per resource (0 disables the limit; default: 0)"
    },

    {
     FLB_CONFIG_MAP_STR, "logs_uri", "/v1/logs",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_uri),
     "Specify an optional HTTP URI for the target OTel endpoint."
    },

    {
     FLB_CONFIG_MAP_STR, "grpc_logs_uri", "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, grpc_logs_uri),
     "Specify an optional gRPCß URI for the target OTel endpoint."
    },

    {
     FLB_CONFIG_MAP_STR, "logs_body_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct opentelemetry_context, log_body_key_list_str),
     "Specify an optional HTTP URI for the target OTel endpoint."
    },

    {
     FLB_CONFIG_MAP_BOOL, "logs_body_key_attributes", "false",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_body_key_attributes),
     "If logs_body_key is set and it matched a pattern, this option will include the "
     "remaining fields in the record as attributes."
    },

    {
     FLB_CONFIG_MAP_STR, "traces_uri", "/v1/traces",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, traces_uri),
     "Specify an optional HTTP URI for the target OTel endpoint."
    },
    {
     FLB_CONFIG_MAP_STR, "grpc_traces_uri",
     "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, grpc_traces_uri),
     "Specify an optional gRPC URI for the target OTel endpoint."
    },

    {
     FLB_CONFIG_MAP_STR, "profiles_uri", "/v1development/profiles",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, profiles_uri),
     "Specify an optional HTTP URI for the profiles OTel endpoint."
    },
    {
     FLB_CONFIG_MAP_STR, "grpc_profiles_uri",
     "/opentelemetry.proto.collector.profiles.v1experimental.ProfilesService/Export",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, grpc_profiles_uri),
     "Specify an optional gRPC URI for the profiles OTel endpoint."
    },

    {
     FLB_CONFIG_MAP_BOOL, "log_response_payload", "true",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, log_response_payload),
     "Specify if the response payload should be logged or not"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_metadata_key", "otlp",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_metadata_key),
    },
    {
     FLB_CONFIG_MAP_STR, "logs_observed_timestamp_metadata_key", "$ObservedTimestamp",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_observed_timestamp_metadata_key),
     "Specify an ObservedTimestamp key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_timestamp_metadata_key", "$Timestamp",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_timestamp_metadata_key),
     "Specify a Timestamp key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_severity_text_metadata_key", "$SeverityText",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_severity_text_metadata_key),
     "Specify a SeverityText key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_severity_number_metadata_key", "$SeverityNumber",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_severity_number_metadata_key),
     "Specify a SeverityNumber key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_trace_flags_metadata_key", "$TraceFlags",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_trace_flags_metadata_key),
     "Specify a TraceFlags key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_span_id_metadata_key", "$SpanId",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_span_id_metadata_key),
     "Specify a SpanId key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_trace_id_metadata_key", "$TraceId",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_trace_id_metadata_key),
     "Specify a TraceId key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_attributes_metadata_key", "$Attributes",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_attributes_metadata_key),
     "Specify an Attributes key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_instrumentation_scope_metadata_key", "InstrumentationScope",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_instrumentation_scope_metadata_key),
     "Specify an InstrumentationScope key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_resource_metadata_key", "Resource",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_resource_metadata_key),
     "Specify a Resource key"
    },
        {
     FLB_CONFIG_MAP_STR, "logs_span_id_message_key", "$SpanId",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_span_id_message_key),
     "Specify a SpanId key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_trace_id_message_key", "$TraceId",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_trace_id_message_key),
     "Specify a TraceId key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_severity_text_message_key", "$SeverityText",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_severity_text_message_key),
     "Specify a Severity Text key"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_severity_number_message_key", "$SeverityNumber",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_severity_number_message_key),
     "Specify a Severity Number key"
    },


    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_opentelemetry_plugin = {
    .name        = "opentelemetry",
    .description = "OpenTelemetry",
    .cb_init     = cb_opentelemetry_init,
    .cb_flush    = cb_opentelemetry_flush,
    .cb_exit     = cb_opentelemetry_exit,
    .config_map  = config_map,
    .event_type  = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS | FLB_OUTPUT_TRACES | FLB_OUTPUT_PROFILES,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,

    .test_formatter.callback = opentelemetry_format_test,
};
