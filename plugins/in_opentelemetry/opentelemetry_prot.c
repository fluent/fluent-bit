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
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_opentelemetry.h>

#include <fluent-bit/http_server/flb_http_server.h>

#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cprofiles/cprof_decode_opentelemetry.h>
#include <cprofiles/cprof_encode_text.h>

#include <fluent-otel-proto/fluent-otel.h>


#include "opentelemetry.h"
#include "opentelemetry_utils.h"
#include "opentelemetry_logs.h"
#include "opentelemetry_traces.h"

#define HTTP_CONTENT_JSON  0

static int is_profiles_export_path(const char *path)
{
    if (path == NULL) {
        return FLB_FALSE;
    }

    if (strcmp(path, "/opentelemetry.proto.collector.profiles.v1experimental.ProfilesService/Export") == 0 ||
        strcmp(path, "/opentelemetry.proto.collector.profiles.v1development.ProfilesService/Export") == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static \
int uncompress_zlib(struct flb_opentelemetry *ctx,
                    char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    flb_plg_warn(ctx->ins, "zlib decompression is not supported");
    return -1;
}

static \
int uncompress_zstd(struct flb_opentelemetry *ctx,
                    char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    int ret;

    ret = flb_zstd_uncompress(input_buffer,
                              input_size,
                              (void *) output_buffer,
                              output_size);

    if (ret != 0) {
        flb_plg_error(ctx->ins, "zstd decompression failed");
        return -1;
    }

    return 1;
}

static \
int uncompress_deflate(struct flb_opentelemetry *ctx,
                       char **output_buffer,
                       size_t *output_size,
                       char *input_buffer,
                       size_t input_size)
{
    flb_plg_warn(ctx->ins, "deflate decompression is not supported");
    return -1;
}

static \
int uncompress_snappy(struct flb_opentelemetry *ctx,
                      char **output_buffer,
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
        flb_plg_error(ctx->ins, "snappy decompression failed");
        return -1;
    }

    return 1;
}

static \
int uncompress_gzip(struct flb_opentelemetry *ctx,
                    char **output_buffer,
                    size_t *output_size,
                    char *input_buffer,
                    size_t input_size)
{
    int ret;

    ret = flb_gzip_uncompress(input_buffer,
                              input_size,
                              (void *) output_buffer,
                              output_size);

    if (ret == -1) {
        flb_error("[opentelemetry] gzip decompression failed");

        return -1;
    }

    return 1;
}

/*
 * We use two backends for HTTP parsing and it depends on the version of the
 * protocol:
 *
 * http/1.x: we use Monkey HTTP parser: struct mk_http_session.parser
 * http/2.x: we use nghttp2: struct flb_http_request
 *
 * based on the protocol version we need to handle the header lookup differently.
 */
static int http_header_lookup(int version, void *ptr, char *key,
                              char **val, size_t *val_len)
{
    int key_len;

    /* HTTP/1.1 */
    struct mk_list *head;
    struct mk_http_session *session;
    struct mk_http_request *request_11;
    struct mk_http_header *header;

    /* HTTP/2.0 */
    char *value;
    struct flb_http_request *request_20;

    if (!key) {
        return -1;
    }

    key_len = strlen(key);
    if (key_len <= 0) {
        return -1;
    }

    if (version <= HTTP_PROTOCOL_VERSION_11) {
        if (!ptr) {
            return -1;
        }

        request_11 = (struct mk_http_request *) ptr;
        session = request_11->session;
        mk_list_foreach(head, &session->parser.header_list) {
            header = mk_list_entry(head, struct mk_http_header, _head);
            if (header->key.len == key_len &&
                strncasecmp(header->key.data, key, key_len) == 0) {
                *val = header->val.data;
                *val_len = header->val.len;
                return 0;
            }
        }
        return -1;
    }
    else if (version == HTTP_PROTOCOL_VERSION_20) {
        request_20 = ptr;
        if (!request_20) {
            return -1;
        }

        value = flb_http_request_get_header(request_20, key);
        if (!value) {
            return -1;
        }

        *val = value;
        *val_len = strlen(value);
        return 0;
    }

    return -1;
}

/* New gen HTTP server */
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

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int send_grpc_response_ng(struct flb_http_response *response,
                                 uint8_t *message_buffer,
                                 size_t message_length,
                                 int grpc_status,
                                 char *grpc_message)
{
    char      grpc_status_as_string[16];
    uint32_t  wire_message_length;
    size_t    body_buffer_size;
    cfl_sds_t body_buffer;

    body_buffer_size = 5 + message_length;

    if (body_buffer_size < 65) {
        body_buffer_size = 65;
    }

    body_buffer = cfl_sds_create_size(body_buffer_size);

    if (body_buffer == NULL) {
        return -1;
    }

    sprintf(grpc_status_as_string, "%u", grpc_status);

    wire_message_length = (uint32_t) message_length;

    cfl_sds_cat_safe(&body_buffer, "\x00----", 5);

    ((uint8_t *) body_buffer)[1] = (wire_message_length & 0xFF000000) >> 24;
    ((uint8_t *) body_buffer)[2] = (wire_message_length & 0x00FF0000) >> 16;
    ((uint8_t *) body_buffer)[3] = (wire_message_length & 0x0000FF00) >> 8;
    ((uint8_t *) body_buffer)[4] = (wire_message_length & 0x000000FF) >> 0;

    if (message_buffer != NULL) {
        cfl_sds_cat_safe(&body_buffer, (char *) message_buffer, message_length);
    }

    flb_http_response_set_status(response, 200);

    flb_http_response_set_body(response,
                                (unsigned char *) body_buffer,
                                5 + message_length);

    flb_http_response_set_header(response,
                                 "content-type",     0,
                                 "application/grpc", 0);

    flb_http_response_set_trailer_header(response,
                                         "grpc-status", 0,
                                         grpc_status_as_string, 0);

    flb_http_response_set_trailer_header(response,
                                         "grpc-message", 0,
                                         grpc_message,   0);

    flb_http_response_commit(response);

    cfl_sds_destroy(body_buffer);

    return 0;
}

static int send_grpc_error_response_ng(struct flb_http_response *response,
                                       int grpc_status,
                                       const char *grpc_message)
{
    const char *message;

    message = grpc_message != NULL ? grpc_message : "";

    return send_grpc_response_ng(response, NULL, 0, grpc_status, (char *) message);
}

static int send_export_logs_service_response_ng(struct flb_http_response *response,
                                                int status)
{
    uint8_t                                                             *message_buffer;
    size_t                                                               message_length;
    const char                                                          *grpc_message;
    int                                                                  grpc_status;
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceResponse message;

    if (status == 0) {
        opentelemetry__proto__collector__logs__v1__export_logs_service_response__init(&message);

        message_length = opentelemetry__proto__collector__logs__v1__export_logs_service_response__get_packed_size(&message);

        message_buffer = flb_calloc(message_length, sizeof(uint8_t));
        if (message_buffer == NULL) {
            return -1;
        }

        opentelemetry__proto__collector__logs__v1__export_logs_service_response__pack(&message, message_buffer);

        grpc_status  = 0;
        grpc_message = "";
    }
    else {
        grpc_status  = 2; /* gRPC UNKNOWN */
        grpc_message = "Serialization error.";
        message_buffer = NULL;
        message_length = 0;
    }

    send_grpc_response_ng(response, message_buffer, message_length, grpc_status, (char *) grpc_message);

    if (message_buffer != NULL) {
        flb_free(message_buffer);
    }

    return 0;
}

static int send_export_metrics_service_response_ng(struct flb_http_response *response,
                                                   int status)
{
    uint8_t                                                                   *message_buffer;
    size_t                                                                     message_length;
    const char                                                                *grpc_message;
    int                                                                        grpc_status;
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceResponse message;

    if (status == 0) {
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_response__init(&message);

        message_length = opentelemetry__proto__collector__metrics__v1__export_metrics_service_response__get_packed_size(&message);

        message_buffer = flb_calloc(message_length, sizeof(uint8_t));

        if (message_buffer == NULL) {
            return -1;
        }

        opentelemetry__proto__collector__metrics__v1__export_metrics_service_response__pack(&message, message_buffer);

        grpc_status  = 0;
        grpc_message = "-";
    }
    else {
        grpc_status  = 2; /* gRPC UNKNOWN */
        grpc_message = "Serialization error.";
        message_buffer = NULL;
        message_length = 0;
    }

    send_grpc_response_ng(response, message_buffer, message_length, grpc_status, (char *) grpc_message);

    if (message_buffer != NULL) {
        flb_free(message_buffer);
    }

    return 0;
}

static int send_export_traces_service_response_ng(struct flb_http_response *response,
                                                  int status)
{
    uint8_t                                                               *message_buffer;
    size_t                                                                 message_length;
    const char                                                            *grpc_message;
    int                                                                    grpc_status;
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceResponse message;

    if (status == 0) {
        opentelemetry__proto__collector__trace__v1__export_trace_service_response__init(&message);

        message_length = opentelemetry__proto__collector__trace__v1__export_trace_service_response__get_packed_size(&message);

        message_buffer = flb_calloc(message_length, sizeof(uint8_t));

        if (message_buffer == NULL) {
            return -1;
        }

        opentelemetry__proto__collector__trace__v1__export_trace_service_response__pack(&message, message_buffer);

        grpc_status  = 0;
        grpc_message = "-";
    }
    else {
        grpc_status  = 2; /* gRPC UNKNOWN */
        grpc_message = "Serialization error.";
        message_buffer = NULL;
        message_length = 0;
    }

    send_grpc_response_ng(response, message_buffer, message_length, grpc_status, (char *) grpc_message);

    if (message_buffer != NULL) {
        flb_free(message_buffer);
    }

    return 0;
}

static int send_export_profiles_service_response_ng(struct flb_http_response *response,
                                                    int status)
{
    uint8_t                                                                    *message_buffer;
    size_t                                                                      message_length;
    const char                                                                 *grpc_message;
    int                                                                         grpc_status;
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceResponse message;

    if (status == 0) {
        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_response__init(&message);

        message_length = opentelemetry__proto__collector__profiles__v1development__export_profiles_service_response__get_packed_size(&message);

        message_buffer = flb_calloc(message_length, sizeof(uint8_t));
        if (message_buffer == NULL) {
            return -1;
        }

        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_response__pack(&message, message_buffer);

        grpc_status  = 0;
        grpc_message = "-";
    }
    else {
        grpc_status  = 2; /* gRPC UNKNOWN */
        grpc_message = "Serialization error.";
        message_buffer = NULL;
        message_length = 0;
    }

    send_grpc_response_ng(response, message_buffer, message_length, grpc_status, (char *) grpc_message);

    if (message_buffer != NULL) {
        flb_free(message_buffer);
    }

    return 0;
}

static int process_payload_metrics_ng(struct flb_opentelemetry *ctx,
                                      flb_sds_t tag,
                                      struct flb_http_request *request,
                                      char *payload, size_t payload_size)

{
    struct cfl_list  decoded_contexts;
    struct cfl_list *iterator;
    struct cmt      *context;
    size_t           offset;
    int              result = -1;

    offset = 0;

    /* note: if the content type is gRPC, it was already decoded */
    if (opentelemetry_is_json_content_type(request->content_type) == FLB_TRUE) {
        result = flb_opentelemetry_metrics_json_to_cmt(&decoded_contexts,
                                                       payload,
                                                       payload_size);
    }
    else if (opentelemetry_is_protobuf_content_type(request->content_type) ==
             FLB_TRUE) {
        result = cmt_decode_opentelemetry_create(&decoded_contexts,
                                                 payload,
                                                 payload_size,
                                                 &offset);
    }
    else {
        flb_plg_error(ctx->ins, "Unsupported content type %s", request->content_type);
        return -1;
    }

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cfl_list_foreach(iterator, &decoded_contexts) {
            context = cfl_list_entry(iterator, struct cmt, _head);

            result = flb_input_metrics_append(ctx->ins, tag, cfl_sds_len(tag), context);

            if (result != 0) {
                flb_plg_debug(ctx->ins, "could not ingest metrics context : %d", result);
            }
        }

        cmt_decode_opentelemetry_destroy(&decoded_contexts);
    }
    else {
        flb_plg_warn(ctx->ins, "non-success cmetrics opentelemetry decode result %d", result);
        return -1;
    }

    return 0;
}

static int ingest_profiles_context_as_log_entry(struct flb_opentelemetry *ctx,
                                                flb_sds_t tag,
                                                struct cprof *profiles_context)
{
    cfl_sds_t                     text_encoded_profiles_context;
    struct flb_log_event_encoder *encoder;
    int                           ret;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);

    if (encoder == NULL) {
        return -1;
    }

    ret = cprof_encode_text_create(&text_encoded_profiles_context,
                                   profiles_context,
                                   CPROF_ENCODE_TEXT_RENDER_DICTIONARIES_AND_INDEXES);

    if (ret != CPROF_ENCODE_TEXT_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);

        return -2;
    }

    flb_log_event_encoder_begin_record(encoder);

    flb_log_event_encoder_set_current_timestamp(encoder);

    ret = flb_log_event_encoder_append_body_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("Profile"),
                FLB_LOG_EVENT_STRING_VALUE(text_encoded_profiles_context,
                                            cfl_sds_len(text_encoded_profiles_context)));

    cprof_encode_text_destroy(text_encoded_profiles_context);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);

        return -3;
    }

    ret = flb_log_event_encoder_commit_record(encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);

        return -4;
    }

    ret = flb_input_log_append(ctx->ins,
                               tag,
                               flb_sds_len(tag),
                               encoder->output_buffer,
                               encoder->output_length);

    flb_log_event_encoder_destroy(encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -5;
    }

    return 0;
}

static int process_payload_profiles_ng(struct flb_opentelemetry *ctx,
                                       flb_sds_t tag,
                                       struct flb_http_request *request,
                                       char *payload,
                                       size_t payload_size)
{
    struct cprof *profiles_context;
    size_t        offset;
    int           ret;

    if (request->content_type == NULL) {
        flb_error("[otel] content type missing");
        return -1;
    }
    else if (opentelemetry_is_json_content_type(request->content_type) == FLB_TRUE) {
        flb_error("[otel] unsuported profiles encoding type : %s",
                  request->content_type);

        return -1;
    }
    else if (opentelemetry_is_protobuf_content_type(request->content_type) ==
             FLB_TRUE) {
        profiles_context = NULL;
        offset = 0;

        ret = cprof_decode_opentelemetry_create(&profiles_context,
                                                (uint8_t *) payload,
                                                payload_size,
                                                &offset);

        if (ret != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            flb_error("[otel] profile decoding error : %d",
                      ret);

            return -1;
        }

        if (ctx->encode_profiles_as_log) {
            ret = ingest_profiles_context_as_log_entry(ctx,
                                                       tag,
                                                       profiles_context);
        }
        else {
            ret = flb_input_profiles_append(ctx->ins,
                                            tag,
                                            flb_sds_len(tag),
                                            profiles_context);
        }

        cprof_decode_opentelemetry_destroy(profiles_context);

        if (ret != 0) {
            flb_error("[otel] profile ingestion error : %d",
                      ret);

            return -1;
        }

        ret = 0;
    }
    else {
        flb_plg_error(ctx->ins, "Unsupported content type %s", request->content_type);

        ret = -1;
    }

    return ret;
}

static int send_export_service_response_ng(struct flb_http_response *response,
                                           int result,
                                           char payload_type)
{
    switch (payload_type) {
    case 'M':
        return send_export_metrics_service_response_ng(response, result);
    case 'T':
        return send_export_traces_service_response_ng(response, result);
    case 'L':
        return  send_export_logs_service_response_ng(response, result);
    case 'P':
        return send_export_profiles_service_response_ng(response, result);
    default:
        return -1;
    }
}

/*
 * Protocol handle for requests coming from HTTP/2 server backend. Note that
 * if the payload is compressed (Content-Encoding) it will be decompressed
 * before this function is called.
 *
 * For gRPC payloads where the gRPC message is compressed (do not confuse with
 * Content-Encoding), each message will be decompressed within this callback.
 */
int opentelemetry_prot_handle_ng(struct flb_http_request *request,
                                 struct flb_http_response *response)
{
    int ret = -1;
    int grpc_request = FLB_FALSE;
    int grpc_uncompressed = FLB_FALSE;
    size_t grpc_offset = 0;
    uint64_t  grpc_size = 0;
    flb_sds_t tag = NULL;
    char payload_type;
    char *encoding = NULL;
    size_t encoding_size = 0;
    char *buf = (char *) request->body;
    size_t request_body_size = 0;
    char *payload = NULL;
    size_t payload_size = 0;
    size_t max_grpc_size = 16 * 1024 * 1024; /* 16M limit per message */
    struct flb_opentelemetry *context;

    context = (struct flb_opentelemetry *) response->stream->user_data;

    if (request->path[0] != '/') {
        send_response_ng(response, 400, "error: invalid request\n");
        return -1;
    }

    if (strcmp(request->path, "/v1/metrics") == 0 ||
        strcmp(request->path, "/v1/traces") == 0  ||
        strcmp(request->path, "/v1/logs") == 0) {
        grpc_request = FLB_FALSE;
    }
    else if(strcmp(request->path, "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.traces.v1.TracesService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.logs.v1.LogsService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.metric.v1.MetricService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.trace.v1.TraceService/Export") == 0 ||
            strcmp(request->path, "/opentelemetry.proto.collector.log.v1.LogService/Export") == 0) {
        grpc_request = FLB_TRUE;
    }
    else if (context->profile_support_enabled &&
             is_profiles_export_path(request->path) == FLB_TRUE) {
        grpc_request = FLB_TRUE;
    }
    else {
        send_response_ng(response, 400, "error: invalid endpoint\n");
        return -1;
    }

    /* ToDo: Fix me */
    /* HTTP/1.1 needs Host header */
    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {
        if (grpc_request) {
            send_grpc_error_response_ng(response, 3, "missing host header");
            return -1;
        }
        return -1;
    }

    if (request->method != HTTP_METHOD_POST) {
        if (grpc_request) {
            send_grpc_error_response_ng(response, 3, "invalid HTTP method");
        }
        else {
            send_response_ng(response, 400, "error: invalid HTTP method\n");
        }
        return -1;
    }

    /* check content-length */
    if (request->content_length <= 0) {
        if (grpc_request) {
            send_grpc_error_response_ng(response, 3, "invalid content-length");
        }
        else {
            send_response_ng(response, 400, "error: invalid content-length\n");
        }
        return -1;
    }

    if (request->body == NULL) {
        if (grpc_request) {
            send_grpc_error_response_ng(response, 3, "invalid payload");
        }
        else {
            send_response_ng(response, 400, "error: invalid payload\n");
        }
        return -1;
    }
    request_body_size = cfl_sds_len(request->body);

    /* If this is a gRPC request validate the content-type */
    if (grpc_request && request->content_type == NULL) {
        send_grpc_error_response_ng(response, 3, "missing content-type");
        return -1;
    }

    /* Check if the payload is gRPC compressed */
    if (grpc_request &&
        opentelemetry_is_grpc_content_type(request->content_type) == FLB_TRUE) {

next_grpc_message:

        if (grpc_offset > request_body_size ||
            request_body_size - grpc_offset < 5) {
            send_grpc_error_response_ng(response, 3, "invalid gRPC packet");
            return -1;
        }

        /* gRPC message size */
        grpc_size = ((uint64_t) (uint8_t) buf[1] << 24) |
                    ((uint64_t) (uint8_t) buf[2] << 16) |
                    ((uint64_t) (uint8_t) buf[3] << 8)  |
                    ((uint64_t) (uint8_t) buf[4]);

        if (grpc_size == 0 || grpc_size > max_grpc_size) {
            send_grpc_error_response_ng(response, 3, "gRPC message size out of valid range");
            return -1;
        }

        if (request_body_size - grpc_offset < grpc_size + 5) {
            send_grpc_error_response_ng(response, 3, "invalid gRPC packet");
            return -1;
        }

        /* check if the message is compressed */
        if (buf[0] == 0x1) {
            /* get compression type */
            ret = http_header_lookup(HTTP_PROTOCOL_VERSION_20, request,
                                     "grpc-encoding", &encoding, &encoding_size);

            /* malformed gRPC message */
            if (ret == -1) {
                send_grpc_error_response_ng(response, 3, "missing gRPC encoding");
                return -1;
            }

            /* buf: skip header */
            buf += 5;

            if (strncasecmp(encoding, "gzip", 4) == 0 && encoding_size == 4) {
                ret = uncompress_gzip(context,
                                      &payload, &payload_size,
                                      buf, grpc_size);
            }
            else if (strncasecmp(encoding, "zlib", 4) == 0 && encoding_size == 4) {
                ret = uncompress_zlib(context,
                                      &payload, &payload_size,
                                      buf, grpc_size);
            }
            else if (strncasecmp(encoding, "zstd", 4) == 0 && encoding_size == 4) {
                ret = uncompress_zstd(context,
                                      &payload, &payload_size,
                                      buf, grpc_size);
            }
            else if (strncasecmp(encoding, "snappy", 6) == 0 && encoding_size == 6) {
                ret = uncompress_snappy(context,
                                        &payload, &payload_size,
                                        buf, grpc_size);
            }
            else if (strncasecmp(encoding, "deflate", 7) == 0 && encoding_size == 7) {
                ret = uncompress_deflate(context,
                                        &payload, &payload_size,
                                        buf, grpc_size);
            }
            else {
                send_grpc_error_response_ng(response, 12, "unsupported gRPC encoding");
                return -1;
            }

            if (ret <= 0) {
                send_grpc_error_response_ng(response, 13, "decompression error");
                return -1;
            }

            grpc_uncompressed = FLB_TRUE;
        }
        else {
            /* uncompressed payload */
            payload = buf + 5;
            payload_size = grpc_size;
            grpc_uncompressed = FLB_FALSE;
        }

        /* mark the end of this gRPC message */
        grpc_offset += grpc_size + 5;
    }
    else {
        grpc_request = FLB_FALSE;
        payload = request->body;
        payload_size = cfl_sds_len(request->body);
    }

    if (strcmp(request->path, "/v1/metrics") == 0 ||
        strcmp(request->path, "/opentelemetry.proto.collector.metric.v1.MetricService/Export") == 0 ||
        strcmp(request->path, "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export") == 0) {
        payload_type = 'M';
        if (context->tag_from_uri == FLB_TRUE) {
            tag = flb_sds_create("v1_metrics");
        }
        else {
            tag = flb_sds_create(context->ins->tag);
        }

        ret = process_payload_metrics_ng(context, tag, request,
                                         payload, payload_size);
    }
    else if (strcmp(request->path, "/v1/traces") == 0 ||
             strcmp(request->path, "/opentelemetry.proto.collector.trace.v1.TraceService/Export") == 0 ||
             strcmp(request->path, "/opentelemetry.proto.collector.traces.v1.TracesService/Export") == 0) {
        payload_type = 'T';
        if (context->tag_from_uri == FLB_TRUE) {
            tag = flb_sds_create("v1_traces");
        }
        else {
            tag = flb_sds_create(context->ins->tag);
        }

        ret = opentelemetry_process_traces(context, request->content_type,
                                           tag, flb_sds_len(tag),
                                           payload, payload_size);
    }
    else if (strcmp(request->path, "/v1/logs") == 0 ||
             strcmp(request->path, "/opentelemetry.proto.collector.log.v1.LogService/Export") == 0 ||
             strcmp(request->path, "/opentelemetry.proto.collector.logs.v1.LogsService/Export") == 0) {
        payload_type = 'L';
        if (context->tag_from_uri == FLB_TRUE) {
            tag = flb_sds_create("v1_logs");
        }
        else {
            tag = flb_sds_create(context->ins->tag);
        }

        ret = opentelemetry_process_logs(context, request->content_type, tag, flb_sds_len(tag),
                                         payload, payload_size);
    }
    else if (context->profile_support_enabled &&
             is_profiles_export_path(request->path) == FLB_TRUE) {
        payload_type = 'P';
        if (context->tag_from_uri == FLB_TRUE) {
            tag = flb_sds_create("v1development_profiles");
        }
        else {
            tag = flb_sds_create(context->ins->tag);
        }
        ret = process_payload_profiles_ng(context, tag, request, payload, payload_size);
    }

    if (grpc_request) {
        /* check if we have uncompressed a gRPC message, if so, release it */
        if (grpc_uncompressed == FLB_TRUE) {
            flb_free(payload);
            grpc_uncompressed = FLB_FALSE;
        }

        /* check if we have more gRPC messages to process */
        if (grpc_offset < request_body_size) {
            buf = (char *) request->body + grpc_offset;
            goto next_grpc_message;
        }

        send_export_service_response_ng(response, ret, payload_type);
    }
    else {
        if (ret == 0) {
            send_response_ng(response, context->successful_response_code, NULL);
        }
        else {
            send_response_ng(response, 400, "invalid request: deserialisation error\n");
        }
    }

    flb_sds_destroy(tag);

    return ret;
}
